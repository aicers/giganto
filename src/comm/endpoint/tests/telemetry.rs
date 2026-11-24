//! The telemetry an admitted connection carries: streams, batches and their
//! acknowledgements, over the entry's port or a pipe.

use senta_protocol::{
    connection::{Message, cbor},
    telemetry::{Ack, DroppedRange, OpenStream, RecordBatch, ResumeInfo, TelemetryMessage},
    telemetry_codes::DropReason,
};
use serde::{Deserialize, Serialize};
use tokio::io::DuplexStream;

use super::*;
use crate::{
    comm::endpoint::receiver::tests::{
        BASE, PROCESS_CREATE_CF, process_create, record_key, stored_seqs, stored_value, unaccepted,
        unconvertible, windows_event_log,
    },
    graphql::tests::TestSchema,
    storage::{
        SENSORS_CF,
        endpoint::{ENDPOINT_LOSSES_CF, ENDPOINT_STREAMS_CF},
    },
};

/// The endpoint id of the list entry `Running::start` lists the fake
/// endpoint's key under.
const ENDPOINT_ID: Uuid = Uuid::from_u128(1);
const STREAM: Uuid = Uuid::from_u128(0x5a);
const KEY_A: [u8; 32] = [0xa; 32];
const KEY_B: [u8; 32] = [0xb; 32];

/// A fake endpoint whose `hello` was admitted, speaking telemetry.
struct Telemetry<S> {
    stream: S,
    decoder: FrameDecoder,
}

impl Telemetry<EndpointStream> {
    /// Connects to `running` and completes the handshake, expecting
    /// `entry_id`.
    async fn connect(running: &Running, node: &Node, entry_id: Uuid) -> Self {
        let mut stream = running.connect(node.ca.root.pem()).await;
        handshake_expecting(&mut stream, entry_id).await;
        Self::new(stream)
    }
}

impl Telemetry<DuplexStream> {
    /// Serves a connection from the key `key` of `entry` over a pipe, and
    /// completes the handshake. The task ends when the connection does.
    async fn piped(
        entry: &Entry,
        key: [u8; 32],
        token: &CancellationToken,
    ) -> (Self, JoinHandle<()>) {
        let (mut side, mut entry_side) = tokio::io::duplex(SERVER_ACTIVE_RECEIVE_LIMIT as usize);
        let task = tokio::spawn({
            let entry = entry.clone();
            let token = token.clone();
            async move {
                let remote = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
                run_admitted_by_list(&mut entry_side, remote, key, entry, &token).await;
            }
        });
        let (_endpoint, hello) = hello(ENTRY_ID);
        side.write_all(hello.as_bytes())
            .await
            .expect("send the hello");
        let mut telemetry = Self::new(side);
        let (kind, _) = next_frame_of(&mut telemetry.stream, &mut telemetry.decoder).await;
        assert_eq!(kind, HelloAck::T);
        (telemetry, task)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Telemetry<S> {
    fn new(stream: S) -> Self {
        Self {
            stream,
            decoder: FrameDecoder::new(ENDPOINT_RECEIVE_LIMIT),
        }
    }

    async fn send_frame(&mut self, frame: &Frame) {
        self.stream
            .write_all(frame.as_bytes())
            .await
            .expect("send a frame");
        self.stream.flush().await.expect("flush");
    }

    async fn send(&mut self, message: &TelemetryMessage) {
        self.send_frame(&message.to_frame().expect("encode a message"))
            .await;
    }

    /// Returns the next telemetry message the entry sends.
    async fn next(&mut self) -> TelemetryMessage {
        loop {
            let (kind, payload) = next_frame_of(&mut self.stream, &mut self.decoder).await;
            if kind == Ping::T {
                continue;
            }
            let envelope = Envelope::parse(&payload).expect("an envelope");
            return TelemetryMessage::decode(envelope.t(), envelope.body())
                .expect("a telemetry message");
        }
    }

    async fn open_stream(&mut self, stream: Uuid) -> ResumeInfo {
        self.send(&TelemetryMessage::OpenStream(OpenStream { stream }))
            .await;
        match self.next().await {
            TelemetryMessage::ResumeInfo(info) => info,
            other => panic!("open_stream answered {other:?}"),
        }
    }

    async fn send_batch(&mut self, stream: Uuid, records: Vec<Vec<u8>>) {
        let batch = RecordBatch::new(stream, records).expect("a batch in size");
        self.send(&TelemetryMessage::RecordBatch(batch)).await;
    }

    /// Reads until the entry closes the connection, and returns the
    /// telemetry messages it sent before.
    async fn until_closed(&mut self) -> Vec<TelemetryMessage> {
        let mut received = Vec::new();
        tokio::time::timeout(IO_TIMEOUT, self.stream.read_to_end(&mut received))
            .await
            .expect("the entry closes the connection in time")
            .expect("the entry closes the connection cleanly");
        self.decoder.push(&received);
        let mut messages = Vec::new();
        while let Some(payload) = self.decoder.next_frame().expect("a frame within the limit") {
            let envelope = Envelope::parse(&payload).expect("an envelope");
            messages.push(
                TelemetryMessage::decode(envelope.t(), envelope.body())
                    .expect("a telemetry message"),
            );
        }
        messages
    }
}

fn ack(stream: Uuid, a: u64) -> TelemetryMessage {
    TelemetryMessage::Ack(Ack { stream, a })
}

fn stream_error(stream: Uuid, error: TelemetryError) -> TelemetryMessage {
    TelemetryMessage::ErrorMessage(ErrorMessage {
        stream: Some(stream),
        error,
    })
}

fn list_error(error: TelemetryError) -> TelemetryMessage {
    TelemetryMessage::ErrorMessage(ErrorMessage {
        stream: None,
        error,
    })
}

/// Waits until `condition` holds, yielding to the runtime and the blocking
/// threads in between.
async fn until(mut condition: impl FnMut() -> bool) {
    while !condition() {
        tokio::task::yield_now().await;
        std::thread::yield_now();
    }
}

/// Returns the response data of `query` on `schema`.
async fn graphql(schema: &TestSchema, query: &str) -> serde_json::Value {
    let response = schema.execute(query).await;
    assert!(response.errors.is_empty(), "{query}: {:?}", response.errors);
    response.data.into_json().expect("JSON data")
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One scene: storage, queries and the sensor sets.
async fn records_are_acknowledged_once_stored_and_read_as_the_endpoints_sensor() {
    let schema = TestSchema::new();
    let node = Node::new();
    let material = node.material(&node.cert, &node.ca.bundle_pem());
    let running = Running::start_on(
        material,
        DEFAULT_LEASE_LENGTH,
        schema.db.clone(),
        schema.ingest_sensors.clone(),
    )
    .await;
    running
        .apply(
            &full(
                1,
                vec![entry(1, endpoint_spki(&ENDPOINT_SEED), EntryState::Active)],
            ),
            ENTRY_ID,
        )
        .await
        .expect("the full list applies");
    let sensor = ENDPOINT_ID.to_string();

    let mut endpoint = Telemetry::connect(&running, &node, ENTRY_ID).await;
    assert_eq!(endpoint.open_stream(STREAM).await.a, 0);
    endpoint
        .send_batch(
            STREAM,
            vec![
                process_create(ENDPOINT_ID, STREAM, 1, BASE, "cmd.exe"),
                windows_event_log(ENDPOINT_ID, STREAM, 2, BASE + 1, "Security"),
            ],
        )
        .await;
    assert_eq!(endpoint.next().await, ack(STREAM, 2));
    // Acknowledged once stored, with the stream's state.
    assert_eq!(stored_seqs(&running.db, &sensor, STREAM), [1]);
    let state = running.db.endpoint_streams(ENTRY_ID).unwrap();
    assert_eq!(state.len(), 1);
    assert_eq!(state[0].1.a, 2);

    let data = graphql(
        &schema,
        &format!(
            "{{ processCreateEvents(filter: {{ sensor: \"{sensor}\" }}, first: 10) \
             {{ edges {{ node {{ image agentId }} }} }} }}"
        ),
    )
    .await;
    assert_eq!(
        data["processCreateEvents"]["edges"][0]["node"],
        serde_json::json!({ "image": "cmd.exe", "agentId": sensor })
    );
    let data = graphql(
        &schema,
        &format!(
            "{{ endpointWindowsEventLogEvents(filter: {{ sensor: \"{sensor}\" }}, first: 10) \
             {{ edges {{ node {{ channel }} }} }} }}"
        ),
    )
    .await;
    assert_eq!(
        data["endpointWindowsEventLogEvents"]["edges"][0]["node"]["channel"],
        "Security"
    );

    // The endpoint joined the sensor sets, and peers were told.
    let row = running
        .db
        .get_cf_for_test(SENSORS_CF, sensor.as_bytes())
        .unwrap()
        .expect("the sensors row");
    assert!(running.ingest_sensors.read().await.contains(&sensor));
    assert!(
        running
            .runtime_ingest_sensors
            .read()
            .await
            .contains_key(&sensor)
    );
    tokio::time::timeout(IO_TIMEOUT, running.sensor_change.notified())
        .await
        .expect("peers are told of the new sensor");

    // Its last connection closing takes it out of the runtime set, with its
    // row rewritten; it stays a sensor.
    endpoint.stream.shutdown().await.expect("send close_notify");
    assert!(
        endpoint.until_closed().await.is_empty(),
        "closed without a word"
    );
    tokio::time::timeout(IO_TIMEOUT, async {
        while running
            .runtime_ingest_sensors
            .read()
            .await
            .contains_key(&sensor)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the runtime set loses the endpoint in time");
    let rewritten = running
        .db
        .get_cf_for_test(SENSORS_CF, sensor.as_bytes())
        .unwrap()
        .expect("the sensors row");
    assert!(rewritten > row, "written again with the close time");
    assert!(running.ingest_sensors.read().await.contains(&sensor));

    // A reconnecting connection that stores a batch adds it again.
    let mut endpoint = Telemetry::connect(&running, &node, ENTRY_ID).await;
    assert_eq!(endpoint.open_stream(STREAM).await.a, 2);
    endpoint
        .send_batch(
            STREAM,
            vec![process_create(ENDPOINT_ID, STREAM, 3, BASE + 2, "more.exe")],
        )
        .await;
    assert_eq!(endpoint.next().await, ack(STREAM, 3));
    assert!(
        running
            .runtime_ingest_sensors
            .read()
            .await
            .contains_key(&sensor)
    );
    drop(endpoint);
    running.stop().await;
}

#[tokio::test]
async fn a_batch_finding_no_free_key_is_not_acknowledged_and_its_resend_is_stored() {
    let node = Node::new();
    let material = node.material(&node.cert, &node.ca.bundle_pem());
    let dir = tempfile::tempdir().expect("tempdir");
    let db = Database::open(dir.path(), &DbOptions::default())
        .expect("open the database")
        .with_append_unique_max_probes(1);
    let sensor = ENDPOINT_ID.to_string();
    let taken = record_key(&sensor, BASE);
    let another = process_create(ENDPOINT_ID, Uuid::from_u128(0x77), 9, BASE, "another.exe");
    db.put_cf_for_test(PROCESS_CREATE_CF, &taken, &stored_value(&another))
        .unwrap();
    let ingest_sensors = crate::comm::new_ingest_sensors(&db);
    let running = Running::start_on(material, DEFAULT_LEASE_LENGTH, db, ingest_sensors).await;
    running
        .apply(
            &full(
                1,
                vec![entry(1, endpoint_spki(&ENDPOINT_SEED), EntryState::Active)],
            ),
            ENTRY_ID,
        )
        .await
        .expect("the full list applies");
    let record = process_create(ENDPOINT_ID, STREAM, 1, BASE, "cmd.exe");

    let mut endpoint = Telemetry::connect(&running, &node, ENTRY_ID).await;
    endpoint.open_stream(STREAM).await;
    endpoint.send_batch(STREAM, vec![record.clone()]).await;
    assert!(
        endpoint.until_closed().await.is_empty(),
        "closed without an ack"
    );
    assert!(
        stored_seqs(&running.db, &sensor, STREAM).is_empty(),
        "nothing is stored"
    );

    running
        .db
        .entries_for_test(PROCESS_CREATE_CF)
        .unwrap()
        .iter()
        .for_each(|(key, _)| assert_eq!(*key, taken));
    let store = running.db.process_create_store().unwrap();
    store.delete(&taken).unwrap();
    let mut endpoint = Telemetry::connect(&running, &node, ENTRY_ID).await;
    assert_eq!(endpoint.open_stream(STREAM).await.a, 0);
    endpoint.send_batch(STREAM, vec![record]).await;
    assert_eq!(endpoint.next().await, ack(STREAM, 1));
    assert_eq!(stored_seqs(&running.db, &sensor, STREAM), [1]);
    drop(endpoint);
    running.stop().await;
}

/// A `record_batch` past a size limit that still decodes.
#[derive(Serialize, Deserialize)]
struct OversizeBatch {
    #[serde(with = "cbor::uuid")]
    stream: Uuid,
    records: Vec<RecordBytes>,
}

struct RecordBytes(Vec<u8>);

impl Serialize for RecordBytes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        cbor::bytes::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for RecordBytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        cbor::bytes::deserialize(deserializer).map(Self)
    }
}

impl Message for OversizeBatch {
    const T: &'static str = RecordBatch::T;
}

/// An `open_stream` whose body is not one.
#[derive(Serialize, Deserialize)]
struct NotAnOpenStream(u8);

impl Message for NotAnOpenStream {
    const T: &'static str = OpenStream::T;
}

#[tokio::test]
async fn an_oversize_batch_is_too_large_and_a_malformed_body_closes() {
    let node = Node::new();
    let material = node.material(&node.cert, &node.ca.bundle_pem());
    let running = Running::start(material, Some(ENTRY_ID)).await;
    let mut endpoint = Telemetry::connect(&running, &node, ENTRY_ID).await;
    endpoint.open_stream(STREAM).await;

    let oversize = Frame::from_message(&OversizeBatch {
        stream: STREAM,
        records: vec![RecordBytes(vec![
            0;
            senta_protocol::telemetry::MAX_RECORD_LEN
                + 1
        ])],
    })
    .expect("encode the batch");
    endpoint.send_frame(&oversize).await;
    assert_eq!(
        endpoint.next().await,
        stream_error(STREAM, TelemetryError::TooLarge)
    );
    ping_pong(&mut endpoint.stream).await;

    let malformed = Frame::from_message(&NotAnOpenStream(7)).expect("encode the frame");
    endpoint.send_frame(&malformed).await;
    assert!(
        endpoint.until_closed().await.is_empty(),
        "a body that does not decode closes without a word"
    );
    running.stop().await;
}

#[tokio::test]
async fn a_call_that_panics_closes_its_connection_without_a_word() {
    let node = Node::new();
    let material = node.material(&node.cert, &node.ca.bundle_pem());
    let running = Running::start(material, Some(ENTRY_ID)).await;
    let sensor = ENDPOINT_ID.to_string();
    let record = process_create(ENDPOINT_ID, STREAM, 1, BASE, "a.exe");
    let mut endpoint = Telemetry::connect(&running, &node, ENTRY_ID).await;
    endpoint.open_stream(STREAM).await;

    // The connection task runs on this test's thread, so its log is caught.
    let (logs, guard) = crate::test_bootroot::capture_logs();
    running.flows.controls().panic_next_lock();
    endpoint.send_batch(STREAM, vec![record.clone()]).await;
    assert!(
        endpoint.until_closed().await.is_empty(),
        "closed without a word"
    );
    drop(guard);
    assert!(
        logs.contents().contains("handling a message failed"),
        "{}",
        logs.contents()
    );
    assert_eq!(stored_seqs(&running.db, &sensor, STREAM), [0_u64; 0]);

    // The streams are read again, and the resend is stored.
    let mut endpoint = Telemetry::connect(&running, &node, ENTRY_ID).await;
    assert_eq!(endpoint.open_stream(STREAM).await.a, 0);
    endpoint.send_batch(STREAM, vec![record]).await;
    assert_eq!(endpoint.next().await, ack(STREAM, 1));
    assert_eq!(stored_seqs(&running.db, &sensor, STREAM), [1]);
    drop(endpoint);
    running.stop().await;
}

#[tokio::test]
async fn the_stream_rules_hold_over_a_connection() {
    let node = Node::new();
    let material = node.material(&node.cert, &node.ca.bundle_pem());
    let running = Running::start(material, Some(ENTRY_ID)).await;
    let sensor = ENDPOINT_ID.to_string();
    let mut endpoint = Telemetry::connect(&running, &node, ENTRY_ID).await;
    endpoint.open_stream(STREAM).await;

    // A kind outside the hello_ack: what came before it is stored and
    // acknowledged, and the connection is kept.
    endpoint
        .send_batch(
            STREAM,
            vec![
                process_create(ENDPOINT_ID, STREAM, 1, BASE, "a.exe"),
                unaccepted(ENDPOINT_ID, STREAM, 2),
            ],
        )
        .await;
    assert_eq!(endpoint.next().await, ack(STREAM, 1));
    assert_eq!(
        endpoint.next().await,
        stream_error(STREAM, TelemetryError::UnsupportedKind)
    );
    ping_pong(&mut endpoint.stream).await;

    // A record that does not convert is a loss; the rest is stored.
    endpoint
        .send_batch(
            STREAM,
            vec![
                unconvertible(ENDPOINT_ID, STREAM, 2),
                process_create(ENDPOINT_ID, STREAM, 3, BASE + 3, "c.exe"),
            ],
        )
        .await;
    assert_eq!(endpoint.next().await, ack(STREAM, 3));
    assert_eq!(stored_seqs(&running.db, &sensor, STREAM), [1, 3]);
    assert_eq!(
        running
            .db
            .entries_for_test(ENDPOINT_LOSSES_CF)
            .unwrap()
            .len(),
        1
    );

    // A record naming another endpoint closes the connection and stores
    // nothing of its batch.
    endpoint
        .send_batch(
            STREAM,
            vec![
                process_create(ENDPOINT_ID, STREAM, 4, BASE + 4, "d.exe"),
                process_create(Uuid::from_u128(2), STREAM, 5, BASE + 5, "e.exe"),
            ],
        )
        .await;
    assert!(
        endpoint.until_closed().await.is_empty(),
        "closed without a word"
    );
    assert_eq!(stored_seqs(&running.db, &sensor, STREAM), [1, 3]);
    running.stop().await;
}

#[tokio::test]
async fn a_new_entry_id_moves_the_streams_or_changes_nothing() {
    let node = Node::new();
    let material = node.material(&node.cert, &node.ca.bundle_pem());
    let running = Running::start(material, Some(ENTRY_ID)).await;
    let entries = vec![entry(1, endpoint_spki(&ENDPOINT_SEED), EntryState::Active)];
    let mut endpoint = Telemetry::connect(&running, &node, ENTRY_ID).await;
    endpoint.open_stream(STREAM).await;
    endpoint
        .send_batch(
            STREAM,
            vec![process_create(ENDPOINT_ID, STREAM, 1, BASE, "a.exe")],
        )
        .await;
    assert_eq!(endpoint.next().await, ack(STREAM, 1));
    endpoint
        .send(&TelemetryMessage::DroppedRange(DroppedRange {
            stream: STREAM,
            from: 2,
            to: 3,
            reason: DropReason::BufferOverflow,
        }))
        .await;
    assert_eq!(endpoint.next().await, ack(STREAM, 3));

    // A change that cannot be stored changes nothing.
    running.flows.controls().fail_writes(true);
    let refusal = running
        .apply(&full(2, entries.clone()), other_entry_id())
        .await
        .expect_err("the entry_id cannot be stored");
    assert!(matches!(refusal.failure, ApplyFailure::Store(_)));
    running.flows.controls().fail_writes(false);
    assert_eq!(running.list.state().entry_id, Some(ENTRY_ID));
    assert_eq!(running.list.state().version, Some(1));
    assert_eq!(running.flows.entry_id(), Some(ENTRY_ID));
    assert_eq!(running.db.endpoint_entry_id().unwrap(), Some(ENTRY_ID));
    ping_pong(&mut endpoint.stream).await;

    running
        .apply(&full(2, entries), other_entry_id())
        .await
        .expect("the new entry_id applies");
    assert!(
        endpoint.until_closed().await.is_empty(),
        "closed without a word"
    );
    assert_eq!(running.flows.entry_id(), Some(other_entry_id()));
    assert!(
        running.db.endpoint_streams(ENTRY_ID).unwrap().is_empty(),
        "no stream state is stored"
    );
    assert!(
        running
            .db
            .entries_for_test(ENDPOINT_STREAMS_CF)
            .unwrap()
            .is_empty(),
        "the old entry_id's streams are gone"
    );
    assert_eq!(
        running
            .db
            .entries_for_test(ENDPOINT_LOSSES_CF)
            .unwrap()
            .len(),
        1,
        "its losses stay"
    );

    let mut endpoint = Telemetry::connect(&running, &node, other_entry_id()).await;
    assert_eq!(
        endpoint.open_stream(STREAM).await,
        ResumeInfo {
            stream: STREAM,
            a: 0,
            last_stored: None,
        },
        "a reconnecting endpoint's stream starts empty"
    );
    drop(endpoint);
    running.stop().await;
}

/// The node's list, database and streams, with endpoints 1 and 2 listed
/// under `KEY_A` and `KEY_B`, served over pipes.
struct Piped {
    list: Arc<EndpointList>,
    db: Database,
    flows: Arc<EndpointFlows>,
    entry: Entry,
    token: CancellationToken,
    _dir: TempDir,
}

impl Piped {
    async fn new(lease: Duration) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Database::open(dir.path(), &DbOptions::default()).expect("open the database");
        let list = Arc::new(EndpointList::new(lease));
        list.load_entry_id(&db);
        let flows = Arc::new(EndpointFlows::new(db.clone()));
        let entries = vec![
            entry(1, KEY_A, EntryState::Active),
            entry(2, KEY_B, EntryState::Active),
        ];
        list.apply(&encode(&full(1, entries)), &ENTRY_ID.to_string(), &flows)
            .await
            .expect("the full list applies");
        let entry = Entry::for_test(&list, &db, &flows);
        Self {
            list,
            db,
            flows,
            entry,
            token: CancellationToken::new(),
            _dir: dir,
        }
    }

    async fn connect(&self, key: [u8; 32]) -> (Telemetry<DuplexStream>, JoinHandle<()>) {
        Telemetry::piped(&self.entry, key, &self.token).await
    }
}

/// An update that closes a connection whose batch write is in progress
/// answers only after the write finished, and the batch is stored.
#[tokio::test]
async fn an_update_closing_a_connection_waits_for_its_batch_write() {
    let piped = Piped::new(DEFAULT_LEASE_LENGTH).await;
    let (mut a, task) = piped.connect(KEY_A).await;
    a.open_stream(STREAM).await;
    let gate = piped.flows.controls().hold_next_batch();
    a.send_batch(
        STREAM,
        vec![process_create(Uuid::from_u128(1), STREAM, 1, BASE, "a.exe")],
    )
    .await;
    gate.entered().await;

    let apply = tokio::spawn({
        let list = Arc::clone(&piped.list);
        let flows = Arc::clone(&piped.flows);
        async move {
            list.apply(
                &encode(&diff(1, 2, Vec::new(), vec![1])),
                &ENTRY_ID.to_string(),
                &flows,
            )
            .await
        }
    });
    until(|| piped.flows.controls().waiters() == 1).await;
    assert!(!apply.is_finished(), "the update waits for the write");
    assert!(
        stored_seqs(&piped.db, "00000000-0000-0000-0000-000000000001", STREAM).is_empty(),
        "nothing is stored"
    );

    gate.release();
    apply
        .await
        .expect("the update task joins")
        .expect("the diff applies");
    assert!(
        task.is_finished(),
        "the connection stopped before the update answered"
    );
    let sensor = Uuid::from_u128(1).to_string();
    assert_eq!(
        stored_seqs(&piped.db, &sensor, STREAM),
        [1],
        "the batch is stored"
    );
    assert_eq!(
        a.until_closed().await,
        [ack(STREAM, 1), list_error(TelemetryError::NotListed)]
    );
    assert_eq!(stored_seqs(&piped.db, &sensor, STREAM), [1]);
}

/// A lease expiry closes a connection whose call waits for the lock that
/// another endpoint's batch write holds: the confirmation that delivers it
/// answers once that write finished, and the waiting call writes nothing.
#[tokio::test(start_paused = true)]
async fn a_call_waiting_for_the_lock_of_a_closed_connection_writes_nothing() {
    const LEASE: Duration = Duration::from_secs(30);

    let piped = Piped::new(LEASE).await;
    let (mut a, a_task) = piped.connect(KEY_A).await;
    let (mut b, b_task) = piped.connect(KEY_B).await;
    let stream_b = Uuid::from_u128(0x5b);
    a.open_stream(STREAM).await;
    b.open_stream(stream_b).await;

    let gate = piped.flows.controls().hold_next_batch();
    b.send_batch(
        stream_b,
        vec![process_create(
            Uuid::from_u128(2),
            stream_b,
            1,
            BASE,
            "b.exe",
        )],
    )
    .await;
    gate.entered().await;
    a.send_batch(
        STREAM,
        vec![process_create(Uuid::from_u128(1), STREAM, 1, BASE, "a.exe")],
    )
    .await;
    until(|| piped.flows.controls().waiters() == 1).await;

    tokio::time::advance(LEASE).await;
    let confirm = tokio::spawn({
        let list = Arc::clone(&piped.list);
        async move { list.confirm(1).await }
    });
    until(|| piped.list.registered() == (0, 0)).await;
    assert!(
        !confirm.is_finished(),
        "the confirmation waits for the write"
    );

    gate.release();
    confirm.await.expect("the confirmation task joins");
    assert!(a_task.is_finished() && b_task.is_finished());
    let sensor_a = Uuid::from_u128(1).to_string();
    let sensor_b = Uuid::from_u128(2).to_string();
    assert_eq!(stored_seqs(&piped.db, &sensor_b, stream_b), [1]);
    assert!(
        stored_seqs(&piped.db, &sensor_a, STREAM).is_empty(),
        "the call of the closed connection wrote nothing"
    );
    let state = piped.db.endpoint_streams(ENTRY_ID).unwrap();
    let a_state = state
        .iter()
        .find(|((endpoint, _), _)| *endpoint == Uuid::from_u128(1))
        .map(|(_, state)| state.a);
    assert_eq!(a_state, Some(0));
    assert_eq!(
        a.until_closed().await,
        [list_error(TelemetryError::LeaseExpired)]
    );
    assert_eq!(
        b.until_closed().await,
        [ack(stream_b, 1), list_error(TelemetryError::LeaseExpired)]
    );
}

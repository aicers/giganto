//! What tests control in the receiver: failed writes, a batch write held
//! until released, and how many calls wait for the lock.

mod scenes;

use std::sync::{
    Arc, Condvar, Mutex, PoisonError,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};

use anyhow::{Result, bail};
use senta_protocol::telemetry::ReceiverChange;
use tokio::sync::watch;

/// The switches a test sets on [`EndpointFlows`](super::EndpointFlows).
#[derive(Default)]
pub(crate) struct Controls {
    fail: AtomicBool,
    gate: Mutex<Option<Arc<Gate>>>,
    waiting: AtomicUsize,
    writes: AtomicU64,
}

/// Counts a call waiting for the lock while it lives.
pub(super) struct Waiting<'a>(&'a AtomicUsize);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Controls {
    pub(super) fn waiting(&self) -> Waiting<'_> {
        self.waiting.fetch_add(1, Ordering::SeqCst);
        Waiting(&self.waiting)
    }

    /// Returns how many calls are taking the lock.
    pub(crate) fn waiters(&self) -> usize {
        self.waiting.load(Ordering::SeqCst)
    }

    /// Makes every later batch write and `entry_id` change fail, writing
    /// nothing, while `fail` is `true`.
    pub(crate) fn fail_writes(&self, fail: bool) {
        self.fail.store(fail, Ordering::SeqCst);
    }

    pub(super) fn check_failure(&self) -> Result<()> {
        if self.fail.load(Ordering::SeqCst) {
            bail!("injected write failure");
        }
        Ok(())
    }

    /// Holds the next batch write that carries a record, before anything of
    /// it is written, until the returned gate is released.
    pub(crate) fn hold_next_batch(&self) -> Arc<Gate> {
        let gate = Arc::new(Gate::new());
        *self.gate.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&gate));
        gate
    }

    /// Returns how many batch writes were attempted and not failed by
    /// [`fail_writes`](Self::fail_writes).
    pub(crate) fn writes(&self) -> u64 {
        self.writes.load(Ordering::SeqCst)
    }

    pub(super) fn before_write(&self, changes: &[ReceiverChange]) -> Result<()> {
        self.check_failure()?;
        self.writes.fetch_add(1, Ordering::SeqCst);
        if changes
            .iter()
            .any(|change| matches!(change, ReceiverChange::AppendRecord(_)))
        {
            let gate = self
                .gate
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some(gate) = gate {
                gate.hold();
            }
        }
        Ok(())
    }
}

/// A batch write held until a test releases it.
pub(crate) struct Gate {
    entered: watch::Sender<bool>,
    released: Mutex<bool>,
    wake: Condvar,
}

impl Gate {
    fn new() -> Self {
        Self {
            entered: watch::Sender::new(false),
            released: Mutex::new(false),
            wake: Condvar::new(),
        }
    }

    fn hold(&self) {
        self.entered.send_replace(true);
        let mut released = self.released.lock().unwrap_or_else(PoisonError::into_inner);
        while !*released {
            released = self
                .wake
                .wait(released)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Waits until a write is held.
    pub(crate) async fn entered(&self) {
        let mut entered = self.entered.subscribe();
        entered
            .wait_for(|entered| *entered)
            .await
            .expect("the gate keeps its sender");
    }

    /// Lets the held write go on.
    pub(crate) fn release(&self) {
        *self.released.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.wake.notify_all();
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

use giganto_client::ingest::sysmon::ProcessCreate as StoredProcessCreate;
use jiff::Timestamp;
use senta_protocol::{
    host::{CollectionMode, OsFamily, OsInfo},
    telemetry::{
        Ack, CloseStream, DroppedRange, ErrorMessage, LostOnReset, NetStateSource, OpenStream,
        RECEIVER_CLOSED_RETENTION, ReceiverConnection, ReceiverOutput, Record, RecordBatch,
        RecordBody, RecordHeader, ResumeInfo, SeqRange, TelemetryMessage, kind, logs, record_hash,
        sysmon,
    },
    telemetry_codes::{DropReason, TelemetryError},
};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{Delivered, EndpointFlows, Handled, convert};
use crate::storage::{
    Database, DbOptions, SENSORS_CF, StorageKey,
    endpoint::{
        ENDPOINT_LAST_RECEIVED_CF, ENDPOINT_LOSSES_CF, ENDPOINT_STREAMS_CF, LossReason,
        StoredStream, endpoint_loss_key, endpoint_stream_key,
    },
};

/// A stream's state as the tuple its value is the bincode 1 of: `A`,
/// `(L, H)` and the closed time.
type StreamTuple = (u64, Option<(u64, [u8; 16])>, Option<i64>);

/// The `entry_id` the node's streams are under.
pub(crate) const ENTRY: Uuid = Uuid::from_u128(0x0e17_0000_0000_4000_8000_0000_0000_00e1);
const OTHER_ENTRY: Uuid = Uuid::from_u128(0x0e17_0000_0000_4000_8000_0000_0000_00e2);
/// The endpoint the connections are from.
pub(crate) const ENDPOINT: Uuid = Uuid::from_u128(0x0b1c_2d3e_4f50_6172_8394_a5b6_c7d8_e9f0);
const OTHER_ENDPOINT: Uuid = Uuid::from_u128(0x0b1c_2d3e_4f50_6172_8394_a5b6_c7d8_e9f1);
const STREAM: Uuid = Uuid::from_u128(0x5a);
const OTHER_STREAM: Uuid = Uuid::from_u128(0x5b);
/// 2023-11-14T22:13:20Z.
pub(crate) const BASE: i64 = 1_700_000_000_000_000_000;
pub(crate) const PROCESS_CREATE_CF: &str = "process create";

fn ts(nanos: i64) -> Timestamp {
    Timestamp::from_nanosecond(i128::from(nanos)).expect("a time in range")
}

fn nanos_of(time: Timestamp) -> i64 {
    i64::try_from(time.as_nanosecond()).expect("a time in range")
}

pub(crate) fn header(endpoint_id: Uuid, stream: Uuid, seq: u64, event_time: i64) -> RecordHeader {
    RecordHeader {
        endpoint_id,
        stream,
        seq,
        event_time: ts(event_time),
        collected_at: ts(event_time),
        clock_offset: None,
        hostname: "host-01".to_owned(),
        ips: vec!["192.0.2.10".parse().expect("an address")],
        default_route_ip: None,
        net_state_source: NetStateSource::Observed,
        os: OsInfo {
            family: OsFamily::Windows,
            version: "10.0.22631".to_owned(),
        },
        collection_mode: CollectionMode::Essential,
        process_key: None,
    }
}

/// Returns a `ProcessCreate` record of `image`.
pub(crate) fn process_create_record(header: RecordHeader, image: &str) -> Record {
    let body = sysmon::ProcessCreate {
        image: Some(image.to_owned()),
        ..Default::default()
    };
    Record {
        header,
        kind: kind::SYSMON_PROCESS_CREATE,
        schema: 1,
        body: sysmon::Body::from(body)
            .to_record_body()
            .expect("the body encodes"),
    }
}

/// Returns the bytes of a `ProcessCreate` record of `image`.
pub(crate) fn process_create(
    endpoint_id: Uuid,
    stream: Uuid,
    seq: u64,
    event_time: i64,
    image: &str,
) -> Vec<u8> {
    process_create_record(header(endpoint_id, stream, seq, event_time), image)
        .to_bytes()
        .expect("the record encodes")
}

/// Returns the bytes of a Windows event log record of `channel`.
pub(crate) fn windows_event_log(
    endpoint_id: Uuid,
    stream: Uuid,
    seq: u64,
    event_time: i64,
    channel: &str,
) -> Vec<u8> {
    let body = logs::LogBody::WindowsEventLog(logs::WindowsEventLogBody {
        channel: Some(channel.to_owned()),
        ..Default::default()
    });
    Record {
        header: header(endpoint_id, stream, seq, event_time),
        kind: body.kind(),
        schema: 1,
        body: body.to_body().expect("the body encodes"),
    }
    .to_bytes()
    .expect("the record encodes")
}

/// Returns the bytes of a `ProcessCreate` record whose body does not convert.
pub(crate) fn unconvertible(endpoint_id: Uuid, stream: Uuid, seq: u64) -> Vec<u8> {
    let body: std::collections::BTreeMap<&str, &str> = [("process_id", "4242")].into();
    Record {
        header: header(endpoint_id, stream, seq, BASE),
        kind: kind::SYSMON_PROCESS_CREATE,
        schema: 1,
        body: RecordBody::encode(&body).expect("a map encodes"),
    }
    .to_bytes()
    .expect("the record encodes")
}

/// Returns the bytes of a record of a kind the entry does not accept.
pub(crate) fn unaccepted(endpoint_id: Uuid, stream: Uuid, seq: u64) -> Vec<u8> {
    Record {
        kind: 4,
        ..process_create_record(header(endpoint_id, stream, seq, BASE), "x.exe")
    }
    .to_bytes()
    .expect("the record encodes")
}

/// Returns why `bytes` does not convert.
fn convert_error(bytes: &[u8]) -> String {
    convert::convert(Record::from_bytes(bytes).expect("the record decodes"))
        .expect_err("the record does not convert")
        .to_string()
}

/// Returns the value `bytes` is stored as.
pub(crate) fn stored_value(bytes: &[u8]) -> Vec<u8> {
    convert::convert(Record::from_bytes(bytes).expect("the record decodes"))
        .expect("the record converts")
        .event
        .to_bincode()
        .expect("the struct serializes")
}

pub(crate) fn record_key(sensor: &str, timestamp: i64) -> Vec<u8> {
    StorageKey::builder()
        .start_key(sensor)
        .end_key(timestamp)
        .build()
        .key()
}

fn ack(stream: Uuid, a: u64) -> TelemetryMessage {
    TelemetryMessage::Ack(Ack { stream, a })
}

fn error(stream: Uuid, error: TelemetryError) -> TelemetryMessage {
    TelemetryMessage::ErrorMessage(ErrorMessage {
        stream: Some(stream),
        error,
    })
}

fn batch(stream: Uuid, records: Vec<Vec<u8>>) -> TelemetryMessage {
    TelemetryMessage::RecordBatch(RecordBatch::new(stream, records).expect("a batch in size"))
}

/// Returns the `ProcessCreate` records stored under `sensor`, by the time in
/// their keys.
pub(crate) fn stored_records(db: &Database, sensor: &str) -> Vec<(i64, StoredProcessCreate)> {
    let mut prefix = sensor.as_bytes().to_vec();
    prefix.push(0);
    db.entries_for_test(PROCESS_CREATE_CF)
        .expect("read the records")
        .into_iter()
        .filter(|(key, _)| key.starts_with(&prefix) && key.len() == prefix.len() + 8)
        .map(|(key, value)| {
            let time: [u8; 8] = key[prefix.len()..].try_into().expect("a timestamp");
            let record = bincode::deserialize(&value).expect("a ProcessCreate");
            (i64::from_be_bytes(time), record)
        })
        .collect()
}

/// Returns the sequence numbers of the stored records of `stream`.
pub(crate) fn stored_seqs(db: &Database, sensor: &str, stream: Uuid) -> Vec<u64> {
    stored_records(db, sensor)
        .into_iter()
        .filter_map(|(_, record)| record.endpoint)
        .filter(|header| header.stream == stream)
        .map(|header| header.seq)
        .collect()
}

/// Returns the state of `stream` of `endpoint` stored under `entry`.
fn stored_state(db: &Database, entry: Uuid, endpoint: Uuid, stream: Uuid) -> Option<StoredStream> {
    db.endpoint_streams(entry)
        .expect("read the streams")
        .into_iter()
        .find(|((e, s), _)| *e == endpoint && *s == stream)
        .map(|(_, state)| state)
}

/// A node's database and telemetry streams, with `ENTRY` stored.
pub(crate) struct Node {
    pub(crate) db: Database,
    pub(crate) flows: EndpointFlows,
    pub(crate) dir: TempDir,
}

impl Node {
    pub(crate) fn new() -> Self {
        Self::open(tempfile::tempdir().expect("tempdir"), None)
    }

    /// Opens the database in `dir`, with `probes` as its probe limit when
    /// given, and stores `ENTRY` in it.
    pub(crate) fn open(dir: TempDir, probes: Option<i64>) -> Self {
        let mut db = Database::open(dir.path(), &DbOptions::default()).expect("open the database");
        if let Some(probes) = probes {
            db = db.with_append_unique_max_probes(probes);
        }
        db.replace_endpoint_entry_id(ENTRY, None)
            .expect("store the entry_id");
        let flows = EndpointFlows::new(db.clone());
        Self { db, flows, dir }
    }

    /// Closes the database and opens it again, as a new generation does.
    pub(crate) fn reopen(self) -> Self {
        let Self { db, flows, dir } = self;
        drop(flows);
        db.shutdown().expect("shut the database down");
        drop(db);
        let db = Database::open(dir.path(), &DbOptions::default()).expect("reopen the database");
        let flows = EndpointFlows::new(db.clone());
        Self { db, flows, dir }
    }

    #[allow(clippy::unused_self)] // A connection to this node, as tests read it.
    pub(crate) fn connection(&self) -> ReceiverConnection {
        ReceiverConnection::new(ENDPOINT, convert::accepted_kinds())
    }

    /// Hands `message` to the streams as `connection`'s, and returns the
    /// output and the received time of a write that stored records.
    pub(crate) fn send_reporting(
        &self,
        connection: &mut ReceiverConnection,
        message: TelemetryMessage,
    ) -> (ReceiverOutput, Option<Timestamp>) {
        match self.flows.handle(
            &CancellationToken::new(),
            connection,
            Delivered::Message(message),
        ) {
            Handled::Done { output, stored_at } => (output, stored_at),
            Handled::Stopped => panic!("an open connection is not stopped"),
        }
    }

    pub(crate) fn send(
        &self,
        connection: &mut ReceiverConnection,
        message: TelemetryMessage,
    ) -> ReceiverOutput {
        self.send_reporting(connection, message).0
    }

    /// Hands `message` over, expecting the connection to be kept, and
    /// returns the replies.
    fn answer(
        &self,
        connection: &mut ReceiverConnection,
        message: TelemetryMessage,
    ) -> Vec<TelemetryMessage> {
        match self.send(connection, message) {
            ReceiverOutput::Reply(messages) => messages,
            ReceiverOutput::Disconnect => panic!("the connection was closed"),
        }
    }

    fn open_stream(&self, connection: &mut ReceiverConnection, stream: Uuid) -> ResumeInfo {
        match self.send(
            connection,
            TelemetryMessage::OpenStream(OpenStream { stream }),
        ) {
            ReceiverOutput::Reply(messages) => match messages.as_slice() {
                [TelemetryMessage::ResumeInfo(info)] => *info,
                other => panic!("open_stream answered {other:?}"),
            },
            ReceiverOutput::Disconnect => panic!("open_stream disconnected"),
        }
    }

    fn records(&self) -> Vec<(i64, StoredProcessCreate)> {
        stored_records(&self.db, &ENDPOINT.to_string())
    }

    fn state(&self, stream: Uuid) -> Option<StoredStream> {
        stored_state(&self.db, ENTRY, ENDPOINT, stream)
    }

    fn losses(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.db
            .entries_for_test(ENDPOINT_LOSSES_CF)
            .expect("read the losses")
    }

    fn last_received(&self) -> Option<Vec<u8>> {
        self.db
            .get_cf_for_test(ENDPOINT_LAST_RECEIVED_CF, ENDPOINT.as_bytes())
            .expect("read the last received time")
    }

    fn sensors_row(&self) -> Option<Vec<u8>> {
        self.db
            .get_cf_for_test(SENSORS_CF, ENDPOINT.to_string().as_bytes())
            .expect("read the sensors row")
    }
}

fn reply(messages: Vec<TelemetryMessage>) -> ReceiverOutput {
    ReceiverOutput::Reply(messages)
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

#[test]
fn a_batch_is_stored_with_its_stream_state_before_it_is_acknowledged() {
    let node = Node::new();
    let mut conn = node.connection();
    assert_eq!(
        node.open_stream(&mut conn, STREAM),
        ResumeInfo {
            stream: STREAM,
            a: 0,
            last_stored: None
        }
    );
    let first = process_create(ENDPOINT, STREAM, 1, BASE, "a.exe");
    let second = process_create(ENDPOINT, STREAM, 2, BASE + 5, "b.exe");
    let (output, stored_at) =
        node.send_reporting(&mut conn, batch(STREAM, vec![first, second.clone()]));
    assert_eq!(output, reply(vec![ack(STREAM, 2)]));
    let received = nanos_of(stored_at.expect("the write stored records"));

    assert_eq!(
        node.state(STREAM),
        Some(StoredStream {
            a: 2,
            last_stored: Some((2, record_hash(&second))),
            closed_at_ns: None,
        })
    );
    let records = node.records();
    let keys: Vec<i64> = records.iter().map(|(time, _)| *time).collect();
    assert_eq!(keys, [BASE, BASE + 5], "stored under the event times");
    let images: Vec<&str> = records.iter().map(|(_, r)| r.image.as_str()).collect();
    assert_eq!(images, ["a.exe", "b.exe"]);
    for (seq, (_, record)) in (1..).zip(&records) {
        assert_eq!(record.agent_id, ENDPOINT.to_string());
        let header = record.endpoint.as_ref().expect("the endpoint header");
        assert_eq!(
            (header.endpoint_id, header.stream, header.seq),
            (ENDPOINT, STREAM, seq)
        );
    }
    assert_eq!(node.sensors_row(), Some(received.to_be_bytes().to_vec()));
    assert_eq!(node.last_received(), Some(received.to_be_bytes().to_vec()));
}

#[test]
fn the_stream_and_loss_records_have_their_layouts() {
    let node = Node::new();
    let mut conn = node.connection();
    node.open_stream(&mut conn, STREAM);
    let first = process_create(ENDPOINT, STREAM, 1, BASE, "a.exe");
    node.answer(&mut conn, batch(STREAM, vec![first.clone()]));

    let mut stream_key = ENTRY.as_bytes().to_vec();
    stream_key.extend_from_slice(ENDPOINT.as_bytes());
    stream_key.extend_from_slice(STREAM.as_bytes());
    assert_eq!(
        endpoint_stream_key(ENTRY, ENDPOINT, STREAM).as_slice(),
        stream_key
    );
    let value = node
        .db
        .get_cf_for_test(ENDPOINT_STREAMS_CF, &stream_key)
        .unwrap()
        .expect("the stream's state");
    let expected: StreamTuple = (1, Some((1, record_hash(&first))), None);
    assert_eq!(value, bincode::serialize(&expected).unwrap());

    let before = nanos_of(Timestamp::now());
    let dropped = TelemetryMessage::DroppedRange(DroppedRange {
        stream: STREAM,
        from: 2,
        to: 3,
        reason: DropReason::BufferOverflow,
    });
    assert_eq!(node.send(&mut conn, dropped), reply(vec![ack(STREAM, 3)]));
    let lost = TelemetryMessage::LostOnReset(LostOnReset {
        old_stream: STREAM,
        ranges: vec![SeqRange { from: 7, to: 9 }],
    });
    assert_eq!(node.send(&mut conn, lost), reply(Vec::new()));
    let bad = unconvertible(ENDPOINT, STREAM, 4);
    assert_eq!(
        node.send(&mut conn, batch(STREAM, vec![bad.clone()])),
        reply(vec![ack(STREAM, 4)])
    );
    let after = nanos_of(Timestamp::now());

    let losses = node.losses();
    assert_eq!(losses.len(), 3);
    let expected = [
        (2_u64, 3_u64, 0_u8, b"buffer_overflow".to_vec()),
        (4, 4, 2, convert_error(&bad).into_bytes()),
        (7, 9, 1, Vec::new()),
    ];
    for ((key, value), (from, to, code, detail)) in losses.iter().zip(expected) {
        assert_eq!(key.len(), 16 * 3 + 8 + 8 + 1 + 8);
        let mut prefix = stream_key.clone();
        prefix.extend_from_slice(&from.to_be_bytes());
        prefix.extend_from_slice(&to.to_be_bytes());
        prefix.push(code);
        assert_eq!(&key[..prefix.len()], prefix.as_slice());
        let received = i64::from_be_bytes(key[prefix.len()..].try_into().unwrap());
        assert!((before..=after).contains(&received), "the received time");
        let reason = match code {
            0 => LossReason::Dropped,
            1 => LossReason::LostOnReset,
            _ => LossReason::ConversionFailure,
        };
        assert_eq!(
            endpoint_loss_key(ENTRY, ENDPOINT, STREAM, from, to, reason, received).as_slice(),
            key.as_slice()
        );
        assert_eq!(*value, detail);
    }

    let close = TelemetryMessage::CloseStream(CloseStream { stream: STREAM });
    assert_eq!(node.send(&mut conn, close), reply(Vec::new()));
    let state = node.state(STREAM).expect("a closed stream is remembered");
    let closed = state.closed_at_ns.expect("closed");
    assert!(closed >= after);
    // The crate takes an unconvertible record as stored: `L` is its number.
    let expected: StreamTuple = (4, Some((4, record_hash(&bad))), Some(closed));
    assert_eq!(
        node.db
            .get_cf_for_test(ENDPOINT_STREAMS_CF, &stream_key)
            .unwrap(),
        Some(bincode::serialize(&expected).unwrap())
    );
}

#[test]
fn a_failed_write_leaves_neither_records_nor_state() {
    let node = Node::new();
    let mut conn = node.connection();
    node.open_stream(&mut conn, STREAM);
    let first = process_create(ENDPOINT, STREAM, 1, BASE, "a.exe");
    node.flows.controls().fail_writes(true);
    assert_eq!(
        node.send(&mut conn, batch(STREAM, vec![first.clone()])),
        ReceiverOutput::Disconnect
    );
    assert!(node.records().is_empty(), "nothing is stored");
    assert_eq!(node.state(STREAM).map(|state| state.a), Some(0));
    assert_eq!(node.last_received(), None);
    assert_eq!(node.sensors_row(), None);

    node.flows.controls().fail_writes(false);
    let mut conn = node.connection();
    assert_eq!(node.open_stream(&mut conn, STREAM).a, 0);
    assert_eq!(
        node.send(&mut conn, batch(STREAM, vec![first])),
        reply(vec![ack(STREAM, 1)])
    );
    assert_eq!(node.records().len(), 1);
}

/// What a crash leaves is what is in the files: the copy is taken while the
/// database is open, with nothing flushed or shut down, and holds both the
/// records and the stream state the write acknowledged.
#[test]
fn a_batch_is_on_disk_once_its_write_returns() {
    let node = Node::new();
    let crashed = tempfile::tempdir().expect("tempdir");
    let mut conn = node.connection();
    node.open_stream(&mut conn, STREAM);
    let first = process_create(ENDPOINT, STREAM, 1, BASE, "a.exe");
    assert_eq!(
        node.send(&mut conn, batch(STREAM, vec![first])),
        reply(vec![ack(STREAM, 1)])
    );
    for file in std::fs::read_dir(node.dir.path()).expect("list the database files") {
        let file = file.expect("a database file");
        if file.file_type().expect("its type").is_file() {
            std::fs::copy(file.path(), crashed.path().join(file.file_name()))
                .expect("copy a database file");
        }
    }
    let recovered = Database::open(crashed.path(), &DbOptions::default()).expect("recover");
    assert_eq!(
        stored_state(&recovered, ENTRY, ENDPOINT, STREAM).map(|state| state.a),
        Some(1)
    );
    assert_eq!(stored_seqs(&recovered, &ENDPOINT.to_string(), STREAM), [1]);
}

#[test]
fn records_never_share_a_key() {
    let node = Node::new();
    let mut conn = node.connection();
    node.open_stream(&mut conn, STREAM);
    // Already stored, by another sender, byte for byte what record 3 is
    // stored as.
    let third = process_create(ENDPOINT, STREAM, 3, BASE + 10, "c.exe");
    let store = node.db.process_create_store().unwrap();
    store
        .append(
            &record_key(&ENDPOINT.to_string(), BASE + 10),
            &stored_value(&third),
        )
        .unwrap();

    let records = vec![
        process_create(ENDPOINT, STREAM, 1, BASE, "a.exe"),
        process_create(ENDPOINT, STREAM, 2, BASE, "b.exe"),
        third.clone(),
    ];
    assert_eq!(
        node.send(&mut conn, batch(STREAM, records)),
        reply(vec![ack(STREAM, 3)])
    );
    let stored: Vec<(i64, String)> = node
        .records()
        .into_iter()
        .map(|(time, record)| (time, record.image))
        .collect();
    assert_eq!(
        stored,
        [
            (BASE, "a.exe".to_owned()),
            (BASE + 1, "b.exe".to_owned()),
            (BASE + 10, "c.exe".to_owned()),
            (BASE + 11, "c.exe".to_owned()),
        ],
        "same-time records of one batch, and a record identical to one stored, take the next \
         free keys"
    );
}

#[test]
fn a_record_finding_no_free_key_writes_nothing_of_its_batch() {
    let (logs, _guard) = crate::test_bootroot::capture_logs();
    let node = Node::open(tempfile::tempdir().expect("tempdir"), Some(2));
    let sensor = ENDPOINT.to_string();
    let store = node.db.process_create_store().unwrap();
    let taken = stored_value(&process_create(
        ENDPOINT,
        OTHER_STREAM,
        9,
        BASE,
        "taken.exe",
    ));
    for time in [BASE, BASE + 1, i64::MAX] {
        store.append(&record_key(&sensor, time), &taken).unwrap();
    }
    let sent = |node: &Node| -> Vec<i64> {
        node.records()
            .into_iter()
            .filter(|(_, record)| record.image != "taken.exe")
            .map(|(time, _)| time)
            .collect()
    };
    let mut conn = node.connection();
    node.open_stream(&mut conn, STREAM);
    let free = process_create(ENDPOINT, STREAM, 1, BASE + 50, "free.exe");
    let crowded = process_create(ENDPOINT, STREAM, 2, BASE, "crowded.exe");
    // Past the probe limit.
    assert_eq!(
        node.send(
            &mut conn,
            batch(STREAM, vec![free.clone(), crowded.clone()])
        ),
        ReceiverOutput::Disconnect
    );
    assert!(sent(&node).is_empty(), "nothing of the batch is stored");
    assert_eq!(node.state(STREAM).map(|state| state.a), Some(0));
    assert_eq!((node.last_received(), node.sensors_row()), (None, None));
    let logged = logs.contents();
    assert!(
        logged.contains("ERROR")
            && logged.contains(&format!(
                "Endpoint {ENDPOINT}, stream {STREAM}: the batch was not written"
            ))
            && logged.contains("are all taken"),
        "{logged}"
    );

    // Past i64::MAX.
    let mut conn = node.connection();
    node.open_stream(&mut conn, STREAM);
    let last = process_create(ENDPOINT, STREAM, 1, i64::MAX, "last.exe");
    assert_eq!(
        node.send(&mut conn, batch(STREAM, vec![last.clone()])),
        ReceiverOutput::Disconnect
    );
    assert!(sent(&node).is_empty(), "nothing is stored");
    assert!(
        logs.contents().contains("up to i64::MAX"),
        "{}",
        logs.contents()
    );

    // Once keys are free, the endpoint's resend is stored.
    store.delete(&record_key(&sensor, BASE + 1)).unwrap();
    store.delete(&record_key(&sensor, i64::MAX)).unwrap();
    let mut conn = node.connection();
    assert_eq!(node.open_stream(&mut conn, STREAM).a, 0);
    assert_eq!(
        node.send(&mut conn, batch(STREAM, vec![free, crowded])),
        reply(vec![ack(STREAM, 2)])
    );
    let other = process_create(ENDPOINT, STREAM, 3, i64::MAX, "last.exe");
    assert_eq!(
        node.send(&mut conn, batch(STREAM, vec![other])),
        reply(vec![ack(STREAM, 3)])
    );
    assert_eq!(sent(&node), [BASE + 1, BASE + 50, i64::MAX]);
    drop(last);
}

#[test]
fn an_unconvertible_record_is_a_loss_and_the_rest_is_stored() {
    let node = Node::new();
    let mut conn = node.connection();
    node.open_stream(&mut conn, STREAM);
    let records = vec![
        process_create(ENDPOINT, STREAM, 1, BASE, "a.exe"),
        unconvertible(ENDPOINT, STREAM, 2),
        process_create(ENDPOINT, STREAM, 3, BASE + 2, "c.exe"),
    ];
    let third_hash = record_hash(&records[2]);
    assert_eq!(
        node.send(&mut conn, batch(STREAM, records)),
        reply(vec![ack(STREAM, 3)])
    );
    assert_eq!(stored_seqs(&node.db, &ENDPOINT.to_string(), STREAM), [1, 3]);
    let losses = node.losses();
    assert_eq!(losses.len(), 1);
    let (key, _) = &losses[0];
    let mut prefix = endpoint_stream_key(ENTRY, ENDPOINT, STREAM).to_vec();
    prefix.extend_from_slice(&2_u64.to_be_bytes());
    prefix.extend_from_slice(&2_u64.to_be_bytes());
    prefix.push(2);
    assert!(key.starts_with(&prefix));
    assert_eq!(
        node.state(STREAM).and_then(|state| state.last_stored),
        Some((3, third_hash))
    );
}

#[test]
fn a_write_whose_records_all_fail_to_convert_still_sets_the_last_received_time() {
    let node = Node::new();
    let mut conn = node.connection();
    node.open_stream(&mut conn, STREAM);
    let before = nanos_of(Timestamp::now());
    let (output, stored_at) = node.send_reporting(
        &mut conn,
        batch(STREAM, vec![unconvertible(ENDPOINT, STREAM, 1)]),
    );
    assert_eq!(output, reply(vec![ack(STREAM, 1)]));
    assert_eq!(stored_at, None, "no record was stored");
    let last = node.last_received().expect("the last received time");
    let last = i64::from_be_bytes(last.try_into().unwrap());
    assert!(last >= before);
    assert_eq!(node.sensors_row(), None, "no record, no sensors row");
    assert!(node.records().is_empty(), "nothing is stored");

    // A write without records leaves it.
    let dropped = TelemetryMessage::DroppedRange(DroppedRange {
        stream: STREAM,
        from: 2,
        to: 2,
        reason: DropReason::RetentionExpired,
    });
    node.answer(&mut conn, dropped);
    assert_eq!(node.last_received(), Some(last.to_be_bytes().to_vec()));
}

#[test]
fn dropped_and_lost_ranges_are_recorded_once_each() {
    let node = Node::new();
    let mut conn = node.connection();
    node.open_stream(&mut conn, STREAM);
    node.answer(
        &mut conn,
        batch(
            STREAM,
            vec![process_create(ENDPOINT, STREAM, 1, BASE, "a.exe")],
        ),
    );
    let dropped = TelemetryMessage::DroppedRange(DroppedRange {
        stream: STREAM,
        from: 1,
        to: 3,
        reason: DropReason::BufferOverflow,
    });
    assert_eq!(
        node.send(&mut conn, dropped.clone()),
        reply(vec![ack(STREAM, 3)])
    );
    let losses = node.losses();
    assert_eq!(losses.len(), 1, "only the new tail, 2 to 3, is a loss");
    assert!(losses[0].0.starts_with(&{
        let mut prefix = endpoint_stream_key(ENTRY, ENDPOINT, STREAM).to_vec();
        prefix.extend_from_slice(&2_u64.to_be_bytes());
        prefix.extend_from_slice(&3_u64.to_be_bytes());
        prefix.push(0);
        prefix
    }));
    let writes = node.flows.controls().writes();
    assert_eq!(node.send(&mut conn, dropped), reply(vec![ack(STREAM, 3)]));
    assert_eq!(
        node.losses().len(),
        1,
        "a repeated dropped range changes nothing"
    );
    assert_eq!(node.flows.controls().writes(), writes);

    let lost = TelemetryMessage::LostOnReset(LostOnReset {
        old_stream: STREAM,
        ranges: vec![SeqRange { from: 2, to: 3 }],
    });
    assert!(
        !node
            .db
            .has_endpoint_lost_on_reset(ENTRY, ENDPOINT, STREAM, 2, 3)
            .unwrap(),
        "a dropped loss is not a lost-on-reset one"
    );
    node.answer(&mut conn, lost.clone());
    assert_eq!(
        node.losses().len(),
        2,
        "a dropped and a lost loss of one range both stay"
    );
    assert!(
        node.db
            .has_endpoint_lost_on_reset(ENTRY, ENDPOINT, STREAM, 2, 3)
            .unwrap()
    );
    assert!(
        !node
            .db
            .has_endpoint_lost_on_reset(ENTRY, ENDPOINT, STREAM, 2, 4)
            .unwrap()
    );
    let mut again = node.connection();
    node.answer(&mut again, lost);
    assert_eq!(
        node.losses().len(),
        2,
        "a lost range received again adds nothing"
    );
}

#[test]
fn the_receiving_rules_are_the_crates() {
    let node = Node::new();
    let mut conn = node.connection();
    node.open_stream(&mut conn, STREAM);
    let records: Vec<Vec<u8>> = (1..=3)
        .map(|seq| {
            process_create(
                ENDPOINT,
                STREAM,
                seq,
                BASE + 10 * i64::try_from(seq).unwrap(),
                "p.exe",
            )
        })
        .collect();

    // Only A + 1 is taken.
    assert_eq!(
        node.send(&mut conn, batch(STREAM, vec![records[1].clone()])),
        reply(vec![
            ack(STREAM, 0),
            error(STREAM, TelemetryError::Gap { expected: 1 })
        ])
    );
    assert!(node.records().is_empty(), "nothing is stored");
    assert_eq!(
        node.send(&mut conn, batch(STREAM, records[..2].to_vec())),
        reply(vec![ack(STREAM, 2)])
    );
    // A resent batch at or below A is acknowledged without a write.
    let writes = node.flows.controls().writes();
    assert_eq!(
        node.send(&mut conn, batch(STREAM, records[..2].to_vec())),
        reply(vec![ack(STREAM, 2)])
    );
    assert_eq!(node.flows.controls().writes(), writes);
    assert_eq!(stored_seqs(&node.db, &ENDPOINT.to_string(), STREAM), [1, 2]);

    // A kind outside the hello_ack stores what came before it and keeps the
    // connection.
    let unsupported = vec![records[2].clone(), unaccepted(ENDPOINT, STREAM, 4)];
    assert_eq!(
        node.send(&mut conn, batch(STREAM, unsupported)),
        reply(vec![
            ack(STREAM, 3),
            error(STREAM, TelemetryError::UnsupportedKind)
        ])
    );
    assert_eq!(
        stored_seqs(&node.db, &ENDPOINT.to_string(), STREAM),
        [1, 2, 3]
    );

    // A record naming another endpoint stores nothing of its batch and
    // closes the connection.
    let foreign = vec![
        process_create(ENDPOINT, STREAM, 4, BASE + 40, "p.exe"),
        process_create(OTHER_ENDPOINT, STREAM, 5, BASE + 50, "p.exe"),
    ];
    assert_eq!(
        node.send(&mut conn, batch(STREAM, foreign)),
        ReceiverOutput::Disconnect
    );
    assert_eq!(
        stored_seqs(&node.db, &ENDPOINT.to_string(), STREAM),
        [1, 2, 3]
    );
    assert!(
        stored_records(&node.db, &OTHER_ENDPOINT.to_string()).is_empty(),
        "nothing is stored"
    );

    // A closed stream is refused.
    let mut conn = node.connection();
    node.open_stream(&mut conn, STREAM);
    node.answer(
        &mut conn,
        TelemetryMessage::CloseStream(CloseStream { stream: STREAM }),
    );
    assert_eq!(
        node.send(
            &mut conn,
            TelemetryMessage::OpenStream(OpenStream { stream: STREAM })
        ),
        reply(vec![error(STREAM, TelemetryError::Closed)])
    );
}

#[test]
fn prune_forgets_streams_closed_thirty_days_ago_and_keeps_their_records() {
    let node = Node::new();
    let mut conn = node.connection();
    for stream in [STREAM, OTHER_STREAM] {
        // Opening the second closes the first.
        node.open_stream(&mut conn, stream);
        node.answer(
            &mut conn,
            batch(
                stream,
                vec![process_create(ENDPOINT, stream, 1, BASE, "p.exe")],
            ),
        );
        node.answer(
            &mut conn,
            TelemetryMessage::DroppedRange(DroppedRange {
                stream,
                from: 2,
                to: 2,
                reason: DropReason::TooLarge,
            }),
        );
    }
    node.answer(
        &mut conn,
        TelemetryMessage::CloseStream(CloseStream {
            stream: OTHER_STREAM,
        }),
    );
    let first = node
        .state(STREAM)
        .and_then(|state| state.closed_at_ns)
        .expect("closed");
    let second = node
        .state(OTHER_STREAM)
        .and_then(|state| state.closed_at_ns)
        .expect("closed");
    assert!(first < second);

    node.flows.prune(ts(first) + RECEIVER_CLOSED_RETENTION);
    assert_eq!(node.state(STREAM), None, "closed 30 days ago: forgotten");
    assert!(
        node.state(OTHER_STREAM).is_some(),
        "closed less than 30 days ago: kept"
    );
    assert_eq!(node.records().len(), 2, "the records stay");
    assert_eq!(node.losses().len(), 2, "the losses stay");

    // The stream's id is new to the entry again.
    let mut conn = node.connection();
    assert_eq!(node.open_stream(&mut conn, STREAM).a, 0);
}

// ---------------------------------------------------------------------------
// The entry_id and the stream held
// ---------------------------------------------------------------------------

#[test]
fn a_new_entry_id_forgets_the_old_streams_and_keeps_their_losses() {
    let node = Node::new();
    let mut conn = node.connection();
    node.open_stream(&mut conn, STREAM);
    node.answer(
        &mut conn,
        batch(
            STREAM,
            vec![process_create(ENDPOINT, STREAM, 1, BASE, "a.exe")],
        ),
    );
    node.answer(
        &mut conn,
        TelemetryMessage::DroppedRange(DroppedRange {
            stream: STREAM,
            from: 2,
            to: 4,
            reason: DropReason::BufferOverflow,
        }),
    );

    // A failure changes nothing.
    node.flows.controls().fail_writes(true);
    assert!(
        node.flows
            .lock()
            .change_entry_id(OTHER_ENTRY, Some(ENTRY))
            .is_err()
    );
    node.flows.controls().fail_writes(false);
    assert_eq!(node.db.endpoint_entry_id().unwrap(), Some(ENTRY));
    assert_eq!(node.flows.entry_id(), Some(ENTRY));
    assert_eq!(node.state(STREAM).map(|state| state.a), Some(4));

    node.flows
        .lock()
        .change_entry_id(OTHER_ENTRY, Some(ENTRY))
        .expect("the entry_id changes");
    assert_eq!(node.db.endpoint_entry_id().unwrap(), Some(OTHER_ENTRY));
    assert_eq!(node.flows.entry_id(), Some(OTHER_ENTRY));
    assert!(
        node.db.endpoint_streams(ENTRY).unwrap().is_empty(),
        "no stream state is stored"
    );
    assert_eq!(node.losses().len(), 1, "the old entry_id's losses stay");
    assert_eq!(node.records().len(), 1, "the records stay");

    let mut conn = node.connection();
    assert_eq!(
        node.open_stream(&mut conn, STREAM).a,
        0,
        "the stream starts empty"
    );
    assert!(stored_state(&node.db, OTHER_ENTRY, ENDPOINT, STREAM).is_some());
}

#[test]
fn without_an_entry_id_no_stream_is_held_until_one_is_stored() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = Database::open(dir.path(), &DbOptions::default()).expect("open the database");
    let flows = EndpointFlows::new(db.clone());
    assert_eq!(flows.entry_id(), None);
    let mut conn = ReceiverConnection::new(ENDPOINT, convert::accepted_kinds());
    let handled = flows.handle(
        &CancellationToken::new(),
        &mut conn,
        Delivered::Message(TelemetryMessage::OpenStream(OpenStream { stream: STREAM })),
    );
    assert!(matches!(
        handled,
        Handled::Done {
            output: ReceiverOutput::Disconnect,
            ..
        }
    ));
    flows
        .lock()
        .change_entry_id(ENTRY, None)
        .expect("the first entry_id is stored");
    assert_eq!(flows.entry_id(), Some(ENTRY));
    assert_eq!(db.endpoint_entry_id().unwrap(), Some(ENTRY));
}

#[test]
fn a_stream_state_that_cannot_be_read_is_read_again_at_the_next_call() {
    let node = Node::new();
    let mut conn = node.connection();
    node.open_stream(&mut conn, STREAM);
    let key = endpoint_stream_key(ENTRY, ENDPOINT, STREAM);
    let good = node
        .db
        .get_cf_for_test(ENDPOINT_STREAMS_CF, &key)
        .unwrap()
        .unwrap();
    node.db
        .put_cf_for_test(ENDPOINT_STREAMS_CF, &key, b"garbage")
        .unwrap();

    let flows = EndpointFlows::new(node.db.clone());
    assert_eq!(flows.entry_id(), None, "the state does not decode");
    let mut conn = node.connection();
    let handled = flows.handle(
        &CancellationToken::new(),
        &mut conn,
        Delivered::Message(TelemetryMessage::OpenStream(OpenStream { stream: STREAM })),
    );
    assert!(matches!(
        handled,
        Handled::Done {
            output: ReceiverOutput::Disconnect,
            ..
        }
    ));

    node.db
        .put_cf_for_test(ENDPOINT_STREAMS_CF, &key, &good)
        .unwrap();
    assert_eq!(flows.entry_id(), Some(ENTRY), "read again once it can be");
}

#[test]
fn a_stopped_connection_writes_nothing() {
    let node = Node::new();
    let mut conn = node.connection();
    let stop = CancellationToken::new();
    stop.cancel();
    let handled = node.flows.handle(
        &stop,
        &mut conn,
        Delivered::Message(TelemetryMessage::OpenStream(OpenStream { stream: STREAM })),
    );
    assert!(matches!(handled, Handled::Stopped));
    assert_eq!(node.state(STREAM), None);
}

#[test]
fn an_oversize_batch_is_answered_too_large() {
    let node = Node::new();
    let mut conn = node.connection();
    node.open_stream(&mut conn, STREAM);
    let handled = node.flows.handle(
        &CancellationToken::new(),
        &mut conn,
        Delivered::BatchTooLarge(STREAM),
    );
    match handled {
        Handled::Done { output, stored_at } => {
            assert_eq!(output, reply(vec![error(STREAM, TelemetryError::TooLarge)]));
            assert_eq!(stored_at, None);
        }
        Handled::Stopped => panic!("not stopped"),
    }
}

#[test]
fn retention_deletes_old_endpoint_records() {
    let node = Node::new();
    let mut conn = node.connection();
    node.open_stream(&mut conn, STREAM);
    let records = vec![
        process_create(ENDPOINT, STREAM, 1, BASE, "old.exe"),
        process_create(ENDPOINT, STREAM, 2, BASE + 10, "new.exe"),
    ];
    node.answer(&mut conn, batch(STREAM, records));
    node.db.retain_older_than_for_test(BASE + 5).unwrap();
    let images: Vec<String> = node.records().into_iter().map(|(_, r)| r.image).collect();
    assert_eq!(
        images,
        ["new.exe"],
        "the endpoint is a sensor retention walks"
    );
}

// ---------------------------------------------------------------------------
// A process killed while it writes
// ---------------------------------------------------------------------------

/// Names the directory the child writes batches into, and marks the child.
const KILL_DIR_ENV: &str = "GIGANTO_TEST_ENDPOINT_KILL_DIR";
/// What the child prints after each batch it wrote.
const WRITTEN_MARK: &str = "endpoint-batch-written";
/// How many batches the parent waits for before it kills the child.
const BATCHES_BEFORE_KILL: usize = 40;

/// A process killed during writes leaves every batch whole or absent: the
/// child, this test run again, writes batches until it is killed with
/// `SIGKILL`; the database it leaves holds, for every stream, an `A` equal
/// to the highest sequence number among the stream's stored records, and
/// the endpoint's resend on the same stream stores no record twice.
#[test]
fn a_killed_process_leaves_every_batch_whole_or_absent() {
    use std::io::BufRead;

    if let Some(dir) = std::env::var_os(KILL_DIR_ENV) {
        write_until_killed(std::path::Path::new(&dir));
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let name = module_path!()
        .split_once("::")
        .map_or(module_path!(), |(_, path)| path);
    let mut child = std::process::Command::new(std::env::current_exe().expect("the test binary"))
        .args([
            &format!("{name}::a_killed_process_leaves_every_batch_whole_or_absent"),
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(KILL_DIR_ENV, dir.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("run the child");
    let stdout = child.stdout.take().expect("the child's stdout");
    let written = std::io::BufReader::new(stdout)
        .lines()
        .map_while(Result::ok)
        .filter(|line| line.starts_with(WRITTEN_MARK))
        .take(BATCHES_BEFORE_KILL)
        .count();
    child.kill().expect("kill the child");
    child.wait().expect("reap the child");
    assert_eq!(written, BATCHES_BEFORE_KILL, "the child wrote batches");

    let node = Node::open(dir, None);
    let sensor = ENDPOINT.to_string();
    let streams = node.db.endpoint_streams(ENTRY).unwrap();
    assert!(!streams.is_empty(), "nothing is left");
    for ((_, stream), state) in &streams {
        let seqs = stored_seqs(&node.db, &sensor, *stream);
        assert_eq!(
            seqs.iter().max().copied().unwrap_or(0),
            state.a,
            "stream {stream}: A is the last record stored"
        );
        let mut unique = seqs.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), seqs.len());
    }

    // The endpoint resends everything it sent on the open stream.
    let ((_, stream), state) = streams
        .iter()
        .find(|(_, state)| state.closed_at_ns.is_none())
        .copied()
        .expect("the open stream");
    let mut conn = node.connection();
    assert_eq!(node.open_stream(&mut conn, stream).a, state.a);
    let resend: Vec<Vec<u8>> = (1..=state.a + 3)
        .map(|seq| killed_record(stream, seq))
        .collect();
    for chunk in resend.chunks(8) {
        let output = node.send(&mut conn, batch(stream, chunk.to_vec()));
        assert!(matches!(output, ReceiverOutput::Reply(_)), "{output:?}");
    }
    let mut seqs = stored_seqs(&node.db, &sensor, stream);
    seqs.sort_unstable();
    let expected: Vec<u64> = (1..=state.a + 3).collect();
    assert_eq!(seqs, expected, "no record stored twice, none missing");
}

/// The record `seq` of `stream` the child writes.
fn killed_record(stream: Uuid, seq: u64) -> Vec<u8> {
    let time = BASE + i64::try_from(seq).unwrap();
    process_create(ENDPOINT, stream, seq, time, "killed.exe")
}

/// Writes batches of five records into the database in `dir` until the
/// process is killed, printing a mark after each.
fn write_until_killed(dir: &std::path::Path) {
    let db = Database::open(dir, &DbOptions::default()).expect("open the database");
    db.replace_endpoint_entry_id(ENTRY, None)
        .expect("store the entry_id");
    let flows = EndpointFlows::new(db);
    let mut conn = ReceiverConnection::new(ENDPOINT, convert::accepted_kinds());
    let stop = CancellationToken::new();
    let mut send = |message| match flows.handle(&stop, &mut conn, Delivered::Message(message)) {
        Handled::Done {
            output: ReceiverOutput::Reply(_),
            ..
        } => {}
        other => panic!("{other:?}"),
    };
    send(TelemetryMessage::OpenStream(OpenStream { stream: STREAM }));
    let mut seq = 0;
    loop {
        let records = (seq + 1..=seq + 5)
            .map(|seq| killed_record(STREAM, seq))
            .collect();
        send(batch(STREAM, records));
        seq += 5;
        println!("{WRITTEN_MARK} {seq}");
    }
}

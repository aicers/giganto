//! The reconnection decisions of RFC 0014 §4.12, one scene per step, with a
//! senta-protocol `SenderStream` as the endpoint and the node's streams over
//! RocksDB as the entry. In each, no stored record is lost and no record of
//! one stream is stored twice.

use std::time::Duration;

use jiff::{SignedDuration, Timestamp};
use senta_protocol::{
    connection::TelemetryEntry,
    telemetry::{
        DroppedRange, MemorySenderStore, ReceiverConnection, ReceiverOutput, SenderAction,
        SenderConfig, SenderConnection, SenderStream, TelemetryMessage,
    },
    telemetry_codes::DropReason,
};
use uuid::Uuid;

use super::{ENDPOINT, ENTRY, Node, header, process_create_record, stored_records};
use crate::{
    comm::endpoint::convert,
    storage::endpoint::{ENDPOINT_LOSSES_CF, ENDPOINT_STREAMS_CF, endpoint_stream_key},
};

/// The fake endpoint: the sender's stream, its connection to the node, and
/// the node's state of that connection.
struct Endpoint {
    sender: SenderStream<MemorySenderStore>,
    connection: Option<(SenderConnection, ReceiverConnection)>,
    wall: Timestamp,
    now: Duration,
    next_stream: u128,
}

impl Endpoint {
    /// An endpoint whose state is `store`, registered and pointed at the
    /// node's entry.
    fn open(store: MemorySenderStore, wall: Timestamp, next_stream: u128) -> Self {
        let config = SenderConfig::new(1_000, 16 * 1024 * 1024);
        let mut sender =
            SenderStream::open(store, config, Duration::ZERO).expect("open the sender");
        sender.register(ENDPOINT).expect("register");
        sender
            .set_entries(vec![ENTRY], wall, Duration::ZERO)
            .expect("set the entries");
        Self {
            sender,
            connection: None,
            wall,
            now: Duration::ZERO,
            next_stream,
        }
    }

    fn new() -> Self {
        Self::open(MemorySenderStore::new(), Timestamp::now(), 0x5000)
    }

    /// A stream id this endpoint has not used.
    fn fresh_stream(&mut self) -> Uuid {
        self.next_stream += 1;
        Uuid::from_u128(self.next_stream)
    }

    /// Connects to the node and runs the handshake and the reconnection
    /// judgment, with everything the sender sends after it.
    fn connect(&mut self, node: &Node) {
        let connected = self.sender.connect(self.wall, self.now).expect("connect");
        let connection = connected.connection.expect("a target");
        self.connection = Some((connection, node.connection()));
        self.run(node, connected.actions);
        let entry = TelemetryEntry {
            entry_id: ENTRY,
            accepted_kinds: convert::accepted_kinds(),
        };
        let stream = self.fresh_stream();
        let actions = self
            .sender
            .hello_ack(connection, &entry, stream, self.wall, self.now)
            .expect("hello_ack");
        self.run(node, actions);
    }

    /// Ends the connection on both sides.
    fn disconnect(&mut self) {
        if let Some((connection, _)) = self.connection.take() {
            self.sender
                .disconnected(connection, self.wall, self.now)
                .expect("disconnected");
        }
    }

    /// Collects a record whose image is `mark`, sending it if connected.
    fn collect(&mut self, node: &Node, mark: &str) {
        let record = process_create_record(header(Uuid::nil(), Uuid::nil(), 0, super::BASE), mark);
        let actions = self
            .sender
            .collect(record, self.wall, self.now)
            .expect("collect");
        self.run(node, actions);
    }

    /// Carries out `actions`, and the sender's answers to what the node
    /// replies, until nothing is left to do.
    fn run(&mut self, node: &Node, actions: Vec<SenderAction>) {
        let mut pending = std::collections::VecDeque::from(actions);
        while let Some(action) = pending.pop_front() {
            match action {
                SenderAction::Send(message) => {
                    let Some((connection, receiver)) = self.connection.as_mut() else {
                        continue;
                    };
                    let connection = *connection;
                    match node.send(receiver, message) {
                        ReceiverOutput::Reply(replies) => {
                            for reply in replies {
                                let stream = self.fresh_stream();
                                let actions = self
                                    .sender
                                    .receive(connection, &reply, stream, self.wall, self.now)
                                    .expect("receive");
                                pending.extend(actions);
                            }
                        }
                        ReceiverOutput::Disconnect => self.disconnect(),
                    }
                }
                SenderAction::Disconnect => self.connection = None,
                SenderAction::Connect { .. } => {}
            }
        }
    }

    fn stream(&self) -> Uuid {
        self.sender.position().expect("a current stream").stream
    }
}

/// Returns the marks stored on `stream`, by sequence number, and checks
/// that none of its sequence numbers is stored twice.
fn stored_on(node: &Node, stream: Uuid) -> Vec<(u64, String)> {
    let mut stored: Vec<(u64, String)> = stored_records(&node.db, &ENDPOINT.to_string())
        .into_iter()
        .filter_map(|(_, record)| {
            let header = record.endpoint?;
            (header.stream == stream).then_some((header.seq, record.image))
        })
        .collect();
    stored.sort_unstable();
    let mut seqs: Vec<u64> = stored.iter().map(|(seq, _)| *seq).collect();
    seqs.dedup();
    assert_eq!(
        seqs.len(),
        stored.len(),
        "a record of {stream} stored twice"
    );
    stored
}

fn marks(range: std::ops::RangeInclusive<u64>) -> Vec<(u64, String)> {
    range.map(|seq| (seq, format!("mark-{seq}"))).collect()
}

/// Returns the loss records of `stream`, as `(from, to, reason code)`.
fn losses_of(node: &Node, stream: Uuid) -> Vec<(u64, u64, u8)> {
    let prefix = endpoint_stream_key(ENTRY, ENDPOINT, stream);
    node.db
        .entries_for_test(ENDPOINT_LOSSES_CF)
        .expect("read the losses")
        .into_iter()
        .filter(|(key, _)| key.starts_with(&prefix))
        .map(|(key, _)| {
            let rest = &key[prefix.len()..];
            let from = u64::from_be_bytes(rest[..8].try_into().unwrap());
            let to = u64::from_be_bytes(rest[8..16].try_into().unwrap());
            (from, to, rest[16])
        })
        .collect()
}

/// An endpoint connected to `node` that has stored `mark-1` to `mark-{n}`
/// on its stream.
fn sent(node: &Node, n: u64) -> Endpoint {
    let mut endpoint = Endpoint::new();
    endpoint.connect(node);
    for seq in 1..=n {
        endpoint.collect(node, &format!("mark-{seq}"));
    }
    endpoint
}

/// Step 1: the endpoint lost its local state and opens a new stream.
#[test]
fn an_endpoint_that_lost_its_state_opens_a_new_stream() {
    let node = Node::new();
    let mut endpoint = sent(&node, 3);
    let old = endpoint.stream();
    endpoint.disconnect();

    let mut fresh = Endpoint::open(MemorySenderStore::new(), Timestamp::now(), 0x6000);
    fresh.connect(&node);
    let new = fresh.stream();
    assert_ne!(new, old);
    fresh.collect(&node, "mark-new");

    assert_eq!(
        stored_on(&node, old),
        marks(1..=3),
        "the old stream's records stay"
    );
    assert_eq!(stored_on(&node, new), [(1, "mark-new".to_owned())]);
    let old_state = node.state(old).expect("the old stream is remembered");
    assert!(old_state.closed_at_ns.is_some(), "and closed");
}

/// Step 2: the node lost flow state (`A < K`): an older copy of the stream's
/// state is restored and read by a new generation. The endpoint resends the
/// copies it kept on a new stream and reports the rest lost on reset.
#[test]
fn a_node_that_lost_flow_state_gets_the_copies_and_the_rest_reported() {
    let mut node = Node::new();
    let mut endpoint = sent(&node, 2);
    let old = endpoint.stream();
    let key = endpoint_stream_key(ENTRY, ENDPOINT, old);
    let older = node
        .db
        .get_cf_for_test(ENDPOINT_STREAMS_CF, &key)
        .unwrap()
        .unwrap();
    endpoint.collect(&node, "mark-3");
    // A day later the copies of 1 to 3 are gone; those of 4 and 5 are kept.
    endpoint.wall += SignedDuration::from_hours(25);
    endpoint.collect(&node, "mark-4");
    endpoint.collect(&node, "mark-5");
    assert_eq!(node.state(old).map(|state| state.a), Some(5));
    endpoint.disconnect();

    node.db
        .put_cf_for_test(ENDPOINT_STREAMS_CF, &key, &older)
        .unwrap();
    node = node.reopen();
    assert_eq!(node.state(old).map(|state| state.a), Some(2));
    endpoint.connect(&node);
    let new = endpoint.stream();
    assert_ne!(new, old, "A < K opens a new stream");

    assert_eq!(
        stored_on(&node, old),
        marks(1..=5),
        "nothing stored is lost"
    );
    let resent: Vec<String> = stored_on(&node, new).into_iter().map(|(_, m)| m).collect();
    assert_eq!(resent, ["mark-4", "mark-5"], "the copies kept are resent");
    assert!(
        losses_of(&node, old).contains(&(3, 3, 1)),
        "the rest is lost on reset: {:?}",
        losses_of(&node, old)
    );
}

/// Step 3: the endpoint went back to an older state (`M < A`).
#[test]
fn a_rolled_back_endpoint_opens_a_new_stream() {
    let node = Node::new();
    let mut endpoint = sent(&node, 2);
    let old = endpoint.stream();
    let snapshot = endpoint.sender.store().clone();
    endpoint.collect(&node, "mark-3");
    endpoint.collect(&node, "mark-4");
    endpoint.disconnect();

    let mut rolled_back = Endpoint::open(snapshot, endpoint.wall, 0x6000);
    rolled_back.connect(&node);
    let new = rolled_back.stream();
    assert_ne!(new, old, "M < A opens a new stream");
    rolled_back.collect(&node, "mark-again");

    assert_eq!(stored_on(&node, old), marks(1..=4));
    assert_eq!(stored_on(&node, new), [(1, "mark-again".to_owned())]);
}

/// Step 4: the node stored a record past `K` whose hash is not the one of
/// the endpoint's record of that number (`L > K`, `H` differs).
#[test]
fn a_last_stored_record_the_endpoint_does_not_have_opens_a_new_stream() {
    let node = Node::new();
    let mut endpoint = sent(&node, 2);
    let old = endpoint.stream();
    let snapshot = endpoint.sender.store().clone();
    endpoint.collect(&node, "mark-3");
    endpoint.disconnect();

    let mut rolled_back = Endpoint::open(snapshot, endpoint.wall, 0x6000);
    // Another record takes number 3 in the state gone back to.
    rolled_back.collect(&node, "other-3");
    rolled_back.connect(&node);
    let new = rolled_back.stream();
    assert_ne!(new, old, "a hash mismatch past K opens a new stream");

    assert_eq!(stored_on(&node, old), marks(1..=3));
    let resent: Vec<String> = stored_on(&node, new).into_iter().map(|(_, m)| m).collect();
    assert_eq!(resent, ["other-3"]);
}

/// Step 5: `A` covers numbers past `max(L, K)` that no dropped range of
/// the endpoint's state covers.
#[test]
fn an_acknowledged_range_the_endpoint_never_dropped_opens_a_new_stream() {
    let node = Node::new();
    let mut endpoint = sent(&node, 2);
    let old = endpoint.stream();
    let snapshot = endpoint.sender.store().clone();
    // The endpoint dropped 3 and 4, in a state it later goes back from.
    let (_, receiver) = endpoint.connection.as_mut().expect("connected");
    let dropped = TelemetryMessage::DroppedRange(DroppedRange {
        stream: old,
        from: 3,
        to: 4,
        reason: DropReason::BufferOverflow,
    });
    assert!(matches!(
        node.send(receiver, dropped),
        ReceiverOutput::Reply(_)
    ));
    endpoint.disconnect();
    assert_eq!(node.state(old).map(|state| state.a), Some(4));

    let mut rolled_back = Endpoint::open(snapshot, endpoint.wall, 0x6000);
    rolled_back.collect(&node, "other-3");
    rolled_back.collect(&node, "other-4");
    rolled_back.connect(&node);
    let new = rolled_back.stream();
    assert_ne!(
        new, old,
        "an unexplained acknowledged range opens a new stream"
    );

    assert_eq!(stored_on(&node, old), marks(1..=2));
    assert_eq!(losses_of(&node, old), [(3, 4, 0)]);
    let resent: Vec<String> = stored_on(&node, new).into_iter().map(|(_, m)| m).collect();
    assert_eq!(resent, ["other-3", "other-4"]);
}

/// Step 6: a normal resume continues the same stream from `A + 1`, also
/// after the database is opened again by a new generation.
#[test]
fn a_normal_resume_continues_the_same_stream() {
    let mut node = Node::new();
    let mut endpoint = sent(&node, 2);
    let stream = endpoint.stream();
    endpoint.disconnect();
    endpoint.collect(&node, "mark-3");

    endpoint.connect(&node);
    assert_eq!(endpoint.stream(), stream);
    endpoint.collect(&node, "mark-4");
    endpoint.disconnect();
    endpoint.collect(&node, "mark-5");

    node = node.reopen();
    endpoint.connect(&node);
    assert_eq!(
        endpoint.stream(),
        stream,
        "the stored A survives the new generation"
    );
    endpoint.collect(&node, "mark-6");

    assert_eq!(stored_on(&node, stream), marks(1..=6));
    assert_eq!(node.state(stream).map(|state| state.a), Some(6));
}

/// Customer data deletion deletes a blocked endpoint's stream states while
/// another endpoint's stream is open: that endpoint's `SenderStream` goes on
/// sending on the same stream, on the same connection, and every record it
/// sends is stored.
#[test]
fn deleting_a_blocked_endpoints_streams_keeps_another_endpoints_stream_open() {
    let node = Node::new();
    let mut endpoint = sent(&node, 2);
    let stream = endpoint.stream();
    let mut deleted = ReceiverConnection::new(super::OTHER_ENDPOINT, convert::accepted_kinds());
    node.open_stream(&mut deleted, super::OTHER_STREAM);
    let record = super::process_create(
        super::OTHER_ENDPOINT,
        super::OTHER_STREAM,
        1,
        super::BASE,
        "o.exe",
    );
    node.answer(
        &mut deleted,
        super::batch(super::OTHER_STREAM, vec![record]),
    );
    assert!(
        super::stored_state(&node.db, ENTRY, super::OTHER_ENDPOINT, super::OTHER_STREAM).is_some()
    );

    node.db
        .block_endpoints(&[super::OTHER_ENDPOINT], 10)
        .expect("block the endpoint");
    node.flows
        .lock()
        .delete_endpoint_streams(&[super::OTHER_ENDPOINT])
        .expect("delete the blocked endpoint's streams");
    assert!(
        node.db
            .endpoint_streams(ENTRY)
            .unwrap()
            .iter()
            .all(|((endpoint_id, _), _)| *endpoint_id == ENDPOINT),
        "the blocked endpoint's stream states are gone"
    );

    endpoint.collect(&node, "mark-3");
    endpoint.collect(&node, "mark-4");
    assert!(endpoint.connection.is_some(), "the connection is kept");
    assert_eq!(endpoint.stream(), stream, "on the same stream");
    assert_eq!(stored_on(&node, stream), marks(1..=4));
    assert_eq!(node.state(stream).map(|state| state.a), Some(4));
}

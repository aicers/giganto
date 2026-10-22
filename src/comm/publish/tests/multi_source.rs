//! Tests of the multi-source range read and the re-read with status.

use std::str::FromStr;

use futures_util::stream;
use giganto_client::{
    RawEventKind,
    frame::send_raw,
    publish::{
        range::{RangeStatus, RequestMultiSourceRange, SourceStatus},
        receive_range_status,
    },
};
use quinn::VarInt;
use serde::{Serialize, de::DeserializeOwned};

use super::*;
use crate::comm::publish::multi_source::{
    EventSink, PEER_RESPONSE_TIMEOUT, Routing, SourceEvent, merge_source_events,
    process_multi_source_range, process_raw_data_with_status,
};

/// A short peer timeout, so a test that waits one out stays quick.
const SHORT_PEER_TIMEOUT: StdDuration = StdDuration::from_millis(500);
/// How long a test waits for any one frame of a response.
const FRAME_TIMEOUT: StdDuration = StdDuration::from_secs(10);
const MULTI_SOURCE_END: i64 = 1_000_000;
const UNKNOWN_SENSOR: &str = "sensor-nobody-serves";

type Event<P> = (i64, String, Vec<P>);

// ---------------------------------------------------------------------------
// Merge, count and boundary rule over in-memory streams
// ---------------------------------------------------------------------------

/// Collects what the merge writes as `(timestamp, source)` pairs.
#[derive(Default)]
struct Collected(Vec<(i64, usize)>);

impl EventSink for Collected {
    fn emit(&mut self, event: SourceEvent) -> impl Future<Output = anyhow::Result<()>> + Send {
        self.0.push((event.timestamp, event.source));
        std::future::ready(Ok(()))
    }
}

// Builds the successful items of an input stream, which sit beside `Err`
// items in the same `Vec`.
#[allow(clippy::unnecessary_wraps)]
fn ok(timestamp: i64, source: usize) -> Result<SourceEvent, String> {
    Ok(SourceEvent {
        timestamp,
        source,
        frame: Vec::new(),
    })
}

async fn merge(
    inputs: Vec<Vec<Result<SourceEvent, String>>>,
    count: usize,
) -> (Vec<(i64, usize)>, Vec<Option<String>>) {
    let mut inputs: Vec<_> = inputs.into_iter().map(stream::iter).collect();
    let mut sink = Collected::default();
    let failures = merge_source_events(&mut inputs, count, &mut sink)
        .await
        .expect("an in-memory sink does not fail");
    (sink.0, failures)
}

#[tokio::test]
async fn merge_orders_ties_by_source_position() {
    // The inputs are listed out of source order, so the tie order can only
    // come from the source positions.
    let (sent, failures) = merge(
        vec![
            vec![ok(10, 2)],
            vec![ok(10, 0), ok(20, 0)],
            vec![ok(10, 1), ok(15, 1)],
        ],
        10,
    )
    .await;

    assert_eq!(sent, vec![(10, 0), (10, 1), (10, 2), (15, 1), (20, 0)]);
    assert_eq!(failures, vec![None, None, None]);
}

#[tokio::test]
async fn merge_sends_every_event_of_the_source_at_the_cut() {
    let (sent, _) = merge(
        vec![
            vec![ok(10, 0), ok(20, 0), ok(20, 0), ok(20, 0), ok(30, 0)],
            vec![ok(25, 1)],
        ],
        2,
    )
    .await;

    assert_eq!(sent, vec![(10, 0), (20, 0), (20, 0), (20, 0)]);
}

#[tokio::test]
async fn merge_leaves_another_source_at_the_cut_timestamp() {
    let (sent, _) = merge(
        vec![vec![ok(10, 0), ok(20, 0), ok(20, 0)], vec![ok(20, 1)]],
        2,
    )
    .await;

    assert_eq!(sent, vec![(10, 0), (20, 0), (20, 0)]);
}

#[tokio::test]
async fn merge_sends_everything_when_count_exceeds_the_events() {
    let (sent, failures) = merge(vec![vec![ok(1, 0), ok(3, 0)], vec![ok(2, 1)], vec![]], 100).await;

    assert_eq!(sent, vec![(1, 0), (2, 1), (3, 0)]);
    assert_eq!(failures, vec![None, None, None]);
}

#[tokio::test]
async fn merge_sends_nothing_for_a_zero_count() {
    let (sent, _) = merge(vec![vec![ok(1, 0)]], 0).await;

    assert_eq!(sent, Vec::new());
}

#[tokio::test]
async fn merge_keeps_going_past_a_failing_input() {
    let (sent, failures) = merge(
        vec![
            vec![ok(10, 0), Err("broken".to_string()), ok(30, 0)],
            vec![ok(5, 1), ok(15, 1), ok(20, 1)],
        ],
        10,
    )
    .await;

    assert_eq!(sent, vec![(5, 1), (10, 0), (15, 1), (20, 1)]);
    assert_eq!(failures, vec![Some("broken".to_string()), None]);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn multi_source_request(
    kind: &str,
    sources: &[(&str, i64)],
    count: usize,
) -> RequestMultiSourceRange {
    RequestMultiSourceRange {
        kind: kind.to_string(),
        sources: sources
            .iter()
            .map(|(source, start)| ((*source).to_string(), *start))
            .collect(),
        end: MULTI_SOURCE_END,
        count,
    }
}

fn raw_data_request(kind: &str, input: &[(&str, &[i64])]) -> RequestRawData {
    RequestRawData {
        kind: kind.to_string(),
        input: input
            .iter()
            .map(|(source, timestamps)| ((*source).to_string(), timestamps.to_vec()))
            .collect(),
    }
}

/// Sends one request over a new stream of `publish` and reads its response
/// through to the status frame, asserting the stream finishes after it.
async fn request_with_status<P, B>(
    publish: &TestClient,
    code: MessageCode,
    body: B,
) -> (Vec<Event<P>>, RangeStatus)
where
    P: DeserializeOwned,
    B: Serialize,
{
    let (mut send, mut recv) = publish.conn.open_bi().await.expect("open a request stream");
    send_range_data_request(&mut send, code, body)
        .await
        .expect("send the request");
    read_status_response(&mut recv).await
}

async fn read_status_response<P>(recv: &mut RecvStream) -> (Vec<Event<P>>, RangeStatus)
where
    P: DeserializeOwned,
{
    let mut events = Vec::new();
    loop {
        let frame =
            tokio::time::timeout(FRAME_TIMEOUT, receive_range_data::<Option<Event<P>>>(recv))
                .await
                .expect("an event frame or the terminator in time")
                .expect("read an event frame or the terminator");
        match frame {
            Some(event) => events.push(event),
            None => break,
        }
    }
    let status = tokio::time::timeout(FRAME_TIMEOUT, receive_range_status(recv))
        .await
        .expect("the status frame in time")
        .expect("read the status frame");
    let rest = tokio::time::timeout(FRAME_TIMEOUT, recv.read_to_end(1024))
        .await
        .expect("the stream finished in time")
        .expect("the stream finishes after the status frame");
    assert!(rest.is_empty(), "nothing may follow the status frame");
    (events, status)
}

fn order(events: &[Event<u8>]) -> Vec<(i64, &str)> {
    events
        .iter()
        .map(|(timestamp, source, _)| (*timestamp, source.as_str()))
        .collect()
}

fn sorted_order(events: &[Event<u8>]) -> Vec<(i64, &str)> {
    let mut order = order(events);
    order.sort_unstable();
    order
}

fn statuses(status: RangeStatus) -> Vec<(String, SourceStatus)> {
    status.expect("the request should be served")
}

fn served(sources: &[&str]) -> Vec<(String, SourceStatus)> {
    sources
        .iter()
        .map(|source| ((*source).to_string(), SourceStatus::Served))
        .collect()
}

fn insert_conn(db: &Database, sensor: &str, timestamps: &[i64]) {
    let store = db.conn_store().expect("open the conn store");
    for timestamp in timestamps {
        insert_conn_raw_event(&store, sensor, *timestamp);
    }
}

fn insert_time_series(db: &Database, id: &str, timestamps: &[i64]) {
    let store = db
        .periodic_time_series_store()
        .expect("open the time-series store");
    for timestamp in timestamps {
        insert_periodic_time_series_raw_event(&store, id, *timestamp);
    }
}

/// A value that no event type decodes from.
const UNDECODABLE: &[u8] = &[0xff];

fn assert_failed(status: &SourceStatus, needles: &[&str]) {
    let SourceStatus::Failed(reason) = status else {
        panic!("expected a failed source, got {status:?}");
    };
    for needle in needles {
        assert!(
            reason.contains(needle),
            "the reason {reason:?} should contain {needle:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Single node
// ---------------------------------------------------------------------------

#[tokio::test]
async fn multi_source_range_reads_each_source_from_its_own_start() {
    with_test_harness(|harness| {
        Box::pin(async move {
            insert_conn(&harness.db, "src1", &[1, 3, 5]);
            insert_conn(&harness.db, "src 1", &[2, 4, 6]);

            let request = multi_source_request("conn", &[("src1", 3), ("src 1", 2)], 100);
            let (events, status) = request_with_status::<u8, _>(
                &harness.publish,
                MessageCode::MultiSourceRange,
                request,
            )
            .await;

            assert_eq!(
                order(&events),
                vec![
                    (2, "src 1"),
                    (3, "src1"),
                    (4, "src 1"),
                    (5, "src1"),
                    (6, "src 1")
                ]
            );
            assert_eq!(statuses(status), served(&["src1", "src 1"]));

            // The shared end is exclusive.
            let mut request = multi_source_request("conn", &[("src1", 0), ("src 1", 0)], 100);
            request.end = 4;
            let (events, _) = request_with_status::<u8, _>(
                &harness.publish,
                MessageCode::MultiSourceRange,
                request,
            )
            .await;
            assert_eq!(order(&events), vec![(1, "src1"), (2, "src 1"), (3, "src1")]);
        })
    })
    .await;
}

#[tokio::test]
async fn multi_source_range_merges_in_time_order_with_ties_in_source_order() {
    with_test_harness(|harness| {
        Box::pin(async move {
            insert_conn(&harness.db, "src1", &[10, 20]);
            insert_conn(&harness.db, "src 1", &[10, 15]);

            let request = multi_source_request("conn", &[("src 1", 0), ("src1", 0)], 100);
            let (events, _) = request_with_status::<u8, _>(
                &harness.publish,
                MessageCode::MultiSourceRange,
                request,
            )
            .await;

            assert_eq!(
                order(&events),
                vec![(10, "src 1"), (10, "src1"), (15, "src 1"), (20, "src1")]
            );
        })
    })
    .await;
}

#[tokio::test]
async fn multi_source_range_stops_at_the_total_count() {
    with_test_harness(|harness| {
        Box::pin(async move {
            insert_conn(&harness.db, "src1", &[1, 3, 5]);
            insert_conn(&harness.db, "src 1", &[2, 4, 6]);

            let request = multi_source_request("conn", &[("src1", 0), ("src 1", 0)], 4);
            let (events, status) = request_with_status::<u8, _>(
                &harness.publish,
                MessageCode::MultiSourceRange,
                request,
            )
            .await;

            assert_eq!(
                order(&events),
                vec![(1, "src1"), (2, "src 1"), (3, "src1"), (4, "src 1")]
            );
            assert_eq!(statuses(status), served(&["src1", "src 1"]));
        })
    })
    .await;
}

#[tokio::test]
async fn multi_source_range_reports_a_source_no_node_serves() {
    with_test_harness(|harness| {
        Box::pin(async move {
            insert_conn(&harness.db, "src1", &[1]);

            let request = multi_source_request("conn", &[(UNKNOWN_SENSOR, 0), ("src1", 0)], 100);
            let (events, status) = request_with_status::<u8, _>(
                &harness.publish,
                MessageCode::MultiSourceRange,
                request,
            )
            .await;

            assert_eq!(order(&events), vec![(1, "src1")]);
            assert_eq!(
                statuses(status),
                vec![
                    (UNKNOWN_SENSOR.to_string(), SourceStatus::NoNode),
                    ("src1".to_string(), SourceStatus::Served),
                ]
            );
        })
    })
    .await;
}

#[tokio::test]
async fn multi_source_range_reads_a_log_kind_under_its_kind_key() {
    with_test_harness(|harness| {
        Box::pin(async move {
            let store = harness.db.log_store().expect("open the log store");
            insert_log_raw_event(&store, "src1", LOG_KIND, 1);
            insert_log_raw_event(&store, "src1", "another-kind", 2);
            insert_log_raw_event(&store, "src 1", LOG_KIND, 3);

            let request = multi_source_request(LOG_KIND, &[("src1", 0), ("src 1", 0)], 100);
            let (events, status) = request_with_status::<u8, _>(
                &harness.publish,
                MessageCode::MultiSourceRange,
                request,
            )
            .await;

            assert_eq!(order(&events), vec![(1, "src1"), (3, "src 1")]);
            assert_eq!(statuses(status), served(&["src1", "src 1"]));
        })
    })
    .await;
}

#[tokio::test]
async fn multi_source_range_fails_a_source_whose_stored_value_does_not_decode() {
    with_test_harness(|harness| {
        Box::pin(async move {
            insert_conn(&harness.db, "src 1", &[1]);
            harness
                .db
                .conn_store()
                .expect("open the conn store")
                .append(&gen_network_event_key("src1", None, 2), UNDECODABLE)
                .expect("write an undecodable value");

            let request = multi_source_request("conn", &[("src1", 0), ("src 1", 0)], 100);
            let (events, status) = request_with_status::<u8, _>(
                &harness.publish,
                MessageCode::MultiSourceRange,
                request,
            )
            .await;

            assert_eq!(order(&events), vec![(1, "src 1")]);
            let statuses = statuses(status);
            assert_failed(&statuses[0].1, &[]);
            assert_eq!(statuses[1], ("src 1".to_string(), SourceStatus::Served));
        })
    })
    .await;
}

#[tokio::test]
async fn multi_source_range_reads_time_series_by_policy_id() {
    const OTHER_POLICY_ID: &str = "another-policy-not-a-sensor";
    with_test_harness(|harness| {
        Box::pin(async move {
            insert_time_series(&harness.db, TIME_SERIES_POLICY_ID, &[1, 3]);
            insert_time_series(&harness.db, OTHER_POLICY_ID, &[2]);

            let request = multi_source_request(
                "timeseries",
                &[(TIME_SERIES_POLICY_ID, 0), (OTHER_POLICY_ID, 0)],
                100,
            );
            let (events, status) = request_with_status::<f64, _>(
                &harness.publish,
                MessageCode::MultiSourceRange,
                request,
            )
            .await;

            let order: Vec<(i64, &str)> = events
                .iter()
                .map(|(timestamp, source, _)| (*timestamp, source.as_str()))
                .collect();
            assert_eq!(
                order,
                vec![
                    (1, TIME_SERIES_POLICY_ID),
                    (2, OTHER_POLICY_ID),
                    (3, TIME_SERIES_POLICY_ID)
                ]
            );
            let expected =
                bincode::deserialize::<PeriodicTimeSeries>(&gen_periodic_time_series_raw_event())
                    .expect("decode the stored series")
                    .data;
            assert!(events.iter().all(|(_, _, data)| *data == expected));
            assert_eq!(
                statuses(status),
                served(&[TIME_SERIES_POLICY_ID, OTHER_POLICY_ID])
            );
        })
    })
    .await;
}

#[tokio::test]
async fn multi_source_range_refuses_malformed_requests() {
    with_test_harness(|harness| {
        Box::pin(async move {
            let cases: Vec<(&str, RequestMultiSourceRange)> = vec![
                ("no source", multi_source_request("conn", &[], 10)),
                (
                    "duplicate",
                    multi_source_request("conn", &[("src1", 0), ("src1", 5)], 10),
                ),
                (
                    "statistics",
                    multi_source_request("statistics", &[("src1", 0)], 10),
                ),
                ("op_log", multi_source_request("op_log", &[("src1", 0)], 10)),
            ];
            for (label, request) in cases {
                let (events, status) = request_with_status::<u8, _>(
                    &harness.publish,
                    MessageCode::MultiSourceRange,
                    request,
                )
                .await;
                assert_eq!(events, Vec::new(), "{label}: no event may be sent");
                assert!(status.is_err(), "{label}: expected a whole-request failure");
            }

            // A body that is not a `RequestMultiSourceRange` at all.
            let (events, status) =
                request_with_status::<u8, _>(&harness.publish, MessageCode::MultiSourceRange, 0_u8)
                    .await;
            assert_eq!(events, Vec::new());
            assert!(
                status.is_err(),
                "a malformed body is a whole-request failure"
            );
        })
    })
    .await;
}

/// Every kind name the two requests serve, as a client spells it: the kinds
/// `ReqRange` serves, with each alias.
const SERVED_KINDS: &[&str] = &[
    "conn",
    "dns",
    "malformed_dns",
    "rdp",
    "http",
    "smtp",
    "log",
    "ntlm",
    "kerberos",
    "ssh",
    "dce_rpc",
    "dce rpc",
    "ftp",
    "mqtt",
    "timeseries",
    "periodic_time_series",
    "ldap",
    "tls",
    "smb",
    "nfs",
    "bootp",
    "dhcp",
    "radius",
    "icmp",
    "process_create",
    "file_create_time",
    "network_connect",
    "process_terminate",
    "image_load",
    "file_create",
    "registry_value_set",
    "registry_key_rename",
    "file_create_stream_hash",
    "pipe_event",
    "dns_query",
    "dns_event",
    "file_delete",
    "process_tamper",
    "file_delete_detected",
    "netflow5",
    "netflow9",
];

#[tokio::test]
async fn multi_source_requests_serve_every_kind_range_reads_serve() {
    with_test_harness(|harness| {
        Box::pin(async move {
            for kind in SERVED_KINDS {
                // A name that does not parse would be read as a log kind and
                // pass without reaching its own store.
                RawEventKind::from_str(kind).expect("a kind name");
                // Time series are served locally under any ID; for any other
                // kind the source is a sensor no node serves.
                let expected = if matches!(*kind, "timeseries" | "periodic_time_series") {
                    SourceStatus::Served
                } else {
                    SourceStatus::NoNode
                };
                let expected = vec![(UNKNOWN_SENSOR.to_string(), expected)];

                let request = multi_source_request(kind, &[(UNKNOWN_SENSOR, 0)], 10);
                let (_, status) = request_with_status::<u8, _>(
                    &harness.publish,
                    MessageCode::MultiSourceRange,
                    request,
                )
                .await;
                assert_eq!(statuses(status), expected, "multi-source range of {kind}");

                let request = raw_data_request(kind, &[(UNKNOWN_SENSOR, &[1])]);
                let (_, status) = request_with_status::<u8, _>(
                    &harness.publish,
                    MessageCode::RawDataWithStatus,
                    request,
                )
                .await;
                assert_eq!(statuses(status), expected, "raw data with status of {kind}");
            }
        })
    })
    .await;
}

#[tokio::test]
async fn raw_data_with_status_rereads_events_of_a_byte_kind() {
    with_test_harness(|harness| {
        Box::pin(async move {
            insert_conn(&harness.db, "src1", &[1, 2]);
            insert_conn(&harness.db, "src 1", &[3]);

            let request = raw_data_request(
                "conn",
                &[
                    ("src1", &[1, 99]),
                    (UNKNOWN_SENSOR, &[1]),
                    ("src 1", &[3]),
                    ("src1", &[2]),
                ],
            );
            let (events, status) = request_with_status::<u8, _>(
                &harness.publish,
                MessageCode::RawDataWithStatus,
                request,
            )
            .await;

            assert_eq!(
                sorted_order(&events),
                vec![(1, "src1"), (2, "src1"), (3, "src 1")]
            );
            let expected = build_conn_range_payload(1, "src1");
            assert!(events.contains(&expected));
            assert_eq!(
                statuses(status),
                vec![
                    ("src1".to_string(), SourceStatus::Served),
                    (UNKNOWN_SENSOR.to_string(), SourceStatus::NoNode),
                    ("src 1".to_string(), SourceStatus::Served),
                ]
            );
        })
    })
    .await;
}

#[tokio::test]
async fn raw_data_with_status_rereads_a_log_kind_under_its_kind_key() {
    with_test_harness(|harness| {
        Box::pin(async move {
            let store = harness.db.log_store().expect("open the log store");
            insert_log_raw_event(&store, "src1", LOG_KIND, 1);
            insert_log_raw_event(&store, "src1", "another-kind", 2);

            let request = raw_data_request(LOG_KIND, &[("src1", &[1, 2])]);
            let (events, status) = request_with_status::<u8, _>(
                &harness.publish,
                MessageCode::RawDataWithStatus,
                request,
            )
            .await;

            assert_eq!(order(&events), vec![(1, "src1")]);
            assert_eq!(statuses(status), served(&["src1"]));
        })
    })
    .await;
}

#[tokio::test]
async fn raw_data_with_status_reports_an_unknown_sensor() {
    with_test_harness(|harness| {
        Box::pin(async move {
            let request = raw_data_request("conn", &[(UNKNOWN_SENSOR, &[1])]);
            let (events, status) = request_with_status::<u8, _>(
                &harness.publish,
                MessageCode::RawDataWithStatus,
                request,
            )
            .await;

            assert_eq!(events, Vec::new());
            assert_eq!(
                statuses(status),
                vec![(UNKNOWN_SENSOR.to_string(), SourceStatus::NoNode)]
            );
        })
    })
    .await;
}

#[tokio::test]
async fn raw_data_with_status_answers_an_empty_input() {
    with_test_harness(|harness| {
        Box::pin(async move {
            let (events, status) = request_with_status::<u8, _>(
                &harness.publish,
                MessageCode::RawDataWithStatus,
                raw_data_request("conn", &[]),
            )
            .await;

            assert_eq!(events, Vec::new());
            assert_eq!(status, Ok(Vec::new()));
        })
    })
    .await;
}

#[tokio::test]
async fn raw_data_with_status_rereads_time_series_by_policy_id() {
    with_test_harness(|harness| {
        Box::pin(async move {
            insert_time_series(&harness.db, TIME_SERIES_POLICY_ID, &[1, 2]);

            let request = raw_data_request("timeseries", &[(TIME_SERIES_POLICY_ID, &[1, 2, 3])]);
            let (events, status) = request_with_status::<f64, _>(
                &harness.publish,
                MessageCode::RawDataWithStatus,
                request,
            )
            .await;

            let mut timestamps: Vec<i64> =
                events.iter().map(|(timestamp, ..)| *timestamp).collect();
            timestamps.sort_unstable();
            assert_eq!(timestamps, vec![1, 2]);
            assert_eq!(statuses(status), served(&[TIME_SERIES_POLICY_ID]));
        })
    })
    .await;
}

#[tokio::test]
async fn raw_data_with_status_fails_only_the_source_that_does_not_decode() {
    const POLICY_UNDECODABLE: &str = "policy-undecodable";
    with_test_harness(|harness| {
        Box::pin(async move {
            // A byte kind.
            insert_conn(&harness.db, "src 1", &[1]);
            harness
                .db
                .conn_store()
                .expect("open the conn store")
                .append(&gen_network_event_key("src1", None, 1), UNDECODABLE)
                .expect("write an undecodable value");
            let (events, status) = request_with_status::<u8, _>(
                &harness.publish,
                MessageCode::RawDataWithStatus,
                raw_data_request("conn", &[("src1", &[1]), ("src 1", &[1])]),
            )
            .await;
            assert_eq!(order(&events), vec![(1, "src 1")]);
            let statuses_conn = statuses(status);
            assert_failed(&statuses_conn[0].1, &["decoding"]);
            assert_eq!(
                statuses_conn[1],
                ("src 1".to_string(), SourceStatus::Served)
            );

            // A log kind.
            let log_store = harness.db.log_store().expect("open the log store");
            insert_log_raw_event(&log_store, "src 1", LOG_KIND, 1);
            log_store
                .append(
                    &gen_network_event_key("src1", Some(LOG_KIND), 1),
                    UNDECODABLE,
                )
                .expect("write an undecodable value");
            let (events, status) = request_with_status::<u8, _>(
                &harness.publish,
                MessageCode::RawDataWithStatus,
                raw_data_request(LOG_KIND, &[("src1", &[1]), ("src 1", &[1])]),
            )
            .await;
            assert_eq!(order(&events), vec![(1, "src 1")]);
            let statuses_log = statuses(status);
            assert_failed(&statuses_log[0].1, &["decoding"]);
            assert_eq!(statuses_log[1], ("src 1".to_string(), SourceStatus::Served));

            // Time series.
            insert_time_series(&harness.db, TIME_SERIES_POLICY_ID, &[1]);
            harness
                .db
                .periodic_time_series_store()
                .expect("open the time-series store")
                .append(
                    &gen_network_event_key(POLICY_UNDECODABLE, None, 1),
                    UNDECODABLE,
                )
                .expect("write an undecodable value");
            let (events, status) = request_with_status::<f64, _>(
                &harness.publish,
                MessageCode::RawDataWithStatus,
                raw_data_request(
                    "timeseries",
                    &[(POLICY_UNDECODABLE, &[1]), (TIME_SERIES_POLICY_ID, &[1])],
                ),
            )
            .await;
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].1, TIME_SERIES_POLICY_ID);
            let statuses_series = statuses(status);
            assert_failed(&statuses_series[0].1, &["decoding"]);
            assert_eq!(
                statuses_series[1],
                (TIME_SERIES_POLICY_ID.to_string(), SourceStatus::Served)
            );
        })
    })
    .await;
}

#[tokio::test]
async fn raw_data_with_status_refuses_malformed_requests() {
    with_test_harness(|harness| {
        Box::pin(async move {
            let (events, status) = request_with_status::<u8, _>(
                &harness.publish,
                MessageCode::RawDataWithStatus,
                raw_data_request("statistics", &[("src1", &[1])]),
            )
            .await;
            assert_eq!(events, Vec::new());
            assert!(
                status.is_err(),
                "an unserved kind is a whole-request failure"
            );

            let (events, status) = request_with_status::<u8, _>(
                &harness.publish,
                MessageCode::RawDataWithStatus,
                0_u8,
            )
            .await;
            assert_eq!(events, Vec::new());
            assert!(
                status.is_err(),
                "a malformed body is a whole-request failure"
            );
        })
    })
    .await;
}

/// `RawData` keeps silently skipping a sensor no node serves.
#[tokio::test]
async fn raw_data_still_skips_an_unknown_sensor() {
    with_test_harness(|harness| {
        Box::pin(async move {
            let events = fetch_raw_data(&harness.publish, "conn", UNKNOWN_SENSOR, 1).await;
            assert_eq!(events, Vec::new());
        })
    })
    .await;
}

fn build_conn_range_payload(timestamp: i64, sensor: &str) -> Event<u8> {
    let conn = bincode::deserialize::<Conn>(&gen_conn_raw_event()).expect("decode conn");
    bincode::deserialize::<Option<Event<u8>>>(
        &conn
            .response_data(timestamp, sensor)
            .expect("encode the response"),
    )
    .expect("decode the response")
    .expect("an event")
}

// ---------------------------------------------------------------------------
// Two-node cluster
// ---------------------------------------------------------------------------

#[tokio::test]
async fn multi_source_range_merges_events_across_nodes() {
    let context = setup_cluster_with_cases(|node2_db| {
        insert_conn(node2_db, "src2", &[2, 4, 6, 8, 10]);
        insert_conn(node2_db, "src 2", &[7]);
        Vec::<()>::new()
    })
    .await;
    insert_conn(&context.node1_db, "src1", &[1, 3, 5]);

    // Both of node 2's sources go to it in one forwarded request.
    let request = multi_source_request(
        "conn",
        &[("src1", 0), ("src2", 0), ("src 2", 0), (UNKNOWN_SENSOR, 0)],
        100,
    );
    let (events, status) =
        request_with_status::<u8, _>(&context.publish, MessageCode::MultiSourceRange, request)
            .await;
    assert_eq!(
        order(&events),
        vec![
            (1, "src1"),
            (2, "src2"),
            (3, "src1"),
            (4, "src2"),
            (5, "src1"),
            (6, "src2"),
            (7, "src 2"),
            (8, "src2"),
            (10, "src2"),
        ]
    );
    assert_eq!(
        statuses(status),
        vec![
            ("src1".to_string(), SourceStatus::Served),
            ("src2".to_string(), SourceStatus::Served),
            ("src 2".to_string(), SourceStatus::Served),
            (UNKNOWN_SENSOR.to_string(), SourceStatus::NoNode),
        ]
    );

    // A count that cuts inside the peer's events: the peer sends its first
    // five, and the merge stops after the fifth event overall.
    let request = multi_source_request("conn", &[("src1", 0), ("src2", 3)], 5);
    let (events, status) =
        request_with_status::<u8, _>(&context.publish, MessageCode::MultiSourceRange, request)
            .await;
    assert_eq!(
        order(&events),
        vec![
            (1, "src1"),
            (3, "src1"),
            (4, "src2"),
            (5, "src1"),
            (6, "src2")
        ]
    );
    assert_eq!(statuses(status), served(&["src1", "src2"]));

    // A count that ends inside the peer's own events: the peer applies it to
    // the request it is forwarded too.
    let request = multi_source_request("conn", &[("src2", 0)], 2);
    let (events, _) =
        request_with_status::<u8, _>(&context.publish, MessageCode::MultiSourceRange, request)
            .await;
    assert_eq!(order(&events), vec![(2, "src2"), (4, "src2")]);

    context.shutdown().await;
}

#[tokio::test]
async fn raw_data_with_status_rereads_events_across_nodes() {
    let context = setup_cluster_with_cases(|node2_db| {
        insert_conn(node2_db, "src2", &[2, 4]);
        Vec::<()>::new()
    })
    .await;
    insert_conn(&context.node1_db, "src1", &[1, 3]);

    let request = raw_data_request(
        "conn",
        &[
            ("src1", &[1, 3]),
            ("src2", &[2, 99]),
            (UNKNOWN_SENSOR, &[1]),
        ],
    );
    let (events, status) =
        request_with_status::<u8, _>(&context.publish, MessageCode::RawDataWithStatus, request)
            .await;
    assert_eq!(
        sorted_order(&events),
        vec![(1, "src1"), (2, "src2"), (3, "src1")]
    );
    assert_eq!(
        statuses(status),
        vec![
            ("src1".to_string(), SourceStatus::Served),
            ("src2".to_string(), SourceStatus::Served),
            (UNKNOWN_SENSOR.to_string(), SourceStatus::NoNode),
        ]
    );

    context.shutdown().await;
}

#[tokio::test]
async fn time_series_requests_do_not_fetch_a_series_from_the_peer() {
    let context = setup_cluster_with_cases(|node2_db| {
        insert_time_series(node2_db, TIME_SERIES_POLICY_ID, &[2]);
        Vec::<()>::new()
    })
    .await;
    insert_time_series(&context.node1_db, TIME_SERIES_POLICY_ID, &[1]);

    let request = multi_source_request("timeseries", &[(TIME_SERIES_POLICY_ID, 0)], 100);
    let (events, status) =
        request_with_status::<f64, _>(&context.publish, MessageCode::MultiSourceRange, request)
            .await;
    let timestamps: Vec<i64> = events.iter().map(|(timestamp, ..)| *timestamp).collect();
    assert_eq!(timestamps, vec![1]);
    assert_eq!(statuses(status), served(&[TIME_SERIES_POLICY_ID]));

    let request = raw_data_request("timeseries", &[(TIME_SERIES_POLICY_ID, &[1, 2])]);
    let (events, status) =
        request_with_status::<f64, _>(&context.publish, MessageCode::RawDataWithStatus, request)
            .await;
    let timestamps: Vec<i64> = events.iter().map(|(timestamp, ..)| *timestamp).collect();
    assert_eq!(timestamps, vec![1]);
    assert_eq!(statuses(status), served(&[TIME_SERIES_POLICY_ID]));

    context.shutdown().await;
}

// ---------------------------------------------------------------------------
// Peer failures, timeouts and cancellation, against the handler directly
// ---------------------------------------------------------------------------

const LOCAL_SOURCE: &str = "multi_source_local";
const PEER_SOURCE: &str = "multi_source_peer";

struct DirectFixture {
    _temp_dir: TempDir,
    db: Database,
    ingest_sensors: IngestSensors,
    peers: Peers,
    peer_idents: PeerIdents,
    tls_watch: TlsWatch,
}

impl DirectFixture {
    fn new(peer_addr: SocketAddr) -> Self {
        init_crypto();
        let temp_dir = tempfile::tempdir().expect("create a temp dir");
        let db = Database::open(temp_dir.path(), &DbOptions::default()).expect("open a database");
        insert_conn(&db, LOCAL_SOURCE, &[1, 3]);
        let certs = build_test_certs();
        Self {
            _temp_dir: temp_dir,
            db,
            ingest_sensors: build_ingest_sensors_from_list(&[LOCAL_SOURCE]),
            peers: build_peers_for_sensor(PEER_SOURCE, peer_addr),
            peer_idents: build_peer_idents(peer_addr, NODE2.server_name()),
            tls_watch: build_test_tls_watch(&certs),
        }
    }

    fn routing<'a>(
        &'a self,
        token: &'a CancellationToken,
        peer_timeout: StdDuration,
    ) -> Routing<'a> {
        Routing {
            ingest_sensors: &self.ingest_sensors,
            peers: &self.peers,
            peer_idents: &self.peer_idents,
            tls_watch: &self.tls_watch,
            token,
            peer_timeout,
        }
    }

    /// Runs a multi-source read of the local source, the peer's source and a
    /// source no node serves, and returns the response the client reads.
    async fn multi_source_range(
        &self,
        host: &str,
        token: &CancellationToken,
        peer_timeout: StdDuration,
    ) -> (Vec<Event<u8>>, RangeStatus) {
        let request = multi_source_request(
            "conn",
            &[(LOCAL_SOURCE, 0), (PEER_SOURCE, 0), (UNKNOWN_SENSOR, 0)],
            100,
        );
        let body = bincode::serialize(&request).expect("encode the request");
        let (mut send, client_conn) = open_range_stream(host).await;
        process_multi_source_range(
            &mut send,
            &self.db,
            &body,
            &self.routing(token, peer_timeout),
        )
        .await
        .expect("serve the request");
        let mut recv = client_conn.accept_uni().await.expect("accept the response");
        read_status_response(&mut recv).await
    }

    async fn raw_data_with_status(
        &self,
        host: &str,
        token: &CancellationToken,
        peer_timeout: StdDuration,
    ) -> (Vec<Event<u8>>, RangeStatus) {
        let request = raw_data_request(
            "conn",
            &[
                (LOCAL_SOURCE, &[1, 3]),
                (PEER_SOURCE, &[2]),
                (UNKNOWN_SENSOR, &[1]),
            ],
        );
        let body = bincode::serialize(&request).expect("encode the request");
        let (mut send, client_conn) = open_range_stream(host).await;
        process_raw_data_with_status(
            &mut send,
            &self.db,
            &body,
            &self.routing(token, peer_timeout),
        )
        .await
        .expect("serve the request");
        let mut recv = client_conn.accept_uni().await.expect("accept the response");
        read_status_response(&mut recv).await
    }
}

/// Asserts the local source was served, the peer's source failed with a
/// reason naming the peer and containing `cause`, and the unknown source has
/// no node, in request order.
fn assert_peer_failed(status: RangeStatus, peer_addr: SocketAddr, cause: &str) {
    let statuses = statuses(status);
    assert_eq!(statuses.len(), 3);
    assert_eq!(
        statuses[0],
        (LOCAL_SOURCE.to_string(), SourceStatus::Served)
    );
    assert_eq!(statuses[1].0, PEER_SOURCE);
    assert_failed(
        &statuses[1].1,
        &[NODE2.server_name(), &peer_addr.to_string(), cause],
    );
    assert_eq!(
        statuses[2],
        (UNKNOWN_SENSOR.to_string(), SourceStatus::NoNode)
    );
}

#[tokio::test]
async fn multi_source_range_fails_the_sources_of_a_peer_that_breaks_off() {
    init_crypto();
    let conn = bincode::deserialize::<Conn>(&gen_conn_raw_event()).expect("decode conn");
    let peer_server = setup_peer_range_server_without_done(
        &NODE2.build_certs(),
        vec![(2, PEER_SOURCE.to_string(), conn)],
    );
    let fixture = DirectFixture::new(peer_server.addr);

    let (events, status) = fixture
        .multi_source_range(
            "multi.source.broken",
            &CancellationToken::new(),
            PEER_RESPONSE_TIMEOUT,
        )
        .await;

    // The peer's event before the break is delivered with the local ones.
    assert_eq!(
        order(&events),
        vec![(1, LOCAL_SOURCE), (2, PEER_SOURCE), (3, LOCAL_SOURCE)]
    );
    assert_peer_failed(status, peer_server.addr, "broke off");
}

#[tokio::test]
async fn multi_source_range_fails_a_peer_whose_server_name_is_unknown() {
    init_crypto();
    let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    let mut fixture = DirectFixture::new(peer_addr);
    fixture.peer_idents = Arc::new(RwLock::new(HashSet::new()));

    let (events, status) = fixture
        .multi_source_range(
            "multi.source.unnamed",
            &CancellationToken::new(),
            SHORT_PEER_TIMEOUT,
        )
        .await;

    assert_eq!(order(&events), vec![(1, LOCAL_SOURCE), (3, LOCAL_SOURCE)]);
    let statuses = statuses(status);
    assert_failed(&statuses[1].1, &[&peer_addr.to_string(), "server name"]);
}

#[tokio::test]
async fn multi_source_range_times_out_a_peer_whose_listener_does_not_answer() {
    init_crypto();
    // A UDP socket nobody reads, so the dial waits instead of being refused.
    let black_hole = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the black hole socket");
    let peer_addr = black_hole.local_addr().expect("black hole address");
    let fixture = DirectFixture::new(peer_addr);

    let started = Instant::now();
    let (events, status) = fixture
        .multi_source_range(
            "multi.source.unanswered",
            &CancellationToken::new(),
            SHORT_PEER_TIMEOUT,
        )
        .await;

    assert!(
        started.elapsed() < StdDuration::from_secs(10),
        "the peer timeout should bound the dial"
    );
    assert_eq!(order(&events), vec![(1, LOCAL_SOURCE), (3, LOCAL_SOURCE)]);
    assert_peer_failed(status, peer_addr, "connecting and the handshake timed out");
}

#[tokio::test]
async fn multi_source_range_times_out_a_peer_that_never_answers() {
    init_crypto();
    let peer_server = setup_silent_peer_server(&NODE2.build_certs());
    let fixture = DirectFixture::new(peer_server.addr);

    let started = Instant::now();
    let (events, status) = fixture
        .multi_source_range(
            "multi.source.silent",
            &CancellationToken::new(),
            SHORT_PEER_TIMEOUT,
        )
        .await;

    assert!(
        started.elapsed() < StdDuration::from_secs(10),
        "the peer timeout should bound the frame read"
    );
    assert_eq!(order(&events), vec![(1, LOCAL_SOURCE), (3, LOCAL_SOURCE)]);
    assert_peer_failed(
        status,
        peer_server.addr,
        "waiting for its response timed out",
    );
}

#[tokio::test]
async fn raw_data_with_status_times_out_a_peer_that_never_answers() {
    init_crypto();
    let peer_server = setup_silent_peer_server(&NODE2.build_certs());
    let fixture = DirectFixture::new(peer_server.addr);

    let (events, status) = fixture
        .raw_data_with_status(
            "raw.status.silent",
            &CancellationToken::new(),
            SHORT_PEER_TIMEOUT,
        )
        .await;

    assert_eq!(
        sorted_order(&events),
        vec![(1, LOCAL_SOURCE), (3, LOCAL_SOURCE)]
    );
    assert_peer_failed(
        status,
        peer_server.addr,
        "waiting for its response timed out",
    );
}

#[tokio::test]
async fn raw_data_with_status_times_out_a_peer_whose_listener_does_not_answer() {
    init_crypto();
    let black_hole = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind the black hole socket");
    let peer_addr = black_hole.local_addr().expect("black hole address");
    let fixture = DirectFixture::new(peer_addr);

    let (events, status) = fixture
        .raw_data_with_status(
            "raw.status.unanswered",
            &CancellationToken::new(),
            SHORT_PEER_TIMEOUT,
        )
        .await;

    assert_eq!(
        sorted_order(&events),
        vec![(1, LOCAL_SOURCE), (3, LOCAL_SOURCE)]
    );
    assert_peer_failed(status, peer_addr, "connecting and the handshake timed out");
}

#[tokio::test]
async fn raw_data_with_status_fails_the_sources_of_a_peer_that_breaks_off() {
    init_crypto();
    let conn = bincode::deserialize::<Conn>(&gen_conn_raw_event()).expect("decode conn");
    let peer_server = setup_peer_range_server_without_done(
        &NODE2.build_certs(),
        vec![(2, PEER_SOURCE.to_string(), conn)],
    );
    let fixture = DirectFixture::new(peer_server.addr);

    let (events, status) = fixture
        .raw_data_with_status(
            "raw.status.broken",
            &CancellationToken::new(),
            PEER_RESPONSE_TIMEOUT,
        )
        .await;

    assert_eq!(
        sorted_order(&events),
        vec![(1, LOCAL_SOURCE), (2, PEER_SOURCE), (3, LOCAL_SOURCE)]
    );
    assert_peer_failed(status, peer_server.addr, "broke off");
}

#[tokio::test]
async fn requests_fail_the_sources_of_a_peer_whose_response_is_wrong() {
    init_crypto();
    // The cause each response should be reported with, and the response.
    let cases = [
        (
            "which it was not asked for",
            vec![event_frame(2, "stray")],
            AfterScript::Finish,
        ),
        (
            "waiting for its status timed out",
            vec![terminator_frame()],
            AfterScript::Hold,
        ),
        (
            "ended without a status",
            vec![terminator_frame()],
            AfterScript::Finish,
        ),
        (
            "did not list the source",
            vec![terminator_frame(), status_frame(&Ok(Vec::new()))],
            AfterScript::Finish,
        ),
        (
            "failed the whole request: refused",
            vec![
                terminator_frame(),
                status_frame(&Err("refused".to_string())),
            ],
            AfterScript::Finish,
        ),
    ];
    for (cause, frames, after) in cases {
        let peer_server = setup_scripted_peer_server(
            &NODE2.build_certs(),
            crate::comm::publish::PUBLISH_VERSION_REQ,
            frames,
            after,
        );
        let fixture = DirectFixture::new(peer_server.addr);

        let (events, status) = fixture
            .multi_source_range(
                "multi.source.wrong",
                &CancellationToken::new(),
                SHORT_PEER_TIMEOUT,
            )
            .await;
        assert_eq!(
            order(&events),
            vec![(1, LOCAL_SOURCE), (3, LOCAL_SOURCE)],
            "{cause}"
        );
        assert_peer_failed(status, peer_server.addr, cause);

        let (events, status) = fixture
            .raw_data_with_status(
                "raw.status.wrong",
                &CancellationToken::new(),
                SHORT_PEER_TIMEOUT,
            )
            .await;
        assert_eq!(
            sorted_order(&events),
            vec![(1, LOCAL_SOURCE), (3, LOCAL_SOURCE)],
            "{cause}"
        );
        assert_peer_failed(status, peer_server.addr, cause);
    }
}

#[tokio::test]
async fn multi_source_range_fails_a_peer_that_refuses_the_handshake() {
    init_crypto();
    // No version meets this requirement, so the peer refuses ours.
    let peer_server = setup_scripted_peer_server(
        &NODE2.build_certs(),
        ">=999.0.0",
        Vec::new(),
        AfterScript::Finish,
    );
    let fixture = DirectFixture::new(peer_server.addr);

    let (events, status) = fixture
        .multi_source_range(
            "multi.source.refused",
            &CancellationToken::new(),
            SHORT_PEER_TIMEOUT,
        )
        .await;

    assert_eq!(order(&events), vec![(1, LOCAL_SOURCE), (3, LOCAL_SOURCE)]);
    assert_peer_failed(status, peer_server.addr, "connecting failed");
}

#[tokio::test]
async fn multi_source_range_times_out_a_peer_that_grants_no_stream() {
    init_crypto();
    let peer_server = setup_streamless_peer_server(&NODE2.build_certs());
    let fixture = DirectFixture::new(peer_server.addr);

    let (events, status) = fixture
        .multi_source_range(
            "multi.source.streamless",
            &CancellationToken::new(),
            SHORT_PEER_TIMEOUT,
        )
        .await;

    assert_eq!(order(&events), vec![(1, LOCAL_SOURCE), (3, LOCAL_SOURCE)]);
    assert_peer_failed(
        status,
        peer_server.addr,
        "opening a stream and sending the request timed out",
    );
}

/// A response that can no longer be written is an error, and the peer is
/// closed rather than waited on.
#[tokio::test]
async fn requests_whose_response_cannot_be_written_return_an_error() {
    init_crypto();
    let peer_server = setup_scripted_peer_server(
        &NODE2.build_certs(),
        crate::comm::publish::PUBLISH_VERSION_REQ,
        vec![event_frame(2, PEER_SOURCE)],
        AfterScript::Hold,
    );
    let fixture = DirectFixture::new(peer_server.addr);
    let token = CancellationToken::new();
    let routing = fixture.routing(&token, PEER_RESPONSE_TIMEOUT);

    let request = multi_source_request("conn", &[(LOCAL_SOURCE, 0), (PEER_SOURCE, 0)], 100);
    let body = bincode::serialize(&request).expect("encode the request");
    let (mut send, _client_conn) = open_range_stream("multi.source.unwritable").await;
    send.reset(VarInt::from_u32(0))
        .expect("reset the response stream");
    let served = tokio::time::timeout(
        FRAME_TIMEOUT,
        process_multi_source_range(&mut send, &fixture.db, &body, &routing),
    )
    .await
    .expect("the request should not wait on the peer");
    assert!(served.is_err(), "a failed write is an error");

    // Only the peer's source, so the first write is the relay of its event.
    let request = raw_data_request("conn", &[(PEER_SOURCE, &[2])]);
    let body = bincode::serialize(&request).expect("encode the request");
    let (mut send, _client_conn) = open_range_stream("raw.status.unwritable").await;
    send.reset(VarInt::from_u32(0))
        .expect("reset the response stream");
    let served = tokio::time::timeout(
        FRAME_TIMEOUT,
        process_raw_data_with_status(&mut send, &fixture.db, &body, &routing),
    )
    .await
    .expect("the request should not wait on the peer");
    assert!(served.is_err(), "a failed write is an error");
}

/// A request cancelled while it waits on a peer, after it has sent events,
/// ends without the terminator and without a status.
#[tokio::test]
async fn a_request_cancelled_while_waiting_on_a_peer_writes_no_terminator() {
    init_crypto();
    // What the peer sends before going quiet, and the event after which the
    // client cancels the request.
    let cases = [
        // The relay is waiting for the peer's next event.
        (vec![event_frame(2, PEER_SOURCE)], (2, PEER_SOURCE)),
        // The merge reads the peer's terminator before it sends the first
        // event, so the relay is left waiting for the peer's status.
        (vec![terminator_frame()], (1, LOCAL_SOURCE)),
    ];
    for (frames, cancel_after) in cases {
        let peer_server = setup_scripted_peer_server(
            &NODE2.build_certs(),
            crate::comm::publish::PUBLISH_VERSION_REQ,
            frames,
            AfterScript::Hold,
        );
        let fixture = DirectFixture::new(peer_server.addr);
        let token = CancellationToken::new();
        let routing = fixture.routing(&token, PEER_RESPONSE_TIMEOUT);
        let request = multi_source_request("conn", &[(LOCAL_SOURCE, 0), (PEER_SOURCE, 0)], 100);
        let body = bincode::serialize(&request).expect("encode the request");
        let (mut send, client_conn) = open_range_stream("multi.source.cancelled.peer").await;

        let serve = async {
            process_multi_source_range(&mut send, &fixture.db, &body, &routing)
                .await
                .expect("giving up is a normal return, not an error");
            // Dropping the stream finishes it, so the client reads to its end.
            drop(send);
        };
        let client = async {
            let mut recv = client_conn.accept_uni().await.expect("accept the response");
            let mut frames = Vec::new();
            while let Ok(Ok(frame)) = tokio::time::timeout(
                FRAME_TIMEOUT,
                receive_range_data::<Option<Event<u8>>>(&mut recv),
            )
            .await
            {
                if frame.as_ref().is_some_and(|(timestamp, source, _)| {
                    (*timestamp, source.as_str()) == cancel_after
                }) {
                    token.cancel();
                }
                frames.push(frame);
            }
            frames
        };
        let ((), frames) = tokio::join!(serve, client);

        assert!(token.is_cancelled(), "the client should have cancelled");
        assert!(
            frames.iter().all(Option::is_some),
            "a cancelled request must not write the terminator, got {frames:?}"
        );
    }
}

/// A request cancelled during shutdown sends neither the terminator nor a
/// status, so the client sees an incomplete response.
#[tokio::test]
async fn cancelled_requests_write_no_terminator_and_no_status() {
    init_crypto();
    // Nothing listens here: if the relay dialled at all, it would retry until
    // the token stopped it rather than return at once.
    let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    let fixture = DirectFixture::new(peer_addr);
    let token = CancellationToken::new();
    token.cancel();

    let request = multi_source_request("conn", &[(PEER_SOURCE, 0)], 100);
    let body = bincode::serialize(&request).expect("encode the request");
    let (mut send, client_conn) = open_range_stream("multi.source.cancelled").await;
    process_multi_source_range(
        &mut send,
        &fixture.db,
        &body,
        &fixture.routing(&token, PEER_RESPONSE_TIMEOUT),
    )
    .await
    .expect("giving up is a normal return, not an error");
    assert_nothing_received(&client_conn, "multi-source range").await;

    let request = raw_data_request("conn", &[(PEER_SOURCE, &[1])]);
    let body = bincode::serialize(&request).expect("encode the request");
    let (mut send, client_conn) = open_range_stream("raw.status.cancelled").await;
    process_raw_data_with_status(
        &mut send,
        &fixture.db,
        &body,
        &fixture.routing(&token, PEER_RESPONSE_TIMEOUT),
    )
    .await
    .expect("giving up is a normal return, not an error");
    assert_nothing_received(&client_conn, "raw data with status").await;
}

/// Fails if the server wrote anything the client could read as a frame.
///
/// A request that gave up before any event may have written nothing at all,
/// so an unopened stream counts as nothing received.
async fn assert_nothing_received(client_conn: &Connection, label: &str) {
    let Ok(Ok(mut recv)) =
        tokio::time::timeout(StdDuration::from_secs(1), client_conn.accept_uni()).await
    else {
        return;
    };
    let received = tokio::time::timeout(
        StdDuration::from_secs(1),
        receive_range_data::<Option<Event<u8>>>(&mut recv),
    )
    .await;
    assert!(
        !matches!(received, Ok(Ok(_))),
        "a cancelled {label} request must write neither the terminator nor a status"
    );
}

/// Starts a peer publish server that completes the handshake, accepts one
/// request, and then never answers it.
fn setup_silent_peer_server(certs: &Arc<Certs>) -> PeerHandshakeServer {
    let server_config = config_server(certs).expect("peer server config");
    let endpoint = Endpoint::server(
        server_config,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .expect("start the silent peer server");
    let addr = endpoint.local_addr().expect("silent peer server address");

    let endpoint_for_accept = endpoint.clone();
    tokio::spawn(async move {
        let Some(connecting) = endpoint_for_accept.accept().await else {
            return;
        };
        let Ok(connection) = connecting.await else {
            return;
        };
        if server_handshake(&connection, crate::comm::publish::PUBLISH_VERSION_REQ)
            .await
            .is_err()
        {
            return;
        }
        let Ok((send, mut recv)) = connection.accept_bi().await else {
            return;
        };
        let _ = receive_range_data_request(&mut recv).await;
        // Holding the streams keeps the request open without an answer; a
        // dropped stream would reset it, which reads as a broken-off response.
        connection.closed().await;
        drop((send, recv));
    });

    PeerHandshakeServer {
        addr,
        _endpoint: endpoint,
    }
}

/// What a scripted peer does once it has written its frames.
#[derive(Clone, Copy)]
enum AfterScript {
    /// Finishes the response stream.
    Finish,
    /// Keeps the response open without writing anything more.
    Hold,
}

fn event_frame(timestamp: i64, source: &str) -> Vec<u8> {
    bincode::serialize(&Some((timestamp, source.to_string(), vec![0_u8])))
        .expect("encode an event frame")
}

fn terminator_frame() -> Vec<u8> {
    bincode::serialize::<Option<Event<u8>>>(&None).expect("encode the terminator")
}

fn status_frame(status: &RangeStatus) -> Vec<u8> {
    bincode::serialize(status).expect("encode a status frame")
}

/// Starts a peer publish server that handshakes with `version_req` and
/// answers each request, one connection at a time, with `frames` as they are,
/// then does what `after` says.
fn setup_scripted_peer_server(
    certs: &Arc<Certs>,
    version_req: &'static str,
    frames: Vec<Vec<u8>>,
    after: AfterScript,
) -> PeerHandshakeServer {
    let server_config = config_server(certs).expect("peer server config");
    let endpoint = Endpoint::server(
        server_config,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .expect("start the scripted peer server");
    let addr = endpoint.local_addr().expect("scripted peer server address");

    let endpoint_for_accept = endpoint.clone();
    tokio::spawn(async move {
        while let Some(connecting) = endpoint_for_accept.accept().await {
            let Ok(connection) = connecting.await else {
                continue;
            };
            if server_handshake(&connection, version_req).await.is_err() {
                continue;
            }
            let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                continue;
            };
            let _ = receive_range_data_request(&mut recv).await;
            for frame in &frames {
                let _ = send_raw(&mut send, frame).await;
            }
            if matches!(after, AfterScript::Finish) {
                let _ = send.finish();
            }
            // The relay closes the connection once it is done with the peer.
            connection.closed().await;
            drop((send, recv));
        }
    });

    PeerHandshakeServer {
        addr,
        _endpoint: endpoint,
    }
}

/// Starts a peer publish server that completes the handshake and then grants
/// no stream to send a request on.
fn setup_streamless_peer_server(certs: &Arc<Certs>) -> PeerHandshakeServer {
    let mut server_config = config_server(certs).expect("peer server config");
    Arc::get_mut(&mut server_config.transport)
        .expect("the transport config is not shared yet")
        .max_concurrent_bidi_streams(1_u8.into());
    let endpoint = Endpoint::server(
        server_config,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .expect("start the streamless peer server");
    let addr = endpoint
        .local_addr()
        .expect("streamless peer server address");

    let endpoint_for_accept = endpoint.clone();
    tokio::spawn(async move {
        let Some(connecting) = endpoint_for_accept.accept().await else {
            return;
        };
        let Ok(connection) = connecting.await else {
            return;
        };
        let Ok(handshake) =
            server_handshake(&connection, crate::comm::publish::PUBLISH_VERSION_REQ).await
        else {
            return;
        };
        // The handshake's stream stays open while it is held, using up the
        // one stream the client may open.
        connection.closed().await;
        drop(handshake);
    });

    PeerHandshakeServer {
        addr,
        _endpoint: endpoint,
    }
}

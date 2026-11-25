use std::fmt::Write as _;

use async_graphql::{Response, Value};
use serde_json::{Value as Json, json};
use uuid::Uuid;

use crate::graphql::{caller::REVIEW_SERVICE, tests::TestSchema};
use crate::storage::{
    Database,
    endpoint::{DuplicateKeyEvent, EndpointBatch, EndpointChange, LossReason},
};

const ENTRY_ID: &str = "0b1c9e4e-6c8f-4a51-9d0e-6a3f6c2a1f10";
const OLD_ENTRY_ID: &str = "5d2a4b7c-1e3f-4a5b-8c6d-7e8f9a0b1c2d";
const ENDPOINT_ID: &str = "7f3e2d1c-0b9a-4876-9543-210fedcba987";
const OTHER_ENDPOINT_ID: &str = "8a9b0c1d-2e3f-4051-8617-28394a5b6c7d";
const STREAM_ID: &str = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";

/// The received time the `since` tests read from.
const SINCE: i64 = 1_700_000_000_000_000_000;

const LOSS_FIELDS: &str = "entryId endpointId streamId from to reason detail receivedAt";
const EVENT_FIELDS: &str = "receivedAt endpointId sequence spkiSha256 addresses replacements";

fn uuid(id: &str) -> Uuid {
    Uuid::parse_str(id).expect("a valid UUID")
}

async fn as_review(schema: &TestSchema, query: &str) -> Response {
    schema.execute_as(Some(REVIEW_SERVICE), query).await
}

/// Returns the data of a response that must have succeeded.
fn data(response: Response) -> Json {
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    response.data.into_json().expect("JSON data")
}

fn write_loss(
    db: &Database,
    entry_id: &str,
    (from, to): (u64, u64),
    (reason, detail): (LossReason, &str),
    received_ns: i64,
) {
    db.write_endpoint_batch(EndpointBatch {
        entry_id: uuid(entry_id),
        received_ns,
        changes: vec![EndpointChange::Loss {
            endpoint_id: uuid(ENDPOINT_ID),
            stream: uuid(STREAM_ID),
            from,
            to,
            reason,
            detail: detail.to_owned(),
        }],
        received_from: Vec::new(),
    })
    .expect("write a loss");
}

fn write_event(db: &Database, endpoint_id: &str, received_ns: i64, replacements: u64) {
    let mut spki_sha256 = [0_u8; 32];
    for (byte, value) in spki_sha256.iter_mut().zip(0_u8..) {
        *byte = value.wrapping_mul(9);
    }
    db.append_endpoint_duplicate_key(
        received_ns,
        uuid(endpoint_id),
        &DuplicateKeyEvent {
            spki_sha256,
            addresses: vec![
                "192.0.2.1".parse().expect("an address"),
                "2001:db8::7".parse().expect("an address"),
            ],
            replacements,
        },
    )
    .expect("write an event");
}

/// The lowercase hex of the SPKI hash [`write_event`] stores.
fn spki_hex() -> String {
    (0_u8..32).fold(String::new(), |mut hex, value| {
        write!(hex, "{:02x}", value.wrapping_mul(9)).expect("writing to a String cannot fail");
        hex
    })
}

fn write_last_received(db: &Database, endpoint_ids: &[Uuid], received_ns: i64) {
    db.write_endpoint_batch(EndpointBatch {
        entry_id: uuid(ENTRY_ID),
        received_ns,
        changes: Vec::new(),
        received_from: endpoint_ids.to_vec(),
    })
    .expect("write last received times");
}

fn losses_query(since: i64) -> String {
    format!(r#"{{ endpointLosses(since: "{since}") {{ {LOSS_FIELDS} }} }}"#)
}

fn events_query(since: i64) -> String {
    format!(r#"{{ endpointEvents(since: "{since}") {{ {EVENT_FIELDS} }} }}"#)
}

fn last_received_query(arguments: &str) -> String {
    format!(
        "{{ endpointLastReceived{arguments} {{ \
         edges {{ cursor node {{ endpointId lastReceivedAt }} }} \
         pageInfo {{ hasNextPage }} }} }}"
    )
}

/// Returns the losses of a response sorted by `receivedAt`, which the field
/// does not order by.
fn sorted_losses(response: Response) -> Vec<Json> {
    let mut losses = data(response)["endpointLosses"]
        .as_array()
        .expect("a list")
        .clone();
    losses.sort_unstable_by_key(|loss| {
        loss["receivedAt"]
            .as_str()
            .expect("a string")
            .parse::<i64>()
            .expect("a number")
    });
    losses
}

#[tokio::test]
async fn losses_since_returns_every_reason_from_the_same_nanosecond_on() {
    let schema = TestSchema::new();
    write_loss(
        &schema.db,
        ENTRY_ID,
        (1, 3),
        (LossReason::Dropped, "queue_full"),
        SINCE - 1,
    );
    write_loss(
        &schema.db,
        ENTRY_ID,
        (4, 9),
        (LossReason::Dropped, "queue_full"),
        SINCE,
    );
    write_loss(
        &schema.db,
        ENTRY_ID,
        (10, 12),
        (LossReason::LostOnReset, ""),
        SINCE + 1,
    );
    write_loss(
        &schema.db,
        OLD_ENTRY_ID,
        (13, 13),
        (LossReason::ConversionFailure, "invalid image path"),
        SINCE + 2,
    );

    let losses = sorted_losses(as_review(&schema, &losses_query(SINCE)).await);
    let loss = |entry_id: &str, from: &str, to: &str, reason: &str, detail: &str, at: i64| {
        json!({
            "entryId": entry_id,
            "endpointId": ENDPOINT_ID,
            "streamId": STREAM_ID,
            "from": from,
            "to": to,
            "reason": reason,
            "detail": detail,
            "receivedAt": at.to_string(),
        })
    };
    assert_eq!(
        losses,
        vec![
            loss(ENTRY_ID, "4", "9", "DROPPED", "queue_full", SINCE),
            loss(ENTRY_ID, "10", "12", "LOST_ON_RESET", "", SINCE + 1),
            loss(
                OLD_ENTRY_ID,
                "13",
                "13",
                "CONVERSION_FAILED",
                "invalid image path",
                SINCE + 2
            ),
        ]
    );

    let all = sorted_losses(as_review(&schema, &losses_query(-1)).await);
    assert_eq!(all.len(), 4, "a negative since returns every loss");
    assert_eq!(
        all.first().map(|loss| loss["receivedAt"].clone()),
        Some(Json::from((SINCE - 1).to_string()))
    );
    assert_eq!(
        sorted_losses(as_review(&schema, &losses_query(SINCE + 3)).await),
        Vec::<Json>::new()
    );
}

#[tokio::test]
async fn events_since_returns_the_events_from_the_same_nanosecond_on_in_key_order() {
    let schema = TestSchema::new();
    write_event(&schema.db, ENDPOINT_ID, SINCE - 1, 1);
    write_event(&schema.db, OTHER_ENDPOINT_ID, SINCE, 2);
    write_event(&schema.db, ENDPOINT_ID, SINCE, 3);
    write_event(&schema.db, ENDPOINT_ID, SINCE, 4);
    write_event(&schema.db, ENDPOINT_ID, SINCE + 1, 5);

    let event = |endpoint_id: &str, at: i64, sequence: &str, replacements: &str| {
        json!({
            "receivedAt": at.to_string(),
            "endpointId": endpoint_id,
            "sequence": sequence,
            "spkiSha256": spki_hex(),
            "addresses": ["192.0.2.1", "2001:db8::7"],
            "replacements": replacements,
        })
    };
    // ENDPOINT_ID sorts before OTHER_ENDPOINT_ID.
    assert_eq!(
        data(as_review(&schema, &events_query(SINCE)).await),
        json!({ "endpointEvents": [
            event(ENDPOINT_ID, SINCE, "0", "3"),
            event(ENDPOINT_ID, SINCE, "1", "4"),
            event(OTHER_ENDPOINT_ID, SINCE, "0", "2"),
            event(ENDPOINT_ID, SINCE + 1, "0", "5"),
        ] })
    );

    let all = data(as_review(&schema, &events_query(i64::MIN)).await);
    let all = all["endpointEvents"].as_array().expect("a list");
    assert_eq!(all.len(), 5, "a negative since returns every event");
    assert_eq!(all.first(), Some(&event(ENDPOINT_ID, SINCE - 1, "0", "1")));
    assert_eq!(
        data(as_review(&schema, &events_query(SINCE + 2)).await),
        json!({ "endpointEvents": [] })
    );
}

#[tokio::test]
async fn last_received_pages_over_every_endpoint_once_in_id_order() {
    let schema = TestSchema::new();
    let mut ids: Vec<Uuid> = (1..=5_u128)
        .map(|n| Uuid::from_u128(n.wrapping_mul(0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c834)))
        .collect();
    for (id, at) in ids.iter().zip(SINCE..) {
        write_last_received(&schema.db, &[*id], at);
    }
    let expected: std::collections::HashMap<String, String> = ids
        .iter()
        .zip(SINCE..)
        .map(|(id, at)| (id.to_string(), at.to_string()))
        .collect();
    ids.sort_unstable();

    let mut seen = Vec::new();
    let mut after = String::new();
    loop {
        let response =
            data(as_review(&schema, &last_received_query(&format!("(first: 2{after})"))).await);
        let connection = &response["endpointLastReceived"];
        let edges = connection["edges"].as_array().expect("edges");
        assert!(edges.len() <= 2);
        for edge in edges {
            let id = edge["node"]["endpointId"].as_str().expect("an id");
            assert_eq!(edge["cursor"].as_str(), Some(id), "the cursor is the id");
            assert_eq!(
                edge["node"]["lastReceivedAt"].as_str(),
                expected.get(id).map(String::as_str)
            );
            seen.push(id.to_owned());
        }
        if connection["pageInfo"]["hasNextPage"] == Json::Bool(false) {
            break;
        }
        let last = seen.last().expect("a page before the next");
        after = format!(r#", after: "{last}""#);
    }
    assert_eq!(
        seen,
        ids.iter().map(Uuid::to_string).collect::<Vec<_>>(),
        "every endpoint once, in id order"
    );
}

#[tokio::test]
async fn last_received_caps_first_at_the_maximum_page_size() {
    let schema = TestSchema::new();
    let ids: Vec<Uuid> = (1..=105_u128).map(Uuid::from_u128).collect();
    write_last_received(&schema.db, &ids, SINCE);

    for arguments in ["(first: 1000)", ""] {
        let response = data(as_review(&schema, &last_received_query(arguments)).await);
        let connection = &response["endpointLastReceived"];
        assert_eq!(
            connection["edges"].as_array().map(Vec::len),
            Some(super::MAXIMUM_PAGE_SIZE),
            "{arguments}"
        );
        assert_eq!(connection["pageInfo"]["hasNextPage"], Json::Bool(true));
    }
    let last = Uuid::from_u128(100).to_string();
    let response = data(
        as_review(
            &schema,
            &last_received_query(&format!(r#"(first: 1000, after: "{last}")"#)),
        )
        .await,
    );
    let connection = &response["endpointLastReceived"];
    assert_eq!(connection["edges"].as_array().map(Vec::len), Some(5));
    assert_eq!(connection["pageInfo"]["hasNextPage"], Json::Bool(false));

    let response = as_review(&schema, &last_received_query(r#"(after: "not-a-uuid")"#)).await;
    assert_eq!(response.errors.len(), 1, "an invalid cursor is refused");
    let response = as_review(&schema, &last_received_query("(first: -1)")).await;
    assert_eq!(response.errors.len(), 1, "a negative first is refused");
}

#[tokio::test]
async fn only_review_may_call_the_endpoint_status_fields() {
    let schema = TestSchema::new();
    write_loss(
        &schema.db,
        ENTRY_ID,
        (1, 1),
        (LossReason::LostOnReset, ""),
        SINCE,
    );
    write_event(&schema.db, ENDPOINT_ID, SINCE, 1);
    write_last_received(&schema.db, &[uuid(ENDPOINT_ID)], SINCE);
    let calls = [losses_query(0), events_query(0), last_received_query("")];
    for call in &calls {
        let response = as_review(&schema, call).await;
        assert!(response.errors.is_empty(), "{call}: {:?}", response.errors);
        assert_ne!(response.data, Value::Null, "{call}");
    }
    for service in [Some("piglet"), Some("giganto"), None] {
        for call in &calls {
            let response = schema.execute_as(service, call).await;
            assert_eq!(response.errors.len(), 1, "{service:?}: {call}");
            assert_eq!(response.data, Value::Null, "{service:?}: {call}");
        }
    }
    // Without any caller in the request data, as from a test harness.
    for call in &calls {
        let response = schema.execute(call).await;
        assert_eq!(response.errors.len(), 1, "{call}");
        assert_eq!(response.data, Value::Null, "{call}");
    }
}

#[cfg(feature = "cluster")]
#[tokio::test]
async fn the_endpoint_status_fields_are_not_forwarded_to_peers() {
    use mockito::{Matcher, Server};

    let mut server = Server::new_async().await;
    let peer = server
        .mock("POST", "/graphql")
        .match_body(Matcher::Any)
        .expect(0)
        .create_async()
        .await;
    let schema = TestSchema::new_with_graphql_peer(server.socket_address().port());
    write_loss(
        &schema.db,
        ENTRY_ID,
        (1, 1),
        (LossReason::LostOnReset, ""),
        SINCE,
    );
    write_event(&schema.db, ENDPOINT_ID, SINCE, 1);
    write_last_received(&schema.db, &[uuid(ENDPOINT_ID)], SINCE);

    assert_eq!(
        sorted_losses(as_review(&schema, &losses_query(0)).await).len(),
        1
    );
    let events = data(as_review(&schema, &events_query(0)).await);
    assert_eq!(events["endpointEvents"].as_array().map(Vec::len), Some(1));
    let last = data(as_review(&schema, &last_received_query("")).await);
    assert_eq!(
        last["endpointLastReceived"]["edges"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    peer.assert_async().await;
}

#[test]
fn the_schema_carries_the_endpoint_status_fields() {
    let sdl = crate::graphql::generate_schema();
    for expected in [
        "endpointLosses(since: StringNumberI64!): [EndpointLoss!]!",
        "endpointEvents(since: StringNumberI64!): [EndpointDuplicateKeyEvent!]!",
        "endpointLastReceived(after: String, first: Int): EndpointLastReceivedTimeConnection!",
        "type EndpointLoss {\n\
         \t\"\"\"\n\
         \tThe entry ID the loss was recorded under.\n\
         \t\"\"\"\n\
         \tentryId: ID!\n",
        "\tendpointId: String!\n",
        "\tstreamId: String!\n",
        "\tfrom: StringNumberU64!\n",
        "\tto: StringNumberU64!\n",
        "\treason: EndpointLossReason!\n",
        "\tdetail: String!\n",
        "\treceivedAt: StringNumberI64!\n",
        "\tsequence: StringNumberU32!\n",
        "\tspkiSha256: String!\n",
        "\taddresses: [String!]!\n",
        "\treplacements: StringNumberU64!\n",
        "\tlastReceivedAt: StringNumberI64!\n",
        "enum EndpointLossReason {",
        "\tDROPPED\n",
        "\tLOST_ON_RESET\n",
        "\tCONVERSION_FAILED\n",
    ] {
        assert!(sdl.contains(expected), "missing {expected:?}");
    }
}

//! The GraphQL REview drives the endpoint entry's active list with: applying
//! a list update with the node's `entry_id`, confirming the version applied,
//! and reading the state.
//!
//! Only REview may call these fields, and none of them is forwarded to
//! peers: each node holds its own list.

use std::sync::Arc;

use async_graphql::{Context, ErrorExtensions, ID, Object, Result, SimpleObject, Value};
use senta_protocol::auth::active_list::ApplyError;

use super::{StringNumberU64, caller::ReviewOnly};
use crate::{
    comm::endpoint::{ApplyFailure, ApplyRefusal, EndpointList, ListAck},
    storage::Database,
};

#[derive(Default)]
pub(super) struct EndpointListQuery;

#[derive(Default)]
pub(super) struct EndpointListMutation;

/// What the node answers an active list update or confirmation with.
#[derive(SimpleObject, Debug)]
struct EndpointListAck {
    /// Whether the node is ready: a full list applied and an entry ID
    /// stored.
    ready: bool,
    /// The version applied; null whenever `ready` is false.
    version: Option<StringNumberU64>,
}

impl From<ListAck> for EndpointListAck {
    fn from(ack: ListAck) -> Self {
        Self {
            ready: ack.ready,
            version: ack.version.map(StringNumberU64),
        }
    }
}

/// The node's active list state.
#[derive(SimpleObject, Debug)]
struct EndpointActiveListState {
    /// The entry ID stored, or null when none is.
    entry_id: Option<ID>,
    /// Whether the node is ready: a full list applied and an entry ID
    /// stored.
    ready: bool,
    /// The version applied; null whenever `ready` is false.
    version: Option<StringNumberU64>,
}

#[Object]
impl EndpointListQuery {
    /// Returns the endpoint active list's state: the entry ID stored, whether
    /// the node is ready, and the version applied.
    ///
    /// Only REview may call it.
    #[graphql(guard = "ReviewOnly")]
    async fn endpoint_active_list_state(
        &self,
        ctx: &Context<'_>,
    ) -> Result<EndpointActiveListState> {
        let state = ctx.data::<Arc<EndpointList>>()?.state();
        super::ready(Ok(EndpointActiveListState {
            entry_id: state.entry_id.map(|id| ID(id.to_string())),
            ready: state.ready,
            version: state.version.map(StringNumberU64),
        }))
        .await
    }
}

#[Object]
impl EndpointListMutation {
    /// Applies an endpoint active list update, the standard base64 (with
    /// padding) of the update's CBOR, with `entryId` as the node's entry ID.
    ///
    /// A refusal is an error whose `code` extension names why and whose
    /// `version` extension is the version applied, null before the first
    /// full list. Only REview may call it.
    #[graphql(guard = "ReviewOnly")]
    async fn endpoint_apply_active_list(
        &self,
        ctx: &Context<'_>,
        update: String,
        entry_id: ID,
    ) -> Result<EndpointListAck> {
        let list = ctx.data::<Arc<EndpointList>>()?;
        let database = ctx.data::<Database>()?;
        list.apply(&update, &entry_id, database)
            .await
            .map(EndpointListAck::from)
            .map_err(|refusal| refusal_error(&refusal))
    }

    /// Confirms that the endpoint active list REview pushes is at
    /// `version`, which extends the lease when it is the version applied.
    ///
    /// Only REview may call it.
    #[graphql(guard = "ReviewOnly")]
    async fn endpoint_confirm_active_list(
        &self,
        ctx: &Context<'_>,
        version: StringNumberU64,
    ) -> Result<EndpointListAck> {
        let list = ctx.data::<Arc<EndpointList>>()?;
        Ok(list.confirm(version.0).await.into())
    }
}

/// Returns the `code` extension of a refusal.
fn refusal_code(failure: &ApplyFailure) -> &'static str {
    match failure {
        ApplyFailure::InvalidUpdate(_) => "INVALID_UPDATE",
        ApplyFailure::InvalidEntryId(_) => "INVALID_ENTRY_ID",
        ApplyFailure::Store(_) => "STORE_FAILED",
        ApplyFailure::Refused(error) => match error {
            ApplyError::VersionMismatch { .. } => "VERSION_MISMATCH",
            ApplyError::VersionNotAdvanced { .. } => "VERSION_NOT_ADVANCED",
            ApplyError::UnknownReason { .. } => "UNKNOWN_REASON",
            ApplyError::RepeatedEndpoint { .. } => "REPEATED_ENDPOINT",
            ApplyError::DuplicateSpki { .. } => "DUPLICATE_SPKI",
            _ => "UNKNOWN",
        },
    }
}

/// Turns a refusal into the GraphQL error REview reads it from.
fn refusal_error(refusal: &ApplyRefusal) -> async_graphql::Error {
    let code = refusal_code(&refusal.failure);
    let message = match &refusal.failure {
        ApplyFailure::InvalidUpdate(message) | ApplyFailure::InvalidEntryId(message) => {
            message.clone()
        }
        ApplyFailure::Refused(error) => format!("the update was refused: {error}"),
        ApplyFailure::Store(error) => format!("the entry ID could not be stored: {error:#}"),
    };
    let version = refusal
        .version
        .map_or(Value::Null, |version| Value::String(version.to_string()));
    async_graphql::Error::new(message).extend_with(|_, extensions| {
        extensions.set("code", code);
        extensions.set("version", version.clone());
    })
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use async_graphql::{Request, Response, Value, value};
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    use poem::{Addr, web::RemoteAddr};
    use senta_protocol::auth::active_list::{EntryState, ListEntry, ListUpdate};
    use uuid::Uuid;

    use super::*;
    use crate::{
        graphql::{caller::REVIEW_SERVICE, tests::TestSchema},
        web::GraphqlCallers,
    };

    const ENTRY_ID: &str = "0b1c9e4e-6c8f-4a51-9d0e-6a3f6c2a1f10";
    const OTHER_ENTRY_ID: &str = "5d2a4b7c-1e3f-4a5b-8c6d-7e8f9a0b1c2d";

    /// The caller, by the service name in its certificate; `None` is a
    /// caller whose certificate carries none.
    async fn execute_as(schema: &TestSchema, service: Option<&str>, query: &str) -> Response {
        let callers = Arc::new(GraphqlCallers::default());
        let addr: SocketAddr = "192.0.2.10:40000".parse().expect("an address");
        callers.record_for_test(addr, service);
        let request = Request::new(query)
            .data(RemoteAddr(Addr::SocketAddr(addr)))
            .data(callers);
        schema.schema.execute(request).await
    }

    async fn as_review(schema: &TestSchema, query: &str) -> Response {
        execute_as(schema, Some(REVIEW_SERVICE), query).await
    }

    fn encode(update: &ListUpdate) -> String {
        BASE64.encode(update.encode().expect("encode the update"))
    }

    fn full_list(version: u64) -> String {
        encode(&ListUpdate::Full {
            version,
            entries: vec![ListEntry {
                endpoint_id: Uuid::from_u128(1),
                spki_sha256: [1; 32],
                customer_endpoint_id: Uuid::from_u128(2),
                state: EntryState::Active,
            }],
        })
    }

    fn apply_query(update: &str, entry_id: &str) -> String {
        format!(
            r#"mutation {{ endpointApplyActiveList(update: "{update}", entryId: "{entry_id}") {{ ready version }} }}"#
        )
    }

    const STATE_QUERY: &str = "{ endpointActiveListState { entryId ready version } }";

    fn error_extensions(response: &Response) -> (Value, Value) {
        let error = response.errors.first().expect("an error");
        let extensions = error.extensions.as_ref().expect("error extensions");
        (
            extensions.get("code").cloned().unwrap_or(Value::Null),
            extensions.get("version").cloned().unwrap_or(Value::Null),
        )
    }

    #[tokio::test]
    async fn apply_confirm_and_state_answer_review() {
        let schema = TestSchema::new();
        let response = as_review(&schema, STATE_QUERY).await;
        assert_eq!(
            response.data.into_json().unwrap(),
            serde_json::json!({
                "endpointActiveListState": { "entryId": null, "ready": false, "version": null }
            })
        );
        let response = as_review(
            &schema,
            r#"mutation { endpointConfirmActiveList(version: "3") { ready version } }"#,
        )
        .await;
        assert_eq!(
            response.data,
            value!({ "endpointConfirmActiveList": { "ready": false, "version": null } })
        );

        let response = as_review(&schema, &apply_query(&full_list(3), ENTRY_ID)).await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        assert_eq!(
            response.data,
            value!({ "endpointApplyActiveList": { "ready": true, "version": "3" } })
        );
        let response = as_review(
            &schema,
            r#"mutation { endpointConfirmActiveList(version: "3") { ready version } }"#,
        )
        .await;
        assert_eq!(
            response.data,
            value!({ "endpointConfirmActiveList": { "ready": true, "version": "3" } })
        );
        let response = as_review(&schema, STATE_QUERY).await;
        assert_eq!(
            response.data,
            value!({
                "endpointActiveListState": { "entryId": ENTRY_ID, "ready": true, "version": "3" }
            })
        );
    }

    #[tokio::test]
    async fn refusals_carry_their_code_and_the_current_version() {
        let schema = TestSchema::new();
        let mismatch = encode(&ListUpdate::Diff {
            base_version: 1,
            version: 2,
            upserts: Vec::new(),
            removals: Vec::new(),
        });
        let response = as_review(&schema, &apply_query(&mismatch, ENTRY_ID)).await;
        assert_eq!(
            error_extensions(&response),
            (Value::from("VERSION_MISMATCH"), Value::Null)
        );

        let response = as_review(&schema, &apply_query(&full_list(4), ENTRY_ID)).await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);

        let not_advanced = encode(&ListUpdate::Diff {
            base_version: 4,
            version: 4,
            upserts: Vec::new(),
            removals: Vec::new(),
        });
        let cbor_garbage = BASE64.encode([0xff_u8, 0x00, 0x13]);
        for (update, entry_id, code) in [
            (mismatch.as_str(), OTHER_ENTRY_ID, "VERSION_MISMATCH"),
            (
                not_advanced.as_str(),
                OTHER_ENTRY_ID,
                "VERSION_NOT_ADVANCED",
            ),
            ("@@not base64@@", OTHER_ENTRY_ID, "INVALID_UPDATE"),
            (cbor_garbage.as_str(), OTHER_ENTRY_ID, "INVALID_UPDATE"),
            (full_list(5).as_str(), "not-a-uuid", "INVALID_ENTRY_ID"),
            (
                full_list(5).as_str(),
                "00000000-0000-0000-0000-000000000000",
                "INVALID_ENTRY_ID",
            ),
        ] {
            let response = as_review(&schema, &apply_query(update, entry_id)).await;
            assert_eq!(
                error_extensions(&response),
                (Value::from(code), Value::from("4")),
                "{update} {entry_id}"
            );
            let state = as_review(&schema, STATE_QUERY).await;
            assert_eq!(
                state.data,
                value!({
                    "endpointActiveListState": { "entryId": ENTRY_ID, "ready": true, "version": "4" }
                }),
                "a refusal changes nothing"
            );
        }
    }

    #[test]
    fn each_refusal_maps_to_its_code() {
        let endpoint_id = Uuid::from_u128(1);
        for (failure, code) in [
            (
                ApplyFailure::Refused(ApplyError::UnknownReason { endpoint_id }),
                "UNKNOWN_REASON",
            ),
            (
                ApplyFailure::Refused(ApplyError::RepeatedEndpoint { endpoint_id }),
                "REPEATED_ENDPOINT",
            ),
            (
                ApplyFailure::Refused(ApplyError::DuplicateSpki {
                    first: endpoint_id,
                    second: Uuid::from_u128(2),
                }),
                "DUPLICATE_SPKI",
            ),
            (
                ApplyFailure::Store(anyhow::anyhow!("disk full")),
                "STORE_FAILED",
            ),
        ] {
            let error = refusal_error(&ApplyRefusal {
                failure,
                version: Some(7),
            });
            let extensions = error.extensions.expect("error extensions");
            assert_eq!(extensions.get("code"), Some(&Value::from(code)));
            assert_eq!(extensions.get("version"), Some(&Value::from("7")));
            if code == "STORE_FAILED" {
                assert!(error.message.contains("disk full"), "{}", error.message);
            }
        }
    }

    #[tokio::test]
    async fn only_review_may_call_the_endpoint_list_fields() {
        let schema = TestSchema::new();
        let calls = [
            apply_query(&full_list(1), ENTRY_ID),
            r#"mutation { endpointConfirmActiveList(version: "1") { ready version } }"#.to_owned(),
            STATE_QUERY.to_owned(),
        ];
        for service in [Some("piglet"), Some("giganto"), None] {
            for call in &calls {
                let response = execute_as(&schema, service, call).await;
                assert_eq!(response.errors.len(), 1, "{service:?}: {call}");
                assert_eq!(response.data, Value::Null, "{service:?}: {call}");
            }
        }
        // Without any caller in the request data, as from a test harness.
        let response = schema.execute(STATE_QUERY).await;
        assert_eq!(response.errors.len(), 1);
        assert_eq!(
            schema.endpoint_list.state(),
            crate::comm::endpoint::ListState {
                entry_id: None,
                ready: false,
                version: None,
            },
            "a refused caller has no effect"
        );

        // Another field still answers another service.
        let response = execute_as(&schema, Some("piglet"), "{ config { endpointSrvAddr } }").await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        // And another mutation reaches its resolver, which refuses the empty
        // configuration on its own grounds rather than the caller's.
        let response = execute_as(
            &schema,
            Some("piglet"),
            r#"mutation { updateConfig(old: "", new: "") { ingestSrvAddr } }"#,
        )
        .await;
        let error = response.errors.first().expect("the resolver's error");
        assert!(
            error.message.contains("empty new config"),
            "{:?}",
            response.errors
        );
    }

    #[test]
    fn the_schema_carries_the_endpoint_list_fields() {
        let sdl = crate::graphql::generate_schema();
        for expected in [
            "endpointApplyActiveList(update: String!, entryId: ID!): EndpointListAck!",
            "endpointConfirmActiveList(version: StringNumberU64!): EndpointListAck!",
            "endpointActiveListState: EndpointActiveListState!",
            "type EndpointListAck {",
            "type EndpointActiveListState {",
            "\tready: Boolean!\n",
            "\tversion: StringNumberU64\n",
            "\tentryId: ID\n",
        ] {
            assert!(sdl.contains(expected), "missing {expected:?}");
        }
    }
}

//! The GraphQL REview reads what the endpoint entry recorded about each
//! endpoint with: its loss records, its duplicate-key events and when it last
//! sent records.
//!
//! Only REview may call these fields, and none of them is forwarded to
//! peers: each node answers with what it holds itself.

use std::fmt::Write as _;

use async_graphql::{
    Context, ID, Object, Result, SimpleObject,
    connection::{Connection, Edge, query},
};
use uuid::Uuid;

use self::loss_reason::EndpointLossReason;
use super::{
    MAXIMUM_PAGE_SIZE, StringNumberI64, StringNumberU32, StringNumberU64, caller::ReviewOnly,
};
use crate::storage::{
    Database,
    endpoint::{StoredEndpointEvent, StoredLoss},
};

#[derive(Default)]
pub(super) struct EndpointStatusQuery;

// The `async_graphql::Enum` derive generates an `OutputType::resolve` impl
// whose `async` body has no `.await`, tripping `clippy::unused_async_trait_impl`
// at the module enclosing the enum, so the enum sits in a module of its own
// for the allow to cover nothing else. Remove it once async-graphql issue
// #1832 is fixed and released.
#[allow(clippy::unused_async_trait_impl)]
mod loss_reason {
    use async_graphql::Enum;

    use crate::storage::endpoint::LossReason;

    /// Why an endpoint's records were lost.
    #[derive(Enum, Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum EndpointLossReason {
        /// The endpoint dropped the range; the detail is the drop reason.
        Dropped,
        /// The endpoint lost the range when its state was reset; the detail is
        /// empty.
        LostOnReset,
        /// The node could not decode or convert the record; the detail is why.
        ConversionFailed,
    }

    impl From<LossReason> for EndpointLossReason {
        fn from(reason: LossReason) -> Self {
            match reason {
                LossReason::Dropped => Self::Dropped,
                LossReason::LostOnReset => Self::LostOnReset,
                LossReason::ConversionFailure => Self::ConversionFailed,
            }
        }
    }
}

/// A range of an endpoint's records that was lost.
#[derive(SimpleObject, Debug)]
struct EndpointLoss {
    /// The entry ID the loss was recorded under.
    entry_id: ID,
    /// The endpoint ID, lowercase hyphenated.
    endpoint_id: String,
    /// The telemetry stream ID, lowercase hyphenated.
    stream_id: String,
    /// The first sequence number of the range.
    from: StringNumberU64,
    /// The last sequence number of the range.
    to: StringNumberU64,
    /// Why the records were lost.
    reason: EndpointLossReason,
    /// The reason's detail, empty for `LOST_ON_RESET`.
    detail: String,
    /// When the node recorded the loss, in nanoseconds since the Unix epoch.
    received_at: StringNumberI64,
}

impl From<StoredLoss> for EndpointLoss {
    fn from(loss: StoredLoss) -> Self {
        Self {
            entry_id: ID(loss.entry_id.to_string()),
            endpoint_id: loss.endpoint_id.to_string(),
            stream_id: loss.stream.to_string(),
            from: StringNumberU64(loss.from),
            to: StringNumberU64(loss.to),
            reason: loss.reason.into(),
            detail: loss.detail,
            received_at: StringNumberI64(loss.received_ns),
        }
    }
}

/// One key's connections replaced each other too often, from more than one
/// address: two hosts may hold the same key.
#[derive(SimpleObject, Debug)]
struct EndpointDuplicateKeyEvent {
    /// When the node recorded the event, in nanoseconds since the Unix epoch.
    received_at: StringNumberI64,
    /// The endpoint ID, lowercase hyphenated.
    endpoint_id: String,
    /// The event's number among those of the same `receivedAt` and endpoint.
    sequence: StringNumberU32,
    /// The SHA-256 of the key's `SubjectPublicKeyInfo`, in lowercase hex.
    spki_sha256: String,
    /// The distinct source addresses of the connections counted.
    addresses: Vec<String>,
    /// How many replacements were counted.
    replacements: StringNumberU64,
}

impl From<StoredEndpointEvent> for EndpointDuplicateKeyEvent {
    fn from(stored: StoredEndpointEvent) -> Self {
        let StoredEndpointEvent {
            received_ns,
            endpoint_id,
            sequence,
            event,
        } = stored;
        let spki_sha256 =
            event
                .spki_sha256
                .iter()
                .fold(String::with_capacity(64), |mut hex, byte| {
                    let _ = write!(hex, "{byte:02x}");
                    hex
                });
        Self {
            received_at: StringNumberI64(received_ns),
            endpoint_id: endpoint_id.to_string(),
            sequence: StringNumberU32(sequence),
            spki_sha256,
            addresses: event.addresses.iter().map(ToString::to_string).collect(),
            replacements: StringNumberU64(event.replacements),
        }
    }
}

/// When an endpoint last sent records to this node.
#[derive(SimpleObject, Debug)]
struct EndpointLastReceivedTime {
    /// The endpoint ID, lowercase hyphenated.
    endpoint_id: String,
    /// The node's time when it received the endpoint's last write carrying
    /// records, in nanoseconds since the Unix epoch.
    last_received_at: StringNumberI64,
}

#[Object]
impl EndpointStatusQuery {
    /// Returns this node's endpoint loss records received at or after
    /// `since`, in nanoseconds since the Unix epoch, under every entry ID.
    ///
    /// `since` is inclusive; a negative one returns every record. The list is
    /// in no particular order and not paged. Only REview may call it.
    #[graphql(guard = "ReviewOnly")]
    async fn endpoint_losses(
        &self,
        ctx: &Context<'_>,
        since: StringNumberI64,
    ) -> Result<Vec<EndpointLoss>> {
        let db = ctx.data::<Database>()?.clone();
        let losses = read_off_runtime(move || db.endpoint_losses_since(since.0)).await?;
        Ok(losses.into_iter().map(Into::into).collect())
    }

    /// Returns this node's endpoint duplicate-key events received at or after
    /// `since`, in nanoseconds since the Unix epoch.
    ///
    /// `since` is inclusive; a negative one returns every event. The list is
    /// ordered by `receivedAt`, then endpoint ID, then `sequence`, and not
    /// paged. Only REview may call it.
    #[graphql(guard = "ReviewOnly")]
    async fn endpoint_events(
        &self,
        ctx: &Context<'_>,
        since: StringNumberI64,
    ) -> Result<Vec<EndpointDuplicateKeyEvent>> {
        let db = ctx.data::<Database>()?.clone();
        let events = read_off_runtime(move || db.endpoint_events_since(since.0)).await?;
        Ok(events
            .into_iter()
            .map(EndpointDuplicateKeyEvent::from)
            .collect())
    }

    /// Returns when each endpoint last sent records to this node, in endpoint
    /// ID order.
    ///
    /// The cursor is the endpoint ID; `after` returns the endpoints strictly
    /// after it. Only REview may call it.
    #[graphql(guard = "ReviewOnly")]
    async fn endpoint_last_received(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        first: Option<i32>,
    ) -> Result<Connection<String, EndpointLastReceivedTime>> {
        let db = ctx.data::<Database>()?;
        query(
            after,
            None,
            first,
            None,
            |after: Option<String>, _before: Option<String>, first, _last| async move {
                let after = after
                    .map(|after| Uuid::parse_str(&after))
                    .transpose()
                    .map_err(|_| "invalid cursor")?;
                let first = first.unwrap_or(MAXIMUM_PAGE_SIZE).min(MAXIMUM_PAGE_SIZE);
                let (page, has_next) = db
                    .endpoint_last_received(after, first)
                    .map_err(|e| format!("{e:#}"))?;
                let mut connection = Connection::new(false, has_next);
                connection.edges = page
                    .into_iter()
                    .map(|(endpoint_id, received_ns)| {
                        let endpoint_id = endpoint_id.to_string();
                        Edge::new(
                            endpoint_id.clone(),
                            EndpointLastReceivedTime {
                                endpoint_id,
                                last_received_at: StringNumberI64(received_ns),
                            },
                        )
                    })
                    .collect();
                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }
}

/// Runs a history read on Tokio's blocking pool and awaits its result.
///
/// `endpointLosses` scans the whole retained loss column family whatever
/// `since` is, and `endpointEvents` reads an unpaged range; the 30-day
/// retention bounds their age, not their size. Run on an async worker, either
/// read would hold that worker for the whole scan, stalling the ingestion,
/// timers and requests scheduled on it. The handle is awaited, so a failed or
/// panicking read fails the request. If the request itself is dropped first,
/// the read runs to completion and its result is discarded: it only reads, so
/// nothing is left half-done.
async fn read_off_runtime<T, F>(read: F) -> Result<T>
where
    F: FnOnce() -> anyhow::Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(read)
        .await
        .map_err(|e| format!("the endpoint history read did not finish: {e}"))?
        .map_err(|e| format!("{e:#}").into())
}

#[cfg(test)]
mod tests;

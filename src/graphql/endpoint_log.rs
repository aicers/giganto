//! Queries for the log records endpoints send: Windows event logs, journald
//! and auditd.

#[cfg(test)]
mod tests;

use std::net::IpAddr;

use async_graphql::{Context, InputObject, Object, Result, SimpleObject, connection::Connection};
use giganto_client::ingest::log::{
    AuditRecord, Auditd, EventData, Journald, LogField, LogValue, WindowsEventLog,
};
#[cfg(feature = "cluster")]
use giganto_proc_macro::ConvertGraphQLEdgesNode;
#[cfg(feature = "cluster")]
use graphql_client::GraphQLQuery;

use super::{
    FromKeyValue, RawEventFilter, StringNumberU64, TimeRange, endpoint_header::EndpointHeader,
    endpoint_header::to_hex, get_time_from_key, handle_paged_events, paged_events_in_cluster,
};
use crate::datetime::DateTime;
#[cfg(feature = "cluster")]
use crate::graphql::client::{
    cluster::impl_from_giganto_time_range_struct_for_graphql_client,
    derives::{
        EndpointAuditdEvents, EndpointJournaldEvents, EndpointWindowsEventLogEvents,
        endpoint_auditd_events, endpoint_journald_events, endpoint_windows_event_log_events,
    },
};
use crate::storage::{Database, KeyExtractor};

#[derive(Default)]
pub(super) struct EndpointLogQuery;

/// Filters for endpoint log queries.
#[derive(InputObject)]
pub struct EndpointLogFilter {
    time: Option<TimeRange>,
    /// Sensor
    ///
    /// The endpoint ID the records are stored under.
    sensor: String,
}

impl KeyExtractor for EndpointLogFilter {
    fn get_start_key(&self) -> &str {
        &self.sensor
    }

    fn get_mid_key(&self) -> Option<Vec<u8>> {
        None
    }

    fn get_range_end_key(&self) -> (Option<DateTime>, Option<DateTime>) {
        if let Some(time) = &self.time {
            (time.start, time.end)
        } else {
            (None, None)
        }
    }
}

impl RawEventFilter for EndpointLogFilter {
    fn check(
        &self,
        _orig_addr: Option<IpAddr>,
        _resp_addr: Option<IpAddr>,
        _orig_port: Option<u16>,
        _resp_port: Option<u16>,
        _log_level: Option<String>,
        _log_contents: Option<String>,
        _text: Option<String>,
        _sensor: Option<String>,
        _agent_id: Option<String>,
        _service_name: Option<String>,
    ) -> Result<bool> {
        Ok(true)
    }
}

/// An `EventData` element of a Windows event log record.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    endpoint_windows_event_log_events::EndpointWindowsEventLogEventsEndpointWindowsEventLogEventsEdgesNodeEventData
]))]
struct EndpointEventData {
    /// Name
    ///
    /// `null` for an unnamed element.
    name: Option<String>,
    /// Value
    value: String,
}

impl From<EventData> for EndpointEventData {
    fn from(data: EventData) -> Self {
        Self {
            name: data.name,
            value: data.value,
        }
    }
}

/// A named field of a journald or auditd record.
///
/// Exactly one of `text` and `bytes` is non-null.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    endpoint_journald_events::EndpointJournaldEventsEndpointJournaldEventsEdgesNodeFields,
    endpoint_auditd_events::EndpointAuditdEventsEndpointAuditdEventsEdgesNodeRecordsFields
]))]
struct EndpointLogField {
    /// Name
    name: String,
    /// Text Value
    ///
    /// The value when it is text.
    text: Option<String>,
    /// Bytes Value
    ///
    /// The value in lowercase hexadecimal when it is not text.
    bytes: Option<String>,
}

impl From<LogField> for EndpointLogField {
    fn from(field: LogField) -> Self {
        let (text, bytes) = match field.value {
            LogValue::Text(text) => (Some(text), None),
            LogValue::Bytes(bytes) => (None, Some(to_hex(&bytes))),
        };
        Self {
            name: field.name,
            text,
            bytes,
        }
    }
}

/// One record of an auditd event.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    endpoint_auditd_events::EndpointAuditdEventsEndpointAuditdEventsEdgesNodeRecords
]))]
struct EndpointAuditRecord {
    /// Record Type
    record_type: String,
    /// Fields
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    fields: Vec<EndpointLogField>,
}

impl From<AuditRecord> for EndpointAuditRecord {
    fn from(record: AuditRecord) -> Self {
        Self {
            record_type: record.record_type,
            fields: record.fields.into_iter().map(Into::into).collect(),
        }
    }
}

/// A Windows event log record an endpoint sent.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    endpoint_windows_event_log_events::EndpointWindowsEventLogEventsEndpointWindowsEventLogEventsEdgesNode
]))]
struct EndpointWindowsEventLogEvent {
    /// Event Time
    ///
    /// The time the record is stored under.
    time: DateTime,
    /// Channel
    channel: Option<String>,
    /// Provider
    provider: Option<String>,
    /// Event ID
    event_id: Option<u16>,
    /// Version
    version: Option<u8>,
    /// Level
    level: Option<u8>,
    /// Task
    task: Option<u16>,
    /// Opcode
    opcode: Option<u8>,
    /// Keywords
    keywords: Option<StringNumberU64>,
    /// Record ID
    record_id: Option<StringNumberU64>,
    /// Computer
    computer: Option<String>,
    /// User SID
    user_sid: Option<String>,
    /// Event Data
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    event_data: Option<Vec<EndpointEventData>>,
    /// User Data XML
    user_data_xml: Option<String>,
    /// Endpoint Header
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: EndpointHeader,
}

impl FromKeyValue<WindowsEventLog> for EndpointWindowsEventLogEvent {
    fn from_key_value(key: &[u8], val: WindowsEventLog) -> Result<Self> {
        Ok(Self {
            time: get_time_from_key(key)?,
            channel: val.channel,
            provider: val.provider,
            event_id: val.event_id,
            version: val.version,
            level: val.level,
            task: val.task,
            opcode: val.opcode,
            keywords: val.keywords.map(Into::into),
            record_id: val.record_id.map(Into::into),
            computer: val.computer,
            user_sid: val.user_sid,
            event_data: val
                .event_data
                .map(|data| data.into_iter().map(Into::into).collect()),
            user_data_xml: val.user_data_xml,
            endpoint: val.endpoint.into(),
        })
    }
}

/// A journald record an endpoint sent.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    endpoint_journald_events::EndpointJournaldEventsEndpointJournaldEventsEdgesNode
]))]
struct EndpointJournaldEvent {
    /// Event Time
    ///
    /// The time the record is stored under.
    time: DateTime,
    /// Fields
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    fields: Option<Vec<EndpointLogField>>,
    /// Endpoint Header
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: EndpointHeader,
}

impl FromKeyValue<Journald> for EndpointJournaldEvent {
    fn from_key_value(key: &[u8], val: Journald) -> Result<Self> {
        Ok(Self {
            time: get_time_from_key(key)?,
            fields: val
                .fields
                .map(|fields| fields.into_iter().map(Into::into).collect()),
            endpoint: val.endpoint.into(),
        })
    }
}

/// An auditd event an endpoint sent.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    endpoint_auditd_events::EndpointAuditdEventsEndpointAuditdEventsEdgesNode
]))]
struct EndpointAuditdEvent {
    /// Event Time
    ///
    /// The time the record is stored under.
    time: DateTime,
    /// Serial Number
    serial: Option<StringNumberU64>,
    /// Records
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    records: Option<Vec<EndpointAuditRecord>>,
    /// Endpoint Header
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: EndpointHeader,
}

impl FromKeyValue<Auditd> for EndpointAuditdEvent {
    fn from_key_value(key: &[u8], val: Auditd) -> Result<Self> {
        Ok(Self {
            time: get_time_from_key(key)?,
            serial: val.serial.map(Into::into),
            records: val
                .records
                .map(|records| records.into_iter().map(Into::into).collect()),
            endpoint: val.endpoint.into(),
        })
    }
}

async fn handle_endpoint_windows_event_log_events(
    ctx: &Context<'_>,
    filter: EndpointLogFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, EndpointWindowsEventLogEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.endpoint_windows_event_log_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_endpoint_journald_events(
    ctx: &Context<'_>,
    filter: EndpointLogFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, EndpointJournaldEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.endpoint_journald_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_endpoint_auditd_events(
    ctx: &Context<'_>,
    filter: EndpointLogFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, EndpointAuditdEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.endpoint_auditd_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

#[Object]
impl EndpointLogQuery {
    /// Returns the Windows event log records an endpoint sent.
    async fn endpoint_windows_event_log_events(
        &self,
        ctx: &Context<'_>,
        filter: EndpointLogFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, EndpointWindowsEventLogEvent>> {
        let handler = handle_endpoint_windows_event_log_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            EndpointWindowsEventLogEvents,
            endpoint_windows_event_log_events::Variables,
            endpoint_windows_event_log_events::ResponseData,
            endpoint_windows_event_log_events
        )
    }

    /// Returns the journald records an endpoint sent.
    async fn endpoint_journald_events(
        &self,
        ctx: &Context<'_>,
        filter: EndpointLogFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, EndpointJournaldEvent>> {
        let handler = handle_endpoint_journald_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            EndpointJournaldEvents,
            endpoint_journald_events::Variables,
            endpoint_journald_events::ResponseData,
            endpoint_journald_events
        )
    }

    /// Returns the auditd events an endpoint sent.
    async fn endpoint_auditd_events(
        &self,
        ctx: &Context<'_>,
        filter: EndpointLogFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, EndpointAuditdEvent>> {
        let handler = handle_endpoint_auditd_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            EndpointAuditdEvents,
            endpoint_auditd_events::Variables,
            endpoint_auditd_events::ResponseData,
            endpoint_auditd_events
        )
    }
}

#[cfg(feature = "cluster")]
macro_rules! impl_from_giganto_endpoint_log_filter_for_graphql_client {
    ($($autogen_mod:ident),*) => {
        $(
            impl From<EndpointLogFilter> for $autogen_mod::EndpointLogFilter {
                fn from(filter: EndpointLogFilter) -> Self {
                    Self {
                        time: filter.time.map(Into::into),
                        sensor: filter.sensor,
                    }
                }
            }
        )*
    };
}

#[cfg(feature = "cluster")]
impl_from_giganto_time_range_struct_for_graphql_client!(
    endpoint_windows_event_log_events,
    endpoint_journald_events,
    endpoint_auditd_events
);
#[cfg(feature = "cluster")]
impl_from_giganto_endpoint_log_filter_for_graphql_client!(
    endpoint_windows_event_log_events,
    endpoint_journald_events,
    endpoint_auditd_events
);

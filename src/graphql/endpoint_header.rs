//! The host header that endpoint records carry, as GraphQL objects.

use std::fmt::Write;

use async_graphql::SimpleObject;
use giganto_client::ingest::endpoint::{
    ClockOffset as ClientClockOffset, EndpointHeader as ClientEndpointHeader,
};
#[cfg(feature = "cluster")]
use giganto_proc_macro::ConvertGraphQLEdgesNode;

use crate::datetime::DateTime;
#[cfg(feature = "cluster")]
use crate::graphql::client::derives::{
    create_remote_thread_events, dns_query_events, driver_load_events, endpoint_auditd_events,
    endpoint_journald_events, endpoint_windows_event_log_events, file_create_events,
    file_create_stream_hash_events, file_create_time_events, file_delete_detected_events,
    file_delete_events, image_load_events, network_connect_events, pipe_event_events,
    process_access_events, process_create_events, process_tamper_events, process_terminate_events,
    raw_access_read_events, registry_key_rename_events, registry_object_add_del_events,
    registry_value_set_events, sysmon_events,
};
use crate::graphql::{StringNumberI64, StringNumberU32, StringNumberU64};

/// A measured offset of an endpoint's clock.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    process_create_events::EndpointHeaderFieldsClockOffset,
    file_create_time_events::EndpointHeaderFieldsClockOffset,
    network_connect_events::EndpointHeaderFieldsClockOffset,
    process_terminate_events::EndpointHeaderFieldsClockOffset,
    image_load_events::EndpointHeaderFieldsClockOffset,
    file_create_events::EndpointHeaderFieldsClockOffset,
    registry_value_set_events::EndpointHeaderFieldsClockOffset,
    registry_key_rename_events::EndpointHeaderFieldsClockOffset,
    file_create_stream_hash_events::EndpointHeaderFieldsClockOffset,
    pipe_event_events::EndpointHeaderFieldsClockOffset,
    dns_query_events::EndpointHeaderFieldsClockOffset,
    file_delete_events::EndpointHeaderFieldsClockOffset,
    process_tamper_events::EndpointHeaderFieldsClockOffset,
    file_delete_detected_events::EndpointHeaderFieldsClockOffset,
    driver_load_events::EndpointHeaderFieldsClockOffset,
    create_remote_thread_events::EndpointHeaderFieldsClockOffset,
    raw_access_read_events::EndpointHeaderFieldsClockOffset,
    process_access_events::EndpointHeaderFieldsClockOffset,
    registry_object_add_del_events::EndpointHeaderFieldsClockOffset,
    sysmon_events::EndpointHeaderFieldsClockOffset,
    endpoint_windows_event_log_events::EndpointHeaderFieldsClockOffset,
    endpoint_journald_events::EndpointHeaderFieldsClockOffset,
    endpoint_auditd_events::EndpointHeaderFieldsClockOffset,
]))]
pub(super) struct EndpointClockOffset {
    /// Clock Offset
    ///
    /// The offset of the endpoint's clock, in milliseconds.
    offset_ms: StringNumberI64,
    /// Uncertainty
    ///
    /// The uncertainty of the offset, in milliseconds.
    uncertainty_ms: StringNumberU32,
    /// Measurement Time
    measured_at: DateTime,
}

/// The host header identifying the endpoint, stream and collection a record
/// came from.
#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    process_create_events::EndpointHeaderFields,
    file_create_time_events::EndpointHeaderFields,
    network_connect_events::EndpointHeaderFields,
    process_terminate_events::EndpointHeaderFields,
    image_load_events::EndpointHeaderFields,
    file_create_events::EndpointHeaderFields,
    registry_value_set_events::EndpointHeaderFields,
    registry_key_rename_events::EndpointHeaderFields,
    file_create_stream_hash_events::EndpointHeaderFields,
    pipe_event_events::EndpointHeaderFields,
    dns_query_events::EndpointHeaderFields,
    file_delete_events::EndpointHeaderFields,
    process_tamper_events::EndpointHeaderFields,
    file_delete_detected_events::EndpointHeaderFields,
    driver_load_events::EndpointHeaderFields,
    create_remote_thread_events::EndpointHeaderFields,
    raw_access_read_events::EndpointHeaderFields,
    process_access_events::EndpointHeaderFields,
    registry_object_add_del_events::EndpointHeaderFields,
    sysmon_events::EndpointHeaderFields,
    endpoint_windows_event_log_events::EndpointHeaderFields,
    endpoint_journald_events::EndpointHeaderFields,
    endpoint_auditd_events::EndpointHeaderFields,
]))]
pub(super) struct EndpointHeader {
    /// Endpoint ID
    ///
    /// A lowercase hyphenated UUID.
    endpoint_id: String,
    /// Stream ID
    ///
    /// A lowercase hyphenated UUID.
    stream: String,
    /// Sequence Number
    seq: StringNumberU64,
    /// Event Time
    ///
    /// The time the event occurred on the endpoint.
    event_time: DateTime,
    /// Collection Time
    ///
    /// The time the endpoint collected the event.
    collected_at: DateTime,
    /// Clock Offset
    ///
    /// `null` when the endpoint did not measure it.
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    clock_offset: Option<EndpointClockOffset>,
    /// Hostname
    hostname: String,
    /// IP Addresses
    ips: Vec<String>,
    /// Default Route IP Address
    default_route_ip: Option<String>,
    /// Network State Source
    ///
    /// `observed`, `inferred`, `unknown`, or another value as sent.
    net_state_source: String,
    /// OS Family
    ///
    /// `windows`, `linux`, `macos`, or another value as sent.
    os_family: String,
    /// OS Version
    os_version: String,
    /// Collection Mode
    ///
    /// `extended`, `essential`, or another value as sent.
    collection_mode: String,
    /// Process Key
    ///
    /// Lowercase hexadecimal.
    process_key: Option<String>,
    /// Schema Version
    schema: u16,
}

impl From<ClientClockOffset> for EndpointClockOffset {
    fn from(offset: ClientClockOffset) -> Self {
        Self {
            offset_ms: offset.offset_ms.into(),
            uncertainty_ms: offset.uncertainty_ms.into(),
            measured_at: DateTime::from_timestamp_nanos(offset.measured_at),
        }
    }
}

impl From<ClientEndpointHeader> for EndpointHeader {
    fn from(header: ClientEndpointHeader) -> Self {
        Self {
            endpoint_id: header.endpoint_id.to_string(),
            stream: header.stream.to_string(),
            seq: header.seq.into(),
            event_time: DateTime::from_timestamp_nanos(header.event_time),
            collected_at: DateTime::from_timestamp_nanos(header.collected_at),
            clock_offset: header.clock_offset.map(Into::into),
            hostname: header.hostname,
            ips: header.ips.iter().map(ToString::to_string).collect(),
            default_route_ip: header.default_route_ip.map(|ip| ip.to_string()),
            net_state_source: header.net_state_source.to_string(),
            os_family: header.os_family.to_string(),
            os_version: header.os_version,
            collection_mode: header.collection_mode.to_string(),
            process_key: header.process_key.as_deref().map(to_hex),
            schema: header.schema,
        }
    }
}

/// Formats bytes as lowercase hexadecimal.
pub(super) fn to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            // Writing to a `String` never fails.
            let _ = write!(out, "{b:02x}");
            out
        })
}

#[cfg(test)]
pub(crate) mod fixtures;

#[cfg(test)]
mod tests {
    use giganto_client::ingest::endpoint::{CollectionMode, NetStateSource, OsFamily};

    use super::{EndpointHeader, fixtures::sparse_header, to_hex};

    #[test]
    fn header_enums_are_lowercase_names_or_the_sent_value() {
        let cases = [
            (
                NetStateSource::Observed,
                OsFamily::Windows,
                CollectionMode::Extended,
                ("observed", "windows", "extended"),
            ),
            (
                NetStateSource::Inferred,
                OsFamily::Linux,
                CollectionMode::Essential,
                ("inferred", "linux", "essential"),
            ),
            (
                NetStateSource::Unknown,
                OsFamily::Macos,
                CollectionMode::Other("Minimal".to_string()),
                ("unknown", "macos", "Minimal"),
            ),
            (
                NetStateSource::Other("probed".to_string()),
                OsFamily::Other("FreeBSD".to_string()),
                CollectionMode::Other(String::new()),
                ("probed", "FreeBSD", ""),
            ),
        ];
        for (net_state_source, os_family, collection_mode, expected) in cases {
            let header = EndpointHeader::from(giganto_client::ingest::endpoint::EndpointHeader {
                net_state_source,
                os_family,
                collection_mode,
                process_key: Some(Vec::new()),
                ..sparse_header()
            });
            assert_eq!(
                (
                    header.net_state_source.as_str(),
                    header.os_family.as_str(),
                    header.collection_mode.as_str()
                ),
                expected
            );
            assert_eq!(header.process_key.as_deref(), Some(""));
        }
    }

    #[test]
    fn to_hex_is_lowercase_and_zero_padded() {
        assert_eq!(to_hex(&[]), "");
        assert_eq!(to_hex(&[0x00, 0x0f, 0xab, 0xff]), "000fabff");
    }
}

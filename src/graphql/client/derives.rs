#![allow(clippy::enum_variant_names)]

use graphql_client::GraphQLQuery;

use crate::graphql::DateTime;
use crate::graphql::{StringNumberI64, StringNumberU32, StringNumberU64, StringNumberUsize};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/network_raw_events.graphql",
    response_derives = "Clone, PartialEq"
)]
pub struct NetworkRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/sysmon_events.graphql",
    response_derives = "Clone, PartialEq"
)]
pub struct SysmonEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/conn_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct ConnRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/dns_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct DnsRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/malformed_dns_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct MalformedDnsRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/dce_rpc_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct DceRpcRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/http_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct HttpRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/rdp_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct RdpRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/bootp_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct BootpRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/dhcp_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct DhcpRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/radius_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct RadiusRawEvents;

// Currently, `PeriodicTimeSeries` is not used in cluster mode. However, this API may be extended
// for use in the future. For now, `#[allow(dead_code)]` is applied to suppress clippy warnings.
#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/periodic_time_series.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
#[allow(dead_code)]
pub struct PeriodicTimeSeries;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/process_create_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct ProcessCreateEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/file_create_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct FileCreateEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/file_delete_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct FileDeleteEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/registry_value_set_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct RegistryValueSetEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/file_create_time_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct FileCreateTimeEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/network_connect_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct NetworkConnectEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/process_terminate_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct ProcessTerminateEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/image_load_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct ImageLoadEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/registry_key_rename_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct RegistryKeyRenameEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/file_create_stream_hash_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct FileCreateStreamHashEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/pipe_event_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct PipeEventEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/dns_query_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct DnsQueryEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/process_tamper_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct ProcessTamperEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/file_delete_detected_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct FileDeleteDetectedEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/ftp_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct FtpRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/kerberos_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct KerberosRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/ldap_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct LdapRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/mqtt_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct MqttRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/nfs_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct NfsRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/ntlm_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct NtlmRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/smb_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SmbRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/smtp_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SmtpRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/ssh_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SshRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/tls_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct TlsRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/packets.graphql",
    response_derives = "Debug, Clone, PartialEq"
)]
pub(crate) struct Packets;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/pcap.graphql",
    response_derives = "Debug, Clone, PartialEq"
)]
pub(crate) struct Pcap;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_conn_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchConnRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_dns_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchDnsRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_malformed_dns_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchMalformedDnsRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_http_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchHttpRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_rdp_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchRdpRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_smtp_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchSmtpRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_ntlm_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchNtlmRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_kerberos_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchKerberosRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_ssh_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchSshRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_dce_rpc_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchDceRpcRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_ftp_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchFtpRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_mqtt_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchMqttRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_ldap_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchLdapRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_tls_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchTlsRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_smb_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchSmbRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_nfs_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchNfsRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_bootp_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchBootpRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_dhcp_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchDhcpRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_radius_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchRadiusRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_process_create_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchProcessCreateEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_file_create_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchFileCreateEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_file_delete_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchFileDeleteEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_registry_value_set_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchRegistryValueSetEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_file_create_time_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchFileCreateTimeEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_network_connect_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchNetworkConnectEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_process_terminate_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchProcessTerminateEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_image_load_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchImageLoadEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_registry_key_rename_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchRegistryKeyRenameEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_file_create_stream_hash_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchFileCreateStreamHashEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_pipe_event_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchPipeEventEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_dns_query_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchDnsQueryEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_process_tamper_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchProcessTamperEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/search_file_delete_detected_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SearchFileDeleteDetectedEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/log_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct LogRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/netflow5_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct Netflow5RawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/netflow9_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct Netflow9RawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/secu_log_raw_events.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct SecuLogRawEvents;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/export.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct Export;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/client/schema/schema.graphql",
    query_path = "src/graphql/client/schema/statistics.graphql",
    response_derives = "Clone, Default, PartialEq"
)]
pub struct Statistics;

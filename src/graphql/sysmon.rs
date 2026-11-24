use std::{collections::BTreeSet, iter::Peekable, net::IpAddr};

use async_graphql::{
    Context, Object, Result, SimpleObject, Union,
    connection::{Connection, Edge, query},
};
use giganto_client::ingest::sysmon::{
    CreateRemoteThread, DnsEvent, DriverLoad, FileCreate, FileCreateStreamHash,
    FileCreationTimeChanged, FileDelete, FileDeleteDetected, ImageLoaded, NetworkConnection,
    PipeEvent, ProcessAccess, ProcessCreate, ProcessTampering, ProcessTerminated, RawAccessRead,
    RegistryKeyValueRename, RegistryObjectAddDel, RegistryValueSet,
};
#[cfg(feature = "cluster")]
use giganto_proc_macro::ConvertGraphQLEdgesNode;
#[cfg(feature = "cluster")]
use graphql_client::GraphQLQuery;

use super::{
    Engine, FromKeyValue, RawEventFilter, SearchFilter, SysmonEventFilter, base64_engine,
    check_agent_id, collect_exist_times, endpoint_header::EndpointHeader, events_vec_in_cluster,
    get_peekable_iter, get_time_from_key, handle_paged_events, min_max_time,
    paged_events_in_cluster,
};
use crate::datetime::DateTime;
#[cfg(feature = "cluster")]
use crate::graphql::client::{
    cluster::{
        impl_from_giganto_range_structs_for_graphql_client,
        impl_from_giganto_search_filter_for_graphql_client,
        impl_from_giganto_sysmon_event_filter_for_graphql_client,
        impl_from_giganto_time_range_struct_for_graphql_client,
    },
    derives::{
        CreateRemoteThreadEvents, DnsQueryEvents, DriverLoadEvents, FileCreateEvents,
        FileCreateStreamHashEvents, FileCreateTimeEvents, FileDeleteDetectedEvents,
        FileDeleteEvents, ImageLoadEvents, NetworkConnectEvents, PipeEventEvents,
        ProcessAccessEvents, ProcessCreateEvents, ProcessTamperEvents, ProcessTerminateEvents,
        RawAccessReadEvents, RegistryKeyRenameEvents, RegistryObjectAddDelEvents,
        RegistryValueSetEvents, SearchCreateRemoteThreadEvents, SearchDnsQueryEvents,
        SearchDriverLoadEvents, SearchFileCreateEvents, SearchFileCreateStreamHashEvents,
        SearchFileCreateTimeEvents, SearchFileDeleteDetectedEvents, SearchFileDeleteEvents,
        SearchImageLoadEvents, SearchNetworkConnectEvents, SearchPipeEventEvents,
        SearchProcessAccessEvents, SearchProcessCreateEvents, SearchProcessTamperEvents,
        SearchProcessTerminateEvents, SearchRawAccessReadEvents, SearchRegistryKeyRenameEvents,
        SearchRegistryObjectAddDelEvents, SearchRegistryValueSetEvents,
        SysmonEvents as SysmonEventsDerive, create_remote_thread_events, dns_query_events,
        driver_load_events, file_create_events, file_create_stream_hash_events,
        file_create_time_events, file_delete_detected_events, file_delete_events,
        image_load_events, network_connect_events, pipe_event_events, process_access_events,
        process_create_events, process_tamper_events, process_terminate_events,
        raw_access_read_events, registry_key_rename_events, registry_object_add_del_events,
        registry_value_set_events, search_create_remote_thread_events, search_dns_query_events,
        search_driver_load_events, search_file_create_events,
        search_file_create_stream_hash_events, search_file_create_time_events,
        search_file_delete_detected_events, search_file_delete_events, search_image_load_events,
        search_network_connect_events, search_pipe_event_events, search_process_access_events,
        search_process_create_events, search_process_tamper_events,
        search_process_terminate_events, search_raw_access_read_events,
        search_registry_key_rename_events, search_registry_object_add_del_events,
        search_registry_value_set_events, sysmon_events as sysmon_events_module,
    },
};
use crate::graphql::{StringNumberU32, StringNumberU64};
use crate::storage::{Database, FilteredIter, KeyExtractor};

#[derive(Default)]
pub(super) struct SysmonQuery;

impl KeyExtractor for SysmonEventFilter {
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

impl RawEventFilter for SysmonEventFilter {
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
        agent_id: Option<String>,
        _service_name: Option<String>,
    ) -> Result<bool> {
        Ok(check_agent_id(
            self.agent_id.as_deref(),
            agent_id.as_deref(),
        ))
    }
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    process_create_events::ProcessCreateEventsProcessCreateEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnProcessCreateEvent
]))]
struct ProcessCreateEvent {
    time: DateTime,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: StringNumberU32,
    image: String,
    file_version: String,
    description: String,
    product: String,
    company: String,
    original_file_name: String,
    command_line: String,
    current_directory: String,
    user: String,
    logon_guid: String,
    logon_id: StringNumberU32,
    terminal_session_id: StringNumberU32,
    integrity_level: String,
    hashes: Vec<String>,
    parent_process_guid: String,
    parent_process_id: StringNumberU32,
    parent_image: String,
    parent_command_line: String,
    parent_user: String,
    /// Endpoint Header
    ///
    /// `null` unless an endpoint sent the record.
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: Option<EndpointHeader>,
    /// Full Logon ID
    ///
    /// The 64-bit logon ID an endpoint sent; `logonId` then holds it if it fits
    /// in 32 bits and `4294967295` otherwise. `null` unless an endpoint sent
    /// the record.
    logon_id_full: Option<StringNumberU64>,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    file_create_time_events::FileCreateTimeEventsFileCreateTimeEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnFileCreationTimeChangedEvent
]))]
struct FileCreationTimeChangedEvent {
    time: DateTime,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: StringNumberU32,
    image: String,
    target_filename: String,
    creation_utc_time: DateTime,
    previous_creation_utc_time: DateTime,
    user: String,
    /// Endpoint Header
    ///
    /// `null` unless an endpoint sent the record.
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: Option<EndpointHeader>,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    network_connect_events::NetworkConnectEventsNetworkConnectEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnNetworkConnectionEvent
]))]
struct NetworkConnectionEvent {
    time: DateTime,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: StringNumberU32,
    image: String,
    user: String,
    protocol: String,
    initiated: bool,
    source_is_ipv6: bool,
    source_ip: String,
    source_hostname: String,
    source_port: u16,
    source_port_name: String,
    destination_is_ipv6: bool,
    destination_ip: String,
    destination_hostname: String,
    destination_port: u16,
    destination_port_name: String,
    /// Endpoint Header
    ///
    /// `null` unless an endpoint sent the record.
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: Option<EndpointHeader>,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    process_terminate_events::ProcessTerminateEventsProcessTerminateEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnProcessTerminatedEvent
]))]
struct ProcessTerminatedEvent {
    time: DateTime,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: StringNumberU32,
    image: String,
    user: String,
    /// Endpoint Header
    ///
    /// `null` unless an endpoint sent the record.
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: Option<EndpointHeader>,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    image_load_events::ImageLoadEventsImageLoadEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnImageLoadedEvent
]))]
struct ImageLoadedEvent {
    time: DateTime,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: StringNumberU32,
    image: String,
    image_loaded: String,
    file_version: String,
    description: String,
    product: String,
    company: String,
    original_file_name: String,
    hashes: Vec<String>,
    signed: bool,
    signature: String,
    signature_status: String,
    user: String,
    /// Endpoint Header
    ///
    /// `null` unless an endpoint sent the record.
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: Option<EndpointHeader>,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    file_create_events::FileCreateEventsFileCreateEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnFileCreateEvent
]))]
struct FileCreateEvent {
    time: DateTime,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: StringNumberU32,
    image: String,
    target_filename: String,
    creation_utc_time: DateTime,
    user: String,
    /// Endpoint Header
    ///
    /// `null` unless an endpoint sent the record.
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: Option<EndpointHeader>,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    registry_value_set_events::RegistryValueSetEventsRegistryValueSetEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnRegistryValueSetEvent
]))]
struct RegistryValueSetEvent {
    time: DateTime,
    agent_name: String,
    agent_id: String,
    event_type: String,
    process_guid: String,
    process_id: StringNumberU32,
    image: String,
    target_object: String,
    details: String,
    user: String,
    /// Endpoint Header
    ///
    /// `null` unless an endpoint sent the record.
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: Option<EndpointHeader>,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    registry_key_rename_events::RegistryKeyRenameEventsRegistryKeyRenameEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnRegistryKeyValueRenameEvent
]))]
struct RegistryKeyValueRenameEvent {
    time: DateTime,
    agent_name: String,
    agent_id: String,
    event_type: String,
    process_guid: String,
    process_id: StringNumberU32,
    image: String,
    target_object: String,
    new_name: String,
    user: String,
    /// Endpoint Header
    ///
    /// `null` unless an endpoint sent the record.
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: Option<EndpointHeader>,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    file_create_stream_hash_events::FileCreateStreamHashEventsFileCreateStreamHashEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnFileCreateStreamHashEvent
]))]
struct FileCreateStreamHashEvent {
    time: DateTime,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: StringNumberU32,
    image: String,
    target_filename: String,
    creation_utc_time: DateTime,
    hash: Vec<String>,
    contents: String,
    user: String,
    /// Endpoint Header
    ///
    /// `null` unless an endpoint sent the record.
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: Option<EndpointHeader>,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    pipe_event_events::PipeEventEventsPipeEventEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnPipeEventEvent
]))]
struct PipeEventEvent {
    time: DateTime,
    agent_name: String,
    agent_id: String,
    event_type: String,
    process_guid: String,
    process_id: StringNumberU32,
    pipe_name: String,
    image: String,
    user: String,
    /// Endpoint Header
    ///
    /// `null` unless an endpoint sent the record.
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: Option<EndpointHeader>,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    dns_query_events::DnsQueryEventsDnsQueryEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnDnsEventEvent
]))]
struct DnsEventEvent {
    time: DateTime,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: StringNumberU32,
    query_name: String,
    query_status: StringNumberU32,
    query_results: Vec<String>, // divided by ';'
    image: String,
    user: String,
    /// Endpoint Header
    ///
    /// `null` unless an endpoint sent the record.
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: Option<EndpointHeader>,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    file_delete_events::FileDeleteEventsFileDeleteEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnFileDeleteEvent
]))]
struct FileDeleteEvent {
    time: DateTime,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: StringNumberU32,
    user: String,
    image: String,
    target_filename: String,
    hashes: Vec<String>,
    is_executable: bool,
    archived: bool,
    /// Endpoint Header
    ///
    /// `null` unless an endpoint sent the record.
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: Option<EndpointHeader>,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    process_tamper_events::ProcessTamperEventsProcessTamperEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnProcessTamperingEvent
]))]
struct ProcessTamperingEvent {
    time: DateTime,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: StringNumberU32,
    image: String,
    tamper_type: String, // type
    user: String,
    /// Endpoint Header
    ///
    /// `null` unless an endpoint sent the record.
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: Option<EndpointHeader>,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    file_delete_detected_events::FileDeleteDetectedEventsFileDeleteDetectedEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnFileDeleteDetectedEvent
]))]
struct FileDeleteDetectedEvent {
    time: DateTime,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: StringNumberU32,
    user: String,
    image: String,
    target_filename: String,
    hashes: Vec<String>,
    is_executable: bool,
    /// Endpoint Header
    ///
    /// `null` unless an endpoint sent the record.
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: Option<EndpointHeader>,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    driver_load_events::DriverLoadEventsDriverLoadEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnDriverLoadEvent
]))]
struct DriverLoadEvent {
    time: DateTime,
    agent_name: String,
    agent_id: String,
    image_loaded: String,
    hashes: Vec<String>,
    signed: bool,
    signature: String,
    signature_status: String,
    /// Endpoint Header
    ///
    /// `null` unless an endpoint sent the record.
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: Option<EndpointHeader>,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    create_remote_thread_events::CreateRemoteThreadEventsCreateRemoteThreadEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnCreateRemoteThreadEvent
]))]
struct CreateRemoteThreadEvent {
    time: DateTime,
    agent_name: String,
    agent_id: String,
    source_process_guid: String,
    source_process_id: StringNumberU32,
    source_image: String,
    target_process_guid: String,
    target_process_id: StringNumberU32,
    target_image: String,
    new_thread_id: StringNumberU32,
    start_address: String,
    start_module: String,
    start_function: String,
    source_user: String,
    target_user: String,
    /// Endpoint Header
    ///
    /// `null` unless an endpoint sent the record.
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: Option<EndpointHeader>,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    raw_access_read_events::RawAccessReadEventsRawAccessReadEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnRawAccessReadEvent
]))]
struct RawAccessReadEvent {
    time: DateTime,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: StringNumberU32,
    image: String,
    device: String,
    user: String,
    /// Endpoint Header
    ///
    /// `null` unless an endpoint sent the record.
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: Option<EndpointHeader>,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    process_access_events::ProcessAccessEventsProcessAccessEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnProcessAccessEvent
]))]
struct ProcessAccessEvent {
    time: DateTime,
    agent_name: String,
    agent_id: String,
    source_process_guid: String,
    source_process_id: StringNumberU32,
    source_thread_id: StringNumberU32,
    source_image: String,
    target_process_guid: String,
    target_process_id: StringNumberU32,
    target_image: String,
    granted_access: StringNumberU64,
    call_trace: String,
    source_user: String,
    target_user: String,
    /// Endpoint Header
    ///
    /// `null` unless an endpoint sent the record.
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: Option<EndpointHeader>,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    registry_object_add_del_events::RegistryObjectAddDelEventsRegistryObjectAddDelEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnRegistryObjectAddDelEvent
]))]
struct RegistryObjectAddDelEvent {
    time: DateTime,
    agent_name: String,
    agent_id: String,
    event_type: String,
    process_guid: String,
    process_id: StringNumberU32,
    image: String,
    target_object: String,
    user: String,
    /// Endpoint Header
    ///
    /// `null` unless an endpoint sent the record.
    #[cfg_attr(feature = "cluster", graphql_client_type(recursive_into = true))]
    endpoint: Option<EndpointHeader>,
}

#[allow(clippy::enum_variant_names)]
#[derive(Union)]
enum SysmonEvents {
    ProcessCreateEvent(ProcessCreateEvent),
    FileCreationTimeChangedEvent(FileCreationTimeChangedEvent),
    NetworkConnectionEvent(NetworkConnectionEvent),
    ProcessTerminatedEvent(ProcessTerminatedEvent),
    ImageLoadedEvent(ImageLoadedEvent),
    FileCreateEvent(FileCreateEvent),
    RegistryValueSetEvent(RegistryValueSetEvent),
    RegistryKeyValueRenameEvent(RegistryKeyValueRenameEvent),
    FileCreateStreamHashEvent(FileCreateStreamHashEvent),
    PipeEventEvent(PipeEventEvent),
    DnsEventEvent(DnsEventEvent),
    FileDeleteEvent(FileDeleteEvent),
    ProcessTamperingEvent(ProcessTamperingEvent),
    FileDeleteDetectedEvent(FileDeleteDetectedEvent),
    DriverLoadEvent(DriverLoadEvent),
    CreateRemoteThreadEvent(CreateRemoteThreadEvent),
    RawAccessReadEvent(RawAccessReadEvent),
    ProcessAccessEvent(ProcessAccessEvent),
    RegistryObjectAddDelEvent(RegistryObjectAddDelEvent),
}

#[cfg(feature = "cluster")]
impl From<sysmon_events_module::SysmonEventsSysmonEventsEdgesNode> for SysmonEvents {
    fn from(node: sysmon_events_module::SysmonEventsSysmonEventsEdgesNode) -> Self {
        match node {
            sysmon_events_module::SysmonEventsSysmonEventsEdgesNode::ProcessCreateEvent(event) => SysmonEvents::ProcessCreateEvent(event.into()),
            sysmon_events_module::SysmonEventsSysmonEventsEdgesNode::FileCreationTimeChangedEvent(event) => SysmonEvents::FileCreationTimeChangedEvent(event.into()),
            sysmon_events_module::SysmonEventsSysmonEventsEdgesNode::NetworkConnectionEvent(event) => SysmonEvents::NetworkConnectionEvent(event.into()),
            sysmon_events_module::SysmonEventsSysmonEventsEdgesNode::ProcessTerminatedEvent(event) => SysmonEvents::ProcessTerminatedEvent(event.into()),
            sysmon_events_module::SysmonEventsSysmonEventsEdgesNode::ImageLoadedEvent(event) => SysmonEvents::ImageLoadedEvent(event.into()),
            sysmon_events_module::SysmonEventsSysmonEventsEdgesNode::FileCreateEvent(event) => SysmonEvents::FileCreateEvent(event.into()),
            sysmon_events_module::SysmonEventsSysmonEventsEdgesNode::RegistryValueSetEvent(event) => SysmonEvents::RegistryValueSetEvent(event.into()),
            sysmon_events_module::SysmonEventsSysmonEventsEdgesNode::RegistryKeyValueRenameEvent(event) => SysmonEvents::RegistryKeyValueRenameEvent(event.into()),
            sysmon_events_module::SysmonEventsSysmonEventsEdgesNode::FileCreateStreamHashEvent(event) => SysmonEvents::FileCreateStreamHashEvent(event.into()),
            sysmon_events_module::SysmonEventsSysmonEventsEdgesNode::PipeEventEvent(event) => SysmonEvents::PipeEventEvent(event.into()),
            sysmon_events_module::SysmonEventsSysmonEventsEdgesNode::DnsEventEvent(event) => SysmonEvents::DnsEventEvent(event.into()),
            sysmon_events_module::SysmonEventsSysmonEventsEdgesNode::FileDeleteEvent(event) => SysmonEvents::FileDeleteEvent(event.into()),
            sysmon_events_module::SysmonEventsSysmonEventsEdgesNode::ProcessTamperingEvent(event) => SysmonEvents::ProcessTamperingEvent(event.into()),
            sysmon_events_module::SysmonEventsSysmonEventsEdgesNode::FileDeleteDetectedEvent(event) => SysmonEvents::FileDeleteDetectedEvent(event.into()),
            sysmon_events_module::SysmonEventsSysmonEventsEdgesNode::DriverLoadEvent(event) => SysmonEvents::DriverLoadEvent(event.into()),
            sysmon_events_module::SysmonEventsSysmonEventsEdgesNode::CreateRemoteThreadEvent(event) => SysmonEvents::CreateRemoteThreadEvent(event.into()),
            sysmon_events_module::SysmonEventsSysmonEventsEdgesNode::RawAccessReadEvent(event) => SysmonEvents::RawAccessReadEvent(event.into()),
            sysmon_events_module::SysmonEventsSysmonEventsEdgesNode::ProcessAccessEvent(event) => SysmonEvents::ProcessAccessEvent(event.into()),
            sysmon_events_module::SysmonEventsSysmonEventsEdgesNode::RegistryObjectAddDelEvent(event) => SysmonEvents::RegistryObjectAddDelEvent(event.into()),
        }
    }
}

macro_rules! from_key_value {
    (
        $to:ty, $from:ty, $($plain_field:ident),* ; $( $str_num_field:ident ),*
        $(; $( $opt_num_field:ident ),* )?
    ) => {
        impl FromKeyValue<$from> for $to {
            fn from_key_value(key: &[u8], val: $from) -> Result<Self> {
                let time = get_time_from_key(key)?;
                Ok(Self {
                    time,
                    agent_name: val.agent_name,
                    agent_id: val.agent_id,
                    process_guid: val.process_guid,
                    $(
                        $plain_field: val.$plain_field,
                    )*
                    $(
                        $str_num_field: val.$str_num_field.into(),
                    )*
                    $($(
                        $opt_num_field: val.$opt_num_field.map(Into::into),
                    )*)?
                    endpoint: val.endpoint.map(Into::into),
                })
            }
        }
    };
}

from_key_value!(
    ProcessCreateEvent,
    ProcessCreate,
    image,
    file_version,
    description,
    product,
    company,
    original_file_name,
    command_line,
    current_directory,
    user,
    logon_guid,
    integrity_level,
    hashes,
    parent_process_guid,
    parent_image,
    parent_command_line,
    parent_user;
    process_id,
    logon_id,
    terminal_session_id,
    parent_process_id;
    logon_id_full
);

impl FromKeyValue<FileCreationTimeChanged> for FileCreationTimeChangedEvent {
    fn from_key_value(key: &[u8], val: FileCreationTimeChanged) -> Result<Self> {
        Ok(FileCreationTimeChangedEvent {
            time: get_time_from_key(key)?,
            agent_name: val.agent_name,
            agent_id: val.agent_id,
            process_guid: val.process_guid,
            image: val.image,
            target_filename: val.target_filename,
            user: val.user,
            process_id: val.process_id.into(),
            creation_utc_time: DateTime::from_timestamp_nanos(val.creation_utc_time),
            previous_creation_utc_time: DateTime::from_timestamp_nanos(
                val.previous_creation_utc_time,
            ),
            endpoint: val.endpoint.map(Into::into),
        })
    }
}

from_key_value!(ProcessTerminatedEvent, ProcessTerminated, image, user; process_id);

from_key_value!(
    ImageLoadedEvent,
    ImageLoaded,
    image,
    image_loaded,
    file_version,
    description,
    product,
    company,
    original_file_name,
    hashes,
    signed,
    signature,
    signature_status,
    user;
    process_id
);

impl FromKeyValue<FileCreate> for FileCreateEvent {
    fn from_key_value(key: &[u8], val: FileCreate) -> Result<Self> {
        Ok(FileCreateEvent {
            time: get_time_from_key(key)?,
            agent_name: val.agent_name,
            agent_id: val.agent_id,
            process_guid: val.process_guid,
            image: val.image,
            target_filename: val.target_filename,
            user: val.user,
            process_id: val.process_id.into(),
            creation_utc_time: DateTime::from_timestamp_nanos(val.creation_utc_time),
            endpoint: val.endpoint.map(Into::into),
        })
    }
}

from_key_value!(
    RegistryValueSetEvent,
    RegistryValueSet,
    event_type,
    image,
    target_object,
    details,
    user;
    process_id
);

from_key_value!(
    RegistryKeyValueRenameEvent,
    RegistryKeyValueRename,
    event_type,
    image,
    target_object,
    new_name,
    user;
    process_id
);

impl FromKeyValue<FileCreateStreamHash> for FileCreateStreamHashEvent {
    fn from_key_value(key: &[u8], val: FileCreateStreamHash) -> Result<Self> {
        Ok(FileCreateStreamHashEvent {
            time: get_time_from_key(key)?,
            agent_name: val.agent_name,
            agent_id: val.agent_id,
            process_guid: val.process_guid,
            image: val.image,
            target_filename: val.target_filename,
            hash: val.hash,
            contents: val.contents,
            user: val.user,
            process_id: val.process_id.into(),
            creation_utc_time: DateTime::from_timestamp_nanos(val.creation_utc_time),
            endpoint: val.endpoint.map(Into::into),
        })
    }
}

from_key_value!(
    PipeEventEvent,
    PipeEvent,
    event_type,
    pipe_name,
    image,
    user;
    process_id
);

from_key_value!(
    DnsEventEvent,
    DnsEvent,
    query_name,
    query_results,
    image,
    user;
    process_id,
    query_status
);

from_key_value!(
    FileDeleteEvent,
    FileDelete,
    user,
    image,
    target_filename,
    hashes,
    is_executable,
    archived;
    process_id
);

from_key_value!(
    ProcessTamperingEvent,
    ProcessTampering,
    image,
    tamper_type,
    user;
    process_id
);

from_key_value!(
    FileDeleteDetectedEvent,
    FileDeleteDetected,
    user,
    image,
    target_filename,
    hashes,
    is_executable;
    process_id
);

impl FromKeyValue<NetworkConnection> for NetworkConnectionEvent {
    fn from_key_value(key: &[u8], value: NetworkConnection) -> Result<Self> {
        Ok(NetworkConnectionEvent {
            time: get_time_from_key(key)?,
            agent_name: value.agent_name,
            agent_id: value.agent_id,
            process_guid: value.process_guid,
            process_id: value.process_id.into(),
            image: value.image,
            user: value.user,
            protocol: value.protocol,
            initiated: value.initiated,
            source_is_ipv6: value.source_is_ipv6,
            source_ip: value.source_ip.to_string(),
            source_hostname: value.source_hostname,
            source_port: value.source_port,
            source_port_name: value.source_port_name,
            destination_is_ipv6: value.destination_is_ipv6,
            destination_ip: value.destination_ip.to_string(),
            destination_hostname: value.destination_hostname,
            destination_port: value.destination_port,
            destination_port_name: value.destination_port_name,
            endpoint: value.endpoint.map(Into::into),
        })
    }
}

impl FromKeyValue<DriverLoad> for DriverLoadEvent {
    fn from_key_value(key: &[u8], val: DriverLoad) -> Result<Self> {
        Ok(Self {
            time: get_time_from_key(key)?,
            agent_name: val.agent_name,
            agent_id: val.agent_id,
            image_loaded: val.image_loaded,
            hashes: val.hashes,
            signed: val.signed,
            signature: val.signature,
            signature_status: val.signature_status,
            endpoint: val.endpoint.map(Into::into),
        })
    }
}

impl FromKeyValue<CreateRemoteThread> for CreateRemoteThreadEvent {
    fn from_key_value(key: &[u8], val: CreateRemoteThread) -> Result<Self> {
        Ok(Self {
            time: get_time_from_key(key)?,
            agent_name: val.agent_name,
            agent_id: val.agent_id,
            source_process_guid: val.source_process_guid,
            source_process_id: val.source_process_id.into(),
            source_image: val.source_image,
            target_process_guid: val.target_process_guid,
            target_process_id: val.target_process_id.into(),
            target_image: val.target_image,
            new_thread_id: val.new_thread_id.into(),
            start_address: val.start_address,
            start_module: val.start_module,
            start_function: val.start_function,
            source_user: val.source_user,
            target_user: val.target_user,
            endpoint: val.endpoint.map(Into::into),
        })
    }
}

impl FromKeyValue<RawAccessRead> for RawAccessReadEvent {
    fn from_key_value(key: &[u8], val: RawAccessRead) -> Result<Self> {
        Ok(Self {
            time: get_time_from_key(key)?,
            agent_name: val.agent_name,
            agent_id: val.agent_id,
            process_guid: val.process_guid,
            process_id: val.process_id.into(),
            image: val.image,
            device: val.device,
            user: val.user,
            endpoint: val.endpoint.map(Into::into),
        })
    }
}

impl FromKeyValue<ProcessAccess> for ProcessAccessEvent {
    fn from_key_value(key: &[u8], val: ProcessAccess) -> Result<Self> {
        Ok(Self {
            time: get_time_from_key(key)?,
            agent_name: val.agent_name,
            agent_id: val.agent_id,
            source_process_guid: val.source_process_guid,
            source_process_id: val.source_process_id.into(),
            source_thread_id: val.source_thread_id.into(),
            source_image: val.source_image,
            target_process_guid: val.target_process_guid,
            target_process_id: val.target_process_id.into(),
            target_image: val.target_image,
            granted_access: val.granted_access.into(),
            call_trace: val.call_trace,
            source_user: val.source_user,
            target_user: val.target_user,
            endpoint: val.endpoint.map(Into::into),
        })
    }
}

impl FromKeyValue<RegistryObjectAddDel> for RegistryObjectAddDelEvent {
    fn from_key_value(key: &[u8], val: RegistryObjectAddDel) -> Result<Self> {
        Ok(Self {
            time: get_time_from_key(key)?,
            agent_name: val.agent_name,
            agent_id: val.agent_id,
            event_type: val.event_type,
            process_guid: val.process_guid,
            process_id: val.process_id.into(),
            image: val.image,
            target_object: val.target_object,
            user: val.user,
            endpoint: val.endpoint.map(Into::into),
        })
    }
}

async fn handle_process_create_events(
    ctx: &Context<'_>,
    filter: SysmonEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, ProcessCreateEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.process_create_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_file_create_time_events(
    ctx: &Context<'_>,
    filter: SysmonEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, FileCreationTimeChangedEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.file_create_time_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_network_connect_events(
    ctx: &Context<'_>,
    filter: SysmonEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, NetworkConnectionEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.network_connect_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_process_terminate_events(
    ctx: &Context<'_>,
    filter: SysmonEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, ProcessTerminatedEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.process_terminate_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_image_load_events(
    ctx: &Context<'_>,
    filter: SysmonEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, ImageLoadedEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.image_load_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_file_create_events(
    ctx: &Context<'_>,
    filter: SysmonEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, FileCreateEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.file_create_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_registry_value_set_events(
    ctx: &Context<'_>,
    filter: SysmonEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, RegistryValueSetEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.registry_value_set_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_registry_key_rename_events(
    ctx: &Context<'_>,
    filter: SysmonEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, RegistryKeyValueRenameEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.registry_key_rename_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_file_create_stream_hash_events(
    ctx: &Context<'_>,
    filter: SysmonEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, FileCreateStreamHashEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.file_create_stream_hash_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_pipe_event_events(
    ctx: &Context<'_>,
    filter: SysmonEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, PipeEventEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.pipe_event_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_dns_query_events(
    ctx: &Context<'_>,
    filter: SysmonEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, DnsEventEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.dns_query_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_file_delete_events(
    ctx: &Context<'_>,
    filter: SysmonEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, FileDeleteEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.file_delete_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_process_tamper_events(
    ctx: &Context<'_>,
    filter: SysmonEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, ProcessTamperingEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.process_tamper_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_file_delete_detected_events(
    ctx: &Context<'_>,
    filter: SysmonEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, FileDeleteDetectedEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.file_delete_detected_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_driver_load_events(
    ctx: &Context<'_>,
    filter: SysmonEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, DriverLoadEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.driver_load_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_create_remote_thread_events(
    ctx: &Context<'_>,
    filter: SysmonEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, CreateRemoteThreadEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.create_remote_thread_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_raw_access_read_events(
    ctx: &Context<'_>,
    filter: SysmonEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, RawAccessReadEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.raw_access_read_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_process_access_events(
    ctx: &Context<'_>,
    filter: SysmonEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, ProcessAccessEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.process_access_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_registry_object_add_del_events(
    ctx: &Context<'_>,
    filter: SysmonEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, RegistryObjectAddDelEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.registry_object_add_del_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

#[Object]
impl SysmonQuery {
    async fn process_create_events(
        &self,
        ctx: &Context<'_>,
        filter: SysmonEventFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, ProcessCreateEvent>> {
        let handler = handle_process_create_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            ProcessCreateEvents,
            process_create_events::Variables,
            process_create_events::ResponseData,
            process_create_events
        )
    }

    async fn file_create_time_events(
        &self,
        ctx: &Context<'_>,
        filter: SysmonEventFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, FileCreationTimeChangedEvent>> {
        let handler = handle_file_create_time_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            FileCreateTimeEvents,
            file_create_time_events::Variables,
            file_create_time_events::ResponseData,
            file_create_time_events
        )
    }

    async fn network_connect_events(
        &self,
        ctx: &Context<'_>,
        filter: SysmonEventFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, NetworkConnectionEvent>> {
        let handler = handle_network_connect_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            NetworkConnectEvents,
            network_connect_events::Variables,
            network_connect_events::ResponseData,
            network_connect_events
        )
    }

    async fn process_terminate_events(
        &self,
        ctx: &Context<'_>,
        filter: SysmonEventFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, ProcessTerminatedEvent>> {
        let handler = handle_process_terminate_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            ProcessTerminateEvents,
            process_terminate_events::Variables,
            process_terminate_events::ResponseData,
            process_terminate_events
        )
    }

    async fn image_load_events(
        &self,
        ctx: &Context<'_>,
        filter: SysmonEventFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, ImageLoadedEvent>> {
        let operation = handle_image_load_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            operation,
            ImageLoadEvents,
            image_load_events::Variables,
            image_load_events::ResponseData,
            image_load_events
        )
    }

    async fn file_create_events(
        &self,
        ctx: &Context<'_>,
        filter: SysmonEventFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, FileCreateEvent>> {
        let handler = handle_file_create_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            FileCreateEvents,
            file_create_events::Variables,
            file_create_events::ResponseData,
            file_create_events
        )
    }

    async fn registry_value_set_events(
        &self,
        ctx: &Context<'_>,
        filter: SysmonEventFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, RegistryValueSetEvent>> {
        let handler = handle_registry_value_set_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            RegistryValueSetEvents,
            registry_value_set_events::Variables,
            registry_value_set_events::ResponseData,
            registry_value_set_events
        )
    }

    async fn registry_key_rename_events(
        &self,
        ctx: &Context<'_>,
        filter: SysmonEventFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, RegistryKeyValueRenameEvent>> {
        let handler = handle_registry_key_rename_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            RegistryKeyRenameEvents,
            registry_key_rename_events::Variables,
            registry_key_rename_events::ResponseData,
            registry_key_rename_events
        )
    }

    async fn file_create_stream_hash_events(
        &self,
        ctx: &Context<'_>,
        filter: SysmonEventFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, FileCreateStreamHashEvent>> {
        let handler = handle_file_create_stream_hash_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            FileCreateStreamHashEvents,
            file_create_stream_hash_events::Variables,
            file_create_stream_hash_events::ResponseData,
            file_create_stream_hash_events
        )
    }

    async fn pipe_event_events(
        &self,
        ctx: &Context<'_>,
        filter: SysmonEventFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, PipeEventEvent>> {
        let handler = handle_pipe_event_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            PipeEventEvents,
            pipe_event_events::Variables,
            pipe_event_events::ResponseData,
            pipe_event_events
        )
    }

    async fn dns_query_events(
        &self,
        ctx: &Context<'_>,
        filter: SysmonEventFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, DnsEventEvent>> {
        let handler = handle_dns_query_events;
        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            DnsQueryEvents,
            dns_query_events::Variables,
            dns_query_events::ResponseData,
            dns_query_events
        )
    }

    async fn file_delete_events(
        &self,
        ctx: &Context<'_>,
        filter: SysmonEventFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, FileDeleteEvent>> {
        let handler = handle_file_delete_events;
        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            FileDeleteEvents,
            file_delete_events::Variables,
            file_delete_events::ResponseData,
            file_delete_events
        )
    }

    async fn process_tamper_events(
        &self,
        ctx: &Context<'_>,
        filter: SysmonEventFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, ProcessTamperingEvent>> {
        let handler = handle_process_tamper_events;
        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            ProcessTamperEvents,
            process_tamper_events::Variables,
            process_tamper_events::ResponseData,
            process_tamper_events
        )
    }

    async fn file_delete_detected_events(
        &self,
        ctx: &Context<'_>,
        filter: SysmonEventFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, FileDeleteDetectedEvent>> {
        let handler = handle_file_delete_detected_events;
        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            FileDeleteDetectedEvents,
            file_delete_detected_events::Variables,
            file_delete_detected_events::ResponseData,
            file_delete_detected_events
        )
    }

    async fn search_process_create_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.process_create_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime, Vec<u8>)>>();
            Ok(collect_exist_times::<ProcessCreate>(&exist_data, filter))
        };
        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchProcessCreateEvents,
            search_process_create_events::Variables,
            search_process_create_events::ResponseData,
            search_process_create_events
        )
    }

    async fn search_file_create_time_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.file_create_time_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime, Vec<u8>)>>();
            Ok(collect_exist_times::<FileCreationTimeChanged>(
                &exist_data,
                filter,
            ))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchFileCreateTimeEvents,
            search_file_create_time_events::Variables,
            search_file_create_time_events::ResponseData,
            search_file_create_time_events
        )
    }

    async fn search_network_connect_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.network_connect_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime, Vec<u8>)>>();
            Ok(collect_exist_times::<NetworkConnection>(
                &exist_data,
                filter,
            ))
        };
        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchNetworkConnectEvents,
            search_network_connect_events::Variables,
            search_network_connect_events::ResponseData,
            search_network_connect_events
        )
    }

    async fn search_process_terminate_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.process_terminate_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime, Vec<u8>)>>();
            Ok(collect_exist_times::<ProcessTerminated>(
                &exist_data,
                filter,
            ))
        };
        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchProcessTerminateEvents,
            search_process_terminate_events::Variables,
            search_process_terminate_events::ResponseData,
            search_process_terminate_events
        )
    }

    async fn search_image_load_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.image_load_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime, Vec<u8>)>>();
            Ok(collect_exist_times::<ImageLoaded>(&exist_data, filter))
        };
        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchImageLoadEvents,
            search_image_load_events::Variables,
            search_image_load_events::ResponseData,
            search_image_load_events
        )
    }

    async fn search_file_create_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.file_create_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime, Vec<u8>)>>();
            Ok(collect_exist_times::<FileCreate>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchFileCreateEvents,
            search_file_create_events::Variables,
            search_file_create_events::ResponseData,
            search_file_create_events
        )
    }

    async fn search_registry_value_set_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.registry_value_set_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime, Vec<u8>)>>();
            Ok(collect_exist_times::<RegistryValueSet>(&exist_data, filter))
        };
        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchRegistryValueSetEvents,
            search_registry_value_set_events::Variables,
            search_registry_value_set_events::ResponseData,
            search_registry_value_set_events
        )
    }

    async fn search_registry_key_rename_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.registry_key_rename_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime, Vec<u8>)>>();
            Ok(collect_exist_times::<RegistryKeyValueRename>(
                &exist_data,
                filter,
            ))
        };
        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchRegistryKeyRenameEvents,
            search_registry_key_rename_events::Variables,
            search_registry_key_rename_events::ResponseData,
            search_registry_key_rename_events
        )
    }

    async fn search_file_create_stream_hash_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.file_create_stream_hash_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime, Vec<u8>)>>();
            Ok(collect_exist_times::<FileCreateStreamHash>(
                &exist_data,
                filter,
            ))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchFileCreateStreamHashEvents,
            search_file_create_stream_hash_events::Variables,
            search_file_create_stream_hash_events::ResponseData,
            search_file_create_stream_hash_events
        )
    }

    async fn search_pipe_event_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.pipe_event_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime, Vec<u8>)>>();
            Ok(collect_exist_times::<PipeEvent>(&exist_data, filter))
        };
        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchPipeEventEvents,
            search_pipe_event_events::Variables,
            search_pipe_event_events::ResponseData,
            search_pipe_event_events
        )
    }

    async fn search_dns_query_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.dns_query_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime, Vec<u8>)>>();
            Ok(collect_exist_times::<DnsEvent>(&exist_data, filter))
        };
        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchDnsQueryEvents,
            search_dns_query_events::Variables,
            search_dns_query_events::ResponseData,
            search_dns_query_events
        )
    }

    async fn search_file_delete_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.file_delete_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime, Vec<u8>)>>();
            Ok(collect_exist_times::<FileDelete>(&exist_data, filter))
        };

        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchFileDeleteEvents,
            search_file_delete_events::Variables,
            search_file_delete_events::ResponseData,
            search_file_delete_events
        )
    }

    async fn search_process_tamper_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.process_tamper_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime, Vec<u8>)>>();
            Ok(collect_exist_times::<ProcessTampering>(&exist_data, filter))
        };
        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchProcessTamperEvents,
            search_process_tamper_events::Variables,
            search_process_tamper_events::ResponseData,
            search_process_tamper_events
        )
    }

    async fn search_file_delete_detected_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.file_delete_detected_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime, Vec<u8>)>>();
            Ok(collect_exist_times::<FileDeleteDetected>(
                &exist_data,
                filter,
            ))
        };
        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchFileDeleteDetectedEvents,
            search_file_delete_detected_events::Variables,
            search_file_delete_detected_events::ResponseData,
            search_file_delete_detected_events
        )
    }

    async fn driver_load_events(
        &self,
        ctx: &Context<'_>,
        filter: SysmonEventFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, DriverLoadEvent>> {
        let handler = handle_driver_load_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            DriverLoadEvents,
            driver_load_events::Variables,
            driver_load_events::ResponseData,
            driver_load_events
        )
    }

    async fn create_remote_thread_events(
        &self,
        ctx: &Context<'_>,
        filter: SysmonEventFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, CreateRemoteThreadEvent>> {
        let handler = handle_create_remote_thread_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            CreateRemoteThreadEvents,
            create_remote_thread_events::Variables,
            create_remote_thread_events::ResponseData,
            create_remote_thread_events
        )
    }

    async fn raw_access_read_events(
        &self,
        ctx: &Context<'_>,
        filter: SysmonEventFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, RawAccessReadEvent>> {
        let handler = handle_raw_access_read_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            RawAccessReadEvents,
            raw_access_read_events::Variables,
            raw_access_read_events::ResponseData,
            raw_access_read_events
        )
    }

    async fn process_access_events(
        &self,
        ctx: &Context<'_>,
        filter: SysmonEventFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, ProcessAccessEvent>> {
        let handler = handle_process_access_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            ProcessAccessEvents,
            process_access_events::Variables,
            process_access_events::ResponseData,
            process_access_events
        )
    }

    async fn registry_object_add_del_events(
        &self,
        ctx: &Context<'_>,
        filter: SysmonEventFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, RegistryObjectAddDelEvent>> {
        let handler = handle_registry_object_add_del_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            RegistryObjectAddDelEvents,
            registry_object_add_del_events::Variables,
            registry_object_add_del_events::ResponseData,
            registry_object_add_del_events
        )
    }

    async fn search_driver_load_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.driver_load_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime, Vec<u8>)>>();
            Ok(collect_exist_times::<DriverLoad>(&exist_data, filter))
        };
        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchDriverLoadEvents,
            search_driver_load_events::Variables,
            search_driver_load_events::ResponseData,
            search_driver_load_events
        )
    }

    async fn search_create_remote_thread_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.create_remote_thread_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime, Vec<u8>)>>();
            Ok(collect_exist_times::<CreateRemoteThread>(
                &exist_data,
                filter,
            ))
        };
        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchCreateRemoteThreadEvents,
            search_create_remote_thread_events::Variables,
            search_create_remote_thread_events::ResponseData,
            search_create_remote_thread_events
        )
    }

    async fn search_raw_access_read_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.raw_access_read_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime, Vec<u8>)>>();
            Ok(collect_exist_times::<RawAccessRead>(&exist_data, filter))
        };
        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchRawAccessReadEvents,
            search_raw_access_read_events::Variables,
            search_raw_access_read_events::ResponseData,
            search_raw_access_read_events
        )
    }

    async fn search_process_access_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.process_access_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime, Vec<u8>)>>();
            Ok(collect_exist_times::<ProcessAccess>(&exist_data, filter))
        };
        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchProcessAccessEvents,
            search_process_access_events::Variables,
            search_process_access_events::ResponseData,
            search_process_access_events
        )
    }

    async fn search_registry_object_add_del_events(
        &self,
        ctx: &Context<'_>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.registry_object_add_del_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime, Vec<u8>)>>();
            Ok(collect_exist_times::<RegistryObjectAddDel>(
                &exist_data,
                filter,
            ))
        };
        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            SearchRegistryObjectAddDelEvents,
            search_registry_object_add_del_events::Variables,
            search_registry_object_add_del_events::ResponseData,
            search_registry_object_add_del_events
        )
    }

    async fn sysmon_events(
        &self,
        ctx: &Context<'_>,
        filter: SysmonEventFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, SysmonEvents>> {
        let handler = handle_sysmon_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            SysmonEventsDerive,
            sysmon_events_module::Variables,
            sysmon_events_module::ResponseData,
            sysmon_events
        )
    }
}

#[allow(clippy::too_many_lines)]
async fn handle_sysmon_events(
    ctx: &Context<'_>,
    filter: SysmonEventFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, SysmonEvents>> {
    let db = ctx.data::<Database>()?;
    query(
        after,
        before,
        first,
        last,
        |after, before, first, last| async move {
            let (process_create_iter, size) = get_peekable_iter(
                &db.process_create_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (file_create_time_iter, _) = get_peekable_iter(
                &db.file_create_time_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (network_connect_iter, _) = get_peekable_iter(
                &db.network_connect_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (process_terminate_iter, _) = get_peekable_iter(
                &db.process_terminate_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (image_load_iter, _) = get_peekable_iter(
                &db.image_load_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (file_create_iter, _) = get_peekable_iter(
                &db.file_create_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (registry_value_set_iter, _) = get_peekable_iter(
                &db.registry_value_set_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (registry_key_rename_iter, _) = get_peekable_iter(
                &db.registry_key_rename_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (file_create_stream_hash_iter, _) = get_peekable_iter(
                &db.file_create_stream_hash_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (pipe_event_iter, _) = get_peekable_iter(
                &db.pipe_event_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (dns_query_iter, _) = get_peekable_iter(
                &db.dns_query_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (file_delete_iter, _) = get_peekable_iter(
                &db.file_delete_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (process_tamper_iter, _) = get_peekable_iter(
                &db.process_tamper_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (file_delete_detected_iter, _) = get_peekable_iter(
                &db.file_delete_detected_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (driver_load_iter, _) = get_peekable_iter(
                &db.driver_load_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (create_remote_thread_iter, _) = get_peekable_iter(
                &db.create_remote_thread_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (raw_access_read_iter, _) = get_peekable_iter(
                &db.raw_access_read_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (process_access_iter, _) = get_peekable_iter(
                &db.process_access_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let (registry_object_add_del_iter, _) = get_peekable_iter(
                &db.registry_object_add_del_store()?,
                &filter,
                after.as_deref(),
                before.as_deref(),
                first,
                last,
            )?;

            let mut is_forward: bool = true;
            if before.is_some() || last.is_some() {
                is_forward = false;
            }

            sysmon_connection(
                process_create_iter,
                file_create_time_iter,
                network_connect_iter,
                process_terminate_iter,
                image_load_iter,
                file_create_iter,
                registry_value_set_iter,
                registry_key_rename_iter,
                file_create_stream_hash_iter,
                pipe_event_iter,
                dns_query_iter,
                file_delete_iter,
                process_tamper_iter,
                file_delete_detected_iter,
                driver_load_iter,
                create_remote_thread_iter,
                raw_access_read_iter,
                process_access_iter,
                registry_object_add_del_iter,
                size,
                is_forward,
                after.is_some(),
                before.is_some(),
            )
        },
    )
    .await
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn sysmon_connection(
    mut process_create_iter: Peekable<FilteredIter<ProcessCreate, SysmonEventFilter>>,
    mut file_create_time_iter: Peekable<FilteredIter<FileCreationTimeChanged, SysmonEventFilter>>,
    mut network_connect_iter: Peekable<FilteredIter<NetworkConnection, SysmonEventFilter>>,
    mut process_terminate_iter: Peekable<FilteredIter<ProcessTerminated, SysmonEventFilter>>,
    mut image_load_iter: Peekable<FilteredIter<ImageLoaded, SysmonEventFilter>>,
    mut file_create_iter: Peekable<FilteredIter<FileCreate, SysmonEventFilter>>,
    mut registry_value_set_iter: Peekable<FilteredIter<RegistryValueSet, SysmonEventFilter>>,
    mut registry_key_rename_iter: Peekable<FilteredIter<RegistryKeyValueRename, SysmonEventFilter>>,
    mut file_create_stream_hash_iter: Peekable<
        FilteredIter<FileCreateStreamHash, SysmonEventFilter>,
    >,
    mut pipe_event_iter: Peekable<FilteredIter<PipeEvent, SysmonEventFilter>>,
    mut dns_query_iter: Peekable<FilteredIter<DnsEvent, SysmonEventFilter>>,
    mut file_delete_iter: Peekable<FilteredIter<FileDelete, SysmonEventFilter>>,
    mut process_tamper_iter: Peekable<FilteredIter<ProcessTampering, SysmonEventFilter>>,
    mut file_delete_detected_iter: Peekable<FilteredIter<FileDeleteDetected, SysmonEventFilter>>,
    mut driver_load_iter: Peekable<FilteredIter<DriverLoad, SysmonEventFilter>>,
    mut create_remote_thread_iter: Peekable<FilteredIter<CreateRemoteThread, SysmonEventFilter>>,
    mut raw_access_read_iter: Peekable<FilteredIter<RawAccessRead, SysmonEventFilter>>,
    mut process_access_iter: Peekable<FilteredIter<ProcessAccess, SysmonEventFilter>>,
    mut registry_object_add_del_iter: Peekable<
        FilteredIter<RegistryObjectAddDel, SysmonEventFilter>,
    >,
    size: usize,
    is_forward: bool,
    has_after: bool,
    has_before: bool,
) -> Result<Connection<String, SysmonEvents>> {
    let time = min_max_time(is_forward);
    let mut result_vec: Vec<Edge<String, SysmonEvents, _>> = Vec::new();
    let mut has_previous_page: bool = false;
    let mut has_next_page: bool = false;
    let mut has_next_value: bool = false;

    let mut process_create_data = process_create_iter.next();
    let mut file_create_time_data = file_create_time_iter.next();
    let mut network_connect_data = network_connect_iter.next();
    let mut process_terminate_data = process_terminate_iter.next();
    let mut image_load_data = image_load_iter.next();
    let mut file_create_data = file_create_iter.next();
    let mut registry_value_set_data = registry_value_set_iter.next();
    let mut registry_key_rename_data = registry_key_rename_iter.next();
    let mut file_create_stream_hash_data = file_create_stream_hash_iter.next();
    let mut pipe_event_data = pipe_event_iter.next();
    let mut dns_query_data = dns_query_iter.next();
    let mut file_delete_data = file_delete_iter.next();
    let mut process_tamper_data = process_tamper_iter.next();
    let mut file_delete_detected_data = file_delete_detected_iter.next();
    let mut driver_load_data = driver_load_iter.next();
    let mut create_remote_thread_data = create_remote_thread_iter.next();
    let mut raw_access_read_data = raw_access_read_iter.next();
    let mut process_access_data = process_access_iter.next();
    let mut registry_object_add_del_data = registry_object_add_del_iter.next();

    loop {
        if (result_vec.len() >= size)
            || (process_create_data.is_none()
                && file_create_time_data.is_none()
                && network_connect_data.is_none()
                && process_terminate_data.is_none()
                && image_load_data.is_none()
                && file_create_data.is_none()
                && registry_value_set_data.is_none()
                && registry_key_rename_data.is_none()
                && file_create_stream_hash_data.is_none()
                && pipe_event_data.is_none()
                && dns_query_data.is_none()
                && file_delete_data.is_none()
                && process_tamper_data.is_none()
                && file_delete_detected_data.is_none()
                && driver_load_data.is_none()
                && create_remote_thread_data.is_none()
                && raw_access_read_data.is_none()
                && process_access_data.is_none()
                && registry_object_add_del_data.is_none())
        {
            if process_create_data.is_some()
                || file_create_time_data.is_some()
                || network_connect_data.is_some()
                || process_terminate_data.is_some()
                || image_load_data.is_some()
                || file_create_data.is_some()
                || registry_value_set_data.is_some()
                || registry_key_rename_data.is_some()
                || file_create_stream_hash_data.is_some()
                || pipe_event_data.is_some()
                || dns_query_data.is_some()
                || file_delete_data.is_some()
                || process_tamper_data.is_some()
                || file_delete_detected_data.is_some()
                || driver_load_data.is_some()
                || create_remote_thread_data.is_some()
                || raw_access_read_data.is_some()
                || process_access_data.is_some()
                || registry_object_add_del_data.is_some()
            {
                has_next_value = true;
            }
            if is_forward {
                has_next_page = has_next_value;
            } else {
                result_vec.reverse();
                has_previous_page = has_next_value;
            }
            break;
        }

        let process_create_ts = if let Some((ref key, _)) = process_create_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let file_create_time_ts = if let Some((ref key, _)) = file_create_time_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let network_connect_ts = if let Some((ref key, _)) = network_connect_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let process_terminate_ts = if let Some((ref key, _)) = process_terminate_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let image_load_ts = if let Some((ref key, _)) = image_load_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let file_create_ts = if let Some((ref key, _)) = file_create_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let registry_value_set_ts = if let Some((ref key, _)) = registry_value_set_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let registry_key_rename_ts = if let Some((ref key, _)) = registry_key_rename_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let file_create_stream_hash_ts = if let Some((ref key, _)) = file_create_stream_hash_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let pipe_event_ts = if let Some((ref key, _)) = pipe_event_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let dns_query_ts = if let Some((ref key, _)) = dns_query_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let file_delete_ts = if let Some((ref key, _)) = file_delete_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let process_tamper_ts = if let Some((ref key, _)) = process_tamper_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let file_delete_detected_ts = if let Some((ref key, _)) = file_delete_detected_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let driver_load_ts = if let Some((ref key, _)) = driver_load_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let create_remote_thread_ts = if let Some((ref key, _)) = create_remote_thread_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let raw_access_read_ts = if let Some((ref key, _)) = raw_access_read_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let process_access_ts = if let Some((ref key, _)) = process_access_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let registry_object_add_del_ts = if let Some((ref key, _)) = registry_object_add_del_data {
            get_time_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let selected = if is_forward {
            time.min(file_create_time_ts)
                .min(process_create_ts)
                .min(network_connect_ts)
                .min(process_terminate_ts)
                .min(image_load_ts)
                .min(file_create_ts)
                .min(registry_value_set_ts)
                .min(registry_key_rename_ts)
                .min(file_create_stream_hash_ts)
                .min(pipe_event_ts)
                .min(dns_query_ts)
                .min(file_delete_ts)
                .min(process_tamper_ts)
                .min(file_delete_detected_ts)
                .min(driver_load_ts)
                .min(create_remote_thread_ts)
                .min(raw_access_read_ts)
                .min(process_access_ts)
                .min(registry_object_add_del_ts)
        } else {
            time.max(file_create_time_ts)
                .max(process_create_ts)
                .max(network_connect_ts)
                .max(process_terminate_ts)
                .max(image_load_ts)
                .max(file_create_ts)
                .max(registry_value_set_ts)
                .max(registry_key_rename_ts)
                .max(file_create_stream_hash_ts)
                .max(pipe_event_ts)
                .max(dns_query_ts)
                .max(file_delete_ts)
                .max(process_tamper_ts)
                .max(file_delete_detected_ts)
                .max(driver_load_ts)
                .max(create_remote_thread_ts)
                .max(raw_access_read_ts)
                .max(process_access_ts)
                .max(registry_object_add_del_ts)
        };

        match selected {
            _ if selected == process_create_ts => {
                if let Some((key, value)) = process_create_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::ProcessCreateEvent(ProcessCreateEvent::from_key_value(
                            &key, value,
                        )?),
                    ));
                    process_create_data = process_create_iter.next();
                }
            }
            _ if selected == file_create_time_ts => {
                if let Some((key, value)) = file_create_time_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::FileCreationTimeChangedEvent(
                            FileCreationTimeChangedEvent::from_key_value(&key, value)?,
                        ),
                    ));
                    file_create_time_data = file_create_time_iter.next();
                }
            }
            _ if selected == network_connect_ts => {
                if let Some((key, value)) = network_connect_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::NetworkConnectionEvent(
                            NetworkConnectionEvent::from_key_value(&key, value)?,
                        ),
                    ));
                    network_connect_data = network_connect_iter.next();
                }
            }
            _ if selected == process_terminate_ts => {
                if let Some((key, value)) = process_terminate_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::ProcessTerminatedEvent(
                            ProcessTerminatedEvent::from_key_value(&key, value)?,
                        ),
                    ));
                    process_terminate_data = process_terminate_iter.next();
                }
            }
            _ if selected == image_load_ts => {
                if let Some((key, value)) = image_load_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::ImageLoadedEvent(ImageLoadedEvent::from_key_value(
                            &key, value,
                        )?),
                    ));
                    image_load_data = image_load_iter.next();
                }
            }
            _ if selected == file_create_ts => {
                if let Some((key, value)) = file_create_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::FileCreateEvent(FileCreateEvent::from_key_value(
                            &key, value,
                        )?),
                    ));
                    file_create_data = file_create_iter.next();
                }
            }
            _ if selected == registry_value_set_ts => {
                if let Some((key, value)) = registry_value_set_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::RegistryValueSetEvent(RegistryValueSetEvent::from_key_value(
                            &key, value,
                        )?),
                    ));
                    registry_value_set_data = registry_value_set_iter.next();
                }
            }
            _ if selected == registry_key_rename_ts => {
                if let Some((key, value)) = registry_key_rename_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::RegistryKeyValueRenameEvent(
                            RegistryKeyValueRenameEvent::from_key_value(&key, value)?,
                        ),
                    ));
                    registry_key_rename_data = registry_key_rename_iter.next();
                }
            }
            _ if selected == file_create_stream_hash_ts => {
                if let Some((key, value)) = file_create_stream_hash_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::FileCreateStreamHashEvent(
                            FileCreateStreamHashEvent::from_key_value(&key, value)?,
                        ),
                    ));
                    file_create_stream_hash_data = file_create_stream_hash_iter.next();
                }
            }
            _ if selected == pipe_event_ts => {
                if let Some((key, value)) = pipe_event_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::PipeEventEvent(PipeEventEvent::from_key_value(&key, value)?),
                    ));
                    pipe_event_data = pipe_event_iter.next();
                }
            }
            _ if selected == dns_query_ts => {
                if let Some((key, value)) = dns_query_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::DnsEventEvent(DnsEventEvent::from_key_value(&key, value)?),
                    ));
                    dns_query_data = dns_query_iter.next();
                }
            }
            _ if selected == file_delete_ts => {
                if let Some((key, value)) = file_delete_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::FileDeleteEvent(FileDeleteEvent::from_key_value(
                            &key, value,
                        )?),
                    ));
                    file_delete_data = file_delete_iter.next();
                }
            }
            _ if selected == process_tamper_ts => {
                if let Some((key, value)) = process_tamper_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::ProcessTamperingEvent(ProcessTamperingEvent::from_key_value(
                            &key, value,
                        )?),
                    ));
                    process_tamper_data = process_tamper_iter.next();
                }
            }
            _ if selected == file_delete_detected_ts => {
                if let Some((key, value)) = file_delete_detected_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::FileDeleteDetectedEvent(
                            FileDeleteDetectedEvent::from_key_value(&key, value)?,
                        ),
                    ));
                    file_delete_detected_data = file_delete_detected_iter.next();
                }
            }
            _ if selected == driver_load_ts => {
                if let Some((key, value)) = driver_load_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::DriverLoadEvent(DriverLoadEvent::from_key_value(
                            &key, value,
                        )?),
                    ));
                    driver_load_data = driver_load_iter.next();
                }
            }
            _ if selected == create_remote_thread_ts => {
                if let Some((key, value)) = create_remote_thread_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::CreateRemoteThreadEvent(
                            CreateRemoteThreadEvent::from_key_value(&key, value)?,
                        ),
                    ));
                    create_remote_thread_data = create_remote_thread_iter.next();
                }
            }
            _ if selected == raw_access_read_ts => {
                if let Some((key, value)) = raw_access_read_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::RawAccessReadEvent(RawAccessReadEvent::from_key_value(
                            &key, value,
                        )?),
                    ));
                    raw_access_read_data = raw_access_read_iter.next();
                }
            }
            _ if selected == process_access_ts => {
                if let Some((key, value)) = process_access_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::ProcessAccessEvent(ProcessAccessEvent::from_key_value(
                            &key, value,
                        )?),
                    ));
                    process_access_data = process_access_iter.next();
                }
            }
            _ if selected == registry_object_add_del_ts => {
                if let Some((key, value)) = registry_object_add_del_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::RegistryObjectAddDelEvent(
                            RegistryObjectAddDelEvent::from_key_value(&key, value)?,
                        ),
                    ));
                    registry_object_add_del_data = registry_object_add_del_iter.next();
                }
            }
            _ => {}
        }
    }

    if is_forward {
        has_previous_page = has_after;
    } else {
        has_next_page = has_before;
    }
    let mut connection: Connection<String, SysmonEvents> =
        Connection::new(has_previous_page, has_next_page);
    connection.edges.extend(result_vec);

    Ok(connection)
}

#[cfg(feature = "cluster")]
impl_from_giganto_time_range_struct_for_graphql_client!(
    sysmon_events_module,
    dns_query_events,
    file_create_events,
    file_create_stream_hash_events,
    file_create_time_events,
    file_delete_detected_events,
    file_delete_events,
    image_load_events,
    network_connect_events,
    pipe_event_events,
    process_create_events,
    process_tamper_events,
    process_terminate_events,
    registry_key_rename_events,
    registry_value_set_events,
    driver_load_events,
    create_remote_thread_events,
    raw_access_read_events,
    process_access_events,
    registry_object_add_del_events
);

#[cfg(feature = "cluster")]
impl_from_giganto_range_structs_for_graphql_client!(
    search_dns_query_events,
    search_file_create_events,
    search_file_create_stream_hash_events,
    search_file_create_time_events,
    search_file_delete_detected_events,
    search_file_delete_events,
    search_image_load_events,
    search_network_connect_events,
    search_pipe_event_events,
    search_process_create_events,
    search_process_tamper_events,
    search_process_terminate_events,
    search_registry_key_rename_events,
    search_registry_value_set_events,
    search_driver_load_events,
    search_create_remote_thread_events,
    search_raw_access_read_events,
    search_process_access_events,
    search_registry_object_add_del_events
);

#[cfg(feature = "cluster")]
impl_from_giganto_sysmon_event_filter_for_graphql_client!(
    sysmon_events_module,
    dns_query_events,
    file_create_events,
    file_create_stream_hash_events,
    file_create_time_events,
    file_delete_detected_events,
    file_delete_events,
    image_load_events,
    network_connect_events,
    pipe_event_events,
    process_create_events,
    process_tamper_events,
    process_terminate_events,
    registry_key_rename_events,
    registry_value_set_events,
    driver_load_events,
    create_remote_thread_events,
    raw_access_read_events,
    process_access_events,
    registry_object_add_del_events
);

#[cfg(feature = "cluster")]
impl_from_giganto_search_filter_for_graphql_client!(
    search_dns_query_events,
    search_file_create_events,
    search_file_create_stream_hash_events,
    search_file_create_time_events,
    search_file_delete_detected_events,
    search_file_delete_events,
    search_image_load_events,
    search_network_connect_events,
    search_pipe_event_events,
    search_process_create_events,
    search_process_tamper_events,
    search_process_terminate_events,
    search_registry_key_rename_events,
    search_registry_value_set_events,
    search_driver_load_events,
    search_create_remote_thread_events,
    search_raw_access_read_events,
    search_process_access_events,
    search_registry_object_add_del_events
);

#[cfg(test)]
pub(crate) mod tests;

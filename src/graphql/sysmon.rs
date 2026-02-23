use std::{collections::BTreeSet, iter::Peekable};

use async_graphql::{
    Context, Object, Result, SimpleObject, Union,
    connection::{Connection, Edge, query},
};
use chrono::{DateTime, Utc};
use giganto_client::ingest::sysmon::{
    DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
    FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate, ProcessTampering,
    ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
};
#[cfg(feature = "cluster")]
use giganto_proc_macro::ConvertGraphQLEdgesNode;
#[cfg(feature = "cluster")]
use graphql_client::GraphQLQuery;

use super::{
    Engine, FromKeyValue, NetworkFilter, SearchFilter, base64_engine, collect_exist_times,
    events_vec_in_cluster, get_peekable_iter, get_time_from_key, handle_paged_events, min_max_time,
    paged_events_in_cluster,
};
use crate::graphql::StringNumberU32;
#[cfg(feature = "cluster")]
use crate::graphql::client::{
    cluster::{
        impl_from_giganto_network_filter_for_graphql_client,
        impl_from_giganto_range_structs_for_graphql_client,
        impl_from_giganto_search_filter_for_graphql_client,
    },
    derives::{
        DnsQueryEvents, FileCreateEvents, FileCreateStreamHashEvents, FileCreateTimeEvents,
        FileDeleteDetectedEvents, FileDeleteEvents, ImageLoadEvents, NetworkConnectEvents,
        PipeEventEvents, ProcessCreateEvents, ProcessTamperEvents, ProcessTerminateEvents,
        RegistryKeyRenameEvents, RegistryValueSetEvents, SearchDnsQueryEvents,
        SearchFileCreateEvents, SearchFileCreateStreamHashEvents, SearchFileCreateTimeEvents,
        SearchFileDeleteDetectedEvents, SearchFileDeleteEvents, SearchImageLoadEvents,
        SearchNetworkConnectEvents, SearchPipeEventEvents, SearchProcessCreateEvents,
        SearchProcessTamperEvents, SearchProcessTerminateEvents, SearchRegistryKeyRenameEvents,
        SearchRegistryValueSetEvents, SysmonEvents as SysmonEventsDerive, dns_query_events,
        file_create_events, file_create_stream_hash_events, file_create_time_events,
        file_delete_detected_events, file_delete_events, image_load_events, network_connect_events,
        pipe_event_events, process_create_events, process_tamper_events, process_terminate_events,
        registry_key_rename_events, registry_value_set_events, search_dns_query_events,
        search_file_create_events, search_file_create_stream_hash_events,
        search_file_create_time_events, search_file_delete_detected_events,
        search_file_delete_events, search_image_load_events, search_network_connect_events,
        search_pipe_event_events, search_process_create_events, search_process_tamper_events,
        search_process_terminate_events, search_registry_key_rename_events,
        search_registry_value_set_events, sysmon_events as sysmon_events_module,
    },
};
use crate::storage::{Database, FilteredIter};

#[derive(Default)]
pub(super) struct SysmonQuery;

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    process_create_events::ProcessCreateEventsProcessCreateEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnProcessCreateEvent
]))]
struct ProcessCreateEvent {
    time: DateTime<Utc>,
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
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    file_create_time_events::FileCreateTimeEventsFileCreateTimeEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnFileCreationTimeChangedEvent
]))]
struct FileCreationTimeChangedEvent {
    time: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: StringNumberU32,
    image: String,
    target_filename: String,
    creation_utc_time: DateTime<Utc>,
    previous_creation_utc_time: DateTime<Utc>,
    user: String,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    network_connect_events::NetworkConnectEventsNetworkConnectEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnNetworkConnectionEvent
]))]
struct NetworkConnectionEvent {
    time: DateTime<Utc>,
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
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    process_terminate_events::ProcessTerminateEventsProcessTerminateEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnProcessTerminatedEvent
]))]
struct ProcessTerminatedEvent {
    time: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: StringNumberU32,
    image: String,
    user: String,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    image_load_events::ImageLoadEventsImageLoadEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnImageLoadedEvent
]))]
struct ImageLoadedEvent {
    time: DateTime<Utc>,
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
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    file_create_events::FileCreateEventsFileCreateEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnFileCreateEvent
]))]
struct FileCreateEvent {
    time: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: StringNumberU32,
    image: String,
    target_filename: String,
    creation_utc_time: DateTime<Utc>,
    user: String,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    registry_value_set_events::RegistryValueSetEventsRegistryValueSetEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnRegistryValueSetEvent
]))]
struct RegistryValueSetEvent {
    time: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    event_type: String,
    process_guid: String,
    process_id: StringNumberU32,
    image: String,
    target_object: String,
    details: String,
    user: String,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    registry_key_rename_events::RegistryKeyRenameEventsRegistryKeyRenameEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnRegistryKeyValueRenameEvent
]))]
struct RegistryKeyValueRenameEvent {
    time: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    event_type: String,
    process_guid: String,
    process_id: StringNumberU32,
    image: String,
    target_object: String,
    new_name: String,
    user: String,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    file_create_stream_hash_events::FileCreateStreamHashEventsFileCreateStreamHashEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnFileCreateStreamHashEvent
]))]
struct FileCreateStreamHashEvent {
    time: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: StringNumberU32,
    image: String,
    target_filename: String,
    creation_utc_time: DateTime<Utc>,
    hash: Vec<String>,
    contents: String,
    user: String,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    pipe_event_events::PipeEventEventsPipeEventEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnPipeEventEvent
]))]
struct PipeEventEvent {
    time: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    event_type: String,
    process_guid: String,
    process_id: StringNumberU32,
    pipe_name: String,
    image: String,
    user: String,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    dns_query_events::DnsQueryEventsDnsQueryEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnDnsEventEvent
]))]
struct DnsEventEvent {
    time: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: StringNumberU32,
    query_name: String,
    query_status: StringNumberU32,
    query_results: Vec<String>, // divided by ';'
    image: String,
    user: String,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    file_delete_events::FileDeleteEventsFileDeleteEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnFileDeleteEvent
]))]
struct FileDeleteEvent {
    time: DateTime<Utc>,
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
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    process_tamper_events::ProcessTamperEventsProcessTamperEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnProcessTamperingEvent
]))]
struct ProcessTamperingEvent {
    time: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: StringNumberU32,
    image: String,
    tamper_type: String, // type
    user: String,
}

#[derive(SimpleObject, Debug)]
#[cfg_attr(feature = "cluster", derive(ConvertGraphQLEdgesNode))]
#[cfg_attr(feature = "cluster", graphql_client_type(names = [
    file_delete_detected_events::FileDeleteDetectedEventsFileDeleteDetectedEventsEdgesNode,
    sysmon_events_module::SysmonEventsSysmonEventsEdgesNodeOnFileDeleteDetectedEvent
]))]
struct FileDeleteDetectedEvent {
    time: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: StringNumberU32,
    user: String,
    image: String,
    target_filename: String,
    hashes: Vec<String>,
    is_executable: bool,
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
        }
    }
}

macro_rules! from_key_value {
    ($to:ty, $from:ty, $($plain_field:ident),* ; $( $str_num_field:ident ),* ) => {
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
    parent_process_id
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
            creation_utc_time: chrono::DateTime::from_timestamp_nanos(val.creation_utc_time),
            previous_creation_utc_time: chrono::DateTime::from_timestamp_nanos(
                val.previous_creation_utc_time,
            ),
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
            creation_utc_time: chrono::DateTime::from_timestamp_nanos(val.creation_utc_time),
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
            creation_utc_time: chrono::DateTime::from_timestamp_nanos(val.creation_utc_time),
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
        })
    }
}

async fn handle_process_create_events(
    ctx: &Context<'_>,
    filter: NetworkFilter,
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
    filter: NetworkFilter,
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
    filter: NetworkFilter,
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
    filter: NetworkFilter,
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
    filter: NetworkFilter,
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
    filter: NetworkFilter,
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
    filter: NetworkFilter,
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
    filter: NetworkFilter,
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
    filter: NetworkFilter,
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
    filter: NetworkFilter,
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
    filter: NetworkFilter,
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
    filter: NetworkFilter,
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
    filter: NetworkFilter,
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
    filter: NetworkFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, FileDeleteDetectedEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.file_delete_detected_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

#[Object]
#[allow(clippy::unused_async)]
impl SysmonQuery {
    async fn process_create_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
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
        filter: NetworkFilter,
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
        filter: NetworkFilter,
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
        filter: NetworkFilter,
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
        filter: NetworkFilter,
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
        filter: NetworkFilter,
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
        filter: NetworkFilter,
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
        filter: NetworkFilter,
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
        filter: NetworkFilter,
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
        filter: NetworkFilter,
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
        filter: NetworkFilter,
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
        filter: NetworkFilter,
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
        filter: NetworkFilter,
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
        filter: NetworkFilter,
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
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.process_create_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
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
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.file_create_time_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
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
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.network_connect_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
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
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.process_terminate_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
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
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.image_load_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
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
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.file_create_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
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
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.registry_value_set_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
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
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.registry_key_rename_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
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
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.file_create_stream_hash_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
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
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.pipe_event_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
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
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.dns_query_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
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
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.file_delete_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
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
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.process_tamper_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
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
    ) -> Result<Vec<DateTime<Utc>>> {
        let handler = |ctx: &Context<'_>, filter: &SearchFilter| {
            let db = ctx.data::<Database>()?;
            let store = db.file_delete_detected_store()?;
            let exist_data = store
                .batched_multi_get_from_ts(&filter.sensor, &filter.times)
                .into_iter()
                .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
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

    async fn sysmon_events(
        &self,
        ctx: &Context<'_>,
        filter: NetworkFilter,
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
    filter: NetworkFilter,
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
                size,
                is_forward,
            )
        },
    )
    .await
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn sysmon_connection(
    mut process_create_iter: Peekable<FilteredIter<ProcessCreate>>,
    mut file_create_time_iter: Peekable<FilteredIter<FileCreationTimeChanged>>,
    mut network_connect_iter: Peekable<FilteredIter<NetworkConnection>>,
    mut process_terminate_iter: Peekable<FilteredIter<ProcessTerminated>>,
    mut image_load_iter: Peekable<FilteredIter<ImageLoaded>>,
    mut file_create_iter: Peekable<FilteredIter<FileCreate>>,
    mut registry_value_set_iter: Peekable<FilteredIter<RegistryValueSet>>,
    mut registry_key_rename_iter: Peekable<FilteredIter<RegistryKeyValueRename>>,
    mut file_create_stream_hash_iter: Peekable<FilteredIter<FileCreateStreamHash>>,
    mut pipe_event_iter: Peekable<FilteredIter<PipeEvent>>,
    mut dns_query_iter: Peekable<FilteredIter<DnsEvent>>,
    mut file_delete_iter: Peekable<FilteredIter<FileDelete>>,
    mut process_tamper_iter: Peekable<FilteredIter<ProcessTampering>>,
    mut file_delete_detected_iter: Peekable<FilteredIter<FileDeleteDetected>>,
    size: usize,
    is_forward: bool,
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

    loop {
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
            _ => {}
        }
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
                && file_delete_detected_data.is_none())
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
    }
    let mut connection: Connection<String, SysmonEvents> =
        Connection::new(has_previous_page, has_next_page);
    connection.edges.extend(result_vec);

    Ok(connection)
}

#[cfg(feature = "cluster")]
impl_from_giganto_range_structs_for_graphql_client!(
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
    search_registry_value_set_events
);

#[cfg(feature = "cluster")]
impl_from_giganto_network_filter_for_graphql_client!(
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
    registry_value_set_events
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
    search_registry_value_set_events
);

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        mem,
        net::IpAddr,
        str::FromStr,
    };

    use chrono::{TimeZone, Utc};
    use giganto_client::ingest::sysmon::{
        DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
        FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate,
        ProcessTampering, ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
    };

    use crate::{graphql::tests::TestSchema, storage::RawEventStore};

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn sysmon_events_timestamp_fomat_stability() {
        let schema = TestSchema::new();
        let sensor = "src1";
        let base_ts = Utc
            .with_ymd_and_hms(2024, 3, 4, 5, 6, 7)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap();
        let step = 1_000_000;

        let process_create_store = schema.db.process_create_store().unwrap();
        let file_create_time_store = schema.db.file_create_time_store().unwrap();
        let network_connect_store = schema.db.network_connect_store().unwrap();
        let process_terminate_store = schema.db.process_terminate_store().unwrap();
        let image_load_store = schema.db.image_load_store().unwrap();
        let file_create_store = schema.db.file_create_store().unwrap();
        let registry_value_set_store = schema.db.registry_value_set_store().unwrap();
        let registry_key_rename_store = schema.db.registry_key_rename_store().unwrap();
        let file_create_stream_hash_store = schema.db.file_create_stream_hash_store().unwrap();
        let pipe_event_store = schema.db.pipe_event_store().unwrap();
        let dns_query_store = schema.db.dns_query_store().unwrap();
        let file_delete_store = schema.db.file_delete_store().unwrap();
        let process_tamper_store = schema.db.process_tamper_store().unwrap();
        let file_delete_detected_store = schema.db.file_delete_detected_store().unwrap();

        insert_process_create_event(&process_create_store, sensor, base_ts);
        let file_create_time_creation = base_ts + step + 10;
        let file_create_time_previous = base_ts + step - 10;
        insert_file_create_time_event(
            &file_create_time_store,
            sensor,
            base_ts + step,
            file_create_time_creation,
            file_create_time_previous,
        );
        insert_network_connect_event(&network_connect_store, sensor, base_ts + step * 2);
        insert_process_terminated_event(&process_terminate_store, sensor, base_ts + step * 3);
        insert_image_loaded_event(&image_load_store, sensor, base_ts + step * 4);
        let file_create_creation = base_ts + step * 5 + 20;
        insert_file_create_event(
            &file_create_store,
            sensor,
            base_ts + step * 5,
            file_create_creation,
        );
        insert_registry_value_set_event(&registry_value_set_store, sensor, base_ts + step * 6);
        insert_registry_key_rename_event(&registry_key_rename_store, sensor, base_ts + step * 7);
        insert_file_create_stream_hash_event(
            &file_create_stream_hash_store,
            sensor,
            base_ts + step * 8,
        );
        insert_pipe_event_raw_event(&pipe_event_store, sensor, base_ts + step * 9);
        insert_dns_event(&dns_query_store, sensor, base_ts + step * 10);
        insert_file_delete_event(&file_delete_store, sensor, base_ts + step * 11);
        insert_process_tampering_event(&process_tamper_store, sensor, base_ts + step * 12);
        insert_file_delete_detected_event(&file_delete_detected_store, sensor, base_ts + step * 13);

        let query = r#"
        {
            sysmonEvents(
                filter: {
                    sensor: "src1",
                    time: { start: "2024-03-04T05:06:06Z", end: "2024-03-04T05:06:25Z" }
                },
                first: 20
            ) {
                edges {
                    node {
                        __typename
                        ... on ProcessCreateEvent { time }
                        ... on FileCreationTimeChangedEvent { time creationUtcTime previousCreationUtcTime }
                        ... on NetworkConnectionEvent { time }
                        ... on ProcessTerminatedEvent { time }
                        ... on ImageLoadedEvent { time }
                        ... on FileCreateEvent { time creationUtcTime }
                        ... on RegistryValueSetEvent { time }
                        ... on RegistryKeyValueRenameEvent { time }
                        ... on FileCreateStreamHashEvent { time creationUtcTime }
                        ... on PipeEventEvent { time }
                        ... on DnsEventEvent { time }
                        ... on FileDeleteEvent { time }
                        ... on ProcessTamperingEvent { time }
                        ... on FileDeleteDetectedEvent { time }
                    }
                }
            }
        }"#;

        let res = schema.execute(query).await;
        assert!(res.errors.is_empty(), "GraphQL errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let edges = data["sysmonEvents"]["edges"].as_array().unwrap();

        let expected_types = [
            "ProcessCreateEvent",
            "FileCreationTimeChangedEvent",
            "NetworkConnectionEvent",
            "ProcessTerminatedEvent",
            "ImageLoadedEvent",
            "FileCreateEvent",
            "RegistryValueSetEvent",
            "RegistryKeyValueRenameEvent",
            "FileCreateStreamHashEvent",
            "PipeEventEvent",
            "DnsEventEvent",
            "FileDeleteEvent",
            "ProcessTamperingEvent",
            "FileDeleteDetectedEvent",
        ];
        let mut seen = HashSet::new();
        let mut expected_times: HashMap<&str, String> = HashMap::new();
        expected_times.insert(
            "ProcessCreateEvent",
            Utc.timestamp_nanos(base_ts).to_rfc3339(),
        );
        expected_times.insert(
            "FileCreationTimeChangedEvent",
            Utc.timestamp_nanos(base_ts + step).to_rfc3339(),
        );
        expected_times.insert(
            "NetworkConnectionEvent",
            Utc.timestamp_nanos(base_ts + step * 2).to_rfc3339(),
        );
        expected_times.insert(
            "ProcessTerminatedEvent",
            Utc.timestamp_nanos(base_ts + step * 3).to_rfc3339(),
        );
        expected_times.insert(
            "ImageLoadedEvent",
            Utc.timestamp_nanos(base_ts + step * 4).to_rfc3339(),
        );
        expected_times.insert(
            "FileCreateEvent",
            Utc.timestamp_nanos(base_ts + step * 5).to_rfc3339(),
        );
        expected_times.insert(
            "RegistryValueSetEvent",
            Utc.timestamp_nanos(base_ts + step * 6).to_rfc3339(),
        );
        expected_times.insert(
            "RegistryKeyValueRenameEvent",
            Utc.timestamp_nanos(base_ts + step * 7).to_rfc3339(),
        );
        expected_times.insert(
            "FileCreateStreamHashEvent",
            Utc.timestamp_nanos(base_ts + step * 8).to_rfc3339(),
        );
        expected_times.insert(
            "PipeEventEvent",
            Utc.timestamp_nanos(base_ts + step * 9).to_rfc3339(),
        );
        expected_times.insert(
            "DnsEventEvent",
            Utc.timestamp_nanos(base_ts + step * 10).to_rfc3339(),
        );
        expected_times.insert(
            "FileDeleteEvent",
            Utc.timestamp_nanos(base_ts + step * 11).to_rfc3339(),
        );
        expected_times.insert(
            "ProcessTamperingEvent",
            Utc.timestamp_nanos(base_ts + step * 12).to_rfc3339(),
        );
        expected_times.insert(
            "FileDeleteDetectedEvent",
            Utc.timestamp_nanos(base_ts + step * 13).to_rfc3339(),
        );

        for edge in edges {
            let node = edge["node"].as_object().unwrap();
            let typename = node["__typename"].as_str().unwrap();
            seen.insert(typename.to_string());
            let expected_time = expected_times.get(typename).unwrap();
            assert_eq!(node["time"].as_str().unwrap(), expected_time);
            match typename {
                "FileCreationTimeChangedEvent" => {
                    assert_eq!(
                        node["creationUtcTime"].as_str().unwrap(),
                        Utc.timestamp_nanos(file_create_time_creation).to_rfc3339()
                    );
                    assert_eq!(
                        node["previousCreationUtcTime"].as_str().unwrap(),
                        Utc.timestamp_nanos(file_create_time_previous).to_rfc3339()
                    );
                }
                "FileCreateEvent" => {
                    assert_eq!(
                        node["creationUtcTime"].as_str().unwrap(),
                        Utc.timestamp_nanos(file_create_creation).to_rfc3339()
                    );
                }
                "FileCreateStreamHashEvent" => {
                    assert_eq!(
                        node["creationUtcTime"].as_str().unwrap(),
                        Utc.timestamp_nanos(base_ts + step * 8).to_rfc3339()
                    );
                }
                _ => {}
            }
        }
        assert_eq!(seen.len(), expected_types.len());
        for expected in expected_types {
            assert!(
                seen.contains(expected),
                "Missing sysmon event type {expected}"
            );
        }
    }

    fn sensor_timestamp_key(sensor: &str, timestamp: i64) -> Vec<u8> {
        let mut key = Vec::with_capacity(sensor.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(sensor.as_bytes());
        key.push(0);
        key.extend_from_slice(&timestamp.to_be_bytes());
        key
    }

    fn insert_process_create_event(
        store: &RawEventStore<ProcessCreate>,
        sensor: &str,
        timestamp: i64,
    ) {
        let key = sensor_timestamp_key(sensor, timestamp);
        let event = ProcessCreate {
            agent_name: "pc-agent".to_string(),
            agent_id: "pc-agent_id".to_string(),
            process_guid: "guid".to_string(),
            process_id: 1234,
            image: "proc.exe".to_string(),
            file_version: "1.0".to_string(),
            description: "desc".to_string(),
            product: "product".to_string(),
            company: "company".to_string(),
            original_file_name: "proc.exe".to_string(),
            command_line: "proc.exe /S".to_string(),
            current_directory: "C:\\".to_string(),
            user: "user".to_string(),
            logon_guid: "logon_guid".to_string(),
            logon_id: 99,
            terminal_session_id: 1,
            integrity_level: "high".to_string(),
            hashes: vec!["SHA256=abc".to_string()],
            parent_process_guid: "parent_guid".to_string(),
            parent_process_id: 4321,
            parent_image: "parent.exe".to_string(),
            parent_command_line: "parent.exe".to_string(),
            parent_user: "parent_user".to_string(),
        };
        let value = bincode::serialize(&event).unwrap();
        store.append(&key, &value).unwrap();
    }

    fn insert_file_create_time_event(
        store: &RawEventStore<FileCreationTimeChanged>,
        sensor: &str,
        timestamp: i64,
        creation_ts: i64,
        prev_ts: i64,
    ) {
        let key = sensor_timestamp_key(sensor, timestamp);
        let event = FileCreationTimeChanged {
            agent_name: "agent".to_string(),
            agent_id: "agent_id".to_string(),
            process_guid: "guid".to_string(),
            process_id: 123,
            image: "proc.exe".to_string(),
            target_filename: "time.log".to_string(),
            creation_utc_time: creation_ts,
            previous_creation_utc_time: prev_ts,
            user: "user".to_string(),
        };
        let value = bincode::serialize(&event).unwrap();
        store.append(&key, &value).unwrap();
    }

    fn insert_network_connect_event(
        store: &RawEventStore<NetworkConnection>,
        sensor: &str,
        timestamp: i64,
    ) {
        let key = sensor_timestamp_key(sensor, timestamp);
        let event = NetworkConnection {
            agent_name: "agent".to_string(),
            agent_id: "agent_id".to_string(),
            process_guid: "guid".to_string(),
            process_id: 1,
            image: "proc.exe".to_string(),
            user: "user".to_string(),
            protocol: "TCP".to_string(),
            initiated: true,
            source_is_ipv6: false,
            source_ip: IpAddr::from_str("192.0.2.1").unwrap(),
            source_hostname: "src-host".to_string(),
            source_port: 1234,
            source_port_name: "src".to_string(),
            destination_is_ipv6: false,
            destination_ip: IpAddr::from_str("192.0.2.2").unwrap(),
            destination_hostname: "dst-host".to_string(),
            destination_port: 4321,
            destination_port_name: "dst".to_string(),
        };
        let value = bincode::serialize(&event).unwrap();
        store.append(&key, &value).unwrap();
    }

    fn insert_process_terminated_event(
        store: &RawEventStore<ProcessTerminated>,
        sensor: &str,
        timestamp: i64,
    ) {
        let key = sensor_timestamp_key(sensor, timestamp);
        let event = ProcessTerminated {
            agent_name: "agent".to_string(),
            agent_id: "agent_id".to_string(),
            process_guid: "guid".to_string(),
            process_id: 77,
            image: "terminated.exe".to_string(),
            user: "user".to_string(),
        };
        let value = bincode::serialize(&event).unwrap();
        store.append(&key, &value).unwrap();
    }

    fn insert_image_loaded_event(store: &RawEventStore<ImageLoaded>, sensor: &str, timestamp: i64) {
        let key = sensor_timestamp_key(sensor, timestamp);
        let event = ImageLoaded {
            agent_name: "agent".to_string(),
            agent_id: "agent_id".to_string(),
            process_guid: "guid".to_string(),
            process_id: 99,
            image: "proc.exe".to_string(),
            image_loaded: "loaded.dll".to_string(),
            file_version: "1.0.0".to_string(),
            description: "desc".to_string(),
            product: "product".to_string(),
            company: "company".to_string(),
            original_file_name: "loaded.dll".to_string(),
            hashes: vec!["SHA256=123".to_string()],
            signed: true,
            signature: "signature".to_string(),
            signature_status: "Valid".to_string(),
            user: "user".to_string(),
        };
        let value = bincode::serialize(&event).unwrap();
        store.append(&key, &value).unwrap();
    }

    fn insert_file_create_event(
        store: &RawEventStore<FileCreate>,
        sensor: &str,
        timestamp: i64,
        creation_ts: i64,
    ) {
        let key = sensor_timestamp_key(sensor, timestamp);
        let event = FileCreate {
            agent_name: "agent".to_string(),
            agent_id: "agent_id".to_string(),
            process_guid: "guid".to_string(),
            process_id: 42,
            image: "proc.exe".to_string(),
            target_filename: "created.txt".to_string(),
            creation_utc_time: creation_ts,
            user: "user".to_string(),
        };
        let value = bincode::serialize(&event).unwrap();
        store.append(&key, &value).unwrap();
    }

    fn insert_registry_value_set_event(
        store: &RawEventStore<RegistryValueSet>,
        sensor: &str,
        timestamp: i64,
    ) {
        let key = sensor_timestamp_key(sensor, timestamp);
        let event = RegistryValueSet {
            agent_name: "agent".to_string(),
            agent_id: "agent_id".to_string(),
            event_type: "SetValue".to_string(),
            process_guid: "guid".to_string(),
            process_id: 8,
            image: "reg.exe".to_string(),
            target_object: "\\Registry\\Machine\\Key".to_string(),
            details: "REG_SZ".to_string(),
            user: "user".to_string(),
        };
        let value = bincode::serialize(&event).unwrap();
        store.append(&key, &value).unwrap();
    }

    fn insert_registry_key_rename_event(
        store: &RawEventStore<RegistryKeyValueRename>,
        sensor: &str,
        timestamp: i64,
    ) {
        let key = sensor_timestamp_key(sensor, timestamp);
        let event = RegistryKeyValueRename {
            agent_name: "agent".to_string(),
            agent_id: "agent_id".to_string(),
            event_type: "RenameValue".to_string(),
            process_guid: "guid".to_string(),
            process_id: 8,
            image: "reg.exe".to_string(),
            target_object: "\\Registry\\Machine\\Key\\Old".to_string(),
            new_name: "NewName".to_string(),
            user: "user".to_string(),
        };
        let value = bincode::serialize(&event).unwrap();
        store.append(&key, &value).unwrap();
    }

    fn insert_file_create_stream_hash_event(
        store: &RawEventStore<FileCreateStreamHash>,
        sensor: &str,
        timestamp: i64,
    ) {
        let key = sensor_timestamp_key(sensor, timestamp);
        let event = FileCreateStreamHash {
            agent_name: "agent".to_string(),
            agent_id: "agent_id".to_string(),
            process_guid: "guid".to_string(),
            process_id: 9,
            image: "proc.exe".to_string(),
            target_filename: "stream.log".to_string(),
            creation_utc_time: timestamp,
            hash: vec!["SHA256=stream".to_string()],
            contents: "stream-bytes".to_string(),
            user: "user".to_string(),
        };
        let value = bincode::serialize(&event).unwrap();
        store.append(&key, &value).unwrap();
    }

    fn insert_pipe_event_raw_event(store: &RawEventStore<PipeEvent>, sensor: &str, timestamp: i64) {
        let key = sensor_timestamp_key(sensor, timestamp);
        let event = PipeEvent {
            agent_name: "agent".to_string(),
            agent_id: "agent_id".to_string(),
            event_type: "PipeEvent".to_string(),
            process_guid: "guid".to_string(),
            process_id: 11,
            pipe_name: "\\\\.\\pipe\\example".to_string(),
            image: "proc.exe".to_string(),
            user: "user".to_string(),
        };
        let value = bincode::serialize(&event).unwrap();
        store.append(&key, &value).unwrap();
    }

    fn insert_dns_event(store: &RawEventStore<DnsEvent>, sensor: &str, timestamp: i64) {
        let key = sensor_timestamp_key(sensor, timestamp);
        let event = DnsEvent {
            agent_name: "agent".to_string(),
            agent_id: "agent_id".to_string(),
            process_guid: "guid".to_string(),
            process_id: 12,
            query_name: "example.com".to_string(),
            query_status: 0,
            query_results: vec!["93.184.216.34".to_string()],
            image: "proc.exe".to_string(),
            user: "user".to_string(),
        };
        let value = bincode::serialize(&event).unwrap();
        store.append(&key, &value).unwrap();
    }

    fn insert_file_delete_event(store: &RawEventStore<FileDelete>, sensor: &str, timestamp: i64) {
        let key = sensor_timestamp_key(sensor, timestamp);
        let event = FileDelete {
            agent_name: "agent".to_string(),
            agent_id: "agent_id".to_string(),
            process_guid: "guid".to_string(),
            process_id: 13,
            user: "user".to_string(),
            image: "proc.exe".to_string(),
            target_filename: "old.log".to_string(),
            hashes: vec!["SHA256=old".to_string()],
            is_executable: false,
            archived: false,
        };
        let value = bincode::serialize(&event).unwrap();
        store.append(&key, &value).unwrap();
    }

    fn insert_process_tampering_event(
        store: &RawEventStore<ProcessTampering>,
        sensor: &str,
        timestamp: i64,
    ) {
        let key = sensor_timestamp_key(sensor, timestamp);
        let event = ProcessTampering {
            agent_name: "agent".to_string(),
            agent_id: "agent_id".to_string(),
            process_guid: "guid".to_string(),
            process_id: 14,
            image: "proc.exe".to_string(),
            tamper_type: "ThreadSuspend".to_string(),
            user: "user".to_string(),
        };
        let value = bincode::serialize(&event).unwrap();
        store.append(&key, &value).unwrap();
    }

    fn insert_file_delete_detected_event(
        store: &RawEventStore<FileDeleteDetected>,
        sensor: &str,
        timestamp: i64,
    ) {
        let key = sensor_timestamp_key(sensor, timestamp);
        let event = FileDeleteDetected {
            agent_name: "agent".to_string(),
            agent_id: "agent_id".to_string(),
            process_guid: "guid".to_string(),
            process_id: 15,
            user: "user".to_string(),
            image: "proc.exe".to_string(),
            target_filename: "suspect.log".to_string(),
            hashes: vec!["SHA256=suspect".to_string()],
            is_executable: true,
        };
        let value = bincode::serialize(&event).unwrap();
        store.append(&key, &value).unwrap();
    }
}

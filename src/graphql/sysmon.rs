#![allow(clippy::unused_async)]
use super::{
    base64_engine, collect_exist_timestamp, get_peekable_iter, get_timestamp_from_key,
    load_connection, min_max_time,
    network::{NetworkFilter, SearchFilter},
    Engine, FromKeyValue,
};
use crate::storage::{Database, FilteredIter};
use async_graphql::{
    connection::{query, Connection, Edge},
    Context, Object, Result, SimpleObject, Union,
};
use chrono::{DateTime, Utc};
use giganto_client::ingest::sysmon::{
    DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
    FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate, ProcessTampering,
    ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
};
use std::{collections::BTreeSet, iter::Peekable};

#[derive(Default)]
pub(super) struct SysmonQuery;

#[derive(SimpleObject, Debug)]
struct ProcessCreateEvent {
    timestamp: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
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
    logon_id: u32,
    terminal_session_id: u32,
    integrity_level: String,
    hashes: Vec<String>,
    parent_process_guid: String,
    parent_process_id: u32,
    parent_image: String,
    parent_command_line: String,
    parent_user: String,
}

#[derive(SimpleObject, Debug)]
struct FileCreationTimeChangedEvent {
    timestamp: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
    image: String,
    target_filename: String,
    creation_utc_time: i64,
    previous_creation_utc_time: i64,
    user: String,
}

#[derive(SimpleObject, Debug)]
struct NetworkConnectionEvent {
    timestamp: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
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
struct ProcessTerminatedEvent {
    timestamp: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
    image: String,
    user: String,
}

#[derive(SimpleObject, Debug)]
struct ImageLoadedEvent {
    timestamp: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
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
struct FileCreateEvent {
    timestamp: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
    image: String,
    target_filename: String,
    creation_utc_time: i64,
    user: String,
}

#[derive(SimpleObject, Debug)]
struct RegistryValueSetEvent {
    timestamp: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    event_type: String,
    process_guid: String,
    process_id: u32,
    image: String,
    target_object: String,
    details: String,
    user: String,
}

#[derive(SimpleObject, Debug)]
struct RegistryKeyValueRenameEvent {
    timestamp: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    event_type: String,
    process_guid: String,
    process_id: u32,
    image: String,
    target_object: String,
    new_name: String,
    user: String,
}

#[derive(SimpleObject, Debug)]
struct FileCreateStreamHashEvent {
    timestamp: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
    image: String,
    target_filename: String,
    creation_utc_time: i64,
    hash: Vec<String>,
    contents: String,
    user: String,
}

#[derive(SimpleObject, Debug)]
struct PipeEventEvent {
    timestamp: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    event_type: String,
    process_guid: String,
    process_id: u32,
    pipe_name: String,
    image: String,
    user: String,
}

#[derive(SimpleObject, Debug)]
struct DnsEventEvent {
    timestamp: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
    query_name: String,
    query_status: u32,
    query_results: Vec<String>, // divided by ';'
    image: String,
    user: String,
}

#[derive(SimpleObject, Debug)]
struct FileDeleteEvent {
    timestamp: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
    user: String,
    image: String,
    target_filename: String,
    hashes: Vec<String>,
    is_executable: bool,
    archived: bool,
}

#[derive(SimpleObject, Debug)]
struct ProcessTamperingEvent {
    timestamp: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
    image: String,
    tamper_type: String, // type
    user: String,
}

#[derive(SimpleObject, Debug)]
struct FileDeleteDetectedEvent {
    timestamp: DateTime<Utc>,
    agent_name: String,
    agent_id: String,
    process_guid: String,
    process_id: u32,
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

macro_rules! from_key_value {
    ($to:ty, $from:ty, $($fields:ident),*) => {
        impl FromKeyValue<$from> for $to {
            fn from_key_value(key: &[u8], val: $from) -> Result<Self> {
                let timestamp = get_timestamp_from_key(key)?;
                Ok(Self {
                    timestamp,
                    agent_name: val.agent_name,
                    agent_id: val.agent_id,
                    process_guid: val.process_guid,
                    process_id: val.process_id,
                    $(
                        $fields: val.$fields,
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
    logon_id,
    terminal_session_id,
    integrity_level,
    hashes,
    parent_process_guid,
    parent_process_id,
    parent_image,
    parent_command_line,
    parent_user
);

from_key_value!(
    FileCreationTimeChangedEvent,
    FileCreationTimeChanged,
    image,
    target_filename,
    creation_utc_time,
    previous_creation_utc_time,
    user
);

from_key_value!(ProcessTerminatedEvent, ProcessTerminated, image, user);

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
    user
);

from_key_value!(
    FileCreateEvent,
    FileCreate,
    image,
    target_filename,
    creation_utc_time,
    user
);

from_key_value!(
    RegistryValueSetEvent,
    RegistryValueSet,
    event_type,
    image,
    target_object,
    details,
    user
);

from_key_value!(
    RegistryKeyValueRenameEvent,
    RegistryKeyValueRename,
    event_type,
    image,
    target_object,
    new_name,
    user
);

from_key_value!(
    FileCreateStreamHashEvent,
    FileCreateStreamHash,
    image,
    target_filename,
    creation_utc_time,
    hash,
    contents,
    user
);

from_key_value!(
    PipeEventEvent,
    PipeEvent,
    event_type,
    pipe_name,
    image,
    user
);

from_key_value!(
    DnsEventEvent,
    DnsEvent,
    query_name,
    query_status,
    query_results,
    image,
    user
);

from_key_value!(
    FileDeleteEvent,
    FileDelete,
    user,
    image,
    target_filename,
    hashes,
    is_executable,
    archived
);

from_key_value!(
    ProcessTamperingEvent,
    ProcessTampering,
    image,
    tamper_type,
    user
);

from_key_value!(
    FileDeleteDetectedEvent,
    FileDeleteDetected,
    user,
    image,
    target_filename,
    hashes,
    is_executable
);

impl FromKeyValue<NetworkConnection> for NetworkConnectionEvent {
    fn from_key_value(key: &[u8], value: NetworkConnection) -> Result<Self> {
        Ok(NetworkConnectionEvent {
            timestamp: get_timestamp_from_key(key)?,
            agent_name: value.agent_name,
            agent_id: value.agent_id,
            process_guid: value.process_guid,
            process_id: value.process_id,
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

#[Object]
impl SysmonQuery {
    async fn process_create_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, ProcessCreateEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.process_create_store()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(&store, &filter, after, before, first, last)
            },
        )
        .await
    }

    async fn file_create_time_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, FileCreationTimeChangedEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.file_create_time_store()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(&store, &filter, after, before, first, last)
            },
        )
        .await
    }

    async fn network_connect_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, NetworkConnectionEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.network_connect_store()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(&store, &filter, after, before, first, last)
            },
        )
        .await
    }

    async fn process_terminate_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, ProcessTerminatedEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.process_terminate_store()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(&store, &filter, after, before, first, last)
            },
        )
        .await
    }

    async fn image_load_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, ImageLoadedEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.image_load_store()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(&store, &filter, after, before, first, last)
            },
        )
        .await
    }

    async fn file_create_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, FileCreateEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.file_create_store()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(&store, &filter, after, before, first, last)
            },
        )
        .await
    }

    async fn registry_value_set_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, RegistryValueSetEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.registry_value_set_store()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(&store, &filter, after, before, first, last)
            },
        )
        .await
    }

    async fn registry_key_rename_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, RegistryKeyValueRenameEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.registry_key_rename_store()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(&store, &filter, after, before, first, last)
            },
        )
        .await
    }

    async fn file_create_stream_hash_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, FileCreateStreamHashEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.file_create_stream_hash_store()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(&store, &filter, after, before, first, last)
            },
        )
        .await
    }

    async fn pipe_event_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, PipeEventEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.pipe_event_store()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(&store, &filter, after, before, first, last)
            },
        )
        .await
    }

    async fn dns_query_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, DnsEventEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.dns_query_store()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(&store, &filter, after, before, first, last)
            },
        )
        .await
    }

    async fn file_delete_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, FileDeleteEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.file_delete_store()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(&store, &filter, after, before, first, last)
            },
        )
        .await
    }

    async fn process_tamper_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, ProcessTamperingEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.process_tamper_store()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(&store, &filter, after, before, first, last)
            },
        )
        .await
    }

    async fn file_delete_detected_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: NetworkFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, FileDeleteDetectedEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.file_delete_detected_store()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(&store, &filter, after, before, first, last)
            },
        )
        .await
    }

    async fn search_process_create_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.process_create_store()?;
        let exist_data = store
            .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<ProcessCreate>(
            &exist_data,
            &filter,
        ))
    }

    async fn search_file_create_time_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.file_create_time_store()?;
        let exist_data = store
            .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<FileCreationTimeChanged>(
            &exist_data,
            &filter,
        ))
    }

    async fn search_network_connect_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.network_connect_store()?;
        let exist_data = store
            .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<NetworkConnection>(
            &exist_data,
            &filter,
        ))
    }

    async fn search_process_terminate_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.process_terminate_store()?;
        let exist_data = store
            .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<ProcessTerminated>(
            &exist_data,
            &filter,
        ))
    }

    async fn search_image_load_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.image_load_store()?;
        let exist_data = store
            .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<ImageLoaded>(&exist_data, &filter))
    }

    async fn search_file_create_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.file_create_store()?;
        let exist_data = store
            .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<FileCreate>(&exist_data, &filter))
    }

    async fn search_registry_value_set_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.registry_value_set_store()?;
        let exist_data = store
            .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<RegistryValueSet>(
            &exist_data,
            &filter,
        ))
    }

    async fn search_registry_key_rename_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.registry_key_rename_store()?;
        let exist_data = store
            .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<RegistryKeyValueRename>(
            &exist_data,
            &filter,
        ))
    }

    async fn search_file_create_stream_hash_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.file_create_stream_hash_store()?;
        let exist_data = store
            .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<FileCreateStreamHash>(
            &exist_data,
            &filter,
        ))
    }

    async fn search_pipe_event_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.pipe_event_store()?;
        let exist_data = store
            .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<PipeEvent>(&exist_data, &filter))
    }

    async fn search_dns_query_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.dns_query_store()?;
        let exist_data = store
            .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<DnsEvent>(&exist_data, &filter))
    }

    async fn search_file_delete_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.file_delete_store()?;
        let exist_data = store
            .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<FileDelete>(&exist_data, &filter))
    }

    async fn search_process_tamper_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.process_tamper_store()?;
        let exist_data = store
            .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<ProcessTampering>(
            &exist_data,
            &filter,
        ))
    }

    async fn search_file_delete_detected_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SearchFilter,
    ) -> Result<Vec<DateTime<Utc>>> {
        let db = ctx.data::<Database>()?;
        let store = db.file_delete_detected_store()?;
        let exist_data = store
            .batched_multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<FileDeleteDetected>(
            &exist_data,
            &filter,
        ))
    }

    #[allow(clippy::too_many_lines)]
    async fn sysmon_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
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
                    &after,
                    &before,
                    first,
                    last,
                )?;

                let (file_create_time_iter, _) = get_peekable_iter(
                    &db.file_create_time_store()?,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;

                let (network_connect_iter, _) = get_peekable_iter(
                    &db.network_connect_store()?,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;

                let (process_terminate_iter, _) = get_peekable_iter(
                    &db.process_terminate_store()?,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;

                let (image_load_iter, _) = get_peekable_iter(
                    &db.image_load_store()?,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;

                let (file_create_iter, _) = get_peekable_iter(
                    &db.file_create_store()?,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;

                let (registry_value_set_iter, _) = get_peekable_iter(
                    &db.registry_value_set_store()?,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;

                let (registry_key_rename_iter, _) = get_peekable_iter(
                    &db.registry_key_rename_store()?,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;

                let (file_create_stream_hash_iter, _) = get_peekable_iter(
                    &db.file_create_stream_hash_store()?,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;

                let (pipe_event_iter, _) = get_peekable_iter(
                    &db.pipe_event_store()?,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;

                let (dns_query_iter, _) = get_peekable_iter(
                    &db.dns_query_store()?,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;

                let (file_delete_iter, _) = get_peekable_iter(
                    &db.file_delete_store()?,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;

                let (process_tamper_iter, _) = get_peekable_iter(
                    &db.process_tamper_store()?,
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;

                let (file_delete_detected_iter, _) = get_peekable_iter(
                    &db.file_delete_detected_store()?,
                    &filter,
                    &after,
                    &before,
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
    let timestamp = min_max_time(is_forward);
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
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let file_create_time_ts = if let Some((ref key, _)) = file_create_time_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let network_connect_ts = if let Some((ref key, _)) = network_connect_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let process_terminate_ts = if let Some((ref key, _)) = process_terminate_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let image_load_ts = if let Some((ref key, _)) = image_load_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let file_create_ts = if let Some((ref key, _)) = file_create_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let registry_value_set_ts = if let Some((ref key, _)) = registry_value_set_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let registry_key_rename_ts = if let Some((ref key, _)) = registry_key_rename_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let file_create_stream_hash_ts = if let Some((ref key, _)) = file_create_stream_hash_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let pipe_event_ts = if let Some((ref key, _)) = pipe_event_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let dns_query_ts = if let Some((ref key, _)) = dns_query_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let file_delete_ts = if let Some((ref key, _)) = file_delete_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let process_tamper_ts = if let Some((ref key, _)) = process_tamper_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let file_delete_detected_ts = if let Some((ref key, _)) = file_delete_detected_data {
            get_timestamp_from_key(key)?
        } else {
            min_max_time(is_forward)
        };

        let selected =
            if is_forward {
                timestamp.min(file_create_time_ts.min(process_create_ts.min(
                    network_connect_ts.min(process_terminate_ts.min(image_load_ts.min(
                        file_create_ts.min(registry_value_set_ts.min(registry_key_rename_ts.min(
                            file_create_stream_hash_ts.min(pipe_event_ts.min(dns_query_ts.min(
                                file_delete_ts.min(process_tamper_ts.min(file_delete_detected_ts)),
                            ))),
                        ))),
                    ))),
                )))
            } else {
                timestamp.max(file_create_time_ts.max(process_create_ts.max(
                    network_connect_ts.max(process_terminate_ts.max(image_load_ts.max(
                        file_create_ts.max(registry_value_set_ts.max(registry_key_rename_ts.max(
                            file_create_stream_hash_ts.max(pipe_event_ts.max(dns_query_ts.max(
                                file_delete_ts.max(process_tamper_ts.max(file_delete_detected_ts)),
                            ))),
                        ))),
                    ))),
                )))
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
                };
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
                };
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
                };
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
                };
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
                };
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
                };
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
                };
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
                };
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
                };
            }
            _ if selected == pipe_event_ts => {
                if let Some((key, value)) = pipe_event_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::PipeEventEvent(PipeEventEvent::from_key_value(&key, value)?),
                    ));
                    pipe_event_data = pipe_event_iter.next();
                };
            }
            _ if selected == dns_query_ts => {
                if let Some((key, value)) = dns_query_data {
                    result_vec.push(Edge::new(
                        base64_engine.encode(&key),
                        SysmonEvents::DnsEventEvent(DnsEventEvent::from_key_value(&key, value)?),
                    ));
                    dns_query_data = dns_query_iter.next();
                };
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
                };
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
                };
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
                };
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

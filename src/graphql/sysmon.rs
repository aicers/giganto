#![allow(clippy::unused_async)]
use super::{
    collect_exist_timestamp, get_timestamp_from_key, load_connection,
    network::{NetworkFilter, SearchFilter},
    FromKeyValue,
};
use crate::storage::Database;
use async_graphql::{
    connection::{query, Connection},
    Context, Object, Result, SimpleObject,
};
use chrono::{DateTime, Utc};
use giganto_client::ingest::sysmon::{
    DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
    FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate, ProcessTampering,
    ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
};
use std::collections::BTreeSet;

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
            .multi_get_from_ts(&filter.source, &filter.timestamps)
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
            .multi_get_from_ts(&filter.source, &filter.timestamps)
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
            .multi_get_from_ts(&filter.source, &filter.timestamps)
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
            .multi_get_from_ts(&filter.source, &filter.timestamps)
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
            .multi_get_from_ts(&filter.source, &filter.timestamps)
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
            .multi_get_from_ts(&filter.source, &filter.timestamps)
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
            .multi_get_from_ts(&filter.source, &filter.timestamps)
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
            .multi_get_from_ts(&filter.source, &filter.timestamps)
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
            .multi_get_from_ts(&filter.source, &filter.timestamps)
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
            .multi_get_from_ts(&filter.source, &filter.timestamps)
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
            .multi_get_from_ts(&filter.source, &filter.timestamps)
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
            .multi_get_from_ts(&filter.source, &filter.timestamps)
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
            .multi_get_from_ts(&filter.source, &filter.timestamps)
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
            .multi_get_from_ts(&filter.source, &filter.timestamps)
            .into_iter()
            .collect::<BTreeSet<(DateTime<Utc>, Vec<u8>)>>();
        Ok(collect_exist_timestamp::<FileDeleteDetected>(
            &exist_data,
            &filter,
        ))
    }
}

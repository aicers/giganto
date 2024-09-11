#[cfg(test)]
mod tests;

use std::{
    fmt::{Debug, Display},
    net::IpAddr,
};

use anyhow::anyhow;
use async_graphql::{
    connection::{query, Connection},
    Context, InputObject, Object, Result, SimpleObject,
};
use chrono::{DateTime, Utc};
use giganto_client::ingest::{
    log::{Log, OpLog},
    network::{
        Bootp, Conn, DceRpc, Dhcp, Dns, Ftp, Http, Kerberos, Ldap, Mqtt, Nfs, Ntlm, Rdp, Smb, Smtp,
        Ssh, Tls,
    },
    sysmon::{
        DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
        FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate,
        ProcessTampering, ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
    },
};
use giganto_proc_macro::ConvertGraphQLEdgesNode;
use graphql_client::GraphQLQuery;
use serde::{de::DeserializeOwned, Serialize};

use super::{
    base64_engine,
    client::derives::{
        log_raw_events, tsv_formatted_raw_events, LogRawEvents, TsvFormattedRawEvents,
    },
    events_vec_in_cluster, get_timestamp_from_key, get_timestamp_from_key_prefix,
    handle_paged_events, impl_from_giganto_time_range_struct_for_graphql_client,
    load_connection_by_prefix_timestamp_key, paged_events_in_cluster, Engine, FromKeyValue,
};
use crate::{
    graphql::{RawEventFilter, TimeRange},
    storage::{Database, KeyExtractor, RawEventStore, TimestampKeyExtractor},
};

#[derive(Default)]
pub(super) struct LogQuery;

#[allow(clippy::module_name_repetitions)]
#[derive(InputObject, Serialize)]
struct TsvFilter {
    protocol: String,
    timestamps: Vec<DateTime<Utc>>,
    sensor: String,
}

#[allow(clippy::module_name_repetitions)]
#[derive(InputObject)]
pub struct LogFilter {
    time: Option<TimeRange>,
    sensor: String,
    kind: Option<String>,
}

impl KeyExtractor for LogFilter {
    fn get_start_key(&self) -> &str {
        &self.sensor
    }

    fn get_mid_key(&self) -> Option<Vec<u8>> {
        self.kind.as_ref().map(|kind| kind.as_bytes().to_vec())
    }

    fn get_range_end_key(&self) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
        if let Some(time) = &self.time {
            (time.start, time.end)
        } else {
            (None, None)
        }
    }
}

impl RawEventFilter for LogFilter {
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
    ) -> Result<bool> {
        Ok(true)
    }
}

#[derive(InputObject)]
pub struct OpLogFilter {
    time: Option<TimeRange>,
    sensor: Option<String>,
    agent_id: Option<String>,
    log_level: Option<String>,
    contents: Option<String>,
}

impl TimestampKeyExtractor for OpLogFilter {
    fn get_range_start_key(&self) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
        if let Some(time) = &self.time {
            (time.start, time.end)
        } else {
            (None, None)
        }
    }
}

impl RawEventFilter for OpLogFilter {
    fn check(
        &self,
        _orig_addr: Option<IpAddr>,
        _resp_addr: Option<IpAddr>,
        _orig_port: Option<u16>,
        _resp_port: Option<u16>,
        log_level: Option<String>,
        log_contents: Option<String>,
        _text: Option<String>,
        sensor: Option<String>,
        agent_id: Option<String>,
    ) -> Result<bool> {
        if let Some(filter_level) = &self.log_level {
            let log_level = if let Some(log_level) = log_level {
                filter_level != &log_level
            } else {
                false
            };
            if log_level {
                return Ok(false);
            }
        }
        if let Some(filter_str) = &self.contents {
            let contents = if let Some(contents) = log_contents {
                !contents.contains(filter_str)
            } else {
                false
            };
            if contents {
                return Ok(false);
            }
        }
        if let Some(filter_agent_id) = &self.agent_id {
            let is_agent_id_mismatch = if let Some(agent_id) = agent_id {
                !agent_id.contains(filter_agent_id)
            } else {
                false
            };
            if is_agent_id_mismatch {
                return Ok(false);
            }
        }
        if let Some(filter_sensor) = &self.sensor {
            let is_sensor_mismatch = if let Some(sensor) = sensor {
                !sensor.contains(filter_sensor)
            } else {
                false
            };
            if is_sensor_mismatch {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[derive(SimpleObject, Debug, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [log_raw_events::LogRawEventsLogRawEventsEdgesNode, ])]
struct LogRawEvent {
    timestamp: DateTime<Utc>,
    log: String,
}

impl FromKeyValue<Log> for LogRawEvent {
    fn from_key_value(key: &[u8], l: Log) -> Result<Self> {
        Ok(LogRawEvent {
            timestamp: get_timestamp_from_key(key)?,
            log: base64_engine.encode(l.log),
        })
    }
}

#[derive(SimpleObject, Debug)]
struct OpLogRawEvent {
    timestamp: DateTime<Utc>,
    level: String,
    contents: String,
    agent_name: String,
    sensor: String,
}

impl FromKeyValue<OpLog> for OpLogRawEvent {
    fn from_key_value(key: &[u8], l: OpLog) -> Result<Self> {
        Ok(OpLogRawEvent {
            timestamp: get_timestamp_from_key_prefix(key)?,
            level: format!("{:?}", l.log_level),
            contents: l.contents,
            agent_name: l.agent_name,
            sensor: l.sensor,
        })
    }
}

async fn handle_log_raw_events<'ctx>(
    ctx: &Context<'_>,
    filter: LogFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, LogRawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.log_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

#[Object]
impl LogQuery {
    async fn log_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: LogFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, LogRawEvent>> {
        if filter.kind.is_none() {
            return Err(anyhow!("log query failed: kind is required").into());
        }

        let handler = handle_log_raw_events;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            after,
            before,
            first,
            last,
            handler,
            LogRawEvents,
            log_raw_events::Variables,
            log_raw_events::ResponseData,
            log_raw_events
        )
    }

    async fn op_log_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: OpLogFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, OpLogRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.op_log_store()?;
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection_by_prefix_timestamp_key(&store, &filter, after, before, first, last)
            },
        )
        .await
    }

    async fn tsv_formatted_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: TsvFilter,
    ) -> Result<Vec<String>> {
        let handler = |ctx: &Context<'ctx>, filter: &TsvFilter| -> Result<Vec<String>> {
            let db = ctx.data::<Database>()?;
            match filter.protocol.as_str() {
                "conn" => Ok(gen_tsv_format_events::<Conn>(&db.conn_store()?, filter)),
                "dns" => Ok(gen_tsv_format_events::<Dns>(&db.dns_store()?, filter)),
                "http" => Ok(gen_tsv_format_events::<Http>(&db.http_store()?, filter)),
                "rdp" => Ok(gen_tsv_format_events::<Rdp>(&db.rdp_store()?, filter)),
                "smtp" => Ok(gen_tsv_format_events::<Smtp>(&db.smtp_store()?, filter)),
                "ntlm" => Ok(gen_tsv_format_events::<Ntlm>(&db.ntlm_store()?, filter)),
                "kerberos" => Ok(gen_tsv_format_events::<Kerberos>(
                    &db.kerberos_store()?,
                    filter,
                )),
                "ssh" => Ok(gen_tsv_format_events::<Ssh>(&db.ssh_store()?, filter)),
                "dce_rpc" => Ok(gen_tsv_format_events::<DceRpc>(
                    &db.dce_rpc_store()?,
                    filter,
                )),
                "ftp" => Ok(gen_tsv_format_events::<Ftp>(&db.ftp_store()?, filter)),
                "mqtt" => Ok(gen_tsv_format_events::<Mqtt>(&db.mqtt_store()?, filter)),
                "ldap" => Ok(gen_tsv_format_events::<Ldap>(&db.ldap_store()?, filter)),
                "tls" => Ok(gen_tsv_format_events::<Tls>(&db.tls_store()?, filter)),
                "smb" => Ok(gen_tsv_format_events::<Smb>(&db.smb_store()?, filter)),
                "nfs" => Ok(gen_tsv_format_events::<Nfs>(&db.nfs_store()?, filter)),
                "bootp" => Ok(gen_tsv_format_events::<Bootp>(&db.bootp_store()?, filter)),
                "dhcp" => Ok(gen_tsv_format_events::<Dhcp>(&db.dhcp_store()?, filter)),
                "process_create" => Ok(gen_tsv_format_events::<ProcessCreate>(
                    &db.process_create_store()?,
                    filter,
                )),
                "file_create_time" => Ok(gen_tsv_format_events::<FileCreationTimeChanged>(
                    &db.file_create_time_store()?,
                    filter,
                )),
                "network_connect" => Ok(gen_tsv_format_events::<NetworkConnection>(
                    &db.network_connect_store()?,
                    filter,
                )),
                "process_terminate" => Ok(gen_tsv_format_events::<ProcessTerminated>(
                    &db.process_terminate_store()?,
                    filter,
                )),
                "image_load" => Ok(gen_tsv_format_events::<ImageLoaded>(
                    &db.image_load_store()?,
                    filter,
                )),
                "file_create" => Ok(gen_tsv_format_events::<FileCreate>(
                    &db.file_create_store()?,
                    filter,
                )),
                "registry_value_set" => Ok(gen_tsv_format_events::<RegistryValueSet>(
                    &db.registry_value_set_store()?,
                    filter,
                )),
                "registry_key_rename" => Ok(gen_tsv_format_events::<RegistryKeyValueRename>(
                    &db.registry_key_rename_store()?,
                    filter,
                )),
                "file_create_stream_hash" => Ok(gen_tsv_format_events::<FileCreateStreamHash>(
                    &db.file_create_stream_hash_store()?,
                    filter,
                )),
                "pipe_event" => Ok(gen_tsv_format_events::<PipeEvent>(
                    &db.pipe_event_store()?,
                    filter,
                )),
                "dns_query" => Ok(gen_tsv_format_events::<DnsEvent>(
                    &db.dns_query_store()?,
                    filter,
                )),
                "file_delete" => Ok(gen_tsv_format_events::<FileDelete>(
                    &db.file_delete_store()?,
                    filter,
                )),
                "process_tamper" => Ok(gen_tsv_format_events::<ProcessTampering>(
                    &db.process_tamper_store()?,
                    filter,
                )),
                "file_delete_detected" => Ok(gen_tsv_format_events::<FileDeleteDetected>(
                    &db.file_delete_detected_store()?,
                    filter,
                )),
                none => Err(anyhow!("{}: Unknown protocol", none).into()),
            }
        };
        events_vec_in_cluster!(
            ctx,
            filter,
            filter.sensor,
            handler,
            TsvFormattedRawEvents,
            tsv_formatted_raw_events::Variables,
            tsv_formatted_raw_events::ResponseData,
            tsv_formatted_raw_events
        )
    }
}

fn gen_tsv_format_events<T>(store: &RawEventStore<'_, T>, filter: &TsvFilter) -> Vec<String>
where
    T: DeserializeOwned + Display,
{
    store
        .batched_multi_get_from_ts(&filter.sensor, &filter.timestamps)
        .into_iter()
        .filter_map(|(timestamp, value)| {
            bincode::deserialize::<T>(&value)
                .ok()
                .map(|v| format!("{timestamp}\t{v}"))
        })
        .collect()
}

macro_rules! impl_from_giganto_log_filter_for_graphql_client {
    ($($autogen_mod:ident),*) => {
        $(
            impl From<LogFilter> for $autogen_mod::LogFilter {
                fn from(filter: LogFilter) -> Self {
                    Self {
                        time:   filter.time.map(Into::into),
                        sensor: filter.sensor,
                        kind:   filter.kind,
                    }
                }
            }
        )*
    };
}
macro_rules! impl_from_giganto_tsv_formatted_raw_events_filter_for_graphql_client {
    ($($autogen_mod:ident),*) => {
        $(
            impl From<TsvFilter> for $autogen_mod::TsvFilter {
                fn from(filter: TsvFilter) -> Self {
                    Self {
                        protocol: filter.protocol,
                        timestamps: filter.timestamps,
                        sensor: filter.sensor,
                    }
                }
            }
        )*
    };
}
impl_from_giganto_time_range_struct_for_graphql_client!(log_raw_events);
impl_from_giganto_log_filter_for_graphql_client!(log_raw_events);
impl_from_giganto_tsv_formatted_raw_events_filter_for_graphql_client!(tsv_formatted_raw_events);

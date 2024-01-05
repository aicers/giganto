#[cfg(test)]
mod tests;

use super::{
    base64_engine,
    client::derives::{log_raw_events, LogRawEvents},
    get_timestamp_from_key, handle_paged_events,
    impl_from_giganto_time_range_struct_for_graphql_client, load_connection,
    paged_events_in_cluster, Engine, FromKeyValue,
};
use crate::{
    graphql::{RawEventFilter, TimeRange},
    storage::{Database, KeyExtractor},
};
use anyhow::anyhow;
use async_graphql::{
    connection::{query, Connection},
    Context, InputObject, Object, Result, SimpleObject,
};
use chrono::{DateTime, Utc};
use giganto_client::ingest::log::{Log, OpLog};
use giganto_proc_macro::ConvertGraphQLEdgesNode;
use graphql_client::GraphQLQuery;
use std::{fmt::Debug, net::IpAddr};

#[derive(Default)]
pub(super) struct LogQuery;

#[allow(clippy::module_name_repetitions)]
#[derive(InputObject)]
pub struct LogFilter {
    time: Option<TimeRange>,
    source: String,
    kind: Option<String>,
}

impl KeyExtractor for LogFilter {
    fn get_start_key(&self) -> &str {
        &self.source
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
        _source: Option<String>,
    ) -> Result<bool> {
        Ok(true)
    }
}

#[derive(InputObject)]
pub struct OpLogFilter {
    time: Option<TimeRange>,
    agent_id: String,
    log_level: Option<String>,
    contents: Option<String>,
}

impl KeyExtractor for OpLogFilter {
    fn get_start_key(&self) -> &str {
        &self.agent_id
    }

    // oplog event don't use mid key
    fn get_mid_key(&self) -> Option<Vec<u8>> {
        None
    }

    fn get_range_end_key(&self) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
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
        _source: Option<String>,
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
}

impl FromKeyValue<OpLog> for OpLogRawEvent {
    fn from_key_value(key: &[u8], l: OpLog) -> Result<Self> {
        Ok(OpLogRawEvent {
            timestamp: get_timestamp_from_key(key)?,
            level: format!("{:?}", l.log_level),
            contents: l.contents,
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
            filter.source,
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
                load_connection(&store, &filter, after, before, first, last)
            },
        )
        .await
    }
}

macro_rules! impl_from_giganto_log_filter_for_graphql_client {
    ($($autogen_mod:ident),*) => {
        $(
            impl From<LogFilter> for $autogen_mod::LogFilter {
                fn from(filter: LogFilter) -> Self {
                    Self {
                        time:   filter.time.map(Into::into),
                        source: filter.source,
                        kind:   filter.kind,
                    }
                }
            }
        )*
    };
}

impl_from_giganto_time_range_struct_for_graphql_client!(log_raw_events);
impl_from_giganto_log_filter_for_graphql_client!(log_raw_events);

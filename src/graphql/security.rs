use super::{
    check_address, check_contents, check_port, check_source, get_timestamp_from_key,
    load_connection, FromKeyValue, IpRange, PortRange,
};
use crate::{
    graphql::{RawEventFilter, TimeRange},
    storage::{Database, KeyExtractor},
};
use async_graphql::{
    connection::{query, Connection},
    Context, InputObject, Object, Result, SimpleObject,
};
use chrono::{DateTime, Utc};
use giganto_client::ingest::log::SecuLog;
use std::{fmt::Debug, net::IpAddr};

#[derive(Default)]
pub(super) struct SecurityLogQuery;

#[derive(InputObject)]
pub struct SecuLogFilter {
    time: Option<TimeRange>,
    source: Option<String>,
    kind: String,
    orig_addr: Option<IpRange>,
    resp_addr: Option<IpRange>,
    orig_port: Option<PortRange>,
    resp_port: Option<PortRange>,
    log: Option<String>,
}

impl KeyExtractor for SecuLogFilter {
    fn get_start_key(&self) -> &str {
        &self.kind
    }

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

impl RawEventFilter for SecuLogFilter {
    fn check(
        &self,
        orig_addr: Option<IpAddr>,
        resp_addr: Option<IpAddr>,
        orig_port: Option<u16>,
        resp_port: Option<u16>,
        _log_level: Option<String>,
        log_contents: Option<String>,
        _text: Option<String>,
        source: Option<String>,
    ) -> Result<bool> {
        if check_address(&self.orig_addr, orig_addr)?
            && check_address(&self.resp_addr, resp_addr)?
            && check_port(&self.orig_port, orig_port)
            && check_port(&self.resp_port, resp_port)
            && check_contents(&self.log, log_contents)
            && check_source(&self.source, &source)
        {
            return Ok(true);
        }
        Ok(false)
    }
}

#[derive(SimpleObject, Debug)]
struct SecuLogRawEvent {
    timestamp: DateTime<Utc>,
    source: String,
    log_type: String,
    version: String,
    orig_addr: Option<String>,
    orig_port: Option<u16>,
    resp_addr: Option<String>,
    resp_port: Option<u16>,
    proto: Option<u8>,
    contents: String,
}

impl FromKeyValue<SecuLog> for SecuLogRawEvent {
    fn from_key_value(key: &[u8], sl: SecuLog) -> Result<Self> {
        Ok(SecuLogRawEvent {
            timestamp: get_timestamp_from_key(key)?,
            source: sl.source,
            log_type: sl.log_type,
            version: sl.version,
            orig_addr: sl.orig_addr.map(|addr| addr.to_string()),
            orig_port: sl.orig_port,
            resp_addr: sl.resp_addr.map(|addr| addr.to_string()),
            resp_port: sl.resp_port,
            proto: sl.proto,
            contents: sl.contents,
        })
    }
}

#[Object]
impl SecurityLogQuery {
    async fn secu_log_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: SecuLogFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, SecuLogRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.secu_log_store()?;

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

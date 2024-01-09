use super::{
    check_address, check_contents, check_port, check_source, get_timestamp_from_key,
    handle_paged_events, impl_from_giganto_range_structs_for_graphql_client,
    paged_events_in_cluster, FromKeyValue, IpRange, NodeSource, PortRange,
};
use crate::{
    graphql::{
        client::derives::{
            netflow5_raw_events, netflow9_raw_events, Netflow5RawEvents, Netflow9RawEvents,
        },
        RawEventFilter, TimeRange,
    },
    storage::{Database, KeyExtractor},
};
use async_graphql::{
    connection::Connection, Context, Error, InputObject, Object, Result, SimpleObject,
};
use chrono::{DateTime, Utc};
use giganto_client::ingest::netflow::{Netflow5, Netflow9};
use giganto_proc_macro::ConvertGraphQLEdgesNode;
use graphql_client::GraphQLQuery;
use std::{fmt::Debug, net::IpAddr};

static TCP_FLAGS: [(u8, &str); 8] = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x08, "CWR"),
];

#[derive(Default)]
pub(super) struct NetflowQuery;

#[derive(InputObject, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct NetflowFilter {
    time: Option<TimeRange>,
    source: Option<String>,
    kind: Option<String>,
    orig_addr: Option<IpRange>,
    resp_addr: Option<IpRange>,
    orig_port: Option<PortRange>,
    resp_port: Option<PortRange>,
    contents: Option<String>,
}

impl KeyExtractor for NetflowFilter {
    fn get_start_key(&self) -> &str {
        self.kind.as_deref().expect("always exists")
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

impl RawEventFilter for NetflowFilter {
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
        _agent_id: Option<String>,
    ) -> Result<bool> {
        if check_address(&self.orig_addr, orig_addr)?
            && check_address(&self.resp_addr, resp_addr)?
            && check_port(&self.orig_port, orig_port)
            && check_port(&self.resp_port, resp_port)
            && check_contents(&self.contents, log_contents)
            && check_source(&self.source, &source)
        {
            return Ok(true);
        }
        Ok(false)
    }
}

#[derive(SimpleObject, Debug, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [netflow5_raw_events::Netflow5RawEventsNetflow5RawEventsEdgesNode, ])]
#[allow(clippy::module_name_repetitions)]
pub struct Netflow5RawEvent {
    timestamp: DateTime<Utc>,
    source: String,
    src_addr: String,
    dst_addr: String,
    next_hop: String,
    input: u16,
    output: u16,
    d_pkts: u32,
    d_octets: u32,
    first: String, // milliseconds
    last: String,  // milliseconds
    src_port: u16,
    dst_port: u16,
    tcp_flags: String,
    prot: u8,
    tos: String, // Hex
    src_as: u16,
    dst_as: u16,
    src_mask: u8,
    dst_mask: u8,
    sequence: u32,
    engine_type: u8,
    engine_id: u8,
    sampling_mode: String,
    sampling_rate: u16,
}

impl FromKeyValue<Netflow5> for Netflow5RawEvent {
    fn from_key_value(key: &[u8], val: Netflow5) -> Result<Self> {
        Ok(Netflow5RawEvent {
            timestamp: get_timestamp_from_key(key)?,
            source: val.source,
            src_addr: val.src_addr.to_string(),
            dst_addr: val.dst_addr.to_string(),
            next_hop: val.next_hop.to_string(),
            input: val.input,
            output: val.output,
            d_pkts: val.d_pkts,
            d_octets: val.d_octets,
            first: millis_to_secs(val.first),
            last: millis_to_secs(val.last),
            src_port: val.src_port,
            dst_port: val.dst_port,
            tcp_flags: tcp_flags(val.tcp_flags),
            prot: val.prot,
            tos: format!("{:x}", val.tos),
            src_as: val.src_as,
            dst_as: val.dst_as,
            src_mask: val.src_mask,
            dst_mask: val.dst_mask,
            sequence: val.sequence,
            engine_type: val.engine_type,
            engine_id: val.engine_id,
            sampling_mode: format!("{:x}", val.sampling_mode),
            sampling_rate: val.sampling_rate,
        })
    }
}

impl NodeSource for Netflow5RawEvent {
    fn source(&self) -> &str {
        &self.source
    }
}

#[derive(SimpleObject, Debug, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [netflow9_raw_events::Netflow9RawEventsNetflow9RawEventsEdgesNode, ])]
#[allow(clippy::module_name_repetitions)]
pub struct Netflow9RawEvent {
    timestamp: DateTime<Utc>,
    source: String,
    sequence: u32,
    source_id: u32,
    template_id: u16,
    orig_addr: String,
    orig_port: u16,
    resp_addr: String,
    resp_port: u16,
    proto: u8,
    contents: String,
}

impl FromKeyValue<Netflow9> for Netflow9RawEvent {
    fn from_key_value(key: &[u8], val: Netflow9) -> Result<Self> {
        Ok(Netflow9RawEvent {
            timestamp: get_timestamp_from_key(key)?,
            source: val.source,
            sequence: val.sequence,
            source_id: val.source_id,
            template_id: val.template_id,
            orig_addr: val.orig_addr.to_string(),
            orig_port: val.orig_port,
            resp_addr: val.resp_addr.to_string(),
            resp_port: val.resp_port,
            proto: val.proto,
            contents: val.contents,
        })
    }
}

impl NodeSource for Netflow9RawEvent {
    fn source(&self) -> &str {
        &self.source
    }
}

pub(crate) fn millis_to_secs(millis: u32) -> String {
    format!("{}.{}", millis / 1000, millis - (millis / 1000) * 1000)
}

pub(crate) fn tcp_flags(b: u8) -> String {
    let mut res = String::new();
    for e in &TCP_FLAGS {
        if b & e.0 == e.0 {
            res.push_str(e.1);
            res.push('-');
        }
    }
    if res.is_empty() {
        res.push_str("None");
    }

    if res.ends_with('-') {
        res.pop();
    }
    res
}

async fn handle_netflow5_raw_events<'ctx>(
    ctx: &Context<'ctx>,
    filter: NetflowFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, Netflow5RawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.netflow5_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

async fn handle_netflow9_raw_events<'ctx>(
    ctx: &Context<'ctx>,
    filter: NetflowFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, Netflow9RawEvent>> {
    let db = ctx.data::<Database>()?;
    let store = db.netflow9_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

#[Object]
impl NetflowQuery {
    #[allow(clippy::too_many_arguments)]
    async fn netflow5_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        mut filter: NetflowFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        request_from_peer: Option<bool>,
    ) -> Result<Connection<String, Netflow5RawEvent>> {
        filter.kind = Some("netflow5".to_string());
        let handler = handle_netflow5_raw_events;

        paged_events_in_cluster!(
            request_all_peers_if_source_is_none
            ctx,
            filter,
            after,
            before,
            first,
            last,
            request_from_peer,
            handler,
            Netflow5RawEvents,
            netflow5_raw_events::Variables,
            netflow5_raw_events::ResponseData,
            netflow5_raw_events
        )
    }

    #[allow(clippy::too_many_arguments)]
    async fn netflow9_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        mut filter: NetflowFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        request_from_peer: Option<bool>,
    ) -> Result<Connection<String, Netflow9RawEvent>> {
        filter.kind = Some("netflow9".to_string());
        let handler = handle_netflow9_raw_events;

        paged_events_in_cluster!(
            request_all_peers_if_source_is_none
            ctx,
            filter,
            after,
            before,
            first,
            last,
            request_from_peer,
            handler,
            Netflow9RawEvents,
            netflow9_raw_events::Variables,
            netflow9_raw_events::ResponseData,
            netflow9_raw_events
        )
    }
}

macro_rules! impl_from_giganto_netflow_filter_for_graphql_client {
    ($($autogen_mod:ident),*) => {
        $(
            impl From<NetflowFilter> for $autogen_mod::NetflowFilter {
                fn from(filter: NetflowFilter) -> Self {
                    Self {
                        time: filter.time.map(Into::into),
                        source: filter.source,
                        kind: filter.kind,
                        orig_addr: filter.orig_addr.map(Into::into),
                        resp_addr: filter.resp_addr.map(Into::into),
                        orig_port: filter.orig_port.map(Into::into),
                        resp_port: filter.resp_port.map(Into::into),
                        contents: filter.contents,
                    }
                }
            }
        )*
    };
}
impl_from_giganto_range_structs_for_graphql_client!(netflow5_raw_events, netflow9_raw_events);
impl_from_giganto_netflow_filter_for_graphql_client!(netflow5_raw_events, netflow9_raw_events);

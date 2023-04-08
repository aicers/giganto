use super::network::HttpRawEvent;
use crate::{
    graphql::{
        lower_closed_bound_key,
        network::{key_prefix, IpRange, PortRange},
        upper_open_bound_key, TimeRange,
    },
    storage::Database,
    storage::Direction,
};
use aho_corasick::AhoCorasick;
use async_graphql::{Context, InputObject, Object, Result, SimpleObject};
use chrono::{DateTime, Utc};
use giganto_client::ingest::network::Http;
use serde::Serialize;
use std::net::IpAddr;
#[derive(Default)]
pub(super) struct SearchQuery;

#[derive(SimpleObject, InputObject, Serialize, Debug)]
#[graphql(input_name = "SourceKeyInput")]
pub struct SourceKey {
    pub source: String,
    pub timestamp: DateTime<Utc>,
    pub name: String,
}

#[allow(clippy::module_name_repetitions)]
#[derive(InputObject, Serialize)]
pub struct SearchFilter {
    pub keyword: Option<String>,
    pub time_range: Option<TimeRange>,
    pub src_ip: Option<IpRange>,
    pub src_port: Option<PortRange>,
    pub dst_ip: Option<IpRange>,
    pub dst_port: Option<PortRange>,
}

impl Clone for HttpRawEvent {
    fn clone(&self) -> Self {
        HttpRawEvent {
            timestamp: self.timestamp,
            orig_addr: self.orig_addr.clone(),
            orig_port: self.orig_port,
            resp_addr: self.resp_addr.clone(),
            resp_port: self.resp_port,
            proto: self.proto,
            last_time: self.last_time,
            method: self.method.clone(),
            host: self.host.clone(),
            uri: self.uri.clone(),
            referrer: self.referrer.clone(),
            version: self.version.clone(),
            user_agent: self.user_agent.clone(),
            request_len: self.request_len,
            response_len: self.response_len,
            status_code: self.status_code,
            status_msg: self.status_msg.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            cookie: self.cookie.clone(),
            content_encoding: self.content_encoding.clone(),
            content_type: self.content_type.clone(),
            cache_control: self.cache_control.clone(),
        }
    }
}

#[Object]
impl SearchQuery {
    #[allow(clippy::too_many_lines, clippy::unused_async)]
    async fn search_filtered_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        keys: Vec<SourceKey>,
        filter: Option<SearchFilter>,
    ) -> Result<Vec<HttpRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.http_store()?;
        let mut records = Vec::with_capacity(keys.len());
        let mut copy = Vec::with_capacity(keys.len());

        for k in &keys {
            let mut temp = store.boundary_iter(
                &lower_closed_bound_key(
                    &key_prefix(&k.source),
                    filter.as_ref().map_or_else(
                        || Some(k.timestamp),
                        |f| {
                            f.time_range
                                .as_ref()
                                .map_or_else(|| Some(k.timestamp), |t| t.start)
                        },
                    ),
                ),
                &upper_open_bound_key(
                    &key_prefix(&k.source),
                    filter.as_ref().map_or_else(
                        || {
                            Some(
                                k.timestamp
                                    .checked_add_signed(chrono::Duration::nanoseconds(1))
                                    .unwrap_or_default(),
                            )
                        },
                        |f| {
                            f.time_range.as_ref().map_or_else(
                                || {
                                    Some(
                                        k.timestamp
                                            .checked_add_signed(chrono::Duration::nanoseconds(1))
                                            .unwrap_or_default(),
                                    )
                                },
                                |t| t.end,
                            )
                        },
                    ),
                ),
                Direction::Forward,
            );

            if let Some(Ok((_, item))) = temp.next() {
                let raw_event = HttpRawEvent {
                    timestamp: k.timestamp,
                    orig_addr: item.orig_addr.to_string().clone(),
                    orig_port: item.orig_port,
                    resp_addr: item.resp_addr.to_string().clone(),
                    resp_port: item.resp_port,
                    proto: item.proto,
                    last_time: item.last_time,
                    method: item.method.clone(),
                    host: item.host.clone(),
                    uri: item.uri.clone(),
                    referrer: item.referrer.clone(),
                    version: item.version.clone(),
                    user_agent: item.user_agent.clone(),
                    request_len: item.request_len,
                    response_len: item.response_len,
                    status_code: item.status_code,
                    status_msg: item.status_msg.clone(),
                    username: item.username.clone(),
                    password: item.password.clone(),
                    cookie: item.cookie.clone(),
                    content_encoding: item.content_encoding.clone(),
                    content_type: item.content_type.clone(),
                    cache_control: item.cache_control.clone(),
                };
                if let Some(filter) = filter.as_ref() {
                    match check(filter, &item, &k.timestamp, &k.name) {
                        Ok(true) => records.push(raw_event.clone()),
                        Ok(false) | Err(_) => {}
                    }
                }
                copy.push(raw_event);
            }
        }

        match filter {
            Some(_) => Ok(records),
            None => Ok(copy),
        }
    }
}

#[allow(clippy::too_many_lines)]
fn check(
    filter: &SearchFilter,
    item: &Http,
    timestamp: &DateTime<Utc>,
    name: &String,
) -> Result<bool> {
    if let Some(keyword) = &filter.keyword {
        let matcher = AhoCorasick::new([keyword.clone()]);
        if matcher.is_match(name)
            || matcher.is_match(item.orig_addr.to_string())
            || matcher.is_match(item.orig_port.to_string())
            || matcher.is_match(item.resp_addr.to_string())
            || matcher.is_match(item.resp_port.to_string())
            || matcher.is_match(item.proto.to_string())
            || matcher.is_match(item.last_time.to_string())
            || matcher.is_match(&item.method)
            || matcher.is_match(&item.host)
            || matcher.is_match(&item.uri)
            || matcher.is_match(&item.referrer)
            || matcher.is_match(&item.version)
            || matcher.is_match(&item.user_agent)
            || matcher.is_match(item.request_len.to_string())
            || matcher.is_match(item.response_len.to_string())
            || matcher.is_match(item.status_code.to_string())
            || matcher.is_match(&item.status_msg)
            || matcher.is_match(&item.username)
            || matcher.is_match(&item.password)
            || matcher.is_match(&item.cookie)
            || matcher.is_match(&item.content_encoding)
            || matcher.is_match(&item.content_type)
            || matcher.is_match(&item.cache_control)
        {
            return Ok(true);
        }
        return Ok(false);
    }

    if let Some(src_ip_range) = &filter.src_ip {
        if check_ip_ranges(&src_ip_range, &item.orig_addr) == Ok(false) {
            return Ok(false);
        }
    }

    if let Some(dst_ip_range) = &filter.src_ip {
        if check_ip_ranges(&dst_ip_range, &item.orig_addr) == Ok(false) {
            return Ok(false);
        }
    }

    if let Some(dst_port_range) = &filter.dst_port {
        if check_port_ranges(&dst_port_range, &item.resp_port) == Ok(false) {
            return Ok(false);
        }
    }

    if let Some(src_port_range) = &filter.src_port {
        if check_port_ranges(&src_port_range, &item.orig_port) == Ok(false) {
            return Ok(false);
        }
    }

    if let Some(time_range) = &filter.time_range {
        let start = if let Some(start) = time_range.start {
            timestamp <= &start
        } else {
            false
        };

        let end = if let Some(end) = time_range.end {
            timestamp >= &end
        } else {
            false
        };

        if end || start {
            return Ok(false);
        };
    }
    Ok(true)
}

fn check_ip_ranges(ip_range: &IpRange, addr: &IpAddr) -> Result<bool> {
    let (start, end) = if let (Some(start), Some(end)) = (&ip_range.start, &ip_range.end) {
        (start.parse::<IpAddr>()?, end.parse::<IpAddr>()?)
    } else {
        return Ok(false);
    };

    if addr <= &start || addr >= &end {
        return Ok(false);
    }
    Ok(true)
}

fn check_port_ranges(port_range: &PortRange, port: &u16) -> Result<bool> {
    if let (Some(start), Some(end)) = (&port_range.start, &port_range.end) {
        if port <= start || port >= end {
            return Ok(false);
        }
    }
    Ok(true)
}

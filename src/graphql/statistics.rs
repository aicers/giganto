use super::{get_filtered_iter, get_timestamp, network::key_prefix};
use crate::{
    graphql::{RawEventFilter, TimeRange},
    ingestion::{AnalyzerStatistics, CollectorStatistics},
    storage::{Database, FilteredIter},
};
use anyhow::anyhow;
use async_graphql::{
    connection::{query, Connection, Edge},
    Context, InputObject, Object, Result, SimpleObject,
};
use chrono::{DateTime, TimeZone, Utc};
use serde::Serialize;
use std::{collections::BTreeMap, fmt::Debug, iter::Peekable, net::IpAddr};
use x509_parser::nom::AsBytes;

#[derive(Default)]
pub(super) struct StatisticsQuery;

#[allow(clippy::module_name_repetitions)]
#[derive(InputObject, Serialize)]
struct CollectorStatsFilter {
    time: Option<TimeRange>,
    source: String,
    protocol: Option<String>,
}

impl RawEventFilter for CollectorStatsFilter {
    fn time(&self) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
        if let Some(time) = &self.time {
            (time.start, time.end)
        } else {
            (None, None)
        }
    }

    fn check(
        &self,
        _orig_addr: Option<IpAddr>,
        _resp_addr: Option<IpAddr>,
        _orig_port: Option<u16>,
        _resp_port: Option<u16>,
        _log_level: Option<String>,
        _log_contents: Option<String>,
    ) -> Result<bool> {
        Ok(true)
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(InputObject, Serialize)]
struct AnalyzerStatsFilter {
    time: Option<TimeRange>,
    source: Option<String>,
    protocol: Option<String>,
    kind: Option<String>,
}

impl RawEventFilter for AnalyzerStatsFilter {
    fn time(&self) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
        if let Some(time) = &self.time {
            (time.start, time.end)
        } else {
            (None, None)
        }
    }

    fn check(
        &self,
        _orig_addr: Option<IpAddr>,
        _resp_addr: Option<IpAddr>,
        _orig_port: Option<u16>,
        _resp_port: Option<u16>,
        _log_level: Option<String>,
        _log_contents: Option<String>,
    ) -> Result<bool> {
        Ok(true)
    }
}

#[derive(SimpleObject, Debug)]
struct CollectorStatRawEvent {
    timestamp: DateTime<Utc>,
    period: u16,
    stats: Statistics,
}

#[derive(SimpleObject, Debug)]
struct AnalyzerStatRawEvent {
    timestamp: DateTime<Utc>,
    period: u16,
    stats: Vec<Statistics>,
}

#[derive(SimpleObject, Debug)]
struct Statistics {
    pub source: String,
    pub stats_detail: Vec<StatisticsDetail>,
}

#[derive(SimpleObject, Debug)]
struct StatisticsDetail {
    pub protocol: String,
    pub kind: Option<String>,
    pub total_len: u64,
    pub total_size: u64,
}

#[Object]
impl StatisticsQuery {
    async fn collector_stats_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: CollectorStatsFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, CollectorStatRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.collector_statistics_store()?;
        let key_prefix = key_prefix(&filter.source);

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let (stats_iter, cursor, size) = get_filtered_iter(
                    &store,
                    Some(&key_prefix),
                    &filter,
                    &after,
                    &before,
                    first,
                    last,
                )?;
                let mut stats_iter = stats_iter.peekable();
                if let Some(cursor) = cursor {
                    if let Some((key, _)) = stats_iter.peek() {
                        if key.as_ref() == cursor {
                            stats_iter.next();
                        }
                    }
                }

                let mut is_forward: bool = true;
                if before.is_some() || last.is_some() {
                    is_forward = false;
                }
                collector_stats_connection(stats_iter, &filter, size, is_forward)
            },
        )
        .await
    }

    async fn analyzer_stats_raw_events<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: AnalyzerStatsFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, AnalyzerStatRawEvent>> {
        let db = ctx.data::<Database>()?;
        let store = db.analyzer_statistics_store()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let (stats_iter, cursor, size) =
                    get_filtered_iter(&store, None, &filter, &after, &before, first, last)?;
                let mut stats_iter = stats_iter.peekable();
                if let Some(cursor) = cursor {
                    if let Some((key, _)) = stats_iter.peek() {
                        if key.as_ref() == cursor {
                            stats_iter.next();
                        }
                    }
                }

                let mut is_forward: bool = true;
                if before.is_some() || last.is_some() {
                    is_forward = false;
                }
                analyzer_stats_connection(stats_iter, &filter, size, is_forward)
            },
        )
        .await
    }
}

fn collector_stats_connection(
    mut stats_iter: Peekable<FilteredIter<CollectorStatistics>>,
    filter: &CollectorStatsFilter,
    size: usize,
    is_forward: bool,
) -> Result<Connection<String, CollectorStatRawEvent>> {
    let mut result_vec: Vec<Edge<String, CollectorStatRawEvent, _>> = Vec::new();
    let mut has_previous_page: bool = false;
    let mut has_next_page: bool = false;
    let mut has_next_value: bool = false;
    let mut statistics_data = stats_iter.next();

    loop {
        if let Some((key, value)) = statistics_data {
            let mut collector_stats = CollectorStatRawEvent {
                timestamp: get_timestamp(&key)?,
                period: value.period,
                stats: Statistics {
                    source: filter.source.clone(),
                    stats_detail: Vec::new(),
                },
            };
            if let Some(ref proto) = filter.protocol {
                for (record, total_len, total_size) in value.stats {
                    if proto.eq(record.convert_to_str()) {
                        let detail = statistics_detail(proto.clone(), None, total_len, total_size);
                        collector_stats.stats.stats_detail.push(detail);
                    }
                }
            } else {
                for (record, total_len, total_size) in value.stats {
                    let detail = statistics_detail(
                        record.convert_to_str().to_string(),
                        None,
                        total_len,
                        total_size,
                    );
                    collector_stats.stats.stats_detail.push(detail);
                }
            }
            result_vec.push(Edge::new(base64::encode(&key), collector_stats));
            statistics_data = stats_iter.next();
        }

        if (result_vec.len() >= size) || (statistics_data.is_none()) {
            if statistics_data.is_some() {
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
    let mut connection: Connection<String, CollectorStatRawEvent> =
        Connection::new(has_previous_page, has_next_page);
    connection.edges.extend(result_vec.into_iter());

    Ok(connection)
}

fn analyzer_stats_connection(
    mut stats_iter: Peekable<FilteredIter<AnalyzerStatistics>>,
    filter: &AnalyzerStatsFilter,
    size: usize,
    is_forward: bool,
) -> Result<Connection<String, AnalyzerStatRawEvent>> {
    let mut result_vec: Vec<Edge<String, AnalyzerStatRawEvent, _>> = Vec::new();
    let mut has_previous_page: bool = false;
    let mut has_next_page: bool = false;
    let mut has_next_value: bool = false;
    let mut statistics_data = stats_iter.next();
    loop {
        if let Some((key, value)) = statistics_data {
            let mut analyzer_stats = AnalyzerStatRawEvent {
                timestamp: Utc.timestamp_nanos(i64::from_be_bytes(key.as_bytes().try_into()?)),
                period: value.period,
                stats: Vec::new(),
            };

            if let Some(ref source) = filter.source {
                if let Some(stats) = value.stats.get(source) {
                    let input_stats =
                        filter_proto_kind(source.clone(), &filter.protocol, &filter.kind, stats)?;
                    if !input_stats.stats_detail.is_empty() {
                        analyzer_stats.stats.push(input_stats);
                    }
                }
            } else {
                for (source, stats) in value.stats {
                    let input_stats =
                        filter_proto_kind(source.clone(), &filter.protocol, &filter.kind, &stats)?;
                    if !input_stats.stats_detail.is_empty() {
                        analyzer_stats.stats.push(input_stats);
                    }
                }
            }
            if !analyzer_stats.stats.is_empty() {
                result_vec.push(Edge::new(base64::encode(&key), analyzer_stats));
            }
            statistics_data = stats_iter.next();
        }

        if (result_vec.len() >= size) || (statistics_data.is_none()) {
            if statistics_data.is_some() {
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
    let mut connection: Connection<String, AnalyzerStatRawEvent> =
        Connection::new(has_previous_page, has_next_page);
    connection.edges.extend(result_vec.into_iter());

    Ok(connection)
}

fn filter_proto_kind(
    source: String,
    filter_proto: &Option<String>,
    filter_kind: &Option<String>,
    stats: &BTreeMap<String, (u64, u64)>,
) -> Result<Statistics> {
    let mut input_stats = Statistics {
        source,
        stats_detail: Vec::new(),
    };

    if let Some(ref proto) = filter_proto {
        if proto.eq("log") {
            let Some(ref kind) = filter_kind else {
                return Err(anyhow!("wrong filter input, kind is required").into());
            };
            let key = format!("{proto}\0{kind}");
            if let Some((len, size)) = stats.get(&key) {
                let detail = statistics_detail(proto.clone(), Some(kind.clone()), *len, *size);
                input_stats.stats_detail.push(detail);
            }
        } else if let Some((len, size)) = stats.get(proto) {
            let detail = statistics_detail(proto.clone(), None, *len, *size);
            input_stats.stats_detail.push(detail);
        }
    } else {
        for (proto_kind, (len, size)) in stats {
            let mut proto_kind = proto_kind.split('\0');
            let proto = proto_kind
                .next()
                .ok_or_else(|| anyhow::anyhow!("Failed to parse proto string"))?;
            let kind = proto_kind.next().map(std::string::ToString::to_string);
            if proto.eq("log") {
                let detail = statistics_detail(proto.to_string(), kind, *len, *size);
                input_stats.stats_detail.push(detail);
            } else {
                let detail = statistics_detail(proto.to_string(), None, *len, *size);
                input_stats.stats_detail.push(detail);
            }
        }
    }
    Ok(input_stats)
}

fn statistics_detail(
    protocol: String,
    kind: Option<String>,
    total_len: u64,
    total_size: u64,
) -> StatisticsDetail {
    StatisticsDetail {
        protocol,
        kind,
        total_len,
        total_size,
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;
    use crate::ingestion::{
        AnalyzerStatistics, CollectorStatistics, RealTimeStatistics, RecordType,
    };
    use crate::storage::RawEventStore;
    use chrono::Utc;

    #[tokio::test]
    async fn collector_statistics_empty() {
        let schema = TestSchema::new();
        let query = r#"
        {
            collectorStatsRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2011-09-22T00:00:00Z" }
                    source: "localhost"
                    protocol: "dns"
                }
            ) {
                edges {
                    node {
                        timestamp,
                        period,
                        stats {
                            source,
                            statsDetail {
                                protocol,
                                totalLen,
                                totalSize
                          }
                        }
                    }

                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{collectorStatsRawEvents: {edges: []}}"
        );
    }

    #[tokio::test]
    async fn collector_statistics_with_data() {
        const SOURCE: &str = "localhost";
        const RECORD_TYPE_DNS: RecordType = RecordType::Dns;
        const RECORD_TYPE_HTTP: RecordType = RecordType::Http;
        let period = 1000;
        let dns_len = 300;
        let http_len = 600;

        let schema = TestSchema::new();
        let store = schema.db.collector_statistics_store().unwrap();
        let mut stats = Vec::new();
        stats.push((RECORD_TYPE_DNS, 1, dns_len));
        stats.push((RECORD_TYPE_HTTP, 1, http_len));
        insert_collecrot_statistic_data(
            &store,
            SOURCE,
            Utc::now().timestamp_nanos(),
            period,
            stats,
        );

        let query = r#"
        {
            collectorStatsRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-12-22T00:00:00Z" }
                    source: "localhost"
                    protocol: "dns"
                }
            ) {
                edges {
                    node {
                        period,
                        stats {
                            source,
                            statsDetail {
                                protocol,
                                totalLen,
                                totalSize
                          }
                        }
                    }

                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(), "{collectorStatsRawEvents: {edges: [{node: {period: 1000,stats: {source: \"localhost\",statsDetail: [{protocol: \"dns\",totalLen: 1,totalSize: 300}]}}}]}}");

        let query = r#"
        {
            collectorStatsRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-12-22T00:00:00Z" }
                    source: "localhost"
                }
            ) {
                edges {
                    node {
                        period,
                        stats {
                            source,
                            statsDetail {
                                protocol,
                                totalLen,
                                totalSize
                          }
                        }
                    }

                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(), "{collectorStatsRawEvents: {edges: [{node: {period: 1000,stats: {source: \"localhost\",statsDetail: [{protocol: \"dns\",totalLen: 1,totalSize: 300},{protocol: \"http\",totalLen: 1,totalSize: 600}]}}}]}}");
    }

    fn insert_collecrot_statistic_data(
        store: &RawEventStore<CollectorStatistics>,
        source: &str,
        timestamp: i64,
        period: u16,
        stats: Vec<(RecordType, u64, u64)>,
    ) {
        let mut key = Vec::with_capacity(source.len() + 1 + std::mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let stats_body = CollectorStatistics { period, stats };
        let ser_stats_body = bincode::serialize(&stats_body).unwrap();

        store.append(&key, &ser_stats_body).unwrap();
    }

    #[tokio::test]
    async fn analyzer_statistics_empty() {
        let schema = TestSchema::new();
        let query = r#"
        {
            analyzerStatsRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2011-09-22T00:00:00Z" }
                    source: "localhost"
                    protocol: "log"
                    kind: "kind1"
                }
            ) {
                edges {
                    node {
                        timestamp,
                        period,
                        stats {
                            source,
                            statsDetail {
                                protocol,
                                kind,
                                totalLen,
                                totalSize
                          }
                        }
                    }

                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{analyzerStatsRawEvents: {edges: []}}"
        );
    }

    #[tokio::test]
    async fn analyzer_statistics_with_target_source_data() {
        const SOURCE1: &str = "localhost1";
        const SOURCE2: &str = "localhost2";
        const KIND: &str = "kind1";
        const RECORD_TYPE_CONN: RecordType = RecordType::Conn;
        const RECORD_TYPE_LOG: RecordType = RecordType::Log;

        let period = 1800;
        let conn_len = 100;
        let log_len = 200;

        let schema = TestSchema::new();
        let store = schema.db.analyzer_statistics_store().unwrap();

        let mut sources = Vec::new();
        sources.push(SOURCE1.to_string());
        sources.push(SOURCE2.to_string());
        let timestamp_key = Utc::now().timestamp_nanos().to_be_bytes();

        insert_analyzer_statistic_data(
            &store,
            period,
            &sources,
            Some(KIND.to_string()),
            RecordType::Log,
            log_len,
            &timestamp_key,
        );
        let query = r#"
        {
            analyzerStatsRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-12-12T00:00:00Z" }
                    source: "localhost1"
                    protocol: "log"
                    kind: "kind1"
                }
            ) {
                edges {
                    node {
                        period,
                        stats {
                            source,
                            statsDetail {
                                protocol,
                                kind,
                                totalLen,
                                totalSize
                          }
                        }
                    }

                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(),"{analyzerStatsRawEvents: {edges: [{node: {period: 1800,stats: [{source: \"localhost1\",statsDetail: [{protocol: \"log\",kind: \"kind1\",totalLen: 1,totalSize: 200}]}]}}]}}");

        insert_analyzer_statistic_data(
            &store,
            period,
            &sources,
            None,
            RecordType::Conn,
            conn_len,
            &timestamp_key,
        );
        let query = r#"
        {
            analyzerStatsRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-12-12T00:00:00Z" }
                    source: "localhost1"
                    protocol: "conn"
                }
            ) {
                edges {
                    node {
                        period,
                        stats {
                            source,
                            statsDetail {
                                protocol,
                                kind,
                                totalLen,
                                totalSize
                          }
                        }
                    }

                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(),"{analyzerStatsRawEvents: {edges: [{node: {period: 1800,stats: [{source: \"localhost1\",statsDetail: [{protocol: \"conn\",kind: null,totalLen: 1,totalSize: 100}]}]}}]}}");

        let query = r#"
        {
            analyzerStatsRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-12-12T00:00:00Z" }
                    source: "localhost1"
                }
            ) {
                edges {
                    node {
                        period,
                        stats {
                            source,
                            statsDetail {
                                protocol,
                                kind,
                                totalLen,
                                totalSize
                          }
                        }
                    }

                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{analyzerStatsRawEvents: {edges: [{node: {period: 1800,stats: [{source: \"localhost1\",\
             statsDetail: [{protocol: \"conn\",kind: null,totalLen: 1,totalSize: 100},\
             {protocol: \"dce rpc\",kind: null,totalLen: 0,totalSize: 0},\
             {protocol: \"dns\",kind: null,totalLen: 0,totalSize: 0},\
             {protocol: \"http\",kind: null,totalLen: 0,totalSize: 0},\
             {protocol: \"kerberos\",kind: null,totalLen: 0,totalSize: 0},\
             {protocol: \"log\",kind: \"kind1\",totalLen: 0,totalSize: 0},\
             {protocol: \"ntlm\",kind: null,totalLen: 0,totalSize: 0},\
             {protocol: \"rdp\",kind: null,totalLen: 0,totalSize: 0},\
             {protocol: \"smtp\",kind: null,totalLen: 0,totalSize: 0},\
             {protocol: \"ssh\",kind: null,totalLen: 0,totalSize: 0}]}]}}]}}"
        );
    }

    #[tokio::test]
    async fn analyzer_statistics_with_all_source_data() {
        const SOURCE1: &str = "localhost1";
        const SOURCE2: &str = "localhost2";
        const KIND: &str = "kind1";
        const RECORD_TYPE_CONN: RecordType = RecordType::Conn;
        const RECORD_TYPE_LOG: RecordType = RecordType::Log;

        let period = 1800;
        let conn_len = 100;
        let log_len = 200;

        let schema = TestSchema::new();
        let store = schema.db.analyzer_statistics_store().unwrap();

        let mut sources = Vec::new();
        sources.push(SOURCE1.to_string());
        sources.push(SOURCE2.to_string());
        let timestamp_key = Utc::now().timestamp_nanos().to_be_bytes();

        insert_analyzer_statistic_data(
            &store,
            period,
            &sources,
            Some(KIND.to_string()),
            RecordType::Log,
            log_len,
            &timestamp_key,
        );
        let query = r#"
        {
            analyzerStatsRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-12-12T00:00:00Z" }
                    protocol: "log"
                    kind: "kind1"
                }
            ) {
                edges {
                    node {
                        period,
                        stats {
                            source,
                            statsDetail {
                                protocol,
                                kind,
                                totalLen,
                                totalSize
                          }
                        }
                    }

                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(),"{analyzerStatsRawEvents: {edges: [{node: {period: 1800,\
            stats: [{source: \"localhost1\",statsDetail: [{protocol: \"log\",kind: \"kind1\",totalLen: 1,totalSize: 200}]},\
            {source: \"localhost2\",statsDetail: [{protocol: \"log\",kind: \"kind1\",totalLen: 1,totalSize: 200}]}]}}]}}");

        insert_analyzer_statistic_data(
            &store,
            period,
            &sources,
            None,
            RecordType::Conn,
            conn_len,
            &timestamp_key,
        );
        let query = r#"
        {
            analyzerStatsRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-12-12T00:00:00Z" }
                    protocol: "conn"
                }
            ) {
                edges {
                    node {
                        period,
                        stats {
                            source,
                            statsDetail {
                                protocol,
                                kind,
                                totalLen,
                                totalSize
                          }
                        }
                    }

                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(),"{analyzerStatsRawEvents: {edges: [{node: {period: 1800,\
            stats: [{source: \"localhost1\",statsDetail: [{protocol: \"conn\",kind: null,totalLen: 1,totalSize: 100}]},\
            {source: \"localhost2\",statsDetail: [{protocol: \"conn\",kind: null,totalLen: 1,totalSize: 100}]}]}}]}}");

        insert_analyzer_statistic_data(
            &store,
            period,
            &sources,
            None,
            RecordType::Conn,
            conn_len,
            &timestamp_key,
        );
        let query = r#"
        {
            analyzerStatsRawEvents(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2023-12-12T00:00:00Z" }
                }
            ) {
                edges {
                    node {
                        period,
                        stats {
                            source,
                            statsDetail {
                                protocol,
                                kind,
                                totalLen,
                                totalSize
                          }
                        }
                    }

                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{analyzerStatsRawEvents: {edges: [{node: {period: 1800,stats: \
            [{source: \"localhost1\",statsDetail: \
                [{protocol: \"conn\",kind: null,totalLen: 1,totalSize: 100},\
                {protocol: \"dce rpc\",kind: null,totalLen: 0,totalSize: 0},\
                {protocol: \"dns\",kind: null,totalLen: 0,totalSize: 0},\
                {protocol: \"http\",kind: null,totalLen: 0,totalSize: 0},\
                {protocol: \"kerberos\",kind: null,totalLen: 0,totalSize: 0},\
                {protocol: \"log\",kind: \"kind1\",totalLen: 0,totalSize: 0},\
                {protocol: \"ntlm\",kind: null,totalLen: 0,totalSize: 0},\
                {protocol: \"rdp\",kind: null,totalLen: 0,totalSize: 0},\
                {protocol: \"smtp\",kind: null,totalLen: 0,totalSize: 0},\
                {protocol: \"ssh\",kind: null,totalLen: 0,totalSize: 0}]},\
            {source: \"localhost2\",statsDetail: \
                [{protocol: \"conn\",kind: null,totalLen: 1,totalSize: 100},\
                {protocol: \"dce rpc\",kind: null,totalLen: 0,totalSize: 0},\
                {protocol: \"dns\",kind: null,totalLen: 0,totalSize: 0},\
                {protocol: \"http\",kind: null,totalLen: 0,totalSize: 0},\
                {protocol: \"kerberos\",kind: null,totalLen: 0,totalSize: 0},\
                {protocol: \"log\",kind: \"kind1\",totalLen: 0,totalSize: 0},\
                {protocol: \"ntlm\",kind: null,totalLen: 0,totalSize: 0},\
                {protocol: \"rdp\",kind: null,totalLen: 0,totalSize: 0},\
                {protocol: \"smtp\",kind: null,totalLen: 0,totalSize: 0},\
                {protocol: \"ssh\",kind: null,totalLen: 0,totalSize: 0}]}]}}]}}"
        );
    }

    fn insert_analyzer_statistic_data(
        store: &RawEventStore<AnalyzerStatistics>,
        period: u16,
        sources: &Vec<String>,
        kind: Option<String>,
        record_type: RecordType,
        data_len: usize,
        timestamp_key: &[u8],
    ) {
        let mut statistics = RealTimeStatistics::new(&store, period).unwrap();
        for source in sources {
            statistics.init_source(source.clone()).unwrap();
            statistics.append(source.clone(), kind.clone(), record_type, data_len);
        }
        let stats_result = statistics.clear().unwrap();
        store
            .append(&timestamp_key, &bincode::serialize(&stats_result).unwrap())
            .unwrap();
    }
}

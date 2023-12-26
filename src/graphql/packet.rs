use super::{
    collect_records, get_timestamp_from_key, handle_paged_events, write_run_tcpdump, Direction,
    FromKeyValue, RawEventFilter, TimeRange, TIMESTAMP_SIZE,
};
use crate::{
    graphql::{
        client::derives::{packets, pcap as pcaps, Packets, Pcap as Pcaps},
        events_in_cluster, impl_from_giganto_time_range_struct_for_graphql_client,
        paged_events_in_cluster,
    },
    storage::{Database, KeyExtractor, StorageKey},
};
use async_graphql::{connection::Connection, Context, InputObject, Object, Result, SimpleObject};
use chrono::{DateTime, Utc};
use data_encoding::BASE64;
use giganto_client::ingest::Packet as pk;
use giganto_proc_macro::ConvertGraphQLEdgesNode;
use graphql_client::GraphQLQuery;
use std::net::IpAddr;

#[derive(Default)]
pub(super) struct PacketQuery;

#[allow(clippy::module_name_repetitions)]
#[derive(InputObject)]
pub struct PacketFilter {
    source: String,
    request_time: DateTime<Utc>,
    packet_time: Option<TimeRange>,
}

impl KeyExtractor for PacketFilter {
    fn get_start_key(&self) -> &str {
        &self.source
    }

    fn get_mid_key(&self) -> Option<Vec<u8>> {
        Some(
            self.request_time
                .timestamp_nanos_opt()?
                .to_be_bytes()
                .to_vec(),
        )
    }

    fn get_range_end_key(&self) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
        if let Some(time) = &self.packet_time {
            (time.start, time.end)
        } else {
            (None, None)
        }
    }
}

impl RawEventFilter for PacketFilter {
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

#[allow(clippy::struct_field_names)]
#[derive(SimpleObject, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [packets::PacketsPacketsEdgesNode, ])]
#[allow(clippy::struct_field_names)]
struct Packet {
    request_time: DateTime<Utc>,
    packet_time: DateTime<Utc>,
    packet: String,
}

#[derive(SimpleObject, Debug, Default, ConvertGraphQLEdgesNode)]
#[graphql_client_type(names = [pcaps::PcapPcap, ])]
struct Pcap {
    request_time: DateTime<Utc>,
    parsed_pcap: String,
}

impl Pcap {
    fn new() -> Self {
        Self::default()
    }
}

impl FromKeyValue<pk> for Packet {
    fn from_key_value(key: &[u8], pk: pk) -> Result<Self> {
        Ok(Packet {
            request_time: get_timestamp_from_key(&key[..key.len() - (TIMESTAMP_SIZE + 1)])?,
            packet_time: get_timestamp_from_key(key)?,
            packet: BASE64.encode(&pk.packet),
        })
    }
}

async fn handle_packets<'ctx>(
    ctx: &Context<'ctx>,
    filter: PacketFilter,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<String, Packet>> {
    let db = ctx.data::<Database>()?;
    let store = db.packet_store()?;

    handle_paged_events(store, filter, after, before, first, last).await
}

fn handle_pcap(ctx: &Context<'_>, filter: &PacketFilter) -> Result<Pcap> {
    let db = ctx.data::<Database>()?;
    let store = db.packet_store()?;

    // generate storage search key
    let key_builder = StorageKey::builder()
        .start_key(filter.get_start_key())
        .mid_key(filter.get_mid_key());
    let from_key = key_builder
        .clone()
        .lower_closed_bound_end_key(filter.get_range_end_key().0)
        .build();
    let to_key = key_builder
        .upper_open_bound_end_key(filter.get_range_end_key().1)
        .build();

    let iter = store.boundary_iter(&from_key.key(), &to_key.key(), Direction::Forward);
    let (records, _) = collect_records(iter, 1000, filter);

    let packet_vector = records.into_iter().map(|(_, packet)| packet).collect();

    let pcap = write_run_tcpdump(&packet_vector)?;

    Ok(Pcap {
        request_time: filter.request_time,
        parsed_pcap: pcap,
    })
}

#[Object]
impl PacketQuery {
    async fn packets<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filter: PacketFilter,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, Packet>> {
        let handler = handle_packets;

        paged_events_in_cluster!(
            ctx,
            filter,
            filter.source,
            after,
            before,
            first,
            last,
            handler,
            Packets,
            packets::Variables,
            packets::ResponseData,
            packets
        )
    }

    #[allow(clippy::unused_async)]
    async fn pcap<'ctx>(&self, ctx: &Context<'ctx>, filter: PacketFilter) -> Result<Pcap> {
        let handler = handle_pcap;

        events_in_cluster!(
            ctx,
            filter,
            filter.source,
            handler,
            Pcaps,
            pcaps::Variables,
            pcaps::ResponseData,
            pcap,
            Pcap
        )
    }
}

macro_rules! impl_from_giganto_packet_filter_for_graphql_client {
    ($($autogen_mod:ident),*) => {
        $(
            impl From<PacketFilter> for $autogen_mod::PacketFilter {
                fn from(filter: PacketFilter) -> Self {
                    Self {
                        source: filter.source,
                        request_time: filter.request_time,
                        packet_time: filter.packet_time.map(Into::into),
                    }
                }
            }
        )*
    };
}

impl_from_giganto_time_range_struct_for_graphql_client!(packets, pcaps);
impl_from_giganto_packet_filter_for_graphql_client!(packets, pcaps);

#[cfg(test)]
mod tests {
    use crate::{graphql::tests::TestSchema, storage::RawEventStore};
    use chrono::{NaiveDateTime, TimeZone, Utc};
    use giganto_client::ingest::Packet as pk;
    use std::mem;

    #[tokio::test]
    async fn packets_empty() {
        let schema = TestSchema::new();
        let query = r#"
        {
            packets(
                filter: {
                    source: "a"
                    requestTime: "1992-06-05T00:00:00Z"
                    packetTime: { start: "1992-06-05T00:00:00Z", end: "2023-09-22T00:00:00Z" }
                }
                first: 1
            ) {
                edges {
                    node {
                        packet
                    }
                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(), "{packets: {edges: []}}");
    }

    #[tokio::test]
    async fn packets_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.packet_store().unwrap();

        let dt1 = Utc.with_ymd_and_hms(2023, 1, 20, 0, 0, 0).unwrap();
        let dt2 = Utc.with_ymd_and_hms(2023, 1, 20, 0, 0, 1).unwrap();
        let dt3 = Utc.with_ymd_and_hms(2023, 1, 20, 0, 0, 2).unwrap();

        let ts1 = dt1.timestamp_nanos_opt().unwrap();
        let ts2 = dt2.timestamp_nanos_opt().unwrap();
        let ts3 = dt3.timestamp_nanos_opt().unwrap();

        insert_packet(&store, "src 1", ts1, ts1);
        insert_packet(&store, "src 1", ts1, ts2);

        insert_packet(&store, "ingest src 1", ts1, ts1);
        insert_packet(&store, "ingest src 1", ts1, ts3);

        insert_packet(&store, "src 1", ts2, ts1);
        insert_packet(&store, "src 1", ts2, ts3);

        let query = r#"
        {
            packets(
                filter: {
                    source: "src 1"
                    requestTime: "2023-01-20T00:00:00Z"
                }
                first: 10
            ) {
                edges {
                    node {
                        packet
                        packetTime
                        requestTime
                    }
                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(), "{packets: {edges: [{node: {packet: \"AAECAw==\",packetTime: \"2023-01-20T00:00:00+00:00\",requestTime: \"2023-01-20T00:00:00+00:00\"}},{node: {packet: \"AAECAw==\",packetTime: \"2023-01-20T00:00:01+00:00\",requestTime: \"2023-01-20T00:00:00+00:00\"}}]}}");

        let query = r#"
        {
            packets(
                filter: {
                    source: "ingest src 1"
                    requestTime: "2023-01-20T00:00:00Z"
                }
                first: 10
            ) {
                edges {
                    node {
                        packetTime
                    }
                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(), "{packets: {edges: [{node: {packetTime: \"2023-01-20T00:00:00+00:00\"}},{node: {packetTime: \"2023-01-20T00:00:02+00:00\"}}]}}");

        let query = r#"
        {
            packets(
                filter: {
                    source: "src 1"
                    requestTime: "2023-01-20T00:00:01Z"
                }
                first: 10
            ) {
                edges {
                    node {
                        packetTime
                    }
                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(), "{packets: {edges: [{node: {packetTime: \"2023-01-20T00:00:00+00:00\"}},{node: {packetTime: \"2023-01-20T00:00:02+00:00\"}}]}}");
    }

    #[tokio::test]
    async fn pcap_with_data() {
        let schema = TestSchema::new();
        let store = schema.db.packet_store().unwrap();

        let pattern = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+";
        let re = regex::Regex::new(pattern).unwrap();

        let dt1 = Utc.with_ymd_and_hms(2023, 1, 20, 0, 0, 0).unwrap();
        let dt2 = Utc.with_ymd_and_hms(2023, 1, 20, 0, 0, 1).unwrap();
        let dt3 = Utc.with_ymd_and_hms(2023, 1, 20, 0, 0, 2).unwrap();

        let ts1 = dt1.timestamp_nanos_opt().unwrap();
        let ts2 = dt2.timestamp_nanos_opt().unwrap();
        let ts3 = dt3.timestamp_nanos_opt().unwrap();

        insert_packet(&store, "src 1", ts1, ts1);
        insert_packet(&store, "src 1", ts1, ts2);

        insert_packet(&store, "ingest src 1", ts1, ts1);
        insert_packet(&store, "ingest src 1", ts1, ts3);

        insert_packet(&store, "src 1", ts2, ts1);
        insert_packet(&store, "src 1", ts2, ts3);

        let query = r#"
        {
            pcap(
                filter: {
                    source: "src 1"
                    requestTime: "2023-01-20T00:00:00Z"
                }
            ) {
                parsedPcap
            }
        }"#;
        let res = schema.execute(query).await;

        // get response timestamps
        let res_json = res.data.into_json().unwrap();
        let parsed_pcap = res_json["pcap"]["parsedPcap"].as_str().unwrap();

        let timestamps: Vec<chrono::NaiveDateTime> = re
            .find_iter(parsed_pcap)
            .map(|m| m.as_str())
            .map(|s| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.6f").unwrap())
            .collect();

        // Change to the UTC timezone by applying an offset
        let timestamp1 = convert_to_utc_timezone(timestamps[0]);
        let timestamp2 = convert_to_utc_timezone(timestamps[1]);

        assert_eq!(timestamp1, "2023-01-20 00:00:00.412745 UTC");
        assert_eq!(timestamp2, "2023-01-20 00:00:01.404277 UTC");

        let query = r#"
        {
            pcap(
                filter: {
                    source: "ingest src 1"
                    requestTime: "2023-01-20T00:00:00Z"
                }
            ) {
                parsedPcap
            }
        }"#;
        let res = schema.execute(query).await;

        // get response timestamps
        let res_json = res.data.into_json().unwrap();
        let parsed_pcap = res_json["pcap"]["parsedPcap"].as_str().unwrap();
        let timestamps: Vec<chrono::NaiveDateTime> = re
            .find_iter(parsed_pcap)
            .map(|m| m.as_str())
            .map(|s| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.6f").unwrap())
            .collect();

        // Change to the UTC timezone by applying an offset
        let timestamp1 = convert_to_utc_timezone(timestamps[0]);
        let timestamp2 = convert_to_utc_timezone(timestamps[1]);

        assert_eq!(timestamp1, "2023-01-20 00:00:00.412745 UTC");
        assert_eq!(timestamp2, "2023-01-20 00:00:02.328237 UTC");

        let query = r#"
        {
            pcap(
                filter: {
                    source: "src 1"
                    requestTime: "2023-01-20T00:00:01Z"
                }
            ) {
                parsedPcap
            }
        }"#;
        let res = schema.execute(query).await;

        // get response timestamps
        let res_json = res.data.into_json().unwrap();
        let parsed_pcap = res_json["pcap"]["parsedPcap"].as_str().unwrap();
        let timestamps: Vec<chrono::NaiveDateTime> = re
            .find_iter(parsed_pcap)
            .map(|m| m.as_str())
            .map(|s| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.6f").unwrap())
            .collect();

        // Change to the UTC timezone by applying an offset
        let timestamp1 = convert_to_utc_timezone(timestamps[0]);
        let timestamp2 = convert_to_utc_timezone(timestamps[1]);

        assert_eq!(timestamp1, "2023-01-20 00:00:00.412745 UTC");
        assert_eq!(timestamp2, "2023-01-20 00:00:02.328237 UTC");
    }

    fn insert_packet(
        store: &RawEventStore<pk>,
        source: &str,
        req_timestamp: i64,
        pk_timestamp: i64,
    ) {
        let mut key = Vec::with_capacity(
            source.len() + 1 + mem::size_of::<i64>() + 1 + mem::size_of::<i64>(),
        );
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(req_timestamp.to_be_bytes());
        key.push(0);
        key.extend(pk_timestamp.to_be_bytes());

        let packet_body = pk {
            packet_timestamp: pk_timestamp,
            packet: vec![0, 1, 2, 3],
        };
        let ser_packet_body = bincode::serialize(&packet_body).unwrap();

        store.append(&key, &ser_packet_body).unwrap();
    }

    fn convert_to_utc_timezone(timestamp: NaiveDateTime) -> String {
        let local_datetime = chrono::Local.from_local_datetime(&timestamp).unwrap();
        let utc_time = local_datetime.with_timezone(&chrono::Utc);
        utc_time.to_string()
    }
}

use super::{
    collect_records, get_key_prefix_packets, get_timestamp, load_connection,
    lower_closed_bound_key, upper_open_bound_key, write_run_tcpdump, Direction, FromKeyValue,
    RawEventFilter, TimeRange, TIMESTAMP_SIZE,
};
use crate::storage::Database;
use async_graphql::{
    connection::{query, Connection},
    Context, InputObject, Object, Result, SimpleObject,
};
use chrono::{DateTime, Utc};
use data_encoding::BASE64;
use giganto_client::ingest::Packet as pk;
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

impl RawEventFilter for PacketFilter {
    fn time(&self) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
        if let Some(time) = &self.packet_time {
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
        _text: Option<String>,
    ) -> Result<bool> {
        Ok(true)
    }
}

#[derive(SimpleObject, Debug)]
struct Packet {
    request_time: DateTime<Utc>,
    packet_time: DateTime<Utc>,
    packet: String,
}

#[derive(SimpleObject, Debug)]
struct Pcap {
    request_time: DateTime<Utc>,
    parsed_pcap: String,
}

impl FromKeyValue<pk> for Packet {
    fn from_key_value(key: &[u8], pk: pk) -> Result<Self> {
        Ok(Packet {
            request_time: get_timestamp(&key[..key.len() - (TIMESTAMP_SIZE + 1)])?,
            packet_time: get_timestamp(key)?,
            packet: BASE64.encode(&pk.packet),
        })
    }
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
        let db = ctx.data::<Database>()?;
        let store = db.packet_store()?;
        let key_prefix = get_key_prefix_packets(&filter.source, filter.request_time);

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_connection(&store, &key_prefix, &filter, after, before, first, last)
            },
        )
        .await
    }

    #[allow(clippy::unused_async)]
    async fn pcap<'ctx>(&self, ctx: &Context<'ctx>, filter: PacketFilter) -> Result<Pcap> {
        let db = ctx.data::<Database>()?;
        let store = db.packet_store()?;
        let key_prefix = get_key_prefix_packets(&filter.source, filter.request_time);

        let (start, end) = filter.time();

        let iter = store.boundary_iter(
            &lower_closed_bound_key(&key_prefix, start),
            &upper_open_bound_key(&key_prefix, end),
            Direction::Forward,
        );
        let (records, _) = collect_records(iter, 1000, &filter);

        let packet_vector = records.into_iter().map(|(_, packet)| packet).collect();

        let pcap = write_run_tcpdump(&packet_vector)?;

        Ok(Pcap {
            request_time: filter.request_time,
            parsed_pcap: pcap,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{graphql::TestSchema, storage::RawEventStore};
    use chrono::{TimeZone, Utc};
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

        let ts1 = dt1.timestamp_nanos();
        let ts2 = dt2.timestamp_nanos();
        let ts3 = dt3.timestamp_nanos();

        insert_packet(&store, "src 1", ts1, ts1);
        insert_packet(&store, "src 1", ts1, ts2);

        insert_packet(&store, "src 2", ts1, ts1);
        insert_packet(&store, "src 2", ts1, ts3);

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
                    source: "src 2"
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

        let dt1 = Utc.with_ymd_and_hms(2023, 1, 20, 0, 0, 0).unwrap();
        let dt2 = Utc.with_ymd_and_hms(2023, 1, 20, 0, 0, 1).unwrap();
        let dt3 = Utc.with_ymd_and_hms(2023, 1, 20, 0, 0, 2).unwrap();

        let ts1 = dt1.timestamp_nanos();
        let ts2 = dt2.timestamp_nanos();
        let ts3 = dt3.timestamp_nanos();

        insert_packet(&store, "src 1", ts1, ts1);
        insert_packet(&store, "src 1", ts1, ts2);

        insert_packet(&store, "src 2", ts1, ts1);
        insert_packet(&store, "src 2", ts1, ts3);

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
        #[cfg(target_os = "macos")]
        assert_eq!(
            res.data.to_string(),
            "{pcap: {parsedPcap: \"2023-01-20 00:00:00.412745 [|ether]\\n2023-01-20 00:00:01.404277 [|ether]\\n\"}}");

        #[cfg(target_os = "linux")]
        assert_eq!(
            res.data.to_string(),
            "{pcap: {parsedPcap: \"2023-01-20 00:00:00.412745  [|ether]\\n2023-01-20 00:00:01.404277  [|ether]\\n\"}}");

        let query = r#"
        {
            pcap(
                filter: {
                    source: "src 2"
                    requestTime: "2023-01-20T00:00:00Z"
                }
            ) {
                parsedPcap
            }
        }"#;
        let res = schema.execute(query).await;
        #[cfg(target_os = "macos")]
        assert_eq!(
            res.data.to_string(),
            "{pcap: {parsedPcap: \"2023-01-20 00:00:00.412745 [|ether]\\n2023-01-20 00:00:02.328237 [|ether]\\n\"}}");

        #[cfg(target_os = "linux")]
        assert_eq!(
            res.data.to_string(),
            "{pcap: {parsedPcap: \"2023-01-20 00:00:00.412745  [|ether]\\n2023-01-20 00:00:02.328237  [|ether]\\n\"}}");

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
        #[cfg(target_os = "macos")]
        assert_eq!(
            res.data.to_string(),
            "{pcap: {parsedPcap: \"2023-01-20 00:00:00.412745 [|ether]\\n2023-01-20 00:00:02.328237 [|ether]\\n\"}}");

        #[cfg(target_os = "linux")]
        assert_eq!(
            res.data.to_string(),
            "{pcap: {parsedPcap: \"2023-01-20 00:00:00.412745  [|ether]\\n2023-01-20 00:00:02.328237  [|ether]\\n\"}}");
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
}

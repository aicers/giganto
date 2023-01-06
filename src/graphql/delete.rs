use async_graphql::{Context, Object, Result};

use crate::storage::Database;

#[derive(Default)]
pub(super) struct DeleteQuery;

#[Object]
impl DeleteQuery {
    #[allow(clippy::unused_async)]
    async fn delete_all(&self, ctx: &Context<'_>, protocol: Option<Vec<String>>) -> Result<String> {
        let mut cfs = String::from("Delete all data");
        if let Some(names) = protocol.clone() {
            cfs = format!("Delete {names:?} data");
        }
        let db = ctx.data::<Database>()?;
        db.delete_all(protocol)?;

        Ok(cfs)
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;
    use crate::storage::RawEventStore;
    use chrono::{Duration, Utc};
    use giganto_client::ingest::network::Conn;
    use std::mem;
    use std::net::IpAddr;

    #[tokio::test]
    async fn delete_conn_data() {
        let schema = TestSchema::new();
        let store = schema.db.conn_store().unwrap();

        insert_conn_raw_event(&store, "src 1", Utc::now().timestamp_nanos());

        let query = r#"
        {
            deleteAll(
                protocol: ["conn"]
            )
        }"#;
        let res = schema.execute(query).await;

        assert_eq!(
            res.data.to_string(),
            "{deleteAll: \"Delete [\\\"conn\\\"] data\"}"
        );

        // check data
        let query = r#"
        {
            connRawEvents(
                filter: {
                    source: "src 1"
                }
                first: 1
            ) {
                edges {
                    node {
                        origAddr,
                        respAddr,
                        origPort,
                    }
                }
            }
        }"#;
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(), "{connRawEvents: {edges: []}}");
    }

    #[tokio::test]
    async fn delete_all_data() {
        let schema = TestSchema::new();
        let store = schema.db.conn_store().unwrap();

        insert_conn_raw_event(&store, "src 1", Utc::now().timestamp_nanos());

        let query = r#"
        {
            deleteAll
        }"#;
        let res = schema.execute(query).await;

        assert_eq!(res.data.to_string(), "{deleteAll: \"Delete all data\"}");

        // check data
        let query = r#"
                {
                    connRawEvents(
                        filter: {
                            source: "src 1"
                        }
                        first: 1
                    ) {
                        edges {
                            node {
                                origAddr,
                                respAddr,
                                origPort,
                            }
                        }
                    }
                }"#;
        let res = schema.execute(query).await;
        assert_eq!(res.data.to_string(), "{connRawEvents: {edges: []}}");
    }

    fn insert_conn_raw_event(store: &RawEventStore<Conn>, source: &str, timestamp: i64) {
        let mut key = Vec::with_capacity(source.len() + 1 + mem::size_of::<i64>());
        key.extend_from_slice(source.as_bytes());
        key.push(0);
        key.extend(timestamp.to_be_bytes());

        let tmp_dur = Duration::nanoseconds(12345);
        let conn_body = Conn {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            duration: tmp_dur.num_nanoseconds().unwrap(),
            service: "".to_string(),
            orig_bytes: 77,
            resp_bytes: 295,
            orig_pkts: 397,
            resp_pkts: 511,
        };
        let ser_conn_body = bincode::serialize(&conn_body).unwrap();

        store.append(&key, &ser_conn_body).unwrap();
    }
}

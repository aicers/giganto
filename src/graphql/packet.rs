use super::network::NetworkFilter;
use crate::ingestion::{request_packets, PACKET_SOURCES};
use async_graphql::{Object, Result};

#[derive(Default)]
pub(super) struct PacketQuery;

#[Object]
impl PacketQuery {
    async fn packets(&self, filter: NetworkFilter) -> Result<Vec<String>> {
        let source = &filter.source;
        let mut resp_data = Vec::new();
        if let Some(connection) = PACKET_SOURCES.lock().await.get(source) {
            for packet in request_packets(connection, filter).await? {
                resp_data.push(base64::encode(packet));
            }
        }
        Ok(resp_data)
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn packets_empty() {
        let schema = TestSchema::new();
        let query = r#"
        {
            packets(
                filter: {
                    time: { start: "1992-06-05T00:00:00Z", end: "2011-09-22T00:00:00Z" }
                    source: "a"
                    origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                    origPort: { start: 46377, end: 46380 }
                    respPort: { start: 100, end: 200 }
                }
            )
        }"#;
        let res = schema.execute(&query).await;
        assert_eq!(res.data.to_string(), "{packets: []}");
    }
}

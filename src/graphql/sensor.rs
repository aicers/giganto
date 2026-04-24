use std::collections::HashSet;

use async_graphql::{Context, Object, Result};

use crate::comm::{IngestSensors, peer::Peers};

#[derive(Default)]
pub(super) struct SensorQuery;

#[Object]
impl SensorQuery {
    /// Returns the list of registered sensor names, sorted in ascending order.
    async fn sensors(&self, ctx: &Context<'_>) -> Result<Vec<String>> {
        let mut total_sensor_list = HashSet::new();
        // Add current giganto's sensors
        let ingest_sensors = ctx.data_opt::<IngestSensors>();
        if let Some(ingest_sensors) = ingest_sensors {
            total_sensor_list.extend(ingest_sensors.read().await.clone());
        }
        // Add peer giganto's sensors
        let peers = ctx.data_opt::<Peers>();
        if let Some(peers) = peers {
            for peer in peers.read().await.values() {
                total_sensor_list.extend(peer.ingest_sensors.clone());
            }
        }

        let mut sensors: Vec<String> = total_sensor_list.into_iter().collect();
        sensors.sort_unstable();
        Ok(sensors)
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::tests::TestSchema;
    #[tokio::test]
    async fn sensors_test() {
        let schema = TestSchema::new();
        let query = r"
        {
            sensors
        }";
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{sensors: [\"ingest src 1\", \"src 1\", \"src1\"]}"
        );
    }

    #[tokio::test]
    async fn sensors_with_giganto_cluster() {
        const TEMP_PORT: u16 = 9999;
        let schema = TestSchema::new_with_graphql_peer(TEMP_PORT);
        let query = r"
        {
            sensors
        }";
        let res = schema.execute(query).await;
        assert_eq!(
            res.data.to_string(),
            "{sensors: [\"ingest src 1\", \"ingest src 2\", \"src 1\", \"src 2\", \"src1\", \"src2\"]}"
        );
    }

    #[cfg(feature = "bootroot")]
    #[tokio::test]
    async fn sensors_returns_service_fqdn_under_bootroot() {
        use std::collections::{HashMap, HashSet};
        use std::sync::Arc;

        use async_graphql::{EmptyMutation, EmptySubscription, Request, Schema};
        use tokio::sync::RwLock;

        use super::SensorQuery;
        use crate::comm::{
            IngestSensors,
            peer::{PeerInfo, Peers},
        };
        use crate::server::service_fqdn_from_cert;
        use crate::test_bootroot::{TestNode, bootroot_cluster_certs};

        let (_, local_fqdn) =
            service_fqdn_from_cert(&bootroot_cluster_certs(TestNode::Node1).certs)
                .expect("parse node1 cert");
        let (_, peer_fqdn) = service_fqdn_from_cert(&bootroot_cluster_certs(TestNode::Node2).certs)
            .expect("parse node2 cert");

        assert_eq!(local_fqdn, "giganto.node1.example.test");
        assert_eq!(peer_fqdn, "giganto.node2.example.test");

        let ingest_sensors: IngestSensors =
            Arc::new(RwLock::new(HashSet::from([local_fqdn.clone()])));
        let peers: Peers = Arc::new(RwLock::new(HashMap::from([(
            "127.0.0.1".to_string(),
            PeerInfo {
                ingest_sensors: HashSet::from([peer_fqdn.clone()]),
                graphql_port: Some(9000),
                publish_port: None,
            },
        )])));

        let schema = Schema::build(SensorQuery, EmptyMutation, EmptySubscription)
            .data(ingest_sensors)
            .data(peers)
            .finish();
        let res = schema.execute(Request::new("{ sensors }")).await;
        assert_eq!(
            res.data.to_string(),
            format!("{{sensors: [{local_fqdn:?}, {peer_fqdn:?}]}}")
        );
    }
}

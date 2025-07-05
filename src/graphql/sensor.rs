use std::collections::HashSet;

use async_graphql::{Context, Object, Result};

use crate::comm::{IngestSensors, peer::Peers};

#[derive(Default)]
pub(super) struct SensorQuery;

#[Object]
impl SensorQuery {
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
        sensors.sort();
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
}

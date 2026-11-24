//! The endpoint entry's share of the generation's sensor sets.
//!
//! An endpoint whose records are stored is a sensor, named by its endpoint
//! id, as a module is by its name: it joins `IngestSensors`, so peers learn
//! of it, and `RunTimeIngestSensors` while a connection of it is live, so
//! module ingest's periodic refresh keeps its `sensors` row current. The
//! `sensors` row itself is written with every batch that stores records.

use std::{collections::HashMap, sync::Arc};

use tokio::sync::{Mutex, Notify};
use tracing::error;

use crate::{
    comm::{IngestSensors, RunTimeIngestSensors},
    datetime::DateTime,
    storage::Database,
};

/// The generation's sensor sets, and how many live connections of each
/// endpoint added it to them.
pub(crate) struct EndpointSensors {
    database: Database,
    ingest_sensors: IngestSensors,
    runtime_ingest_sensors: RunTimeIngestSensors,
    /// Raised whenever a sensor is added to `ingest_sensors`, as module
    /// ingest raises it; present only when the generation has peers to tell.
    notify_sensor_change: Option<Arc<Notify>>,
    /// The live connections that added each endpoint, by its sensor name.
    /// Held across every set change it decides, so an add and the removal of
    /// the same endpoint's last connection never interleave.
    live: Mutex<HashMap<String, usize>>,
}

impl EndpointSensors {
    /// Creates the entry's share of the generation's sensor sets.
    pub(crate) fn new(
        database: Database,
        ingest_sensors: IngestSensors,
        runtime_ingest_sensors: RunTimeIngestSensors,
        notify_sensor_change: Option<Arc<Notify>>,
    ) -> Self {
        Self {
            database,
            ingest_sensors,
            runtime_ingest_sensors,
            notify_sensor_change,
            live: Mutex::new(HashMap::new()),
        }
    }

    /// Counts a connection of `sensor` that stored records, the last at
    /// `received`, and adds `sensor` to both sets.
    pub(super) async fn add(&self, sensor: &str, received: DateTime) {
        let mut live = self.live.lock().await;
        *live.entry(sensor.to_owned()).or_default() += 1;
        self.runtime_ingest_sensors
            .write()
            .await
            .insert(sensor.to_owned(), received);
        self.ingest_sensors.write().await.insert(sensor.to_owned());
        if let Some(notify) = &self.notify_sensor_change {
            notify.notify_one();
        }
    }

    /// Stops counting a connection [`add`](Self::add) counted. When it was
    /// the last of `sensor`, the sensor's `sensors` row is written with the
    /// current time and it leaves `RunTimeIngestSensors`, as module ingest
    /// does on a sensor's last disconnect; it stays in `IngestSensors`.
    pub(super) async fn remove(&self, sensor: &str) {
        let mut live = self.live.lock().await;
        let Some(count) = live.get_mut(sensor) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count > 0 {
            return;
        }
        live.remove(sensor);
        let mut runtime = self.runtime_ingest_sensors.write().await;
        // A missing entry may mean customer deletion; its row is not
        // written back.
        if runtime.contains_key(sensor) {
            let written = self
                .database
                .sensors_store()
                .and_then(|store| store.insert(sensor, DateTime::now()));
            if let Err(e) = written {
                error!("Endpoint {sensor}: its sensors row was not written: {e:#}");
            }
            runtime.remove(sensor);
        }
    }
}

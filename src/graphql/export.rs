use std::{borrow::Cow, fs::File, path::Path};

use crate::{
    ingestion::{Conn, DceRpc, Dns, Http, Kerberos, Log, Ntlm, PeriodicTimeSeries, Rdp, Smtp, Ssh},
    storage::{self, clear, Database, RAW_DATA_COLUMN_FAMILY_NAMES},
};
use anyhow::{anyhow, bail};
use async_graphql::{Context, Object, Result};
use chrono::{Local, NaiveDateTime};
use serde::de::DeserializeOwned;
use std::io::Write;
use tracing::error;

#[derive(Default)]
pub(super) struct ExportQuery;

#[Object]
impl ExportQuery {
    async fn statistics<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        stores: Vec<String>,
    ) -> Result<Vec<String>> {
        let db = ctx.data::<Database>()?;

        let mut statistics = Vec::new();
        for store in stores {
            statistics.push(format!("{}: {}", store, iter(db, &store)?.count()));
        }

        Ok(statistics)
    }

    async fn export<'ctx>(&self, ctx: &Context<'ctx>, stores: Vec<String>) -> Result<Vec<String>> {
        let db = ctx.data::<Database>()?;
        let mut exported = Vec::new();
        for store in stores {
            let rst = match store.as_str() {
                "conn" => export::<Conn>(db, &store)?,
                "dns" => export::<Dns>(db, &store)?,
                "http" => export::<Http>(db, &store)?,
                "log" => export::<Log>(db, &store)?,
                "rdp" => export::<Rdp>(db, &store)?,
                "smtp" => export::<Smtp>(db, &store)?,
                "periodic time series" => export::<PeriodicTimeSeries>(db, &store)?,
                "ntlm" => export::<Ntlm>(db, &store)?,
                "kerberos" => export::<Kerberos>(db, &store)?,
                "ssh" => export::<Ssh>(db, &store)?,
                "dce rpc" => export::<DceRpc>(db, &store)?,
                _ => format!("{}: Unknown store", store),
            };
            exported.push(rst);
        }
        Ok(exported)
    }

    async fn clear<'ctx>(&self, ctx: &Context<'ctx>) -> Result<Vec<String>> {
        let db = ctx.data::<Database>()?;
        clear(db)?;

        let mut statistics = Vec::new();
        for store in RAW_DATA_COLUMN_FAMILY_NAMES {
            statistics.push(format!("{}: {}", store, iter(db, store)?.count()));
        }
        Ok(statistics)
    }
}

fn iter<'db>(db: &'db Database, store: &str) -> anyhow::Result<storage::Iter<'db>> {
    let iter = match store {
        "conn" => db.conn_store()?.iterator(),
        "dns" => db.dns_store()?.iterator(),
        "http" => db.http_store()?.iterator(),
        "log" => db.log_store()?.iterator(),
        "rdp" => db.rdp_store()?.iterator(),
        "smtp" => db.smtp_store()?.iterator(),
        "periodic time series" => db.periodic_time_series_store()?.iterator(),
        "ntlm" => db.ntlm_store()?.iterator(),
        "kerberos" => db.kerberos_store()?.iterator(),
        "ssh" => db.ssh_store()?.iterator(),
        "dce rpc" => db.dce_rpc_store()?.iterator(),
        _ => return Err(anyhow!("unknown store")),
    };
    Ok(iter)
}

fn export<T: std::fmt::Display + DeserializeOwned>(
    db: &Database,
    store: &str,
) -> anyhow::Result<String> {
    let iter = iter(db, store)?;
    let mut exported = 0;
    let path = Path::new("/data/logs");
    if path.exists() {
        let filename = format!("{}_{}.dump", store, Local::now().format("%Y%m%d_%H%M%S"));
        let path = path.join(&filename.replace(' ', ""));
        let mut f = File::create(&path)?;
        for (k, v) in iter.flatten() {
            let value = bincode::deserialize::<T>(&v)?;
            if let Ok((source, timestamp)) = key(&k) {
                let _r = writeln!(f, "{}\t{}\t{}", timestamp, source, value);
                exported += 1;
            }
        }
    } else {
        bail!("Path /data/logs not found.");
    }
    Ok(format!("{}: {} events are exported", store, exported))
}

const A_BILLION: i64 = 1_000_000_000;
fn key(key: &[u8]) -> anyhow::Result<(Cow<str>, String)> {
    if let Some(pos) = key.iter().position(|x| *x == 0) {
        if let Some(s) = key.get(..pos) {
            let source = String::from_utf8_lossy(s);
            if let Some(t) = key.get(key.len() - 8..) {
                let tt: Option<[u8; 8]> = t.try_into().ok();
                if tt.is_none() {
                    error!("Error: invalid timestamp in key. t={:?}, {:?}", t, key);
                }
                let ts = tt.map(i64::from_be_bytes).unwrap_or_default();
                return Ok((source, timestamp(ts)));
            };
        }
    }
    Err(anyhow!("invalid key"))
}

fn timestamp(timestamp: i64) -> String {
    let nsecs = u32::try_from(timestamp % A_BILLION).unwrap_or_default();
    NaiveDateTime::from_timestamp_opt(timestamp / A_BILLION, nsecs)
        .map_or("-".to_string(), |s| s.format("%s%.6f").to_string())
}

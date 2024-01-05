use crate::storage::{Database, StorageKey};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use giganto_client::ingest::log::{OpLog, OpLogLevel};
use redis::AsyncCommands;
use std::{net::SocketAddr, num::NonZeroUsize, str::FromStr, sync::Arc, time::Duration};
use tokio::{select, sync::Notify, time};

const REDIS_LOG_FETCH_BULK_COUNT: Option<NonZeroUsize> = NonZeroUsize::new(100);

/// Fetch and store operation log from redis every `fetch_interval`.
pub async fn fetch_and_store_op_logs(
    db: Database,
    server_addr: SocketAddr,
    fetch_interval: Duration,
    notify_shutdown: Arc<Notify>,
) -> Result<()> {
    let mut itv = time::interval(fetch_interval);
    let store = db.op_log_store()?;

    loop {
        select! {
            _ = itv.tick() => {
                let logs = fetch_from_redis(server_addr).await?;
                for (agent, log) in logs {
                    let log: Vec<&str> = log.splitn(3, '\t').collect();
                    let Ok(log_level) = filter_by_log_level(log[1]) else {
                        continue;
                    };
                    let timestamp = DateTime::<Utc>::from_str(log[0])?
                        .timestamp_nanos_opt()
                        .unwrap_or_default();

                    let oplog = OpLog {
                        agent_name: agent.split('@').collect::<Vec<&str>>()[0].to_string(),
                        log_level,
                        contents: log[2].to_string(),
                    };
                    let storage_key = StorageKey::builder()
                        .start_key(&agent)
                        .end_key(timestamp)
                        .build();

                    store.append(&storage_key.key(), &bincode::serialize(&oplog)?)?;
                }
            }
            () = notify_shutdown.notified() => {
                return Ok(());
            },
        }
    }
}

async fn fetch_from_redis(server_addr: SocketAddr) -> Result<Vec<(String, String)>> {
    let client = redis::Client::open(format!("redis://{server_addr}"))?;
    let mut con = client.get_async_connection().await?;

    // get all keys from redis.
    let keys: Vec<String> = con.keys("*").await?;

    let mut data = Vec::new();
    for key in keys {
        loop {
            let values: Vec<String> = con.lpop(&key, REDIS_LOG_FETCH_BULK_COUNT).await?;
            if values.is_empty() {
                break;
            }
            for value in values {
                data.push((key.clone(), value));
            }
        }
    }

    Ok(data)
}

fn filter_by_log_level(level: &str) -> Result<OpLogLevel> {
    match level {
        "INFO" => Ok(OpLogLevel::Info),
        "WARN" => Ok(OpLogLevel::Warn),
        "ERROR" => Ok(OpLogLevel::Error),
        _ => Err(anyhow!("invalid log level")),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        redis::fetch_and_store_op_logs,
        storage::{Database, DbOptions},
    };
    use giganto_client::ingest::log::OpLog;
    use log_broker::{info, init_redis_connection, LogLocation};
    use std::{net::SocketAddr, sync::Arc, time::Duration};
    use tokio::{sync::Notify, time::sleep};

    #[tokio::test]
    #[ignore = "it requires connection to redis"]
    async fn test_fetch_and_store_op_logs() {
        const TEST_ID: &str = "test@localhost";
        const SERVER_ADDR: &str = "127.0.0.1:6379";

        // Open temporary database
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();

        let server_addr: SocketAddr = SERVER_ADDR.parse().unwrap();

        init_redis_connection(server_addr.ip(), server_addr.port(), TEST_ID.to_string())
            .await
            .unwrap();

        let fetch_interval = Duration::from_secs(1);
        let notify_shutdown = Arc::new(Notify::new());
        let notify_shutdown_2 = notify_shutdown.clone();

        // Notify shutdown after 5 seconds.
        tokio::spawn(async move {
            sleep(Duration::from_secs(5)).await;
            notify_shutdown_2.notify_one();
        });

        info!(LogLocation::Both, "Test log");

        let res =
            fetch_and_store_op_logs(db.clone(), server_addr, fetch_interval, notify_shutdown).await;

        assert!(res.is_ok());

        let store = db.op_log_store().unwrap();

        if let Some(Ok((_, value))) = store.iter_forward().next() {
            let value = bincode::deserialize::<OpLog>(&value).unwrap();

            assert_eq!(value.agent_name, "test".to_string());
            assert_eq!(value.contents, "Test log".to_string());
        } else {
            panic!("there must be an item in op_log_store");
        };
    }
}

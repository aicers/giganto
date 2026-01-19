use std::fs;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use anyhow::anyhow;
use chrono::{TimeZone, Utc};
use giganto_client::ingest::{log::OpLog, network::Conn};
use mockito::Server;
use tempfile::tempdir;

use super::{
    ExportFilter, export_file, export_oplog_file, export_statistic_file, to_string_or_empty,
};
use crate::comm::ingest::generation::SequenceGenerator;
use crate::graphql::TimeRange;
use crate::graphql::export::tests::fixture::{
    assert_export_error, assert_export_response, export_cases, export_filter_base,
    insert_bootp_raw_event, insert_conn_raw_event, insert_dce_rpc_raw_event, insert_dhcp_raw_event,
    insert_dns_raw_event, insert_ftp_raw_event, insert_http_raw_event, insert_kerberos_raw_event,
    insert_ldap_raw_event, insert_log_raw_event, insert_mqtt_raw_event, insert_nfs_raw_event,
    insert_ntlm_raw_event, insert_op_log_raw_event, insert_rdp_raw_event, insert_smb_raw_event,
    insert_smtp_raw_event, insert_ssh_raw_event, insert_statistics_raw_event, insert_time_series,
    insert_tls_raw_event, run_export_case, sensor_bounds, test_event_timestamp_nanos,
};
use crate::graphql::tests::TestSchema;
use crate::storage::{Database, DbOptions, Direction, KeyExtractor, TimestampKeyExtractor};

mod fixture;

#[test]
fn test_to_string_or_empty() {
    assert_eq!(to_string_or_empty(Some(42)), "42");
    assert_eq!(to_string_or_empty::<i32>(None), "-");
}

#[test]
fn export_filter_mid_key() {
    let mut filter = export_filter_base("process create");
    filter.agent_name = Some("agent-name".to_string());
    filter.agent_id = Some("agent-id".to_string());

    let mid_key = filter.get_mid_key().expect("mid_key should be set");
    assert_eq!(mid_key, b"agent-name\0agent-id".to_vec());
}

#[test]
fn export_filter_time_range_keys() {
    let mut filter = export_filter_base("conn");
    assert_eq!(filter.get_range_end_key(), (None, None));
    assert_eq!(filter.get_range_start_key(), (None, None));

    let start = Utc.with_ymd_and_hms(2024, 3, 4, 5, 6, 6).unwrap();
    let end = Utc.with_ymd_and_hms(2024, 3, 4, 5, 6, 8).unwrap();
    filter.time = Some(TimeRange {
        start: Some(start),
        end: Some(end),
    });

    assert_eq!(filter.get_range_end_key(), (Some(start), Some(end)));
    assert_eq!(filter.get_range_start_key(), (Some(start), Some(end)));
}

#[test]
fn export_file_succeeds_with_invalid_data() {
    let dir = tempdir().unwrap();
    let progress_path = dir.path().join("progress.dump");
    let done_path = dir.path().join("done.csv");
    let filter = export_filter_base("conn");
    let iter: Vec<anyhow::Result<(Box<[u8]>, Conn)>> =
        vec![Err(anyhow!("invalid1")), Err(anyhow!("invalid2"))];

    let result = export_file(iter.into_iter(), &filter, "csv", &done_path, &progress_path);

    assert!(result.is_ok());
    assert!(done_path.exists());
}

#[test]
fn export_oplog_file_succeeds_with_invalid_data() {
    let dir = tempdir().unwrap();
    let progress_path = dir.path().join("progress.dump");
    let done_path = dir.path().join("done.csv");
    let filter = export_filter_base("op_log");
    let iter: Vec<anyhow::Result<(Box<[u8]>, OpLog)>> =
        vec![Err(anyhow!("invalid1")), Err(anyhow!("invalid2"))];

    let result = export_oplog_file(iter.into_iter(), &filter, "csv", &done_path, &progress_path);

    assert!(result.is_ok());
    assert!(done_path.exists());
}

#[test]
fn export_statistic_file_orders_multiple_iterators() {
    let dir = tempdir().unwrap();
    let db = Database::open(dir.path(), &DbOptions::default()).unwrap();
    let store = db.statistics_store().unwrap();

    insert_statistics_raw_event(&store, 5, "sensor-a", 1, 1, 100, 1000);
    insert_statistics_raw_event(&store, 15, "sensor-a", 1, 1, 200, 2000);
    insert_statistics_raw_event(&store, 10, "sensor-b", 1, 1, 300, 3000);
    insert_statistics_raw_event(&store, 20, "sensor-b", 1, 1, 400, 4000);

    let filter = export_filter_base("statistics");
    let mut bounds = Vec::new();
    let mut iterators = Vec::new();
    for sensor in ["sensor-a", "sensor-b"] {
        bounds.push(sensor_bounds(sensor));
        let (from, to) = bounds.last().unwrap();
        iterators.push(store.boundary_iter(from, to, Direction::Forward).peekable());
    }

    let progress_path = dir.path().join("stats_progress.csv");
    let done_path = dir.path().join("stats_done.csv");
    let result = export_statistic_file(iterators, &filter, "csv", &done_path, &progress_path);

    assert!(result.is_ok());
    assert!(done_path.exists());

    let contents = fs::read_to_string(&done_path).unwrap();
    let extracted_times: Vec<&str> = contents
        .lines()
        .filter_map(|line| line.split('\t').next())
        .collect();
    let expected = vec!["0.000000005", "0.000000010", "0.000000015", "0.000000020"];

    assert_eq!(extracted_times, expected);
}

#[tokio::test]
async fn export_rejects_log_with_addr_filter() {
    let query = r#"
    {
        export(
            filter:{
                protocol: "log",
                sensorId: "src1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
            }
            ,exportType:"json")
    }"#;
    assert_export_error(query, "Invalid ip/port input").await;
}

#[tokio::test]
async fn export_rejects_kind_with_network_protocol() {
    let query = r#"
    {
        export(
            filter:{
                protocol: "conn",
                sensorId: "src1",
                kind: "log1"
            }
            ,exportType:"json")
    }"#;
    assert_export_error(query, "Invalid kind/agent_name/agent_id input").await;
}

#[tokio::test]
async fn export_rejects_invalid_format() {
    let query = r#"
    {
        export(
            filter:{
                protocol: "conn",
                sensorId: "src1",
            }
            ,exportType:"ppt")
    }"#;
    assert_export_error(query, "Invalid export file format").await;
}

#[tokio::test]
async fn export_rejects_unknown_protocol() {
    let query = r#"
     {
         export(
             filter:{
                 protocol: "invalid_proto",
                 sensorId: "src1",
             }
             ,exportType:"json")
     }"#;
    assert_export_error(query, "Unknown protocol").await;
}

#[tokio::test]
async fn export_rejects_agent_filter_for_non_sysmon() {
    let query = r#"
    {
        export(
            filter:{
                protocol: "conn",
                sensorId: "src1",
                agentName: "agent",
                agentId: "agent_id"
            }
            ,exportType:"json")
    }"#;
    assert_export_error(query, "Invalid kind/agent_name/agent_id input").await;
}

#[tokio::test]
async fn export_conn_giganto_cluster_with_address_filter() {
    let query = r#"
    {
        export(
            filter:{
                protocol: "conn",
                sensorId: "src 2",
                time: { start: "2024-03-04T05:06:06Z", end: "2024-03-04T05:06:08Z" },
                origAddr: { start: "192.0.2.1", end: "192.0.2.9" },
                respAddr: { start: "192.0.2.10", end: "192.0.2.19" },
                origPort: { start: 1000, end: 2000 },
                respPort: { start: 3000, end: 4000 }
            }
            ,exportType:"json")
    }"#;

    let mut peer_server = Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "export": "download-token-address"
        }
    }
    "#;

    let mock = peer_server
        .mock("POST", "/graphql")
        .with_status(200)
        .with_body(peer_response_mock_data)
        .create();

    let peer_port = peer_server
        .host_with_port()
        .parse::<SocketAddr>()
        .expect("Port must exist")
        .port();
    let schema = TestSchema::new_with_graphql_peer(peer_port);

    let res = schema.execute(query).await;
    assert_eq!(res.data.to_string(), "{export: \"download-token-address\"}");
    mock.assert_async().await;
}

#[tokio::test]
async fn export_sysmon_giganto_cluster_with_agent_filter() {
    let query = r#"
    {
        export(
            filter:{
                protocol: "process create",
                sensorId: "src 2",
                agentName: "agent-name",
                agentId: "agent-id",
                time: { start: "2024-03-04T05:06:06Z", end: "2024-03-04T05:06:08Z" }
            }
            ,exportType:"json")
    }"#;

    let mut peer_server = Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "export": "download-token-agent"
        }
    }
    "#;

    let mock = peer_server
        .mock("POST", "/graphql")
        .with_status(200)
        .with_body(peer_response_mock_data)
        .create();

    let peer_port = peer_server
        .host_with_port()
        .parse::<SocketAddr>()
        .expect("Port must exist")
        .port();
    let schema = TestSchema::new_with_graphql_peer(peer_port);

    let res = schema.execute(query).await;
    assert_eq!(res.data.to_string(), "{export: \"download-token-agent\"}");
    mock.assert_async().await;
}

#[tokio::test]
async fn export_log_giganto_cluster_with_kind_filter() {
    let query = r#"
    {
        export(
            filter:{
                protocol: "log",
                sensorId: "src 2",
                kind: "kind1",
                time: { start: "2024-03-04T05:06:06Z", end: "2024-03-04T05:06:08Z" }
            }
            ,exportType:"json")
    }"#;

    let mut peer_server = Server::new_async().await;
    let peer_response_mock_data = r#"
    {
        "data": {
            "export": "download-token-kind"
        }
    }
    "#;

    let mock = peer_server
        .mock("POST", "/graphql")
        .with_status(200)
        .with_body(peer_response_mock_data)
        .create();

    let peer_port = peer_server
        .host_with_port()
        .parse::<SocketAddr>()
        .expect("Port must exist")
        .port();
    let schema = TestSchema::new_with_graphql_peer(peer_port);

    let res = schema.execute(query).await;
    assert_eq!(res.data.to_string(), "{export: \"download-token-kind\"}");
    mock.assert_async().await;
}

#[tokio::test]
async fn export_conn() {
    let schema = TestSchema::new();
    let store = schema.db.conn_store().unwrap();

    insert_conn_raw_event(
        &store,
        "src1",
        test_event_timestamp_nanos(),
        chrono::DateTime::from_timestamp_nanos(12345)
            .timestamp_nanos_opt()
            .unwrap(),
    );
    insert_conn_raw_event(
        &store,
        "ingest src 1",
        test_event_timestamp_nanos(),
        chrono::DateTime::from_timestamp_nanos(12345)
            .timestamp_nanos_opt()
            .unwrap(),
    );

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "conn",
                sensorId: "src1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46378, end: 46379 }
                respPort: { start: 50, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "conn", "csv").await;

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "conn",
                sensorId: "ingest src 1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46378, end: 46379 }
                respPort: { start: 50, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "conn", "json").await;
}

#[tokio::test]
async fn export_timestamp_format_stability() {
    for case in export_cases() {
        run_export_case(case).await;
    }
}

#[tokio::test]
async fn export_dns() {
    let schema = TestSchema::new();
    let store = schema.db.dns_store().unwrap();

    insert_dns_raw_event(&store, "src1", test_event_timestamp_nanos());
    insert_dns_raw_event(&store, "ingest src 1", test_event_timestamp_nanos());

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "dns",
                sensorId: "src1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "31.3.245.100", end: "31.3.245.245" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "dns", "csv").await;

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "dns",
                sensorId: "ingest src 1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "31.3.245.100", end: "31.3.245.245" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "dns", "json").await;
}

#[tokio::test]
async fn export_http() {
    let schema = TestSchema::new();
    let store = schema.db.http_store().unwrap();

    insert_http_raw_event(&store, "src1", test_event_timestamp_nanos());
    insert_http_raw_event(&store, "ingest src 1", test_event_timestamp_nanos());

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "http",
                sensorId: "src1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "http", "csv").await;

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "http",
                sensorId: "ingest src 1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "http", "json").await;
}

#[tokio::test]
async fn export_rdp() {
    let schema = TestSchema::new();
    let store = schema.db.rdp_store().unwrap();

    insert_rdp_raw_event(&store, "src1", test_event_timestamp_nanos());
    insert_rdp_raw_event(&store, "ingest src 1", test_event_timestamp_nanos());

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "rdp",
                sensorId: "src1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "rdp", "csv").await;

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "rdp",
                sensorId: "ingest src 1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "rdp", "json").await;
}

#[tokio::test]
async fn export_smtp() {
    let schema = TestSchema::new();
    let store = schema.db.smtp_store().unwrap();

    insert_smtp_raw_event(&store, "src1", test_event_timestamp_nanos());
    insert_smtp_raw_event(&store, "ingest src 1", test_event_timestamp_nanos());

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "smtp",
                sensorId: "src1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "smtp", "csv").await;

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "smtp",
                sensorId: "ingest src 1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "smtp", "json").await;
}

#[tokio::test]
async fn export_ntlm() {
    let schema = TestSchema::new();
    let store = schema.db.ntlm_store().unwrap();

    insert_ntlm_raw_event(&store, "src1", test_event_timestamp_nanos());
    insert_ntlm_raw_event(&store, "ingest src 1", test_event_timestamp_nanos());

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "ntlm",
                sensorId: "src1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46378, end: 46379 }
                respPort: { start: 50, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "ntlm", "csv").await;

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "ntlm",
                sensorId: "ingest src 1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46378, end: 46379 }
                respPort: { start: 50, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "ntlm", "json").await;
}

#[tokio::test]
async fn export_kerberos() {
    let schema = TestSchema::new();
    let store = schema.db.kerberos_store().unwrap();

    insert_kerberos_raw_event(&store, "src1", test_event_timestamp_nanos());
    insert_kerberos_raw_event(&store, "ingest src 1", test_event_timestamp_nanos());

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "kerberos",
                sensorId: "src1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46378, end: 46379 }
                respPort: { start: 50, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "kerberos", "csv").await;

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "kerberos",
                sensorId: "ingest src 1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46378, end: 46379 }
                respPort: { start: 50, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "kerberos", "json").await;
}

#[tokio::test]
async fn export_ssh() {
    let schema = TestSchema::new();
    let store = schema.db.ssh_store().unwrap();

    insert_ssh_raw_event(&store, "src1", test_event_timestamp_nanos());
    insert_ssh_raw_event(&store, "ingest src 1", test_event_timestamp_nanos());

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "ssh",
                sensorId: "src1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "ssh", "csv").await;

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "ssh",
                sensorId: "ingest src 1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.72", end: "192.168.4.79" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "ssh", "json").await;
}

#[tokio::test]
async fn export_dce_rpc() {
    let schema = TestSchema::new();
    let store = schema.db.dce_rpc_store().unwrap();

    insert_dce_rpc_raw_event(&store, "src1", test_event_timestamp_nanos());
    insert_dce_rpc_raw_event(&store, "ingest src 1", test_event_timestamp_nanos());

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "dce rpc",
                sensorId: "src1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "dce rpc", "csv").await;

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "dce rpc",
                sensorId: "ingest src 1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "dce rpc", "json").await;
}

#[tokio::test]
async fn export_log() {
    let schema = TestSchema::new();
    let store = schema.db.log_store().unwrap();

    insert_log_raw_event(
        &store,
        "src1",
        test_event_timestamp_nanos(),
        "kind1",
        b"log1",
    );
    insert_log_raw_event(
        &store,
        "ingest src 1",
        test_event_timestamp_nanos(),
        "kind2",
        b"log2",
    );

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "log",
                sensorId: "src1",
                kind: "kind1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "log", "csv").await;

    // export json file
    let query = r#"
            {
                export(
                    filter:{
                        protocol: "log",
                        sensorId: "ingest src 1",
                        kind: "kind2",
                        time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                    }
                    ,exportType:"json")
            }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "log", "json").await;
}

#[tokio::test]
async fn export_time_series() {
    let schema = TestSchema::new();
    let store = schema.db.periodic_time_series_store().unwrap();

    insert_time_series(&store, "src1", test_event_timestamp_nanos(), vec![0.0; 12]);
    insert_time_series(
        &store,
        "ingest src 1",
        test_event_timestamp_nanos(),
        vec![0.0; 12],
    );

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "periodic time series",
                sensorId: "src1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "periodic time series", "csv").await;

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "periodic time series",
                sensorId: "ingest src 1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "periodic time series", "json").await;
}

#[tokio::test]
async fn export_op_log() {
    let schema = TestSchema::new();
    let store = schema.db.op_log_store().unwrap();
    let generator: OnceLock<Arc<SequenceGenerator>> = OnceLock::new();

    insert_op_log_raw_event(&store, "agent1", "src1", 1, &generator);
    insert_op_log_raw_event(&store, "agent2", "src1", 1, &generator);

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "op_log",
                sensorId: "src1",
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "op_log", "csv").await;

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "op_log",
                sensorId: "src1",
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "op_log", "json").await;
}

#[tokio::test]
async fn export_ftp() {
    let schema = TestSchema::new();
    let store = schema.db.ftp_store().unwrap();

    insert_ftp_raw_event(&store, "src1", test_event_timestamp_nanos());
    insert_ftp_raw_event(&store, "ingest src 1", test_event_timestamp_nanos());

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "ftp",
                sensorId: "src1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "ftp", "csv").await;

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "ftp",
                sensorId: "ingest src 1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "ftp", "json").await;
}

#[tokio::test]
async fn export_mqtt() {
    let schema = TestSchema::new();
    let store = schema.db.mqtt_store().unwrap();

    insert_mqtt_raw_event(&store, "src1", test_event_timestamp_nanos());
    insert_mqtt_raw_event(&store, "ingest src 1", test_event_timestamp_nanos());

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "mqtt",
                sensorId: "src1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "mqtt", "csv").await;

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "mqtt",
                sensorId: "ingest src 1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "mqtt", "json").await;
}

#[tokio::test]
async fn export_ldap() {
    let schema = TestSchema::new();
    let store = schema.db.ldap_store().unwrap();

    insert_ldap_raw_event(&store, "src1", test_event_timestamp_nanos());
    insert_ldap_raw_event(&store, "ingest src 1", test_event_timestamp_nanos());

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "ldap",
                sensorId: "src1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "ldap", "csv").await;

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "ldap",
                sensorId: "ingest src 1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "ldap", "json").await;
}

#[tokio::test]
async fn export_tls() {
    let schema = TestSchema::new();
    let store = schema.db.tls_store().unwrap();

    insert_tls_raw_event(&store, "src1", test_event_timestamp_nanos());
    insert_tls_raw_event(&store, "ingest src 1", test_event_timestamp_nanos());

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "tls",
                sensorId: "src1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "tls", "csv").await;

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "tls",
                sensorId: "ingest src 1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "tls", "json").await;
}

#[tokio::test]
async fn export_smb() {
    let schema = TestSchema::new();
    let store = schema.db.smb_store().unwrap();

    insert_smb_raw_event(&store, "src1", test_event_timestamp_nanos());
    insert_smb_raw_event(&store, "ingest src 1", test_event_timestamp_nanos());

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "smb",
                sensorId: "src1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "smb", "csv").await;

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "smb",
                sensorId: "ingest src 1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "smb", "json").await;
}

#[tokio::test]
async fn export_nfs() {
    let schema = TestSchema::new();
    let store = schema.db.nfs_store().unwrap();

    insert_nfs_raw_event(&store, "src1", test_event_timestamp_nanos());
    insert_nfs_raw_event(&store, "ingest src 1", test_event_timestamp_nanos());

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "nfs",
                sensorId: "src1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "nfs", "csv").await;

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "nfs",
                sensorId: "ingest src 1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "nfs", "json").await;
}

#[tokio::test]
async fn export_bootp() {
    let schema = TestSchema::new();
    let store = schema.db.bootp_store().unwrap();

    insert_bootp_raw_event(&store, "src1", test_event_timestamp_nanos());
    insert_bootp_raw_event(&store, "ingest src 1", test_event_timestamp_nanos());

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "bootp",
                sensorId: "src1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "bootp", "csv").await;

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "bootp",
                sensorId: "ingest src 1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "bootp", "json").await;
}

#[tokio::test]
async fn export_dhcp() {
    let schema = TestSchema::new();
    let store = schema.db.dhcp_store().unwrap();

    insert_dhcp_raw_event(&store, "src1", test_event_timestamp_nanos());
    insert_dhcp_raw_event(&store, "ingest src 1", test_event_timestamp_nanos());

    // export csv file
    let query = r#"
    {
        export(
            filter:{
                protocol: "dhcp",
                sensorId: "src1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"csv")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "dhcp", "csv").await;

    // export json file
    let query = r#"
    {
        export(
            filter:{
                protocol: "dhcp",
                sensorId: "ingest src 1",
                time: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" }
                origAddr: { start: "192.168.4.70", end: "192.168.4.78" }
                respAddr: { start: "192.168.4.75", end: "192.168.4.79" }
                origPort: { start: 46377, end: 46380 }
                respPort: { start: 0, end: 200 }
            }
            ,exportType:"json")
    }"#;
    let res = schema.execute(query).await;
    assert_export_response(&schema, &res, "dhcp", "json").await;
}

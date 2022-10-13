mod common;

use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::Serialize;
use std::net::IpAddr;

const PUBLISH_LOG_MESSAGE_CODE: u32 = 0x00;
const RECORD_TYPE_PERIOD_TIME_SERIES: u32 = 0x05;
const RECORD_TYPE_RDP: u32 = 0x04;
const RECORD_TYPE_HTTP: u32 = 0x03;
const RECORD_TYPE_LOG: u32 = 0x02;
const RECORD_TYPE_DNS: u32 = 0x01;
const RECORD_TYPE_CONN: u32 = 0x00;

const SERVER_URL: &str = "https://127.0.0.1:38370";
const PUBLISH_URL: &str = "https://127.0.0.1:38371";

#[derive(Serialize)]
struct DNSConn {
    orig_addr: IpAddr,
    resp_addr: IpAddr,
    orig_port: u16,
    resp_port: u16,
    proto: u8,
    query: String,
}

#[derive(Serialize)]
struct Conn {
    orig_addr: IpAddr,
    resp_addr: IpAddr,
    orig_port: u16,
    resp_port: u16,
    proto: u8,
    duration: i64,
    orig_bytes: u64,
    resp_bytes: u64,
    orig_pkts: u64,
    resp_pkts: u64,
}

#[derive(Serialize)]
struct HttpConn {
    orig_addr: IpAddr,
    resp_addr: IpAddr,
    orig_port: u16,
    resp_port: u16,
    method: String,
    host: String,
    uri: String,
    referrer: String,
    user_agent: String,
    status_code: u16,
}

#[derive(Serialize)]
struct RdpConn {
    orig_addr: IpAddr,
    resp_addr: IpAddr,
    orig_port: u16,
    resp_port: u16,
    cookie: String,
}

type Log = (String, Vec<u8>);

type PeriodicTimeSeries = (String, i64, i64, Vec<f64>);

#[derive(Serialize)]
struct Message {
    source: String,
    kind: String,
    start: i64,
    end: i64,
    count: usize,
}

#[tokio::test]
#[cfg(not(tarpaulin))]
async fn send_conn_info() {
    let comm_info = common::setup(SERVER_URL).await;
    let (mut send_conn, _) = comm_info
        .conn
        .open_bi()
        .await
        .expect("failed to open stream");

    let mut conn_data: Vec<u8> = Vec::new();
    let tmp_dur = Duration::nanoseconds(12345);
    let conn_body = Conn {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
        proto: 6,
        duration: tmp_dur.num_nanoseconds().unwrap(),
        orig_bytes: 77,
        resp_bytes: 295,
        orig_pkts: 397,
        resp_pkts: 511,
    };
    let mut ser_conn_body = bincode::serialize(&conn_body).unwrap();

    conn_data.append(&mut RECORD_TYPE_CONN.to_le_bytes().to_vec());
    conn_data.append(&mut Utc::now().timestamp_nanos().to_le_bytes().to_vec());
    conn_data.append(&mut (ser_conn_body.len() as u32).to_le_bytes().to_vec());
    conn_data.append(&mut ser_conn_body);

    send_conn
        .write_all(&conn_data)
        .await
        .expect("failed to send request");

    send_conn.finish().await.expect("failed to shutdown stream");

    comm_info.conn.close(0u32.into(), b"conn_done");
    comm_info.endpoint.wait_idle().await;
}

#[tokio::test]
#[cfg(not(tarpaulin))]
async fn send_dns_info() {
    let comm_info = common::setup(SERVER_URL).await;
    let (mut send_dns, _) = comm_info
        .conn
        .open_bi()
        .await
        .expect("failed to open stream");

    let mut dns_data: Vec<u8> = Vec::new();
    let dns_body = DNSConn {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
        proto: 17,
        query:
            "Hello ServerHello ServerHello ServerHello ServerHello ServerHello ServerHello Server"
                .to_string(),
    };
    let mut ser_dns_body = bincode::serialize(&dns_body).unwrap();

    dns_data.append(&mut RECORD_TYPE_DNS.to_le_bytes().to_vec());
    dns_data.append(&mut Utc::now().timestamp_nanos().to_le_bytes().to_vec());
    dns_data.append(&mut (ser_dns_body.len() as u32).to_le_bytes().to_vec());
    dns_data.append(&mut ser_dns_body);

    send_dns
        .write_all(&dns_data)
        .await
        .expect("failed to send request");

    send_dns.finish().await.expect("failed to shutdown stream");

    comm_info.conn.close(0u32.into(), b"dns_done");
    comm_info.endpoint.wait_idle().await;
}

#[tokio::test]
#[cfg(not(tarpaulin))]
async fn send_log_info() {
    let comm_info = common::setup(SERVER_URL).await;
    let (mut send_log, _) = comm_info
        .conn
        .open_bi()
        .await
        .expect("failed to open stream");

    let mut log_data: Vec<u8> = Vec::new();
    let log_body: Log = (
        String::from("Hello"),
        base64::decode("aGVsbG8gd29ybGQ=").unwrap(),
    );
    let mut ser_log_body = bincode::serialize(&log_body).unwrap();

    log_data.append(&mut RECORD_TYPE_LOG.to_le_bytes().to_vec());
    log_data.append(&mut Utc::now().timestamp_nanos().to_le_bytes().to_vec());
    log_data.append(&mut (ser_log_body.len() as u32).to_le_bytes().to_vec());
    log_data.append(&mut ser_log_body);

    send_log
        .write_all(&log_data)
        .await
        .expect("failed to send request");
    send_log.finish().await.expect("failed to shutdown stream");

    comm_info.conn.close(0u32.into(), b"log_done");
    comm_info.endpoint.wait_idle().await;
}

#[tokio::test]
#[cfg(not(tarpaulin))]
async fn send_http_info() {
    let comm_info = common::setup(SERVER_URL).await;
    let (mut send_http, _) = comm_info
        .conn
        .open_bi()
        .await
        .expect("failed to open stream");

    let mut http_data: Vec<u8> = Vec::new();
    let http_body = HttpConn {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
        method: "POST".to_string(),
        host: "einsis".to_string(),
        uri: "/einsis.gif".to_string(),
        referrer: "einsis.com".to_string(),
        user_agent: "giganto".to_string(),
        status_code: 200,
    };
    let mut ser_http_body = bincode::serialize(&http_body).unwrap();

    http_data.append(&mut RECORD_TYPE_HTTP.to_le_bytes().to_vec());
    http_data.append(&mut Utc::now().timestamp_nanos().to_le_bytes().to_vec());
    http_data.append(&mut (ser_http_body.len() as u32).to_le_bytes().to_vec());
    http_data.append(&mut ser_http_body);

    send_http
        .write_all(&http_data)
        .await
        .expect("failed to send request");

    send_http.finish().await.expect("failed to shutdown stream");

    comm_info.conn.close(0u32.into(), b"http_done");
    comm_info.endpoint.wait_idle().await;
}

#[tokio::test]
#[cfg(not(tarpaulin))]
async fn send_rdp_info() {
    let comm_info = common::setup(SERVER_URL).await;
    let (mut send_rdp, _) = comm_info
        .conn
        .open_bi()
        .await
        .expect("failed to open stream");

    let mut rdp_data: Vec<u8> = Vec::new();
    let rdp_body = RdpConn {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_port: 80,
        cookie: "rdp_test".to_string(),
    };
    let mut ser_rdp_body = bincode::serialize(&rdp_body).unwrap();

    rdp_data.append(&mut RECORD_TYPE_RDP.to_le_bytes().to_vec());
    rdp_data.append(&mut Utc::now().timestamp_nanos().to_le_bytes().to_vec());
    rdp_data.append(&mut (ser_rdp_body.len() as u32).to_le_bytes().to_vec());
    rdp_data.append(&mut ser_rdp_body);

    send_rdp
        .write_all(&rdp_data)
        .await
        .expect("failed to send request");
    send_rdp.finish().await.expect("failed to shutdown stream");

    comm_info.conn.close(0u32.into(), b"log_done");
    comm_info.endpoint.wait_idle().await;
}

#[tokio::test]
#[cfg(not(tarpaulin))]
async fn send_periodic_time_series_info() {
    let comm_info = common::setup(SERVER_URL).await;
    let (mut send_periodic_time_series, _) = comm_info
        .conn
        .open_bi()
        .await
        .expect("failed to open stream");

    let mut periodic_time_series_data: Vec<u8> = Vec::new();
    let periodic_time_series_body: PeriodicTimeSeries = (
        String::from("Hello"),
        Utc::now().timestamp_nanos(),
        10,
        Vec::new(),
    );
    let mut ser_periodic_time_series_body = bincode::serialize(&periodic_time_series_body).unwrap();

    periodic_time_series_data.append(&mut RECORD_TYPE_PERIOD_TIME_SERIES.to_le_bytes().to_vec());
    periodic_time_series_data.append(&mut Utc::now().timestamp_nanos().to_le_bytes().to_vec());
    periodic_time_series_data.append(
        &mut (ser_periodic_time_series_body.len() as u32)
            .to_le_bytes()
            .to_vec(),
    );
    periodic_time_series_data.append(&mut ser_periodic_time_series_body);

    send_periodic_time_series
        .write_all(&periodic_time_series_data)
        .await
        .expect("failed to send request");
    send_periodic_time_series
        .finish()
        .await
        .expect("failed to shutdown stream");

    comm_info
        .conn
        .close(0u32.into(), b"periodic_time_series_done");
    comm_info.endpoint.wait_idle().await;
}

#[tokio::test]
#[cfg(not(tarpaulin))]
async fn request_publish_log() {
    let publish = common::setup(PUBLISH_URL).await;
    let (mut send_pub_reg, mut recv_pub_resp) =
        publish.conn.open_bi().await.expect("failed to open stream");

    let start = DateTime::<Utc>::from_utc(NaiveDate::from_ymd(1970, 1, 1).and_hms(00, 00, 00), Utc);
    let end = DateTime::<Utc>::from_utc(NaiveDate::from_ymd(2050, 12, 31).and_hms(23, 59, 59), Utc);
    let mesaage = Message {
        source: String::from("einsis"),
        kind: String::from("Hello"),
        start: start.timestamp_nanos(),
        end: end.timestamp_nanos(),
        count: 5,
    };
    let mut mesaage_buf = bincode::serialize(&mesaage).unwrap();

    let mut request_buf: Vec<u8> = Vec::new();
    request_buf.append(&mut PUBLISH_LOG_MESSAGE_CODE.to_le_bytes().to_vec());
    request_buf.append(&mut (mesaage_buf.len() as u32).to_le_bytes().to_vec());
    request_buf.append(&mut mesaage_buf);

    send_pub_reg
        .write_all(&request_buf)
        .await
        .expect("failed to send request");

    loop {
        let mut len_buf = [0; std::mem::size_of::<u32>()];
        recv_pub_resp.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_le_bytes(len_buf);

        let mut resp_data = vec![0; len.try_into().unwrap()];
        recv_pub_resp.read_exact(&mut resp_data).await.unwrap();
        let resp = bincode::deserialize::<Option<(i64, Vec<u8>)>>(&resp_data).unwrap();
        if resp.is_none() {
            break;
        }
    }

    publish.conn.close(0u32.into(), b"publish_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
#[cfg(not(tarpaulin))]
async fn ack_info() {
    let comm_info = common::setup(SERVER_URL).await;
    let (mut send_log, mut recv_log) = comm_info
        .conn
        .open_bi()
        .await
        .expect("failed to open stream");

    let mut log_data: Vec<u8> = Vec::new();
    let log_body: Log = (String::from("Hello Server I am Log"), vec![0; 10]);
    let mut ser_log_body = bincode::serialize(&log_body).unwrap();

    log_data.append(&mut RECORD_TYPE_LOG.to_le_bytes().to_vec());
    log_data.append(&mut Utc::now().timestamp_nanos().to_le_bytes().to_vec());
    log_data.append(&mut (ser_log_body.len() as u32).to_le_bytes().to_vec());
    log_data.append(&mut ser_log_body);

    send_log
        .write_all(&log_data)
        .await
        .expect("failed to send request");

    let mut last_timestamp: i64 = 0;
    for _ in 0..127 {
        let mut log_data: Vec<u8> = Vec::new();
        let log_body: Log = (String::from("Hello Server I am Log"), vec![0; 10]);
        let mut ser_log_body = bincode::serialize(&log_body).unwrap();
        last_timestamp = Utc::now().timestamp_nanos();

        log_data.append(&mut last_timestamp.to_le_bytes().to_vec());
        log_data.append(&mut (ser_log_body.len() as u32).to_le_bytes().to_vec());
        log_data.append(&mut ser_log_body);

        send_log
            .write_all(&log_data)
            .await
            .expect("failed to send request");
    }

    let mut ts_buf = [0; std::mem::size_of::<u64>()];
    recv_log.read_exact(&mut ts_buf).await.unwrap();
    let recv_timestamp = i64::from_be_bytes(ts_buf);

    send_log.finish().await.expect("failed to shutdown stream");
    comm_info.conn.close(0u32.into(), b"log_done");
    comm_info.endpoint.wait_idle().await;
    assert_eq!(last_timestamp, recv_timestamp);
}

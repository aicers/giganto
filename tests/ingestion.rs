mod common;

use chrono::{Duration, Utc};
use serde::Serialize;
use std::net::IpAddr;

const RECORD_TYPE_LOG: u32 = 0x02;
const RECORD_TYPE_DNS: u32 = 0x01;
const RECORD_TYPE_TCPUDP: u32 = 0x00;

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

type Log = (String, Vec<u8>);

#[tokio::test]
async fn run() {
    let comm_info = common::setup().await;
    let (mut send_tcp_udp, _) = comm_info
        .conn
        .open_bi()
        .await
        .expect("failed to open stream");

    let (mut send_dns, _) = comm_info
        .conn
        .open_bi()
        .await
        .expect("failed to open stream");

    let (mut send_log, _) = comm_info
        .conn
        .open_bi()
        .await
        .expect("failed to open stream");

    let mut tcpudp_data: Vec<u8> = Vec::new();
    let mut dns_data: Vec<u8> = Vec::new();
    let mut log_data: Vec<u8> = Vec::new();

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

    tcpudp_data.append(&mut RECORD_TYPE_TCPUDP.to_le_bytes().to_vec());
    tcpudp_data.append(&mut Utc::now().timestamp_nanos().to_le_bytes().to_vec());
    tcpudp_data.append(&mut (ser_conn_body.len() as u32).to_le_bytes().to_vec());
    tcpudp_data.append(&mut ser_conn_body);

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

    let dns_handle = tokio::spawn(async move {
        send_dns
            .write_all(&dns_data)
            .await
            .expect("failed to send request");
        send_dns.finish().await.expect("failed to shutdown stream");
    });

    let log_body: Log = (String::from("Hello Server I am Log"), vec![0; 10]);
    let mut ser_log_body = bincode::serialize(&log_body).unwrap();

    log_data.append(&mut RECORD_TYPE_LOG.to_le_bytes().to_vec());
    log_data.append(&mut Utc::now().timestamp_nanos().to_le_bytes().to_vec());
    log_data.append(&mut (ser_log_body.len() as u32).to_le_bytes().to_vec());
    log_data.append(&mut ser_log_body);

    let log_handle = tokio::spawn(async move {
        send_log
            .write_all(&log_data)
            .await
            .expect("failed to send request");
        send_log.finish().await.expect("failed to shutdown stream");
    });
    send_tcp_udp
        .write_all(&tcpudp_data)
        .await
        .expect("failed to send request");
    send_tcp_udp
        .finish()
        .await
        .expect("failed to shutdown stream");

    dns_handle.await.expect("failed to send dns");
    log_handle.await.expect("failed to send log");

    comm_info.conn.close(0u32.into(), b"done");
    comm_info.endpoint.wait_idle().await;
}

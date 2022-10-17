mod common;

use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;

const PUBLISH_LOG_MESSAGE_CODE: u32 = 0x00;
const PUBLISH_PERIOD_TIME_SERIES_MESSAGE_CODE: u32 = 0x01;
const RECORD_TYPE_LOG: u32 = 0x02;

const SERVER_URL: &str = "https://127.0.0.1:38370";
const PUBLISH_URL: &str = "https://127.0.0.1:38371";

type Log = (String, Vec<u8>);

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
    publish.conn.close(0u32.into(), b"publish_log_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
#[cfg(not(tarpaulin))]
async fn request_publish_period_time_series() {
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
    request_buf.append(
        &mut PUBLISH_PERIOD_TIME_SERIES_MESSAGE_CODE
            .to_le_bytes()
            .to_vec(),
    );
    request_buf.append(&mut (mesaage_buf.len() as u32).to_le_bytes().to_vec());
    request_buf.append(&mut mesaage_buf);

    send_pub_reg
        .write_all(&request_buf)
        .await
        .expect("failed to send request");
    println!("send test:{:?}", send_pub_reg);

    loop {
        let mut len_buf = [0; std::mem::size_of::<u32>()];
        recv_pub_resp.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_le_bytes(len_buf);

        let mut resp_data = vec![0; len.try_into().unwrap()];
        recv_pub_resp.read_exact(&mut resp_data).await.unwrap();
        let resp = bincode::deserialize::<Option<(i64, Vec<f64>)>>(&resp_data).unwrap();
        if resp.is_none() {
            break;
        }
    }

    publish.conn.close(0u32.into(), b"publish_time_done");
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

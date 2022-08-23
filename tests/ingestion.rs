mod common;

use chrono::Utc;

const RECORD_TYPE: u32 = 0x11223344;
const RECORD: u32 = 0x55667788;

#[tokio::test]
async fn run() {
    let comm_info = common::setup().await;
    let (mut send, _) = comm_info
        .conn
        .open_bi()
        .await
        .expect("failed to open stream");

    let timestamp: i64 = Utc::now().timestamp_nanos();
    let mut send_data: Vec<u8> = Vec::new();
    send_data.append(&mut RECORD_TYPE.to_le_bytes().to_vec());
    send_data.append(&mut timestamp.to_le_bytes().to_vec());
    send_data.append(&mut RECORD.to_le_bytes().to_vec());

    send.write_all(&send_data)
        .await
        .expect("failed to send request");
    send.finish().await.expect("failed to shutdown stream");

    comm_info.conn.close(0u32.into(), b"done");
    comm_info.endpoint.wait_idle().await;
}

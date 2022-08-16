mod common;

const MESSAGE_TEST: &str = "Hello Server";

#[tokio::test]
async fn run() {
    let comm_info = common::setup().await;
    let (mut send, _) = comm_info
        .conn
        .open_bi()
        .await
        .expect("failed to open stream");

    send.write_all(MESSAGE_TEST.as_bytes())
        .await
        .expect("failed to send request");
    send.finish().await.expect("failed to shutdown stream");

    comm_info.conn.close(0u32.into(), b"done");
    comm_info.endpoint.wait_idle().await;
}

//! Shared test code

use lazy_static::lazy_static;
use quinn::{Connection, RecvStream, SendStream};
use tokio::sync::Mutex;

pub(crate) struct Channel {
    pub(crate) server: Endpoint,
    pub(crate) client: Endpoint,
}

pub(crate) struct Endpoint {
    pub(crate) conn: Connection,
    pub(crate) send: SendStream,
    pub(crate) recv: RecvStream,
}

lazy_static! {
    pub(crate) static ref TOKEN: Mutex<u32> = Mutex::new(0);
}

/// Creates a bidirectional channel, returning server's send and receive and
/// client's send and receive streams.
pub(crate) async fn channel() -> Channel {
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};

    const TEST_SERVER_NAME: &str = "test-server";
    const TEST_PORT: u16 = 60190;

    let cert =
        rcgen::generate_simple_self_signed([TEST_SERVER_NAME.to_string()]).expect("infallible");
    let cert_chain = vec![rustls::Certificate(
        cert.serialize_der().expect("infallible"),
    )];
    let key_der = rustls::PrivateKey(cert.serialize_private_key_der());
    let server_config =
        quinn::ServerConfig::with_single_cert(cert_chain, key_der).expect("infallible");
    let server_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), TEST_PORT);

    let server_endpoint = {
        loop {
            break match quinn::Endpoint::server(server_config.clone(), server_addr) {
                Ok(e) => e,
                Err(e) => {
                    if e.kind() == tokio::io::ErrorKind::AddrInUse {
                        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                        continue;
                    } else {
                        panic!("{}", e);
                    }
                }
            };
        }
    };

    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.add_parsable_certificates(&[cert.serialize_der().expect("infallible")]);
    let client_endpoint =
        quinn::Endpoint::client(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)).unwrap();
    let client_config = quinn::ClientConfig::with_root_certificates(root_cert_store);
    let client_connecting = client_endpoint
        .connect_with(client_config, server_addr, TEST_SERVER_NAME)
        .unwrap();

    let client_connection = client_connecting.await.unwrap();

    let (mut client_send, client_recv) = client_connection.open_bi().await.unwrap();
    client_send.write_all(b"ready").await.unwrap();

    let server_connection = match server_endpoint.accept().await {
        Some(conn) => match conn.await {
            Ok(conn) => conn,
            Err(e) => panic!("{}", e.to_string()),
        },
        None => panic!("connection closed"),
    };
    let (server_send, mut server_recv) = server_connection.accept_bi().await.unwrap();
    let mut server_buf = [0; 5];
    server_recv.read_exact(&mut server_buf).await.unwrap();

    Channel {
        server: self::Endpoint {
            conn: server_connection,
            send: server_send,
            recv: server_recv,
        },
        client: self::Endpoint {
            conn: client_connection,
            send: client_send,
            recv: client_recv,
        },
    }
}

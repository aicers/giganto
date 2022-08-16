use quinn::{Connection, Endpoint};
use std::{
    fs,
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};
use url::Url;

const CERT: &str = "tests/cert.der";
const HOST: &str = "localhost";
const SERVER_URL: &str = "https://127.0.0.1:38400";

pub struct CommInfo {
    pub conn: Connection,
    pub endpoint: Endpoint,
}

fn init_server() -> SocketAddr {
    let url = Url::parse(SERVER_URL).expect("Failed to parse server url");
    let remote = (
        url.host_str().expect("Failed to get host"),
        url.port().expect("Failed to get port"),
    )
        .to_socket_addrs()
        .expect("Failed to convert address")
        .next()
        .expect("couldn't resolve to an address");
    remote
}

fn init_client() -> Endpoint {
    let mut roots = rustls::RootCertStore::empty();
    let file = fs::read(CERT).expect("Failed to read file");
    roots
        .add(&rustls::Certificate(file))
        .expect("Failed to add cert");

    let client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let mut endpoint =
        quinn::Endpoint::client("[::]:0".parse().expect("Failed to parse Endpoint addr"))
            .expect("Failed to create endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));
    endpoint
}

pub async fn setup() -> CommInfo {
    let remote = init_server();
    let endpoint = init_client();

    let new_conn = endpoint
        .connect(remote, HOST)
        .expect("Failed to connect server's endpoint, Please check if the setting value is correct")
        .await
        .expect("Failed to connect server's endpoint, Please make sure the Server is alive");
    let quinn::NewConnection {
        connection: conn, ..
    } = new_conn;
    CommInfo { conn, endpoint }
}

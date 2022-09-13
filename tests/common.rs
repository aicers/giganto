use quinn::{Connection, Endpoint};
use std::path::Path;
use std::{
    fs,
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};
use url::Url;

const CERT: &str = "tests/cert.pem";
const HOST: &str = "localhost";
const KEY: &str = "tests/key.pem";
const ROOT: &str = "tests/root.pem";
const SERVER_URL: &str = "https://127.0.0.1:38370";

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
    let (cert, key) = match fs::read(CERT)
        .and_then(|x| Ok((x, fs::read(KEY).expect("Failed to Read key file"))))
    {
        Ok(x) => x,
        Err(_) => {
            panic!(
                "failed to read (cert, key) file, {}, {} read file error. Cert or key doesn't exist in default test folder",
                CERT,
                KEY
            );
        }
    };

    let pv_key = if Path::new(KEY).extension().map_or(false, |x| x == "der") {
        rustls::PrivateKey(key)
    } else {
        let pkcs8 =
            rustls_pemfile::pkcs8_private_keys(&mut &*key).expect("malformed PKCS #8 private key");
        match pkcs8.into_iter().next() {
            Some(x) => rustls::PrivateKey(x),
            None => {
                let rsa = rustls_pemfile::rsa_private_keys(&mut &*key)
                    .expect("malformed PKCS #1 private key");
                match rsa.into_iter().next() {
                    Some(x) => rustls::PrivateKey(x),
                    None => {
                        panic!(
                            "no private keys found. Private key doesn't exist in default test folder"
                        );
                    }
                }
            }
        }
    };
    let cert_chain = if Path::new(CERT).extension().map_or(false, |x| x == "der") {
        vec![rustls::Certificate(cert)]
    } else {
        rustls_pemfile::certs(&mut &*cert)
            .expect("invalid PEM-encoded certificate")
            .into_iter()
            .map(rustls::Certificate)
            .collect()
    };

    let mut server_root = rustls::RootCertStore::empty();
    let file = fs::read(ROOT).expect("Failed to read file");
    let root_cert: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut &*file)
        .expect("invalid PEM-encoded certificate")
        .into_iter()
        .map(rustls::Certificate)
        .collect();

    if let Some(cert) = root_cert.get(0) {
        server_root.add(cert).expect("Failed to add cert");
    }

    let client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(server_root)
        .with_single_cert(cert_chain, pv_key)
        .expect("the server root, cert chain or private key are not valid");

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

use std::{
    collections::{HashMap, HashSet},
    fs,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::{Arc, OnceLock},
};

use base64::{Engine, engine::general_purpose::STANDARD as base64_engine};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use giganto_client::{
    connection::client_handshake,
    ingest::{
        log::Log,
        network::{
            Bootp, Conn, DceRpc, Dhcp, Dns, Ftp, Http, Kerberos, Ldap, Mqtt, Nfs, Ntlm, Rdp, Smb,
            Smtp, Ssh, Tls,
        },
        timeseries::PeriodicTimeSeries,
    },
    publish::{
        range::{MessageCode, RequestRange, RequestRawData, ResponseRangeData},
        receive_range_data, receive_semi_supervised_data,
        receive_semi_supervised_stream_start_message, receive_time_series_generator_data,
        receive_time_series_generator_stream_start_message, send_range_data_request,
        send_stream_request,
        stream::{
            NodeType, RequestSemiSupervisedStream, RequestStreamRecord,
            RequestTimeSeriesGeneratorStream,
        },
    },
};
use quinn::{Connection, Endpoint, SendStream};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serial_test::serial;
use tokio::sync::{Mutex, Notify, RwLock};

use super::Server;
use crate::{
    new_pcap_sensors, new_peers_data, new_stream_direct_channels,
    peer::{PeerIdentity, PeerInfo},
    server::Certs,
    storage::{Database, DbOptions, RawEventStore},
    to_cert_chain, to_private_key, to_root_cert,
};

fn get_token() -> &'static Mutex<u32> {
    static TOKEN: OnceLock<Mutex<u32>> = OnceLock::new();

    TOKEN.get_or_init(|| Mutex::new(0))
}

const CA_CERT_PATH: &str = "tests/certs/ca_cert.pem";
const PROTOCOL_VERSION: &str = "0.23.0";

const NODE1_CERT_PATH: &str = "tests/certs/node1/cert.pem";
const NODE1_KEY_PATH: &str = "tests/certs/node1/key.pem";
const NODE1_HOST: &str = "node1";
const NODE1_TEST_PORT: u16 = 60191;

const NODE2_CERT_PATH: &str = "tests/certs/node2/cert.pem";
const NODE2_KEY_PATH: &str = "tests/certs/node2/key.pem";
const NODE2_HOST: &str = "node2";
const NODE2_PORT: u16 = 60192;

const NODE1_GIGANTO_INGEST_SENSORS: [&str; 3] = ["src1", "src 1", "ingest src 1"];
const NODE2_GIGANTO_INGEST_SENSORS: [&str; 3] = ["src2", "src 2", "ingest src 2"];

struct TestClient {
    send: SendStream,
    conn: Connection,
    endpoint: Endpoint,
}

impl TestClient {
    async fn new() -> Self {
        let endpoint = init_client();
        let conn = endpoint
            .connect(
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), NODE1_TEST_PORT),
                NODE1_HOST,
            )
            .expect(
                "Failed to connect server's endpoint, Please check if the setting value is correct",
            )
            .await
            .expect("Failed to connect server's endpoint, Please make sure the Server is alive");
        let (send, _) = client_handshake(&conn, PROTOCOL_VERSION).await.unwrap();
        Self {
            send,
            conn,
            endpoint,
        }
    }
}

fn server() -> Server {
    let cert_pem = fs::read(NODE1_CERT_PATH).unwrap();
    let cert = to_cert_chain(&cert_pem).unwrap();
    let key_pem = fs::read(NODE1_KEY_PATH).unwrap();
    let key = to_private_key(&key_pem).unwrap();
    let ca_cert_path = vec![CA_CERT_PATH.to_string()];
    let root = to_root_cert(&ca_cert_path).unwrap();

    let certs = Arc::new(Certs {
        certs: cert,
        key,
        root,
    });

    Server::new(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), NODE1_TEST_PORT),
        &certs,
    )
}

fn init_client() -> Endpoint {
    let (cert, key): (Vec<u8>, Vec<u8>) = if let Ok(x) = fs::read(NODE1_CERT_PATH).map(|x| {
        (
            x,
            fs::read(NODE1_KEY_PATH).expect("Failed to Read key file"),
        )
    }) {
        x
    } else {
        panic!(
            "failed to read (cert, key) file, {NODE1_CERT_PATH}, {NODE1_KEY_PATH} read file error. Cert or key doesn't exist in default test folder"
        );
    };

    let pv_key = if Path::new(NODE1_KEY_PATH)
        .extension()
        .is_some_and(|x| x == "der")
    {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))
    } else {
        rustls_pemfile::private_key(&mut &*key)
            .expect("malformed PKCS #1 private key")
            .expect("no private keys found")
    };

    let cert_chain = if Path::new(NODE1_CERT_PATH)
        .extension()
        .is_some_and(|x| x == "der")
    {
        vec![CertificateDer::from(cert)]
    } else {
        rustls_pemfile::certs(&mut &*cert)
            .collect::<Result<_, _>>()
            .expect("invalid PEM-encoded certificate")
    };
    let ca_cert_path = vec![CA_CERT_PATH.to_string()];
    let server_root = to_root_cert(&ca_cert_path).unwrap();

    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(server_root)
        .with_client_auth_cert(cert_chain, pv_key)
        .expect("the server root, cert chain or private key are not valid");

    let mut endpoint =
        quinn::Endpoint::client("[::]:0".parse().expect("Failed to parse Endpoint addr"))
            .expect("Failed to create endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .expect("Failed to generate QuicClientConfig"),
    )));
    endpoint
}

fn gen_network_event_key(sensor: &str, kind: Option<&str>, timestamp: i64) -> Vec<u8> {
    let mut key = Vec::new();
    key.extend_from_slice(sensor.as_bytes());
    key.push(0);
    if let Some(kind) = kind {
        key.extend_from_slice(kind.as_bytes());
        key.push(0);
    }
    key.extend(timestamp.to_be_bytes());
    key
}

fn gen_conn_raw_event() -> Vec<u8> {
    let tmp_dur = Duration::nanoseconds(12345);
    let conn_body = Conn {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 6,
        conn_state: "sf".to_string(),
        duration: tmp_dur.num_nanoseconds().unwrap(),
        service: "-".to_string(),
        orig_bytes: 77,
        resp_bytes: 295,
        orig_pkts: 397,
        resp_pkts: 511,
        orig_l2_bytes: 21515,
        resp_l2_bytes: 27889,
    };

    bincode::serialize(&conn_body).unwrap()
}

fn gen_dns_raw_event() -> Vec<u8> {
    let dns_body = Dns {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        query: "Hello Server".to_string(),
        answer: vec!["1.1.1.1".to_string(), "2.2.2.2".to_string()],
        trans_id: 1,
        rtt: 1,
        qclass: 0,
        qtype: 0,
        rcode: 0,
        aa_flag: false,
        tc_flag: false,
        rd_flag: false,
        ra_flag: false,
        ttl: vec![1; 5],
    };

    bincode::serialize(&dns_body).unwrap()
}

fn gen_rdp_raw_event() -> Vec<u8> {
    let rdp_body = Rdp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        cookie: "rdp_test".to_string(),
    };

    bincode::serialize(&rdp_body).unwrap()
}

fn gen_http_raw_event() -> Vec<u8> {
    let http_body = Http {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        method: "POST".to_string(),
        host: "cluml".to_string(),
        uri: "/cluml.gif".to_string(),
        referrer: "cluml.com".to_string(),
        version: String::new(),
        user_agent: "giganto".to_string(),
        request_len: 0,
        response_len: 0,
        status_code: 200,
        status_msg: String::new(),
        username: String::new(),
        password: String::new(),
        cookie: String::new(),
        content_encoding: String::new(),
        content_type: String::new(),
        cache_control: String::new(),
        orig_filenames: Vec::new(),
        orig_mime_types: Vec::new(),
        resp_filenames: Vec::new(),
        resp_mime_types: Vec::new(),
        post_body: Vec::new(),
        state: String::new(),
    };

    bincode::serialize(&http_body).unwrap()
}

fn gen_smtp_raw_event() -> Vec<u8> {
    let smtp_body = Smtp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        mailfrom: "google".to_string(),
        date: "2022-11-28".to_string(),
        from: "safe2@cluml.com".to_string(),
        to: "safe1@cluml.com".to_string(),
        subject: "hello giganto".to_string(),
        agent: "giganto".to_string(),
        state: String::new(),
    };

    bincode::serialize(&smtp_body).unwrap()
}

fn gen_ntlm_raw_event() -> Vec<u8> {
    let ntlm_body = Ntlm {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        username: "bly".to_string(),
        hostname: "host".to_string(),
        domainname: "domain".to_string(),
        success: "tf".to_string(),
        protocol: "protocol".to_string(),
    };

    bincode::serialize(&ntlm_body).unwrap()
}

fn gen_kerberos_raw_event() -> Vec<u8> {
    let kerberos_body = Kerberos {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        client_time: 1,
        server_time: 1,
        error_code: 1,
        client_realm: "client_realm".to_string(),
        cname_type: 1,
        client_name: vec!["client_name".to_string()],
        realm: "realm".to_string(),
        sname_type: 1,
        service_name: vec!["service_name".to_string()],
    };

    bincode::serialize(&kerberos_body).unwrap()
}

fn gen_ssh_raw_event() -> Vec<u8> {
    let ssh_body = Ssh {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        client: "client".to_string(),
        server: "server".to_string(),
        cipher_alg: "cipher_alg".to_string(),
        mac_alg: "mac_alg".to_string(),
        compression_alg: "compression_alg".to_string(),
        kex_alg: "kex_alg".to_string(),
        host_key_alg: "host_key_alg".to_string(),
        hassh_algorithms: "hassh_algorithms".to_string(),
        hassh: "hassh".to_string(),
        hassh_server_algorithms: "hassh_server_algorithms".to_string(),
        hassh_server: "hassh_server".to_string(),
        client_shka: "client_shka".to_string(),
        server_shka: "server_shka".to_string(),
    };

    bincode::serialize(&ssh_body).unwrap()
}

fn gen_dce_rpc_raw_event() -> Vec<u8> {
    let dce_rpc_body = DceRpc {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        rtt: 3,
        named_pipe: "named_pipe".to_string(),
        endpoint: "endpoint".to_string(),
        operation: "operation".to_string(),
    };

    bincode::serialize(&dce_rpc_body).unwrap()
}

fn gen_log_raw_event() -> Vec<u8> {
    let log_body = Log {
        kind: String::from("Hello"),
        log: base64_engine.decode("aGVsbG8gd29ybGQ=").unwrap(),
    };

    bincode::serialize(&log_body).unwrap()
}

fn gen_periodic_time_series_raw_event() -> Vec<u8> {
    let periodic_time_series_body: PeriodicTimeSeries = PeriodicTimeSeries {
        id: String::from("policy_one"),
        data: vec![1.1, 2.2, 3.3, 4.4, 5.5, 6.6],
    };

    bincode::serialize(&periodic_time_series_body).unwrap()
}

fn gen_ftp_raw_event() -> Vec<u8> {
    let ftp_body = Ftp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        user: "cluml".to_string(),
        password: "aice".to_string(),
        command: "command".to_string(),
        reply_code: "500".to_string(),
        reply_msg: "reply_message".to_string(),
        data_passive: false,
        data_orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        data_resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        data_resp_port: 80,
        file: "ftp_file".to_string(),
        file_size: 100,
        file_id: "1".to_string(),
    };

    bincode::serialize(&ftp_body).unwrap()
}

fn gen_mqtt_raw_event() -> Vec<u8> {
    let mqtt_body = Mqtt {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        protocol: "protocol".to_string(),
        version: 1,
        client_id: "1".to_string(),
        connack_reason: 1,
        subscribe: vec!["subscribe".to_string()],
        suback_reason: vec![1],
    };

    bincode::serialize(&mqtt_body).unwrap()
}

fn gen_ldap_raw_event() -> Vec<u8> {
    let ldap_body = Ldap {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        message_id: 1,
        version: 1,
        opcode: vec!["opcode".to_string()],
        result: vec!["result".to_string()],
        diagnostic_message: Vec::new(),
        object: Vec::new(),
        argument: Vec::new(),
    };

    bincode::serialize(&ldap_body).unwrap()
}

fn gen_tls_raw_event() -> Vec<u8> {
    let tls_body = Tls {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        server_name: "server_name".to_string(),
        alpn_protocol: "alpn_protocol".to_string(),
        ja3: "ja3".to_string(),
        version: "version".to_string(),
        client_cipher_suites: vec![771, 769, 770],
        client_extensions: vec![0, 1, 2],
        cipher: 10,
        extensions: vec![0, 1],
        ja3s: "ja3s".to_string(),
        serial: "serial".to_string(),
        subject_country: "sub_country".to_string(),
        subject_org_name: "sub_org".to_string(),
        subject_common_name: "sub_comm".to_string(),
        validity_not_before: 11,
        validity_not_after: 12,
        subject_alt_name: "sub_alt".to_string(),
        issuer_country: "issuer_country".to_string(),
        issuer_org_name: "issuer_org".to_string(),
        issuer_org_unit_name: "issuer_org_unit".to_string(),
        issuer_common_name: "issuer_comm".to_string(),
        last_alert: 13,
    };

    bincode::serialize(&tls_body).unwrap()
}

fn gen_smb_raw_event() -> Vec<u8> {
    let smb_body = Smb {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        command: 0,
        path: "something/path".to_string(),
        service: "service".to_string(),
        file_name: "fine_name".to_string(),
        file_size: 10,
        resource_type: 20,
        fid: 30,
        create_time: 10_000_000,
        access_time: 20_000_000,
        write_time: 10_000_000,
        change_time: 20_000_000,
    };

    bincode::serialize(&smb_body).unwrap()
}

fn gen_nfs_raw_event() -> Vec<u8> {
    let nfs_body = Nfs {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        read_files: vec![],
        write_files: vec![],
    };

    bincode::serialize(&nfs_body).unwrap()
}

fn gen_bootp_raw_event() -> Vec<u8> {
    let bootp_body = Bootp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        op: 0,
        htype: 0,
        hops: 0,
        xid: 0,
        ciaddr: "192.168.4.1".parse::<IpAddr>().unwrap(),
        yiaddr: "192.168.4.2".parse::<IpAddr>().unwrap(),
        siaddr: "192.168.4.3".parse::<IpAddr>().unwrap(),
        giaddr: "192.168.4.4".parse::<IpAddr>().unwrap(),
        chaddr: vec![0, 1, 2],
        sname: "sname".to_string(),
        file: "file".to_string(),
    };

    bincode::serialize(&bootp_body).unwrap()
}

fn gen_dhcp_raw_event() -> Vec<u8> {
    let dhcp_body = Dhcp {
        orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
        orig_port: 46378,
        resp_addr: "31.3.245.133".parse::<IpAddr>().unwrap(),
        resp_port: 80,
        proto: 17,
        last_time: 1,
        msg_type: 0,
        ciaddr: "192.168.4.1".parse::<IpAddr>().unwrap(),
        yiaddr: "192.168.4.2".parse::<IpAddr>().unwrap(),
        siaddr: "192.168.4.3".parse::<IpAddr>().unwrap(),
        giaddr: "192.168.4.4".parse::<IpAddr>().unwrap(),
        subnet_mask: "192.168.4.5".parse::<IpAddr>().unwrap(),
        router: vec![
            "192.168.1.11".parse::<IpAddr>().unwrap(),
            "192.168.1.22".parse::<IpAddr>().unwrap(),
        ],
        domain_name_server: vec![
            "192.168.1.33".parse::<IpAddr>().unwrap(),
            "192.168.1.44".parse::<IpAddr>().unwrap(),
        ],
        req_ip_addr: "192.168.4.6".parse::<IpAddr>().unwrap(),
        lease_time: 1,
        server_id: "192.168.4.7".parse::<IpAddr>().unwrap(),
        param_req_list: vec![0, 1, 2],
        message: "message".to_string(),
        renewal_time: 1,
        rebinding_time: 1,
        class_id: vec![0, 1, 2],
        client_id_type: 1,
        client_id: vec![0, 1, 2],
    };

    bincode::serialize(&dhcp_body).unwrap()
}

fn insert_conn_raw_event(store: &RawEventStore<Conn>, sensor: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_conn_body = gen_conn_raw_event();
    store.append(&key, &ser_conn_body).unwrap();
    ser_conn_body
}

fn insert_dns_raw_event(store: &RawEventStore<Dns>, sensor: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_dns_body = gen_dns_raw_event();
    store.append(&key, &ser_dns_body).unwrap();
    ser_dns_body
}

fn insert_rdp_raw_event(store: &RawEventStore<Rdp>, sensor: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_rdp_body = gen_rdp_raw_event();
    store.append(&key, &ser_rdp_body).unwrap();
    ser_rdp_body
}

fn insert_http_raw_event(store: &RawEventStore<Http>, sensor: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_http_body = gen_http_raw_event();
    store.append(&key, &ser_http_body).unwrap();
    ser_http_body
}

fn insert_smtp_raw_event(store: &RawEventStore<Smtp>, sensor: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_smtp_body = gen_smtp_raw_event();
    store.append(&key, &ser_smtp_body).unwrap();
    ser_smtp_body
}

fn insert_ntlm_raw_event(store: &RawEventStore<Ntlm>, sensor: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_ntlm_body = gen_ntlm_raw_event();
    store.append(&key, &ser_ntlm_body).unwrap();
    ser_ntlm_body
}

fn insert_kerberos_raw_event(
    store: &RawEventStore<Kerberos>,
    sensor: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_kerberos_body = gen_kerberos_raw_event();
    store.append(&key, &ser_kerberos_body).unwrap();
    ser_kerberos_body
}

fn insert_ssh_raw_event(store: &RawEventStore<Ssh>, sensor: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_ssh_body = gen_ssh_raw_event();
    store.append(&key, &ser_ssh_body).unwrap();
    ser_ssh_body
}

fn insert_dce_rpc_raw_event(
    store: &RawEventStore<DceRpc>,
    sensor: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_dce_rpc_body = gen_dce_rpc_raw_event();
    store.append(&key, &ser_dce_rpc_body).unwrap();
    ser_dce_rpc_body
}

fn insert_log_raw_event(
    store: &RawEventStore<Log>,
    sensor: &str,
    kind: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, Some(kind), timestamp);
    let ser_log_body = gen_log_raw_event();
    store.append(&key, &ser_log_body).unwrap();
    ser_log_body
}

fn insert_periodic_time_series_raw_event(
    store: &RawEventStore<PeriodicTimeSeries>,
    sensor: &str,
    timestamp: i64,
) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_periodic_time_series_body = gen_periodic_time_series_raw_event();
    store.append(&key, &ser_periodic_time_series_body).unwrap();
    ser_periodic_time_series_body
}

fn insert_ftp_raw_event(store: &RawEventStore<Ftp>, sensor: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_ftp_body = gen_ftp_raw_event();
    store.append(&key, &ser_ftp_body).unwrap();
    ser_ftp_body
}

fn insert_mqtt_raw_event(store: &RawEventStore<Mqtt>, sensor: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_mqtt_body = gen_mqtt_raw_event();
    store.append(&key, &ser_mqtt_body).unwrap();
    ser_mqtt_body
}

fn insert_ldap_raw_event(store: &RawEventStore<Ldap>, sensor: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_ldap_body = gen_ldap_raw_event();
    store.append(&key, &ser_ldap_body).unwrap();
    ser_ldap_body
}

fn insert_tls_raw_event(store: &RawEventStore<Tls>, sensor: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_tls_body = gen_tls_raw_event();
    store.append(&key, &ser_tls_body).unwrap();
    ser_tls_body
}

fn insert_smb_raw_event(store: &RawEventStore<Smb>, sensor: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_smb_body = gen_smb_raw_event();
    store.append(&key, &ser_smb_body).unwrap();
    ser_smb_body
}

fn insert_nfs_raw_event(store: &RawEventStore<Nfs>, sensor: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_nfs_body = gen_nfs_raw_event();
    store.append(&key, &ser_nfs_body).unwrap();
    ser_nfs_body
}

fn insert_bootp_raw_event(store: &RawEventStore<Bootp>, sensor: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_bootp_body = gen_bootp_raw_event();
    store.append(&key, &ser_bootp_body).unwrap();
    ser_bootp_body
}

fn insert_dhcp_raw_event(store: &RawEventStore<Dhcp>, sensor: &str, timestamp: i64) -> Vec<u8> {
    let key = gen_network_event_key(sensor, None, timestamp);
    let ser_dhcp_body = gen_dhcp_raw_event();
    store.append(&key, &ser_dhcp_body).unwrap();
    ser_dhcp_body
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn request_range_data_with_protocol() {
    const PUBLISH_RANGE_MESSAGE_CODE: MessageCode = MessageCode::ReqRange;
    const SENSOR: &str = "ingest src 1";
    const CONN_KIND: &str = "conn";
    const DNS_KIND: &str = "dns";
    const HTTP_KIND: &str = "http";
    const RDP_KIND: &str = "rdp";
    const SMTP_KIND: &str = "smtp";
    const NTLM_KIND: &str = "ntlm";
    const KERBEROS_KIND: &str = "kerberos";
    const SSH_KIND: &str = "ssh";
    const DCE_RPC_KIND: &str = "dce rpc";
    const FTP_KIND: &str = "ftp";
    const MQTT_KIND: &str = "mqtt";
    const LDAP_KIND: &str = "ldap";
    const TLS_KIND: &str = "tls";
    const SMB_KIND: &str = "smb";
    const NFS_KIND: &str = "nfs";
    const BOOTP_KIND: &str = "bootp";
    const DHCP_KIND: &str = "dhcp";

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let pcap_sensors = new_pcap_sensors();
    let stream_direct_channels = new_stream_direct_channels();
    let ingest_sensors = Arc::new(tokio::sync::RwLock::new(
        NODE1_GIGANTO_INGEST_SENSORS
            .into_iter()
            .map(str::to_string)
            .collect::<HashSet<String>>(),
    ));
    let (peers, peer_idents) = new_peers_data(None);

    let cert_pem = fs::read(NODE1_CERT_PATH).unwrap();
    let cert = to_cert_chain(&cert_pem).unwrap();
    let key_pem = fs::read(NODE1_KEY_PATH).unwrap();
    let key = to_private_key(&key_pem).unwrap();
    let ca_cert_path = vec![CA_CERT_PATH.to_string()];
    let root = to_root_cert(&ca_cert_path).unwrap();

    let certs = Arc::new(Certs {
        certs: cert,
        key,
        root,
    });

    tokio::spawn(server().run(
        db.clone(),
        pcap_sensors,
        stream_direct_channels,
        ingest_sensors,
        peers,
        peer_idents,
        certs,
        Arc::new(Notify::new()),
    ));
    let publish = TestClient::new().await;

    // conn protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let conn_store = db.conn_store().unwrap();
        let send_conn_time = Utc::now().timestamp_nanos_opt().unwrap();
        let conn_data = bincode::deserialize::<Conn>(&insert_conn_raw_event(
            &conn_store,
            SENSOR,
            send_conn_time,
        ))
        .unwrap();

        let start = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("valid date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            sensor: String::from(SENSOR),
            kind: String::from(CONN_KIND),
            start: start.timestamp_nanos_opt().unwrap(),
            end: end.timestamp_nanos_opt().unwrap(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Conn::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            conn_data.response_data(send_conn_time, SENSOR).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // dns protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let dns_store = db.dns_store().unwrap();
        let send_dns_time = Utc::now().timestamp_nanos_opt().unwrap();
        let dns_data =
            bincode::deserialize::<Dns>(&insert_dns_raw_event(&dns_store, SENSOR, send_dns_time))
                .unwrap();

        let start = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("valid date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            sensor: String::from(SENSOR),
            kind: String::from(DNS_KIND),
            start: start.timestamp_nanos_opt().unwrap(),
            end: end.timestamp_nanos_opt().unwrap(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Dns::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            dns_data.response_data(send_dns_time, SENSOR).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // http protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let http_store = db.http_store().unwrap();
        let send_http_time = Utc::now().timestamp_nanos_opt().unwrap();
        let http_data = bincode::deserialize::<Http>(&insert_http_raw_event(
            &http_store,
            SENSOR,
            send_http_time,
        ))
        .unwrap();

        let start = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("valid date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            sensor: String::from(SENSOR),
            kind: String::from(HTTP_KIND),
            start: start.timestamp_nanos_opt().unwrap(),
            end: end.timestamp_nanos_opt().unwrap(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Http::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            http_data.response_data(send_http_time, SENSOR).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // rdp protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let rdp_store = db.rdp_store().unwrap();
        let send_rdp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let rdp_data =
            bincode::deserialize::<Rdp>(&insert_rdp_raw_event(&rdp_store, SENSOR, send_rdp_time))
                .unwrap();

        let start = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("valid date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            sensor: String::from(SENSOR),
            kind: String::from(RDP_KIND),
            start: start.timestamp_nanos_opt().unwrap(),
            end: end.timestamp_nanos_opt().unwrap(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Rdp::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            rdp_data.response_data(send_rdp_time, SENSOR).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // smtp protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let smtp_store = db.smtp_store().unwrap();
        let send_smtp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let smtp_data = bincode::deserialize::<Smtp>(&insert_smtp_raw_event(
            &smtp_store,
            SENSOR,
            send_smtp_time,
        ))
        .unwrap();

        let start = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("valid date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            sensor: String::from(SENSOR),
            kind: String::from(SMTP_KIND),
            start: start.timestamp_nanos_opt().unwrap(),
            end: end.timestamp_nanos_opt().unwrap(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Conn::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            smtp_data.response_data(send_smtp_time, SENSOR).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // ntlm protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let ntlm_store = db.ntlm_store().unwrap();
        let send_ntlm_time = Utc::now().timestamp_nanos_opt().unwrap();
        let ntlm_data = bincode::deserialize::<Ntlm>(&insert_ntlm_raw_event(
            &ntlm_store,
            SENSOR,
            send_ntlm_time,
        ))
        .unwrap();

        let start = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("valid date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            sensor: String::from(SENSOR),
            kind: String::from(NTLM_KIND),
            start: start.timestamp_nanos_opt().unwrap(),
            end: end.timestamp_nanos_opt().unwrap(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Ntlm::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            ntlm_data.response_data(send_ntlm_time, SENSOR).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // kerberos protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let kerberos_store = db.kerberos_store().unwrap();
        let send_kerberos_time = Utc::now().timestamp_nanos_opt().unwrap();
        let kerberos_data = bincode::deserialize::<Kerberos>(&insert_kerberos_raw_event(
            &kerberos_store,
            SENSOR,
            send_kerberos_time,
        ))
        .unwrap();

        let start = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("valid date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            sensor: String::from(SENSOR),
            kind: String::from(KERBEROS_KIND),
            start: start.timestamp_nanos_opt().unwrap(),
            end: end.timestamp_nanos_opt().unwrap(),
            count: 5,
        };
        send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Kerberos::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            kerberos_data
                .response_data(send_kerberos_time, SENSOR)
                .unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // ssh protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let ssh_store = db.ssh_store().unwrap();
        let send_ssh_time = Utc::now().timestamp_nanos_opt().unwrap();
        let ssh_data =
            bincode::deserialize::<Ssh>(&insert_ssh_raw_event(&ssh_store, SENSOR, send_ssh_time))
                .unwrap();

        let start = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("valid date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            sensor: String::from(SENSOR),
            kind: String::from(SSH_KIND),
            start: start.timestamp_nanos_opt().unwrap(),
            end: end.timestamp_nanos_opt().unwrap(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Ssh::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            ssh_data.response_data(send_ssh_time, SENSOR).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // dce_rpc protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let dce_rpc_store = db.dce_rpc_store().unwrap();
        let send_dce_rpc_time = Utc::now().timestamp_nanos_opt().unwrap();
        let dce_rpc_data = bincode::deserialize::<DceRpc>(&insert_dce_rpc_raw_event(
            &dce_rpc_store,
            SENSOR,
            send_dce_rpc_time,
        ))
        .unwrap();

        let start = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("valid date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            sensor: String::from(SENSOR),
            kind: String::from(DCE_RPC_KIND),
            start: start.timestamp_nanos_opt().unwrap(),
            end: end.timestamp_nanos_opt().unwrap(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            DceRpc::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            dce_rpc_data
                .response_data(send_dce_rpc_time, SENSOR)
                .unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // ftp protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let ftp_store = db.ftp_store().unwrap();
        let send_ftp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let ftp_data =
            bincode::deserialize::<Ftp>(&insert_ftp_raw_event(&ftp_store, SENSOR, send_ftp_time))
                .unwrap();

        let start = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("valid date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            sensor: String::from(SENSOR),
            kind: String::from(FTP_KIND),
            start: start.timestamp_nanos_opt().unwrap(),
            end: end.timestamp_nanos_opt().unwrap(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Ftp::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            ftp_data.response_data(send_ftp_time, SENSOR).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // mqtt protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let mqtt_store = db.mqtt_store().unwrap();
        let send_mqtt_time = Utc::now().timestamp_nanos_opt().unwrap();
        let mqtt_data = bincode::deserialize::<Mqtt>(&insert_mqtt_raw_event(
            &mqtt_store,
            SENSOR,
            send_mqtt_time,
        ))
        .unwrap();

        let start = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("valid date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            sensor: String::from(SENSOR),
            kind: String::from(MQTT_KIND),
            start: start.timestamp_nanos_opt().unwrap(),
            end: end.timestamp_nanos_opt().unwrap(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Mqtt::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            mqtt_data.response_data(send_mqtt_time, SENSOR).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // ldap protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let ldap_store = db.ldap_store().unwrap();
        let send_ldap_time = Utc::now().timestamp_nanos_opt().unwrap();
        let ldap_data = bincode::deserialize::<Ldap>(&insert_ldap_raw_event(
            &ldap_store,
            SENSOR,
            send_ldap_time,
        ))
        .unwrap();

        let start = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("valid date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            sensor: String::from(SENSOR),
            kind: String::from(LDAP_KIND),
            start: start.timestamp_nanos_opt().unwrap(),
            end: end.timestamp_nanos_opt().unwrap(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Ldap::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            ldap_data.response_data(send_ldap_time, SENSOR).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // tls protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let tls_store = db.tls_store().unwrap();
        let send_tls_time = Utc::now().timestamp_nanos_opt().unwrap();
        let tls_data =
            bincode::deserialize::<Tls>(&insert_tls_raw_event(&tls_store, SENSOR, send_tls_time))
                .unwrap();

        let start = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("valid date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            sensor: String::from(SENSOR),
            kind: String::from(TLS_KIND),
            start: start.timestamp_nanos_opt().unwrap(),
            end: end.timestamp_nanos_opt().unwrap(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Tls::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            tls_data.response_data(send_tls_time, SENSOR).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // smb protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let smb_store = db.smb_store().unwrap();
        let send_smb_time = Utc::now().timestamp_nanos_opt().unwrap();
        let smb_data =
            bincode::deserialize::<Smb>(&insert_smb_raw_event(&smb_store, SENSOR, send_smb_time))
                .unwrap();

        let start = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("valid date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            sensor: String::from(SENSOR),
            kind: String::from(SMB_KIND),
            start: start.timestamp_nanos_opt().unwrap(),
            end: end.timestamp_nanos_opt().unwrap(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Smb::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            smb_data.response_data(send_smb_time, SENSOR).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // nfs protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let nfs_store = db.nfs_store().unwrap();
        let send_nfs_time = Utc::now().timestamp_nanos_opt().unwrap();
        let nfs_data =
            bincode::deserialize::<Nfs>(&insert_nfs_raw_event(&nfs_store, SENSOR, send_nfs_time))
                .unwrap();

        let start = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("valid date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            sensor: String::from(SENSOR),
            kind: String::from(NFS_KIND),
            start: start.timestamp_nanos_opt().unwrap(),
            end: end.timestamp_nanos_opt().unwrap(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Nfs::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            nfs_data.response_data(send_nfs_time, SENSOR).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // bootp protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let bootp_store = db.bootp_store().unwrap();
        let send_bootp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let bootp_data = bincode::deserialize::<Bootp>(&insert_bootp_raw_event(
            &bootp_store,
            SENSOR,
            send_bootp_time,
        ))
        .unwrap();

        let start = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("valid date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            sensor: String::from(SENSOR),
            kind: String::from(BOOTP_KIND),
            start: start.timestamp_nanos_opt().unwrap(),
            end: end.timestamp_nanos_opt().unwrap(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Bootp::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            bootp_data.response_data(send_bootp_time, SENSOR).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    // dhcp protocol
    {
        let (mut send_pub_req, mut recv_pub_resp) =
            publish.conn.open_bi().await.expect("failed to open stream");
        let dhcp_store = db.dhcp_store().unwrap();
        let send_dhcp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let dhcp_data = bincode::deserialize::<Dhcp>(&insert_dhcp_raw_event(
            &dhcp_store,
            SENSOR,
            send_dhcp_time,
        ))
        .unwrap();

        let start = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("valid date")
                .and_hms_opt(00, 00, 00)
                .expect("valid time"),
            Utc,
        );
        let end = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2050, 12, 31)
                .expect("valid date")
                .and_hms_opt(23, 59, 59)
                .expect("valid time"),
            Utc,
        );
        let message = RequestRange {
            sensor: String::from(SENSOR),
            kind: String::from(DHCP_KIND),
            start: start.timestamp_nanos_opt().unwrap(),
            end: end.timestamp_nanos_opt().unwrap(),
            count: 5,
        };

        send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
            .await
            .unwrap();

        let mut result_data = Vec::new();
        loop {
            let resp_data =
                receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
                    .await
                    .unwrap();

            result_data.push(resp_data.clone());
            if resp_data.is_none() {
                break;
            }
        }

        assert_eq!(
            Dhcp::response_done().unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
        assert_eq!(
            dhcp_data.response_data(send_dhcp_time, SENSOR).unwrap(),
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap())
                .unwrap()
        );
    }

    publish.conn.close(0u32.into(), b"publish_protocol_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
async fn request_range_data_with_log() {
    const PUBLISH_RANGE_MESSAGE_CODE: MessageCode = MessageCode::ReqRange;
    const SENSOR: &str = "src1";
    const KIND: &str = "Hello";

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let pcap_sensors = new_pcap_sensors();
    let stream_direct_channels = new_stream_direct_channels();
    let ingest_sensors = Arc::new(tokio::sync::RwLock::new(
        NODE1_GIGANTO_INGEST_SENSORS
            .into_iter()
            .map(str::to_string)
            .collect::<HashSet<String>>(),
    ));
    let (peers, peer_idents) = new_peers_data(None);

    let cert_pem = fs::read(NODE1_CERT_PATH).unwrap();
    let cert = to_cert_chain(&cert_pem).unwrap();
    let key_pem = fs::read(NODE1_KEY_PATH).unwrap();
    let key = to_private_key(&key_pem).unwrap();
    let ca_cert_path = vec![CA_CERT_PATH.to_string()];
    let root = to_root_cert(&ca_cert_path).unwrap();

    let certs = Arc::new(Certs {
        certs: cert,
        key,
        root,
    });

    tokio::spawn(server().run(
        db.clone(),
        pcap_sensors,
        stream_direct_channels,
        ingest_sensors,
        peers,
        peer_idents,
        certs,
        Arc::new(Notify::new()),
    ));
    let publish = TestClient::new().await;
    let (mut send_pub_req, mut recv_pub_resp) =
        publish.conn.open_bi().await.expect("failed to open stream");

    let log_store = db.log_store().unwrap();
    let send_log_time = Utc::now().timestamp_nanos_opt().unwrap();
    let log_data = bincode::deserialize::<Log>(&insert_log_raw_event(
        &log_store,
        SENSOR,
        KIND,
        send_log_time,
    ))
    .unwrap();

    let start = DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDate::from_ymd_opt(1970, 1, 1)
            .expect("valid date")
            .and_hms_opt(00, 00, 00)
            .expect("valid time"),
        Utc,
    );
    let end = DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDate::from_ymd_opt(2050, 12, 31)
            .expect("valid date")
            .and_hms_opt(23, 59, 59)
            .expect("valid time"),
        Utc,
    );
    let message = RequestRange {
        sensor: String::from(SENSOR),
        kind: String::from(KIND),
        start: start.timestamp_nanos_opt().unwrap(),
        end: end.timestamp_nanos_opt().unwrap(),
        count: 5,
    };

    send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
        .await
        .unwrap();

    let mut result_data = Vec::new();
    loop {
        let resp_data = receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
            .await
            .unwrap();

        result_data.push(resp_data.clone());
        if resp_data.is_none() {
            break;
        }
    }

    assert_eq!(
        Conn::response_done().unwrap(),
        bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap()).unwrap()
    );
    assert_eq!(
        log_data.response_data(send_log_time, SENSOR).unwrap(),
        bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap()).unwrap()
    );

    publish.conn.close(0u32.into(), b"publish_log_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
async fn request_range_data_with_period_time_series() {
    const PUBLISH_RANGE_MESSAGE_CODE: MessageCode = MessageCode::ReqRange;
    const SAMPLING_POLICY_ID_AS_SENSOR: &str = "ingest src 1";
    const KIND: &str = "timeseries";

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let pcap_sensors = new_pcap_sensors();
    let stream_direct_channels = new_stream_direct_channels();
    let ingest_sensors = Arc::new(tokio::sync::RwLock::new(
        NODE1_GIGANTO_INGEST_SENSORS
            .into_iter()
            .map(str::to_string)
            .collect::<HashSet<String>>(),
    ));
    let (peers, peer_idents) = new_peers_data(None);

    let cert_pem = fs::read(NODE1_CERT_PATH).unwrap();
    let cert = to_cert_chain(&cert_pem).unwrap();
    let key_pem = fs::read(NODE1_KEY_PATH).unwrap();
    let key = to_private_key(&key_pem).unwrap();
    let ca_cert_path = vec![CA_CERT_PATH.to_string()];
    let root = to_root_cert(&ca_cert_path).unwrap();

    let certs = Arc::new(Certs {
        certs: cert,
        key,
        root,
    });

    tokio::spawn(server().run(
        db.clone(),
        pcap_sensors,
        stream_direct_channels,
        ingest_sensors,
        peers,
        peer_idents,
        certs,
        Arc::new(Notify::new()),
    ));
    let publish = TestClient::new().await;
    let (mut send_pub_req, mut recv_pub_resp) =
        publish.conn.open_bi().await.expect("failed to open stream");

    let time_series_store = db.periodic_time_series_store().unwrap();
    let send_time_series_time = Utc::now().timestamp_nanos_opt().unwrap();
    let time_series_data =
        bincode::deserialize::<PeriodicTimeSeries>(&insert_periodic_time_series_raw_event(
            &time_series_store,
            SAMPLING_POLICY_ID_AS_SENSOR,
            send_time_series_time,
        ))
        .unwrap();

    let start = DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDate::from_ymd_opt(1970, 1, 1)
            .expect("valid date")
            .and_hms_opt(00, 00, 00)
            .expect("valid time"),
        Utc,
    );
    let end = DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDate::from_ymd_opt(2050, 12, 31)
            .expect("valid date")
            .and_hms_opt(23, 59, 59)
            .expect("valid time"),
        Utc,
    );
    let message = RequestRange {
        sensor: String::from(SAMPLING_POLICY_ID_AS_SENSOR),
        kind: String::from(KIND),
        start: start.timestamp_nanos_opt().unwrap(),
        end: end.timestamp_nanos_opt().unwrap(),
        count: 5,
    };

    send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
        .await
        .unwrap();

    let mut result_data = Vec::new();
    loop {
        let resp_data = receive_range_data::<Option<(i64, String, Vec<f64>)>>(&mut recv_pub_resp)
            .await
            .unwrap();

        result_data.push(resp_data.clone());
        if resp_data.is_none() {
            break;
        }
    }

    assert_eq!(
        PeriodicTimeSeries::response_done().unwrap(),
        bincode::serialize::<Option<(i64, String, Vec<f64>)>>(&result_data.pop().unwrap()).unwrap()
    );
    assert_eq!(
        time_series_data
            .response_data(send_time_series_time, SAMPLING_POLICY_ID_AS_SENSOR)
            .unwrap(),
        bincode::serialize::<Option<(i64, String, Vec<f64>)>>(&result_data.pop().unwrap()).unwrap()
    );

    publish.conn.close(0u32.into(), b"publish_time_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn request_network_event_stream() {
    use crate::ingest::NetworkKey;
    use crate::publish::send_direct_stream;

    const SEMI_SUPERVISED_TYPE: NodeType = NodeType::SemiSupervised;
    const TIME_SERIES_GENERATOR_TYPE: NodeType = NodeType::TimeSeriesGenerator;
    const NETWORK_STREAM_CONN: RequestStreamRecord = RequestStreamRecord::Conn;
    const NETWORK_STREAM_DNS: RequestStreamRecord = RequestStreamRecord::Dns;
    const NETWORK_STREAM_RDP: RequestStreamRecord = RequestStreamRecord::Rdp;
    const NETWORK_STREAM_HTTP: RequestStreamRecord = RequestStreamRecord::Http;
    const NETWORK_STREAM_SMTP: RequestStreamRecord = RequestStreamRecord::Smtp;
    const NETWORK_STREAM_NTLM: RequestStreamRecord = RequestStreamRecord::Ntlm;
    const NETWORK_STREAM_KERBEROS: RequestStreamRecord = RequestStreamRecord::Kerberos;
    const NETWORK_STREAM_SSH: RequestStreamRecord = RequestStreamRecord::Ssh;
    const NETWORK_STREAM_DCE_RPC: RequestStreamRecord = RequestStreamRecord::DceRpc;
    const NETWORK_STREAM_FTP: RequestStreamRecord = RequestStreamRecord::Ftp;
    const NETWORK_STREAM_MQTT: RequestStreamRecord = RequestStreamRecord::Mqtt;
    const NETWORK_STREAM_LDAP: RequestStreamRecord = RequestStreamRecord::Ldap;
    const NETWORK_STREAM_TLS: RequestStreamRecord = RequestStreamRecord::Tls;
    const NETWORK_STREAM_SMB: RequestStreamRecord = RequestStreamRecord::Smb;
    const NETWORK_STREAM_NFS: RequestStreamRecord = RequestStreamRecord::Nfs;
    const NETWORK_STREAM_BOOTP: RequestStreamRecord = RequestStreamRecord::Bootp;
    const NETWORK_STREAM_DHCP: RequestStreamRecord = RequestStreamRecord::Dhcp;

    const SENSOR_SEMI_SUPERVISED_ONE: &str = "src1";
    const SENSOR_SEMI_SUPERVISED_TWO: &str = "src2";
    const SENSOR_TIME_SERIES_GENERATOR_THREE: &str = "src3";
    const POLICY_ID: u32 = 1;

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();

    let semi_supervised_msg = RequestSemiSupervisedStream {
        start: 0,
        sensor: Some(vec![
            String::from(SENSOR_SEMI_SUPERVISED_ONE),
            String::from(SENSOR_SEMI_SUPERVISED_TWO),
        ]),
    };
    let time_series_generator_msg = RequestTimeSeriesGeneratorStream {
        start: 0,
        id: POLICY_ID.to_string(),
        src_ip: Some("192.168.4.76".parse::<IpAddr>().unwrap()),
        dst_ip: Some("31.3.245.133".parse::<IpAddr>().unwrap()),
        sensor: Some(String::from(SENSOR_TIME_SERIES_GENERATOR_THREE)),
    };
    let pcap_sensors = new_pcap_sensors();
    let stream_direct_channels = new_stream_direct_channels();
    let ingest_sensors = Arc::new(tokio::sync::RwLock::new(
        NODE1_GIGANTO_INGEST_SENSORS
            .into_iter()
            .map(str::to_string)
            .collect::<HashSet<String>>(),
    ));
    let (peers, peer_idents) = new_peers_data(None);

    let cert_pem = fs::read(NODE1_CERT_PATH).unwrap();
    let cert = to_cert_chain(&cert_pem).unwrap();
    let key_pem = fs::read(NODE1_KEY_PATH).unwrap();
    let key = to_private_key(&key_pem).unwrap();
    let ca_cert_path = vec![CA_CERT_PATH.to_string()];
    let root = to_root_cert(&ca_cert_path).unwrap();

    let certs = Arc::new(Certs {
        certs: cert,
        key,
        root,
    });

    tokio::spawn(server().run(
        db.clone(),
        pcap_sensors,
        stream_direct_channels.clone(),
        ingest_sensors,
        peers,
        peer_idents,
        certs,
        Arc::new(Notify::new()),
    ));
    let mut publish = TestClient::new().await;

    {
        let conn_store = db.conn_store().unwrap();

        // direct conn network event for the Semi-supervised Engine (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_CONN,
            SEMI_SUPERVISED_TYPE,
            semi_supervised_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_conn_stream = publish.conn.accept_uni().await.unwrap();

        let conn_start_msg = receive_semi_supervised_stream_start_message(&mut send_conn_stream)
            .await
            .unwrap();
        assert_eq!(conn_start_msg, NETWORK_STREAM_CONN);

        let send_conn_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_ONE, "conn");
        let conn_data = gen_conn_raw_event();
        send_direct_stream(
            &key,
            &conn_data,
            send_conn_time,
            SENSOR_SEMI_SUPERVISED_ONE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_conn_stream)
            .await
            .unwrap();
        assert_eq!(conn_data, recv_data[20..]);

        let send_conn_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_TWO, "conn");
        let conn_data = gen_conn_raw_event();
        send_direct_stream(
            &key,
            &conn_data,
            send_conn_time,
            SENSOR_SEMI_SUPERVISED_TWO,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();
        let recv_data = receive_semi_supervised_data(&mut send_conn_stream)
            .await
            .unwrap();
        assert_eq!(conn_data, recv_data[20..]);

        // database conn network event for the Time Series Generator
        let send_conn_time = Utc::now().timestamp_nanos_opt().unwrap();
        let conn_data = insert_conn_raw_event(
            &conn_store,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            send_conn_time,
        );
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_CONN,
            TIME_SERIES_GENERATOR_TYPE,
            time_series_generator_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_conn_stream = publish.conn.accept_uni().await.unwrap();
        let conn_start_msg =
            receive_time_series_generator_stream_start_message(&mut send_conn_stream)
                .await
                .unwrap();
        assert_eq!(conn_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_conn_stream)
            .await
            .unwrap();
        assert_eq!(send_conn_time, recv_timestamp);
        assert_eq!(conn_data, recv_data);

        // direct conn network event for the Time Series Generator
        let send_conn_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_TIME_SERIES_GENERATOR_THREE, "conn");
        let conn_data = gen_conn_raw_event();

        send_direct_stream(
            &key,
            &conn_data,
            send_conn_time,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_conn_stream)
            .await
            .unwrap();
        assert_eq!(send_conn_time, recv_timestamp);
        assert_eq!(conn_data, recv_data);
    }

    {
        let dns_store = db.dns_store().unwrap();

        // direct dns network event for the Semi-supervised Engine (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_DNS,
            SEMI_SUPERVISED_TYPE,
            semi_supervised_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_dns_stream = publish.conn.accept_uni().await.unwrap();

        let dns_start_msg = receive_semi_supervised_stream_start_message(&mut send_dns_stream)
            .await
            .unwrap();
        assert_eq!(dns_start_msg, NETWORK_STREAM_DNS);

        let send_dns_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_ONE, "dns");
        let dns_data = gen_conn_raw_event();
        send_direct_stream(
            &key,
            &dns_data,
            send_dns_time,
            SENSOR_SEMI_SUPERVISED_ONE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_dns_stream)
            .await
            .unwrap();
        assert_eq!(dns_data, recv_data[20..]);

        let send_dns_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_TWO, "dns");
        let dns_data = gen_conn_raw_event();
        send_direct_stream(
            &key,
            &dns_data,
            send_dns_time,
            SENSOR_SEMI_SUPERVISED_TWO,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_dns_stream)
            .await
            .unwrap();
        assert_eq!(dns_data, recv_data[20..]);

        // database dns network event for the Time Series Generator
        let send_dns_time = Utc::now().timestamp_nanos_opt().unwrap();
        let dns_data = insert_dns_raw_event(
            &dns_store,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            send_dns_time,
        );

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_DNS,
            TIME_SERIES_GENERATOR_TYPE,
            time_series_generator_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_dns_stream = publish.conn.accept_uni().await.unwrap();

        let dns_start_msg =
            receive_time_series_generator_stream_start_message(&mut send_dns_stream)
                .await
                .unwrap();
        assert_eq!(dns_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_dns_stream)
            .await
            .unwrap();
        assert_eq!(send_dns_time, recv_timestamp);
        assert_eq!(dns_data, recv_data);

        // direct dns network event for the Time Series Generator
        let send_dns_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_TIME_SERIES_GENERATOR_THREE, "dns");
        let dns_data = gen_dns_raw_event();

        send_direct_stream(
            &key,
            &dns_data,
            send_dns_time,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_dns_stream)
            .await
            .unwrap();
        assert_eq!(send_dns_time, recv_timestamp);
        assert_eq!(dns_data, recv_data);
    }

    {
        let rdp_store = db.rdp_store().unwrap();

        // direct rdp network event for the Semi-supervised Engine (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_RDP,
            SEMI_SUPERVISED_TYPE,
            semi_supervised_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_rdp_stream = publish.conn.accept_uni().await.unwrap();

        let rdp_start_msg = receive_semi_supervised_stream_start_message(&mut send_rdp_stream)
            .await
            .unwrap();
        assert_eq!(rdp_start_msg, NETWORK_STREAM_RDP);

        let send_rdp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_ONE, "rdp");
        let rdp_data = gen_conn_raw_event();
        send_direct_stream(
            &key,
            &rdp_data,
            send_rdp_time,
            SENSOR_SEMI_SUPERVISED_ONE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_rdp_stream)
            .await
            .unwrap();
        assert_eq!(rdp_data, recv_data[20..]);

        let send_rdp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_TWO, "rdp");
        let rdp_data = gen_conn_raw_event();
        send_direct_stream(
            &key,
            &rdp_data,
            send_rdp_time,
            SENSOR_SEMI_SUPERVISED_TWO,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_rdp_stream)
            .await
            .unwrap();
        assert_eq!(rdp_data, recv_data[20..]);

        // database rdp network event for the Time Series Generator
        let send_rdp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let rdp_data = insert_rdp_raw_event(
            &rdp_store,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            send_rdp_time,
        );

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_RDP,
            TIME_SERIES_GENERATOR_TYPE,
            time_series_generator_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_rdp_stream = publish.conn.accept_uni().await.unwrap();

        let rdp_start_msg =
            receive_time_series_generator_stream_start_message(&mut send_rdp_stream)
                .await
                .unwrap();
        assert_eq!(rdp_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_rdp_stream)
            .await
            .unwrap();
        assert_eq!(send_rdp_time, recv_timestamp);
        assert_eq!(rdp_data, recv_data);

        // direct rdp network event for the Time Series Generator
        let send_rdp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_TIME_SERIES_GENERATOR_THREE, "rdp");
        let rdp_data = gen_rdp_raw_event();
        send_direct_stream(
            &key,
            &rdp_data,
            send_rdp_time,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_rdp_stream)
            .await
            .unwrap();
        assert_eq!(send_rdp_time, recv_timestamp);
        assert_eq!(rdp_data, recv_data);
    }

    {
        let http_store = db.http_store().unwrap();

        // direct http network event for the Semi-supervised Engine (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_HTTP,
            SEMI_SUPERVISED_TYPE,
            semi_supervised_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_http_stream = publish.conn.accept_uni().await.unwrap();

        let http_start_msg = receive_semi_supervised_stream_start_message(&mut send_http_stream)
            .await
            .unwrap();
        assert_eq!(http_start_msg, NETWORK_STREAM_HTTP);

        let send_http_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_ONE, "http");
        let http_data = gen_conn_raw_event();

        send_direct_stream(
            &key,
            &http_data,
            send_http_time,
            SENSOR_SEMI_SUPERVISED_ONE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_http_stream)
            .await
            .unwrap();
        assert_eq!(http_data, recv_data[20..]);

        let send_http_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_TWO, "http");
        let http_data = gen_conn_raw_event();

        send_direct_stream(
            &key,
            &http_data,
            send_http_time,
            SENSOR_SEMI_SUPERVISED_TWO,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_http_stream)
            .await
            .unwrap();
        assert_eq!(http_data, recv_data[20..]);

        // database http network event for the Time Series Generator
        let send_http_time = Utc::now().timestamp_nanos_opt().unwrap();
        let http_data = insert_http_raw_event(
            &http_store,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            send_http_time,
        );

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_HTTP,
            TIME_SERIES_GENERATOR_TYPE,
            time_series_generator_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_http_stream = publish.conn.accept_uni().await.unwrap();

        let http_start_msg =
            receive_time_series_generator_stream_start_message(&mut send_http_stream)
                .await
                .unwrap();
        assert_eq!(http_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_http_stream)
            .await
            .unwrap();
        assert_eq!(send_http_time, recv_timestamp);
        assert_eq!(http_data, recv_data);

        // direct http network event for the Time Series Generator
        let send_http_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_TIME_SERIES_GENERATOR_THREE, "http");
        let http_data = gen_http_raw_event();
        send_direct_stream(
            &key,
            &http_data,
            send_http_time,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_http_stream)
            .await
            .unwrap();
        assert_eq!(send_http_time, recv_timestamp);
        assert_eq!(http_data, recv_data);
    }

    {
        let smtp_store = db.smtp_store().unwrap();

        // direct smtp network event for the Semi-supervised Engine (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_SMTP,
            SEMI_SUPERVISED_TYPE,
            semi_supervised_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_smtp_stream = publish.conn.accept_uni().await.unwrap();

        let smtp_start_msg = receive_semi_supervised_stream_start_message(&mut send_smtp_stream)
            .await
            .unwrap();
        assert_eq!(smtp_start_msg, NETWORK_STREAM_SMTP);

        let send_smtp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_ONE, "smtp");
        let smtp_data = gen_smtp_raw_event();

        send_direct_stream(
            &key,
            &smtp_data,
            send_smtp_time,
            SENSOR_SEMI_SUPERVISED_ONE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_smtp_stream)
            .await
            .unwrap();
        assert_eq!(smtp_data, recv_data[20..]);

        let send_smtp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_TWO, "smtp");
        let smtp_data = gen_smtp_raw_event();

        send_direct_stream(
            &key,
            &smtp_data,
            send_smtp_time,
            SENSOR_SEMI_SUPERVISED_TWO,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_smtp_stream)
            .await
            .unwrap();
        assert_eq!(smtp_data, recv_data[20..]);

        // database smtp network event for the Time Series Generator
        let send_smtp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let smtp_data = insert_smtp_raw_event(
            &smtp_store,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            send_smtp_time,
        );

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_SMTP,
            TIME_SERIES_GENERATOR_TYPE,
            time_series_generator_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_smtp_stream = publish.conn.accept_uni().await.unwrap();

        let smtp_start_msg =
            receive_time_series_generator_stream_start_message(&mut send_smtp_stream)
                .await
                .unwrap();
        assert_eq!(smtp_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_smtp_stream)
            .await
            .unwrap();
        assert_eq!(send_smtp_time, recv_timestamp);
        assert_eq!(smtp_data, recv_data);

        // direct smtp network event for the Time Series Generator
        let send_smtp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_TIME_SERIES_GENERATOR_THREE, "smtp");
        let smtp_data = gen_smtp_raw_event();
        send_direct_stream(
            &key,
            &smtp_data,
            send_smtp_time,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_smtp_stream)
            .await
            .unwrap();
        assert_eq!(send_smtp_time, recv_timestamp);
        assert_eq!(smtp_data, recv_data);
    }

    {
        let ntlm_store = db.ntlm_store().unwrap();

        // direct ntlm network event for the Semi-supervised Engine (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_NTLM,
            SEMI_SUPERVISED_TYPE,
            semi_supervised_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_ntlm_stream = publish.conn.accept_uni().await.unwrap();

        let ntlm_start_msg = receive_semi_supervised_stream_start_message(&mut send_ntlm_stream)
            .await
            .unwrap();
        assert_eq!(ntlm_start_msg, NETWORK_STREAM_NTLM);

        let send_ntlm_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_ONE, "ntlm");
        let ntlm_data = gen_ntlm_raw_event();

        send_direct_stream(
            &key,
            &ntlm_data,
            send_ntlm_time,
            SENSOR_SEMI_SUPERVISED_ONE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_ntlm_stream)
            .await
            .unwrap();
        assert_eq!(ntlm_data, recv_data[20..]);

        let send_ntlm_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_TWO, "ntlm");
        let ntlm_data = gen_ntlm_raw_event();

        send_direct_stream(
            &key,
            &ntlm_data,
            send_ntlm_time,
            SENSOR_SEMI_SUPERVISED_TWO,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_ntlm_stream)
            .await
            .unwrap();
        assert_eq!(ntlm_data, recv_data[20..]);

        // database ntlm network event for the Time Series Generator
        let send_ntlm_time = Utc::now().timestamp_nanos_opt().unwrap();
        let ntlm_data = insert_ntlm_raw_event(
            &ntlm_store,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            send_ntlm_time,
        );

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_NTLM,
            TIME_SERIES_GENERATOR_TYPE,
            time_series_generator_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_ntlm_stream = publish.conn.accept_uni().await.unwrap();

        let ntlm_start_msg =
            receive_time_series_generator_stream_start_message(&mut send_ntlm_stream)
                .await
                .unwrap();
        assert_eq!(ntlm_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_ntlm_stream)
            .await
            .unwrap();
        assert_eq!(send_ntlm_time, recv_timestamp);
        assert_eq!(ntlm_data, recv_data);

        // direct ntlm network event for the Time Series Generator
        let send_ntlm_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_TIME_SERIES_GENERATOR_THREE, "ntlm");
        let ntlm_data = gen_ntlm_raw_event();
        send_direct_stream(
            &key,
            &ntlm_data,
            send_ntlm_time,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_ntlm_stream)
            .await
            .unwrap();
        assert_eq!(send_ntlm_time, recv_timestamp);
        assert_eq!(ntlm_data, recv_data);
    }

    {
        let kerberos_store = db.kerberos_store().unwrap();

        // direct kerberos network event for the Semi-supervised Engine (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_KERBEROS,
            SEMI_SUPERVISED_TYPE,
            semi_supervised_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_kerberos_stream = publish.conn.accept_uni().await.unwrap();
        let kerberos_start_msg =
            receive_semi_supervised_stream_start_message(&mut send_kerberos_stream)
                .await
                .unwrap();
        assert_eq!(kerberos_start_msg, NETWORK_STREAM_KERBEROS);

        let send_kerberos_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_ONE, "kerberos");
        let kerberos_data = gen_kerberos_raw_event();

        send_direct_stream(
            &key,
            &kerberos_data,
            send_kerberos_time,
            SENSOR_SEMI_SUPERVISED_ONE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_kerberos_stream)
            .await
            .unwrap();
        assert_eq!(kerberos_data, recv_data[20..]);

        let send_kerberos_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_TWO, "kerberos");
        let kerberos_data = gen_kerberos_raw_event();

        send_direct_stream(
            &key,
            &kerberos_data,
            send_kerberos_time,
            SENSOR_SEMI_SUPERVISED_TWO,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_kerberos_stream)
            .await
            .unwrap();
        assert_eq!(kerberos_data, recv_data[20..]);

        // database kerberos network event for the Time Series Generator
        let send_kerberos_time = Utc::now().timestamp_nanos_opt().unwrap();
        let kerberos_data = insert_kerberos_raw_event(
            &kerberos_store,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            send_kerberos_time,
        );

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_KERBEROS,
            TIME_SERIES_GENERATOR_TYPE,
            time_series_generator_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_kerberos_stream = publish.conn.accept_uni().await.unwrap();

        let kerberos_start_msg =
            receive_time_series_generator_stream_start_message(&mut send_kerberos_stream)
                .await
                .unwrap();
        assert_eq!(kerberos_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) =
            receive_time_series_generator_data(&mut send_kerberos_stream)
                .await
                .unwrap();
        assert_eq!(send_kerberos_time, recv_timestamp);
        assert_eq!(kerberos_data, recv_data);

        // direct kerberos network event for the Time Series Generator
        let send_kerberos_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_TIME_SERIES_GENERATOR_THREE, "kerberos");
        let kerberos_data = gen_kerberos_raw_event();
        send_direct_stream(
            &key,
            &kerberos_data,
            send_kerberos_time,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) =
            receive_time_series_generator_data(&mut send_kerberos_stream)
                .await
                .unwrap();
        assert_eq!(send_kerberos_time, recv_timestamp);
        assert_eq!(kerberos_data, recv_data);
    }

    {
        let ssh_store = db.ssh_store().unwrap();

        // direct ssh network event for the Semi-supervised Engine (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_SSH,
            SEMI_SUPERVISED_TYPE,
            semi_supervised_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_ssh_stream = publish.conn.accept_uni().await.unwrap();

        let ssh_start_msg = receive_semi_supervised_stream_start_message(&mut send_ssh_stream)
            .await
            .unwrap();
        assert_eq!(ssh_start_msg, NETWORK_STREAM_SSH);

        let send_ssh_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_ONE, "ssh");
        let ssh_data = gen_ssh_raw_event();

        send_direct_stream(
            &key,
            &ssh_data,
            send_ssh_time,
            SENSOR_SEMI_SUPERVISED_ONE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_ssh_stream)
            .await
            .unwrap();
        assert_eq!(ssh_data, recv_data[20..]);

        let send_ssh_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_TWO, "ssh");
        let ssh_data = gen_ssh_raw_event();

        send_direct_stream(
            &key,
            &ssh_data,
            send_ssh_time,
            SENSOR_SEMI_SUPERVISED_TWO,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_ssh_stream)
            .await
            .unwrap();
        assert_eq!(ssh_data, recv_data[20..]);

        // database ssh network event for the Time Series Generator
        let send_ssh_time = Utc::now().timestamp_nanos_opt().unwrap();
        let ssh_data = insert_ssh_raw_event(
            &ssh_store,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            send_ssh_time,
        );

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_SSH,
            TIME_SERIES_GENERATOR_TYPE,
            time_series_generator_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_ssh_stream = publish.conn.accept_uni().await.unwrap();

        let ssh_start_msg =
            receive_time_series_generator_stream_start_message(&mut send_ssh_stream)
                .await
                .unwrap();
        assert_eq!(ssh_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_ssh_stream)
            .await
            .unwrap();
        assert_eq!(send_ssh_time, recv_timestamp);
        assert_eq!(ssh_data, recv_data);

        // direct ssh network event for the Time Series Generator
        let send_ssh_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_TIME_SERIES_GENERATOR_THREE, "ssh");
        let ssh_data = gen_ssh_raw_event();
        send_direct_stream(
            &key,
            &ssh_data,
            send_ssh_time,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_ssh_stream)
            .await
            .unwrap();
        assert_eq!(send_ssh_time, recv_timestamp);
        assert_eq!(ssh_data, recv_data);
    }

    {
        let dce_rpc_store = db.dce_rpc_store().unwrap();

        // direct dce_rpc network event for the Semi-supervised Engine (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_DCE_RPC,
            SEMI_SUPERVISED_TYPE,
            semi_supervised_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_dce_rpc_stream = publish.conn.accept_uni().await.unwrap();

        let dce_rpc_start_msg =
            receive_semi_supervised_stream_start_message(&mut send_dce_rpc_stream)
                .await
                .unwrap();
        assert_eq!(dce_rpc_start_msg, NETWORK_STREAM_DCE_RPC);

        let send_dce_rpc_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_ONE, "dce rpc");
        let dce_rpc_data = gen_dce_rpc_raw_event();

        send_direct_stream(
            &key,
            &dce_rpc_data,
            send_dce_rpc_time,
            SENSOR_SEMI_SUPERVISED_ONE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_dce_rpc_stream)
            .await
            .unwrap();
        assert_eq!(dce_rpc_data, recv_data[20..]);

        let send_dce_rpc_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_TWO, "dce rpc");
        let dce_rpc_data = gen_dce_rpc_raw_event();

        send_direct_stream(
            &key,
            &dce_rpc_data,
            send_dce_rpc_time,
            SENSOR_SEMI_SUPERVISED_TWO,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_dce_rpc_stream)
            .await
            .unwrap();
        assert_eq!(dce_rpc_data, recv_data[20..]);

        // database dce_rpc network event for the Time Series Generator
        let send_dce_rpc_time = Utc::now().timestamp_nanos_opt().unwrap();
        let dce_rpc_data = insert_dce_rpc_raw_event(
            &dce_rpc_store,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            send_dce_rpc_time,
        );

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_DCE_RPC,
            TIME_SERIES_GENERATOR_TYPE,
            time_series_generator_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_dce_rpc_stream = publish.conn.accept_uni().await.unwrap();

        let dce_rpc_start_msg =
            receive_time_series_generator_stream_start_message(&mut send_dce_rpc_stream)
                .await
                .unwrap();
        assert_eq!(dce_rpc_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) =
            receive_time_series_generator_data(&mut send_dce_rpc_stream)
                .await
                .unwrap();
        assert_eq!(send_dce_rpc_time, recv_timestamp);
        assert_eq!(dce_rpc_data, recv_data);

        // direct dce_rpc network event for the Time Series Generator
        let send_dce_rpc_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_TIME_SERIES_GENERATOR_THREE, "dce rpc");
        let dce_rpc_data = gen_dce_rpc_raw_event();
        send_direct_stream(
            &key,
            &dce_rpc_data,
            send_dce_rpc_time,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) =
            receive_time_series_generator_data(&mut send_dce_rpc_stream)
                .await
                .unwrap();
        assert_eq!(send_dce_rpc_time, recv_timestamp);
        assert_eq!(dce_rpc_data, recv_data);
    }

    {
        let ftp_store = db.ftp_store().unwrap();

        // direct ftp network event for the Semi-supervised Engine (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_FTP,
            SEMI_SUPERVISED_TYPE,
            semi_supervised_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_ftp_stream = publish.conn.accept_uni().await.unwrap();

        let ftp_start_msg = receive_semi_supervised_stream_start_message(&mut send_ftp_stream)
            .await
            .unwrap();
        assert_eq!(ftp_start_msg, NETWORK_STREAM_FTP);

        let send_ftp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_ONE, "ftp");
        let ftp_data = gen_ftp_raw_event();

        send_direct_stream(
            &key,
            &ftp_data,
            send_ftp_time,
            SENSOR_SEMI_SUPERVISED_ONE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_ftp_stream)
            .await
            .unwrap();
        assert_eq!(ftp_data, recv_data[20..]);

        let send_ftp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_TWO, "ftp");
        let ftp_data = gen_ftp_raw_event();

        send_direct_stream(
            &key,
            &ftp_data,
            send_ftp_time,
            SENSOR_SEMI_SUPERVISED_TWO,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_ftp_stream)
            .await
            .unwrap();
        assert_eq!(ftp_data, recv_data[20..]);

        // database ftp network event for the Time Series Generator
        let send_ftp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let ftp_data = insert_ftp_raw_event(
            &ftp_store,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            send_ftp_time,
        );

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_FTP,
            TIME_SERIES_GENERATOR_TYPE,
            time_series_generator_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_ftp_stream = publish.conn.accept_uni().await.unwrap();

        let ftp_start_msg =
            receive_time_series_generator_stream_start_message(&mut send_ftp_stream)
                .await
                .unwrap();
        assert_eq!(ftp_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_ftp_stream)
            .await
            .unwrap();
        assert_eq!(send_ftp_time, recv_timestamp);
        assert_eq!(ftp_data, recv_data);

        // direct ftp network event for the Time Series Generator
        let send_ftp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_TIME_SERIES_GENERATOR_THREE, "ftp");
        let ftp_data = gen_ftp_raw_event();
        send_direct_stream(
            &key,
            &ftp_data,
            send_ftp_time,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_ftp_stream)
            .await
            .unwrap();
        assert_eq!(send_ftp_time, recv_timestamp);
        assert_eq!(ftp_data, recv_data);
    }

    {
        let mqtt_store = db.mqtt_store().unwrap();

        // direct mqtt network event for the Semi-supervised Engine (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_MQTT,
            SEMI_SUPERVISED_TYPE,
            semi_supervised_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_mqtt_stream = publish.conn.accept_uni().await.unwrap();

        let mqtt_start_msg = receive_semi_supervised_stream_start_message(&mut send_mqtt_stream)
            .await
            .unwrap();
        assert_eq!(mqtt_start_msg, NETWORK_STREAM_MQTT);

        let send_mqtt_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_ONE, "mqtt");
        let mqtt_data = gen_mqtt_raw_event();

        send_direct_stream(
            &key,
            &mqtt_data,
            send_mqtt_time,
            SENSOR_SEMI_SUPERVISED_ONE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_mqtt_stream)
            .await
            .unwrap();
        assert_eq!(mqtt_data, recv_data[20..]);

        let send_mqtt_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_TWO, "mqtt");
        let mqtt_data = gen_mqtt_raw_event();

        send_direct_stream(
            &key,
            &mqtt_data,
            send_mqtt_time,
            SENSOR_SEMI_SUPERVISED_TWO,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_mqtt_stream)
            .await
            .unwrap();
        assert_eq!(mqtt_data, recv_data[20..]);

        // database mqtt network event for the Time Series Generator
        let send_mqtt_time = Utc::now().timestamp_nanos_opt().unwrap();
        let mqtt_data = insert_mqtt_raw_event(
            &mqtt_store,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            send_mqtt_time,
        );

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_MQTT,
            TIME_SERIES_GENERATOR_TYPE,
            time_series_generator_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_mqtt_stream = publish.conn.accept_uni().await.unwrap();

        let mqtt_start_msg =
            receive_time_series_generator_stream_start_message(&mut send_mqtt_stream)
                .await
                .unwrap();
        assert_eq!(mqtt_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_mqtt_stream)
            .await
            .unwrap();
        assert_eq!(send_mqtt_time, recv_timestamp);
        assert_eq!(mqtt_data, recv_data);

        // direct mqtt network event for the Time Series Generator
        let send_mqtt_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_TIME_SERIES_GENERATOR_THREE, "mqtt");
        let mqtt_data = gen_mqtt_raw_event();
        send_direct_stream(
            &key,
            &mqtt_data,
            send_mqtt_time,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_mqtt_stream)
            .await
            .unwrap();
        assert_eq!(send_mqtt_time, recv_timestamp);
        assert_eq!(mqtt_data, recv_data);
    }

    {
        let ldap_store = db.ldap_store().unwrap();

        // direct ldap network event for the Semi-supervised Engine (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_LDAP,
            SEMI_SUPERVISED_TYPE,
            semi_supervised_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_ldap_stream = publish.conn.accept_uni().await.unwrap();

        let ldap_start_msg = receive_semi_supervised_stream_start_message(&mut send_ldap_stream)
            .await
            .unwrap();
        assert_eq!(ldap_start_msg, NETWORK_STREAM_LDAP);

        let send_ldap_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_ONE, "ldap");
        let ldap_data = gen_ldap_raw_event();

        send_direct_stream(
            &key,
            &ldap_data,
            send_ldap_time,
            SENSOR_SEMI_SUPERVISED_ONE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_ldap_stream)
            .await
            .unwrap();
        assert_eq!(ldap_data, recv_data[20..]);

        let send_ldap_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_TWO, "ldap");
        let ldap_data = gen_ldap_raw_event();

        send_direct_stream(
            &key,
            &ldap_data,
            send_ldap_time,
            SENSOR_SEMI_SUPERVISED_TWO,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_ldap_stream)
            .await
            .unwrap();
        assert_eq!(ldap_data, recv_data[20..]);

        // database ldap network event for the Time Series Generator
        let send_ldap_time = Utc::now().timestamp_nanos_opt().unwrap();
        let ldap_data = insert_ldap_raw_event(
            &ldap_store,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            send_ldap_time,
        );

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_LDAP,
            TIME_SERIES_GENERATOR_TYPE,
            time_series_generator_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_ldap_stream = publish.conn.accept_uni().await.unwrap();

        let ldap_start_msg =
            receive_time_series_generator_stream_start_message(&mut send_ldap_stream)
                .await
                .unwrap();
        assert_eq!(ldap_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_ldap_stream)
            .await
            .unwrap();
        assert_eq!(send_ldap_time, recv_timestamp);
        assert_eq!(ldap_data, recv_data);

        // direct ldap network event for the Time Series Generator
        let send_ldap_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_TIME_SERIES_GENERATOR_THREE, "ldap");
        let ldap_data = gen_ldap_raw_event();
        send_direct_stream(
            &key,
            &ldap_data,
            send_ldap_time,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_ldap_stream)
            .await
            .unwrap();
        assert_eq!(send_ldap_time, recv_timestamp);
        assert_eq!(ldap_data, recv_data);
    }

    {
        let tls_store = db.tls_store().unwrap();

        // direct tls network event for the Semi-supervised Engine (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_TLS,
            SEMI_SUPERVISED_TYPE,
            semi_supervised_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_tls_stream = publish.conn.accept_uni().await.unwrap();

        let tls_start_msg = receive_semi_supervised_stream_start_message(&mut send_tls_stream)
            .await
            .unwrap();
        assert_eq!(tls_start_msg, NETWORK_STREAM_TLS);

        let send_tls_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_ONE, "tls");
        let tls_data = gen_tls_raw_event();

        send_direct_stream(
            &key,
            &tls_data,
            send_tls_time,
            SENSOR_SEMI_SUPERVISED_ONE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_tls_stream)
            .await
            .unwrap();
        assert_eq!(tls_data, recv_data[20..]);

        let send_tls_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_TWO, "tls");
        let tls_data = gen_tls_raw_event();

        send_direct_stream(
            &key,
            &tls_data,
            send_tls_time,
            SENSOR_SEMI_SUPERVISED_TWO,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_tls_stream)
            .await
            .unwrap();
        assert_eq!(tls_data, recv_data[20..]);

        // database tls network event for the Time Series Generator
        let send_tls_time = Utc::now().timestamp_nanos_opt().unwrap();
        let tls_data = insert_tls_raw_event(
            &tls_store,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            send_tls_time,
        );

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_TLS,
            TIME_SERIES_GENERATOR_TYPE,
            time_series_generator_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_tls_stream = publish.conn.accept_uni().await.unwrap();

        let tls_start_msg =
            receive_time_series_generator_stream_start_message(&mut send_tls_stream)
                .await
                .unwrap();
        assert_eq!(tls_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_tls_stream)
            .await
            .unwrap();
        assert_eq!(send_tls_time, recv_timestamp);
        assert_eq!(tls_data, recv_data);

        // direct tls network event for the Time Series Generator
        let send_tls_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_TIME_SERIES_GENERATOR_THREE, "tls");
        let tls_data = gen_tls_raw_event();
        send_direct_stream(
            &key,
            &tls_data,
            send_tls_time,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_tls_stream)
            .await
            .unwrap();
        assert_eq!(send_tls_time, recv_timestamp);
        assert_eq!(tls_data, recv_data);
    }

    {
        let smb_store = db.smb_store().unwrap();

        // direct smb network event for the Semi-supervised Engine (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_SMB,
            SEMI_SUPERVISED_TYPE,
            semi_supervised_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_smb_stream = publish.conn.accept_uni().await.unwrap();

        let smb_start_msg = receive_semi_supervised_stream_start_message(&mut send_smb_stream)
            .await
            .unwrap();
        assert_eq!(smb_start_msg, NETWORK_STREAM_SMB);

        let send_smb_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_ONE, "smb");
        let smb_data = gen_smb_raw_event();

        send_direct_stream(
            &key,
            &smb_data,
            send_smb_time,
            SENSOR_SEMI_SUPERVISED_ONE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_smb_stream)
            .await
            .unwrap();
        assert_eq!(smb_data, recv_data[20..]);

        let send_smb_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_TWO, "smb");
        let smb_data = gen_smb_raw_event();

        send_direct_stream(
            &key,
            &smb_data,
            send_smb_time,
            SENSOR_SEMI_SUPERVISED_TWO,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_smb_stream)
            .await
            .unwrap();
        assert_eq!(smb_data, recv_data[20..]);

        // database smb network event for the Time Series Generator
        let send_smb_time = Utc::now().timestamp_nanos_opt().unwrap();
        let smb_data = insert_smb_raw_event(
            &smb_store,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            send_smb_time,
        );

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_SMB,
            TIME_SERIES_GENERATOR_TYPE,
            time_series_generator_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_smb_stream = publish.conn.accept_uni().await.unwrap();

        let smb_start_msg =
            receive_time_series_generator_stream_start_message(&mut send_smb_stream)
                .await
                .unwrap();
        assert_eq!(smb_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_smb_stream)
            .await
            .unwrap();
        assert_eq!(send_smb_time, recv_timestamp);
        assert_eq!(smb_data, recv_data);

        // direct smb network event for the Time Series Generator
        let send_smb_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_TIME_SERIES_GENERATOR_THREE, "smb");
        let smb_data = gen_smb_raw_event();
        send_direct_stream(
            &key,
            &smb_data,
            send_smb_time,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_smb_stream)
            .await
            .unwrap();
        assert_eq!(send_smb_time, recv_timestamp);
        assert_eq!(smb_data, recv_data);
    }

    {
        let nfs_store = db.nfs_store().unwrap();

        // direct nfs network event for the Semi-supervised Engine (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_NFS,
            SEMI_SUPERVISED_TYPE,
            semi_supervised_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_nfs_stream = publish.conn.accept_uni().await.unwrap();

        let nfs_start_msg = receive_semi_supervised_stream_start_message(&mut send_nfs_stream)
            .await
            .unwrap();
        assert_eq!(nfs_start_msg, NETWORK_STREAM_NFS);

        let send_nfs_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_ONE, "nfs");
        let nfs_data = gen_nfs_raw_event();

        send_direct_stream(
            &key,
            &nfs_data,
            send_nfs_time,
            SENSOR_SEMI_SUPERVISED_ONE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_nfs_stream)
            .await
            .unwrap();
        assert_eq!(nfs_data, recv_data[20..]);

        let send_nfs_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_TWO, "nfs");
        let nfs_data = gen_nfs_raw_event();

        send_direct_stream(
            &key,
            &nfs_data,
            send_nfs_time,
            SENSOR_SEMI_SUPERVISED_TWO,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_nfs_stream)
            .await
            .unwrap();
        assert_eq!(nfs_data, recv_data[20..]);

        // database nfs network event for the Time Series Generator
        let send_nfs_time = Utc::now().timestamp_nanos_opt().unwrap();
        let nfs_data = insert_nfs_raw_event(
            &nfs_store,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            send_nfs_time,
        );

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_NFS,
            TIME_SERIES_GENERATOR_TYPE,
            time_series_generator_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_nfs_stream = publish.conn.accept_uni().await.unwrap();

        let nfs_start_msg =
            receive_time_series_generator_stream_start_message(&mut send_nfs_stream)
                .await
                .unwrap();
        assert_eq!(nfs_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_nfs_stream)
            .await
            .unwrap();
        assert_eq!(send_nfs_time, recv_timestamp);
        assert_eq!(nfs_data, recv_data);

        // direct nfs network event for the Time Series Generator
        let send_nfs_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_TIME_SERIES_GENERATOR_THREE, "nfs");
        let nfs_data = gen_nfs_raw_event();
        send_direct_stream(
            &key,
            &nfs_data,
            send_nfs_time,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_nfs_stream)
            .await
            .unwrap();
        assert_eq!(send_nfs_time, recv_timestamp);
        assert_eq!(nfs_data, recv_data);
    }

    {
        let bootp_store = db.bootp_store().unwrap();

        // direct bootp network event for the Semi-supervised Engine (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_BOOTP,
            SEMI_SUPERVISED_TYPE,
            semi_supervised_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_bootp_stream = publish.conn.accept_uni().await.unwrap();

        let bootp_start_msg = receive_semi_supervised_stream_start_message(&mut send_bootp_stream)
            .await
            .unwrap();
        assert_eq!(bootp_start_msg, NETWORK_STREAM_BOOTP);

        let send_bootp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_ONE, "bootp");
        let bootp_data = gen_bootp_raw_event();

        send_direct_stream(
            &key,
            &bootp_data,
            send_bootp_time,
            SENSOR_SEMI_SUPERVISED_ONE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_bootp_stream)
            .await
            .unwrap();
        assert_eq!(bootp_data, recv_data[20..]);

        let send_bootp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_TWO, "bootp");
        let bootp_data = gen_bootp_raw_event();

        send_direct_stream(
            &key,
            &bootp_data,
            send_bootp_time,
            SENSOR_SEMI_SUPERVISED_TWO,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_bootp_stream)
            .await
            .unwrap();
        assert_eq!(bootp_data, recv_data[20..]);

        // database bootp network event for the Time Series Generator
        let send_bootp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let bootp_data = insert_bootp_raw_event(
            &bootp_store,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            send_bootp_time,
        );

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_BOOTP,
            TIME_SERIES_GENERATOR_TYPE,
            time_series_generator_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_bootp_stream = publish.conn.accept_uni().await.unwrap();

        let bootp_start_msg =
            receive_time_series_generator_stream_start_message(&mut send_bootp_stream)
                .await
                .unwrap();
        assert_eq!(bootp_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) =
            receive_time_series_generator_data(&mut send_bootp_stream)
                .await
                .unwrap();
        assert_eq!(send_bootp_time, recv_timestamp);
        assert_eq!(bootp_data, recv_data);

        // direct bootp network event for the Time Series Generator
        let send_bootp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_TIME_SERIES_GENERATOR_THREE, "bootp");
        let bootp_data = gen_bootp_raw_event();
        send_direct_stream(
            &key,
            &bootp_data,
            send_bootp_time,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) =
            receive_time_series_generator_data(&mut send_bootp_stream)
                .await
                .unwrap();
        assert_eq!(send_bootp_time, recv_timestamp);
        assert_eq!(bootp_data, recv_data);
    }

    {
        let dhcp_store = db.dhcp_store().unwrap();

        // direct dhcp network event for the Semi-supervised Engine (src1,src2)
        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_DHCP,
            SEMI_SUPERVISED_TYPE,
            semi_supervised_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_dhcp_stream = publish.conn.accept_uni().await.unwrap();

        let dhcp_start_msg = receive_semi_supervised_stream_start_message(&mut send_dhcp_stream)
            .await
            .unwrap();
        assert_eq!(dhcp_start_msg, NETWORK_STREAM_DHCP);

        let send_dhcp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_ONE, "dhcp");
        let dhcp_data = gen_dhcp_raw_event();

        send_direct_stream(
            &key,
            &dhcp_data,
            send_dhcp_time,
            SENSOR_SEMI_SUPERVISED_ONE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_dhcp_stream)
            .await
            .unwrap();
        assert_eq!(dhcp_data, recv_data[20..]);

        let send_dhcp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_SEMI_SUPERVISED_TWO, "dhcp");
        let dhcp_data = gen_dhcp_raw_event();

        send_direct_stream(
            &key,
            &dhcp_data,
            send_dhcp_time,
            SENSOR_SEMI_SUPERVISED_TWO,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let recv_data = receive_semi_supervised_data(&mut send_dhcp_stream)
            .await
            .unwrap();
        assert_eq!(dhcp_data, recv_data[20..]);

        // database dhcp network event for the Time Series Generator
        let send_dhcp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let dhcp_data = insert_dhcp_raw_event(
            &dhcp_store,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            send_dhcp_time,
        );

        send_stream_request(
            &mut publish.send,
            NETWORK_STREAM_DHCP,
            TIME_SERIES_GENERATOR_TYPE,
            time_series_generator_msg.clone(),
        )
        .await
        .unwrap();

        let mut send_dhcp_stream = publish.conn.accept_uni().await.unwrap();

        let dhcp_start_msg =
            receive_time_series_generator_stream_start_message(&mut send_dhcp_stream)
                .await
                .unwrap();
        assert_eq!(dhcp_start_msg, POLICY_ID);

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_dhcp_stream)
            .await
            .unwrap();
        assert_eq!(send_dhcp_time, recv_timestamp);
        assert_eq!(dhcp_data, recv_data);

        // direct dhcp network event for the Time Series Generator
        let send_dhcp_time = Utc::now().timestamp_nanos_opt().unwrap();
        let key = NetworkKey::new(SENSOR_TIME_SERIES_GENERATOR_THREE, "dhcp");
        let dhcp_data = gen_dhcp_raw_event();
        send_direct_stream(
            &key,
            &dhcp_data,
            send_dhcp_time,
            SENSOR_TIME_SERIES_GENERATOR_THREE,
            stream_direct_channels.clone(),
        )
        .await
        .unwrap();

        let (recv_data, recv_timestamp) = receive_time_series_generator_data(&mut send_dhcp_stream)
            .await
            .unwrap();
        assert_eq!(send_dhcp_time, recv_timestamp);
        assert_eq!(dhcp_data, recv_data);
    }

    publish.conn.close(0u32.into(), b"publish_time_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
async fn request_raw_events() {
    const SENSOR: &str = "src 1";
    const KIND: &str = "conn";
    const TIMESTAMP: i64 = 100;

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let pcap_sensors = new_pcap_sensors();
    let stream_direct_channels = new_stream_direct_channels();
    let ingest_sensors = Arc::new(tokio::sync::RwLock::new(
        NODE1_GIGANTO_INGEST_SENSORS
            .into_iter()
            .map(str::to_string)
            .collect::<HashSet<String>>(),
    ));
    let (peers, peer_idents) = new_peers_data(None);

    let cert_pem = fs::read(NODE1_CERT_PATH).unwrap();
    let cert = to_cert_chain(&cert_pem).unwrap();
    let key_pem = fs::read(NODE1_KEY_PATH).unwrap();
    let key = to_private_key(&key_pem).unwrap();
    let ca_cert_path = vec![CA_CERT_PATH.to_string()];
    let root = to_root_cert(&ca_cert_path).unwrap();

    let certs = Arc::new(Certs {
        certs: cert,
        key,
        root,
    });

    tokio::spawn(server().run(
        db.clone(),
        pcap_sensors,
        stream_direct_channels,
        ingest_sensors,
        peers,
        peer_idents,
        certs,
        Arc::new(Notify::new()),
    ));
    let publish = TestClient::new().await;

    let (mut send_pub_req, mut recv_pub_resp) =
        publish.conn.open_bi().await.expect("failed to open stream");

    let conn_store = db.conn_store().unwrap();
    let send_conn_time = TIMESTAMP;
    let conn_raw_data = insert_conn_raw_event(&conn_store, SENSOR, send_conn_time);
    let conn_data = bincode::deserialize::<Conn>(&conn_raw_data).unwrap();
    let raw_data = conn_data.response_data(TIMESTAMP, SENSOR).unwrap();

    let message = RequestRawData {
        kind: String::from(KIND),
        input: vec![(String::from(SENSOR), vec![TIMESTAMP])],
    };

    send_range_data_request(&mut send_pub_req, MessageCode::RawData, message)
        .await
        .unwrap();

    let mut result_data = vec![];
    loop {
        let resp_data = receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
            .await
            .unwrap();

        if let Some(data) = resp_data {
            result_data.push(data);
        } else {
            break;
        }
    }
    assert_eq!(result_data.len(), 1);
    assert_eq!(result_data[0].0, TIMESTAMP);
    assert_eq!(&result_data[0].1, SENSOR);
    assert_eq!(
        raw_data,
        bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop()).unwrap()
    );
}

#[tokio::test]
#[serial]
async fn request_range_data_with_protocol_giganto_cluster() {
    const PUBLISH_RANGE_MESSAGE_CODE: MessageCode = MessageCode::ReqRange;
    const SENSOR: &str = "ingest src 2";
    const CONN_KIND: &str = "conn";

    let (oneshot_send, oneshot_recv) = tokio::sync::oneshot::channel();

    // spawn node2 publish server
    tokio::spawn(async {
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
        let pcap_sensors = new_pcap_sensors();
        let stream_direct_channels = new_stream_direct_channels();
        let ingest_sensors = Arc::new(tokio::sync::RwLock::new(
            NODE2_GIGANTO_INGEST_SENSORS
                .into_iter()
                .map(str::to_string)
                .collect::<HashSet<String>>(),
        ));

        let cert_pem = fs::read(NODE2_CERT_PATH).unwrap();
        let cert = to_cert_chain(&cert_pem).unwrap();
        let key_pem = fs::read(NODE2_KEY_PATH).unwrap();
        let key = to_private_key(&key_pem).unwrap();
        let ca_cert_path = vec![CA_CERT_PATH.to_string()];
        let root = to_root_cert(&ca_cert_path).unwrap();
        let certs = Arc::new(Certs {
            certs: cert,
            key,
            root,
        });

        let peers = Arc::new(tokio::sync::RwLock::new(HashMap::from([(
            Ipv6Addr::LOCALHOST.to_string(),
            PeerInfo {
                ingest_sensors: NODE1_GIGANTO_INGEST_SENSORS
                    .into_iter()
                    .map(str::to_string)
                    .collect::<HashSet<String>>(),
                graphql_port: None,
                publish_port: Some(NODE1_TEST_PORT),
            },
        )])));

        let mut peer_identities = HashSet::new();
        peer_identities.insert(PeerIdentity {
            addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), NODE1_TEST_PORT),
            hostname: NODE1_HOST.to_string(),
        });
        let peer_idents = Arc::new(RwLock::new(peer_identities));

        let notify_shutdown = Arc::new(Notify::new());

        // prepare data in node2 database
        let conn_store = db.conn_store().unwrap();
        let send_conn_time = Utc::now().timestamp_nanos_opt().unwrap();
        let conn_data = bincode::deserialize::<Conn>(&insert_conn_raw_event(
            &conn_store,
            SENSOR,
            send_conn_time,
        ))
        .unwrap();

        if oneshot_send
            .send(conn_data.response_data(send_conn_time, SENSOR).unwrap())
            .is_err()
        {
            eprintln!("the receiver is dropped");
        }

        let node2_server = Server::new(
            SocketAddr::new("127.0.0.1".parse::<IpAddr>().unwrap(), NODE2_PORT),
            &certs,
        );
        node2_server
            .run(
                db,
                pcap_sensors,
                stream_direct_channels,
                ingest_sensors,
                peers,
                peer_idents,
                certs,
                notify_shutdown,
            )
            .await;
    });

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let pcap_sensors = new_pcap_sensors();
    let stream_direct_channels = new_stream_direct_channels();
    let ingest_sensors = Arc::new(tokio::sync::RwLock::new(
        NODE1_GIGANTO_INGEST_SENSORS
            .into_iter()
            .map(str::to_string)
            .collect::<HashSet<String>>(),
    ));

    let peers = Arc::new(tokio::sync::RwLock::new(HashMap::from([(
        "127.0.0.1".to_string(),
        PeerInfo {
            ingest_sensors: NODE2_GIGANTO_INGEST_SENSORS
                .into_iter()
                .map(str::to_string)
                .collect::<HashSet<String>>(),
            graphql_port: None,
            publish_port: Some(NODE2_PORT),
        },
    )])));
    let mut peer_identities = HashSet::new();
    let addr_to_peers = SocketAddr::new("127.0.0.1".parse::<IpAddr>().unwrap(), NODE2_PORT);
    peer_identities.insert(PeerIdentity {
        addr: addr_to_peers,
        hostname: NODE2_HOST.to_string(),
    });
    let peer_idents = Arc::new(RwLock::new(peer_identities));

    let cert_pem = fs::read(NODE1_CERT_PATH).unwrap();
    let cert = to_cert_chain(&cert_pem).unwrap();
    let key_pem = fs::read(NODE1_KEY_PATH).unwrap();
    let key = to_private_key(&key_pem).unwrap();
    let ca_cert_path = vec![CA_CERT_PATH.to_string()];
    let root = to_root_cert(&ca_cert_path).unwrap();

    let certs = Arc::new(Certs {
        certs: cert,
        key,
        root,
    });

    tokio::spawn(server().run(
        db.clone(),
        pcap_sensors,
        stream_direct_channels,
        ingest_sensors,
        peers,
        peer_idents,
        certs,
        Arc::new(Notify::new()),
    ));

    let publish = TestClient::new().await;

    let (mut send_pub_req, mut recv_pub_resp) =
        publish.conn.open_bi().await.expect("failed to open stream");

    let start = DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDate::from_ymd_opt(1970, 1, 1)
            .expect("valid date")
            .and_hms_opt(00, 00, 00)
            .expect("valid time"),
        Utc,
    );
    let end = DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDate::from_ymd_opt(2050, 12, 31)
            .expect("valid date")
            .and_hms_opt(23, 59, 59)
            .expect("valid time"),
        Utc,
    );
    let message = RequestRange {
        sensor: String::from(SENSOR),
        kind: String::from(CONN_KIND),
        start: start.timestamp_nanos_opt().unwrap(),
        end: end.timestamp_nanos_opt().unwrap(),
        count: 5,
    };

    send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
        .await
        .unwrap();

    let mut result_data = Vec::new();
    loop {
        let resp_data = receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
            .await
            .unwrap();

        result_data.push(resp_data.clone());
        if resp_data.is_none() {
            break;
        }
    }

    let raw_data = if let Ok(v) = oneshot_recv.await {
        v
    } else {
        eprintln!("the sender dropped");
        Vec::new()
    };

    assert_eq!(
        Conn::response_done().unwrap(),
        bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap()).unwrap()
    );
    assert_eq!(
        raw_data,
        bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap()).unwrap()
    );

    publish.conn.close(0u32.into(), b"publish_time_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
#[serial]
async fn request_range_data_with_log_giganto_cluster() {
    const PUBLISH_RANGE_MESSAGE_CODE: MessageCode = MessageCode::ReqRange;
    const SENSOR: &str = "src2";
    const KIND: &str = "Hello";

    let (oneshot_send, oneshot_recv) = tokio::sync::oneshot::channel();

    // spawn node2 publish server
    tokio::spawn(async {
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
        let pcap_sensors = new_pcap_sensors();
        let stream_direct_channels = new_stream_direct_channels();
        let ingest_sensors = Arc::new(tokio::sync::RwLock::new(
            NODE2_GIGANTO_INGEST_SENSORS
                .into_iter()
                .map(str::to_string)
                .collect::<HashSet<String>>(),
        ));

        let cert_pem = fs::read(NODE2_CERT_PATH).unwrap();
        let cert = to_cert_chain(&cert_pem).unwrap();
        let key_pem = fs::read(NODE2_KEY_PATH).unwrap();
        let key = to_private_key(&key_pem).unwrap();
        let ca_cert_path = vec![CA_CERT_PATH.to_string()];
        let root = to_root_cert(&ca_cert_path).unwrap();
        let certs = Arc::new(Certs {
            certs: cert,
            key,
            root,
        });

        let peers = Arc::new(tokio::sync::RwLock::new(HashMap::from([(
            Ipv6Addr::LOCALHOST.to_string(),
            PeerInfo {
                ingest_sensors: NODE1_GIGANTO_INGEST_SENSORS
                    .into_iter()
                    .map(str::to_string)
                    .collect::<HashSet<String>>(),
                graphql_port: None,
                publish_port: Some(NODE1_TEST_PORT),
            },
        )])));

        let mut peer_identities = HashSet::new();
        peer_identities.insert(PeerIdentity {
            addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), NODE1_TEST_PORT),
            hostname: NODE1_HOST.to_string(),
        });
        let peer_idents = Arc::new(RwLock::new(peer_identities));

        let notify_shutdown = Arc::new(Notify::new());

        // prepare data in node2 database
        let log_store = db.log_store().unwrap();
        let send_log_time = Utc::now().timestamp_nanos_opt().unwrap();
        let log_data = bincode::deserialize::<Log>(&insert_log_raw_event(
            &log_store,
            SENSOR,
            KIND,
            send_log_time,
        ))
        .unwrap();

        if oneshot_send
            .send(log_data.response_data(send_log_time, SENSOR).unwrap())
            .is_err()
        {
            eprintln!("the receiver is dropped");
        }

        let node2_server = Server::new(
            SocketAddr::new("127.0.0.1".parse::<IpAddr>().unwrap(), NODE2_PORT),
            &certs,
        );
        node2_server
            .run(
                db,
                pcap_sensors,
                stream_direct_channels,
                ingest_sensors,
                peers,
                peer_idents,
                certs,
                notify_shutdown,
            )
            .await;
    });

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let pcap_sensors = new_pcap_sensors();
    let stream_direct_channels = new_stream_direct_channels();
    let ingest_sensors = Arc::new(tokio::sync::RwLock::new(
        NODE1_GIGANTO_INGEST_SENSORS
            .into_iter()
            .map(str::to_string)
            .collect::<HashSet<String>>(),
    ));

    let peers = Arc::new(tokio::sync::RwLock::new(HashMap::from([(
        "127.0.0.1".to_string(),
        PeerInfo {
            ingest_sensors: NODE2_GIGANTO_INGEST_SENSORS
                .into_iter()
                .map(str::to_string)
                .collect::<HashSet<String>>(),
            graphql_port: None,
            publish_port: Some(NODE2_PORT),
        },
    )])));
    let mut peer_identities = HashSet::new();
    let addr_to_peers = SocketAddr::new("127.0.0.1".parse::<IpAddr>().unwrap(), NODE2_PORT);
    peer_identities.insert(PeerIdentity {
        addr: addr_to_peers,
        hostname: NODE2_HOST.to_string(),
    });
    let peer_idents = Arc::new(RwLock::new(peer_identities));

    let cert_pem = fs::read(NODE1_CERT_PATH).unwrap();
    let cert = to_cert_chain(&cert_pem).unwrap();
    let key_pem = fs::read(NODE1_KEY_PATH).unwrap();
    let key = to_private_key(&key_pem).unwrap();
    let ca_cert_path = vec![CA_CERT_PATH.to_string()];
    let root = to_root_cert(&ca_cert_path).unwrap();

    let certs = Arc::new(Certs {
        certs: cert,
        key,
        root,
    });

    tokio::spawn(server().run(
        db.clone(),
        pcap_sensors,
        stream_direct_channels,
        ingest_sensors,
        peers,
        peer_idents,
        certs,
        Arc::new(Notify::new()),
    ));
    let publish = TestClient::new().await;
    let (mut send_pub_req, mut recv_pub_resp) =
        publish.conn.open_bi().await.expect("failed to open stream");

    let start = DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDate::from_ymd_opt(1970, 1, 1)
            .expect("valid date")
            .and_hms_opt(00, 00, 00)
            .expect("valid time"),
        Utc,
    );
    let end = DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDate::from_ymd_opt(2050, 12, 31)
            .expect("valid date")
            .and_hms_opt(23, 59, 59)
            .expect("valid time"),
        Utc,
    );
    let message = RequestRange {
        sensor: String::from(SENSOR),
        kind: String::from(KIND),
        start: start.timestamp_nanos_opt().unwrap(),
        end: end.timestamp_nanos_opt().unwrap(),
        count: 5,
    };

    send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
        .await
        .unwrap();

    let mut result_data = Vec::new();
    loop {
        let resp_data = receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
            .await
            .unwrap();

        result_data.push(resp_data.clone());
        if resp_data.is_none() {
            break;
        }
    }

    let raw_data = if let Ok(v) = oneshot_recv.await {
        v
    } else {
        eprintln!("the sender dropped");
        Vec::new()
    };

    assert_eq!(
        Conn::response_done().unwrap(),
        bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap()).unwrap()
    );
    assert_eq!(
        raw_data,
        bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop().unwrap()).unwrap()
    );

    publish.conn.close(0u32.into(), b"publish_log_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
#[serial]
async fn request_range_data_with_period_time_series_giganto_cluster() {
    const PUBLISH_RANGE_MESSAGE_CODE: MessageCode = MessageCode::ReqRange;
    const SAMPLING_POLICY_ID_AS_SENSOR: &str = "ingest src 2";
    const KIND: &str = "timeseries";

    let (oneshot_send, oneshot_recv) = tokio::sync::oneshot::channel();

    // spawn node2 publish server
    tokio::spawn(async {
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
        let pcap_sensors = new_pcap_sensors();
        let stream_direct_channels = new_stream_direct_channels();
        let ingest_sensors = Arc::new(tokio::sync::RwLock::new(
            NODE2_GIGANTO_INGEST_SENSORS
                .into_iter()
                .map(str::to_string)
                .collect::<HashSet<String>>(),
        ));

        let cert_pem = fs::read(NODE2_CERT_PATH).unwrap();
        let cert = to_cert_chain(&cert_pem).unwrap();
        let key_pem = fs::read(NODE2_KEY_PATH).unwrap();
        let key = to_private_key(&key_pem).unwrap();
        let ca_cert_path = vec![CA_CERT_PATH.to_string()];
        let root = to_root_cert(&ca_cert_path).unwrap();
        let certs = Arc::new(Certs {
            certs: cert,
            key,
            root,
        });

        let peers = Arc::new(tokio::sync::RwLock::new(HashMap::from([(
            Ipv6Addr::LOCALHOST.to_string(),
            PeerInfo {
                ingest_sensors: NODE1_GIGANTO_INGEST_SENSORS
                    .into_iter()
                    .map(str::to_string)
                    .collect::<HashSet<String>>(),
                graphql_port: None,
                publish_port: Some(NODE1_TEST_PORT),
            },
        )])));

        let mut peer_identities = HashSet::new();
        peer_identities.insert(PeerIdentity {
            addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), NODE1_TEST_PORT),
            hostname: NODE1_HOST.to_string(),
        });
        let peer_idents = Arc::new(RwLock::new(peer_identities));

        let notify_shutdown = Arc::new(Notify::new());

        // prepare data in node2 database
        let time_series_store = db.periodic_time_series_store().unwrap();
        let send_time_series_time = Utc::now().timestamp_nanos_opt().unwrap();
        let time_series_data =
            bincode::deserialize::<PeriodicTimeSeries>(&insert_periodic_time_series_raw_event(
                &time_series_store,
                SAMPLING_POLICY_ID_AS_SENSOR,
                send_time_series_time,
            ))
            .unwrap();

        if oneshot_send
            .send(
                time_series_data
                    .response_data(send_time_series_time, SAMPLING_POLICY_ID_AS_SENSOR)
                    .unwrap(),
            )
            .is_err()
        {
            eprintln!("the receiver is dropped");
        }

        let node2_server = Server::new(
            SocketAddr::new("127.0.0.1".parse::<IpAddr>().unwrap(), NODE2_PORT),
            &certs,
        );
        node2_server
            .run(
                db,
                pcap_sensors,
                stream_direct_channels,
                ingest_sensors,
                peers,
                peer_idents,
                certs,
                notify_shutdown,
            )
            .await;
    });

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let pcap_sensors = new_pcap_sensors();
    let stream_direct_channels = new_stream_direct_channels();
    let ingest_sensors = Arc::new(tokio::sync::RwLock::new(
        NODE1_GIGANTO_INGEST_SENSORS
            .into_iter()
            .map(str::to_string)
            .collect::<HashSet<String>>(),
    ));

    let peers = Arc::new(tokio::sync::RwLock::new(HashMap::from([(
        "127.0.0.1".to_string(),
        PeerInfo {
            ingest_sensors: NODE2_GIGANTO_INGEST_SENSORS
                .into_iter()
                .map(str::to_string)
                .collect::<HashSet<String>>(),
            graphql_port: None,
            publish_port: Some(NODE2_PORT),
        },
    )])));

    let mut peer_identities = HashSet::new();
    let addr_to_peers = SocketAddr::new("127.0.0.1".parse::<IpAddr>().unwrap(), NODE2_PORT);
    peer_identities.insert(PeerIdentity {
        addr: addr_to_peers,
        hostname: NODE2_HOST.to_string(),
    });
    let peer_idents = Arc::new(RwLock::new(peer_identities));

    let cert_pem = fs::read(NODE1_CERT_PATH).unwrap();
    let cert = to_cert_chain(&cert_pem).unwrap();
    let key_pem = fs::read(NODE1_KEY_PATH).unwrap();
    let key = to_private_key(&key_pem).unwrap();
    let ca_cert_path = vec![CA_CERT_PATH.to_string()];
    let root = to_root_cert(&ca_cert_path).unwrap();

    let certs = Arc::new(Certs {
        certs: cert,
        key,
        root,
    });

    tokio::spawn(server().run(
        db.clone(),
        pcap_sensors,
        stream_direct_channels,
        ingest_sensors,
        peers,
        peer_idents,
        certs,
        Arc::new(Notify::new()),
    ));
    let publish = TestClient::new().await;
    let (mut send_pub_req, mut recv_pub_resp) =
        publish.conn.open_bi().await.expect("failed to open stream");

    let start = DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDate::from_ymd_opt(1970, 1, 1)
            .expect("valid date")
            .and_hms_opt(00, 00, 00)
            .expect("valid time"),
        Utc,
    );
    let end = DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDate::from_ymd_opt(2050, 12, 31)
            .expect("valid date")
            .and_hms_opt(23, 59, 59)
            .expect("valid time"),
        Utc,
    );
    let message = RequestRange {
        sensor: String::from(SAMPLING_POLICY_ID_AS_SENSOR),
        kind: String::from(KIND),
        start: start.timestamp_nanos_opt().unwrap(),
        end: end.timestamp_nanos_opt().unwrap(),
        count: 5,
    };

    send_range_data_request(&mut send_pub_req, PUBLISH_RANGE_MESSAGE_CODE, message)
        .await
        .unwrap();

    let mut result_data = Vec::new();
    loop {
        let resp_data = receive_range_data::<Option<(i64, String, Vec<f64>)>>(&mut recv_pub_resp)
            .await
            .unwrap();

        result_data.push(resp_data.clone());
        if resp_data.is_none() {
            break;
        }
    }

    let raw_data = if let Ok(v) = oneshot_recv.await {
        v
    } else {
        eprintln!("the sender dropped");
        Vec::new()
    };

    assert_eq!(
        PeriodicTimeSeries::response_done().unwrap(),
        bincode::serialize::<Option<(i64, String, Vec<f64>)>>(&result_data.pop().unwrap()).unwrap()
    );
    assert_eq!(
        raw_data,
        bincode::serialize::<Option<(i64, String, Vec<f64>)>>(&result_data.pop().unwrap()).unwrap()
    );

    publish.conn.close(0u32.into(), b"publish_time_done");
    publish.endpoint.wait_idle().await;
}

#[tokio::test]
#[serial]
async fn request_raw_events_giganto_cluster() {
    const SENSOR: &str = "src 2";
    const KIND: &str = "conn";
    const TIMESTAMP: i64 = 100;

    let (oneshot_send, oneshot_recv) = tokio::sync::oneshot::channel();

    // spawn node2 publish server
    tokio::spawn(async {
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
        let pcap_sensors = new_pcap_sensors();
        let stream_direct_channels = new_stream_direct_channels();
        let ingest_sensors = Arc::new(tokio::sync::RwLock::new(
            NODE2_GIGANTO_INGEST_SENSORS
                .into_iter()
                .map(str::to_string)
                .collect::<HashSet<String>>(),
        ));

        let cert_pem = fs::read(NODE2_CERT_PATH).unwrap();
        let cert = to_cert_chain(&cert_pem).unwrap();
        let key_pem = fs::read(NODE2_KEY_PATH).unwrap();
        let key = to_private_key(&key_pem).unwrap();
        let ca_cert_path = vec![CA_CERT_PATH.to_string()];
        let root = to_root_cert(&ca_cert_path).unwrap();
        let certs = Arc::new(Certs {
            certs: cert,
            key,
            root,
        });

        let peers = Arc::new(tokio::sync::RwLock::new(HashMap::from([(
            Ipv6Addr::LOCALHOST.to_string(),
            PeerInfo {
                ingest_sensors: NODE1_GIGANTO_INGEST_SENSORS
                    .into_iter()
                    .map(str::to_string)
                    .collect::<HashSet<String>>(),
                graphql_port: None,
                publish_port: Some(NODE1_TEST_PORT),
            },
        )])));

        let mut peer_identities = HashSet::new();
        peer_identities.insert(PeerIdentity {
            addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), NODE1_TEST_PORT),
            hostname: NODE1_HOST.to_string(),
        });
        let peer_idents = Arc::new(RwLock::new(peer_identities));

        let notify_shutdown = Arc::new(Notify::new());

        // prepare data in node2 database
        let conn_store = db.conn_store().unwrap();
        let send_conn_time = TIMESTAMP;
        let conn_raw_data = insert_conn_raw_event(&conn_store, SENSOR, send_conn_time);
        let conn_data = bincode::deserialize::<Conn>(&conn_raw_data).unwrap();
        let raw_data = conn_data.response_data(TIMESTAMP, SENSOR).unwrap();

        if oneshot_send.send(raw_data).is_err() {
            eprintln!("the receiver is dropped");
        }

        let node2_server = Server::new(
            SocketAddr::new("127.0.0.1".parse::<IpAddr>().unwrap(), NODE2_PORT),
            &certs,
        );
        node2_server
            .run(
                db,
                pcap_sensors,
                stream_direct_channels,
                ingest_sensors,
                peers,
                peer_idents,
                certs,
                notify_shutdown,
            )
            .await;
    });

    let _lock = get_token().lock().await;
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path(), &DbOptions::default()).unwrap();
    let pcap_sensors = new_pcap_sensors();
    let stream_direct_channels = new_stream_direct_channels();
    let ingest_sensors = Arc::new(tokio::sync::RwLock::new(
        NODE1_GIGANTO_INGEST_SENSORS
            .into_iter()
            .map(str::to_string)
            .collect::<HashSet<String>>(),
    ));

    let peers = Arc::new(tokio::sync::RwLock::new(HashMap::from([(
        "127.0.0.1".to_string(),
        PeerInfo {
            ingest_sensors: NODE2_GIGANTO_INGEST_SENSORS
                .into_iter()
                .map(str::to_string)
                .collect::<HashSet<String>>(),
            graphql_port: None,
            publish_port: Some(NODE2_PORT),
        },
    )])));

    let mut peer_identities = HashSet::new();
    let addr_to_peers = SocketAddr::new("127.0.0.1".parse::<IpAddr>().unwrap(), NODE2_PORT);
    peer_identities.insert(PeerIdentity {
        addr: addr_to_peers,
        hostname: NODE2_HOST.to_string(),
    });
    let peer_idents = Arc::new(RwLock::new(peer_identities));

    let cert_pem = fs::read(NODE1_CERT_PATH).unwrap();
    let cert = to_cert_chain(&cert_pem).unwrap();
    let key_pem = fs::read(NODE1_KEY_PATH).unwrap();
    let key = to_private_key(&key_pem).unwrap();
    let ca_cert_path = vec![CA_CERT_PATH.to_string()];
    let root = to_root_cert(&ca_cert_path).unwrap();

    let certs = Arc::new(Certs {
        certs: cert,
        key,
        root,
    });

    tokio::spawn(server().run(
        db.clone(),
        pcap_sensors,
        stream_direct_channels,
        ingest_sensors,
        peers,
        peer_idents,
        certs,
        Arc::new(Notify::new()),
    ));
    let publish = TestClient::new().await;

    let (mut send_pub_req, mut recv_pub_resp) =
        publish.conn.open_bi().await.expect("failed to open stream");

    let message = RequestRawData {
        kind: String::from(KIND),
        input: vec![(String::from(SENSOR), vec![TIMESTAMP])],
    };

    send_range_data_request(&mut send_pub_req, MessageCode::RawData, message)
        .await
        .unwrap();

    let mut result_data = vec![];
    loop {
        let resp_data = receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut recv_pub_resp)
            .await
            .unwrap();

        if let Some(data) = resp_data {
            result_data.push(data);
        } else {
            break;
        }
    }

    let raw_data = if let Ok(v) = oneshot_recv.await {
        v
    } else {
        eprintln!("the sender dropped");
        Vec::new()
    };

    assert_eq!(result_data.len(), 1);
    assert_eq!(result_data[0].0, TIMESTAMP);
    assert_eq!(&result_data[0].1, SENSOR);
    assert_eq!(
        raw_data,
        bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&result_data.pop()).unwrap()
    );
}

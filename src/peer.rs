use std::{
    collections::{HashMap, HashSet},
    mem,
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use giganto_client::{
    connection::{client_handshake, server_handshake},
    frame::{self, recv_bytes, recv_raw, send_bytes},
};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use quinn::{
    ClientConfig, Connection, ConnectionError, Endpoint, RecvStream, SendStream, ServerConfig,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::{
    select,
    sync::{
        mpsc::{channel, Receiver, Sender},
        Notify, RwLock,
    },
    time::sleep,
};
use toml_edit::DocumentMut;
use tracing::{error, info, warn};

use crate::{
    graphql::status::{
        insert_toml_peers, parse_toml_element_to_string, read_toml_file, write_toml_file,
        TomlPeers, CONFIG_GRAPHQL_SRV_ADDR, CONFIG_PUBLISH_SRV_ADDR,
    },
    server::{
        certificate_info, config_client, config_server, extract_cert_from_conn, Certs,
        SERVER_CONNNECTION_DELAY, SERVER_ENDPOINT_DELAY,
    },
    IngestSources,
};

const PEER_VERSION_REQ: &str = ">=0.21.0-alpha.2,<0.22.0";
const PEER_RETRY_INTERVAL: u64 = 5;

pub type Peers = Arc<RwLock<HashMap<String, PeerInfo>>>;
#[allow(clippy::module_name_repetitions)]
pub type PeerIdents = Arc<RwLock<HashSet<PeerIdentity>>>;

#[allow(clippy::module_name_repetitions)]
#[derive(Deserialize, Serialize, Debug, Default)]
pub struct PeerInfo {
    pub ingest_sources: HashSet<String>,
    pub graphql_port: Option<u16>,
    pub publish_port: Option<u16>,
}

#[allow(clippy::module_name_repetitions)]
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, IntoPrimitive, PartialEq, Serialize, TryFromPrimitive,
)]
#[repr(u32)]
#[non_exhaustive]
pub enum PeerCode {
    UpdatePeerList = 0,
    UpdateSourceList = 1,
}

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct PeerIdentity {
    pub addr: SocketAddr,
    pub hostname: String,
}

impl TomlPeers for PeerIdentity {
    fn get_hostname(&self) -> String {
        self.hostname.clone()
    }

    fn get_addr(&self) -> String {
        self.addr.to_string()
    }
}

#[allow(clippy::module_name_repetitions, clippy::struct_field_names)]
#[derive(Clone, Debug)]
pub struct PeerConns {
    // Key string is cert's CN hostname; Value is Connection; e.g. ( ("node2", Connection { .. }), }
    peer_conns: Arc<RwLock<HashMap<String, Connection>>>,
    // `peer_identities` is in sync with config toml's `peers`;
    // e.g. { PeerIdentity {"node2", "1.2.3.2:38384"}, PeerIdentity {"node1", "1.2.3.1:38384"}, }
    peer_identities: PeerIdents,
    ingest_sources: IngestSources,
    // Key string is peer's address(without port); Value is `ingest_sources`, `graphql_port`,
    // and `publish_port` belonging to that peer;
    // e.g. { ("10.20.0.2", PeerInfo { ("ingest_node1", "ingest_node2"),  8443, 38371 }), }
    peers: Peers,
    peer_sender: Sender<PeerIdentity>, // pita
    local_address: SocketAddr,
    notify_source: Arc<Notify>,
    config_doc: DocumentMut,
    config_path: String,
}

pub struct Peer {
    client_config: ClientConfig,
    server_config: ServerConfig,
    local_address: SocketAddr,
    local_host_name: String,
}

impl Peer {
    pub fn new(local_address: SocketAddr, certs: &Arc<Certs>) -> Result<Self> {
        let (_, local_host_name) = certificate_info(certs.certs.as_slice())?;

        let server_config =
            config_server(certs).expect("server configuration error with cert, key or root");

        let client_config =
            config_client(certs).expect("client configuration error with cert, key or root");

        Ok(Peer {
            client_config,
            server_config,
            local_address,
            local_host_name,
        })
    }

    pub async fn run(
        self,
        ingest_sources: IngestSources,
        peers: Peers,
        peer_idents: PeerIdents,
        notify_source: Arc<Notify>,
        notify_shutdown: Arc<Notify>,
        config_path: String,
    ) -> Result<()> {
        let server_endpoint =
            Endpoint::server(self.server_config, self.local_address).expect("endpoint");
        info!(
            "listening on {}",
            server_endpoint
                .local_addr()
                .expect("for local addr display")
        );

        let client_socket = SocketAddr::new(self.local_address.ip(), 0);
        let client_endpoint = {
            let mut e = Endpoint::client(client_socket).expect("endpoint");
            e.set_default_client_config(self.client_config);
            e
        };

        let (sender, mut receiver): (Sender<PeerIdentity>, Receiver<PeerIdentity>) = channel(100);

        let Ok(config_doc) = read_toml_file(&config_path) else {
            bail!("Failed to open/read config's toml file");
        };

        // A structure of values common to peer connections.
        let peer_conn_info = PeerConns {
            peer_conns: Arc::new(RwLock::new(HashMap::new())),
            peer_identities: peer_idents,
            peers,
            ingest_sources,
            peer_sender: sender,
            local_address: self.local_address,
            notify_source,
            config_doc,
            config_path,
        };

        tokio::spawn(client_run(
            client_endpoint.clone(),
            peer_conn_info.clone(),
            self.local_host_name.clone(),
            notify_shutdown.clone(),
        ));

        loop {
            select! {
                Some(conn) = server_endpoint.accept()  => {
                    let peer_conn_info = peer_conn_info.clone();
                    let notify_shutdown = notify_shutdown.clone();
                    tokio::spawn(async move {
                        let remote = conn.remote_address();
                        if let Err(e) = server_connection(
                            conn,
                            peer_conn_info,
                            notify_shutdown,
                        )
                        .await
                        {
                            error!("connection failed: {e}. {}", remote);
                        }
                    });
                },
                Some(peer) = receiver.recv()  => {
                    tokio::spawn(client_connection(
                        client_endpoint.clone(),
                        peer,
                        peer_conn_info.clone(),
                        self.local_host_name.clone(),
                        notify_shutdown.clone(),
                    ));
                },
                () = notify_shutdown.notified() => {
                    sleep(Duration::from_millis(SERVER_ENDPOINT_DELAY)).await;      // Wait time for connection to be ready for shutdown.
                    server_endpoint.close(0_u32.into(), &[]);
                    info!("Shutting down peer");
                    return Ok(())
                }

            }
        }
    }
}

async fn client_run(
    client_endpoint: Endpoint,
    peer_conn_info: PeerConns,
    local_host_name: String,
    notify_shutdown: Arc<Notify>,
) {
    for peer in &*peer_conn_info.peer_identities.read().await {
        tokio::spawn(client_connection(
            client_endpoint.clone(),
            peer.clone(),
            peer_conn_info.clone(),
            local_host_name.clone(),
            notify_shutdown.clone(),
        ));
    }
}

async fn connect(
    client_endpoint: &Endpoint,
    peer_info: &PeerIdentity,
) -> Result<(Connection, SendStream, RecvStream)> {
    let connection = client_endpoint
        .connect(peer_info.addr, &peer_info.hostname)?
        .await?;
    let (send, recv) = client_handshake(&connection, env!("CARGO_PKG_VERSION")).await?;
    Ok((connection, send, recv))
}

fn get_peer_ports(config_doc: &DocumentMut) -> (Option<u16>, Option<u16>) {
    (
        get_port_from_config(CONFIG_GRAPHQL_SRV_ADDR, config_doc),
        get_port_from_config(CONFIG_PUBLISH_SRV_ADDR, config_doc),
    )
}

fn get_port_from_config(config_key: &str, config_doc: &DocumentMut) -> Option<u16> {
    parse_toml_element_to_string(config_key, config_doc)
        .ok()
        .and_then(|address_str| address_str.to_socket_addrs().ok())
        .and_then(|mut addr| match addr.next() {
            Some(SocketAddr::V4(v4_addr)) => Some(v4_addr.port()),
            Some(SocketAddr::V6(v6_addr)) => Some(v6_addr.port()),
            _ => None,
        })
}

#[allow(clippy::too_many_lines)]
async fn client_connection(
    client_endpoint: Endpoint,
    peer_info: PeerIdentity,
    peer_conn_info: PeerConns,
    local_host_name: String,
    notify_shutdown: Arc<Notify>,
) -> Result<()> {
    let (graphql_port, publish_port) = get_peer_ports(&peer_conn_info.config_doc);
    'connection: loop {
        match connect(&client_endpoint, &peer_info).await {
            Ok((connection, mut send, mut recv)) => {
                // Remove duplicate connections.
                let (remote_addr, remote_host_name) = match check_for_duplicate_connections(
                    &connection,
                    peer_conn_info.peer_conns.clone(),
                )
                .await
                {
                    Ok((addr, name)) => {
                        info!("Connection established to {addr}/{name} (client role)");
                        (addr, name)
                    }
                    Err(_) => {
                        return Ok(());
                    }
                };

                let send_source_list: HashSet<String> =
                    peer_conn_info.ingest_sources.read().await.to_owned();

                // Add my peer info to the peer list.
                let mut send_peer_list = peer_conn_info.peer_identities.read().await.clone();
                send_peer_list.insert(PeerIdentity {
                    addr: peer_conn_info.local_address,
                    hostname: local_host_name.clone(),
                });

                // Exchange peer list/source list.
                let (recv_peer_list, recv_source_list) =
                    request_init_info::<(HashSet<PeerIdentity>, PeerInfo)>(
                        &mut send,
                        &mut recv,
                        PeerCode::UpdatePeerList,
                        (
                            send_peer_list,
                            PeerInfo {
                                ingest_sources: send_source_list,
                                graphql_port,
                                publish_port,
                            },
                        ),
                    )
                    .await?;

                // Update to the list of received sources.
                update_to_new_source_list(
                    recv_source_list,
                    remote_addr.clone(),
                    peer_conn_info.peers.clone(),
                )
                .await;

                // Update to the list of received peers.
                update_to_new_peer_list(
                    recv_peer_list,
                    peer_conn_info.local_address,
                    peer_conn_info.peer_identities.clone(),
                    peer_conn_info.peer_sender.clone(),
                    peer_conn_info.config_doc.clone(),
                    &peer_conn_info.config_path,
                )
                .await?;

                // Share the received peer list with connected peers.
                for conn in (*peer_conn_info.peer_conns.read().await).values() {
                    tokio::spawn(update_peer_info::<HashSet<PeerIdentity>>(
                        conn.clone(),
                        PeerCode::UpdatePeerList,
                        peer_conn_info.peer_identities.read().await.clone(),
                    ));
                }

                // Update my peer list
                peer_conn_info
                    .peer_conns
                    .write()
                    .await
                    .insert(remote_host_name.clone(), connection.clone());

                loop {
                    select! {
                        stream = connection.accept_bi()  => {
                            let stream = match stream {
                                Err(e) => {
                                    peer_conn_info.peer_conns.write().await.remove(&remote_host_name);
                                    peer_conn_info.peers.write().await.remove(&remote_addr);
                                    if let quinn::ConnectionError::ApplicationClosed(_) = e {
                                        info!("giganto peer({remote_host_name}/{remote_addr}) closed");
                                        return Ok(());
                                    }
                                    continue 'connection;
                                }
                                Ok(s) => s,
                            };

                            let peer_list = peer_conn_info.peer_identities.clone();
                            let sender = peer_conn_info.peer_sender.clone();
                            let remote_addr = remote_addr.clone();
                            let peers = peer_conn_info.peers.clone();
                            let doc = peer_conn_info.config_doc.clone();
                            let path= peer_conn_info.config_path.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_request(stream, peer_conn_info.local_address, remote_addr, peer_list, peers, sender, doc, path).await {
                                    error!("failed: {e}");
                                }
                            });
                        },
                        () = peer_conn_info.notify_source.notified() => {
                            let source_list = peer_conn_info.ingest_sources.read().await.to_owned();
                            for conn in (*peer_conn_info.peer_conns.write().await).values() {
                                tokio::spawn(update_peer_info::<PeerInfo>(
                                    conn.clone(),
                                    PeerCode::UpdateSourceList,
                                    PeerInfo {
                                        ingest_sources: source_list.clone(),
                                        graphql_port,
                                        publish_port,
                                    }
                                ));
                            }
                        },
                        () = notify_shutdown.notified() => {
                            // Wait time for channels to be ready for shutdown.
                            sleep(Duration::from_millis(SERVER_CONNNECTION_DELAY)).await;
                            connection.close(0_u32.into(), &[]);
                            return Ok(())
                        },
                    }
                }
            }
            Err(e) => {
                if let Some(e) = e.downcast_ref::<ConnectionError>() {
                    match e {
                        ConnectionError::ConnectionClosed(_)
                        | ConnectionError::ApplicationClosed(_)
                        | ConnectionError::Reset
                        | ConnectionError::TimedOut => {
                            warn!(
                                "Retry connection to {} after {PEER_RETRY_INTERVAL} seconds.",
                                peer_info.addr,
                            );
                            sleep(Duration::from_secs(PEER_RETRY_INTERVAL)).await;
                            continue 'connection;
                        }
                        _ => {}
                    }
                } else {
                    return Ok(());
                }
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn server_connection(
    conn: quinn::Incoming,
    peer_conn_info: PeerConns,
    notify_shutdown: Arc<Notify>,
) -> Result<()> {
    let connection = conn.await?;

    let (mut send, mut recv) = match server_handshake(&connection, PEER_VERSION_REQ).await {
        Ok((send, recv)) => (send, recv),
        Err(e) => {
            connection.close(quinn::VarInt::from_u32(0), e.to_string().as_bytes());
            bail!("{e}")
        }
    };

    // Remove duplicate connections.
    let (remote_addr, remote_host_name) =
        match check_for_duplicate_connections(&connection, peer_conn_info.peer_conns.clone()).await
        {
            Ok((addr, name)) => {
                info!("Connection established to {addr}/{name} (server role)");
                (addr, name)
            }
            Err(_) => {
                return Ok(());
            }
        };

    let source_list: HashSet<String> = peer_conn_info.ingest_sources.read().await.to_owned();

    // Exchange peer list/source list.
    let (graphql_port, publish_port) = get_peer_ports(&peer_conn_info.config_doc);
    let (recv_peer_list, recv_source_list) =
        response_init_info::<(HashSet<PeerIdentity>, PeerInfo)>(
            &mut send,
            &mut recv,
            PeerCode::UpdatePeerList,
            (
                peer_conn_info.peer_identities.read().await.clone(),
                PeerInfo {
                    ingest_sources: source_list,
                    graphql_port,
                    publish_port,
                },
            ),
        )
        .await?;

    // Update to the list of received sources.
    update_to_new_source_list(
        recv_source_list,
        remote_addr.clone(),
        peer_conn_info.peers.clone(),
    )
    .await;

    // Update to the list of received peers.
    update_to_new_peer_list(
        recv_peer_list.clone(),
        peer_conn_info.local_address,
        peer_conn_info.peer_identities.clone(),
        peer_conn_info.peer_sender.clone(),
        peer_conn_info.config_doc.clone(),
        &peer_conn_info.config_path,
    )
    .await?;

    // Share the received peer list with your connected peers.
    for conn in (*peer_conn_info.peer_conns.read().await).values() {
        tokio::spawn(update_peer_info::<HashSet<PeerIdentity>>(
            conn.clone(),
            PeerCode::UpdatePeerList,
            peer_conn_info.peer_identities.read().await.clone(),
        ));
    }

    // Update my peer list
    peer_conn_info
        .peer_conns
        .write()
        .await
        .insert(remote_host_name.clone(), connection.clone());

    loop {
        select! {
            stream = connection.accept_bi()  => {
                let stream = match stream {
                    Err(e) => {
                        peer_conn_info.peer_conns.write().await.remove(&remote_host_name);
                        peer_conn_info.peers.write().await.remove(&remote_addr);
                        if let quinn::ConnectionError::ApplicationClosed(_) = e {
                            info!("giganto peer({remote_host_name}/{remote_addr}) closed");
                            return Ok(());
                        }
                        return Err(e.into());
                    }
                    Ok(s) => s,
                };

                let peer_list = peer_conn_info.peer_identities.clone();
                let sender = peer_conn_info.peer_sender.clone();
                let remote_addr = remote_addr.clone();
                let peers = peer_conn_info.peers.clone();
                let doc = peer_conn_info.config_doc.clone();
                let path= peer_conn_info.config_path.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_request(stream, peer_conn_info.local_address, remote_addr, peer_list, peers, sender, doc, path).await {
                        error!("failed: {}", e);
                    }
                });
            },
            () = peer_conn_info.notify_source.notified() => {
                let source_list: HashSet<String> = peer_conn_info.ingest_sources.read().await.to_owned();
                for conn in (*peer_conn_info.peer_conns.read().await).values() {
                    tokio::spawn(update_peer_info::<PeerInfo>(
                        conn.clone(),
                        PeerCode::UpdateSourceList,
                        PeerInfo {
                            ingest_sources: source_list.clone(),
                            graphql_port,
                            publish_port
                        }
                    ));
                }
            },
            () = notify_shutdown.notified() => {
                // Wait time for channels to be ready for shutdown.
                sleep(Duration::from_millis(SERVER_CONNNECTION_DELAY)).await;
                connection.close(0_u32.into(), &[]);
                return Ok(())
            },
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_request(
    (_, mut recv): (SendStream, RecvStream),
    local_addr: SocketAddr,
    remote_addr: String,
    peer_list: Arc<RwLock<HashSet<PeerIdentity>>>,
    peers: Peers,
    sender: Sender<PeerIdentity>,
    doc: DocumentMut,
    path: String,
) -> Result<()> {
    let (msg_type, msg_buf) = receive_peer_data(&mut recv).await?;
    match msg_type {
        PeerCode::UpdatePeerList => {
            let update_peer_list = bincode::deserialize::<HashSet<PeerIdentity>>(&msg_buf)
                .map_err(|e| anyhow!("Failed to deserialize peer list: {e}"))?;
            update_to_new_peer_list(update_peer_list, local_addr, peer_list, sender, doc, &path)
                .await?;
        }
        PeerCode::UpdateSourceList => {
            let update_source_list = bincode::deserialize::<PeerInfo>(&msg_buf)
                .map_err(|e| anyhow!("Failed to deserialize source list: {e}"))?;
            update_to_new_source_list(update_source_list, remote_addr, peers).await;
        }
    }
    Ok(())
}

pub async fn send_peer_data<T>(send: &mut SendStream, msg: PeerCode, update_data: T) -> Result<()>
where
    T: Serialize,
{
    // send PeerCode
    let msg_type: u32 = msg.into();
    send_bytes(send, &msg_type.to_le_bytes()).await?;

    // send the peer data to be updated
    let mut buf = Vec::new();
    frame::send(send, &mut buf, update_data).await?;
    Ok(())
}

pub async fn receive_peer_data(recv: &mut RecvStream) -> Result<(PeerCode, Vec<u8>)> {
    // receive PeerCode
    let mut buf = [0; mem::size_of::<u32>()];
    recv_bytes(recv, &mut buf).await?;
    let msg_type = PeerCode::try_from(u32::from_le_bytes(buf)).context("unknown peer code")?;

    // receive the peer data to be updated
    let mut buf = Vec::new();
    recv_raw(recv, &mut buf).await?;
    Ok((msg_type, buf))
}

async fn request_init_info<T>(
    send: &mut SendStream,
    recv: &mut RecvStream,
    init_type: PeerCode,
    init_data: T,
) -> Result<T>
where
    T: Serialize + DeserializeOwned,
{
    send_peer_data::<T>(send, init_type, init_data).await?;
    let (_, recv_data) = receive_peer_data(recv).await?;
    let recv_init_data = bincode::deserialize::<T>(&recv_data)?;
    Ok(recv_init_data)
}

async fn response_init_info<T>(
    send: &mut SendStream,
    recv: &mut RecvStream,
    init_type: PeerCode,
    init_data: T,
) -> Result<T>
where
    T: Serialize + DeserializeOwned,
{
    let (_, recv_data) = receive_peer_data(recv).await?;
    let recv_init_data = bincode::deserialize::<T>(&recv_data)?;
    send_peer_data::<T>(send, init_type, init_data).await?;
    Ok(recv_init_data)
}

async fn update_peer_info<T>(connection: Connection, msg_type: PeerCode, peer_data: T) -> Result<()>
where
    T: Serialize + DeserializeOwned,
{
    match connection.open_bi().await {
        Ok((mut send, _)) => {
            send_peer_data::<T>(&mut send, msg_type, peer_data).await?;
            Ok(())
        }
        Err(_) => {
            bail!("Failed to send peer data");
        }
    }
}

async fn check_for_duplicate_connections(
    connection: &Connection,
    peer_conn: Arc<RwLock<HashMap<String, Connection>>>,
) -> Result<(String, String)> {
    let remote_addr = connection.remote_address().ip().to_string();
    let (_, remote_host_name) = certificate_info(&extract_cert_from_conn(connection)?)?;
    if peer_conn.read().await.contains_key(&remote_host_name) {
        connection.close(
            quinn::VarInt::from_u32(0),
            "exist connection close".as_bytes(),
        );
        bail!("Duplicated connection close:{remote_host_name:?}");
    }
    Ok((remote_addr, remote_host_name))
}

async fn update_to_new_peer_list(
    recv_peer_list: HashSet<PeerIdentity>,
    local_address: SocketAddr,
    peer_list: Arc<RwLock<HashSet<PeerIdentity>>>,
    sender: Sender<PeerIdentity>,
    mut doc: DocumentMut,
    path: &str,
) -> Result<()> {
    let mut is_change = false;
    for recv_peer_info in recv_peer_list {
        let is_changed = if cfg!(debug_assertions) {
            !((local_address.ip() == recv_peer_info.addr.ip()
                && local_address.port() == recv_peer_info.addr.port())
                || peer_list.read().await.contains(&recv_peer_info))
        } else {
            local_address.ip() != recv_peer_info.addr.ip()
                && !peer_list.read().await.contains(&recv_peer_info)
        };
        if is_changed {
            is_change = true;
            peer_list.write().await.insert(recv_peer_info.clone());
            sender.send(recv_peer_info).await?;
        }
    }

    if is_change {
        let data: Vec<PeerIdentity> = peer_list.read().await.iter().cloned().collect();
        if let Err(e) = insert_toml_peers(&mut doc, Some(data)) {
            error!("{e:?}");
        }
        if let Err(e) = write_toml_file(&doc, path) {
            error!("{e:?}");
        }
    }

    Ok(())
}

async fn update_to_new_source_list(
    recv_source_list: PeerInfo,
    remote_addr: String,
    peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
) {
    peers.write().await.insert(remote_addr, recv_source_list);
}

#[cfg(test)]
pub mod tests {
    use std::{
        collections::{HashMap, HashSet},
        fs::{self, File},
        net::{IpAddr, Ipv6Addr, SocketAddr},
        path::Path,
        sync::{Arc, OnceLock},
    };

    use giganto_client::connection::client_handshake;
    use quinn::{Connection, Endpoint, RecvStream, SendStream};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tempfile::TempDir;
    use tokio::sync::{Mutex, Notify, RwLock};

    use super::Peer;
    use crate::{
        peer::{receive_peer_data, request_init_info, PeerCode, PeerIdentity},
        server::Certs,
        to_cert_chain, to_private_key, to_root_cert, PeerInfo,
    };

    fn get_token() -> &'static Mutex<u32> {
        static TOKEN: OnceLock<Mutex<u32>> = OnceLock::new();

        TOKEN.get_or_init(|| Mutex::new(0))
    }

    const CERT_PATH: &str = "tests/certs/node1/cert.pem";
    const KEY_PATH: &str = "tests/certs/node1/key.pem";
    const ROOT_PATH: &str = "tests/certs/root.pem";
    const HOST: &str = "node1";
    const TEST_PORT: u16 = 60191;
    const PROTOCOL_VERSION: &str = "0.21.0-alpha.2";

    pub struct TestClient {
        send: SendStream,
        recv: RecvStream,
        conn: Connection,
    }

    impl TestClient {
        pub async fn new() -> Self {
            let endpoint = init_client();
            let conn = endpoint
            .connect(
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), TEST_PORT),
                HOST,
            )
            .expect(
                "Failed to connect server's endpoint, Please check if the setting value is correct",
            )
            .await
            .expect("Failed to connect server's endpoint, Please make sure the Server is alive");
            let (send, recv) = client_handshake(&conn, PROTOCOL_VERSION).await.unwrap();
            Self { send, recv, conn }
        }
    }

    fn init_client() -> Endpoint {
        let (cert, key) = match fs::read(CERT_PATH)
            .map(|x| (x, fs::read(KEY_PATH).expect("Failed to Read key file")))
        {
            Ok(x) => x,
            Err(_) => {
                panic!(
                    "failed to read (cert, key) file, {CERT_PATH}, {KEY_PATH} read file error. Cert or key doesn't exist in default test folder",
                );
            }
        };

        let pv_key = if Path::new(KEY_PATH)
            .extension()
            .map_or(false, |x| x == "der")
        {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))
        } else {
            rustls_pemfile::private_key(&mut &*key)
                .expect("malformed PKCS #1 private key")
                .expect("no private keys found")
        };

        let cert_chain = if Path::new(CERT_PATH)
            .extension()
            .map_or(false, |x| x == "der")
        {
            vec![CertificateDer::from(cert)]
        } else {
            rustls_pemfile::certs(&mut &*cert)
                .collect::<Result<_, _>>()
                .expect("invalid PEM-encoded certificate")
        };

        let root = fs::read(ROOT_PATH).expect("Failed to read file");
        let server_root = to_root_cert(&root).unwrap();

        let client_crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("Failed to set default tls protocol version")
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

    fn peer_init() -> Peer {
        let cert_pem = fs::read(CERT_PATH).unwrap();
        let cert = to_cert_chain(&cert_pem).unwrap();
        let key_pem = fs::read(KEY_PATH).unwrap();
        let key = to_private_key(&key_pem).unwrap();
        let root_pem = fs::read(ROOT_PATH).unwrap();
        let root = to_root_cert(&root_pem).unwrap();

        let certs = Arc::new(Certs {
            certs: cert,
            key,
            root,
        });

        Peer::new(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), TEST_PORT),
            &certs,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn recv_peer_data() {
        let _lock = get_token().lock().await;

        // peer server's peer list
        let peer_addr = SocketAddr::new("123.123.123.123".parse::<IpAddr>().unwrap(), TEST_PORT);
        let peer_name = String::from("einsis_peer");
        let mut peer_identities = HashSet::new();
        peer_identities.insert(PeerIdentity {
            addr: peer_addr,
            hostname: peer_name.clone(),
        });
        let peer_idents = Arc::new(RwLock::new(peer_identities));

        // peer server's source list
        let source_name = String::from("einsis_source");
        let mut source_info = HashSet::new();
        source_info.insert(source_name.clone());

        let ingest_sources = Arc::new(RwLock::new(source_info));
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let notify_source = Arc::new(Notify::new());

        // create temp config file
        let tmp_dir = TempDir::new().unwrap();
        let file_path = tmp_dir.path().join("config.toml");
        File::create(&file_path).unwrap();

        // run peer
        tokio::spawn(peer_init().run(
            ingest_sources.clone(),
            peers,
            peer_idents,
            notify_source.clone(),
            Arc::new(Notify::new()),
            file_path.to_str().unwrap().to_string(),
        ));

        // run peer client
        let mut peer_client_one = TestClient::new().await;
        let (recv_peer_list, recv_source_list) =
            request_init_info::<(HashSet<PeerIdentity>, PeerInfo)>(
                &mut peer_client_one.send,
                &mut peer_client_one.recv,
                PeerCode::UpdatePeerList,
                (HashSet::new(), PeerInfo::default()),
            )
            .await
            .unwrap();

        // compare server's peer list/source list
        assert!(recv_peer_list.contains(&PeerIdentity {
            addr: peer_addr,
            hostname: peer_name,
        }));
        assert!(recv_source_list.ingest_sources.contains(&source_name));

        // insert peer server's source value & notify to server
        let source_name2 = String::from("einsis_source2");
        ingest_sources.write().await.insert(source_name2.clone());
        notify_source.notify_one();

        // receive source list
        let (_, mut recv_pub_resp) = peer_client_one
            .conn
            .accept_bi()
            .await
            .expect("failed to open stream");
        let (msg_type, msg_buf) = receive_peer_data(&mut recv_pub_resp).await.unwrap();
        let update_source_list = bincode::deserialize::<PeerInfo>(&msg_buf).unwrap();

        // compare server's source list
        assert_eq!(msg_type, PeerCode::UpdateSourceList);
        assert!(update_source_list.ingest_sources.contains(&source_name));
        assert!(update_source_list.ingest_sources.contains(&source_name2));
    }
}

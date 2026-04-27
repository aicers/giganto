use std::{
    collections::{HashMap, HashSet},
    mem,
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, RwLock as StdRwLock},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use giganto_client::{
    connection::{client_handshake, server_handshake},
    frame::{self, recv_bytes, recv_raw, send_bytes},
};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use quinn::{
    ClientConfig, Connection, ConnectionError, Endpoint, RecvStream, SendStream, ServerConfig,
};
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tokio::{
    select,
    sync::{
        Notify, RwLock,
        mpsc::{Receiver, Sender, channel},
    },
    time::sleep,
};
use toml_edit::DocumentMut;
use tracing::{error, info, warn};

use crate::{
    comm::IngestSensors,
    graphql::status::{
        CONFIG_GRAPHQL_SRV_ADDR, CONFIG_PUBLISH_SRV_ADDR, TomlPeers, insert_toml_peers,
        parse_toml_element_to_string, read_toml_file, write_toml_file,
    },
    server::{
        Certs, SERVER_CONNNECTION_DELAY, SERVER_ENDPOINT_DELAY, config_client, config_server,
        extract_cert_from_conn, peer_dedup_key_from_cert, peer_name_from_cert,
    },
    tls_reload::TlsWatch,
};

/// Peer subsystem's currently active client TLS state. The `generation`
/// counter is incremented on every successful reload so that an outbound
/// reconnect that snapshotted its client config before a reload can
/// detect, after its dial completes, that the snapshot is stale.
pub(super) struct PeerClientConfigState {
    generation: u64,
    config: Arc<ClientConfig>,
}

/// Shared slot holding the peer subsystem's currently active client TLS
/// state. Readers (`connect`) snapshot `(generation, Arc<ClientConfig>)`
/// under a short-lived read lock; the reload handler bumps the generation
/// and replaces the inner `Arc` under a write lock when a new
/// configuration is applied.
type SharedClientConfig = Arc<StdRwLock<PeerClientConfigState>>;

fn new_shared_client_config(config: ClientConfig) -> SharedClientConfig {
    Arc::new(StdRwLock::new(PeerClientConfigState {
        generation: 0,
        config: Arc::new(config),
    }))
}

/// Computes a lowercase hex SHA-256 fingerprint of the leaf (first)
/// certificate in the chain, for use in reload logging and tests.
pub(crate) fn leaf_cert_fingerprint(certs: &[CertificateDer<'_>]) -> String {
    let Some(leaf) = certs.first() else {
        return "<none>".to_string();
    };
    let mut hasher = Sha256::new();
    hasher.update(leaf.as_ref());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn snapshot_client_config(slot: &SharedClientConfig) -> (u64, ClientConfig) {
    let guard = slot.read().expect("peer client config lock poisoned");
    (guard.generation, guard.config.as_ref().clone())
}

fn current_client_generation(slot: &SharedClientConfig) -> u64 {
    slot.read()
        .expect("peer client config lock poisoned")
        .generation
}

// The `PEER_VERSION_REQ` defines the compatibility range for Giganto instances in a cluster.
// Reasons for updating this version include, but not be limited to:
// - Updates of GraphQL API version: Since Giganto acts as both a client and server for other
//   Gigantos in the cluster, maintaining the same API version is necessary for the communication
//   within the cluster.
// - Updates of event protocol structures: Any changes to giganto-client's event protocols require
//   all Gigantos in the cluster to use the same protocol version for compatibility.
const PEER_VERSION_REQ: &str = ">=0.27.0-alpha.2,<0.28.0";
const PEER_RETRY_INTERVAL: u64 = 5;

pub type Peers = Arc<RwLock<HashMap<String, PeerInfo>>>;
#[allow(clippy::module_name_repetitions)]
pub type PeerIdents = Arc<RwLock<HashSet<PeerIdentity>>>;

#[allow(clippy::module_name_repetitions)]
#[derive(Deserialize, Serialize, Debug, Default)]
pub struct PeerInfo {
    pub ingest_sensors: HashSet<String>,
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
    UpdateSensorList = 1,
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
    // Key string is the peer dedup key derived from the certificate identity.
    peer_conns: Arc<RwLock<HashMap<String, Connection>>>,
    // `peer_identities` is in sync with config toml's `peers`;
    // its `hostname` field is the peer connect name used for TLS SNI.
    peer_identities: PeerIdents,
    ingest_sensors: IngestSensors,
    // Key string is peer's address(without port); Value is `ingest_sensors`, `graphql_port`,
    // and `publish_port` belonging to that peer;
    // e.g. { ("10.20.0.2", PeerInfo { ("ingest_node1", "ingest_node2"),  8443, 38371 }), }
    peers: Peers,
    peer_sender: Sender<PeerIdentity>,
    local_address: SocketAddr,
    notify_sensor: Arc<Notify>,
    config_doc: DocumentMut,
    config_path: String,
}

pub struct Peer {
    client_config: ClientConfig,
    server_config: ServerConfig,
    local_address: SocketAddr,
    local_connect_name: String,
}

impl Peer {
    pub fn new(local_address: SocketAddr, certs: &Certs) -> Result<Self> {
        let local_connect_name = peer_name_from_cert(certs.certs.as_slice())?;

        let server_config =
            config_server(certs).expect("server configuration error with cert, key or root");

        let client_config =
            config_client(certs).expect("client configuration error with cert, key or root");

        Ok(Peer {
            client_config,
            server_config,
            local_address,
            local_connect_name,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        self,
        ingest_sensors: IngestSensors,
        peers: Peers,
        peer_idents: PeerIdents,
        notify_sensor: Arc<Notify>,
        notify_shutdown: Arc<Notify>,
        config_path: String,
        mut tls_watch: TlsWatch,
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
        let client_endpoint = Endpoint::client(client_socket).expect("endpoint");
        let shared_client_config = new_shared_client_config(self.client_config);
        // Discard any initial value to avoid triggering the reload branch
        // before the subsystem has advertised its current TLS state.
        tls_watch.mark_unchanged();

        let (sender, mut receiver): (Sender<PeerIdentity>, Receiver<PeerIdentity>) = channel(100);

        let Ok(config_doc) = read_toml_file(&config_path) else {
            bail!("Failed to open/read config's toml file");
        };

        // A structure of values common to peer connections.
        let peer_conn_info = PeerConns {
            peer_conns: Arc::new(RwLock::new(HashMap::new())),
            peer_identities: peer_idents,
            peers,
            ingest_sensors,
            peer_sender: sender,
            local_address: self.local_address,
            notify_sensor,
            config_doc,
            config_path,
        };

        tokio::spawn(client_run(
            client_endpoint.clone(),
            shared_client_config.clone(),
            peer_conn_info.clone(),
            self.local_connect_name.clone(),
            notify_shutdown.clone(),
        ));

        let mut tls_reload_closed = false;
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
                            error!("Connection to {remote} failed: {e}");
                        }
                    });
                },
                Some(peer) = receiver.recv()  => {
                    tokio::spawn(client_connection(
                        client_endpoint.clone(),
                        shared_client_config.clone(),
                        peer,
                        peer_conn_info.clone(),
                        self.local_connect_name.clone(),
                        notify_shutdown.clone(),
                    ));
                },
                res = tls_watch.changed(), if !tls_reload_closed => {
                    if res.is_err() {
                        warn!("peer TLS reload channel closed; reload branch disabled");
                        tls_reload_closed = true;
                        continue;
                    }
                    let material = tls_watch.borrow_and_update().clone();
                    apply_peer_tls_reload(
                        &server_endpoint,
                        &shared_client_config,
                        &material.certs,
                    );
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

/// Prepares fresh peer server/client TLS configurations from `certs` and,
/// only if both build successfully, swaps them into the active peer
/// subsystem state under a single write lock and bumps the client-config
/// generation. On any prepare failure the previous active state is
/// preserved and the failure is logged.
///
/// The write lock serializes with `connect()` readers so that a reader
/// which waits for this lock (or starts after it) sees post-reload server
/// and client state together. A reader that snapshotted the old client
/// config before this critical section may still be in the middle of a
/// dial when the swap lands; the generation bump lets the caller detect
/// that case after the dial completes and retry with the refreshed client
/// config instead of letting a stale outbound connection remain active
/// while new inbound handshakes already observe the new server leaf.
fn apply_peer_tls_reload(
    server_endpoint: &Endpoint,
    shared_client_config: &SharedClientConfig,
    certs: &Certs,
) {
    let new_server = match config_server(certs) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("peer TLS reload: server config build failed: {e:#}");
            warn!("peer TLS reload aborted; keeping previous state");
            return;
        }
    };
    let new_client = match config_client(certs) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("peer TLS reload: client config build failed: {e:#}");
            warn!("peer TLS reload aborted; keeping previous state");
            return;
        }
    };

    let mut state = shared_client_config
        .write()
        .expect("peer client config lock poisoned");
    server_endpoint.set_server_config(Some(new_server));
    state.generation = state.generation.saturating_add(1);
    state.config = Arc::new(new_client);
    drop(state);
    info!(
        "peer TLS state reloaded; new leaf fingerprint: {}",
        leaf_cert_fingerprint(&certs.certs)
    );
}

async fn client_run(
    client_endpoint: Endpoint,
    shared_client_config: SharedClientConfig,
    peer_conn_info: PeerConns,
    local_connect_name: String,
    notify_shutdown: Arc<Notify>,
) {
    for peer in &*peer_conn_info.peer_identities.read().await {
        tokio::spawn(client_connection(
            client_endpoint.clone(),
            shared_client_config.clone(),
            peer.clone(),
            peer_conn_info.clone(),
            local_connect_name.clone(),
            notify_shutdown.clone(),
        ));
    }
}

async fn connect(
    client_endpoint: &Endpoint,
    shared_client_config: &SharedClientConfig,
    peer_info: &PeerIdentity,
) -> Result<(Connection, SendStream, RecvStream, u64)> {
    let (generation, config) = snapshot_client_config(shared_client_config);
    let connection = client_endpoint
        .connect_with(config, peer_info.addr, &peer_info.hostname)?
        .await?;
    let (send, recv) = client_handshake(&connection, env!("CARGO_PKG_VERSION")).await?;
    Ok((connection, send, recv, generation))
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

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn client_connection(
    client_endpoint: Endpoint,
    shared_client_config: SharedClientConfig,
    peer_info: PeerIdentity,
    peer_conn_info: PeerConns,
    local_connect_name: String,
    notify_shutdown: Arc<Notify>,
) -> Result<()> {
    let (graphql_port, publish_port) = get_peer_ports(&peer_conn_info.config_doc);
    'connection: loop {
        match connect(&client_endpoint, &shared_client_config, &peer_info).await {
            Ok((connection, mut send, mut recv, snapshot_gen)) => {
                // If peer TLS state was reloaded while this reconnect was
                // in flight, the connection we just established was dialed
                // with stale client material. Close it and retry so the
                // reconnect is driven by the refreshed client config; this
                // prevents an outbound connection from remaining active on
                // the old client leaf after the server endpoint has
                // already switched to the new TLS state.
                if current_client_generation(&shared_client_config) != snapshot_gen {
                    info!(
                        "outbound reconnect to {} superseded by peer TLS reload; retrying with refreshed client config",
                        peer_info.addr
                    );
                    connection.close(0_u32.into(), b"peer TLS reload superseded");
                    continue 'connection;
                }
                // Remove duplicate connections.
                let (remote_addr, remote_peer_dedup_key) = match check_for_duplicate_connections(
                    &connection,
                    peer_conn_info.peer_conns.clone(),
                )
                .await
                {
                    Ok((addr, name)) => {
                        info!("Peer connection established to {addr}/{name} (client role)");
                        (addr, name)
                    }
                    Err(_) => {
                        return Ok(());
                    }
                };

                let send_sensor_list: HashSet<String> =
                    peer_conn_info.ingest_sensors.read().await.to_owned();

                // Add my peer info to the peer list.
                let mut send_peer_list = peer_conn_info.peer_identities.read().await.clone();
                send_peer_list.insert(PeerIdentity {
                    addr: peer_conn_info.local_address,
                    hostname: local_connect_name.clone(),
                });

                // Exchange peer list/sensor list.
                let (recv_peer_list, recv_sensor_list) =
                    request_init_info::<(HashSet<PeerIdentity>, PeerInfo)>(
                        &mut send,
                        &mut recv,
                        PeerCode::UpdatePeerList,
                        (
                            send_peer_list,
                            PeerInfo {
                                ingest_sensors: send_sensor_list,
                                graphql_port,
                                publish_port,
                            },
                        ),
                    )
                    .await?;

                // Update to the list of received sensors.
                update_to_new_sensor_list(
                    recv_sensor_list,
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
                    .insert(remote_peer_dedup_key.clone(), connection.clone());

                loop {
                    select! {
                        stream = connection.accept_bi()  => {
                            let stream = match stream {
                                Err(e) => {
                                    peer_conn_info.peer_conns.write().await.remove(&remote_peer_dedup_key);
                                    peer_conn_info.peers.write().await.remove(&remote_addr);
                                    if let quinn::ConnectionError::ApplicationClosed(_) = e {
                                        info!("Data store peer({remote_peer_dedup_key}/{remote_addr}) closed");
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
                                if let Err(e) = handle_request(stream, peer_conn_info.local_address, remote_addr, peer_list, peers, sender, doc, &path).await {
                                    error!("Failed: {e}");
                                }
                            });
                        },
                        () = peer_conn_info.notify_sensor.notified() => {
                            let sensor_list = peer_conn_info.ingest_sensors.read().await.to_owned();
                            for conn in (*peer_conn_info.peer_conns.write().await).values() {
                                tokio::spawn(update_peer_info::<PeerInfo>(
                                    conn.clone(),
                                    PeerCode::UpdateSensorList,
                                    PeerInfo {
                                        ingest_sensors: sensor_list.clone(),
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
                                "Retrying connection to {} in {PEER_RETRY_INTERVAL} seconds",
                                peer_info.addr,
                            );
                            sleep(Duration::from_secs(PEER_RETRY_INTERVAL)).await;
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
    let (remote_addr, remote_peer_dedup_key) =
        match check_for_duplicate_connections(&connection, peer_conn_info.peer_conns.clone()).await
        {
            Ok((addr, name)) => {
                info!("Peer connection established to {addr}/{name} (server role)");
                (addr, name)
            }
            Err(_) => {
                return Ok(());
            }
        };

    let sensor_list: HashSet<String> = peer_conn_info.ingest_sensors.read().await.to_owned();

    // Exchange peer list/sensor list.
    let (graphql_port, publish_port) = get_peer_ports(&peer_conn_info.config_doc);
    let (recv_peer_list, recv_sensor_list) =
        response_init_info::<(HashSet<PeerIdentity>, PeerInfo)>(
            &mut send,
            &mut recv,
            PeerCode::UpdatePeerList,
            (
                peer_conn_info.peer_identities.read().await.clone(),
                PeerInfo {
                    ingest_sensors: sensor_list,
                    graphql_port,
                    publish_port,
                },
            ),
        )
        .await?;

    // Update to the list of received sensors.
    update_to_new_sensor_list(
        recv_sensor_list,
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
        .insert(remote_peer_dedup_key.clone(), connection.clone());

    loop {
        select! {
            stream = connection.accept_bi()  => {
                let stream = match stream {
                    Err(e) => {
                        peer_conn_info.peer_conns.write().await.remove(&remote_peer_dedup_key);
                        peer_conn_info.peers.write().await.remove(&remote_addr);
                        if let quinn::ConnectionError::ApplicationClosed(_) = e {
                            info!("Data store peer({remote_peer_dedup_key}/{remote_addr}) closed");
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
                let path = peer_conn_info.config_path.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_request(stream, peer_conn_info.local_address, remote_addr, peer_list, peers, sender, doc, &path).await {
                        error!("Failed: {}", e);
                    }
                });
            },
            () = peer_conn_info.notify_sensor.notified() => {
                let sensor_list: HashSet<String> = peer_conn_info.ingest_sensors.read().await.to_owned();
                for conn in (*peer_conn_info.peer_conns.read().await).values() {
                    tokio::spawn(update_peer_info::<PeerInfo>(
                        conn.clone(),
                        PeerCode::UpdateSensorList,
                        PeerInfo {
                            ingest_sensors: sensor_list.clone(),
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
    path: &str,
) -> Result<()> {
    let (msg_type, msg_buf) = receive_peer_data(&mut recv).await?;
    match msg_type {
        PeerCode::UpdatePeerList => {
            let update_peer_list = bincode::deserialize::<HashSet<PeerIdentity>>(&msg_buf)
                .map_err(|e| anyhow!("Failed to deserialize peer list: {e}"))?;
            update_to_new_peer_list(update_peer_list, local_addr, peer_list, sender, doc, path)
                .await?;
        }
        PeerCode::UpdateSensorList => {
            let update_sensor_list = bincode::deserialize::<PeerInfo>(&msg_buf)
                .map_err(|e| anyhow!("Failed to deserialize sensor list: {e}"))?;
            update_to_new_sensor_list(update_sensor_list, remote_addr, peers).await;
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

fn ensure_peer_code_matches(expected: PeerCode, actual: PeerCode) -> Result<()> {
    if expected != actual {
        bail!("peer code mismatch: expected={expected:?}, actual={actual:?}");
    }
    Ok(())
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
    let (recv_code, recv_data) = receive_peer_data(recv).await?;
    ensure_peer_code_matches(init_type, recv_code)?;
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
    let (recv_code, recv_data) = receive_peer_data(recv).await?;
    ensure_peer_code_matches(init_type, recv_code)?;
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
    let remote_peer_dedup_key = peer_dedup_key_from_cert(&extract_cert_from_conn(connection)?)?;
    if peer_conn.read().await.contains_key(&remote_peer_dedup_key) {
        connection.close(
            quinn::VarInt::from_u32(0),
            "exist connection close".as_bytes(),
        );
        bail!("Duplicated connection close:{remote_peer_dedup_key:?}");
    }
    Ok((remote_addr, remote_peer_dedup_key))
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
            error!("Unable to generate TOML content: {e:?}");
        }
        if let Err(e) = write_toml_file(&doc, path) {
            error!("Failed to write TOML content to file: {e:?}");
        }
        info!("Peer list updated - {peer_list:?}");
    }

    Ok(())
}

async fn update_to_new_sensor_list(
    recv_sensor_list: PeerInfo,
    remote_addr: String,
    peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
) {
    info!("Sensor list updated - {recv_sensor_list:?}");
    peers.write().await.insert(remote_addr, recv_sensor_list);
}

#[cfg(test)]
pub mod tests {
    use std::{
        collections::{HashMap, HashSet},
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    use fixtures::*;
    use giganto_client::frame::{send_bytes, send_handshake, send_raw};
    use tokio::sync::mpsc::error::TryRecvError;
    use tokio::sync::{Notify, RwLock, oneshot};

    use super::*;
    use crate::graphql::status::{CONFIG_GRAPHQL_SRV_ADDR, CONFIG_PUBLISH_SRV_ADDR};
    #[cfg(feature = "bootroot")]
    use crate::server::peer_dedup_key_from_cert;
    #[cfg(feature = "bootroot")]
    use crate::test_bootroot::{
        build_bootroot_chain_fixture_with_server_name, build_bootroot_duplicate_peer_fixture,
        config_client_for_tests, load_certs,
    };

    mod fixtures {
        use std::{
            collections::{HashMap, HashSet},
            fs,
            future::Future,
            net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
            sync::{Arc, OnceLock},
            time::{Duration, Instant},
        };

        use anyhow::{Result, bail};
        use giganto_client::connection::{client_handshake, server_handshake};
        use giganto_client::frame::{send_bytes, send_raw};
        use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream};
        use tempfile::TempDir;
        use tokio::sync::{Notify, RwLock, oneshot};
        use tokio::{select, time::sleep};
        use toml_edit::DocumentMut;

        use super::super::{
            IngestSensors, PEER_VERSION_REQ, Peer, PeerCode, PeerConns, PeerIdentity, PeerIdents,
            PeerInfo, Peers, SharedClientConfig, client_connection, client_run, read_toml_file,
            server_connection,
        };
        use crate::comm::peer::{receive_peer_data, response_init_info};
        #[cfg(not(feature = "bootroot"))]
        use crate::comm::{to_cert_chain, to_private_key, to_root_cert};
        use crate::server::{Certs, SERVER_ENDPOINT_DELAY, config_client, config_server};
        #[cfg(feature = "bootroot")]
        use crate::test_bootroot::{
            TestNode, bootroot_cluster_certs, bootroot_cluster_server_name,
        };

        pub(super) const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");
        pub(super) const TEST_TIMEOUT: Duration = Duration::from_secs(10);

        static INIT: OnceLock<()> = OnceLock::new();
        static CLIENT_CONFIG: OnceLock<ClientConfig> = OnceLock::new();
        static CERTS_NODE1: OnceLock<Certs> = OnceLock::new();
        static CERTS_NODE2: OnceLock<Certs> = OnceLock::new();

        pub(super) fn init_crypto() {
            INIT.get_or_init(|| {
                let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            });
        }

        #[cfg(not(feature = "bootroot"))]
        pub(super) fn test_connect_name() -> &'static str {
            "node1"
        }

        #[cfg(feature = "bootroot")]
        pub(super) fn test_connect_name() -> &'static str {
            bootroot_cluster_server_name(TestNode::Node1)
        }

        #[cfg(not(feature = "bootroot"))]
        pub(super) fn test_connect_name_node2() -> &'static str {
            "node2"
        }

        #[cfg(feature = "bootroot")]
        pub(super) fn test_connect_name_node2() -> &'static str {
            bootroot_cluster_server_name(TestNode::Node2)
        }

        #[cfg(not(feature = "bootroot"))]
        pub(super) fn test_subject_peer_dedup_key() -> &'static str {
            "node1"
        }

        #[cfg(feature = "bootroot")]
        pub(super) fn test_subject_peer_dedup_key() -> &'static str {
            bootroot_cluster_server_name(TestNode::Node1)
        }

        pub(super) struct TempConfig {
            _dir: TempDir,
            path: String,
        }

        impl TempConfig {
            pub(super) fn from_str(contents: &str) -> Self {
                let dir = TempDir::new().unwrap();
                let path = dir.path().join("config.toml");
                fs::write(&path, contents).unwrap();
                Self {
                    _dir: dir,
                    path: path.to_string_lossy().to_string(),
                }
            }

            pub(super) fn from_doc(doc: &DocumentMut) -> Self {
                Self::from_str(&doc.to_string())
            }

            pub(super) fn path(&self) -> &str {
                &self.path
            }
        }

        pub(super) async fn with_timeout<T, F>(label: &'static str, fut: F) -> T
        where
            F: Future<Output = T>,
        {
            tokio::time::timeout(TEST_TIMEOUT, fut).await.expect(label)
        }

        pub(super) async fn accept_incoming(
            endpoint: &Endpoint,
            label: &'static str,
        ) -> quinn::Incoming {
            with_timeout(label, endpoint.accept())
                .await
                .expect("incoming closed before accept")
        }

        pub(super) fn peer_identity(addr: SocketAddr, hostname: &str) -> PeerIdentity {
            PeerIdentity {
                addr,
                hostname: hostname.to_string(),
            }
        }

        pub(super) fn peer_info(
            sensors: &[&str],
            graphql_port: Option<u16>,
            publish_port: Option<u16>,
        ) -> PeerInfo {
            PeerInfo {
                ingest_sensors: sensors.iter().map(|s| (*s).to_string()).collect(),
                graphql_port,
                publish_port,
            }
        }

        pub(super) struct TestClient {
            pub(super) send: SendStream,
            pub(super) recv: RecvStream,
            pub(super) conn: Connection,
        }

        impl TestClient {
            pub(super) async fn new(server_addr: SocketAddr) -> Self {
                let endpoint = init_client();
                let conn = endpoint
                    .connect(server_addr, test_connect_name())
                    .expect(
                        "Failed to connect server's endpoint, Please check if the setting value is correct",
                    )
                    .await
                    .expect(
                        "Failed to connect server's endpoint, Please make sure the Server is alive",
                    );
                let (send, recv) = client_handshake(&conn, PROTOCOL_VERSION).await.unwrap();
                Self { send, recv, conn }
            }
        }

        fn client_config() -> ClientConfig {
            CLIENT_CONFIG
                .get_or_init(|| config_client(&create_certs()).expect("peer test client config"))
                .clone()
        }

        pub(super) fn init_client() -> Endpoint {
            let mut endpoint =
                quinn::Endpoint::client("[::]:0".parse().expect("Failed to parse Endpoint addr"))
                    .expect("Failed to create endpoint");
            endpoint.set_default_client_config(client_config());
            endpoint
        }

        pub(super) fn init_shared_client_config() -> super::SharedClientConfig {
            super::new_shared_client_config(client_config())
        }

        /// Builds a paired `watch::Sender`/`TlsWatch` seeded with `certs`.
        /// Tests keep the sender alive to broadcast reload events on demand.
        pub(super) fn test_tls_watch_from_certs(
            certs: Certs,
        ) -> (
            tokio::sync::watch::Sender<Arc<crate::tls_reload::TlsMaterial>>,
            crate::tls_reload::TlsWatch,
        ) {
            let material = Arc::new(crate::tls_reload::TlsMaterial {
                certs: Arc::new(certs),
                cert_pem: Vec::new(),
                key_pem: Vec::new(),
            });
            crate::tls_reload::test_tls_watch(material)
        }

        #[cfg(not(feature = "bootroot"))]
        fn create_certs_from_paths(cert_path: &str, key_path: &str) -> Certs {
            Certs {
                certs: to_cert_chain(&fs::read(cert_path).unwrap()).unwrap(),
                key: to_private_key(&fs::read(key_path).unwrap()).unwrap(),
                root: to_root_cert(&["tests/certs/ca_cert.pem".to_string()]).unwrap(),
            }
        }

        pub(super) fn create_certs() -> Certs {
            #[cfg(not(feature = "bootroot"))]
            {
                CERTS_NODE1
                    .get_or_init(|| {
                        create_certs_from_paths(
                            "tests/certs/node1/cert.pem",
                            "tests/certs/node1/key.pem",
                        )
                    })
                    .clone()
            }

            #[cfg(feature = "bootroot")]
            {
                CERTS_NODE1
                    .get_or_init(|| bootroot_cluster_certs(TestNode::Node1))
                    .clone()
            }
        }

        pub(super) fn create_node2_certs() -> Certs {
            #[cfg(not(feature = "bootroot"))]
            {
                CERTS_NODE2
                    .get_or_init(|| {
                        create_certs_from_paths(
                            "tests/certs/node2/cert.pem",
                            "tests/certs/node2/key.pem",
                        )
                    })
                    .clone()
            }

            #[cfg(feature = "bootroot")]
            {
                CERTS_NODE2
                    .get_or_init(|| bootroot_cluster_certs(TestNode::Node2))
                    .clone()
            }
        }

        pub(super) fn build_peer_conn_info(local_address: SocketAddr) -> (PeerConns, TempConfig) {
            let peer_conns = Arc::new(RwLock::new(HashMap::new()));
            let peer_idents = Arc::new(RwLock::new(HashSet::new()));
            let peers = Arc::new(RwLock::new(HashMap::new()));
            let ingest_sensors = Arc::new(RwLock::new(HashSet::new()));
            let (sender, _receiver) = tokio::sync::mpsc::channel(1);
            let doc = "peers = []".parse::<DocumentMut>().unwrap();
            let config = TempConfig::from_doc(&doc);
            let peer_conn_info = PeerConns {
                peer_conns,
                peer_identities: peer_idents,
                peers,
                ingest_sensors,
                peer_sender: sender,
                local_address,
                notify_sensor: Arc::new(Notify::new()),
                config_doc: doc,
                config_path: config.path().to_string(),
            };

            (peer_conn_info, config)
        }

        pub(super) fn build_peer_conn_info_with_sensors(
            local_address: SocketAddr,
            sensors: &[&str],
        ) -> (PeerConns, TempConfig) {
            let (mut peer_conn_info, config) = build_peer_conn_info(local_address);
            let ingest_sensors = sensors.iter().map(|s| (*s).to_string()).collect();
            peer_conn_info.ingest_sensors = Arc::new(RwLock::new(ingest_sensors));
            (peer_conn_info, config)
        }

        pub(super) async fn send_peer_code_payload(
            send: &mut SendStream,
            code: PeerCode,
            payload: &[u8],
        ) {
            let code: u32 = code.into();
            send_bytes(send, &code.to_le_bytes()).await.unwrap();
            send_raw(send, payload).await.unwrap();
            send.finish().ok();
        }

        pub(super) struct ConnectedPeers {
            pub(super) client_endpoint: Endpoint,
            pub(super) server_conn: Connection,
            pub(super) client_conn: Connection,
        }

        pub(super) fn setup_server_endpoint_with_certs(certs: &Certs) -> (Endpoint, SocketAddr) {
            let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
            let server_config = config_server(certs).unwrap();
            let server_endpoint = Endpoint::server(server_config, server_addr).unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();

            (server_endpoint, server_addr)
        }

        pub(super) fn setup_server_endpoint() -> (Endpoint, SocketAddr) {
            let certs = create_certs();
            setup_server_endpoint_with_certs(&certs)
        }

        pub(super) async fn connect_client_server(
            server_endpoint: &Endpoint,
            server_addr: SocketAddr,
        ) -> ConnectedPeers {
            let client_endpoint = init_client();
            let connect_fut = client_endpoint
                .connect(server_addr, test_connect_name())
                .unwrap();
            let accept_fut = async {
                let incoming = accept_incoming(server_endpoint, "server accept timeout").await;
                incoming.await.unwrap()
            };
            let (server_conn, client_conn_res) = tokio::join!(accept_fut, connect_fut);
            let client_conn = client_conn_res.unwrap();

            ConnectedPeers {
                client_endpoint,
                server_conn,
                client_conn,
            }
        }

        pub(super) async fn connect_client_handshake(
            server_addr: SocketAddr,
        ) -> (Connection, SendStream, RecvStream) {
            let client_endpoint = init_client();
            let conn = with_timeout(
                "client connect timeout",
                client_endpoint
                    .connect(server_addr, test_connect_name())
                    .unwrap(),
            )
            .await
            .unwrap();
            let (send, recv) = client_handshake(&conn, PROTOCOL_VERSION).await.unwrap();
            (conn, send, recv)
        }

        pub(super) async fn accept_server_handshake(
            server_endpoint: Endpoint,
        ) -> (SendStream, RecvStream) {
            let incoming = accept_incoming(&server_endpoint, "server accept timeout").await;
            let server_conn = incoming.await.unwrap();
            server_handshake(&server_conn, PEER_VERSION_REQ)
                .await
                .unwrap()
        }

        pub(super) fn assert_peer_info_eq(actual: &PeerInfo, expected: &PeerInfo) {
            assert_eq!(actual.graphql_port, expected.graphql_port);
            assert_eq!(actual.publish_port, expected.publish_port);
            assert_eq!(actual.ingest_sensors, expected.ingest_sensors);
        }

        pub(super) fn peer_init() -> Peer {
            let certs = Arc::new(create_certs());

            Peer::new(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0), &certs).unwrap()
        }

        pub(super) async fn connect_test_client(server_addr: SocketAddr) -> TestClient {
            let start = Instant::now();
            let endpoint = init_client();
            loop {
                let connect = endpoint.connect(server_addr, test_connect_name());
                if let Ok(connecting) = connect
                    && let Ok(conn) = tokio::time::timeout(Duration::from_secs(1), connecting).await
                    && let Ok(conn) = conn
                    && let Ok((send, recv)) = client_handshake(&conn, PROTOCOL_VERSION).await
                {
                    return TestClient { send, recv, conn };
                }

                assert!(
                    start.elapsed() <= Duration::from_secs(2),
                    "server did not accept connection in time"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }

        pub(super) async fn wait_for_peer_info<F>(
            label: &'static str,
            peers: &Arc<RwLock<HashMap<String, PeerInfo>>>,
            mut predicate: F,
        ) where
            F: FnMut(&HashMap<String, PeerInfo>) -> bool,
        {
            let fut = async {
                let mut interval = tokio::time::interval(Duration::from_millis(10));
                loop {
                    interval.tick().await;
                    let read_peers = peers.read().await;
                    if predicate(&read_peers) {
                        break;
                    }
                }
            };
            if tokio::time::timeout(TEST_TIMEOUT, fut).await.is_err() {
                let read_peers = peers.read().await;
                let peer_summaries: Vec<String> = read_peers
                    .iter()
                    .map(|(key, info)| {
                        format!(
                            "{key} ports={:?}/{:?} sensors={}",
                            info.graphql_port,
                            info.publish_port,
                            info.ingest_sensors.len()
                        )
                    })
                    .collect();
                panic!("{label}: timeout; peers={peer_summaries:?}");
            }
        }

        pub(super) async fn drain_peer_receiver(
            mut receiver: tokio::sync::mpsc::Receiver<PeerIdentity>,
            expected: usize,
        ) -> HashSet<PeerIdentity> {
            let mut recv = HashSet::new();
            for _ in 0..expected {
                let peer = receiver.recv().await.expect("peer recv closed");
                recv.insert(peer);
            }
            recv
        }

        pub(super) fn spawn_server_connection(
            server_endpoint: Endpoint,
            peer_conn_info: PeerConns,
            notify_shutdown: Arc<Notify>,
        ) -> tokio::task::JoinHandle<Result<()>> {
            tokio::spawn(async move {
                let incoming = accept_incoming(&server_endpoint, "server accept timeout").await;
                server_connection(incoming, peer_conn_info, notify_shutdown).await
            })
        }

        #[allow(clippy::too_many_arguments)]
        pub(super) async fn run_peer_with_ready(
            peer: Peer,
            ingest_sensors: IngestSensors,
            peers: Peers,
            peer_idents: PeerIdents,
            notify_sensor: Arc<Notify>,
            notify_shutdown: Arc<Notify>,
            config_path: String,
            ready: oneshot::Sender<SocketAddr>,
        ) -> Result<()> {
            let local_connect_name = peer.local_connect_name.clone();
            let server_endpoint =
                Endpoint::server(peer.server_config, peer.local_address).expect("endpoint");
            let local_addr = server_endpoint
                .local_addr()
                .expect("for local addr display");
            let _ = ready.send(local_addr);

            let client_socket = SocketAddr::new(peer.local_address.ip(), 0);
            let client_endpoint = Endpoint::client(client_socket).expect("endpoint");
            let shared_client_config: SharedClientConfig =
                super::new_shared_client_config(peer.client_config);

            let (sender, mut receiver) = tokio::sync::mpsc::channel(100);
            let Ok(config_doc) = read_toml_file(&config_path) else {
                bail!("Failed to open/read config's toml file");
            };

            let peer_conn_info = PeerConns {
                peer_conns: Arc::new(RwLock::new(HashMap::new())),
                peer_identities: peer_idents,
                peers,
                ingest_sensors,
                peer_sender: sender,
                local_address: peer.local_address,
                notify_sensor,
                config_doc,
                config_path,
            };

            tokio::spawn(client_run(
                client_endpoint.clone(),
                shared_client_config.clone(),
                peer_conn_info.clone(),
                peer.local_connect_name.clone(),
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
                                tracing::error!("Connection to {remote} failed: {e}");
                            }
                        });
                    },
                    Some(peer) = receiver.recv()  => {
                            tokio::spawn(client_connection(
                                client_endpoint.clone(),
                                shared_client_config.clone(),
                                peer,
                                peer_conn_info.clone(),
                                local_connect_name.clone(),
                                notify_shutdown.clone(),
                            ));
                    },
                    () = notify_shutdown.notified() => {
                        sleep(Duration::from_millis(SERVER_ENDPOINT_DELAY)).await;
                        server_endpoint.close(0_u32.into(), &[]);
                        return Ok(());
                    }
                }
            }
        }
        /// Variant of `run_peer_with_ready` that additionally wires a
        /// [`TlsWatch`](crate::tls_reload::TlsWatch) into the peer subsystem
        /// so tests can drive the common-reload-trigger code path.
        #[allow(clippy::too_many_arguments)]
        pub(super) async fn run_peer_with_ready_and_tls_watch(
            peer: Peer,
            ingest_sensors: IngestSensors,
            peers: Peers,
            peer_idents: PeerIdents,
            notify_sensor: Arc<Notify>,
            notify_shutdown: Arc<Notify>,
            config_path: String,
            tls_watch: crate::tls_reload::TlsWatch,
            ready: oneshot::Sender<SocketAddr>,
        ) -> Result<()> {
            let local_connect_name = peer.local_connect_name.clone();
            let server_endpoint =
                Endpoint::server(peer.server_config, peer.local_address).expect("endpoint");
            let local_addr = server_endpoint
                .local_addr()
                .expect("for local addr display");
            let _ = ready.send(local_addr);

            let client_socket = SocketAddr::new(peer.local_address.ip(), 0);
            let client_endpoint = Endpoint::client(client_socket).expect("endpoint");
            let shared_client_config: SharedClientConfig =
                super::new_shared_client_config(peer.client_config);

            let (sender, mut receiver) = tokio::sync::mpsc::channel(100);
            let Ok(config_doc) = read_toml_file(&config_path) else {
                bail!("Failed to open/read config's toml file");
            };

            let peer_conn_info = PeerConns {
                peer_conns: Arc::new(RwLock::new(HashMap::new())),
                peer_identities: peer_idents,
                peers,
                ingest_sensors,
                peer_sender: sender,
                local_address: peer.local_address,
                notify_sensor,
                config_doc,
                config_path,
            };

            tokio::spawn(client_run(
                client_endpoint.clone(),
                shared_client_config.clone(),
                peer_conn_info.clone(),
                peer.local_connect_name.clone(),
                notify_shutdown.clone(),
            ));

            let mut tls_watch = tls_watch;
            tls_watch.mark_unchanged();
            let mut tls_reload_closed = false;
            loop {
                select! {
                    Some(conn) = server_endpoint.accept() => {
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
                                tracing::error!("Connection to {remote} failed: {e}");
                            }
                        });
                    },
                    Some(peer) = receiver.recv() => {
                        tokio::spawn(client_connection(
                            client_endpoint.clone(),
                            shared_client_config.clone(),
                            peer,
                            peer_conn_info.clone(),
                            local_connect_name.clone(),
                            notify_shutdown.clone(),
                        ));
                    },
                    res = tls_watch.changed(), if !tls_reload_closed => {
                        if res.is_err() {
                            tls_reload_closed = true;
                            continue;
                        }
                        let material = tls_watch.borrow_and_update().clone();
                        super::apply_peer_tls_reload(
                            &server_endpoint,
                            &shared_client_config,
                            &material.certs,
                        );
                    },
                    () = notify_shutdown.notified() => {
                        sleep(Duration::from_millis(SERVER_ENDPOINT_DELAY)).await;
                        server_endpoint.close(0_u32.into(), &[]);
                        return Ok(());
                    }
                }
            }
        }

        pub(super) fn spawn_request_init_info_response_server(
            server_endpoint: Endpoint,
            response_code: PeerCode,
            response_payload: Vec<u8>,
        ) -> (oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let handle = tokio::spawn(async move {
                let (mut send, mut recv) = accept_server_handshake(server_endpoint).await;
                let _ = receive_peer_data(&mut recv).await.unwrap();
                send_peer_code_payload(&mut send, response_code, &response_payload).await;
                let _ = shutdown_rx.await;
            });
            (shutdown_tx, handle)
        }

        pub(super) fn spawn_response_init_info_server(
            server_endpoint: Endpoint,
        ) -> tokio::task::JoinHandle<Result<PeerInfo>> {
            tokio::spawn(async move {
                let (mut send, mut recv) = accept_server_handshake(server_endpoint).await;
                response_init_info(
                    &mut send,
                    &mut recv,
                    PeerCode::UpdatePeerList,
                    PeerInfo::default(),
                )
                .await
            })
        }

        pub(super) fn assert_peer_code_mismatch(
            err: &anyhow::Error,
            expected: PeerCode,
            actual: PeerCode,
        ) {
            assert!(err.to_string().contains(&format!(
                "peer code mismatch: expected={expected:?}, actual={actual:?}"
            )));
        }
    }

    #[tokio::test]
    async fn recv_peer_data_updates_peer_and_sensor_lists() {
        init_crypto();

        // peer server's peer list
        let peer_addr = SocketAddr::new("123.123.123.123".parse::<IpAddr>().unwrap(), 38383);
        let peer_name = String::from("test_peer");
        let mut peer_identities = HashSet::new();
        peer_identities.insert(PeerIdentity {
            addr: peer_addr,
            hostname: peer_name.clone(),
        });
        let peer_idents = Arc::new(RwLock::new(peer_identities));

        // peer server's sensor list
        let sensor_name = String::from("test_sensor");
        let mut sensor_info = HashSet::new();
        sensor_info.insert(sensor_name.clone());

        let ingest_sensors = Arc::new(RwLock::new(sensor_info));
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let notify_sensor = Arc::new(Notify::new());

        let config = TempConfig::from_str("peers = []");

        // run peer
        let notify_shutdown = Arc::new(Notify::new());
        let notify_shutdown_handle = notify_shutdown.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        let peer_handle = tokio::spawn(run_peer_with_ready(
            peer_init(),
            ingest_sensors.clone(),
            peers,
            peer_idents,
            notify_sensor.clone(),
            notify_shutdown,
            config.path().to_string(),
            ready_tx,
        ));

        // run peer client
        let server_addr = with_timeout("peer server ready timeout", ready_rx)
            .await
            .expect("peer server did not report addr");
        let mut peer_client_one = TestClient::new(server_addr).await;
        let (recv_peer_list, recv_sensor_list) =
            request_init_info::<(HashSet<PeerIdentity>, PeerInfo)>(
                &mut peer_client_one.send,
                &mut peer_client_one.recv,
                PeerCode::UpdatePeerList,
                (HashSet::new(), PeerInfo::default()),
            )
            .await
            .unwrap();

        // compare server's peer list/sensor list
        let expected_peer = PeerIdentity {
            addr: peer_addr,
            hostname: peer_name,
        };
        assert_eq!(recv_peer_list.len(), 1);
        assert!(recv_peer_list.contains(&expected_peer));
        assert_eq!(recv_sensor_list.ingest_sensors.len(), 1);
        assert!(recv_sensor_list.ingest_sensors.contains(&sensor_name));

        // insert peer server's sensor value & notify to server
        let sensor_name2 = String::from("test_sensor2");
        ingest_sensors.write().await.insert(sensor_name2.clone());
        notify_sensor.notify_one();

        // receive sensor list
        let (_, mut recv_pub_resp) = with_timeout(
            "peer update stream timeout",
            peer_client_one.conn.accept_bi(),
        )
        .await
        .expect("failed to open stream");
        let (msg_type, msg_buf) = receive_peer_data(&mut recv_pub_resp).await.unwrap();
        let update_sensor_list = bincode::deserialize::<PeerInfo>(&msg_buf).unwrap();

        // compare server's sensor list
        assert_eq!(msg_type, PeerCode::UpdateSensorList);
        assert_eq!(update_sensor_list.ingest_sensors.len(), 2);
        assert!(update_sensor_list.ingest_sensors.contains(&sensor_name));
        assert!(update_sensor_list.ingest_sensors.contains(&sensor_name2));

        notify_shutdown_handle.notify_waiters();
        with_timeout("peer shutdown timeout", peer_handle)
            .await
            .expect("peer task failed")
            .expect("peer task join error");
    }

    #[tokio::test]
    async fn test_run_accepts_connection_and_updates_peer_info() {
        init_crypto();

        let certs = Arc::new(create_certs());
        let peer = Peer::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), &certs).unwrap();

        let ingest_sensors = Arc::new(RwLock::new(HashSet::from(["run-sensor".to_string()])));
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let peers_for_assert = peers.clone();
        let peer_idents = Arc::new(RwLock::new(HashSet::new()));
        let notify_sensor = Arc::new(Notify::new());
        let notify_shutdown = Arc::new(Notify::new());

        let config = TempConfig::from_str("peers = []");

        let other_certs = create_node2_certs();
        let (other_endpoint, other_addr) = setup_server_endpoint_with_certs(&other_certs);
        let (other_ready_tx, other_ready_rx) = oneshot::channel();
        let (other_shutdown_tx, other_shutdown_rx) = oneshot::channel();
        let other_task = tokio::spawn(async move {
            let incoming = accept_incoming(&other_endpoint, "other peer accept timeout").await;
            let connection = incoming.await.unwrap();
            let (mut send, mut recv) = server_handshake(&connection, PEER_VERSION_REQ)
                .await
                .unwrap();
            response_init_info::<(HashSet<PeerIdentity>, PeerInfo)>(
                &mut send,
                &mut recv,
                PeerCode::UpdatePeerList,
                (HashSet::new(), PeerInfo::default()),
            )
            .await
            .unwrap();
            let _ = other_ready_tx.send(());
            let _ = other_shutdown_rx.await;
        });

        let (ready_tx, ready_rx) = oneshot::channel();
        let run_handle = tokio::spawn(run_peer_with_ready(
            peer,
            ingest_sensors.clone(),
            peers,
            peer_idents,
            notify_sensor,
            notify_shutdown.clone(),
            config.path().to_string(),
            ready_tx,
        ));

        let run_addr = with_timeout("peer server ready timeout", ready_rx)
            .await
            .expect("peer server did not report addr");
        let mut client = connect_test_client(run_addr).await;
        let peer_list: HashSet<PeerIdentity> =
            HashSet::from([peer_identity(other_addr, test_connect_name_node2())]);
        let client_info = peer_info(&["client-sensor"], Some(9201), Some(9202));
        let (_recv_peer_list, recv_sensor_list) =
            request_init_info::<(HashSet<PeerIdentity>, PeerInfo)>(
                &mut client.send,
                &mut client.recv,
                PeerCode::UpdatePeerList,
                (peer_list, client_info),
            )
            .await
            .unwrap();
        assert!(recv_sensor_list.ingest_sensors.contains("run-sensor"));

        wait_for_peer_info(
            "peer info update timeout",
            &peers_for_assert,
            |read_peers| {
                read_peers.values().any(|info| {
                    info.graphql_port == Some(9201)
                        && info.publish_port == Some(9202)
                        && info.ingest_sensors.contains("client-sensor")
                })
            },
        )
        .await;

        with_timeout("client connection spawn timeout", other_ready_rx)
            .await
            .expect("other peer did not accept");

        notify_shutdown.notify_waiters();
        let _ = other_shutdown_tx.send(());
        with_timeout("run shutdown timeout", run_handle)
            .await
            .expect("run task failed")
            .expect("run returned error");
        with_timeout("other peer shutdown timeout", other_task)
            .await
            .expect("other peer task failed");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_client_connection_exchanges_lists_and_notifies_existing_peer() {
        init_crypto();

        let (server_endpoint, server_addr) = setup_server_endpoint();
        let server_identity = peer_identity(server_addr, test_connect_name());

        let (server_ready_tx, server_ready_rx) =
            oneshot::channel::<(HashSet<PeerIdentity>, PeerInfo)>();
        let (server_shutdown_tx, server_shutdown_rx) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let incoming = accept_incoming(&server_endpoint, "server accept timeout").await;
            let connection = incoming.await.unwrap();
            let (mut send, mut recv) = server_handshake(&connection, PEER_VERSION_REQ)
                .await
                .unwrap();
            let server_info = peer_info(&["server-sensor"], Some(9101), Some(9102));
            let server_peer_list: HashSet<PeerIdentity> =
                vec![server_identity].into_iter().collect();
            let (recv_peer_list, recv_sensor_list) =
                response_init_info::<(HashSet<PeerIdentity>, PeerInfo)>(
                    &mut send,
                    &mut recv,
                    PeerCode::UpdatePeerList,
                    (server_peer_list, server_info),
                )
                .await
                .unwrap();

            let _ = server_ready_tx.send((recv_peer_list, recv_sensor_list));
            let _ = server_shutdown_rx.await;
        });

        let (dummy_server_endpoint, dummy_addr) = setup_server_endpoint();
        let ConnectedPeers {
            client_endpoint: _dummy_client_endpoint,
            server_conn: _dummy_server_conn,
            client_conn: dummy_client_conn,
        } = connect_client_server(&dummy_server_endpoint, dummy_addr).await;

        let peer_conns = Arc::new(RwLock::new(HashMap::from([(
            "dummy".to_string(),
            dummy_client_conn,
        )])));
        let peer_idents = Arc::new(RwLock::new(HashSet::from([PeerIdentity {
            addr: dummy_addr,
            hostname: "dummy".to_string(),
        }])));
        let ingest_sensors = Arc::new(RwLock::new(HashSet::from(["client-sensor".to_string()])));
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
        let toml_str = format!(
            "{CONFIG_GRAPHQL_SRV_ADDR} = \"127.0.0.1:9001\"\n{CONFIG_PUBLISH_SRV_ADDR} = \"127.0.0.1:9002\"\npeers = []"
        );
        let doc = toml_str.parse::<toml_edit::DocumentMut>().unwrap();
        let config = TempConfig::from_doc(&doc);

        let peer_conn_info = PeerConns {
            peer_conns,
            peer_identities: peer_idents.clone(),
            peers: peers.clone(),
            ingest_sensors,
            peer_sender: sender,
            local_address: "127.0.0.1:1111".parse().unwrap(),
            notify_sensor: Arc::new(Notify::new()),
            config_doc: doc,
            config_path: config.path().to_string(),
        };

        let client_endpoint = init_client();
        let notify_shutdown = Arc::new(Notify::new());
        let peer_info = PeerIdentity {
            addr: server_addr,
            hostname: test_connect_name().to_string(),
        };
        let shared_client_config = init_shared_client_config();
        let client_task = tokio::spawn(client_connection(
            client_endpoint,
            shared_client_config,
            peer_info,
            peer_conn_info,
            "client-node".to_string(),
            notify_shutdown.clone(),
        ));

        let (recv_peer_list, recv_sensor_list) =
            with_timeout("server ready timeout", server_ready_rx)
                .await
                .expect("server ready channel closed");
        let expected_identity = peer_identity("127.0.0.1:1111".parse().unwrap(), "client-node");
        assert!(recv_peer_list.contains(&expected_identity));
        assert!(recv_sensor_list.ingest_sensors.contains("client-sensor"));

        let recv_peer = with_timeout("peer sender timeout", receiver.recv()).await;
        assert_eq!(
            recv_peer,
            Some(peer_identity(server_addr, test_connect_name()))
        );

        wait_for_peer_info("peers update timeout", &peers, |read_peers| {
            read_peers.values().any(|info| {
                info.graphql_port == Some(9101)
                    && info.publish_port == Some(9102)
                    && info.ingest_sensors.contains("server-sensor")
            })
        })
        .await;

        let _ = server_shutdown_tx.send(());
        notify_shutdown.notify_waiters();
        let _ = with_timeout("client shutdown timeout", client_task).await;

        let _ = with_timeout("server shutdown timeout", server_task).await;
    }

    #[tokio::test]
    async fn test_server_connection_handles_stream_and_notifies_existing_peer() {
        init_crypto();

        let (server_endpoint, server_addr) = setup_server_endpoint();
        let (existing_server_endpoint, existing_addr) = setup_server_endpoint();

        let existing_accept = tokio::spawn(async move {
            let incoming =
                accept_incoming(&existing_server_endpoint, "existing accept timeout").await;
            let connection = incoming.await.unwrap();
            let (_send, mut recv) = connection.accept_bi().await.unwrap();
            receive_peer_data(&mut recv).await.unwrap()
        });
        let existing_client_endpoint = init_client();
        let existing_client_conn = existing_client_endpoint
            .connect(existing_addr, test_connect_name())
            .unwrap()
            .await
            .unwrap();

        let peer_conns = Arc::new(RwLock::new(HashMap::from([(
            "existing".to_string(),
            existing_client_conn,
        )])));
        let (sender, mut receiver) = tokio::sync::mpsc::channel(10);
        let (mut peer_conn_info, _config) = build_peer_conn_info_with_sensors(
            "127.0.0.1:2222".parse().unwrap(),
            &["server-sensor"],
        );
        peer_conn_info.peer_conns = peer_conns;
        peer_conn_info.peer_sender = sender;
        let peers = peer_conn_info.peers.clone();

        let notify_shutdown = Arc::new(Notify::new());
        let notify_shutdown_handle = notify_shutdown.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = accept_incoming(&server_endpoint, "server accept timeout").await;
            server_connection(incoming, peer_conn_info, notify_shutdown_handle)
                .await
                .unwrap();
        });

        let mut client = connect_test_client(server_addr).await;
        let client_info = peer_info(&["client-sensor"], Some(9001), Some(9002));
        let new_peer = peer_identity("127.0.0.1:3333".parse().unwrap(), "node-new");
        let client_peer_list: HashSet<PeerIdentity> = HashSet::from([new_peer.clone()]);
        request_init_info::<(HashSet<PeerIdentity>, PeerInfo)>(
            &mut client.send,
            &mut client.recv,
            PeerCode::UpdatePeerList,
            (client_peer_list, client_info),
        )
        .await
        .unwrap();

        let recv_peer = with_timeout("peer sender timeout", receiver.recv()).await;
        assert_eq!(recv_peer, Some(new_peer.clone()));

        let (mut send_update, _recv_update) = client.conn.open_bi().await.unwrap();
        let update_info = peer_info(&["updated-sensor"], Some(9003), Some(9004));
        send_peer_data(&mut send_update, PeerCode::UpdateSensorList, update_info)
            .await
            .unwrap();
        send_update.finish().ok();

        let (code, buf) = existing_accept.await.unwrap();
        assert_eq!(code, PeerCode::UpdatePeerList);
        let received_peer_list: HashSet<PeerIdentity> = bincode::deserialize(&buf).unwrap();
        assert!(received_peer_list.contains(&new_peer));
        assert_eq!(received_peer_list.len(), 1);

        wait_for_peer_info("peer info update timeout", &peers, |read_peers| {
            if let Some(stored) = read_peers.get(&server_addr.ip().to_string()) {
                stored.graphql_port == Some(9003)
                    && stored.publish_port == Some(9004)
                    && stored.ingest_sensors.contains("updated-sensor")
                    && stored.ingest_sensors.len() == 1
            } else {
                false
            }
        })
        .await;

        notify_shutdown.notify_waiters();
        drop(client.conn);
        let server_result = with_timeout("server shutdown timeout", server_handle).await;
        server_result.expect("server task panicked");
    }

    #[tokio::test]
    async fn test_server_connection_returns_error_on_handshake_failure() {
        init_crypto();

        let (server_endpoint, server_addr) = setup_server_endpoint();

        let (peer_conn_info, _config) = build_peer_conn_info("127.0.0.1:3333".parse().unwrap());
        let notify_shutdown = Arc::new(Notify::new());
        let server_handle =
            spawn_server_connection(server_endpoint, peer_conn_info, notify_shutdown);

        let client_endpoint = init_client();
        let client_conn = with_timeout(
            "client connect timeout",
            client_endpoint
                .connect(server_addr, test_connect_name())
                .unwrap(),
        )
        .await
        .unwrap();
        let (mut send, _recv) = client_conn.open_bi().await.unwrap();
        send_handshake(&mut send, &[0xFF]).await.unwrap();
        send.finish().ok();

        let err = server_handle.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("Invalid message"));
    }

    #[tokio::test]
    async fn test_server_connection_rejects_incompatible_protocol() {
        init_crypto();

        let (server_endpoint, server_addr) = setup_server_endpoint();

        let (peer_conn_info, _config) = build_peer_conn_info("127.0.0.1:3334".parse().unwrap());
        let notify_shutdown = Arc::new(Notify::new());
        let server_handle =
            spawn_server_connection(server_endpoint, peer_conn_info, notify_shutdown);

        let client_endpoint = init_client();
        let client_conn = with_timeout(
            "client connect timeout",
            client_endpoint
                .connect(server_addr, test_connect_name())
                .unwrap(),
        )
        .await
        .unwrap();
        let _ = client_handshake(&client_conn, "99.0.0").await;

        let err = server_handle.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("not supported"));
        assert!(err.to_string().contains("Protocol version"));
    }

    #[test]
    fn test_get_port_from_config() {
        let toml_str = r#"
            graphql_address = "127.0.0.1:8443"
            publish_address = "127.0.0.1:38371"
        "#;
        let doc = toml_str.parse::<toml_edit::DocumentMut>().unwrap();
        assert_eq!(get_port_from_config("graphql_address", &doc), Some(8443));
        assert_eq!(get_port_from_config("publish_address", &doc), Some(38371));
        assert_eq!(get_port_from_config("non_existent", &doc), None);
    }

    #[test]
    fn test_get_port_from_config_rejects_invalid_port() {
        let toml_str = r#"
            graphql_address = "127.0.0.1:not_a_port"
            publish_address = "127.0.0.1"
        "#;
        let doc = toml_str.parse::<toml_edit::DocumentMut>().unwrap();
        assert_eq!(get_port_from_config("graphql_address", &doc), None);
        assert_eq!(get_port_from_config("publish_address", &doc), None);
    }

    #[test]
    fn test_get_peer_ports() {
        let toml_str = format!(
            "{} = \"127.0.0.1:8443\"\n{} = \"127.0.0.1:38371\"",
            crate::graphql::status::CONFIG_GRAPHQL_SRV_ADDR,
            crate::graphql::status::CONFIG_PUBLISH_SRV_ADDR
        );
        let doc = toml_str.parse::<toml_edit::DocumentMut>().unwrap();
        let (graphql, publish) = get_peer_ports(&doc);
        assert_eq!(graphql, Some(8443));
        assert_eq!(publish, Some(38371));
    }

    #[tokio::test]
    async fn test_send_receive_peer_data() {
        init_crypto();

        let (server_endpoint, server_actual_addr) = setup_server_endpoint();

        let server_handle = tokio::spawn(async move {
            let incoming = accept_incoming(&server_endpoint, "server accept timeout").await;
            let server_conn = incoming.await.unwrap();
            let (_server_send, mut server_recv) = server_conn.accept_bi().await.unwrap();
            receive_peer_data(&mut server_recv).await.unwrap()
        });

        let client_endpoint = init_client();

        let client_conn = with_timeout(
            "client connect timeout",
            client_endpoint
                .connect(server_actual_addr, test_connect_name())
                .unwrap(),
        )
        .await
        .unwrap();

        let (mut client_send, _client_recv) = client_conn.open_bi().await.unwrap();

        let test_info = peer_info(&["sensor1"], Some(8080), Some(9090));

        send_peer_data(&mut client_send, PeerCode::UpdateSensorList, &test_info)
            .await
            .unwrap();

        let (code, buf) = server_handle.await.unwrap();
        assert_eq!(code, PeerCode::UpdateSensorList);
        let received_info: PeerInfo = bincode::deserialize(&buf).unwrap();
        assert_eq!(received_info.graphql_port, Some(8080));
        assert_eq!(received_info.publish_port, Some(9090));
        assert!(received_info.ingest_sensors.contains("sensor1"));
    }

    #[tokio::test]
    async fn test_receive_peer_data_rejects_unknown_code() {
        init_crypto();

        let (server_endpoint, server_addr) = setup_server_endpoint();

        let server_handle = tokio::spawn(async move {
            let incoming = accept_incoming(&server_endpoint, "server accept timeout").await;
            let server_conn = incoming.await.unwrap();
            let (_server_send, mut server_recv) = server_conn.accept_bi().await.unwrap();
            receive_peer_data(&mut server_recv).await
        });

        let client_endpoint = init_client();
        let client_conn = with_timeout(
            "client connect timeout",
            client_endpoint
                .connect(server_addr, test_connect_name())
                .unwrap(),
        )
        .await
        .unwrap();
        let (mut send, _recv) = client_conn.open_bi().await.unwrap();

        let invalid_code: u32 = 0xFFFF_FFFE;
        send_bytes(&mut send, &invalid_code.to_le_bytes())
            .await
            .unwrap();
        send.finish().ok();

        let err = server_handle.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("unknown peer code"));
    }

    #[tokio::test]
    async fn test_handle_request_rejects_invalid_peer_list_payload() {
        init_crypto();

        let (server_endpoint, server_addr) = setup_server_endpoint();
        let ConnectedPeers {
            client_endpoint: _client_endpoint,
            server_conn,
            client_conn,
        } = connect_client_server(&server_endpoint, server_addr).await;

        let (mut client_send, _client_recv) = client_conn.open_bi().await.unwrap();
        send_peer_code_payload(&mut client_send, PeerCode::UpdatePeerList, &[0xFF, 0xFE]).await;
        let server_stream = server_conn.accept_bi().await.unwrap();

        let peer_list = Arc::new(RwLock::new(HashSet::new()));
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let (sender, _receiver) = tokio::sync::mpsc::channel(10);
        let doc = "peers = []".parse::<DocumentMut>().unwrap();
        let config = TempConfig::from_doc(&doc);
        let err = handle_request(
            server_stream,
            "127.0.0.1:9999".parse().unwrap(),
            "127.0.0.1".to_string(),
            peer_list,
            peers,
            sender,
            doc,
            config.path(),
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("Failed to deserialize peer list"));
    }

    #[tokio::test]
    async fn test_handle_request_rejects_invalid_sensor_list_payload() {
        init_crypto();

        let (server_endpoint, server_addr) = setup_server_endpoint();
        let ConnectedPeers {
            client_endpoint: _client_endpoint,
            server_conn,
            client_conn,
        } = connect_client_server(&server_endpoint, server_addr).await;

        let (mut client_send, _client_recv) = client_conn.open_bi().await.unwrap();
        send_peer_code_payload(&mut client_send, PeerCode::UpdateSensorList, &[0xAA, 0xBB]).await;
        let server_stream = server_conn.accept_bi().await.unwrap();

        let peer_list = Arc::new(RwLock::new(HashSet::new()));
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let doc = "peers = []".parse::<DocumentMut>().unwrap();
        let config = TempConfig::from_doc(&doc);
        let err = handle_request(
            server_stream,
            "127.0.0.1:9998".parse().unwrap(),
            "127.0.0.1".to_string(),
            peer_list,
            peers,
            sender,
            doc,
            config.path(),
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("Failed to deserialize sensor list")
        );
    }

    #[tokio::test]
    async fn test_request_init_info_rejects_invalid_response_payload() {
        init_crypto();

        let (server_endpoint, server_addr) = setup_server_endpoint();
        let (server_shutdown_tx, server_handle) = spawn_request_init_info_response_server(
            server_endpoint,
            PeerCode::UpdatePeerList,
            vec![0xFF, 0xFF, 0xFF],
        );

        let (_client_conn, mut send, mut recv) = connect_client_handshake(server_addr).await;

        let err = request_init_info::<PeerInfo>(
            &mut send,
            &mut recv,
            PeerCode::UpdatePeerList,
            PeerInfo::default(),
        )
        .await
        .unwrap_err();
        let has_bincode = err
            .chain()
            .any(|cause| cause.is::<bincode::Error>() || cause.is::<bincode::ErrorKind>());
        assert!(has_bincode, "unexpected error: {err:#}");

        let _ = server_shutdown_tx.send(());
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_request_init_info_returns_payload() {
        init_crypto();

        let (server_endpoint, server_addr) = setup_server_endpoint();
        let expected = peer_info(&["sensor-1"], Some(9191), Some(9292));
        let (server_shutdown_tx, server_handle) = spawn_request_init_info_response_server(
            server_endpoint,
            PeerCode::UpdatePeerList,
            bincode::serialize(&expected).unwrap(),
        );

        let (_client_conn, mut send, mut recv) = connect_client_handshake(server_addr).await;

        let recv_info = request_init_info::<PeerInfo>(
            &mut send,
            &mut recv,
            PeerCode::UpdatePeerList,
            PeerInfo::default(),
        )
        .await
        .unwrap();
        assert_peer_info_eq(&recv_info, &expected);

        let _ = server_shutdown_tx.send(());
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_request_init_info_rejects_mismatched_response_code() {
        init_crypto();

        let (server_endpoint, server_addr) = setup_server_endpoint();
        let payload_info = peer_info(&["mismatch-sensor"], Some(9191), Some(9292));
        let (server_shutdown_tx, server_handle) = spawn_request_init_info_response_server(
            server_endpoint,
            PeerCode::UpdateSensorList,
            bincode::serialize(&payload_info).unwrap(),
        );

        let (_client_conn, mut send, mut recv) = connect_client_handshake(server_addr).await;

        let err = request_init_info::<PeerInfo>(
            &mut send,
            &mut recv,
            PeerCode::UpdatePeerList,
            PeerInfo::default(),
        )
        .await
        .unwrap_err();
        assert_peer_code_mismatch(&err, PeerCode::UpdatePeerList, PeerCode::UpdateSensorList);

        let _ = server_shutdown_tx.send(());
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_response_init_info_rejects_invalid_request_payload() {
        init_crypto();

        let (server_endpoint, server_addr) = setup_server_endpoint();
        let server_handle = spawn_response_init_info_server(server_endpoint);

        let (_client_conn, mut send, _recv) = connect_client_handshake(server_addr).await;

        let request_code: u32 = PeerCode::UpdatePeerList.into();
        send_bytes(&mut send, &request_code.to_le_bytes())
            .await
            .unwrap();
        send_raw(&mut send, &[0xAA]).await.unwrap();
        send.finish().ok();

        let err = server_handle.await.unwrap().unwrap_err();
        let has_bincode = err
            .chain()
            .any(|cause| cause.is::<bincode::Error>() || cause.is::<bincode::ErrorKind>());
        assert!(has_bincode, "unexpected error: {err:#}");
    }

    #[tokio::test]
    async fn test_response_init_info_rejects_mismatched_request_code() {
        init_crypto();

        let (server_endpoint, server_addr) = setup_server_endpoint();
        let server_handle = spawn_response_init_info_server(server_endpoint);

        let (_client_conn, mut send, _recv) = connect_client_handshake(server_addr).await;
        let payload = peer_info(&["request-sensor"], Some(7001), Some(7002));
        send_peer_code_payload(
            &mut send,
            PeerCode::UpdateSensorList,
            &bincode::serialize(&payload).unwrap(),
        )
        .await;

        let err = server_handle.await.unwrap().unwrap_err();
        assert_peer_code_mismatch(&err, PeerCode::UpdatePeerList, PeerCode::UpdateSensorList);
    }

    #[tokio::test]
    async fn test_update_to_new_sensor_list() {
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let remote_addr = "127.0.0.1".to_string();
        let sensor_list = peer_info(&["s1"], None, None);

        update_to_new_sensor_list(sensor_list, remote_addr.clone(), peers.clone()).await;

        let read_peers = peers.read().await;
        assert!(read_peers.contains_key(&remote_addr));
        assert!(
            read_peers
                .get(&remote_addr)
                .unwrap()
                .ingest_sensors
                .contains("s1")
        );
    }

    #[tokio::test]
    async fn test_update_to_new_peer_list() {
        let peer_list = Arc::new(RwLock::new(HashSet::new()));
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let local_addr = "127.0.0.1:38383".parse().unwrap();
        let initial = "peers = []\n";
        let doc = initial.parse::<toml_edit::DocumentMut>().unwrap();
        let config = TempConfig::from_str(initial);

        let peer_ident = PeerIdentity {
            addr: "127.0.0.2:38383".parse().unwrap(),
            hostname: "peer2".to_string(),
        };
        let peer_ident2 = PeerIdentity {
            addr: "127.0.0.3:38383".parse().unwrap(),
            hostname: "peer3".to_string(),
        };
        let mut new_peers = HashSet::new();
        new_peers.insert(peer_ident.clone());
        new_peers.insert(peer_ident2.clone());

        let (recv_tx, recv_rx) = oneshot::channel();
        let recv_handle = tokio::spawn(async move {
            let recv = drain_peer_receiver(receiver, 2).await;
            let _ = recv_tx.send(recv);
        });

        update_to_new_peer_list(
            new_peers,
            local_addr,
            peer_list.clone(),
            sender,
            doc,
            config.path(),
        )
        .await
        .unwrap();

        assert!(peer_list.read().await.contains(&peer_ident));
        assert!(peer_list.read().await.contains(&peer_ident2));
        let recv = with_timeout("peer recv timeout", recv_rx)
            .await
            .expect("peer recv closed");
        let _ = recv_handle.await;
        assert!(recv.contains(&peer_ident));
        assert!(recv.contains(&peer_ident2));
    }

    #[tokio::test]
    async fn test_update_to_new_peer_list_ignores_local_and_existing() {
        let peer_list = Arc::new(RwLock::new(HashSet::new()));
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let _sender_keepalive = sender.clone();
        let local_addr: SocketAddr = "127.0.0.1:38383".parse().unwrap();
        let doc = toml_edit::DocumentMut::new();
        let config = TempConfig::from_str("peers = []");

        let existing_peer = peer_identity("127.0.0.2:38383".parse().unwrap(), "peer2");
        peer_list.write().await.insert(existing_peer.clone());

        let local_peer = peer_identity(local_addr, "local");
        let recv_peers: HashSet<PeerIdentity> = vec![local_peer, existing_peer.clone()]
            .into_iter()
            .collect();

        update_to_new_peer_list(
            recv_peers,
            local_addr,
            peer_list.clone(),
            sender,
            doc,
            config.path(),
        )
        .await
        .unwrap();

        assert_eq!(peer_list.read().await.len(), 1);
        assert!(peer_list.read().await.contains(&existing_peer));
        let recv = receiver.try_recv();
        assert!(
            matches!(recv, Err(TryRecvError::Empty)),
            "unexpected peer recv: {recv:?}"
        );
    }

    #[tokio::test]
    async fn test_update_to_new_peer_list_does_not_update_config_when_no_changes() {
        let peer_list = Arc::new(RwLock::new(HashSet::new()));
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let local_addr: SocketAddr = "127.0.0.1:38383".parse().unwrap();

        let initial = "peers = []\n";
        let doc = initial.parse::<toml_edit::DocumentMut>().unwrap();
        let config = TempConfig::from_str(initial);
        let before = std::fs::read_to_string(config.path()).unwrap();

        let local_peer = peer_identity(local_addr, "local");
        let recv_peers: HashSet<PeerIdentity> = vec![local_peer].into_iter().collect();

        update_to_new_peer_list(
            recv_peers,
            local_addr,
            peer_list,
            sender,
            doc,
            config.path(),
        )
        .await
        .unwrap();

        let after = std::fs::read_to_string(config.path()).unwrap();
        assert_eq!(before, after);
    }

    #[tokio::test]
    async fn test_update_to_new_peer_list_updates_config_when_changed() {
        let peer_list = Arc::new(RwLock::new(HashSet::new()));
        let (sender, receiver) = tokio::sync::mpsc::channel(10);
        let local_addr: SocketAddr = "127.0.0.1:38383".parse().unwrap();

        let initial = "peers = []\n";
        let doc = initial.parse::<toml_edit::DocumentMut>().unwrap();
        let config = TempConfig::from_str(initial);

        let peer_ident = peer_identity("127.0.0.2:38383".parse().unwrap(), "peer2");
        let peer_ident2 = peer_identity("127.0.0.3:38383".parse().unwrap(), "peer3");
        let recv_peers: HashSet<PeerIdentity> = vec![peer_ident.clone(), peer_ident2.clone()]
            .into_iter()
            .collect();

        let recv_handle = tokio::spawn(async move {
            let _ = drain_peer_receiver(receiver, 2).await;
        });

        update_to_new_peer_list(
            recv_peers,
            local_addr,
            peer_list,
            sender,
            doc,
            config.path(),
        )
        .await
        .unwrap();
        let _ = recv_handle.await;

        let after = std::fs::read_to_string(config.path()).unwrap();
        let parsed = after.parse::<toml_edit::DocumentMut>().unwrap();
        let peers = parsed["peers"].as_array().expect("peers array");
        assert_eq!(peers.len(), 2);
        let entries: HashSet<(String, String)> = peers
            .iter()
            .map(|item| {
                let table = item.as_inline_table().expect("inline table");
                let addr = table.get("addr").and_then(|value| value.as_str()).unwrap();
                let hostname = table
                    .get("hostname")
                    .and_then(|value| value.as_str())
                    .unwrap();
                (addr.to_string(), hostname.to_string())
            })
            .collect();
        assert!(entries.contains(&(peer_ident.addr.to_string(), peer_ident.hostname.clone())));
        assert!(entries.contains(&(peer_ident2.addr.to_string(), peer_ident2.hostname.clone())));
    }

    #[tokio::test]
    async fn test_update_to_new_peer_list_returns_error_on_channel_send_failure() {
        let peer_list = Arc::new(RwLock::new(HashSet::new()));
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        drop(receiver);
        let local_addr: SocketAddr = "127.0.0.1:38383".parse().unwrap();

        let doc = toml_edit::DocumentMut::new();
        let config = TempConfig::from_str("");

        let peer_ident = peer_identity("127.0.0.2:38383".parse().unwrap(), "peer2");
        let recv_peers: HashSet<PeerIdentity> = vec![peer_ident].into_iter().collect();

        let err = update_to_new_peer_list(
            recv_peers,
            local_addr,
            peer_list,
            sender,
            doc,
            config.path(),
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("channel closed"));
    }

    #[tokio::test]
    async fn test_update_to_new_peer_list_keeps_config_structure_when_peers_key_missing() {
        let peer_list = Arc::new(RwLock::new(HashSet::new()));
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let local_addr: SocketAddr = "127.0.0.1:38383".parse().unwrap();

        // Config is rewritten even if the peers key is missing; ensure structure stays the same.
        let initial = "title = \"ok\"\n";
        let doc = initial.parse::<toml_edit::DocumentMut>().unwrap();
        let config = TempConfig::from_str(initial);
        let before = std::fs::read_to_string(config.path()).unwrap();

        let peer_ident = peer_identity("127.0.0.2:38383".parse().unwrap(), "peer2");
        let recv_peers: HashSet<PeerIdentity> = vec![peer_ident.clone()].into_iter().collect();

        update_to_new_peer_list(
            recv_peers,
            local_addr,
            peer_list.clone(),
            sender,
            doc,
            config.path(),
        )
        .await
        .unwrap();

        assert!(peer_list.read().await.contains(&peer_ident));

        let after = std::fs::read_to_string(config.path()).unwrap();
        let before_toml: toml::Value = toml::from_str(&before).unwrap();
        let after_toml: toml::Value = toml::from_str(&after).unwrap();
        assert_eq!(before_toml, after_toml);
    }

    #[tokio::test]
    async fn check_for_duplicate_connections_allows_first_connection() {
        init_crypto();

        let (server_endpoint, server_addr) = setup_server_endpoint();
        let ConnectedPeers {
            client_endpoint: _client_endpoint,
            server_conn,
            client_conn: _client_conn,
        } = connect_client_server(&server_endpoint, server_addr).await;

        let peer_conn = Arc::new(RwLock::new(HashMap::new()));
        let (remote_addr, remote_host_identity) =
            check_for_duplicate_connections(&server_conn, peer_conn.clone())
                .await
                .unwrap();

        assert_eq!(remote_host_identity, test_subject_peer_dedup_key());
        assert_eq!(remote_addr, server_conn.remote_address().ip().to_string());
        assert!(peer_conn.read().await.is_empty());
    }

    #[tokio::test]
    async fn check_for_duplicate_connections_rejects_duplicates() {
        init_crypto();

        let peer_conn = Arc::new(RwLock::new(HashMap::new()));
        let (server_endpoint, server_addr) = setup_server_endpoint();

        let ConnectedPeers {
            client_endpoint: _client_endpoint1,
            server_conn: server_conn1,
            client_conn: _client_conn1,
        } = connect_client_server(&server_endpoint, server_addr).await;
        let (_, remote_host_identity) =
            check_for_duplicate_connections(&server_conn1, peer_conn.clone())
                .await
                .unwrap();
        peer_conn
            .write()
            .await
            .insert(remote_host_identity.clone(), server_conn1.clone());

        let ConnectedPeers {
            client_endpoint: _client_endpoint2,
            server_conn: server_conn2,
            client_conn: _client_conn2,
        } = connect_client_server(&server_endpoint, server_addr).await;

        let err = super::check_for_duplicate_connections(&server_conn2, peer_conn.clone())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Duplicated connection"));
        assert_eq!(peer_conn.read().await.len(), 1);
    }

    #[cfg(feature = "bootroot")]
    #[test]
    fn peer_dedup_key_distinguishes_instance_ids() {
        let node1_fixture = build_bootroot_chain_fixture_with_server_name(
            "001.giganto.node1.example.test",
            "001.giganto.node1.example.test",
            "001.giganto.node1.example.test",
        );
        let node2_fixture = build_bootroot_chain_fixture_with_server_name(
            "002.giganto.node1.example.test",
            "002.giganto.node1.example.test",
            "002.giganto.node1.example.test",
        );

        let node1_certs = load_certs(
            &node1_fixture.client_leaf_path,
            &node1_fixture.client_key_path,
            &node1_fixture.ca_bundle_intermediate_then_root_path,
        );
        let node2_certs = load_certs(
            &node2_fixture.client_leaf_path,
            &node2_fixture.client_key_path,
            &node2_fixture.ca_bundle_intermediate_then_root_path,
        );

        let node1_key = peer_dedup_key_from_cert(&node1_certs.certs).expect("node1 dedup key");
        let node2_key = peer_dedup_key_from_cert(&node2_certs.certs).expect("node2 dedup key");

        assert_eq!(node1_key, "001.giganto.node1.example.test");
        assert_eq!(node2_key, "002.giganto.node1.example.test");
        assert_ne!(node1_key, node2_key);
    }

    #[cfg(feature = "bootroot")]
    #[tokio::test]
    async fn check_for_duplicate_connections_allows_distinct_bootroot_instance_ids() {
        init_crypto();

        let fixture = build_bootroot_duplicate_peer_fixture(
            "001.giganto.node1.example.test",
            "001.giganto.node1.example.test",
            "002.giganto.node1.example.test",
        );

        let server_certs = fixture.server.load_certs();
        let first_client_certs = fixture.first_client.load_certs();
        let second_client_certs = fixture.second_client.load_certs();

        let (server_endpoint, server_addr) = setup_server_endpoint_with_certs(&server_certs);
        let peer_conn = Arc::new(RwLock::new(HashMap::new()));

        let mut first_client_endpoint =
            quinn::Endpoint::client("[::]:0".parse().expect("client addr")).expect("endpoint");
        first_client_endpoint
            .set_default_client_config(config_client_for_tests(&first_client_certs));
        let first_connect = first_client_endpoint
            .connect(server_addr, &fixture.server_name)
            .expect("first connect future");
        let first_incoming = accept_incoming(&server_endpoint, "first server accept timeout").await;
        let first_server_future = async { first_incoming.await };
        let (first_server_conn, first_client_conn) =
            tokio::join!(first_server_future, first_connect);
        let first_server_conn = first_server_conn.expect("first server connection");
        let first_client_conn = first_client_conn.expect("first client connection");

        let (_, first_key) = check_for_duplicate_connections(&first_server_conn, peer_conn.clone())
            .await
            .expect("first connection should be accepted");
        peer_conn
            .write()
            .await
            .insert(first_key.clone(), first_server_conn.clone());

        let mut second_client_endpoint =
            quinn::Endpoint::client("[::]:0".parse().expect("client addr")).expect("endpoint");
        second_client_endpoint
            .set_default_client_config(config_client_for_tests(&second_client_certs));
        let second_connect = second_client_endpoint
            .connect(server_addr, &fixture.server_name)
            .expect("second connect future");
        let second_incoming =
            accept_incoming(&server_endpoint, "second server accept timeout").await;
        let second_server_future = async { second_incoming.await };
        let (second_server_conn, second_client_conn) =
            tokio::join!(second_server_future, second_connect);
        let second_server_conn = second_server_conn.expect("second server connection");
        let second_client_conn = second_client_conn.expect("second client connection");

        let (_, second_key) =
            check_for_duplicate_connections(&second_server_conn, peer_conn.clone())
                .await
                .expect("second connection with different instance id should be accepted");
        peer_conn
            .write()
            .await
            .insert(second_key.clone(), second_server_conn.clone());

        assert_eq!(first_key, "001.giganto.node1.example.test");
        assert_eq!(second_key, "002.giganto.node1.example.test");
        assert_ne!(first_key, second_key);
        assert_eq!(peer_conn.read().await.len(), 2);

        first_client_conn.close(0_u32.into(), b"done");
        second_client_conn.close(0_u32.into(), b"done");
        first_server_conn.close(0_u32.into(), b"done");
        second_server_conn.close(0_u32.into(), b"done");
        first_client_endpoint.wait_idle().await;
        second_client_endpoint.wait_idle().await;
        server_endpoint.wait_idle().await;
    }

    #[test]
    fn test_peer_identity_toml_accessors() {
        let ident = PeerIdentity {
            addr: "127.0.0.1:1234".parse().unwrap(),
            hostname: "node-a".to_string(),
        };

        assert_eq!(TomlPeers::get_hostname(&ident), "node-a");
        assert_eq!(TomlPeers::get_addr(&ident), "127.0.0.1:1234");
    }

    #[test]
    fn test_get_port_from_config_ipv6() {
        let toml_str = r#"
            addr = "[::1]:8443"
        "#;
        let doc = toml_str.parse::<toml_edit::DocumentMut>().unwrap();

        assert_eq!(get_port_from_config("addr", &doc), Some(8443));
    }

    #[tokio::test]
    async fn test_run_errors_on_missing_config() {
        init_crypto();

        let certs = create_certs();
        let peer = Peer::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), &certs).unwrap();

        let ingest_sensors = Arc::new(RwLock::new(HashSet::new()));
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let peer_idents = Arc::new(RwLock::new(HashSet::new()));
        let notify_sensor = Arc::new(Notify::new());
        let notify_shutdown = Arc::new(Notify::new());
        let (_tls_tx, tls_watch) = test_tls_watch_from_certs(create_certs());

        let err = peer
            .run(
                ingest_sensors,
                peers,
                peer_idents,
                notify_sensor,
                notify_shutdown,
                "missing-config.toml".to_string(),
                tls_watch,
            )
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("Failed to open/read config's toml file")
        );
    }

    #[tokio::test]
    async fn test_connect_completes_handshake() {
        init_crypto();

        let (server_endpoint, server_addr) = setup_server_endpoint();

        let client_endpoint = init_client();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let incoming = accept_incoming(&server_endpoint, "server accept timeout").await;
            let connection = incoming.await.unwrap();
            server_handshake(&connection, PEER_VERSION_REQ)
                .await
                .unwrap();
            let _ = ready_rx.await;
        });

        let peer_info = PeerIdentity {
            addr: server_addr,
            hostname: test_connect_name().to_string(),
        };
        let shared_client_config = init_shared_client_config();
        let (connection, _send, _recv, _gen) =
            connect(&client_endpoint, &shared_client_config, &peer_info)
                .await
                .unwrap();
        let _ = ready_tx.send(());

        let remote = connection.remote_address();
        let remote_ip = remote.ip();
        let is_loopback = match remote_ip {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4().is_some_and(|v4| v4.is_loopback()),
        };
        assert_eq!(remote.port(), server_addr.port());
        assert!(is_loopback);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_request_response_init_info_roundtrip() {
        init_crypto();

        let (server_endpoint, server_addr) = setup_server_endpoint();
        let ConnectedPeers {
            client_endpoint: _client_endpoint,
            server_conn,
            client_conn,
        } = connect_client_server(&server_endpoint, server_addr).await;

        let (client_res, server_res) = tokio::join!(
            client_handshake(&client_conn, PROTOCOL_VERSION),
            server_handshake(&server_conn, PEER_VERSION_REQ),
        );
        let (mut client_send, mut client_recv) = client_res.unwrap();
        let (mut server_send, mut server_recv) = server_res.unwrap();

        let client_info = peer_info(&["client-sensor"], Some(9001), Some(9002));
        let expected_client_info = peer_info(&["client-sensor"], Some(9001), Some(9002));
        let server_info = peer_info(&["server-sensor"], Some(9011), Some(9012));
        let expected_server_info = peer_info(&["server-sensor"], Some(9011), Some(9012));

        let server_task = tokio::spawn(async move {
            response_init_info(
                &mut server_send,
                &mut server_recv,
                PeerCode::UpdateSensorList,
                server_info,
            )
            .await
            .unwrap()
        });
        let client_task = tokio::spawn(async move {
            request_init_info(
                &mut client_send,
                &mut client_recv,
                PeerCode::UpdateSensorList,
                client_info,
            )
            .await
            .unwrap()
        });

        let server_received = server_task.await.unwrap();
        let client_received = client_task.await.unwrap();

        assert_peer_info_eq(&server_received, &expected_client_info);
        assert_peer_info_eq(&client_received, &expected_server_info);
    }

    #[tokio::test]
    async fn test_handle_request_updates_peer_list() {
        init_crypto();

        let (server_endpoint, server_addr) = setup_server_endpoint();
        let ConnectedPeers {
            client_endpoint: _client_endpoint,
            server_conn,
            client_conn,
        } = connect_client_server(&server_endpoint, server_addr).await;

        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let peer_list = Arc::new(RwLock::new(HashSet::new()));
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let local_addr = "127.0.0.1:1111".parse().unwrap();
        let remote_addr = "127.0.0.1".to_string();
        let doc = "peers = []".parse::<toml_edit::DocumentMut>().unwrap();
        let config = TempConfig::from_doc(&doc);
        let config_path = config.path().to_string();

        let new_peer = PeerIdentity {
            addr: "127.0.0.1:2222".parse().unwrap(),
            hostname: "peer-two".to_string(),
        };
        let update_peer_list: HashSet<PeerIdentity> = vec![new_peer.clone()].into_iter().collect();

        let server_handle = tokio::spawn({
            let peer_list = peer_list.clone();
            let peers = peers.clone();
            let config_path = config_path.clone();
            async move {
                let stream = server_conn.accept_bi().await.unwrap();
                handle_request(
                    stream,
                    local_addr,
                    remote_addr,
                    peer_list,
                    peers,
                    sender,
                    doc,
                    &config_path,
                )
                .await
                .unwrap();
            }
        });

        let (mut client_send, _client_recv) = client_conn.open_bi().await.unwrap();
        send_peer_data(&mut client_send, PeerCode::UpdatePeerList, update_peer_list)
            .await
            .unwrap();
        client_send.finish().ok();

        server_handle.await.unwrap();

        assert!(peer_list.read().await.contains(&new_peer));
        assert_eq!(receiver.recv().await.unwrap(), new_peer);
    }

    #[tokio::test]
    async fn test_handle_request_updates_sensor_list() {
        init_crypto();

        let (server_endpoint, server_addr) = setup_server_endpoint();
        let ConnectedPeers {
            client_endpoint: _client_endpoint,
            server_conn,
            client_conn,
        } = connect_client_server(&server_endpoint, server_addr).await;

        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let peer_list = Arc::new(RwLock::new(HashSet::new()));
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let local_addr = "127.0.0.1:1111".parse().unwrap();
        let remote_addr = "127.0.0.1".to_string();
        let doc = toml_edit::DocumentMut::new();
        let config = TempConfig::from_str("");
        let config_path = config.path().to_string();

        let sensor_info = peer_info(&["sensor-a"], Some(9100), Some(9200));

        let remote_addr_for_task = remote_addr.clone();
        let server_handle = tokio::spawn({
            let peer_list = peer_list.clone();
            let peers = peers.clone();
            let config_path = config_path.clone();
            async move {
                let stream = server_conn.accept_bi().await.unwrap();
                handle_request(
                    stream,
                    local_addr,
                    remote_addr_for_task,
                    peer_list,
                    peers,
                    sender,
                    doc,
                    &config_path,
                )
                .await
                .unwrap();
            }
        });

        let (mut client_send, _client_recv) = client_conn.open_bi().await.unwrap();
        send_peer_data(&mut client_send, PeerCode::UpdateSensorList, sensor_info)
            .await
            .unwrap();
        client_send.finish().ok();

        server_handle.await.unwrap();

        let read_peers = peers.read().await;
        let stored_info = read_peers.get(&remote_addr).unwrap();
        assert!(stored_info.ingest_sensors.contains("sensor-a"));
        assert_eq!(stored_info.graphql_port, Some(9100));
        assert_eq!(stored_info.publish_port, Some(9200));
    }

    #[tokio::test]
    async fn test_update_peer_info_returns_error_on_closed_connection() {
        init_crypto();

        let (server_endpoint, server_addr) = setup_server_endpoint();
        let ConnectedPeers {
            client_endpoint: _client_endpoint,
            server_conn,
            client_conn,
        } = connect_client_server(&server_endpoint, server_addr).await;

        client_conn.close(0_u32.into(), b"test close");
        let _ = client_conn.closed().await;
        let err = update_peer_info(client_conn, PeerCode::UpdateSensorList, PeerInfo::default())
            .await
            .unwrap_err();

        assert!(err.to_string().contains("Failed to send peer data"));
        drop(server_conn);
    }

    #[test]
    fn leaf_cert_fingerprint_is_stable_and_distinct() {
        init_crypto();

        let certs_a = create_certs();
        let certs_b = create_node2_certs();

        let fp_a = leaf_cert_fingerprint(&certs_a.certs);
        let fp_a_again = leaf_cert_fingerprint(&certs_a.certs);
        let fp_b = leaf_cert_fingerprint(&certs_b.certs);

        assert_eq!(fp_a, fp_a_again, "fingerprint must be deterministic");
        assert_ne!(
            fp_a, fp_b,
            "distinct certs must produce distinct fingerprints"
        );
        assert_eq!(fp_a.len(), 64, "sha256 hex encoding should be 64 chars");
    }

    #[test]
    fn leaf_cert_fingerprint_handles_empty_chain() {
        assert_eq!(leaf_cert_fingerprint(&[]), "<none>");
    }

    #[tokio::test]
    async fn apply_peer_tls_reload_swaps_client_config_on_success() {
        init_crypto();

        let initial_certs = create_certs();
        let new_certs = create_node2_certs();

        let (server_endpoint, _server_addr) = setup_server_endpoint_with_certs(&initial_certs);
        let initial_client_config = config_client(&initial_certs).expect("initial client config");
        let shared: SharedClientConfig = super::new_shared_client_config(initial_client_config);

        // Snapshot the actual pre-reload slot value so the post-reload
        // comparison can detect a replacement rather than just a distinct
        // allocation that was never installed.
        let before_gen = shared.read().expect("lock").generation;
        let before = Arc::clone(&shared.read().expect("lock").config);

        apply_peer_tls_reload(&server_endpoint, &shared, &new_certs);

        let after_gen = shared.read().expect("lock").generation;
        let after = Arc::clone(&shared.read().expect("lock").config);
        assert!(
            !Arc::ptr_eq(&before, &after),
            "client config slot must be replaced with a new Arc after reload"
        );
        assert_eq!(
            after_gen,
            before_gen + 1,
            "successful reload must bump the client-config generation"
        );

        // Confirm the swapped client config can actually dial a server that
        // holds the new certificate material. This proves the slot was
        // installed with configuration derived from `new_certs`, not just
        // replaced with an arbitrary different Arc.
        let (probe_server_endpoint, probe_addr) = setup_server_endpoint_with_certs(&new_certs);
        let mut client_endpoint =
            quinn::Endpoint::client("[::]:0".parse().expect("client addr")).expect("endpoint");
        client_endpoint.set_default_client_config((*after).clone());
        let connect_fut = client_endpoint
            .connect(probe_addr, test_connect_name_node2())
            .expect("connect config");
        let accept_fut = async {
            let incoming = accept_incoming(&probe_server_endpoint, "probe accept timeout").await;
            incoming.await.expect("probe server accept")
        };
        let (server_conn, client_conn) = tokio::join!(accept_fut, connect_fut);
        let client_conn = client_conn.expect("new client config must dial new server");
        let presented = extract_cert_from_conn(&client_conn).expect("probe server certs");
        assert_eq!(
            leaf_cert_fingerprint(&presented),
            leaf_cert_fingerprint(&new_certs.certs),
            "swapped client config must observe the new server leaf fingerprint"
        );
        drop(server_conn);
    }

    #[tokio::test]
    async fn apply_peer_tls_reload_preserves_state_when_server_config_build_fails() {
        init_crypto();

        let initial_certs = create_certs();
        let (server_endpoint, _server_addr) = setup_server_endpoint_with_certs(&initial_certs);
        let initial_client_config = config_client(&initial_certs).expect("client config");
        let shared: SharedClientConfig = super::new_shared_client_config(initial_client_config);
        let before_gen = shared.read().expect("lock").generation;
        let before = Arc::clone(&shared.read().expect("lock").config);

        // Build a Certs where cert and key do not form a valid pair so
        // config_server fails at with_single_cert.
        let other = create_node2_certs();
        let mismatched = Certs {
            certs: initial_certs.certs.clone(),
            key: other.key.clone_key(),
            root: initial_certs.root.clone(),
        };

        apply_peer_tls_reload(&server_endpoint, &shared, &mismatched);

        let after_gen = shared.read().expect("lock").generation;
        let after = Arc::clone(&shared.read().expect("lock").config);
        assert!(
            Arc::ptr_eq(&before, &after),
            "client config slot must be preserved when reload preparation fails"
        );
        assert_eq!(
            after_gen, before_gen,
            "failed reload must not bump the client-config generation"
        );
    }

    #[tokio::test]
    async fn run_applies_new_server_cert_on_tls_watch_update() {
        init_crypto();

        // Use genuinely different certificate material for the reload so a
        // fingerprint comparison actually proves the server endpoint
        // transitioned, rather than trivially matching against the same
        // cached fixture on both sides of the reload.
        let initial_certs = create_certs();
        let new_certs = create_node2_certs();
        assert_ne!(
            leaf_cert_fingerprint(&initial_certs.certs),
            leaf_cert_fingerprint(&new_certs.certs),
            "test setup requires distinct cert material pre- and post-reload"
        );

        let peer = Peer::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &initial_certs,
        )
        .unwrap();

        let ingest_sensors = Arc::new(RwLock::new(HashSet::new()));
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let peer_idents = Arc::new(RwLock::new(HashSet::new()));
        let notify_sensor = Arc::new(Notify::new());
        let notify_shutdown = Arc::new(Notify::new());
        let notify_shutdown_handle = notify_shutdown.clone();
        let (tls_tx, tls_watch) = test_tls_watch_from_certs(initial_certs.clone());
        let config = TempConfig::from_str("peers = []");
        let config_path = config.path().to_string();

        let (ready_tx, ready_rx) = oneshot::channel();
        let ingest_sensors_for_run = ingest_sensors.clone();
        let peers_for_run = peers.clone();
        let peer_idents_for_run = peer_idents.clone();
        let peer_handle = tokio::spawn(async move {
            run_peer_with_ready_and_tls_watch(
                peer,
                ingest_sensors_for_run,
                peers_for_run,
                peer_idents_for_run,
                notify_sensor,
                notify_shutdown,
                config_path,
                tls_watch,
                ready_tx,
            )
            .await
        });

        let server_addr = with_timeout("peer server ready", ready_rx)
            .await
            .expect("peer ready");

        // Pre-reload: connect under the initial SNI and capture the server
        // leaf fingerprint.
        let pre = TestClient::new(server_addr).await;
        let pre_peer_certs = extract_cert_from_conn(&pre.conn).expect("peer certs pre-reload");
        assert_eq!(
            leaf_cert_fingerprint(&pre_peer_certs),
            leaf_cert_fingerprint(&initial_certs.certs),
        );
        drop(pre);

        // Push genuinely different TLS material through the watch channel.
        let new_material = Arc::new(crate::tls_reload::TlsMaterial {
            certs: Arc::new(new_certs.clone()),
            cert_pem: Vec::new(),
            key_pem: Vec::new(),
        });
        tls_tx
            .send(new_material)
            .expect("broadcast reload material");

        // Post-reload: the server now presents `new_certs`, whose SAN is
        // the node2 identity. Probe with the matching SNI until the
        // subsystem converges to the new leaf fingerprint.
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(25)).await;
            let client_endpoint = init_client();
            let Ok(connecting) = client_endpoint.connect(server_addr, test_connect_name_node2())
            else {
                continue;
            };
            let Ok(conn) = connecting.await else {
                continue;
            };
            let probe_certs = extract_cert_from_conn(&conn).expect("peer certs probe");
            if leaf_cert_fingerprint(&probe_certs) == leaf_cert_fingerprint(&new_certs.certs) {
                drop(conn);
                notify_shutdown_handle.notify_waiters();
                with_timeout("peer shutdown", peer_handle)
                    .await
                    .expect("peer task join")
                    .expect("peer task result");
                return;
            }
        }
        panic!("peer server did not converge to new leaf fingerprint within timeout");
    }

    /// Failed reloads must leave the live peer server endpoint serving the
    /// previously installed certificate, so that both new inbound
    /// handshakes and a subsequent outbound reconnect continue to observe
    /// the last-known-good TLS state.
    #[tokio::test]
    async fn run_preserves_previous_server_cert_on_failed_reload() {
        init_crypto();

        let initial_certs = create_certs();
        let peer = Peer::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &initial_certs,
        )
        .unwrap();

        let ingest_sensors = Arc::new(RwLock::new(HashSet::new()));
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let peer_idents = Arc::new(RwLock::new(HashSet::new()));
        let notify_sensor = Arc::new(Notify::new());
        let notify_shutdown = Arc::new(Notify::new());
        let notify_shutdown_handle = notify_shutdown.clone();
        let (tls_tx, tls_watch) = test_tls_watch_from_certs(initial_certs.clone());
        let config = TempConfig::from_str("peers = []");
        let config_path = config.path().to_string();

        let (ready_tx, ready_rx) = oneshot::channel();
        let peer_handle = tokio::spawn(run_peer_with_ready_and_tls_watch(
            peer,
            ingest_sensors,
            peers,
            peer_idents,
            notify_sensor,
            notify_shutdown,
            config_path,
            tls_watch,
            ready_tx,
        ));

        let server_addr = with_timeout("peer server ready", ready_rx)
            .await
            .expect("peer ready");

        // Baseline inbound handshake observes initial server leaf cert.
        let pre = TestClient::new(server_addr).await;
        let pre_fp = leaf_cert_fingerprint(
            &extract_cert_from_conn(&pre.conn).expect("peer certs pre-reload"),
        );
        assert_eq!(pre_fp, leaf_cert_fingerprint(&initial_certs.certs));
        drop(pre);

        // Push material whose cert/key pair is mismatched, forcing the
        // reload to fail during config build. The subsystem must keep
        // serving the previous certificate.
        let other_certs = create_node2_certs();
        let broken_certs = Arc::new(Certs {
            certs: initial_certs.certs.clone(),
            key: other_certs.key.clone_key(),
            root: initial_certs.root.clone(),
        });
        let broken_material = Arc::new(crate::tls_reload::TlsMaterial {
            certs: broken_certs,
            cert_pem: Vec::new(),
            key_pem: Vec::new(),
        });
        tls_tx
            .send(broken_material)
            .expect("broadcast broken material");

        // Give the subsystem time to observe the watch update and decide
        // the reload, then repeatedly verify that new inbound handshakes
        // still observe the original server leaf fingerprint.
        for _ in 0..8 {
            tokio::time::sleep(Duration::from_millis(25)).await;
            let probe = TestClient::new(server_addr).await;
            let fp = leaf_cert_fingerprint(
                &extract_cert_from_conn(&probe.conn).expect("probe peer certs"),
            );
            assert_eq!(
                fp,
                leaf_cert_fingerprint(&initial_certs.certs),
                "failed reload must preserve the previous server leaf cert"
            );
            drop(probe);
        }

        notify_shutdown_handle.notify_waiters();
        with_timeout("peer shutdown", peer_handle)
            .await
            .expect("peer task join")
            .expect("peer task result");
    }

    /// Drives the production `connect()` helper across a successful
    /// reload. Because `client_connection()`'s reconnect loop dials via
    /// exactly this helper, the refreshed client TLS state it picks up
    /// here is the same state a real outbound reconnect would observe
    /// on a remote peer's handshake.
    #[tokio::test]
    async fn connect_reads_latest_shared_client_config_across_reload() {
        init_crypto();

        let server_certs = create_certs();
        let initial_client_certs = create_certs();
        let new_client_certs = create_node2_certs();
        assert_ne!(
            leaf_cert_fingerprint(&initial_client_certs.certs),
            leaf_cert_fingerprint(&new_client_certs.certs),
            "test setup requires distinct client leaf material"
        );

        let (server_endpoint, server_addr) = setup_server_endpoint_with_certs(&server_certs);
        let shared: SharedClientConfig = super::new_shared_client_config(
            config_client(&initial_client_certs).expect("initial client config"),
        );

        let peer_info = PeerIdentity {
            addr: server_addr,
            hostname: test_connect_name().to_string(),
        };
        let client_endpoint =
            quinn::Endpoint::client("[::]:0".parse().expect("client addr")).expect("endpoint");

        // Cycle 1: dial with the initial client config and confirm the
        // remote peer observes the initial client leaf fingerprint.
        let accept_1 = async {
            let incoming = accept_incoming(&server_endpoint, "accept 1").await;
            let conn = incoming.await.expect("server accept 1");
            let fp = leaf_cert_fingerprint(&extract_cert_from_conn(&conn).expect("client certs 1"));
            let _ = server_handshake(&conn, PEER_VERSION_REQ)
                .await
                .expect("server handshake 1");
            (conn, fp)
        };
        let dial_1 = async {
            super::connect(&client_endpoint, &shared, &peer_info)
                .await
                .expect("dial 1")
        };
        let ((server_conn_1, observed_fp_1), (client_conn_1, _s1, _r1, gen_1)) =
            tokio::join!(accept_1, dial_1);
        assert_eq!(gen_1, 0);
        assert_eq!(
            observed_fp_1,
            leaf_cert_fingerprint(&initial_client_certs.certs),
            "remote peer must observe the initial client leaf before reload"
        );
        drop(client_conn_1);
        drop(server_conn_1);

        // Simulate a successful reload. We intentionally do not run
        // `apply_peer_tls_reload` against this server endpoint, because
        // that would also swap the server config and change the SNI
        // identity of the peer. The contract under test is the client
        // path: that `connect()` picks up whatever the current shared
        // slot holds.
        {
            let new_client_config = config_client(&new_client_certs).expect("new client config");
            let mut state = shared.write().expect("peer client config lock poisoned");
            state.generation = state.generation.saturating_add(1);
            state.config = Arc::new(new_client_config);
        }

        // Cycle 2: redial and confirm the remote peer observes the new
        // client leaf fingerprint. This is the outbound-reconnect
        // observation the review was asking for.
        let accept_2 = async {
            let incoming = accept_incoming(&server_endpoint, "accept 2").await;
            let conn = incoming.await.expect("server accept 2");
            let fp = leaf_cert_fingerprint(&extract_cert_from_conn(&conn).expect("client certs 2"));
            let _ = server_handshake(&conn, PEER_VERSION_REQ)
                .await
                .expect("server handshake 2");
            (conn, fp)
        };
        let dial_2 = async {
            super::connect(&client_endpoint, &shared, &peer_info)
                .await
                .expect("dial 2")
        };
        let ((server_conn_2, observed_fp_2), (client_conn_2, _s2, _r2, gen_2)) =
            tokio::join!(accept_2, dial_2);
        assert_eq!(gen_2, 1, "second dial must snapshot the bumped generation");
        assert_eq!(
            observed_fp_2,
            leaf_cert_fingerprint(&new_client_certs.certs),
            "remote peer must observe the refreshed client leaf after reload"
        );
        assert_eq!(current_client_generation(&shared), 1);
        drop(client_conn_2);
        drop(server_conn_2);
    }

    /// A failed reload must leave the shared client TLS state byte-for-byte
    /// intact, so that a subsequent outbound reconnect presents the
    /// previously installed client leaf on the wire.
    #[tokio::test]
    async fn connect_preserves_client_leaf_on_failed_reload() {
        init_crypto();

        let server_certs = create_certs();
        let initial_client_certs = create_certs();
        let (server_endpoint, server_addr) = setup_server_endpoint_with_certs(&server_certs);
        let shared: SharedClientConfig = super::new_shared_client_config(
            config_client(&initial_client_certs).expect("initial client config"),
        );

        // Trigger a reload that fails at config build time. Use a
        // throwaway server endpoint so the live peer-server endpoint
        // under `server_addr` is not affected.
        let (probe_server_endpoint, _probe_addr) = setup_server_endpoint_with_certs(&server_certs);
        let other = create_node2_certs();
        let mismatched = Certs {
            certs: initial_client_certs.certs.clone(),
            key: other.key.clone_key(),
            root: initial_client_certs.root.clone(),
        };
        apply_peer_tls_reload(&probe_server_endpoint, &shared, &mismatched);
        assert_eq!(
            current_client_generation(&shared),
            0,
            "failed reload must not bump the client-config generation"
        );

        // Dial after the failed reload and confirm the remote peer still
        // observes the preserved client leaf.
        let peer_info = PeerIdentity {
            addr: server_addr,
            hostname: test_connect_name().to_string(),
        };
        let client_endpoint =
            quinn::Endpoint::client("[::]:0".parse().expect("client addr")).expect("endpoint");
        let accept_fut = async {
            let incoming = accept_incoming(&server_endpoint, "accept after failed reload").await;
            let conn = incoming.await.expect("server accept");
            let fp = leaf_cert_fingerprint(&extract_cert_from_conn(&conn).expect("client certs"));
            let _ = server_handshake(&conn, PEER_VERSION_REQ)
                .await
                .expect("server handshake");
            (conn, fp)
        };
        let dial_fut = async {
            super::connect(&client_endpoint, &shared, &peer_info)
                .await
                .expect("dial after failed reload")
        };
        let ((server_conn, observed_fp), (client_conn, _s, _r, generation)) =
            tokio::join!(accept_fut, dial_fut);
        assert_eq!(generation, 0);
        assert_eq!(
            observed_fp,
            leaf_cert_fingerprint(&initial_client_certs.certs),
            "outbound reconnect must observe the preserved client leaf after a failed reload"
        );
        drop(client_conn);
        drop(server_conn);
    }
}

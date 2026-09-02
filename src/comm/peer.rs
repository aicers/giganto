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
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{
    select,
    sync::{
        Mutex, Notify, RwLock,
        mpsc::{Receiver, Sender, channel},
        oneshot,
    },
    time::sleep,
};
use tokio_util::sync::CancellationToken;
use toml_edit::DocumentMut;
use tracing::{error, info, warn};

use crate::{
    cancellation::{DRAIN_REPORT_INTERVAL, TaskTracker, drain_with_report},
    comm::IngestSensors,
    graphql::status::{
        CONFIG_GRAPHQL_SRV_ADDR, CONFIG_PUBLISH_SRV_ADDR, TomlPeers, insert_toml_peers,
        parse_toml_element_to_string, read_toml_file, write_toml_file,
    },
    server::{
        Certs, config_client, config_server, extract_cert_from_conn, peer_dedup_key_from_cert,
        peer_name_from_cert,
    },
    tls_reload::{TlsMaterial, TlsWatch},
};

/// Peer subsystem's currently active client TLS state.
/// `applied_generation` tracks the [`TlsMaterial`] generation that was
/// last successfully installed into the peer subsystem (initially the
/// generation `Peer` was constructed from). It is bumped only after a
/// reload's server- and client-config rebuilds both succeed, so that an
/// outbound reconnect that snapshotted its client config before a
/// reload can detect a stale snapshot after its dial completes.
pub(super) struct PeerClientConfigState {
    applied_generation: u64,
    config: Arc<ClientConfig>,
}

/// Shared slot holding the peer subsystem's currently active client TLS
/// state. Readers (`connect`) snapshot `(applied_generation, Arc<ClientConfig>)`
/// under a short-lived read lock; the reload handler updates both
/// `applied_generation` and the inner `Arc` under a write lock when a
/// new configuration is applied.
type SharedClientConfig = Arc<StdRwLock<PeerClientConfigState>>;

fn new_shared_client_config(config: ClientConfig, applied_generation: u64) -> SharedClientConfig {
    Arc::new(StdRwLock::new(PeerClientConfigState {
        applied_generation,
        config: Arc::new(config),
    }))
}

// Recover from poison rather than panic. The shared state is updated
// inside `apply_peer_tls_reload` as `(generation, Arc<ClientConfig>)`
// between non-fallible operations, so a poisoned lock either reflects
// the previous consistent state or the post-update consistent state —
// there is no torn intermediate state for callers to observe.
fn read_state(slot: &SharedClientConfig) -> std::sync::RwLockReadGuard<'_, PeerClientConfigState> {
    slot.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_state(
    slot: &SharedClientConfig,
) -> std::sync::RwLockWriteGuard<'_, PeerClientConfigState> {
    slot.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn snapshot_client_config(slot: &SharedClientConfig) -> (u64, ClientConfig) {
    let guard = read_state(slot);
    (guard.applied_generation, guard.config.as_ref().clone())
}

fn current_applied_generation(slot: &SharedClientConfig) -> u64 {
    read_state(slot).applied_generation
}

// The `PEER_VERSION_REQ` defines the compatibility range for Giganto instances in a cluster.
// Reasons for updating this version include, but not be limited to:
// - Updates of GraphQL API version: Since Giganto acts as both a client and server for other
//   Gigantos in the cluster, maintaining the same API version is necessary for the communication
//   within the cluster.
// - Updates of event protocol structures: Any changes to giganto-client's event protocols require
//   all Gigantos in the cluster to use the same protocol version for compatibility.
const PEER_VERSION_REQ: &str = ">=0.28.0,<0.29.0";
const PEER_RETRY_INTERVAL: u64 = 5;
/// Names the peer subsystem tracker in the drain progress log.
const PEER_DRAIN_LABEL: &str = "peer";

pub type Peers = Arc<RwLock<HashMap<String, PeerInfo>>>;
#[allow(clippy::module_name_repetitions)]
pub type PeerIdents = Arc<RwLock<HashSet<PeerIdentity>>>;
type SharedConfigDoc = Arc<Mutex<DocumentMut>>;

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
    config_doc: SharedConfigDoc,
    config_path: String,
}

pub struct Peer {
    client_config: ClientConfig,
    server_config: ServerConfig,
    local_address: SocketAddr,
    local_connect_name: String,
    /// Generation of the [`TlsMaterial`] this `Peer` was constructed
    /// from. `Peer::run` compares it to the current watched material's
    /// generation at startup to decide whether a reload landed between
    /// the daemon's snapshot and the first watch read, regardless of
    /// which TLS field changed (cert, key, or CA bundle).
    initial_generation: u64,
}

impl Peer {
    pub fn new(local_address: SocketAddr, certs: &Certs, initial_generation: u64) -> Result<Self> {
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
            initial_generation,
        })
    }

    /// Serves the peer subsystem until `token` is cancelled, then drains
    /// every task it admitted.
    ///
    /// # Errors
    ///
    /// Returns an error if either endpoint cannot be created, if the
    /// configuration file cannot be read, or if the peer task tracker's lock
    /// is poisoned while closing or draining it.
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        self,
        ingest_sensors: IngestSensors,
        peers: Peers,
        peer_idents: PeerIdents,
        notify_sensor: Arc<Notify>,
        config_path: String,
        tls_watch: TlsWatch,
        token: CancellationToken,
    ) -> Result<()> {
        self.run_with_ready(
            ingest_sensors,
            peers,
            peer_idents,
            notify_sensor,
            config_path,
            tls_watch,
            token,
            None,
        )
        .await
    }

    /// Internal entry point shared by [`Peer::run`] and tests. The optional
    /// `ready` channel lets tests observe the bound server address, the
    /// shared client TLS slot, and a sending half of the peer-identity
    /// channel this task owns, once all three exist — without forcing
    /// production callers to plumb a sender they do not need. Handing the
    /// peer-identity sender out is what lets a test offer an identity on the
    /// real channel and see the entry task's `receiver.close()` refuse it.
    ///
    /// What runs after the accept loop is [`shutdown_peer`], called
    /// unconditionally as the last statement here.
    ///
    /// # Errors
    ///
    /// Returns an error if either endpoint cannot be created, if the
    /// configuration file cannot be read, or if the peer task tracker's lock
    /// is poisoned while closing or draining it.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub(super) async fn run_with_ready(
        self,
        ingest_sensors: IngestSensors,
        peers: Peers,
        peer_idents: PeerIdents,
        notify_sensor: Arc<Notify>,
        config_path: String,
        mut tls_watch: TlsWatch,
        token: CancellationToken,
        ready: Option<oneshot::Sender<(SocketAddr, SharedClientConfig, Sender<PeerIdentity>)>>,
    ) -> Result<()> {
        let server_endpoint = Endpoint::server(self.server_config, self.local_address)
            .context("failed to create peer server endpoint")?;
        let local_addr = server_endpoint
            .local_addr()
            .context("failed to get peer server local address")?;
        info!("listening on {local_addr}");

        let client_socket = SocketAddr::new(self.local_address.ip(), 0);
        let client_endpoint =
            Endpoint::client(client_socket).context("failed to create peer client endpoint")?;
        let shared_client_config =
            new_shared_client_config(self.client_config, self.initial_generation);
        let (sender, mut receiver): (Sender<PeerIdentity>, Receiver<PeerIdentity>) = channel(100);
        if let Some(tx) = ready {
            let _ = tx.send((local_addr, shared_client_config.clone(), sender.clone()));
        }
        // Atomically read the most recent watched material AND mark it as
        // seen. If a reload landed between when the watch receiver was
        // cloned (in `main`) and now, that update would otherwise be
        // discarded and the peer subsystem would keep using the snapshot
        // captured at `Peer::new`. Comparing material generations covers
        // every TLS field a reload can change (cert, key, or CA), not
        // just the leaf certificate.
        {
            let material = tls_watch.borrow_and_update().clone();
            if material.generation != self.initial_generation {
                apply_peer_tls_reload(&server_endpoint, &shared_client_config, &material);
            }
        }

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
            config_doc: Arc::new(Mutex::new(config_doc)),
            config_path,
        };

        // Built from the token handed down by `main`, so the top-level
        // `cancel_children` reaches every peer task registered here and by the
        // connection handlers in turn. Building it with `TaskTracker::new()`
        // would start a fresh root and cut peer off from process shutdown
        // without the compiler noticing.
        let tracker = TaskTracker::with_token(token.clone());

        // The initial bootstrap the detached `client_run` task used to do,
        // inline in the entry task: dialing the configured peers is the entry
        // task's own startup work, and each dial is registered in the tracker
        // rather than being spawned behind a task nothing waits for.
        for peer in snapshot_peer_identities(&peer_conn_info.peer_identities).await {
            spawn_client_connection(
                &tracker,
                &client_endpoint,
                &shared_client_config,
                peer,
                &peer_conn_info,
                &self.local_connect_name,
            );
        }

        let mut tls_reload_closed = false;
        loop {
            select! {
                biased;

                // Cancellation branch. What is lost here is only work that has
                // not started: an inbound handshake quinn has not yet handed
                // over, a peer identity still queued in the channel, and a TLS
                // update that changes nothing for connections already up. The
                // entry task has no per-connection state of its own to clean
                // up, so its cleanup is the shutdown sequence below — close
                // admission, close the endpoints and connections, close the
                // peer-identity receive side — and it returns only once the
                // drain that follows is empty.
                () = token.cancelled() => {
                    info!("Shutting down peer");
                    break;
                }

                Some(conn) = server_endpoint.accept()  => {
                    let remote = conn.remote_address();
                    let spawned = tracker.spawn(format!("peer-server-conn-{remote}"), {
                        let peer_conn_info = peer_conn_info.clone();
                        let tracker = tracker.clone();
                        move |token| async move {
                            if let Err(e) = server_connection(
                                conn,
                                peer_conn_info,
                                tracker,
                                token,
                            )
                            .await
                            {
                                error!("Connection to {remote} failed: {e}");
                            }
                        }
                    });
                    // The handle is dropped: the handler logs its own domain
                    // errors and the tracker's registry guard names a task
                    // that vanishes without returning. Admission only closes
                    // after cancellation, so a rejection here means shutdown
                    // has begun and the remote will reconnect to the next
                    // generation.
                    if let Err(e) = spawned {
                        warn!("Rejected peer connection from {remote}: {e}");
                    }
                },
                Some(peer) = receiver.recv()  => {
                    spawn_client_connection(
                        &tracker,
                        &client_endpoint,
                        &shared_client_config,
                        peer,
                        &peer_conn_info,
                        &self.local_connect_name,
                    );
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
                        &material,
                    );
                },
            }
        }

        shutdown_peer(
            &tracker,
            &server_endpoint,
            &client_endpoint,
            peer_conn_info,
            &mut receiver,
        )
        .await
    }
}

/// Everything the peer entry task does after it has left its accept loop.
///
/// Extracted from [`Peer::run`] purely so a test can drive it over a tracker
/// of its own — a tracker built inside `run` is reachable from nowhere else,
/// and the recovery a poisoned drain performs is what these statements have to
/// survive. `run` calls it unconditionally as its last statement, so the two
/// are the same sequence.
///
/// Peer's teardown runs *before* its drain and has to stay there: the closes
/// below are what release the awaits no cancellation token reaches, so a drain
/// placed ahead of them would wait forever rather than fail. Nothing follows
/// the drain, which is why peer needs no capture-and-return of its error.
///
/// # Errors
///
/// Returns an error if the drain reported a poisoned tracker lock, which by
/// then means the peer tracker was observed empty.
async fn shutdown_peer(
    tracker: &TaskTracker,
    server_endpoint: &Endpoint,
    client_endpoint: &Endpoint,
    peer_conn_info: PeerConns,
    receiver: &mut Receiver<PeerIdentity>,
) -> Result<()> {
    // Admission rejection, the half leaving the accept loop cannot do on
    // its own: a closed tracker turns away every request handler and
    // sensor-update fan-out a still-running connection handler might try
    // to register. Closing does not cancel, so everything already tracked
    // keeps running until it observes cancellation for itself. Failing here
    // is no longer fatal: `drain_with_report` closes the tracker itself,
    // through a poisoned admission lock if it has to, so this close only
    // shuts admission a little earlier than the drain would — and returning
    // here would skip the endpoint teardown the drain below depends on.
    if let Err(e) = tracker.close() {
        error!("failed to close the peer task tracker: {e}");
    }

    // Closing the endpoints is what releases the awaits no token reaches:
    // the `giganto_client` handshakes, the init-info frame exchanges, a
    // `receive_peer_data` waiting on a frame that never arrives,
    // `accept_bi`, an outbound dial, and an `update_peer_info` stream
    // write the remote never reads. Closing an endpoint closes the
    // connections on it too; the explicit sweep below covers a connection
    // whose endpoint a test drives separately.
    server_endpoint.close(0_u32.into(), b"shutting down");
    client_endpoint.close(0_u32.into(), b"shutting down");
    for connection in snapshot_connections(&peer_conn_info.peer_conns).await {
        connection.close(0_u32.into(), b"shutting down");
    }

    // The peer-identity channel holds 100 entries and its receiver is a
    // local of this task, so a `handle_request` blocked sending into a
    // full channel nobody drains would hang the drain forever. Closing the
    // receive side makes that send fail at once through the existing
    // `Failed to enqueue peer connection attempt` path. Peers discovered
    // during shutdown are not dialed; that loss is accepted.
    receiver.close();

    // State cleanup. Every connection handler removes its own `peer_conns`
    // and `peers` entries before it returns, so what is left to the entry
    // task is its own hold on peer state: dropping its `PeerConns` clone
    // releases the last `peer_sender` outside the handlers, so the channel
    // is closed rather than merely drained once they have returned.
    drop(peer_conn_info);

    // Same policy as the top level: report every round and keep waiting.
    // `drain_with_report` closes and cancels again, both idempotent.
    drain_with_report(tracker, DRAIN_REPORT_INTERVAL, PEER_DRAIN_LABEL)
        .await
        .context("failed to drain the peer task tracker")?;

    Ok(())
}

/// Prepares fresh peer server/client TLS configurations from `material`
/// and, only if both build successfully, swaps them into the active peer
/// subsystem state under a single write lock and stores the published
/// generation as the new `applied_generation`. On any prepare failure
/// the previous active state is preserved, `applied_generation` is left
/// unchanged, and the failure is logged.
///
/// The write lock serializes with `connect()` readers so that a reader
/// which waits for this lock (or starts after it) sees post-reload server
/// and client state together. A reader that snapshotted the old client
/// config before this critical section may still be in the middle of a
/// dial when the swap lands; comparing the snapshot's generation to the
/// updated `applied_generation` lets the caller detect that case after
/// the dial completes and retry with the refreshed client config instead
/// of letting a stale outbound connection remain active while new
/// inbound handshakes already observe the new server leaf.
fn apply_peer_tls_reload(
    server_endpoint: &Endpoint,
    shared_client_config: &SharedClientConfig,
    material: &TlsMaterial,
) {
    let certs = material.certs.as_ref();
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

    {
        let mut state = write_state(shared_client_config);
        server_endpoint.set_server_config(Some(new_server));
        state.applied_generation = material.generation;
        state.config = Arc::new(new_client);
    }
    info!(
        "peer TLS state reloaded; generation {}",
        material.generation
    );
}

/// Registers one outbound peer connection in the peer-local tracker.
///
/// Used by the entry task for both the startup bootstrap and every peer
/// identity that later arrives on the peer-identity channel. The handle is
/// dropped: `client_connection` logs its own domain errors and the tracker's
/// registry guard names a task that ends without returning, so there is no
/// outcome left for the entry task to observe.
fn spawn_client_connection(
    tracker: &TaskTracker,
    client_endpoint: &Endpoint,
    shared_client_config: &SharedClientConfig,
    peer_info: PeerIdentity,
    peer_conn_info: &PeerConns,
    local_connect_name: &str,
) {
    let addr = peer_info.addr;
    let spawned = tracker.spawn(format!("peer-client-conn-{addr}"), {
        let client_endpoint = client_endpoint.clone();
        let shared_client_config = shared_client_config.clone();
        let peer_conn_info = peer_conn_info.clone();
        let local_connect_name = local_connect_name.to_string();
        let tracker = tracker.clone();
        move |token| async move {
            if let Err(e) = client_connection(
                client_endpoint,
                shared_client_config,
                peer_info,
                peer_conn_info,
                local_connect_name,
                tracker,
                token,
            )
            .await
            {
                error!("Peer connection to {addr} failed: {e}");
            }
        }
    });
    // Admission only closes after cancellation, so a rejection here means the
    // entry task has already begun shutting down and this peer will be dialed
    // by the next generation instead.
    if let Err(e) = spawned {
        warn!("Rejected peer connection to {addr}: {e}");
    }
}

/// Registers one `update_peer_info` fan-out in the peer-local tracker.
///
/// The fan-out is no longer fire-and-forget: a send that fails is logged with
/// the peer and the update kind, and a registration the closed tracker refuses
/// is logged and dropped rather than being spawned outside the tracker.
fn spawn_peer_info_update<T>(
    tracker: &TaskTracker,
    connection: Connection,
    msg_type: PeerCode,
    peer_data: T,
) where
    T: Serialize + DeserializeOwned + Send + 'static,
{
    let remote = connection.remote_address();
    let spawned = tracker.spawn(
        format!("peer-update-{msg_type:?}-{remote}"),
        move |_token| async move {
            if let Err(e) = update_peer_info::<T>(connection, msg_type, peer_data).await {
                warn!("Failed to send {msg_type:?} to peer {remote}: {e}");
            }
        },
    );
    if let Err(e) = spawned {
        warn!("Rejected {msg_type:?} to peer {remote}: {e}");
    }
}

/// Drops this connection's entries from the shared peer state.
///
/// Every path out of a connection handler runs this before returning — the
/// cancellation path as much as the connection-error path — because `Drop`
/// cannot `.await` and the entry task's drain ends the moment the handlers
/// return. Both removals are idempotent, so a handler that already cleaned up
/// on an earlier lap costs nothing here.
async fn remove_peer_state(
    peer_conn_info: &PeerConns,
    remote_peer_dedup_key: &str,
    remote_addr: &str,
) {
    peer_conn_info
        .peer_conns
        .write()
        .await
        .remove(remote_peer_dedup_key);
    peer_conn_info.peers.write().await.remove(remote_addr);
}

/// How a connection handler's serve loop ended.
enum ConnectionExit {
    /// The connection is gone but the peer is still worth dialing again.
    Retry,
    /// The handler is done with this peer.
    Done,
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

/// Registers one inbound peer request stream in the peer-local tracker.
///
/// Shared by both connection loops. A stream the closed tracker refuses is
/// logged with the peer it came from and dropped; the frame on it was never
/// fully received or validated, so nothing acknowledged is lost with it.
fn spawn_request_handler(
    tracker: &TaskTracker,
    stream: (SendStream, RecvStream),
    peer_conn_info: &PeerConns,
    remote_addr: &str,
) {
    let remote = remote_addr.to_string();
    let spawned = tracker.spawn(format!("peer-request-{remote_addr}"), {
        let peer_conn_info = peer_conn_info.clone();
        let remote = remote.clone();
        move |_token| async move {
            if let Err(e) = handle_request(
                stream,
                peer_conn_info.local_address,
                remote.clone(),
                peer_conn_info.peer_identities.clone(),
                peer_conn_info.peers.clone(),
                peer_conn_info.peer_sender.clone(),
                peer_conn_info.config_doc.clone(),
                &peer_conn_info.config_path,
            )
            .await
            {
                error!("Peer request from {remote} failed: {e}");
            }
        }
    });
    if let Err(e) = spawned {
        warn!("Rejected peer request from {remote}: {e}");
    }
}

/// Fans the current `ingest_sensors` snapshot out to every live peer
/// connection, one tracked task per connection.
///
/// A wake on `notify_sensor` sends the whole snapshot as it stands at that
/// moment rather than a per-change delta, so a notification that coalesced
/// with another or was dropped costs no sensor state.
async fn fan_out_sensor_list(
    tracker: &TaskTracker,
    peer_conn_info: &PeerConns,
    graphql_port: Option<u16>,
    publish_port: Option<u16>,
) {
    let sensor_list: HashSet<String> = peer_conn_info.ingest_sensors.read().await.to_owned();
    for conn in snapshot_connections(&peer_conn_info.peer_conns).await {
        spawn_peer_info_update::<PeerInfo>(
            tracker,
            conn,
            PeerCode::UpdateSensorList,
            PeerInfo {
                ingest_sensors: sensor_list.clone(),
                graphql_port,
                publish_port,
            },
        );
    }
}

#[allow(clippy::too_many_arguments)]
async fn client_connection(
    client_endpoint: Endpoint,
    shared_client_config: SharedClientConfig,
    peer_info: PeerIdentity,
    peer_conn_info: PeerConns,
    local_connect_name: String,
    tracker: TaskTracker,
    token: CancellationToken,
) -> Result<()> {
    let (graphql_port, publish_port) = {
        let config_doc = peer_conn_info.config_doc.lock().await;
        get_peer_ports(&config_doc)
    };
    'connection: loop {
        // The dial is one of the two awaits closure does not release: an
        // unreachable address keeps `connect_with` waiting out its handshake
        // timeout with no connection to close. What is lost when the token
        // fires here is one dial attempt; nothing has been inserted into
        // `peer_conns` or `peers` yet, so there is nothing to clean up.
        let Some(dialed) = token
            .run_until_cancelled(connect(&client_endpoint, &shared_client_config, &peer_info))
            .await
        else {
            return Ok(());
        };
        match dialed {
            Ok((connection, mut send, mut recv, snapshot_gen)) => {
                // If peer TLS state was reloaded while this reconnect was
                // in flight, the connection we just established was dialed
                // with stale client material. Close it and retry so the
                // reconnect is driven by the refreshed client config; this
                // prevents an outbound connection from remaining active on
                // the old client leaf after the server endpoint has
                // already switched to the new TLS state.
                if current_applied_generation(&shared_client_config) != snapshot_gen {
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

                // From here on this handler owns entries under
                // `remote_peer_dedup_key` and `remote_addr`, so every way out
                // of the serve call below — cancellation, connection error, or
                // a clean close — passes through the same removal before the
                // handler returns or dials again.
                let exit = serve_client_connection(
                    &connection,
                    &mut send,
                    &mut recv,
                    &peer_conn_info,
                    &local_connect_name,
                    &remote_addr,
                    &remote_peer_dedup_key,
                    (graphql_port, publish_port),
                    &tracker,
                    &token,
                )
                .await;
                remove_peer_state(&peer_conn_info, &remote_peer_dedup_key, &remote_addr).await;
                match exit {
                    Ok(ConnectionExit::Done) => return Ok(()),
                    Err(e) => return Err(e),
                    // The connection is gone but the peer is still worth
                    // another dial: fall through to the next lap of the
                    // reconnect loop, with this connection's shared state
                    // already removed above.
                    Ok(ConnectionExit::Retry) => {}
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
                            // The reconnect sleep is the other await no
                            // closure reaches. Cancellation drops the wait and
                            // gives up the reconnect; nothing is registered in
                            // the shared peer state at this point, so the
                            // handler can return as it is.
                            if token
                                .run_until_cancelled(sleep(Duration::from_secs(
                                    PEER_RETRY_INTERVAL,
                                )))
                                .await
                                .is_none()
                            {
                                return Ok(());
                            }
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

/// Serves one established outbound peer connection: the init exchange, the
/// peer-list fan-out it triggers, and then the request/sensor-update loop.
///
/// Split out of [`client_connection`] so that the caller has exactly one place
/// to remove this connection's `peer_conns` and `peers` entries, whichever way
/// the connection ends.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_client_connection(
    connection: &Connection,
    send: &mut SendStream,
    recv: &mut RecvStream,
    peer_conn_info: &PeerConns,
    local_connect_name: &str,
    remote_addr: &str,
    remote_peer_dedup_key: &str,
    (graphql_port, publish_port): (Option<u16>, Option<u16>),
    tracker: &TaskTracker,
    token: &CancellationToken,
) -> Result<ConnectionExit> {
    let send_sensor_list: HashSet<String> = peer_conn_info.ingest_sensors.read().await.to_owned();

    // Add my peer info to the peer list.
    let mut send_peer_list = snapshot_peer_identities(&peer_conn_info.peer_identities).await;
    send_peer_list.insert(PeerIdentity {
        addr: peer_conn_info.local_address,
        hostname: local_connect_name.to_string(),
    });

    // Exchange peer list/sensor list. No token is threaded through the frame
    // helpers: closing the connection or the client endpoint is what releases
    // them, and a half-received init frame is discarded with the connection.
    let (recv_peer_list, recv_sensor_list) =
        request_init_info::<(HashSet<PeerIdentity>, PeerInfo)>(
            send,
            recv,
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
        remote_addr.to_string(),
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
    let connections = snapshot_connections(&peer_conn_info.peer_conns).await;
    let peer_identities = snapshot_peer_identities(&peer_conn_info.peer_identities).await;
    for conn in connections {
        spawn_peer_info_update::<HashSet<PeerIdentity>>(
            tracker,
            conn,
            PeerCode::UpdatePeerList,
            peer_identities.clone(),
        );
    }

    // Update my peer list
    peer_conn_info
        .peer_conns
        .write()
        .await
        .insert(remote_peer_dedup_key.to_string(), connection.clone());

    loop {
        select! {
            biased;

            // Cancellation branch. What is lost here is an inbound stream the
            // remote had opened but this loop had not yet selected, and a
            // sensor-update round the wake below would have started. Both are
            // resent by the reconnect and the init handshake of the next
            // generation. The caller removes this connection's `peer_conns`
            // and `peers` entries as soon as this branch returns, before the
            // handler itself returns.
            () = token.cancelled() => {
                connection.close(0_u32.into(), b"shutting down");
                return Ok(ConnectionExit::Done);
            },

            stream = connection.accept_bi()  => {
                let stream = match stream {
                    Err(e) => {
                        if let quinn::ConnectionError::ApplicationClosed(_) = e {
                            info!("Data store peer({remote_peer_dedup_key}/{remote_addr}) closed");
                            return Ok(ConnectionExit::Done);
                        }
                        return Ok(ConnectionExit::Retry);
                    }
                    Ok(s) => s,
                };
                spawn_request_handler(tracker, stream, peer_conn_info, remote_addr);
            },
            () = peer_conn_info.notify_sensor.notified() => {
                fan_out_sensor_list(tracker, peer_conn_info, graphql_port, publish_port).await;
            },
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn server_connection(
    conn: quinn::Incoming,
    peer_conn_info: PeerConns,
    tracker: TaskTracker,
    token: CancellationToken,
) -> Result<()> {
    // No token is threaded through the inbound handshake: `Incoming`,
    // `server_handshake`, and the init exchange below all resolve when the
    // entry task closes the server endpoint, so a remote that connects and
    // then stalls cannot hold the drain.
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

    // From here on this handler owns entries under `remote_peer_dedup_key` and
    // `remote_addr`, so every way out of the serve call below passes through
    // the same removal before the handler returns.
    let outcome = serve_server_connection(
        &connection,
        &mut send,
        &mut recv,
        &peer_conn_info,
        &remote_addr,
        &remote_peer_dedup_key,
        &tracker,
        &token,
    )
    .await;
    remove_peer_state(&peer_conn_info, &remote_peer_dedup_key, &remote_addr).await;
    outcome
}

/// Serves one established inbound peer connection: the init exchange, the
/// peer-list fan-out it triggers, and then the request/sensor-update loop.
///
/// Split out of [`server_connection`] so that the caller has exactly one place
/// to remove this connection's `peer_conns` and `peers` entries, whichever way
/// the connection ends.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_server_connection(
    connection: &Connection,
    send: &mut SendStream,
    recv: &mut RecvStream,
    peer_conn_info: &PeerConns,
    remote_addr: &str,
    remote_peer_dedup_key: &str,
    tracker: &TaskTracker,
    token: &CancellationToken,
) -> Result<()> {
    let sensor_list: HashSet<String> = peer_conn_info.ingest_sensors.read().await.to_owned();
    let peer_identities = snapshot_peer_identities(&peer_conn_info.peer_identities).await;

    // Exchange peer list/sensor list.
    let (graphql_port, publish_port) = {
        let config_doc = peer_conn_info.config_doc.lock().await;
        get_peer_ports(&config_doc)
    };
    let (recv_peer_list, recv_sensor_list) =
        response_init_info::<(HashSet<PeerIdentity>, PeerInfo)>(
            send,
            recv,
            PeerCode::UpdatePeerList,
            (
                peer_identities,
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
        remote_addr.to_string(),
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
    let connections = snapshot_connections(&peer_conn_info.peer_conns).await;
    let peer_identities = snapshot_peer_identities(&peer_conn_info.peer_identities).await;
    for conn in connections {
        spawn_peer_info_update::<HashSet<PeerIdentity>>(
            tracker,
            conn,
            PeerCode::UpdatePeerList,
            peer_identities.clone(),
        );
    }

    // Update my peer list
    peer_conn_info
        .peer_conns
        .write()
        .await
        .insert(remote_peer_dedup_key.to_string(), connection.clone());

    loop {
        select! {
            biased;

            // Cancellation branch. What is lost here is an inbound stream the
            // remote had opened but this loop had not yet selected, and a
            // sensor-update round the wake below would have started. The peer
            // reconnects to the next generation and the init handshake
            // exchanges both lists again. The caller removes this connection's
            // `peer_conns` and `peers` entries as soon as this branch returns,
            // before the handler itself returns.
            () = token.cancelled() => {
                connection.close(0_u32.into(), b"shutting down");
                return Ok(());
            },

            stream = connection.accept_bi()  => {
                let stream = match stream {
                    Err(e) => {
                        if let quinn::ConnectionError::ApplicationClosed(_) = e {
                            info!("Data store peer({remote_peer_dedup_key}/{remote_addr}) closed");
                            return Ok(());
                        }
                        return Err(e.into());
                    }
                    Ok(s) => s,
                };
                spawn_request_handler(tracker, stream, peer_conn_info, remote_addr);
            },
            () = peer_conn_info.notify_sensor.notified() => {
                fan_out_sensor_list(tracker, peer_conn_info, graphql_port, publish_port).await;
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
    config_doc: SharedConfigDoc,
    path: &str,
) -> Result<()> {
    let (msg_type, msg_buf) = receive_peer_data(&mut recv).await?;
    match msg_type {
        PeerCode::UpdatePeerList => {
            let update_peer_list = bincode::deserialize::<HashSet<PeerIdentity>>(&msg_buf)
                .map_err(|e| anyhow!("Failed to deserialize peer list: {e}"))?;
            update_to_new_peer_list(
                update_peer_list,
                local_addr,
                peer_list,
                sender,
                config_doc,
                path,
            )
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

async fn snapshot_connections(peer_conns: &RwLock<HashMap<String, Connection>>) -> Vec<Connection> {
    let peer_conns = peer_conns.read().await;
    peer_conns.values().cloned().collect()
}

async fn snapshot_peer_identities(
    peer_identities: &RwLock<HashSet<PeerIdentity>>,
) -> HashSet<PeerIdentity> {
    let peer_identities = peer_identities.read().await;
    peer_identities.clone()
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
    config_doc: SharedConfigDoc,
    path: &str,
) -> Result<()> {
    update_to_new_peer_list_with_writer(
        recv_peer_list,
        local_address,
        peer_list,
        sender,
        config_doc,
        path,
        write_toml_file,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn update_to_new_peer_list_with_writer<F>(
    recv_peer_list: HashSet<PeerIdentity>,
    local_address: SocketAddr,
    peer_list: Arc<RwLock<HashSet<PeerIdentity>>>,
    sender: Sender<PeerIdentity>,
    config_doc: SharedConfigDoc,
    path: &str,
    write_config: F,
) -> Result<()>
where
    F: FnOnce(&DocumentMut, &str) -> anyhow::Result<()>,
{
    let new_peers = {
        let mut config_doc_guard = config_doc.lock().await;
        let mut peer_list_guard = peer_list.write().await;
        let new_peers: Vec<PeerIdentity> = recv_peer_list
            .into_iter()
            .filter(|peer| peer.addr != local_address && !peer_list_guard.contains(peer))
            .collect();

        if new_peers.is_empty() {
            return Ok(());
        }

        let mut updated_peer_list = peer_list_guard.clone();
        updated_peer_list.extend(new_peers.iter().cloned());

        // Refresh from disk while holding the write-serialization lock so edits are
        // never applied to the stale document loaded when the peer service started.
        let mut updated_doc = read_toml_file(path).context("failed to refresh config file")?;
        insert_toml_peers(
            &mut updated_doc,
            Some(updated_peer_list.iter().cloned().collect()),
        )
        .map_err(|error| anyhow!(error.message))
        .context("failed to update peers in config")?;
        write_config(&updated_doc, path).context("failed to persist peer list")?;

        *config_doc_guard = updated_doc;
        *peer_list_guard = updated_peer_list;
        new_peers
    };

    for peer in new_peers {
        if let Err(error) = sender.send(peer).await {
            let message = error.to_string();
            let peer = error.0;
            error!(?peer, %message, "Failed to enqueue peer connection attempt");
        }
    }
    info!("Peer list updated - {peer_list:?}");

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
    use rustls::pki_types::CertificateDer;
    use tokio::sync::mpsc::error::TryRecvError;
    use tokio::sync::{Notify, RwLock, oneshot};

    use super::*;

    /// Returns an owned copy of the leaf (first) certificate's DER bytes for
    /// direct equality comparison between certificate chains observed during
    /// a reload test. Returning owned bytes lets callers drop the source
    /// connection or temporary chain immediately after the comparison.
    fn leaf(certs: &[CertificateDer<'_>]) -> Option<Vec<u8>> {
        certs.first().map(|c| c.as_ref().to_vec())
    }
    use crate::graphql::status::{CONFIG_GRAPHQL_SRV_ADDR, CONFIG_PUBLISH_SRV_ADDR};
    #[cfg(feature = "bootroot")]
    use crate::server::peer_dedup_key_from_cert;
    #[cfg(feature = "bootroot")]
    use crate::test_bootroot::{
        build_bootroot_chain_fixture_with_server_name, build_bootroot_duplicate_peer_fixture,
        config_client_for_tests, load_certs,
    };

    pub(crate) mod fixtures {
        use std::{
            collections::{HashMap, HashSet},
            fs,
            future::Future,
            net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
            sync::{Arc, OnceLock},
            time::Duration,
        };

        use anyhow::Result;
        use giganto_client::connection::{client_handshake, server_handshake};
        use giganto_client::frame::{send_bytes, send_raw};
        use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream};
        use tempfile::TempDir;
        use tokio::sync::{Notify, RwLock, mpsc, oneshot};
        use tokio::time::sleep;
        use toml_edit::DocumentMut;

        #[cfg(feature = "bootroot")]
        use super::super::request_init_info;
        use super::super::{
            CancellationToken, IngestSensors, PEER_VERSION_REQ, Peer, PeerCode, PeerConns,
            PeerIdentity, PeerIdents, PeerInfo, Peers, SharedClientConfig, TaskTracker,
            server_connection,
        };
        use crate::comm::peer::{receive_peer_data, response_init_info};
        #[cfg(not(feature = "bootroot"))]
        use crate::comm::{to_cert_chain, to_private_key, to_root_cert};
        use crate::server::{Certs, config_client, config_server};
        #[cfg(feature = "bootroot")]
        use crate::test_bootroot::{
            TestNode, bootroot_cluster_certs, bootroot_cluster_server_name,
        };

        pub(super) const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");
        pub(super) const TEST_TIMEOUT: Duration = Duration::from_secs(10);
        /// Caps one dial attempt (QUIC connect + protocol handshake).
        /// Short enough that a genuine server hang fails fast across all
        /// attempts, yet far larger than a healthy localhost handshake.
        pub(super) const DIAL_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);
        /// Number of bounded dial attempts before a test dial gives up.
        pub(super) const DIAL_ATTEMPTS: usize = 5;
        /// Pause between dial attempts, giving a stalled runner room to
        /// recover before the next try.
        pub(super) const DIAL_RETRY_INTERVAL: Duration = Duration::from_millis(50);

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
                let (conn, send, recv) = connect_client_handshake(server_addr).await;
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
            super::new_shared_client_config(client_config(), 0)
        }

        /// A client endpoint that advertises a small receive window, so a peer
        /// writing more than that into a stream this side never reads parks on
        /// flow control instead of running to completion.
        pub(super) fn small_stream_window_client_endpoint() -> Endpoint {
            let mut transport = quinn::TransportConfig::default();
            transport.stream_receive_window(16_384_u32.into());
            transport.receive_window(65_536_u32.into());
            let mut config = client_config();
            config.transport_config(Arc::new(transport));
            let mut endpoint =
                quinn::Endpoint::client("[::]:0".parse().expect("Failed to parse Endpoint addr"))
                    .expect("Failed to create endpoint");
            endpoint.set_default_client_config(config);
            endpoint
        }

        /// Builds a paired `watch::Sender`/`TlsWatch` seeded with `certs`.
        /// Tests keep the sender alive to broadcast reload events on demand.
        pub(super) fn test_tls_watch_from_certs(
            certs: Certs,
        ) -> (
            tokio::sync::watch::Sender<Arc<crate::tls_reload::TlsMaterial>>,
            crate::tls_reload::TlsWatch,
        ) {
            test_tls_watch_from_certs_with_generation(certs, 0)
        }

        /// Variant of `test_tls_watch_from_certs` that lets a test seed
        /// the watch with a non-zero material generation, so it can drive
        /// the path that detects a TLS reload published before
        /// `Peer::run` first observes the watch channel.
        pub(super) fn test_tls_watch_from_certs_with_generation(
            certs: Certs,
            generation: u64,
        ) -> (
            tokio::sync::watch::Sender<Arc<crate::tls_reload::TlsMaterial>>,
            crate::tls_reload::TlsWatch,
        ) {
            let material = Arc::new(crate::tls_reload::TlsMaterial {
                certs: Arc::new(certs),
                cert_pem: Vec::new(),
                key_pem: Vec::new(),
                ca_pem: Vec::new(),
                generation,
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
                config_doc: Arc::new(tokio::sync::Mutex::new(doc)),
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

        /// Runs a bounded dial `attempt` until one succeeds, returning its
        /// value.
        ///
        /// QUIC liveness rides on wall-clock timers, so on an
        /// oversubscribed CI runner a scheduler stall can expire quinn's
        /// idle timeout mid-handshake even though both peers are healthy.
        /// A single long-timeout dial dies permanently in that case, while
        /// retrying lets the first clean scheduling window complete the
        /// dial. A genuine hang still fails fast because every attempt is
        /// capped at `DIAL_ATTEMPT_TIMEOUT`; the accumulated error is
        /// surfaced in the final panic.
        async fn retry_dial<T>(
            what: &str,
            server_addr: SocketAddr,
            mut attempt: impl AsyncFnMut() -> Result<T, String>,
        ) -> T {
            let mut last_error = String::new();
            for _ in 0..DIAL_ATTEMPTS {
                match tokio::time::timeout(DIAL_ATTEMPT_TIMEOUT, attempt()).await {
                    Ok(Ok(value)) => return value,
                    Ok(Err(e)) => last_error = e,
                    Err(_) => {
                        last_error = format!("attempt timed out after {DIAL_ATTEMPT_TIMEOUT:?}");
                    }
                }
                sleep(DIAL_RETRY_INTERVAL).await;
            }
            panic!(
                "{what} at {server_addr} failed after {DIAL_ATTEMPTS} attempts; last error: {last_error}"
            );
        }

        /// Accepts a raw QUIC connection with the same bounded attempt count
        /// and handshake budget used by the client-side peer fixtures.
        /// Dropping a timed-out handshake lets the production client observe
        /// the failed attempt and make a fresh connection attempt.
        pub(super) async fn accept_quic_with_retry(
            server_endpoint: Endpoint,
            what: &'static str,
        ) -> Connection {
            // This is the reconnect delay used by the production
            // `client_connection` error path. After the first failed QUIC
            // connection, later server attempts must allow for this delay
            // before granting the next handshake its full timeout budget.
            const PRODUCTION_CLIENT_RETRY_INTERVAL: Duration = Duration::from_secs(5);

            let server_addr = server_endpoint
                .local_addr()
                .expect("server endpoint address");
            let mut last_error = String::new();
            for attempt_index in 0..DIAL_ATTEMPTS {
                // The first dial is already in flight, so it only needs the
                // standard 3-second handshake budget. Later attempts may
                // begin while the production client is waiting 5 seconds to
                // reconnect, so they allow that delay plus a fresh 3-second
                // handshake budget.
                let attempt_timeout = if attempt_index == 0 {
                    DIAL_ATTEMPT_TIMEOUT
                } else {
                    PRODUCTION_CLIENT_RETRY_INTERVAL + DIAL_ATTEMPT_TIMEOUT
                };
                let attempt = async {
                    let incoming = server_endpoint
                        .accept()
                        .await
                        .ok_or_else(|| "server endpoint closed".to_string())?;
                    incoming
                        .await
                        .map_err(|e| format!("QUIC handshake failed: {e}"))
                };
                match tokio::time::timeout(attempt_timeout, attempt).await {
                    Ok(Ok(connection)) => return connection,
                    Ok(Err(e)) => last_error = e,
                    Err(_) => {
                        last_error = format!("attempt timed out after {attempt_timeout:?}");
                    }
                }
                sleep(DIAL_RETRY_INTERVAL).await;
            }
            panic!(
                "{what} at {server_addr} failed after {DIAL_ATTEMPTS} attempts; last error: {last_error}"
            );
        }

        /// Establishes a raw client/server QUIC connection pair, retrying
        /// the whole accept+connect pair per attempt so a scheduler stall
        /// on a loaded runner cannot expire quinn's idle timeout and
        /// permanently wedge the fixture.
        ///
        /// The server endpoint's accept queue is shared across attempts, so
        /// an aborted earlier attempt can leave a stale incoming ahead of
        /// this attempt's client. The accept side therefore matches each
        /// incoming to the current client endpoint by source port and
        /// ignores any other, guaranteeing the returned `server_conn` and
        /// `client_conn` belong to the same handshake rather than being
        /// cross-paired (which would later dead-lock `open_bi`/`accept_bi`).
        pub(super) async fn connect_client_server(
            server_endpoint: &Endpoint,
            server_addr: SocketAddr,
        ) -> ConnectedPeers {
            retry_dial("client/server pair", server_addr, async || {
                let client_endpoint = init_client();
                // Bound synchronously, so the source port that identifies
                // this attempt's client is known before the dial races.
                let client_port = client_endpoint
                    .local_addr()
                    .map_err(|e| format!("client local addr failed: {e}"))?
                    .port();
                let connect_fut = async {
                    client_endpoint
                        .connect(server_addr, test_connect_name())
                        .map_err(|e| format!("connect setup failed: {e}"))?
                        .await
                        .map_err(|e| format!("connect failed: {e}"))
                };
                let accept_fut = async {
                    loop {
                        let incoming = server_endpoint
                            .accept()
                            .await
                            .ok_or_else(|| "server endpoint closed".to_string())?;
                        // The client binds `[::]:0`, so only the port is
                        // stable between its `local_addr()` and the source
                        // address the server observes; the IP differs
                        // (unspecified vs loopback).
                        if incoming.remote_address().port() != client_port {
                            incoming.ignore();
                            continue;
                        }
                        return incoming
                            .await
                            .map_err(|e| format!("server accept failed: {e}"));
                    }
                };
                let (server_conn, client_conn) = tokio::try_join!(accept_fut, connect_fut)?;
                Ok(ConnectedPeers {
                    client_endpoint,
                    server_conn,
                    client_conn,
                })
            })
            .await
        }

        /// Dials the test peer server with a fresh client endpoint per
        /// attempt, completing both the QUIC connect and the protocol
        /// handshake within one bounded attempt. Wrapping the connect and
        /// handshake together matters: if only the connect were bounded,
        /// the immediately following handshake would die on the same
        /// stall.
        pub(super) async fn connect_client_handshake(
            server_addr: SocketAddr,
        ) -> (Connection, SendStream, RecvStream) {
            retry_dial("client dial to peer server", server_addr, async || {
                let client_endpoint = init_client();
                let conn = client_endpoint
                    .connect(server_addr, test_connect_name())
                    .map_err(|e| format!("connect setup failed: {e}"))?
                    .await
                    .map_err(|e| format!("connect failed: {e}"))?;
                let (send, recv) = client_handshake(&conn, PROTOCOL_VERSION)
                    .await
                    .map_err(|e| format!("client handshake failed: {e}"))?;
                Ok((conn, send, recv))
            })
            .await
        }

        /// Accepts connections until one completes the server handshake.
        /// A retrying dialer (`connect_client_handshake`) may abandon
        /// earlier attempts, so failed or dead incoming connections are
        /// skipped instead of unwrapping the first one.
        pub(super) async fn accept_server_handshake(
            server_endpoint: Endpoint,
        ) -> (SendStream, RecvStream) {
            let mut last_error = String::new();
            for _ in 0..DIAL_ATTEMPTS {
                let incoming = accept_incoming(&server_endpoint, "server accept timeout").await;
                let server_conn = match incoming.await {
                    Ok(conn) => conn,
                    Err(e) => {
                        last_error = format!("incoming connection failed: {e}");
                        continue;
                    }
                };
                match server_handshake(&server_conn, PEER_VERSION_REQ).await {
                    Ok(streams) => return streams,
                    Err(e) => last_error = format!("server handshake failed: {e}"),
                }
            }
            panic!(
                "no client dial completed the server handshake after {DIAL_ATTEMPTS} accepts; last error: {last_error}"
            );
        }

        pub(super) fn assert_peer_info_eq(actual: &PeerInfo, expected: &PeerInfo) {
            assert_eq!(actual.graphql_port, expected.graphql_port);
            assert_eq!(actual.publish_port, expected.publish_port);
            assert_eq!(actual.ingest_sensors, expected.ingest_sensors);
        }

        pub(super) fn peer_init() -> Peer {
            let certs = Arc::new(create_certs());

            Peer::new(
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
                &certs,
                0,
            )
            .unwrap()
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
            tracker: TaskTracker,
            token: CancellationToken,
        ) -> tokio::task::JoinHandle<Result<()>> {
            tokio::spawn(async move {
                let incoming = accept_incoming(&server_endpoint, "server accept timeout").await;
                server_connection(incoming, peer_conn_info, tracker, token).await
            })
        }

        /// Runs the production peer entry task over a TLS watch the test does
        /// not care about, reporting the bound server address once the entry
        /// task has published it.
        ///
        /// The watch is seeded with the same material `peer_init` built the
        /// `Peer` from and at the same generation, so the startup reload check
        /// finds nothing to apply. Its sender is held for the lifetime of the
        /// call so the reload branch is not disabled by a closed channel.
        #[allow(clippy::too_many_arguments)]
        pub(super) async fn run_peer_with_ready(
            peer: Peer,
            ingest_sensors: IngestSensors,
            peers: Peers,
            peer_idents: PeerIdents,
            notify_sensor: Arc<Notify>,
            config_path: String,
            token: CancellationToken,
            ready: oneshot::Sender<(SocketAddr, SharedClientConfig, mpsc::Sender<PeerIdentity>)>,
        ) -> Result<()> {
            let (_tls_tx, tls_watch) = test_tls_watch_from_certs(create_certs());
            peer.run_with_ready(
                ingest_sensors,
                peers,
                peer_idents,
                notify_sensor,
                config_path,
                tls_watch,
                token,
                Some(ready),
            )
            .await
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

        /// Runs the real peer server and exposes the sensor-list exchange used
        /// by tests outside this module.
        #[cfg(feature = "bootroot")]
        pub(crate) struct SensorListPeerHarness {
            client: TestClient,
            token: CancellationToken,
            peer_handle: tokio::task::JoinHandle<Result<()>>,
            _config: TempConfig,
        }

        #[cfg(feature = "bootroot")]
        impl SensorListPeerHarness {
            pub(crate) async fn start(
                ingest_sensors: IngestSensors,
                notify_sensor: Arc<Notify>,
            ) -> (Self, HashSet<String>) {
                init_crypto();
                let peers = Arc::new(RwLock::new(HashMap::new()));
                let peer_idents = Arc::new(RwLock::new(HashSet::new()));
                let config = TempConfig::from_str("peers = []");
                let token = CancellationToken::new();
                let (ready_tx, ready_rx) = oneshot::channel();
                let peer_handle = tokio::spawn(run_peer_with_ready(
                    peer_init(),
                    ingest_sensors,
                    peers,
                    peer_idents,
                    notify_sensor,
                    config.path().to_string(),
                    token.clone(),
                    ready_tx,
                ));

                let (server_addr, _, _) = with_timeout("peer server ready timeout", ready_rx)
                    .await
                    .expect("peer server did not report its address");
                let mut client = TestClient::new(server_addr).await;
                let (_, initial_sensor_list) =
                    request_init_info::<(HashSet<PeerIdentity>, PeerInfo)>(
                        &mut client.send,
                        &mut client.recv,
                        PeerCode::UpdatePeerList,
                        (HashSet::new(), PeerInfo::default()),
                    )
                    .await
                    .expect("initial peer information exchange failed");

                (
                    Self {
                        client,
                        token,
                        peer_handle,
                        _config: config,
                    },
                    initial_sensor_list.ingest_sensors,
                )
            }

            pub(crate) async fn receive_sensor_list(&self) -> HashSet<String> {
                let (_, mut recv) = with_timeout(
                    "peer sensor-list update stream timeout",
                    self.client.conn.accept_bi(),
                )
                .await
                .expect("peer did not open a sensor-list update stream");
                let (message_type, payload) = receive_peer_data(&mut recv)
                    .await
                    .expect("failed to receive peer sensor-list update");
                assert_eq!(message_type, PeerCode::UpdateSensorList);
                bincode::deserialize::<PeerInfo>(&payload)
                    .expect("invalid peer sensor-list update")
                    .ingest_sensors
            }

            pub(crate) async fn shutdown(self) {
                self.token.cancel();
                with_timeout("peer shutdown timeout", self.peer_handle)
                    .await
                    .expect("peer task join failed")
                    .expect("peer task returned an error");
            }
        }
    }

    /// A scheduler stall can leave a stale incoming in the shared server
    /// accept queue ahead of a retry's own dial. `connect_client_server`
    /// must skip it and pair the server side with its own client, or the
    /// returned pair would be cross-wired and dead-lock later stream I/O.
    #[tokio::test]
    async fn connect_client_server_pairs_live_dial_over_stale_incoming() {
        init_crypto();
        let (server_endpoint, server_addr) = setup_server_endpoint();

        // Queue a stale incoming ahead of the helper's own dial: a client
        // sends its Initial but is never accepted, mimicking a connection
        // left behind by an attempt that a scheduler stall aborted.
        let stale_client = init_client();
        let stale_connecting = stale_client
            .connect(server_addr, test_connect_name())
            .expect("stale client dial setup");
        // Let the server receive the Initial and queue the incoming first.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let peers = connect_client_server(&server_endpoint, server_addr).await;

        // The returned server side must belong to the helper's own client,
        // not the stale one queued ahead of it.
        assert_eq!(
            peers.server_conn.remote_address().port(),
            peers
                .client_endpoint
                .local_addr()
                .expect("client local addr")
                .port(),
            "server_conn must pair with the helper's own client_conn"
        );

        // And the pair must truly be one connection: a bidirectional
        // stream opened on the client is observed on the server.
        let (mut send, _recv) = peers.client_conn.open_bi().await.expect("open_bi");
        send.write_all(b"ping").await.expect("write");
        send.finish().expect("finish");
        let (_srv_send, mut srv_recv) = peers.server_conn.accept_bi().await.expect("accept_bi");
        assert_eq!(
            srv_recv.read_to_end(16).await.expect("read"),
            b"ping".to_vec(),
            "round-trip must flow over the paired connection"
        );

        // Keep the stale connection alive until here so the helper had to
        // actively skip it rather than win by the peer disappearing.
        drop(stale_connecting);
        drop(stale_client);
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
        let token = CancellationToken::new();
        let (ready_tx, ready_rx) = oneshot::channel();
        let peer_handle = tokio::spawn(run_peer_with_ready(
            peer_init(),
            ingest_sensors.clone(),
            peers,
            peer_idents,
            notify_sensor.clone(),
            config.path().to_string(),
            token.clone(),
            ready_tx,
        ));

        // run peer client
        let (server_addr, _, _) = with_timeout("peer server ready timeout", ready_rx)
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

        token.cancel();
        with_timeout("peer shutdown timeout", peer_handle)
            .await
            .expect("peer task failed")
            .expect("peer task join error");
    }

    #[tokio::test]
    async fn test_run_accepts_connection_and_updates_peer_info() {
        init_crypto();

        let certs = Arc::new(create_certs());
        let peer = Peer::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &certs,
            0,
        )
        .unwrap();

        let ingest_sensors = Arc::new(RwLock::new(HashSet::from(["run-sensor".to_string()])));
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let peers_for_assert = peers.clone();
        let peer_idents = Arc::new(RwLock::new(HashSet::new()));
        let notify_sensor = Arc::new(Notify::new());
        let token = CancellationToken::new();

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
            config.path().to_string(),
            token.clone(),
            ready_tx,
        ));

        let (run_addr, _, _) = with_timeout("peer server ready timeout", ready_rx)
            .await
            .expect("peer server did not report addr");
        let mut client = TestClient::new(run_addr).await;
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

        token.cancel();
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
            config_doc: Arc::new(Mutex::new(doc)),
            config_path: config.path().to_string(),
        };

        let client_endpoint = init_client();
        let token = CancellationToken::new();
        let tracker = TaskTracker::with_token(token.clone());
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
            tracker,
            token.clone(),
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
        token.cancel();
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

        let token = CancellationToken::new();
        let tracker = TaskTracker::with_token(token.clone());
        let server_token = token.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = accept_incoming(&server_endpoint, "server accept timeout").await;
            server_connection(incoming, peer_conn_info, tracker, server_token)
                .await
                .unwrap();
        });

        let mut client = TestClient::new(server_addr).await;
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

        token.cancel();
        drop(client.conn);
        let server_result = with_timeout("server shutdown timeout", server_handle).await;
        server_result.expect("server task panicked");
    }

    #[tokio::test]
    async fn test_server_connection_returns_error_on_handshake_failure() {
        init_crypto();

        let (server_endpoint, server_addr) = setup_server_endpoint();

        let (peer_conn_info, _config) = build_peer_conn_info("127.0.0.1:3333".parse().unwrap());
        let token = CancellationToken::new();
        let tracker = TaskTracker::with_token(token.clone());
        let server_handle =
            spawn_server_connection(server_endpoint, peer_conn_info, tracker, token);

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
        let token = CancellationToken::new();
        let tracker = TaskTracker::with_token(token.clone());
        let server_handle =
            spawn_server_connection(server_endpoint, peer_conn_info, tracker, token);

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
            Arc::new(Mutex::new(doc)),
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
            Arc::new(Mutex::new(doc)),
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
            Arc::new(Mutex::new(doc)),
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
            Arc::new(Mutex::new(doc)),
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
    async fn test_update_to_new_peer_list_same_ip_different_port_is_distinct() {
        let peer_list = Arc::new(RwLock::new(HashSet::new()));
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let local_addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();
        let doc = toml_edit::DocumentMut::new();
        let config = TempConfig::from_str("peers = []");

        let peer_on_same_ip = peer_identity("127.0.0.1:8001".parse().unwrap(), "peer-b");
        let recv_peers: HashSet<PeerIdentity> = vec![peer_on_same_ip.clone()].into_iter().collect();

        let (recv_tx, recv_rx) = oneshot::channel();
        let recv_handle = tokio::spawn(async move {
            let recv = drain_peer_receiver(receiver, 1).await;
            let _ = recv_tx.send(recv);
        });

        update_to_new_peer_list(
            recv_peers,
            local_addr,
            peer_list.clone(),
            sender,
            Arc::new(Mutex::new(doc)),
            config.path(),
        )
        .await
        .unwrap();

        assert!(peer_list.read().await.contains(&peer_on_same_ip));
        let recv = with_timeout("peer recv timeout", recv_rx)
            .await
            .expect("peer recv closed");
        let _ = recv_handle.await;
        assert!(recv.contains(&peer_on_same_ip));
    }

    #[tokio::test]
    async fn test_update_to_new_peer_list_skips_exact_local_address() {
        let peer_list = Arc::new(RwLock::new(HashSet::new()));
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let _sender_keepalive = sender.clone();
        let local_addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();
        let doc = toml_edit::DocumentMut::new();
        let config = TempConfig::from_str("peers = []");

        let self_peer = peer_identity(local_addr, "self");
        let recv_peers: HashSet<PeerIdentity> = vec![self_peer].into_iter().collect();

        update_to_new_peer_list(
            recv_peers,
            local_addr,
            peer_list.clone(),
            sender,
            Arc::new(Mutex::new(doc)),
            config.path(),
        )
        .await
        .unwrap();

        assert!(peer_list.read().await.is_empty());
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
            Arc::new(Mutex::new(doc)),
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
            Arc::new(Mutex::new(doc)),
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
    async fn test_update_to_new_peer_list_commits_state_on_channel_send_failure() {
        let peer_list = Arc::new(RwLock::new(HashSet::new()));
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        drop(receiver);
        let local_addr: SocketAddr = "127.0.0.1:38383".parse().unwrap();

        let doc = "peers = []".parse::<toml_edit::DocumentMut>().unwrap();
        let config_doc = Arc::new(Mutex::new(doc));
        let config = TempConfig::from_str("peers = []");

        let peer_ident = peer_identity("127.0.0.2:38383".parse().unwrap(), "peer2");
        let recv_peers: HashSet<PeerIdentity> = vec![peer_ident.clone()].into_iter().collect();

        update_to_new_peer_list(
            recv_peers,
            local_addr,
            peer_list.clone(),
            sender,
            config_doc.clone(),
            config.path(),
        )
        .await
        .unwrap();

        assert!(peer_list.read().await.contains(&peer_ident));
        let persisted = read_toml_file(config.path()).unwrap();
        assert_eq!(config_doc.lock().await.to_string(), persisted.to_string());
        assert_eq!(persisted["peers"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_update_to_new_peer_list_returns_insert_error_without_changing_state() {
        let peer_list = Arc::new(RwLock::new(HashSet::new()));
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let local_addr: SocketAddr = "127.0.0.1:38383".parse().unwrap();

        let initial = "title = \"ok\"\n";
        let doc = initial.parse::<toml_edit::DocumentMut>().unwrap();
        let config_doc = Arc::new(Mutex::new(doc));
        let config = TempConfig::from_str(initial);
        let before = std::fs::read_to_string(config.path()).unwrap();

        let peer_ident = peer_identity("127.0.0.2:38383".parse().unwrap(), "peer2");
        let recv_peers: HashSet<PeerIdentity> = vec![peer_ident.clone()].into_iter().collect();

        let err = update_to_new_peer_list(
            recv_peers,
            local_addr,
            peer_list.clone(),
            sender,
            config_doc.clone(),
            config.path(),
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("failed to update peers in config"));
        assert!(!peer_list.read().await.contains(&peer_ident));
        assert_eq!(config_doc.lock().await.to_string(), initial);

        let after = std::fs::read_to_string(config.path()).unwrap();
        assert_eq!(before, after);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_peer_list_updates_preserve_union() {
        let peer_list = Arc::new(RwLock::new(HashSet::new()));
        let (sender, _receiver) = tokio::sync::mpsc::channel(2);
        let local_addr: SocketAddr = "127.0.0.1:38383".parse().unwrap();
        let initial = "peers = []\n";
        let config_doc = Arc::new(Mutex::new(initial.parse::<DocumentMut>().unwrap()));
        let config = TempConfig::from_str(initial);

        let peer_a = peer_identity("127.0.0.2:38383".parse().unwrap(), "peer-a");
        let peer_b = peer_identity("127.0.0.3:38383".parse().unwrap(), "peer-b");
        let path = config.path().to_string();
        let (first_writer_entered_tx, first_writer_entered_rx) = oneshot::channel();
        let (release_first_writer_tx, release_first_writer_rx) = std::sync::mpsc::channel();

        let update_a = tokio::spawn({
            let peer_list = peer_list.clone();
            let config_doc = config_doc.clone();
            let path = path.clone();
            let peer_a = peer_a.clone();
            let sender = sender.clone();
            async move {
                update_to_new_peer_list_with_writer(
                    HashSet::from([peer_a]),
                    local_addr,
                    peer_list,
                    sender,
                    config_doc,
                    &path,
                    move |doc, path| {
                        first_writer_entered_tx.send(()).unwrap();
                        release_first_writer_rx.recv().unwrap();
                        write_toml_file(doc, path)
                    },
                )
                .await
            }
        });

        first_writer_entered_rx.await.unwrap();
        assert!(config_doc.try_lock().is_err());

        let (second_update_started_tx, second_update_started_rx) = oneshot::channel();
        let (second_writer_entered_tx, mut second_writer_entered_rx) = oneshot::channel();
        let update_b = tokio::spawn({
            let peer_list = peer_list.clone();
            let config_doc = config_doc.clone();
            let peer_b = peer_b.clone();
            async move {
                second_update_started_tx.send(()).unwrap();
                update_to_new_peer_list_with_writer(
                    HashSet::from([peer_b]),
                    local_addr,
                    peer_list,
                    sender,
                    config_doc,
                    &path,
                    move |doc, path| {
                        second_writer_entered_tx.send(()).unwrap();
                        write_toml_file(doc, path)
                    },
                )
                .await
            }
        });

        second_update_started_rx.await.unwrap();
        assert!(
            matches!(
                second_writer_entered_rx.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ),
            "the second writer entered while the first update held the serialization lock"
        );

        release_first_writer_tx.send(()).unwrap();
        update_a.await.unwrap().unwrap();
        second_writer_entered_rx.await.unwrap();
        update_b.await.unwrap().unwrap();

        let persisted = read_toml_file(config.path()).unwrap();
        let peers = persisted["peers"].as_array().expect("peers array");
        let persisted_addresses: HashSet<&str> = peers
            .iter()
            .map(|peer| {
                peer.as_inline_table()
                    .and_then(|table| table.get("addr"))
                    .and_then(toml_edit::Value::as_str)
                    .expect("peer address")
            })
            .collect();
        assert_eq!(persisted_addresses.len(), 2);
        assert!(persisted_addresses.contains(peer_a.addr.to_string().as_str()));
        assert!(persisted_addresses.contains(peer_b.addr.to_string().as_str()));
        assert_eq!(*peer_list.read().await, HashSet::from([peer_a, peer_b]));
        assert_eq!(config_doc.lock().await.to_string(), persisted.to_string());
    }

    #[tokio::test]
    async fn test_peer_list_write_failure_leaves_config_and_runtime_unchanged() {
        let peer_list = Arc::new(RwLock::new(HashSet::new()));
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let local_addr: SocketAddr = "127.0.0.1:38383".parse().unwrap();
        let initial = "peers = []\n";
        let config_doc = Arc::new(Mutex::new(initial.parse::<DocumentMut>().unwrap()));
        let config = TempConfig::from_str(initial);
        let peer = peer_identity("127.0.0.2:38383".parse().unwrap(), "peer-a");

        let err = update_to_new_peer_list_with_writer(
            HashSet::from([peer.clone()]),
            local_addr,
            peer_list.clone(),
            sender,
            config_doc.clone(),
            config.path(),
            |_doc, _path| Err(anyhow!("injected write failure")),
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("failed to persist peer list"));
        assert!(peer_list.read().await.is_empty());
        assert_eq!(config_doc.lock().await.to_string(), initial);
        assert_eq!(std::fs::read_to_string(config.path()).unwrap(), initial);
        assert!(matches!(
            receiver.try_recv(),
            Err(TryRecvError::Empty | TryRecvError::Disconnected)
        ));
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
        let peer = Peer::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &certs,
            0,
        )
        .unwrap();

        let ingest_sensors = Arc::new(RwLock::new(HashSet::new()));
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let peer_idents = Arc::new(RwLock::new(HashSet::new()));
        let notify_sensor = Arc::new(Notify::new());
        let (_tls_tx, tls_watch) = test_tls_watch_from_certs(create_certs());

        let err = peer
            .run(
                ingest_sensors,
                peers,
                peer_idents,
                notify_sensor,
                "missing-config.toml".to_string(),
                tls_watch,
                CancellationToken::new(),
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
                    Arc::new(Mutex::new(doc)),
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
                    Arc::new(Mutex::new(doc)),
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
    async fn test_connection_snapshot_releases_lock_before_subsequent_await() {
        let peer_conns = Arc::new(RwLock::new(HashMap::new()));
        let continue_task = Arc::new(Notify::new());
        let continue_task_handle = continue_task.clone();
        let peer_conns_handle = peer_conns.clone();
        let (snapshot_ready_tx, snapshot_ready_rx) = oneshot::channel();

        let task = tokio::spawn(async move {
            let connections = snapshot_connections(&peer_conns_handle).await;
            snapshot_ready_tx.send(connections.len()).unwrap();
            continue_task_handle.notified().await;
        });

        assert_eq!(snapshot_ready_rx.await.unwrap(), 0);
        let peer_conns_write =
            with_timeout("peer connection write lock timeout", peer_conns.write()).await;
        drop(peer_conns_write);

        continue_task.notify_one();
        task.await.unwrap();
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

    #[tokio::test]
    async fn apply_peer_tls_reload_swaps_client_config_on_success() {
        init_crypto();

        let initial_certs = create_certs();
        let new_certs = create_node2_certs();

        let (server_endpoint, _server_addr) = setup_server_endpoint_with_certs(&initial_certs);
        let initial_client_config = config_client(&initial_certs).expect("initial client config");
        let shared: SharedClientConfig = super::new_shared_client_config(initial_client_config, 0);

        // Snapshot the actual pre-reload slot value so the post-reload
        // comparison can detect a replacement rather than just a distinct
        // allocation that was never installed.
        let before = Arc::clone(&shared.read().expect("lock").config);

        let new_material = crate::tls_reload::TlsMaterial {
            certs: Arc::new(new_certs.clone()),
            cert_pem: Vec::new(),
            key_pem: Vec::new(),
            ca_pem: Vec::new(),
            generation: 1,
        };
        apply_peer_tls_reload(&server_endpoint, &shared, &new_material);

        let after_gen = shared.read().expect("lock").applied_generation;
        let after = Arc::clone(&shared.read().expect("lock").config);
        assert!(
            !Arc::ptr_eq(&before, &after),
            "client config slot must be replaced with a new Arc after reload"
        );
        assert_eq!(
            after_gen, 1,
            "successful reload must adopt the published material generation"
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
            leaf(&presented),
            leaf(&new_certs.certs),
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
        let shared: SharedClientConfig = super::new_shared_client_config(initial_client_config, 0);
        let before_gen = shared.read().expect("lock").applied_generation;
        let before = Arc::clone(&shared.read().expect("lock").config);

        // Build a Certs where cert and key do not form a valid pair so
        // config_server fails at with_single_cert.
        let other = create_node2_certs();
        let mismatched = Certs {
            certs: initial_certs.certs.clone(),
            key: other.key.clone_key(),
            root: initial_certs.root.clone(),
        };
        let mismatched_material = crate::tls_reload::TlsMaterial {
            certs: Arc::new(mismatched),
            cert_pem: Vec::new(),
            key_pem: Vec::new(),
            ca_pem: Vec::new(),
            generation: 1,
        };

        apply_peer_tls_reload(&server_endpoint, &shared, &mismatched_material);

        let after_gen = shared.read().expect("lock").applied_generation;
        let after = Arc::clone(&shared.read().expect("lock").config);
        assert!(
            Arc::ptr_eq(&before, &after),
            "client config slot must be preserved when reload preparation fails"
        );
        assert_eq!(
            after_gen, before_gen,
            "failed reload must not adopt the new material generation"
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
            leaf(&initial_certs.certs),
            leaf(&new_certs.certs),
            "test setup requires distinct cert material pre- and post-reload"
        );

        let peer = Peer::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &initial_certs,
            0,
        )
        .unwrap();

        let ingest_sensors = Arc::new(RwLock::new(HashSet::new()));
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let peer_idents = Arc::new(RwLock::new(HashSet::new()));
        let notify_sensor = Arc::new(Notify::new());
        let token = CancellationToken::new();
        let token_handle = token.clone();
        let (tls_tx, tls_watch) = test_tls_watch_from_certs(initial_certs.clone());
        let config = TempConfig::from_str("peers = []");
        let config_path = config.path().to_string();

        let (ready_tx, ready_rx) = oneshot::channel();
        let ingest_sensors_for_run = ingest_sensors.clone();
        let peers_for_run = peers.clone();
        let peer_idents_for_run = peer_idents.clone();
        let peer_handle = tokio::spawn(async move {
            peer.run_with_ready(
                ingest_sensors_for_run,
                peers_for_run,
                peer_idents_for_run,
                notify_sensor,
                config_path,
                tls_watch,
                token,
                Some(ready_tx),
            )
            .await
        });

        let (server_addr, _shared_client_config, _) = with_timeout("peer server ready", ready_rx)
            .await
            .expect("peer ready");

        // Pre-reload: connect under the initial SNI and capture the server
        // leaf fingerprint.
        let pre = TestClient::new(server_addr).await;
        let pre_peer_certs = extract_cert_from_conn(&pre.conn).expect("peer certs pre-reload");
        assert_eq!(leaf(&pre_peer_certs), leaf(&initial_certs.certs),);
        drop(pre);

        // Push genuinely different TLS material through the watch channel.
        let new_material = Arc::new(crate::tls_reload::TlsMaterial {
            certs: Arc::new(new_certs.clone()),
            cert_pem: Vec::new(),
            key_pem: Vec::new(),
            ca_pem: Vec::new(),
            generation: 1,
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
            if leaf(&probe_certs) == leaf(&new_certs.certs) {
                drop(conn);
                token_handle.cancel();
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
            0,
        )
        .unwrap();

        let ingest_sensors = Arc::new(RwLock::new(HashSet::new()));
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let peer_idents = Arc::new(RwLock::new(HashSet::new()));
        let notify_sensor = Arc::new(Notify::new());
        let token = CancellationToken::new();
        let token_handle = token.clone();
        let (tls_tx, tls_watch) = test_tls_watch_from_certs(initial_certs.clone());
        let config = TempConfig::from_str("peers = []");
        let config_path = config.path().to_string();

        let (ready_tx, ready_rx) = oneshot::channel();
        let peer_handle = tokio::spawn(peer.run_with_ready(
            ingest_sensors,
            peers,
            peer_idents,
            notify_sensor,
            config_path,
            tls_watch,
            token,
            Some(ready_tx),
        ));

        let (server_addr, _shared_client_config, _) = with_timeout("peer server ready", ready_rx)
            .await
            .expect("peer ready");

        // Baseline inbound handshake observes initial server leaf cert.
        let pre = TestClient::new(server_addr).await;
        let pre_fp = leaf(&extract_cert_from_conn(&pre.conn).expect("peer certs pre-reload"));
        assert_eq!(pre_fp, leaf(&initial_certs.certs));
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
            ca_pem: Vec::new(),
            generation: 1,
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
            let fp = leaf(&extract_cert_from_conn(&probe.conn).expect("probe peer certs"));
            assert_eq!(
                fp,
                leaf(&initial_certs.certs),
                "failed reload must preserve the previous server leaf cert"
            );
            drop(probe);
        }

        token_handle.cancel();
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
            leaf(&initial_client_certs.certs),
            leaf(&new_client_certs.certs),
            "test setup requires distinct client leaf material"
        );

        let (server_endpoint, server_addr) = setup_server_endpoint_with_certs(&server_certs);
        let shared: SharedClientConfig = super::new_shared_client_config(
            config_client(&initial_client_certs).expect("initial client config"),
            0,
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
            let fp = leaf(&extract_cert_from_conn(&conn).expect("client certs 1"));
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
            leaf(&initial_client_certs.certs),
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
            state.applied_generation = state.applied_generation.saturating_add(1);
            state.config = Arc::new(new_client_config);
        }

        // Cycle 2: redial and confirm the remote peer observes the new
        // client leaf fingerprint. This is the outbound-reconnect
        // observation the review was asking for.
        let accept_2 = async {
            let incoming = accept_incoming(&server_endpoint, "accept 2").await;
            let conn = incoming.await.expect("server accept 2");
            let fp = leaf(&extract_cert_from_conn(&conn).expect("client certs 2"));
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
            leaf(&new_client_certs.certs),
            "remote peer must observe the refreshed client leaf after reload"
        );
        assert_eq!(current_applied_generation(&shared), 1);
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
            0,
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
        let mismatched_material = crate::tls_reload::TlsMaterial {
            certs: Arc::new(mismatched),
            cert_pem: Vec::new(),
            key_pem: Vec::new(),
            ca_pem: Vec::new(),
            generation: 1,
        };
        apply_peer_tls_reload(&probe_server_endpoint, &shared, &mismatched_material);
        assert_eq!(
            current_applied_generation(&shared),
            0,
            "failed reload must not adopt the new material generation"
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
            let fp = leaf(&extract_cert_from_conn(&conn).expect("client certs"));
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
            leaf(&initial_client_certs.certs),
            "outbound reconnect must observe the preserved client leaf after a failed reload"
        );
        drop(client_conn);
        drop(server_conn);
    }

    /// Regression test for the stale-in-flight reconnect race.
    ///
    /// The production guard in `client_connection()` snapshots
    /// `(generation, ClientConfig)` at dial time and, after the dial
    /// completes, closes the connection and retries with the refreshed
    /// config when a peer TLS reload bumped the generation while the
    /// dial was in flight. This test forces exactly that sequence:
    /// the server pauses between the QUIC handshake and the
    /// giganto-client handshake so the test can swap the shared client
    /// config under the running task before the gen check fires. The
    /// retry must therefore present the post-reload client leaf to the
    /// server.
    #[tokio::test]
    async fn client_connection_retries_when_inflight_dial_is_superseded_by_reload() {
        // A full server-side accept cycle can consume about 35.25 seconds:
        // 3 seconds for the initial attempt, four subsequent attempts that
        // each allow the production client's 5-second reconnect delay plus
        // a fresh 3-second QUIC handshake, and five 50-millisecond retry
        // intervals. Keep this larger budget local so the shared 10-second
        // test timeout remains strict for unrelated peer tests.
        const RELOAD_RACE_TIMEOUT: Duration = Duration::from_secs(40);

        init_crypto();

        let server_certs = create_certs();
        let initial_client_certs = create_certs();
        let new_client_certs = create_node2_certs();
        assert_ne!(
            leaf(&initial_client_certs.certs),
            leaf(&new_client_certs.certs),
            "test setup requires distinct client leaf material",
        );

        let (server_endpoint, server_addr) = setup_server_endpoint_with_certs(&server_certs);
        let server_endpoint_for_task = server_endpoint.clone();

        let initial_client_config =
            config_client(&initial_client_certs).expect("initial client config");
        let shared = super::new_shared_client_config(initial_client_config, 0);
        let new_client_config = config_client(&new_client_certs).expect("new client config");

        let local_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (peer_conn_info, _config_temp) = build_peer_conn_info(local_address);
        let peer_info = PeerIdentity {
            addr: server_addr,
            hostname: test_connect_name().to_string(),
        };
        let client_endpoint =
            quinn::Endpoint::client("[::]:0".parse().expect("client addr")).expect("endpoint");

        let token = CancellationToken::new();
        let tracker = TaskTracker::with_token(token.clone());

        let (first_quic_done_tx, first_quic_done_rx) = oneshot::channel::<()>();
        let (release_first_handshake_tx, release_first_handshake_rx) = oneshot::channel::<()>();
        let (second_dial_observed_tx, second_dial_observed_rx) =
            oneshot::channel::<Option<Vec<u8>>>();

        let server_task = tokio::spawn(async move {
            // First dial: complete the QUIC handshake, then pause until the
            // test bumps the shared generation. The client's
            // giganto-client handshake stays blocked until we resume.
            let conn1 = accept_quic_with_retry(
                server_endpoint_for_task.clone(),
                "first QUIC handshake for TLS reload race",
            )
            .await;
            first_quic_done_tx.send(()).expect("signal first quic done");
            release_first_handshake_rx
                .await
                .expect("release first handshake");
            let _ = server_handshake(&conn1, PEER_VERSION_REQ)
                .await
                .expect("first server_handshake");

            // Retry dial: extract the client leaf so the test can verify
            // the refreshed config was used, then complete the handshake.
            let conn2 =
                accept_quic_with_retry(server_endpoint_for_task, "post-reload QUIC handshake")
                    .await;
            let observed_fp =
                leaf(&extract_cert_from_conn(&conn2).expect("extract second client cert"));
            second_dial_observed_tx
                .send(observed_fp)
                .expect("send observed fingerprint");
            let _ = server_handshake(&conn2, PEER_VERSION_REQ).await;
        });

        let shared_for_client = Arc::clone(&shared);
        let client_task = tokio::spawn({
            let token = token.clone();
            async move {
                client_connection(
                    client_endpoint,
                    shared_for_client,
                    peer_info,
                    peer_conn_info,
                    test_connect_name().to_string(),
                    tracker,
                    token,
                )
                .await
            }
        });

        tokio::time::timeout(RELOAD_RACE_TIMEOUT, first_quic_done_rx)
            .await
            .expect("first QUIC handshake exceeded the retry budget")
            .expect("server should accept the first dial");

        // Simulate a peer TLS reload landing while the first dial is
        // still mid-handshake: bump the shared generation and swap the
        // client config to the refreshed material. Only after that do we
        // unblock the server-side handshake, so the client's `connect()`
        // returns with a stale snapshot generation and the gen guard
        // must fire.
        {
            let mut state = super::write_state(&shared);
            state.applied_generation = state.applied_generation.saturating_add(1);
            state.config = Arc::new(new_client_config);
        }
        release_first_handshake_tx
            .send(())
            .expect("release first handshake");

        let observed_fp = tokio::time::timeout(RELOAD_RACE_TIMEOUT, second_dial_observed_rx)
            .await
            .expect("post-reload QUIC handshake exceeded the retry budget")
            .expect("client_connection should retry after detecting stale snapshot");
        assert_eq!(
            observed_fp,
            leaf(&new_client_certs.certs),
            "retry must present the refreshed client leaf fingerprint",
        );

        token.cancel();
        client_task.abort();
        let _ = client_task.await;
        server_task.abort();
        let _ = server_task.await;
    }

    /// Regression test for the post-spawn startup-reload race.
    ///
    /// `main` reads TLS material, builds `Peer` from that snapshot, and
    /// passes a cloned `tls_watch` into `Peer::run()`. If a SIGHUP
    /// publishes refreshed material between the receiver clone and the
    /// point inside `Peer::run` that decides what to do with the
    /// initial watch value, the previous implementation discarded that
    /// update — leaving the peer subsystem on stale TLS state until the
    /// next reload. This test preloads the watch with material that
    /// differs from what `Peer` was constructed with and verifies the
    /// subsystem applies it at startup so new inbound handshakes observe
    /// the post-reload leaf.
    #[tokio::test]
    async fn peer_run_applies_post_spawn_reload_at_startup() {
        init_crypto();

        let initial_certs = create_certs();
        let new_certs = create_node2_certs();
        assert_ne!(
            leaf(&initial_certs.certs),
            leaf(&new_certs.certs),
            "test setup requires distinct cert material",
        );

        let peer = Peer::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &initial_certs,
            0,
        )
        .unwrap();

        // Seed the watch with the post-reload material at a higher
        // generation so it looks like the SIGHUP-driven reload landed
        // before `Peer::run()` got to examine the watch value.
        let (_tls_tx, tls_watch) = test_tls_watch_from_certs_with_generation(new_certs.clone(), 1);

        let ingest_sensors = Arc::new(RwLock::new(HashSet::new()));
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let peer_idents = Arc::new(RwLock::new(HashSet::new()));
        let notify_sensor = Arc::new(Notify::new());
        let token = CancellationToken::new();
        let token_handle = token.clone();
        let config = TempConfig::from_str("peers = []");
        let config_path = config.path().to_string();

        let (ready_tx, ready_rx) = oneshot::channel();
        let peer_handle = tokio::spawn(peer.run_with_ready(
            ingest_sensors,
            peers,
            peer_idents,
            notify_sensor,
            config_path,
            tls_watch,
            token,
            Some(ready_tx),
        ));

        let (server_addr, _shared_client_config, _) = with_timeout("peer server ready", ready_rx)
            .await
            .expect("peer ready");

        // Probe with the post-reload SAN. If the subsystem had discarded
        // the watch value via `mark_unchanged()`, the listener would
        // still serve `initial_certs` and the post-reload SNI would
        // either fail to validate or yield the wrong leaf fingerprint.
        let mut converged = false;
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
            if leaf(&probe_certs) == leaf(&new_certs.certs) {
                converged = true;
                drop(conn);
                break;
            }
        }
        assert!(
            converged,
            "peer subsystem must apply a post-spawn watch update at startup instead of \
             discarding it via mark_unchanged()",
        );

        token_handle.cancel();
        with_timeout("peer shutdown", peer_handle)
            .await
            .expect("peer task join")
            .expect("peer task result");
    }

    /// Regression test for the CA/root-only startup-reload race.
    ///
    /// `ReloadHandle::reload()` advances the published material's
    /// generation whenever cert/key/CA bytes change, including a
    /// CA-only update. If the peer subsystem's startup check only
    /// compared the leaf certificate fingerprint, a CA-only reload
    /// published before `Peer::run()` first observed the watch would
    /// be silently discarded — the leaf would match, but the trust
    /// root would still be the pre-reload value. Comparing material
    /// generations covers this case. Here the watched material is
    /// constructed from the same cert/key/root bytes as `Peer` was
    /// built from but at a higher generation, so the pre-fix
    /// fingerprint check would have skipped the apply while the new
    /// generation-based check applies it.
    #[tokio::test]
    async fn peer_run_applies_ca_only_post_spawn_reload_at_startup() {
        init_crypto();

        let initial_certs = create_certs();

        let peer = Peer::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &initial_certs,
            0,
        )
        .unwrap();

        // Same certs as what `Peer` was built from — i.e. the leaf
        // fingerprint is unchanged — but with a higher generation,
        // simulating a CA-only reload that bumped the published
        // generation without changing the leaf certificate.
        let (_tls_tx, tls_watch) =
            test_tls_watch_from_certs_with_generation(initial_certs.clone(), 1);

        let ingest_sensors = Arc::new(RwLock::new(HashSet::new()));
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let peer_idents = Arc::new(RwLock::new(HashSet::new()));
        let notify_sensor = Arc::new(Notify::new());
        let token = CancellationToken::new();
        let token_handle = token.clone();
        let config = TempConfig::from_str("peers = []");
        let config_path = config.path().to_string();

        let (ready_tx, ready_rx) = oneshot::channel();
        let peer_handle = tokio::spawn(peer.run_with_ready(
            ingest_sensors,
            peers,
            peer_idents,
            notify_sensor,
            config_path,
            tls_watch,
            token,
            Some(ready_tx),
        ));

        let (_server_addr, shared_client_config, _) = with_timeout("peer server ready", ready_rx)
            .await
            .expect("peer ready");

        // The startup TLS apply runs in the peer task right after the
        // `ready` send, so poll the shared state until the apply lands.
        // A leaf-fingerprint-only check would have left
        // `applied_generation` at 0 forever; the generation-based check
        // must adopt the published generation 1.
        let mut applied = false;
        for _ in 0..40 {
            if super::current_applied_generation(&shared_client_config) == 1 {
                applied = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            applied,
            "CA-only reload published before `Peer::run()` first observed the \
             watch must still be applied at startup, but applied_generation \
             stayed at {} (expected 1)",
            super::current_applied_generation(&shared_client_config),
        );

        token_handle.cancel();
        with_timeout("peer shutdown", peer_handle)
            .await
            .expect("peer task join")
            .expect("peer task result");
    }

    /// Cooperative shutdown: cancellation, admission control, and drain.
    ///
    /// Every test here drives shutdown through a [`CancellationToken`] and
    /// asserts on task completion, log output, or shared peer state — never on
    /// elapsed time. The bounded timeouts that do appear are there to fail a
    /// hang fast, or to establish that something is genuinely blocked before
    /// the step that is supposed to release it runs.
    mod shutdown {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::{
            collections::{HashMap, HashSet},
            io::{self, Write},
            net::SocketAddr,
            sync::{Arc, Mutex as StdMutex},
            time::Duration,
        };

        use anyhow::Result;
        use giganto_client::connection::{client_handshake, server_handshake};
        use giganto_client::frame::send_bytes;
        use quinn::Endpoint;
        use tokio::sync::{Mutex, Notify, RwLock, mpsc, oneshot};
        use tokio_util::sync::CancellationToken;
        use toml_edit::DocumentMut;
        use tracing_subscriber::fmt::MakeWriter;

        use super::super::{
            PEER_DRAIN_LABEL, PEER_VERSION_REQ, PeerCode, PeerConns, PeerIdentity, PeerInfo, Peers,
            client_connection, receive_peer_data, request_init_info, response_init_info,
            send_peer_data, server_connection, shutdown_peer, spawn_request_handler,
            update_to_new_peer_list_with_writer,
        };
        use super::fixtures::{
            ConnectedPeers, PROTOCOL_VERSION, TEST_TIMEOUT, TempConfig, TestClient,
            accept_incoming, build_peer_conn_info, build_peer_conn_info_with_sensors,
            connect_client_server, create_certs, create_node2_certs, init_client, init_crypto,
            init_shared_client_config, peer_identity, peer_info, run_peer_with_ready,
            setup_server_endpoint, setup_server_endpoint_with_certs,
            small_stream_window_client_endpoint, test_connect_name, test_connect_name_node2,
            wait_for_peer_info, with_timeout,
        };
        use crate::cancellation::{
            DRAIN_REPORT_INTERVAL, DrainOutcome, TaskTracker, drain_with_report,
        };
        use crate::comm::peer::Peer;
        use crate::server::config_server;

        /// A dial that shutdown has already made unservable must fail rather
        /// than hang; this caps how long a test waits to find that out.
        const REFUSED_DIAL_TIMEOUT: Duration = Duration::from_secs(2);
        /// How long a test waits to establish that something is genuinely
        /// blocked before it runs the step meant to release it.
        const BLOCKED_PROBE: Duration = Duration::from_millis(200);
        /// The remote a directly driven request handler is registered
        /// under, so a test can name the task it expects to find pending.
        const BLOCKED_REMOTE: &str = "127.0.0.1:7100";
        /// What the peer-identity enqueue path reports when the receive side
        /// will not take an identity.
        const REFUSED_ENQUEUE: &str = "Failed to enqueue peer connection attempt";

        #[derive(Clone, Default)]
        struct SharedLogBuffer(Arc<StdMutex<Vec<u8>>>);

        impl SharedLogBuffer {
            fn contents(&self) -> String {
                let bytes = self.0.lock().expect("log buffer lock").clone();
                String::from_utf8_lossy(&bytes).into_owned()
            }

            fn contains(&self, needle: &str) -> bool {
                self.contents().contains(needle)
            }
        }

        struct SharedLogWriter(Arc<StdMutex<Vec<u8>>>);

        impl Write for SharedLogWriter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0
                    .lock()
                    .expect("log buffer lock")
                    .extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        impl<'a> MakeWriter<'a> for SharedLogBuffer {
            type Writer = SharedLogWriter;

            fn make_writer(&'a self) -> Self::Writer {
                SharedLogWriter(Arc::clone(&self.0))
            }
        }

        /// Installs a log-capturing subscriber for the current thread, the way
        /// `src/cancellation.rs` does. A `#[tokio::test]` runs its tasks on
        /// the calling thread, so the peer tasks spawned below are captured
        /// too.
        fn capture_logs() -> (SharedLogBuffer, tracing::subscriber::DefaultGuard) {
            let logs = SharedLogBuffer::default();
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .without_time()
                .with_target(false)
                .with_writer(logs.clone())
                .finish();
            let guard = tracing::subscriber::set_default(subscriber);
            (logs, guard)
        }

        /// Waits until `needle` shows up in the captured log.
        async fn wait_for_log(logs: &SharedLogBuffer, needle: &str) {
            let fut = async {
                let mut interval = tokio::time::interval(Duration::from_millis(5));
                loop {
                    interval.tick().await;
                    if logs.contains(needle) {
                        return;
                    }
                }
            };
            assert!(
                tokio::time::timeout(TEST_TIMEOUT, fut).await.is_ok(),
                "log never contained {needle:?}; got: {}",
                logs.contents()
            );
        }

        /// Waits until `predicate` holds for the shared connection map.
        async fn wait_for_conns<F>(label: &'static str, conns: &PeerConns, mut predicate: F)
        where
            F: FnMut(&HashMap<String, quinn::Connection>) -> bool,
        {
            let fut = async {
                let mut interval = tokio::time::interval(Duration::from_millis(5));
                loop {
                    interval.tick().await;
                    if predicate(&*conns.peer_conns.read().await) {
                        return;
                    }
                }
            };
            assert!(
                tokio::time::timeout(TEST_TIMEOUT, fut).await.is_ok(),
                "{label}"
            );
        }

        /// Waits until `predicate` holds, polling the runtime rather than
        /// sleeping for a span that would have to guess how long the work
        /// takes.
        async fn wait_until<F>(label: &'static str, mut predicate: F)
        where
            F: FnMut() -> bool,
        {
            let fut = async {
                let mut interval = tokio::time::interval(Duration::from_millis(5));
                loop {
                    interval.tick().await;
                    if predicate() {
                        return;
                    }
                }
            };
            assert!(
                tokio::time::timeout(TEST_TIMEOUT, fut).await.is_ok(),
                "{label}"
            );
        }

        /// The captured log lines that report a refused peer-identity
        /// enqueue, so a test can tie a refusal to the identity it dropped
        /// rather than to any mention of that identity in the log.
        fn refusals(output: &str) -> impl Iterator<Item = &str> {
            output.lines().filter(|line| line.contains(REFUSED_ENQUEUE))
        }

        /// State the shared peer maps are keyed on and the tests read back.
        fn local_address() -> SocketAddr {
            "127.0.0.1:2222".parse().expect("local address")
        }

        /// Everything a running peer entry task exposes to a test.
        struct PeerHarness {
            addr: SocketAddr,
            token: CancellationToken,
            handle: tokio::task::JoinHandle<Result<()>>,
            peers: Peers,
            notify_sensor: Arc<Notify>,
            /// A sending half of the peer-identity channel the entry task
            /// created, so a test can offer an identity on the real channel.
            peer_sender: mpsc::Sender<PeerIdentity>,
            _config: TempConfig,
        }

        impl PeerHarness {
            /// Starts the production entry task over an `IPv4` loopback
            /// listener, seeded with `sensors` and with `peer_idents` as the
            /// bootstrap peer list.
            async fn start(sensors: &[&str], peer_idents: HashSet<PeerIdentity>) -> Self {
                init_crypto();
                let peer = Peer::new(
                    "127.0.0.1:0".parse().expect("peer bind address"),
                    &create_certs(),
                    0,
                )
                .expect("peer");
                let ingest_sensors: crate::comm::IngestSensors = Arc::new(RwLock::new(
                    sensors.iter().map(|s| (*s).to_string()).collect(),
                ));
                let peers: Peers = Arc::new(RwLock::new(HashMap::new()));
                let notify_sensor = Arc::new(Notify::new());
                let config = TempConfig::from_str("peers = []");
                let token = CancellationToken::new();
                let (ready_tx, ready_rx) = oneshot::channel();
                let handle = tokio::spawn(run_peer_with_ready(
                    peer,
                    ingest_sensors,
                    peers.clone(),
                    Arc::new(RwLock::new(peer_idents)),
                    notify_sensor.clone(),
                    config.path().to_string(),
                    token.clone(),
                    ready_tx,
                ));
                let (addr, _, peer_sender) = with_timeout("peer server ready timeout", ready_rx)
                    .await
                    .expect("peer server did not report its address");
                Self {
                    addr,
                    token,
                    handle,
                    peers,
                    notify_sensor,
                    peer_sender,
                    _config: config,
                }
            }

            /// Cancels the token and waits for the entry task to return, which
            /// it does only after its drain is empty.
            async fn cancel_and_join(self) -> Peers {
                self.token.cancel();
                with_timeout("peer shutdown timeout", self.handle)
                    .await
                    .expect("peer entry task join")
                    .expect("peer entry task result");
                self.peers
            }
        }

        /// Completes the init handshake a peer expects from an inbound client.
        async fn exchange_init(client: &mut TestClient) -> (HashSet<PeerIdentity>, PeerInfo) {
            request_init_info::<(HashSet<PeerIdentity>, PeerInfo)>(
                &mut client.send,
                &mut client.recv,
                PeerCode::UpdatePeerList,
                (HashSet::new(), PeerInfo::default()),
            )
            .await
            .expect("initial peer information exchange failed")
        }

        /// Drives one inbound connection handler directly, so a test can own
        /// the peer-local tracker and the shared peer state the handler
        /// mutates.
        struct ServerRoleHarness {
            client: TestClient,
            handle: tokio::task::JoinHandle<Result<()>>,
            peer_conn_info: PeerConns,
            tracker: TaskTracker,
            token: CancellationToken,
            _config: TempConfig,
        }

        impl ServerRoleHarness {
            async fn start(sensors: &[&str], close_tracker: bool) -> Self {
                init_crypto();
                let (server_endpoint, server_addr) = setup_server_endpoint();
                let (peer_conn_info, config) =
                    build_peer_conn_info_with_sensors(local_address(), sensors);
                let token = CancellationToken::new();
                let tracker = TaskTracker::with_token(token.clone());
                if close_tracker {
                    tracker.close().expect("close the peer-local tracker");
                }
                let handle = tokio::spawn({
                    let peer_conn_info = peer_conn_info.clone();
                    let tracker = tracker.clone();
                    let token = token.clone();
                    async move {
                        let incoming =
                            accept_incoming(&server_endpoint, "server accept timeout").await;
                        server_connection(incoming, peer_conn_info, tracker, token).await
                    }
                });
                let mut client = TestClient::new(server_addr).await;
                exchange_init(&mut client).await;
                // The handler inserts its connection last, so this is what
                // says it has reached its serve loop.
                wait_for_conns(
                    "the handler never registered its connection",
                    &peer_conn_info,
                    |conns| !conns.is_empty(),
                )
                .await;
                Self {
                    client,
                    handle,
                    peer_conn_info,
                    tracker,
                    token,
                    _config: config,
                }
            }
        }

        /// The entry task returns on cancellation, and its server endpoint is
        /// closed by the time it does.
        #[tokio::test]
        async fn cancellation_returns_the_entry_task_with_the_endpoints_closed() {
            let harness = PeerHarness::start(&[], HashSet::new()).await;
            let addr = harness.addr;
            harness.cancel_and_join().await;

            let client = init_client();
            let dial = client
                .connect(addr, test_connect_name())
                .expect("dial setup should still succeed");
            let refused = match tokio::time::timeout(REFUSED_DIAL_TIMEOUT, dial).await {
                Ok(result) => result.is_err(),
                // A closed endpoint answers nothing, so a dial that never
                // resolves is refused just as surely as one that errors.
                Err(_) => true,
            };
            assert!(refused, "a dial after shutdown must not be served");
        }

        /// A dial that arrives after the entry task closed the server endpoint
        /// is refused by quinn before peer can attempt a registration, so it
        /// creates no peer task and no `peers` entry — and logs no rejection,
        /// because it never reaches one.
        #[tokio::test]
        async fn a_dial_after_the_endpoint_closed_creates_no_peer_task() {
            let (logs, _guard) = capture_logs();
            let harness = PeerHarness::start(&["late-sensor"], HashSet::new()).await;
            let addr = harness.addr;
            let peers = harness.cancel_and_join().await;

            let client = init_client();
            if let Ok(dial) = client.connect(addr, test_connect_name()) {
                let _ = tokio::time::timeout(REFUSED_DIAL_TIMEOUT, dial).await;
            }

            assert!(
                peers.read().await.is_empty(),
                "a refused dial must not reach the peer state"
            );
            let output = logs.contents();
            assert!(
                !output.contains("Rejected peer connection from"),
                "a dial quinn refused must not produce a spawn rejection, got: {output}"
            );
        }

        /// With a peer connection in each role, cancellation closes both and
        /// both handlers return before the entry task does.
        #[tokio::test]
        async fn cancellation_ends_connection_handlers_in_both_roles() {
            init_crypto();
            let other_certs = create_node2_certs();
            let (other_endpoint, other_addr) = setup_server_endpoint_with_certs(&other_certs);
            let (other_ready_tx, other_ready_rx) = oneshot::channel();
            let other_task = tokio::spawn(async move {
                let incoming = accept_incoming(&other_endpoint, "other peer accept timeout").await;
                let connection = incoming.await.expect("other peer connection");
                let (mut send, mut recv) = server_handshake(&connection, PEER_VERSION_REQ)
                    .await
                    .expect("other peer protocol handshake");
                response_init_info::<(HashSet<PeerIdentity>, PeerInfo)>(
                    &mut send,
                    &mut recv,
                    PeerCode::UpdatePeerList,
                    (HashSet::new(), PeerInfo::default()),
                )
                .await
                .expect("other peer init exchange");
                let _ = other_ready_tx.send(());
                // Resolves only once the peer has closed the connection it
                // dialed, which is what shutdown must do.
                connection.closed().await
            });

            let harness = PeerHarness::start(
                &["both-roles-sensor"],
                HashSet::from([peer_identity(other_addr, test_connect_name_node2())]),
            )
            .await;

            // Server role: an inbound peer that finished its init exchange.
            let mut client = TestClient::new(harness.addr).await;
            exchange_init(&mut client).await;
            let inbound = client.conn.clone();

            // Client role: the bootstrap dial reached the other peer.
            with_timeout("other peer ready timeout", other_ready_rx)
                .await
                .expect("the bootstrap dial never completed its init exchange");

            let peers = harness.cancel_and_join().await;

            // Both remotes observe their connection closed ...
            with_timeout("inbound connection close timeout", inbound.closed()).await;
            with_timeout("outbound connection close timeout", other_task)
                .await
                .expect("other peer task join");

            // ... and both handlers cleaned their shared state up on the way
            // out.
            assert!(
                peers.read().await.is_empty(),
                "both handlers should have removed their peers entries"
            );
        }

        /// A request task still holding a half-delivered frame when
        /// cancellation arrives is drained: its failure is already in the log
        /// by the time the entry task returns.
        #[tokio::test]
        async fn a_request_task_in_flight_is_drained_before_the_entry_task_returns() {
            let (logs, _guard) = capture_logs();
            let harness = PeerHarness::start(&["run-sensor"], HashSet::new()).await;
            let mut client = TestClient::new(harness.addr).await;
            exchange_init(&mut client).await;

            // The stream that stalls: only the peer code is ever delivered, so
            // its handler parks in `recv_raw` waiting for a frame body.
            let (mut stalled, _stalled_recv) = client
                .conn
                .open_bi()
                .await
                .expect("open the stalled stream");
            let code: u32 = PeerCode::UpdatePeerList.into();
            send_bytes(&mut stalled, &code.to_le_bytes())
                .await
                .expect("send the peer code");

            // A second stream, opened after it and therefore accepted after
            // it, carries a complete frame. Its effect landing is what proves
            // the stalled stream was accepted and its handler spawned.
            let (mut marker, _marker_recv) =
                client.conn.open_bi().await.expect("open the marker stream");
            send_peer_data(
                &mut marker,
                PeerCode::UpdateSensorList,
                peer_info(&["marker-sensor"], Some(1), Some(2)),
            )
            .await
            .expect("send the marker frame");
            marker.finish().ok();
            wait_for_peer_info("marker request timeout", &harness.peers, |read_peers| {
                read_peers
                    .values()
                    .any(|info| info.ingest_sensors.contains("marker-sensor"))
            })
            .await;

            let peers = harness.cancel_and_join().await;

            let output = logs.contents();
            assert!(
                output.contains("Peer request from"),
                "the stalled request task should have reported its failure \
                 before the entry task returned, got: {output}"
            );
            assert!(
                peers.read().await.is_empty(),
                "the connection handler should have removed its peers entry"
            );
        }

        /// A remote that completes the QUIC handshake and then never sends the
        /// protocol handshake cannot keep the entry task from returning.
        #[tokio::test]
        async fn a_stalled_inbound_handshake_does_not_block_shutdown() {
            let harness = PeerHarness::start(&[], HashSet::new()).await;

            // The QUIC handshake only completes once the entry task has handed
            // the `Incoming` to a tracked task, so this connection resolving is
            // what says the handler is parked in `server_handshake`.
            let client = init_client();
            let _stalled = client
                .connect(harness.addr, test_connect_name())
                .expect("dial setup")
                .await
                .expect("QUIC handshake");

            harness.cancel_and_join().await;
        }

        /// A sensor-update fan-out whose stream write cannot complete — the
        /// remote accepts the stream and never reads it — is drained, and its
        /// failure is reported.
        #[tokio::test]
        async fn a_stalled_sensor_update_fan_out_is_drained_and_reported() {
            let (logs, _guard) = capture_logs();
            // Large enough that it cannot fit in the receive window the client
            // endpoint below advertises, so the write parks on flow control.
            let bulky: Vec<String> = (0..4096).map(|i| format!("sensor-{i:0>60}")).collect();
            let bulky_refs: Vec<&str> = bulky.iter().map(String::as_str).collect();
            let harness = PeerHarness::start(&bulky_refs, HashSet::new()).await;

            let client_endpoint = small_stream_window_client_endpoint();
            let conn = client_endpoint
                .connect(harness.addr, test_connect_name())
                .expect("dial setup")
                .await
                .expect("QUIC handshake");
            let (mut send, mut recv) = client_handshake(&conn, PROTOCOL_VERSION)
                .await
                .expect("protocol handshake");
            request_init_info::<(HashSet<PeerIdentity>, PeerInfo)>(
                &mut send,
                &mut recv,
                PeerCode::UpdatePeerList,
                (HashSet::new(), PeerInfo::default()),
            )
            .await
            .expect("init exchange");

            harness.notify_sensor.notify_one();
            // The fan-out has opened its stream and is writing into a window
            // this side never drains.
            let (_fan_send, _fan_recv) = with_timeout("fan-out stream timeout", conn.accept_bi())
                .await
                .expect("the fan-out should have opened a stream");

            harness.cancel_and_join().await;

            let output = logs.contents();
            assert!(
                output.contains("Failed to send UpdateSensorList to peer"),
                "the fan-out task should have reported its outcome before the \
                 entry task returned, got: {output}"
            );
        }

        /// A tracked `handle_request` task blocked on a full peer-identity
        /// channel is released when the receive side closes, and the peer
        /// drain that was waiting on it then completes.
        ///
        /// The block is established before the release: a bounded drain
        /// reports the request task as still pending, so the completion below
        /// distinguishes a task the close freed from one that was never stuck.
        /// The channel is the test's own, at a capacity the test picked, since
        /// how many identities it takes to fill the entry task's channel is an
        /// implementation detail of the entry task.
        #[tokio::test]
        async fn a_tracked_request_task_blocked_on_the_peer_identity_channel_is_released() {
            let (logs, _guard) = capture_logs();
            init_crypto();
            let (server_endpoint, server_addr) = setup_server_endpoint();
            let ConnectedPeers {
                client_endpoint: _client_endpoint,
                server_conn,
                client_conn,
            } = connect_client_server(&server_endpoint, server_addr).await;

            // One slot and nobody receiving: the first of the two identities
            // below is buffered and the second has nowhere to go.
            let (sender, mut receiver) = mpsc::channel::<PeerIdentity>(1);
            let queued = sender.clone();
            let (mut peer_conn_info, _config) = build_peer_conn_info(local_address());
            peer_conn_info.peer_sender = sender;
            let tracker = TaskTracker::new();

            // The frame the handler reads: two peers neither the local address
            // nor the (empty) peer list already covers.
            let (mut send, _recv) = client_conn
                .open_bi()
                .await
                .expect("open the request stream");
            send_peer_data(
                &mut send,
                PeerCode::UpdatePeerList,
                HashSet::from([
                    peer_identity("127.0.0.1:7001".parse().expect("addr"), "blocked-peer-one"),
                    peer_identity("127.0.0.1:7002".parse().expect("addr"), "blocked-peer-two"),
                ]),
            )
            .await
            .expect("send the peer list frame");
            send.finish().ok();

            let stream = with_timeout("request stream timeout", server_conn.accept_bi())
                .await
                .expect("accept the request stream");
            spawn_request_handler(&tracker, stream, &peer_conn_info, BLOCKED_REMOTE);
            let task_name = format!("peer-request-{BLOCKED_REMOTE}");

            // The handler has received its frame and taken the only slot, so
            // the enqueue it is on now is the one that cannot complete.
            wait_until("the handler never filled the peer-identity channel", || {
                queued.capacity() == 0
            })
            .await;
            let pending = match tracker
                .drain(BLOCKED_PROBE)
                .await
                .expect("drain the tracker")
            {
                DrainOutcome::Pending(pending) => pending,
                DrainOutcome::Drained => {
                    panic!("the request task cannot get past its enqueue on its own")
                }
            };
            assert!(
                pending.iter().any(|task| task.name == task_name),
                "the pending snapshot should name the blocked request task, got: {pending:?}"
            );

            // What the entry task does once it has observed cancellation.
            receiver.close();

            with_timeout(
                "peer drain timeout",
                drain_with_report(&tracker, DRAIN_REPORT_INTERVAL, PEER_DRAIN_LABEL),
            )
            .await
            .expect("the drain should complete once the receive side is closed");
            wait_for_log(&logs, REFUSED_ENQUEUE).await;
        }

        /// The entry task's own `receiver.close()` releases a tracked send
        /// parked on the peer-identity channel while shutdown is in progress,
        /// and an identity offered once that task has returned is refused
        /// rather than swallowed or returned as an error.
        ///
        /// Both halves run against the real channel: the sender comes out of
        /// the running entry task through the `ready` payload, so the refusal
        /// is that channel's own and not a stand-in the test closed itself.
        ///
        /// The first half is what pins the production close. Joining the entry
        /// task drops its receiver, so a post-return refusal on its own would
        /// still hold if the explicit `receiver.close()` were deleted. A
        /// tracked task parked on a send while the entry task is still
        /// draining tells the two apart: the receiver is alive there but
        /// nobody polls it, so only the explicit close can let that send fail,
        /// and without it the drain — and so the join below — never completes.
        ///
        /// The park is arranged without a sleep. The test owns the shared
        /// `peers` map the harness runs on, so holding its write lock stops
        /// the inbound connection handler in `update_to_new_sensor_list` —
        /// after it has taken the peer list off the init exchange and before
        /// it enqueues anything from it. With the handler held there the test
        /// fills the channel through the entry task's sender and cancels the
        /// token, neither of which awaits, so the entry task cannot drain a
        /// slot back before it observes cancellation; releasing the lock then
        /// walks the handler straight into a send that cannot complete on its
        /// own.
        #[tokio::test]
        async fn a_send_parked_during_shutdown_is_released_and_a_later_one_refused() {
            let (logs, _guard) = capture_logs();
            let harness = PeerHarness::start(&[], HashSet::new()).await;
            let peer_sender = harness.peer_sender.clone();
            let shared_peers = harness.peers.clone();
            let blocked_peer = peer_identity(
                "127.0.0.1:7004".parse().expect("addr"),
                "blocked-during-shutdown",
            );

            // An inbound connection, so that the handler serving it is a task
            // in the entry task's own tracker and the drain has to wait for
            // it. Everything the handler needs from the network it has before
            // the cancellation below, so closing the connection cannot stand
            // in for the release the test is after.
            let client_endpoint = init_client();
            let conn = client_endpoint
                .connect(harness.addr, test_connect_name())
                .expect("dial setup")
                .await
                .expect("QUIC handshake");
            let (mut send, mut recv) = client_handshake(&conn, PROTOCOL_VERSION)
                .await
                .expect("protocol handshake");

            // Taken before the init exchange, so the handler cannot get past
            // the sensor-list update ahead of it.
            let peers_guard = shared_peers.write().await;
            request_init_info::<(HashSet<PeerIdentity>, PeerInfo)>(
                &mut send,
                &mut recv,
                PeerCode::UpdatePeerList,
                (HashSet::from([blocked_peer.clone()]), PeerInfo::default()),
            )
            .await
            .expect("init exchange");
            // The handler answers only after it has read that peer list, so it
            // is now parked on the write lock above with the list in hand.

            // Nothing awaits between here and the cancel: the entry task
            // cannot run, so it can neither hand a slot back nor drain one
            // after the token is set.
            let mut filled = 0;
            while peer_sender
                .try_send(peer_identity(
                    format!("127.0.0.1:{}", 20000 + filled)
                        .parse()
                        .expect("addr"),
                    "channel-filler",
                ))
                .is_ok()
            {
                filled += 1;
            }
            assert!(filled > 0, "the peer-identity channel should start empty");
            assert_eq!(
                peer_sender.capacity(),
                0,
                "the handler's next send must have nowhere to go"
            );
            harness.token.cancel();
            drop(peers_guard);

            // The handler now walks into a send on a full channel the entry
            // task has stopped receiving from. Without `receiver.close()` the
            // drain waits on it forever and this join times out.
            let peers = harness.cancel_and_join().await;
            assert!(
                peer_sender.is_closed(),
                "the entry task should have closed the peer-identity receive side"
            );
            assert!(
                refusals(&logs.contents()).any(|line| line.contains(&blocked_peer.hostname)),
                "the parked send should have been refused and reported, got: {}",
                logs.contents()
            );

            // Second half: the same sender, now that the entry task has
            // returned. A caller that still holds it gets a refusal it reports
            // rather than an error it propagates, and nothing is dialed.
            let late_peer = peer_identity("127.0.0.1:7003".parse().expect("addr"), "late-peer");
            let doc = "peers = []".parse::<DocumentMut>().expect("doc");
            let config = TempConfig::from_doc(&doc);
            update_to_new_peer_list_with_writer(
                HashSet::from([late_peer.clone()]),
                local_address(),
                Arc::new(RwLock::new(HashSet::new())),
                peer_sender,
                Arc::new(Mutex::new(doc)),
                config.path(),
                |_doc, _path| Ok(()),
            )
            .await
            .expect("a refused enqueue is reported, not returned as an error");

            let output = logs.contents();
            assert!(
                refusals(&output).any(|line| line.contains(&late_peer.hostname)),
                "the post-return refusal should name the identity it dropped, got: {output}"
            );
            let addr = late_peer.addr;
            assert!(
                !output.contains(&format!("Peer connection to {addr}"))
                    && !output.contains(&format!("Rejected peer connection to {addr}")),
                "a refused identity must not have been dialed, got: {output}"
            );
            assert!(
                peers.read().await.is_empty(),
                "the connection handler should have removed its peers entry"
            );
        }

        /// A registration attempt that reaches an already closed tracker is
        /// rejected with context and the work is dropped.
        ///
        /// The tracker is closed by the test before the handler ever runs, so
        /// closure is established rather than inferred from cancellation —
        /// closing does not cancel, and the handler keeps serving.
        #[tokio::test]
        async fn a_closed_tracker_refuses_requests_and_sensor_updates() {
            let (logs, _guard) = capture_logs();
            let harness = ServerRoleHarness::start(&["closed-tracker-sensor"], true).await;

            // A sensor-change wake and an inbound stream, both of which would
            // register a task on an open tracker.
            harness.peer_conn_info.notify_sensor.notify_one();
            let (mut send, _recv) = harness
                .client
                .conn
                .open_bi()
                .await
                .expect("open a request stream");
            let code: u32 = PeerCode::UpdateSensorList.into();
            send_bytes(&mut send, &code.to_le_bytes())
                .await
                .expect("send the peer code");

            wait_for_log(&logs, "Rejected peer request from").await;
            wait_for_log(&logs, "Rejected UpdateSensorList to peer").await;

            let output = logs.contents();
            assert!(
                output.contains("tracker is closed; cannot spawn new tasks"),
                "the rejection should name the closed tracker, got: {output}"
            );
            assert_eq!(
                harness.tracker.pending_count(),
                0,
                "refused work must not be spawned outside the tracker"
            );
            // And no update reached the remote.
            assert!(
                tokio::time::timeout(BLOCKED_PROBE, harness.client.conn.accept_bi())
                    .await
                    .is_err(),
                "a refused fan-out must not send anything"
            );

            harness.token.cancel();
            with_timeout("handler shutdown timeout", harness.handle)
                .await
                .expect("handler join")
                .expect("handler result");
        }

        /// A connection handler that returns on cancellation has removed both
        /// of its shared-state entries before it returns.
        #[tokio::test]
        async fn a_cancelled_connection_handler_removes_its_state() {
            let harness = ServerRoleHarness::start(&["cleanup-sensor"], false).await;
            assert!(
                !harness.peer_conn_info.peers.read().await.is_empty(),
                "the init exchange should have recorded the remote's peer info"
            );

            harness.token.cancel();
            with_timeout("handler shutdown timeout", harness.handle)
                .await
                .expect("handler join")
                .expect("handler result");

            assert!(
                harness.peer_conn_info.peer_conns.read().await.is_empty(),
                "the handler should have removed its peer_conns entry"
            );
            assert!(
                harness.peer_conn_info.peers.read().await.is_empty(),
                "the handler should have removed its peers entry"
            );
        }

        /// Every sensor-change wake sends the snapshot as it stands, not a
        /// per-change delta, so a coalesced or dropped notification costs no
        /// sensor state.
        #[tokio::test]
        async fn a_sensor_change_wake_sends_the_whole_snapshot() {
            let harness = ServerRoleHarness::start(&["sensor-a"], false).await;

            harness
                .peer_conn_info
                .ingest_sensors
                .write()
                .await
                .insert("sensor-b".to_string());
            harness.peer_conn_info.notify_sensor.notify_one();
            let first = receive_update(&harness.client).await;
            assert_eq!(
                first,
                HashSet::from(["sensor-a".to_string(), "sensor-b".to_string()])
            );

            harness
                .peer_conn_info
                .ingest_sensors
                .write()
                .await
                .insert("sensor-c".to_string());
            harness.peer_conn_info.notify_sensor.notify_one();
            let second = receive_update(&harness.client).await;
            assert_eq!(
                second,
                HashSet::from([
                    "sensor-a".to_string(),
                    "sensor-b".to_string(),
                    "sensor-c".to_string()
                ]),
                "the second wake must carry the whole snapshot, not just what changed"
            );

            harness.token.cancel();
            with_timeout("handler shutdown timeout", harness.handle)
                .await
                .expect("handler join")
                .expect("handler result");
        }

        /// Reads one sensor-list update the peer opened a stream for.
        async fn receive_update(client: &TestClient) -> HashSet<String> {
            let (_, mut recv) =
                with_timeout("sensor update stream timeout", client.conn.accept_bi())
                    .await
                    .expect("peer did not open a sensor-list update stream");
            let (msg_type, payload) = receive_peer_data(&mut recv)
                .await
                .expect("failed to receive the sensor-list update");
            assert_eq!(msg_type, PeerCode::UpdateSensorList);
            bincode::deserialize::<PeerInfo>(&payload)
                .expect("invalid sensor-list update")
                .ingest_sensors
        }

        /// An outbound dial to an address that never answers returns on
        /// cancellation instead of waiting the dial out.
        #[tokio::test]
        async fn a_dial_to_an_unreachable_address_returns_on_cancellation() {
            init_crypto();
            let (peer_conn_info, _config) = build_peer_conn_info(local_address());
            let token = CancellationToken::new();
            let tracker = TaskTracker::with_token(token.clone());
            // TEST-NET-1: routable nowhere, so the dial waits out quinn's idle
            // timeout, which is far longer than this test's budget.
            let unreachable = peer_identity("192.0.2.1:9999".parse().expect("addr"), "unreachable");
            let mut dial = tokio::spawn(client_connection(
                init_client(),
                init_shared_client_config(),
                unreachable,
                peer_conn_info,
                "local-node".to_string(),
                tracker,
                token.clone(),
            ));

            assert!(
                tokio::time::timeout(BLOCKED_PROBE, &mut dial)
                    .await
                    .is_err(),
                "the dial should still be in flight"
            );
            token.cancel();
            tokio::time::timeout(REFUSED_DIAL_TIMEOUT, dial)
                .await
                .expect("the dial should have been given up on cancellation")
                .expect("dial task join")
                .expect("a cancelled dial is not an error");
        }

        /// A connection parked in its reconnect sleep returns on cancellation
        /// without waiting the interval out.
        #[tokio::test]
        async fn a_reconnect_sleep_returns_on_cancellation() {
            let (logs, _guard) = capture_logs();
            init_crypto();
            let (server_endpoint, server_addr) = setup_server_endpoint();
            let refuser = tokio::spawn(async move {
                let incoming = accept_incoming(&server_endpoint, "refuser accept timeout").await;
                incoming.refuse();
                // Hold the endpoint so the port stays bound for the retry.
                std::future::pending::<()>().await;
            });

            let (peer_conn_info, _config) = build_peer_conn_info(local_address());
            let token = CancellationToken::new();
            let tracker = TaskTracker::with_token(token.clone());
            let reconnect = tokio::spawn(client_connection(
                init_client(),
                init_shared_client_config(),
                peer_identity(server_addr, test_connect_name()),
                peer_conn_info,
                "local-node".to_string(),
                tracker,
                token.clone(),
            ));

            // The retry log is emitted immediately before the sleep, so this
            // is what says the task is parked in it rather than still dialing.
            wait_for_log(&logs, "Retrying connection to").await;
            token.cancel();
            tokio::time::timeout(
                Duration::from_secs(super::super::PEER_RETRY_INTERVAL - 2),
                reconnect,
            )
            .await
            .expect("the reconnect sleep should have been cut short")
            .expect("reconnect task join")
            .expect("a cancelled reconnect is not an error");

            refuser.abort();
        }

        /// A peer task that ends abnormally is named by the tracker's registry
        /// guard, and the drain that follows still completes.
        ///
        /// No production peer path panics on demand, so the panic is raised in
        /// a task registered the way peer registers its own — same tracker
        /// shape, same name form — which is what the guard reports on.
        #[tokio::test]
        async fn a_panicking_peer_task_is_named_by_the_registry_guard() {
            let (logs, _guard) = capture_logs();
            let token = CancellationToken::new();
            let tracker = TaskTracker::with_token(token.clone());
            let handle = tracker
                .spawn("peer-request-127.0.0.1", |_token| async {
                    panic!("peer task panic");
                })
                .expect("register the peer task");
            assert!(handle.await.is_err(), "the task should have panicked");

            with_timeout(
                "peer drain timeout",
                drain_with_report(&tracker, DRAIN_REPORT_INTERVAL, PEER_DRAIN_LABEL),
            )
            .await
            .expect("the drain should complete even after a panic");

            let output = logs.contents();
            assert!(
                output.contains("tracked task did not run to completion"),
                "the registry guard should have reported the panic, got: {output}"
            );
            assert!(
                output.contains("peer-request-127.0.0.1"),
                "the report should name the peer task, got: {output}"
            );
        }

        /// The peer shutdown tail, driven over a tracker the test poisoned
        /// itself.
        ///
        /// The tail is what `run` calls as its last statement, so what holds
        /// here holds for the entry task. A poisoned admission lock used to
        /// return the entry task at its preliminary `close()` — before the
        /// endpoint closes, the connection sweep, `receiver.close()` and the
        /// drain — leaving the connection handlers and fan-outs running while
        /// the generation moved on. Now the close is reported and the tail
        /// carries on through the whole of its teardown.
        #[tokio::test]
        async fn the_peer_tail_waits_and_tears_down_through_a_poisoned_tracker() {
            init_crypto();
            let certs = create_certs();
            let (server_endpoint, server_addr) = setup_server_endpoint_with_certs(&certs);
            let (peer_conn_info, _config) = build_peer_conn_info(server_addr);
            let (_sender, mut receiver) = mpsc::channel::<PeerIdentity>(1);

            let tracker = TaskTracker::with_token(CancellationToken::new());
            let (release_tx, release_rx) = oneshot::channel::<()>();
            let handler_cancelled = Arc::new(AtomicBool::new(false));
            let handler = tracker
                .spawn("peer-server-conn-test", {
                    let handler_cancelled = Arc::clone(&handler_cancelled);
                    move |token| async move {
                        token.cancelled().await;
                        handler_cancelled.store(true, Ordering::SeqCst);
                        let _ = release_rx.await;
                    }
                })
                .expect("a fresh tracker admits the handler");

            // Only now, with the handler registered: the production trigger
            // poisons a tracker before any runtime exists, which is a tracker
            // that can hold nothing.
            tracker.poison_admission_lock();

            let client_endpoint = init_client();
            let tail = tokio::spawn({
                let tracker = tracker.clone();
                async move {
                    let result = shutdown_peer(
                        &tracker,
                        &server_endpoint,
                        &client_endpoint,
                        peer_conn_info,
                        &mut receiver,
                    )
                    .await;
                    (result, server_endpoint, client_endpoint)
                }
            });

            // Cancellation reaching the handler is the proof the tail did not
            // return at its preliminary `close()`: nothing else in this test
            // cancels, and the only `cancel_children` in the process is inside
            // `drain_with_report`.
            wait_until("the tail reaches the drain", || {
                handler_cancelled.load(Ordering::SeqCst)
            })
            .await;
            assert!(
                !tail.is_finished(),
                "the tail must not return while a nested handler is still running"
            );
            assert!(
                tracker.is_closed(),
                "the drain closes the tracker through the poison"
            );

            release_tx.send(()).expect("the handler is still waiting");
            handler.await.expect("the handler should not be aborted");
            let (result, server_endpoint, client_endpoint) = with_timeout("peer tail", tail)
                .await
                .expect("the tail should not panic");

            result.expect_err("a poisoned tracker lock is reported to the entry task");
            assert_eq!(
                tracker.pending_count(),
                0,
                "the tail returns only once its tracker is empty"
            );

            // The pre-drain teardown ran despite the failed close: a closed
            // endpoint hands back no more connections, and dropping it
            // releases the address the next generation has to rebind.
            assert!(
                server_endpoint.accept().await.is_none(),
                "the pre-drain endpoint teardown should have closed the listener"
            );
            drop((server_endpoint, client_endpoint));
            // The endpoint's driver releases the UDP socket once the last
            // handle is gone, which it does on its own schedule, so the
            // rebind is retried until it succeeds rather than attempted once.
            wait_until("the peer address is released", || {
                Endpoint::server(
                    config_server(&certs).expect("peer server config"),
                    server_addr,
                )
                .is_ok()
            })
            .await;
        }

        /// Peer's teardown runs *before* its drain, and has to keep doing so.
        ///
        /// The tracked handler here is parked on `accept_bi`, one of the
        /// awaits no cancellation token reaches: only the endpoint and
        /// connection closes release it. The tail returning at all is the
        /// assertion — move that teardown after the drain and the drain waits
        /// on a task nothing can release, so this hangs rather than fails.
        #[tokio::test]
        async fn the_peer_tail_tears_its_connections_down_before_it_drains() {
            init_crypto();
            let (server_endpoint, server_addr) = setup_server_endpoint();
            let peers = connect_client_server(&server_endpoint, server_addr).await;
            let (mut peer_conn_info, _config) = build_peer_conn_info(server_addr);
            let (sender, mut receiver) = mpsc::channel::<PeerIdentity>(1);
            peer_conn_info.peer_sender = sender.clone();
            peer_conn_info
                .peer_conns
                .write()
                .await
                .insert("parked-peer".to_string(), peers.server_conn.clone());

            let tracker = TaskTracker::with_token(CancellationToken::new());
            let parked_returned = Arc::new(AtomicBool::new(false));
            let parked = tracker
                .spawn("peer-server-conn-parked", {
                    let conn = peers.server_conn.clone();
                    let parked_returned = Arc::clone(&parked_returned);
                    // Deliberately ignores its token, the way a handler parked
                    // on a frame that never arrives does.
                    move |_token| async move {
                        let _ = conn.accept_bi().await;
                        parked_returned.store(true, Ordering::SeqCst);
                    }
                })
                .expect("a fresh tracker admits the parked handler");

            let client_endpoint = init_client();
            with_timeout(
                "the peer tail should drain once its teardown released the parked await",
                shutdown_peer(
                    &tracker,
                    &server_endpoint,
                    &client_endpoint,
                    peer_conn_info,
                    &mut receiver,
                ),
            )
            .await
            .expect("a healthy tracker drains cleanly");

            parked
                .await
                .expect("the parked handler should not be aborted");
            assert!(
                parked_returned.load(Ordering::SeqCst),
                "the parked handler should have been released by the teardown, not aborted"
            );
            assert_eq!(tracker.pending_count(), 0);
            // `receiver.close()` ran ahead of the drain too, so a send that
            // arrives now is refused rather than queued against a receiver
            // nobody polls.
            assert!(
                sender
                    .send(peer_identity(server_addr, "after-shutdown"))
                    .await
                    .is_err(),
                "the peer-identity receive side should have been closed before the drain"
            );
        }

        /// `run_with_ready` reaches the tail unconditionally, which is what
        /// carries the assertions above back to the entry task.
        #[test]
        fn peer_run_ends_in_the_shutdown_tail() {
            let source = include_str!("peer.rs");
            assert!(
                source.contains(
                    "shutdown_peer(\n            &tracker,\n            &server_endpoint,\n            \
                     &client_endpoint,\n            peer_conn_info,\n            &mut receiver,\n        )\n        .await\n    }"
                ),
                "`run_with_ready` should end in one unconditional call to `shutdown_peer`"
            );
        }
    }
}

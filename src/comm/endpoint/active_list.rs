//! The node's active list, the lease on it, the `entry_id` stored, and the
//! endpoint connections the list admitted.
//!
//! REview pushes the list to the node over GraphQL and keeps it alive with a
//! lease; the rules — version checks, standing, lease arithmetic, replacement
//! counting — are senta-protocol's [`ActiveList`]. What is here is the
//! node's side: one list for the whole process, kept across generations, the
//! `entry_id` the database holds, and carrying out what the list asks for on
//! the connections it names.
//!
//! One lock covers the list, the `entry_id` and the registry of admitted
//! connections, and both an update and a connection's admission at its first
//! `hello` take it. So an admission that races an update is either judged
//! against the updated list and the newly stored `entry_id`, or registered
//! before the update and among the connections the update closes.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use jiff::Timestamp;
use senta_protocol::{
    auth::active_list::{
        ActiveList, ApplyError, ConnectionId, ConnectionStanding, DuplicateKey, Lease, ListUpdate,
        Standing, allowed,
    },
    connection::{ConnectionKind, Frame, Hello, Message, StandingVerdict},
};
use tokio::{
    select,
    sync::watch,
    time::{Instant, sleep_until},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::receiver::{EndpointFlows, FlowsGuard};
use crate::storage::{Database, endpoint::DuplicateKeyEvent};

/// What the node answers an update or a confirmation with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ListAck {
    /// Whether the node is ready: a full list applied and an `entry_id`
    /// stored.
    pub(crate) ready: bool,
    /// The version applied, `None` whenever the node is not ready.
    pub(crate) version: Option<u64>,
}

/// The node's list state, as `endpointActiveListState` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ListState {
    /// The `entry_id` stored, if any.
    pub(crate) entry_id: Option<Uuid>,
    /// As [`ListAck::ready`].
    pub(crate) ready: bool,
    /// As [`ListAck::version`].
    pub(crate) version: Option<u64>,
}

/// Why an update was not applied.
#[derive(Debug)]
pub(crate) enum ApplyFailure {
    /// The update is not valid base64, or not a decodable [`ListUpdate`].
    InvalidUpdate(String),
    /// The `entryId` is not a UUID, or is the nil UUID.
    InvalidEntryId(String),
    /// The list refused the update.
    Refused(ApplyError),
    /// The new `entry_id` could not be stored.
    Store(anyhow::Error),
}

/// An update that was not applied, with the version the list is at.
#[derive(Debug)]
pub(crate) struct ApplyRefusal {
    /// Why it was not applied.
    pub(crate) failure: ApplyFailure,
    /// The version applied, `None` before the first full list.
    pub(crate) version: Option<u64>,
}

/// How a connection the node closes is told.
#[derive(Debug, Clone)]
pub(super) enum CloseCommand {
    /// Closed without a word.
    Silent,
    /// The telemetry error frame is sent, then the connection is closed.
    Error(Frame),
}

impl CloseCommand {
    /// Returns how a connection whose standing is now `standing` is closed:
    /// with the telemetry error the standing calls for at `hello`, or
    /// without a word when it calls for none, as for an entry that now
    /// belongs to another endpoint.
    fn for_standing(standing: &Standing) -> Self {
        match allowed(standing, ConnectionKind::Telemetry, Hello::T).to_standing_verdict() {
            StandingVerdict::SendThenClose(frame) => Self::Error(frame),
            StandingVerdict::Accept | StandingVerdict::Unsupported | StandingVerdict::Close => {
                Self::Silent
            }
        }
    }
}

/// How one connection is told to close, and how it reports that it has
/// stopped processing messages.
#[derive(Debug)]
pub(super) struct Closing {
    /// The first close asked for; a later one changes nothing.
    command: Mutex<Option<CloseCommand>>,
    /// Cancelled to stop the connection.
    stop: CancellationToken,
    /// Cancelled once the connection has stopped processing messages.
    stopped: CancellationToken,
}

impl Closing {
    fn new(stop: CancellationToken) -> Self {
        Self {
            command: Mutex::new(None),
            stop,
            stopped: CancellationToken::new(),
        }
    }

    /// Asks the connection to close as `command` says, unless it was already
    /// asked to.
    fn close(&self, command: CloseCommand) {
        let mut slot = self.command.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(command);
        }
        drop(slot);
        self.stop.cancel();
    }

    /// Returns how the connection was asked to close, if it was.
    pub(super) fn command(&self) -> Option<CloseCommand> {
        self.command
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Waits until the connection has stopped processing messages.
    async fn stopped(&self) {
        self.stopped.cancelled().await;
    }
}

/// What the lock covers.
struct Inner {
    list: ActiveList,
    entry_id: Option<Uuid>,
    /// The connections admitted and not yet closed, by the id they are
    /// registered under.
    connections: HashMap<ConnectionId, Arc<Closing>>,
}

impl Inner {
    fn ready(&self) -> bool {
        self.list.is_ready() && self.entry_id.is_some()
    }

    fn ack(&self) -> ListAck {
        let ready = self.ready();
        ListAck {
            ready,
            version: if ready { self.list.version() } else { None },
        }
    }

    /// Forgets `id` and asks it to close as `command` says, adding it to
    /// `closed` when it was open.
    fn close(&mut self, id: ConnectionId, command: CloseCommand, closed: &mut Vec<Arc<Closing>>) {
        self.list.remove(id);
        if let Some(closing) = self.connections.remove(&id) {
            closing.close(command);
            closed.push(closing);
        }
    }

    /// Sends `lease_expired` to every connection an expiry delivered, and
    /// closes it.
    fn expire(&mut self, expired: Option<Vec<ConnectionId>>, closed: &mut Vec<Arc<Closing>>) {
        let Some(expired) = expired else {
            return;
        };
        info!(
            "Endpoint active list: the lease has expired; closing {} connection(s)",
            expired.len()
        );
        let command = CloseCommand::for_standing(&Standing::LeaseExpired);
        for id in expired {
            self.close(id, command.clone(), closed);
        }
    }
}

/// The node's active list, with its lease, the `entry_id` stored and the
/// endpoint connections admitted.
///
/// It is process state: created once, before the first generation, and kept
/// across generation restarts. The list is not persisted, so after a
/// process restart the node is unready until REview sends a full list.
pub(crate) struct EndpointList {
    /// The origin of the monotonic time every call on the list takes.
    origin: Instant,
    inner: Mutex<Inner>,
    /// The lease deadline, watched by the lease timer.
    lease_deadline: watch::Sender<Option<Duration>>,
    next_connection: AtomicU64,
}

impl EndpointList {
    /// Creates an unready list whose lease is `lease_length` long, with no
    /// `entry_id` stored.
    pub(crate) fn new(lease_length: Duration) -> Self {
        let (lease_deadline, _) = watch::channel(None);
        Self {
            origin: Instant::now(),
            inner: Mutex::new(Inner {
                list: ActiveList::new(Some(Lease::new(lease_length))),
                entry_id: None,
                connections: HashMap::new(),
            }),
            lease_deadline,
            next_connection: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns the monotonic time since the list was created.
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    /// Publishes the lease deadline to the lease timer, when it changed.
    fn publish_deadline(&self, inner: &Inner) {
        let deadline = inner.list.lease_deadline();
        self.lease_deadline.send_if_modified(|current| {
            let changed = *current != deadline;
            *current = deadline;
            changed
        });
    }

    /// Reads the `entry_id` stored in `database` into the node's copy, as a
    /// generation opens it.
    ///
    /// A value that cannot be read is logged and taken as none stored: the
    /// node is then unready until REview sends a full list with an
    /// `entryId`.
    pub(crate) fn load_entry_id(&self, database: &Database) {
        let entry_id = database.endpoint_entry_id().unwrap_or_else(|e| {
            error!("Endpoint entry: {e:#}; taking it as no entry_id stored");
            None
        });
        self.lock().entry_id = entry_id;
    }

    /// Returns the node's list state.
    pub(crate) fn state(&self) -> ListState {
        let inner = self.lock();
        let ack = inner.ack();
        ListState {
            entry_id: inner.entry_id,
            ready: ack.ready,
            version: ack.version,
        }
    }

    /// Applies `update`, the standard base64 of a [`ListUpdate`]'s CBOR,
    /// with `entry_id` as the node's `entry_id`. When the `entry_id`
    /// changes, it is stored and the telemetry streams of `flows` move to it.
    ///
    /// The list is changed on a blocking thread holding the `ReceiverStream`
    /// lock of `flows`, taken first, and then the list's, so a batch write in
    /// progress finishes before any connection is closed; both are released
    /// before the call waits. It answers only once every connection it
    /// closes has stopped processing messages.
    ///
    /// # Errors
    ///
    /// Returns the refusal when the update or the `entry_id` is invalid, the
    /// list refuses the update, or the new `entry_id` cannot be stored. None
    /// of them changes the list, its version, the `entry_id` or the
    /// streams, though a lease expiry the call reveals is still delivered.
    pub(crate) async fn apply(
        self: &Arc<Self>,
        update: &str,
        entry_id: &str,
        flows: &Arc<EndpointFlows>,
    ) -> Result<ListAck, ApplyRefusal> {
        let decoded = decode_update(update);
        let parsed = parse_entry_id(entry_id);
        let list = Arc::clone(self);
        let flows = Arc::clone(flows);
        let applied = tokio::task::spawn_blocking(move || {
            let mut flows = flows.lock();
            list.apply_locked(decoded, parsed, &mut flows)
        })
        .await;
        let (result, closed) = match applied {
            Ok(applied) => applied,
            Err(e) => {
                error!("Endpoint active list: the update was not applied: {e}");
                let refusal = ApplyRefusal {
                    failure: ApplyFailure::Store(anyhow::anyhow!(
                        "the update was interrupted: {e}"
                    )),
                    version: self.lock().list.version(),
                };
                return Err(refusal);
            }
        };
        wait_stopped(&closed).await;
        result
    }

    fn apply_locked(
        &self,
        update: Result<ListUpdate, String>,
        entry_id: Result<Uuid, String>,
        flows: &mut FlowsGuard<'_>,
    ) -> (Result<ListAck, ApplyRefusal>, Vec<Arc<Closing>>) {
        let mut closed = Vec::new();
        let mut inner = self.lock();
        let refusal = |failure, inner: &Inner| ApplyRefusal {
            failure,
            version: inner.list.version(),
        };
        let update = match update {
            Ok(update) => update,
            Err(e) => return (Err(refusal(ApplyFailure::InvalidUpdate(e), &inner)), closed),
        };
        let entry_id = match entry_id {
            Ok(entry_id) => entry_id,
            Err(e) => {
                return (
                    Err(refusal(ApplyFailure::InvalidEntryId(e), &inner)),
                    closed,
                );
            }
        };

        let now = self.now();
        let entry_id_changes = inner.entry_id != Some(entry_id);
        // Kept to undo the update should the new `entry_id` not be stored.
        let before = entry_id_changes.then(|| inner.list.clone());
        let outcome = inner.list.apply(update, now);
        let applied = match outcome.result {
            Ok(applied) => applied,
            Err(e) => {
                inner.expire(outcome.expired, &mut closed);
                self.publish_deadline(&inner);
                let refused = refusal(ApplyFailure::Refused(e), &inner);
                return (Err(refused), closed);
            }
        };
        if let Some(before) = before
            && let Err(e) = flows.change_entry_id(entry_id, inner.entry_id)
        {
            error!("Endpoint active list: {e:#}; the update is not applied");
            inner.list = before;
            // The expiry the undone call delivered is delivered again here.
            let expired = inner.list.check_lease(now);
            inner.expire(expired, &mut closed);
            self.publish_deadline(&inner);
            let refused = refusal(ApplyFailure::Store(e), &inner);
            return (Err(refused), closed);
        }

        inner.expire(outcome.expired, &mut closed);
        for change in applied.changes {
            inner.close(
                change.connection,
                CloseCommand::for_standing(&change.standing),
                &mut closed,
            );
        }
        if entry_id_changes {
            info!("Endpoint active list: entry_id is now {entry_id}; closing every connection");
            inner.entry_id = Some(entry_id);
            let open: Vec<ConnectionId> = inner.connections.keys().copied().collect();
            for id in open {
                inner.close(id, CloseCommand::Silent, &mut closed);
            }
        }
        info!(
            "Endpoint active list: version {} applied, {} connection(s) closed",
            applied.version,
            closed.len()
        );
        self.publish_deadline(&inner);
        (Ok(inner.ack()), closed)
    }

    /// Takes REview's confirmation of `version`, which extends the lease
    /// when it is the version applied.
    ///
    /// It answers only once every connection a lease expiry it reveals
    /// closes has stopped processing messages.
    pub(crate) async fn confirm(&self, version: u64) -> ListAck {
        let mut closed = Vec::new();
        let ack = {
            let mut inner = self.lock();
            let now = self.now();
            let outcome = inner.list.confirm(version, now);
            inner.expire(outcome.expired, &mut closed);
            if !outcome.extended {
                debug!(
                    "Endpoint active list: confirmation of version {version} did not extend the \
                     lease; the list is at {:?}",
                    inner.list.version()
                );
            }
            self.publish_deadline(&inner);
            inner.ack()
        };
        wait_stopped(&closed).await;
        ack
    }

    /// Delivers a lease expiry, if the lease has expired and the expiry has
    /// not been delivered yet.
    fn check_lease(&self) {
        let mut closed = Vec::new();
        let mut inner = self.lock();
        let now = self.now();
        let expired = inner.list.check_lease(now);
        inner.expire(expired, &mut closed);
        self.publish_deadline(&inner);
    }

    /// Runs the lease timer until `token` is cancelled: at the lease
    /// deadline it delivers the expiry, so that it comes to light without
    /// any other call, and it moves to the new deadline whenever the lease
    /// is extended.
    pub(super) async fn run_lease_timer(self: Arc<Self>, token: CancellationToken) {
        let mut deadlines = self.lease_deadline.subscribe();
        // The deadline whose expiry was delivered: the timer does not fire
        // for it again.
        let mut fired = None;
        loop {
            let deadline = *deadlines.borrow_and_update();
            let armed = deadline
                .filter(|deadline| fired != Some(*deadline))
                .and_then(|deadline| Some((deadline, self.origin.checked_add(deadline)?)));
            let wake = armed.map_or_else(Instant::now, |(_, at)| at);
            select! {
                () = token.cancelled() => return,
                changed = deadlines.changed() => {
                    // The sender lives as long as `self`.
                    if changed.is_err() {
                        return;
                    }
                }
                () = sleep_until(wake), if armed.is_some() => {
                    fired = armed.map(|(deadline, _)| deadline);
                    self.check_lease();
                }
            }
        }
    }

    /// Starts a connection whose TLS handshake has completed, from the key
    /// whose SPKI hash is `spki_sha256` at `address`.
    ///
    /// Its `hello_ack` carries the `entry_id` stored now, or the nil UUID
    /// while none is. It is stopped through `stop`, which the connection
    /// serves under.
    pub(super) fn open_connection(
        self: &Arc<Self>,
        spki_sha256: [u8; 32],
        address: IpAddr,
        stop: CancellationToken,
    ) -> PendingConnection {
        let id = ConnectionId(self.next_connection.fetch_add(1, Ordering::Relaxed));
        let entry_id = self.lock().entry_id;
        PendingConnection {
            list: Arc::clone(self),
            id,
            spki_sha256,
            address,
            entry_id,
            closing: Arc::new(Closing::new(stop)),
        }
    }
}

/// A connection the list has not yet judged.
pub(super) struct PendingConnection {
    list: Arc<EndpointList>,
    id: ConnectionId,
    spki_sha256: [u8; 32],
    address: IpAddr,
    /// The `entry_id` stored when the connection was built.
    entry_id: Option<Uuid>,
    closing: Arc<Closing>,
}

/// What became of a connection's first `hello`.
pub(super) struct Admission {
    /// The standing check's verdict on the `hello`.
    pub(super) verdict: StandingVerdict,
    /// The duplicate key its registration revealed, with the wall-clock time
    /// it was revealed at.
    pub(super) duplicate_key: Option<(Timestamp, DuplicateKey)>,
    /// The endpoint id of the list entry an admitted connection's key
    /// matched: the source of everything it sends. It is present exactly
    /// when `verdict` admits the connection.
    pub(super) endpoint_id: Option<Uuid>,
}

impl PendingConnection {
    /// Returns the `entry_id` the connection's `hello_ack` carries: the one
    /// stored when the connection was built, or the nil UUID.
    pub(super) fn hello_ack_entry_id(&self) -> Uuid {
        self.entry_id.unwrap_or_else(Uuid::nil)
    }

    /// Returns the guard that removes the connection from the list when it
    /// ends.
    pub(super) fn registration(&self) -> Registration {
        Registration {
            list: Arc::clone(&self.list),
            id: self.id,
            closing: Arc::clone(&self.closing),
        }
    }

    /// Judges the connection at its first `hello`.
    ///
    /// Unless the node is ready and the `entry_id` stored is still the one
    /// the connection was built with, it is closed without a word. Otherwise
    /// it is registered, which may replace the connection open with the same
    /// key and reveal a lease expiry, and judged by its standing: an active
    /// one is admitted and stays registered until it ends, and any other
    /// gets its standing's telemetry error.
    pub(super) fn admit(&self) -> Admission {
        let mut closed = Vec::new();
        let mut inner = self.list.lock();
        if !inner.list.is_ready() {
            debug!("Endpoint connection from {}: unready", self.address);
            return Admission {
                verdict: StandingVerdict::Close,
                duplicate_key: None,
                endpoint_id: None,
            };
        }
        if inner.entry_id.is_none() || inner.entry_id != self.entry_id {
            debug!(
                "Endpoint connection from {}: its hello_ack would carry entry_id {:?}, \
                 and the node's is {:?}",
                self.address, self.entry_id, inner.entry_id
            );
            return Admission {
                verdict: StandingVerdict::Close,
                duplicate_key: None,
                endpoint_id: None,
            };
        }
        let now = self.list.now();
        let outcome = inner
            .list
            .register(self.id, &self.spki_sha256, self.address, now);
        let duplicate_key = outcome.duplicate_key.map(|key| (Timestamp::now(), key));
        inner.expire(outcome.expired, &mut closed);
        if let Some(replaced) = outcome.replaced {
            debug!(
                "Endpoint connection from {} replaces another with the same key",
                self.address
            );
            inner.close(replaced, CloseCommand::Silent, &mut closed);
        }
        let ConnectionStanding { standing, identity } = inner.list.standing(&self.spki_sha256, now);
        // Only an active standing matched to a list entry is admitted: the
        // entry's endpoint id is the source of everything the connection
        // sends, and an active standing always comes from one.
        let endpoint_id = identity
            .filter(|_| standing == Standing::Active)
            .map(|identity| identity.endpoint_id);
        let verdict =
            match allowed(&standing, ConnectionKind::Telemetry, Hello::T).to_standing_verdict() {
                StandingVerdict::Accept if endpoint_id.is_none() => StandingVerdict::Close,
                verdict => verdict,
            };
        let endpoint_id = endpoint_id.filter(|_| verdict == StandingVerdict::Accept);
        if endpoint_id.is_some() {
            inner.connections.insert(self.id, Arc::clone(&self.closing));
        } else {
            debug!(
                "Endpoint connection from {}: standing {standing:?}",
                self.address
            );
            inner.list.remove(self.id);
        }
        Admission {
            verdict,
            duplicate_key,
            endpoint_id,
        }
    }
}

/// Removes a connection from the list when it ends, whichever way it ends,
/// and reports that it has stopped processing messages.
pub(super) struct Registration {
    list: Arc<EndpointList>,
    id: ConnectionId,
    closing: Arc<Closing>,
}

impl Registration {
    /// Returns how the connection was asked to close, if it was.
    pub(super) fn command(&self) -> Option<CloseCommand> {
        self.closing.command()
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        {
            let mut inner = self.list.lock();
            inner.list.remove(self.id);
            inner.connections.remove(&self.id);
        }
        self.closing.stopped.cancel();
    }
}

/// Stores `duplicate_key`, revealed at `at`, in `database`'s endpoint
/// events.
///
/// One whose key matches no entry of the list is logged and not stored: a
/// connection admitted as active always matches one.
pub(super) fn store_duplicate_key(database: &Database, at: Timestamp, duplicate_key: DuplicateKey) {
    let DuplicateKey {
        spki_sha256,
        endpoint_id,
        addresses,
        replacements,
    } = duplicate_key;
    warn!(
        "Endpoint {endpoint_id:?}: its key's connections replaced each other {replacements} \
         times from {addresses:?}"
    );
    let Some(endpoint_id) = endpoint_id else {
        warn!("Endpoint duplicate key matches no entry of the list; not stored");
        return;
    };
    let Ok(received_ns) = i64::try_from(at.as_nanosecond()) else {
        error!("Endpoint duplicate key: the time {at} does not fit the event key; not stored");
        return;
    };
    let event = DuplicateKeyEvent {
        spki_sha256,
        addresses,
        replacements: u64::try_from(replacements).unwrap_or(u64::MAX),
    };
    if let Err(e) = database.append_endpoint_duplicate_key(received_ns, endpoint_id, &event) {
        error!("Endpoint duplicate key of {endpoint_id}: {e:#}");
    }
}

/// Waits until every connection in `closed` has stopped processing
/// messages.
async fn wait_stopped(closed: &[Arc<Closing>]) {
    for closing in closed {
        closing.stopped().await;
    }
}

/// Decodes the standard base64, with padding, of a [`ListUpdate`]'s CBOR.
fn decode_update(update: &str) -> Result<ListUpdate, String> {
    let bytes = BASE64
        .decode(update)
        .map_err(|e| format!("the update is not valid base64: {e}"))?;
    ListUpdate::decode(&bytes).map_err(|e| format!("the update does not decode: {e}"))
}

/// Parses an `entryId`, which must be a UUID other than the nil UUID.
fn parse_entry_id(entry_id: &str) -> Result<Uuid, String> {
    let parsed =
        Uuid::parse_str(entry_id).map_err(|e| format!("the entryId is not a UUID: {e}"))?;
    if parsed.is_nil() {
        return Err("the entryId is the nil UUID".to_owned());
    }
    Ok(parsed)
}

#[cfg(test)]
impl EndpointList {
    /// Returns how many connections are registered with the list, and how
    /// many the node holds as admitted; the two always agree outside the
    /// lock.
    pub(super) fn registered(&self) -> (usize, usize) {
        let inner = self.lock();
        (inner.list.connections().count(), inner.connections.len())
    }

    /// Returns how many connections have been built since the list was
    /// created.
    pub(super) fn connections_opened(&self) -> u64 {
        self.next_connection.load(Ordering::Relaxed)
    }

    /// Returns the lease deadline, as the lease timer sees it.
    pub(crate) fn lease_deadline(&self) -> Option<Duration> {
        *self.lease_deadline.borrow()
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::{net::Ipv4Addr, sync::Barrier};

    use senta_protocol::{
        auth::active_list::{
            DUPLICATE_KEY_THRESHOLD, EntryState, LicenseRestriction, ListEntry, OperatorStatus,
        },
        connection::{Envelope, FrameDecoder, SERVER_ACTIVE_RECEIVE_LIMIT},
        standing::SuspendReason,
        telemetry::ErrorMessage,
        telemetry_codes::TelemetryError,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::storage::{
        DbOptions,
        endpoint::{ENDPOINT_EVENTS_CF, endpoint_event_key},
    };

    pub(in crate::comm::endpoint) const ENTRY_ID: Uuid =
        Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
    const OTHER_ENTRY_ID: Uuid = Uuid::from_u128(0xfeed);
    const LEASE: Duration = Duration::from_secs(60);
    const WAIT: Duration = Duration::from_secs(10);

    /// How a connection was told to close.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(in crate::comm::endpoint) enum Told {
        Silent,
        Error(TelemetryError),
    }

    /// Returns the telemetry error `frame` carries.
    pub(in crate::comm::endpoint) fn error_of(frame: &[u8]) -> TelemetryError {
        let mut decoder = FrameDecoder::new(SERVER_ACTIVE_RECEIVE_LIMIT);
        decoder.push(frame);
        let payload = decoder
            .next_frame()
            .expect("a frame within the limit")
            .expect("a whole frame");
        let envelope = Envelope::parse(&payload).expect("an envelope");
        assert_eq!(envelope.t(), ErrorMessage::T);
        let message: ErrorMessage = envelope.body().decode().expect("an error message");
        assert_eq!(message.stream, None);
        message.error
    }

    fn told(command: Option<CloseCommand>) -> Option<Told> {
        command.map(|command| match command {
            CloseCommand::Silent => Told::Silent,
            CloseCommand::Error(frame) => Told::Error(error_of(frame.as_bytes())),
        })
    }

    fn verdict_error(verdict: &StandingVerdict) -> Option<TelemetryError> {
        match verdict {
            StandingVerdict::SendThenClose(frame) => Some(error_of(frame.as_bytes())),
            _ => None,
        }
    }

    pub(in crate::comm::endpoint) fn spki(n: u8) -> [u8; 32] {
        [n; 32]
    }

    pub(in crate::comm::endpoint) fn entry(
        id: u128,
        spki: [u8; 32],
        state: EntryState,
    ) -> ListEntry {
        ListEntry {
            endpoint_id: Uuid::from_u128(id),
            spki_sha256: spki,
            customer_endpoint_id: Uuid::from_u128(id + 1_000),
            state,
        }
    }

    pub(in crate::comm::endpoint) fn suspended() -> EntryState {
        EntryState::combine(OperatorStatus::Suspended, LicenseRestriction::None)
    }

    pub(in crate::comm::endpoint) fn encode(update: &ListUpdate) -> String {
        BASE64.encode(update.encode().expect("encode the update"))
    }

    pub(in crate::comm::endpoint) fn full(version: u64, entries: Vec<ListEntry>) -> ListUpdate {
        ListUpdate::Full { version, entries }
    }

    pub(in crate::comm::endpoint) fn diff(
        base_version: u64,
        version: u64,
        upserts: Vec<ListEntry>,
        removals: Vec<u128>,
    ) -> ListUpdate {
        ListUpdate::Diff {
            base_version,
            version,
            upserts,
            removals: removals.into_iter().map(Uuid::from_u128).collect(),
        }
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    struct Fixture {
        list: Arc<EndpointList>,
        db: Database,
        flows: Arc<EndpointFlows>,
        _dir: TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let db = Database::open(dir.path(), &DbOptions::default()).expect("open the database");
            let list = Arc::new(EndpointList::new(LEASE));
            list.load_entry_id(&db);
            let flows = Arc::new(EndpointFlows::new(db.clone()));
            Self {
                list,
                db,
                flows,
                _dir: dir,
            }
        }

        async fn apply(
            &self,
            update: &ListUpdate,
            entry_id: Uuid,
        ) -> Result<ListAck, ApplyRefusal> {
            self.list
                .apply(&encode(update), &entry_id.to_string(), &self.flows)
                .await
        }

        /// A connection whose TLS handshake has just completed.
        fn connect(&self, spki: [u8; 32], address: IpAddr) -> Conn {
            let stop = CancellationToken::new();
            let pending = self.list.open_connection(spki, address, stop.clone());
            let registration = pending.registration();
            Conn {
                pending,
                registration: Some(registration),
                stop,
            }
        }

        /// A connection whose `hello` the list admitted, served by a task
        /// that waits until it is told to close.
        fn admitted(&self, spki: [u8; 32], address: IpAddr) -> Served {
            let mut conn = self.connect(spki, address);
            assert_eq!(conn.hello(), StandingVerdict::Accept);
            conn.serve()
        }

        fn state(&self) -> ListState {
            self.list.state()
        }
    }

    struct Conn {
        pending: PendingConnection,
        registration: Option<Registration>,
        stop: CancellationToken,
    }

    impl Conn {
        fn hello(&mut self) -> StandingVerdict {
            self.pending.admit().verdict
        }

        /// Serves the connection until it is told to close; the task ends as
        /// the connection's would, dropping its registration.
        fn serve(mut self) -> Served {
            let registration = self.registration.take().expect("not yet served");
            let stop = self.stop.clone();
            let handle = tokio::spawn(async move {
                stop.cancelled().await;
                let command = registration.command();
                drop(registration);
                told(command)
            });
            Served {
                stop: self.stop,
                handle,
            }
        }
    }

    struct Served {
        stop: CancellationToken,
        handle: tokio::task::JoinHandle<Option<Told>>,
    }

    impl Served {
        fn is_told(&self) -> bool {
            self.stop.is_cancelled()
        }

        async fn told(self) -> Told {
            tokio::time::timeout(WAIT, self.handle)
                .await
                .expect("the connection is told to close")
                .expect("the connection task joins")
                .expect("the connection was told how to close")
        }
    }

    #[tokio::test]
    async fn an_unready_node_closes_a_hello_without_registering() {
        let fixture = Fixture::new();
        let mut conn = fixture.connect(spki(1), ip(1));
        assert_eq!(conn.hello(), StandingVerdict::Close);
        assert_eq!(fixture.list.registered(), (0, 0));
        assert_eq!(
            fixture.state(),
            ListState {
                entry_id: None,
                ready: false,
                version: None
            }
        );
    }

    #[tokio::test]
    async fn each_standing_is_judged_at_hello() {
        let fixture = Fixture::new();
        let ack = fixture
            .apply(
                &full(
                    3,
                    vec![
                        entry(1, spki(1), EntryState::Active),
                        entry(2, spki(2), EntryState::LicensePending),
                        entry(
                            3,
                            spki(3),
                            EntryState::Suspended {
                                reason: SuspendReason::License,
                            },
                        ),
                    ],
                ),
                ENTRY_ID,
            )
            .await
            .expect("a full list applies");
        assert_eq!(
            ack,
            ListAck {
                ready: true,
                version: Some(3)
            }
        );

        let mut active = fixture.connect(spki(1), ip(1));
        assert_eq!(active.pending.hello_ack_entry_id(), ENTRY_ID);
        assert_eq!(active.hello(), StandingVerdict::Accept);
        assert_eq!(fixture.list.registered(), (1, 1));
        for (key, error) in [
            (spki(2), TelemetryError::NotListed),
            (spki(4), TelemetryError::NotListed),
            (spki(3), TelemetryError::Suspended),
        ] {
            let mut refused = fixture.connect(key, ip(2));
            assert_eq!(verdict_error(&refused.hello()), Some(error));
        }
        assert_eq!(
            fixture.list.registered(),
            (1, 1),
            "a refused connection is not left registered"
        );

        // Later messages of an admitted connection are not judged again: the
        // standing check of a `ServerConfig` takes them as active.
        drop(active);
        assert_eq!(fixture.list.registered(), (0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn an_expired_lease_refuses_every_standing() {
        let fixture = Fixture::new();
        fixture
            .apply(
                &full(1, vec![entry(1, spki(1), EntryState::Active)]),
                ENTRY_ID,
            )
            .await
            .expect("a full list applies");
        tokio::time::advance(LEASE).await;
        for key in [spki(1), spki(2)] {
            let mut conn = fixture.connect(key, ip(1));
            assert_eq!(
                verdict_error(&conn.hello()),
                Some(TelemetryError::LeaseExpired)
            );
        }
    }

    #[tokio::test]
    async fn the_entry_id_a_connection_was_built_with_must_still_be_stored() {
        let fixture = Fixture::new();
        let entries = vec![entry(1, spki(1), EntryState::Active)];

        // Built before any `entry_id` was stored: its `hello_ack` would carry
        // the nil UUID.
        let mut early = fixture.connect(spki(1), ip(1));
        assert_eq!(early.pending.hello_ack_entry_id(), Uuid::nil());
        fixture
            .apply(&full(1, entries.clone()), ENTRY_ID)
            .await
            .expect("a full list applies");
        assert_eq!(early.hello(), StandingVerdict::Close);

        // Built before the `entry_id` changed.
        let mut before_change = fixture.connect(spki(1), ip(1));
        assert_eq!(before_change.pending.hello_ack_entry_id(), ENTRY_ID);
        fixture
            .apply(&full(2, entries), OTHER_ENTRY_ID)
            .await
            .expect("a full list applies");
        assert_eq!(before_change.hello(), StandingVerdict::Close);

        // Reconnecting gets the current one.
        let mut again = fixture.connect(spki(1), ip(1));
        assert_eq!(again.pending.hello_ack_entry_id(), OTHER_ENTRY_ID);
        assert_eq!(again.hello(), StandingVerdict::Accept);
    }

    #[tokio::test]
    async fn a_list_change_closes_the_connections_it_changes() {
        let fixture = Fixture::new();
        fixture
            .apply(
                &full(
                    1,
                    vec![
                        entry(1, spki(1), EntryState::Active),
                        entry(2, spki(2), EntryState::Active),
                        entry(3, spki(3), EntryState::Active),
                        entry(4, spki(4), EntryState::Active),
                    ],
                ),
                ENTRY_ID,
            )
            .await
            .expect("a full list applies");
        let suspended_conn = fixture.admitted(spki(1), ip(1));
        let removed_conn = fixture.admitted(spki(2), ip(2));
        let reassigned_conn = fixture.admitted(spki(3), ip(3));
        let untouched = fixture.admitted(spki(4), ip(4));

        let ack = fixture
            .apply(
                &diff(
                    1,
                    2,
                    vec![
                        entry(1, spki(1), suspended()),
                        // Endpoint 3's key is now endpoint 5's.
                        entry(5, spki(3), EntryState::Active),
                    ],
                    vec![2, 3],
                ),
                ENTRY_ID,
            )
            .await
            .expect("the diff applies");
        assert_eq!(
            ack,
            ListAck {
                ready: true,
                version: Some(2)
            }
        );
        // The mutation answered after the closed connections stopped.
        assert!(suspended_conn.handle.is_finished());
        assert!(removed_conn.handle.is_finished());
        assert!(reassigned_conn.handle.is_finished());
        assert_eq!(
            suspended_conn.told().await,
            Told::Error(TelemetryError::Suspended)
        );
        assert_eq!(
            removed_conn.told().await,
            Told::Error(TelemetryError::NotListed)
        );
        assert_eq!(reassigned_conn.told().await, Told::Silent);
        assert!(!untouched.is_told(), "a connection the diff leaves is kept");
        assert_eq!(fixture.list.registered(), (1, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn the_mutation_answers_only_after_the_closed_connections_stop() {
        let fixture = Fixture::new();
        fixture
            .apply(
                &full(1, vec![entry(1, spki(1), EntryState::Active)]),
                ENTRY_ID,
            )
            .await
            .expect("a full list applies");
        let mut conn = fixture.connect(spki(1), ip(1));
        assert_eq!(conn.hello(), StandingVerdict::Accept);

        let update = encode(&diff(1, 2, Vec::new(), vec![1]));
        let entry_id = ENTRY_ID.to_string();
        let mut apply = std::pin::pin!(fixture.list.apply(&update, &entry_id, &fixture.flows));
        assert!(
            tokio::time::timeout(Duration::from_secs(60), &mut apply)
                .await
                .is_err(),
            "the mutation waits while the closed connection is still processing"
        );
        assert!(conn.stop.is_cancelled(), "the connection was told to stop");
        assert_eq!(
            told(conn.registration.as_ref().and_then(Registration::command)),
            Some(Told::Error(TelemetryError::NotListed))
        );
        conn.registration = None;
        let ack = apply.await.expect("the diff applies");
        assert_eq!(ack.version, Some(2));
    }

    #[tokio::test]
    async fn refused_updates_change_nothing() {
        let fixture = Fixture::new();
        let mismatch = diff(4, 5, Vec::new(), Vec::new());
        let refusal = fixture
            .apply(&mismatch, ENTRY_ID)
            .await
            .expect_err("a diff before any full list is refused");
        assert!(matches!(
            refusal.failure,
            ApplyFailure::Refused(ApplyError::VersionMismatch { .. })
        ));
        assert_eq!(refusal.version, None);
        assert_eq!(fixture.state().entry_id, None, "no entry_id is stored");
        assert_eq!(fixture.db.endpoint_entry_id().unwrap(), None);

        fixture
            .apply(
                &full(7, vec![entry(1, spki(1), EntryState::Active)]),
                ENTRY_ID,
            )
            .await
            .expect("a full list applies");
        let expected = ListState {
            entry_id: Some(ENTRY_ID),
            ready: true,
            version: Some(7),
        };
        let refusal = fixture
            .apply(&mismatch, OTHER_ENTRY_ID)
            .await
            .expect_err("a diff from another version is refused");
        assert!(matches!(
            refusal.failure,
            ApplyFailure::Refused(ApplyError::VersionMismatch { .. })
        ));
        assert_eq!(refusal.version, Some(7));
        assert_eq!(fixture.state(), expected);
        assert_eq!(fixture.db.endpoint_entry_id().unwrap(), Some(ENTRY_ID));

        let entry_id = OTHER_ENTRY_ID.to_string();
        let valid = encode(&full(8, Vec::new()));
        for (update, entry_id, invalid_update) in [
            ("not base64!", entry_id.as_str(), true),
            ("AAAA", entry_id.as_str(), true),
            (valid.as_str(), "not-a-uuid", false),
            (
                valid.as_str(),
                "00000000-0000-0000-0000-000000000000",
                false,
            ),
        ] {
            let refusal = fixture
                .list
                .apply(update, entry_id, &fixture.flows)
                .await
                .expect_err("an invalid argument is refused");
            if invalid_update {
                assert!(
                    matches!(refusal.failure, ApplyFailure::InvalidUpdate(_)),
                    "{update}: {refusal:?}"
                );
            } else {
                assert!(
                    matches!(refusal.failure, ApplyFailure::InvalidEntryId(_)),
                    "{entry_id}: {refusal:?}"
                );
            }
            assert_eq!(refusal.version, Some(7));
            assert_eq!(fixture.state(), expected);
            assert_eq!(fixture.db.endpoint_entry_id().unwrap(), Some(ENTRY_ID));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_confirmation_of_the_version_applied_extends_the_lease() {
        let fixture = Fixture::new();
        let unready = fixture.list.confirm(1).await;
        assert_eq!(
            unready,
            ListAck {
                ready: false,
                version: None
            }
        );
        fixture
            .apply(
                &full(1, vec![entry(1, spki(1), EntryState::Active)]),
                ENTRY_ID,
            )
            .await
            .expect("a full list applies");
        let started = fixture.list.lease_deadline().expect("the lease started");

        tokio::time::advance(LEASE / 2).await;
        assert_eq!(
            fixture.list.confirm(2).await,
            ListAck {
                ready: true,
                version: Some(1)
            }
        );
        assert_eq!(
            fixture.list.lease_deadline(),
            Some(started),
            "another version does not extend the lease"
        );
        assert_eq!(
            fixture.list.confirm(1).await,
            ListAck {
                ready: true,
                version: Some(1)
            }
        );
        let extended = fixture.list.lease_deadline().expect("the lease runs");
        assert_eq!(extended, started + LEASE / 2);

        // Past the first deadline, the extended lease still admits.
        tokio::time::advance(LEASE / 2 + Duration::from_secs(1)).await;
        let mut conn = fixture.connect(spki(1), ip(1));
        assert_eq!(conn.hello(), StandingVerdict::Accept);
    }

    #[tokio::test(start_paused = true)]
    async fn the_lease_timer_alone_delivers_an_expiry() {
        let fixture = Fixture::new();
        let token = CancellationToken::new();
        let timer = tokio::spawn(Arc::clone(&fixture.list).run_lease_timer(token.clone()));
        fixture
            .apply(
                &full(
                    1,
                    vec![
                        entry(1, spki(1), EntryState::Active),
                        entry(2, spki(2), EntryState::Active),
                    ],
                ),
                ENTRY_ID,
            )
            .await
            .expect("a full list applies");
        let first = fixture.admitted(spki(1), ip(1));

        // A confirmation moves the timer to the new deadline.
        tokio::time::advance(LEASE / 2).await;
        assert!(fixture.list.confirm(1).await.ready);
        tokio::time::advance(LEASE / 2 + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(!first.is_told(), "the lease was extended");
        let second = fixture.admitted(spki(2), ip(2));

        tokio::time::sleep(LEASE).await;
        assert_eq!(
            first.told().await,
            Told::Error(TelemetryError::LeaseExpired)
        );
        assert_eq!(
            second.told().await,
            Told::Error(TelemetryError::LeaseExpired)
        );
        assert_eq!(fixture.list.registered(), (0, 0));
        token.cancel();
        timer.await.expect("the timer joins");
    }

    /// Without the timer, the first call after the lease lapsed delivers the
    /// expiry to the connections open then, whichever call it is.
    #[tokio::test(start_paused = true)]
    async fn the_first_call_after_expiry_delivers_it() {
        #[derive(Debug, Clone, Copy)]
        enum Call {
            Confirm,
            Applied,
            Refused,
            Register,
        }

        for call in [Call::Confirm, Call::Applied, Call::Refused, Call::Register] {
            let fixture = Fixture::new();
            fixture
                .apply(
                    &full(
                        1,
                        vec![
                            entry(1, spki(1), EntryState::Active),
                            entry(2, spki(2), EntryState::Active),
                        ],
                    ),
                    ENTRY_ID,
                )
                .await
                .expect("a full list applies");
            let open = fixture.admitted(spki(1), ip(1));
            tokio::time::advance(LEASE).await;
            assert!(!open.is_told(), "{call:?}: nothing has revealed the expiry");

            match call {
                Call::Confirm => {
                    fixture.list.confirm(1).await;
                }
                Call::Applied => {
                    let ack = fixture
                        .apply(
                            &full(2, vec![entry(1, spki(1), EntryState::Active)]),
                            ENTRY_ID,
                        )
                        .await
                        .expect("the full list applies");
                    assert_eq!(ack.version, Some(2));
                }
                Call::Refused => {
                    let refusal = fixture
                        .apply(&diff(5, 6, Vec::new(), Vec::new()), OTHER_ENTRY_ID)
                        .await
                        .expect_err("the diff is refused");
                    assert!(matches!(
                        refusal.failure,
                        ApplyFailure::Refused(ApplyError::VersionMismatch { .. })
                    ));
                    assert_eq!(
                        fixture.state(),
                        ListState {
                            entry_id: Some(ENTRY_ID),
                            ready: true,
                            version: Some(1),
                        },
                        "the refusal changed nothing"
                    );
                    assert_eq!(fixture.db.endpoint_entry_id().unwrap(), Some(ENTRY_ID));
                }
                Call::Register => {
                    let mut late = fixture.connect(spki(2), ip(2));
                    assert_eq!(
                        verdict_error(&late.hello()),
                        Some(TelemetryError::LeaseExpired)
                    );
                }
            }
            assert_eq!(
                open.told().await,
                Told::Error(TelemetryError::LeaseExpired),
                "{call:?}"
            );
            assert_eq!(fixture.list.registered(), (0, 0), "{call:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_entry_id_that_also_reveals_an_expiry_closes_with_lease_expired() {
        let fixture = Fixture::new();
        let entries = vec![
            entry(1, spki(1), EntryState::Active),
            entry(2, spki(2), EntryState::Active),
        ];
        fixture
            .apply(&full(1, entries.clone()), ENTRY_ID)
            .await
            .expect("a full list applies");
        let first = fixture.admitted(spki(1), ip(1));
        let second = fixture.admitted(spki(2), ip(2));
        tokio::time::advance(LEASE).await;

        fixture
            .apply(&full(2, entries), OTHER_ENTRY_ID)
            .await
            .expect("the full list applies");
        assert_eq!(
            first.told().await,
            Told::Error(TelemetryError::LeaseExpired)
        );
        assert_eq!(
            second.told().await,
            Told::Error(TelemetryError::LeaseExpired)
        );
        assert_eq!(fixture.state().entry_id, Some(OTHER_ENTRY_ID));
    }

    #[tokio::test]
    async fn a_new_entry_id_closes_every_connection() {
        let fixture = Fixture::new();
        fixture
            .apply(
                &full(
                    1,
                    vec![
                        entry(1, spki(1), EntryState::Active),
                        entry(2, spki(2), EntryState::Active),
                        entry(3, spki(3), EntryState::Active),
                        entry(4, spki(4), EntryState::Active),
                    ],
                ),
                ENTRY_ID,
            )
            .await
            .expect("a full list applies");
        let suspended_conn = fixture.admitted(spki(1), ip(1));
        let removed_conn = fixture.admitted(spki(2), ip(2));
        let others = [
            fixture.admitted(spki(3), ip(3)),
            fixture.admitted(spki(4), ip(4)),
        ];

        let ack = fixture
            .apply(
                &diff(1, 2, vec![entry(1, spki(1), suspended())], vec![2]),
                OTHER_ENTRY_ID,
            )
            .await
            .expect("the diff applies");
        assert_eq!(
            ack,
            ListAck {
                ready: true,
                version: Some(2)
            }
        );
        assert_eq!(
            suspended_conn.told().await,
            Told::Error(TelemetryError::Suspended)
        );
        assert_eq!(
            removed_conn.told().await,
            Told::Error(TelemetryError::NotListed)
        );
        for other in others {
            assert_eq!(other.told().await, Told::Silent);
        }
        assert_eq!(fixture.state().entry_id, Some(OTHER_ENTRY_ID));
        assert_eq!(
            fixture.db.endpoint_entry_id().unwrap(),
            Some(OTHER_ENTRY_ID)
        );

        let mut reconnect = fixture.connect(spki(3), ip(3));
        assert_eq!(reconnect.pending.hello_ack_entry_id(), OTHER_ENTRY_ID);
        assert_eq!(reconnect.hello(), StandingVerdict::Accept);
    }

    #[tokio::test]
    async fn an_entry_id_that_cannot_be_stored_leaves_everything_as_it_was() {
        let fixture = Fixture::new();
        fixture
            .apply(
                &full(1, vec![entry(1, spki(1), EntryState::Active)]),
                ENTRY_ID,
            )
            .await
            .expect("a full list applies");
        fixture.flows.controls().fail_writes(true);
        let refusal = fixture
            .apply(&full(2, Vec::new()), OTHER_ENTRY_ID)
            .await
            .expect_err("the entry_id cannot be stored");
        assert!(matches!(refusal.failure, ApplyFailure::Store(_)));
        assert_eq!(refusal.version, Some(1));
        assert_eq!(
            fixture.list.state(),
            ListState {
                entry_id: Some(ENTRY_ID),
                ready: true,
                version: Some(1),
            }
        );
        assert_eq!(fixture.db.endpoint_entry_id().unwrap(), Some(ENTRY_ID));
        assert_eq!(fixture.flows.entry_id(), Some(ENTRY_ID));
    }

    #[tokio::test]
    async fn an_update_whose_call_panics_is_refused_and_changes_nothing() {
        let fixture = Fixture::new();
        fixture
            .apply(
                &full(1, vec![entry(1, spki(1), EntryState::Active)]),
                ENTRY_ID,
            )
            .await
            .expect("a full list applies");
        fixture.flows.controls().panic_next_lock();
        let refusal = fixture
            .apply(&full(2, Vec::new()), OTHER_ENTRY_ID)
            .await
            .expect_err("the call panicked");
        assert!(
            matches!(&refusal.failure, ApplyFailure::Store(e) if e.to_string().contains("interrupted")),
            "{:?}",
            refusal.failure
        );
        assert_eq!(refusal.version, Some(1));
        assert_eq!(
            fixture.list.state(),
            ListState {
                entry_id: Some(ENTRY_ID),
                ready: true,
                version: Some(1),
            }
        );
        assert_eq!(fixture.db.endpoint_entry_id().unwrap(), Some(ENTRY_ID));
        assert_eq!(fixture.flows.entry_id(), Some(ENTRY_ID));

        // The next update takes the lock again.
        fixture
            .apply(&full(2, Vec::new()), OTHER_ENTRY_ID)
            .await
            .expect("the update applies");
        assert_eq!(fixture.flows.entry_id(), Some(OTHER_ENTRY_ID));
    }

    #[tokio::test]
    async fn a_second_connection_with_the_same_key_replaces_the_first() {
        let fixture = Fixture::new();
        fixture
            .apply(
                &full(1, vec![entry(1, spki(1), EntryState::Active)]),
                ENTRY_ID,
            )
            .await
            .expect("a full list applies");
        let first = fixture.admitted(spki(1), ip(1));
        let second = fixture.admitted(spki(1), ip(1));
        assert_eq!(first.told().await, Told::Silent);
        assert!(!second.is_told());
        assert_eq!(fixture.list.registered(), (1, 1));
    }

    #[tokio::test]
    async fn repeated_replacements_from_two_addresses_store_a_duplicate_key() {
        let fixture = Fixture::new();
        fixture
            .apply(
                &full(1, vec![entry(1, spki(1), EntryState::Active)]),
                ENTRY_ID,
            )
            .await
            .expect("a full list applies");
        let mut held = Vec::new();
        let mut revealed = None;
        for n in 0..=DUPLICATE_KEY_THRESHOLD {
            let address = ip(if n % 2 == 0 { 1 } else { 2 });
            let conn = fixture.connect(spki(1), address);
            let admission = conn.pending.admit();
            assert_eq!(admission.verdict, StandingVerdict::Accept);
            if let Some(found) = admission.duplicate_key {
                revealed = Some(found);
            }
            held.push(conn);
        }
        let (at, duplicate_key) = revealed.expect("the replacements reveal a duplicate key");
        assert_eq!(duplicate_key.endpoint_id, Some(Uuid::from_u128(1)));
        store_duplicate_key(&fixture.db, at, duplicate_key);

        let received_ns = i64::try_from(at.as_nanosecond()).unwrap();
        let stored = fixture
            .db
            .get_cf_for_test(
                ENDPOINT_EVENTS_CF,
                &endpoint_event_key(received_ns, Uuid::from_u128(1), 0),
            )
            .unwrap()
            .expect("the duplicate key is stored");
        let event: DuplicateKeyEvent = bincode::deserialize(&stored).unwrap();
        assert_eq!(
            event,
            DuplicateKeyEvent {
                spki_sha256: spki(1),
                addresses: vec![ip(1), ip(2)],
                replacements: u64::try_from(DUPLICATE_KEY_THRESHOLD).unwrap(),
            }
        );
    }

    #[test]
    fn a_duplicate_key_that_cannot_be_stored_is_dropped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut db = Database::open(dir.path(), &DbOptions::default()).expect("open");
        let duplicate_key = |endpoint_id| DuplicateKey {
            spki_sha256: spki(1),
            endpoint_id,
            addresses: vec![ip(1), ip(2)],
            replacements: DUPLICATE_KEY_THRESHOLD,
        };
        let at = Timestamp::from_second(1_700_000_000).expect("a valid time");
        let received_ns = i64::try_from(at.as_nanosecond()).unwrap();

        // An event matching no entry has no endpoint id to key it by.
        store_duplicate_key(&db, at, duplicate_key(None));
        assert_eq!(
            db.get_cf_for_test(
                ENDPOINT_EVENTS_CF,
                &endpoint_event_key(received_ns, Uuid::nil(), 0)
            )
            .unwrap(),
            None
        );

        // A time past what an `i64` of nanoseconds holds does not fit the key.
        store_duplicate_key(&db, Timestamp::MAX, duplicate_key(Some(Uuid::from_u128(1))));
        assert_eq!(
            db.get_cf_for_test(
                ENDPOINT_EVENTS_CF,
                &endpoint_event_key(i64::MAX, Uuid::from_u128(1), 0)
            )
            .unwrap(),
            None
        );

        // A write that fails is logged, not propagated.
        db.drop_cf_for_test(ENDPOINT_EVENTS_CF)
            .expect("drop the events family");
        store_duplicate_key(&db, at, duplicate_key(Some(Uuid::from_u128(1))));
    }

    #[test]
    fn an_unreadable_stored_entry_id_is_taken_as_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Database::open(dir.path(), &DbOptions::default()).expect("open");
        db.put_cf_for_test(
            crate::storage::endpoint::ENDPOINT_ENTRY_CF,
            b"entry_id",
            b"short",
        )
        .expect("raw write");
        let list = EndpointList::new(LEASE);
        list.load_entry_id(&db);
        assert_eq!(
            list.state(),
            ListState {
                entry_id: None,
                ready: false,
                version: None,
            }
        );
    }

    /// Connections completing `hello` while an update removes or suspends
    /// their entry, or changes the `entry_id`, never stay open past the
    /// update's answer: each is either closed by it or judged against it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_admission_racing_an_update_never_outlives_it() {
        const ROUNDS: usize = 100;
        const CONNECTIONS: u8 = 6;

        #[derive(Debug, Clone, Copy)]
        enum Update {
            Remove,
            Suspend,
            NewEntryId,
        }

        for update in [Update::Remove, Update::Suspend, Update::NewEntryId] {
            for _ in 0..ROUNDS {
                let fixture = Fixture::new();
                let entries: Vec<ListEntry> = (1..=CONNECTIONS)
                    .map(|n| entry(u128::from(n), spki(n), EntryState::Active))
                    .collect();
                fixture
                    .apply(&full(1, entries.clone()), ENTRY_ID)
                    .await
                    .expect("a full list applies");
                let (change, entry_id) = match update {
                    Update::Remove => (
                        diff(1, 2, Vec::new(), (1..=u128::from(CONNECTIONS)).collect()),
                        ENTRY_ID,
                    ),
                    Update::Suspend => (
                        diff(
                            1,
                            2,
                            (1..=CONNECTIONS)
                                .map(|n| entry(u128::from(n), spki(n), suspended()))
                                .collect(),
                            Vec::new(),
                        ),
                        ENTRY_ID,
                    ),
                    Update::NewEntryId => (full(2, entries), OTHER_ENTRY_ID),
                };

                let start = Arc::new(Barrier::new(usize::from(CONNECTIONS) + 1));
                let conns: Vec<_> = (1..=CONNECTIONS)
                    .map(|n| {
                        let mut conn = fixture.connect(spki(n), ip(n));
                        let start = Arc::clone(&start);
                        tokio::spawn(async move {
                            tokio::task::block_in_place(|| start.wait());
                            let verdict = conn.hello();
                            let registration = conn.registration.take().expect("not yet served");
                            if verdict != StandingVerdict::Accept {
                                return Ok(());
                            }
                            // Admitted: it must be told to close by the update.
                            let told = tokio::time::timeout(WAIT, conn.stop.cancelled()).await;
                            drop(registration);
                            told.map_err(|_| "an admitted connection was never told to close")
                        })
                    })
                    .collect();
                let applied = {
                    let start = Arc::clone(&start);
                    tokio::task::block_in_place(|| start.wait());
                    fixture.apply(&change, entry_id).await
                };
                applied.expect("the update applies");
                // Every admitted connection has stopped by now; any admitted
                // after the update would never be told and would time out.
                for conn in conns {
                    conn.await
                        .expect("the connection task joins")
                        .unwrap_or_else(|e| panic!("{update:?}: {e}"));
                }
                assert_eq!(fixture.list.registered(), (0, 0), "{update:?}");
            }
        }
    }
}

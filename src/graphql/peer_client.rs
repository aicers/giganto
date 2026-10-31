//! The client a node sends its peers' GraphQL requests with.
//!
//! A request goes to `https://<name>:<GraphQL port>/graphql`, where `<name>`
//! is the certificate name recorded for the peer in [`PeerIdents`]. The client
//! resolves that name itself, through [`PeerIdents`] and [`Peers`], and
//! verifies the peer's certificate against Giganto's CA bundle and that name.

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, PoisonError},
};

use anyhow::{Context, Result};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use rustls::pki_types::ServerName;
use tracing::error;

use crate::{
    comm::peer::{PeerIdentity, PeerIdents, Peers},
    server::{Certs, tls_client_config},
    tls_reload::{TlsWatch, get_current_tls_material},
};

/// The URL scheme peer GraphQL requests are sent with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scheme {
    Https,
    /// Plain HTTP, for tests that mock a peer without TLS.
    #[cfg(test)]
    Http,
}

impl Scheme {
    fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            #[cfg(test)]
            Self::Http => "http",
        }
    }
}

/// Why a peer GraphQL request was not sent.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PeerRequestRefusal {
    #[error("Peer GraphQL request to {0} refused: no recorded peer identity")]
    NoIdentity(IpAddr),
    #[error("Peer GraphQL request to {0} refused: more than one recorded peer identity")]
    MoreThanOneIdentity(IpAddr),
    #[error("Peer GraphQL request to {0} refused: recorded peer name {1:?} is not a DNS name")]
    NotDnsName(IpAddr, String),
}

/// A per-generation client for peer GraphQL requests.
///
/// It holds a `reqwest::Client` built from the TLS material it last saw, and
/// rebuilds it when the watched material's generation changes, so a request
/// after a TLS reload presents the new client certificate.
pub(crate) struct PeerGraphqlClient {
    scheme: Scheme,
    resolver: Arc<PeerNameResolver>,
    /// The process's TLS material, or `None` for a plain-HTTP test client,
    /// which is never rebuilt.
    tls_watch: Option<TlsWatch>,
    current: Mutex<CurrentClient>,
}

struct CurrentClient {
    client: reqwest::Client,
    /// The `TlsMaterial::generation` `client` was built from.
    generation: u64,
}

impl PeerGraphqlClient {
    /// Creates the `https` client from the current material in `tls_watch`.
    ///
    /// # Errors
    ///
    /// Returns an error if the TLS configuration or the client cannot be built
    /// from the current material.
    pub(crate) fn new(peer_idents: PeerIdents, peers: Peers, tls_watch: TlsWatch) -> Result<Self> {
        let resolver = Arc::new(PeerNameResolver::new(peer_idents, peers));
        let material = get_current_tls_material(&tls_watch);
        let client = build_tls_client(&resolver, &material.certs)?;
        Ok(Self {
            scheme: Scheme::Https,
            resolver,
            tls_watch: Some(tls_watch),
            current: Mutex::new(CurrentClient {
                client,
                generation: material.generation,
            }),
        })
    }

    /// Creates a plain-HTTP client over the same resolver, for tests that mock
    /// a peer without TLS.
    #[cfg(test)]
    pub(crate) fn plain_http(peer_idents: PeerIdents, peers: Peers) -> Self {
        let resolver = Arc::new(PeerNameResolver::new(peer_idents, peers));
        let client = reqwest::Client::builder()
            .dns_resolver(Arc::clone(&resolver))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("a plain-HTTP client needs no TLS material");
        Self {
            scheme: Scheme::Http,
            resolver,
            tls_watch: None,
            current: Mutex::new(CurrentClient {
                client,
                generation: 0,
            }),
        }
    }

    /// Returns the URL scheme requests through this client use.
    #[must_use]
    pub(crate) fn scheme(&self) -> &'static str {
        self.scheme.as_str()
    }

    /// Returns the client built from the current TLS material, rebuilding it
    /// first if the material was reloaded since it was built.
    ///
    /// If the rebuild fails, the previous client is kept and the failure is
    /// logged.
    #[must_use]
    pub(crate) fn client(&self) -> reqwest::Client {
        // Every write replaces the client and its generation together, so a
        // poisoned lock still holds a consistent pair.
        let mut current = self.current.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(tls_watch) = &self.tls_watch {
            let material = get_current_tls_material(tls_watch);
            if material.generation != current.generation {
                match build_tls_client(&self.resolver, &material.certs) {
                    Ok(client) => {
                        *current = CurrentClient {
                            client,
                            generation: material.generation,
                        };
                    }
                    Err(e) => error!(
                        "Failed to rebuild the peer GraphQL client after a TLS reload, keeping the previous one: {e:#}"
                    ),
                }
            }
        }
        current.client.clone()
    }
}

fn build_tls_client(resolver: &Arc<PeerNameResolver>, certs: &Certs) -> Result<reqwest::Client> {
    let tls = tls_client_config(certs)?;
    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .dns_resolver(Arc::clone(resolver))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .build()
        .context("failed to build the peer GraphQL client")
}

/// Returns the URL of the GraphQL endpoint of the peer at `peer`, named by
/// the one certificate name recorded for its IP in `idents`.
///
/// # Errors
///
/// Returns the refusal if no name, more than one name, or a name that is not a
/// DNS name is recorded for the IP.
pub(crate) fn peer_graphql_url(
    scheme: &str,
    idents: &HashSet<PeerIdentity>,
    peer: SocketAddr,
) -> Result<String, PeerRequestRefusal> {
    let ip = peer.ip();
    let canonical = ip.to_canonical();
    let mut names: Vec<&str> = Vec::new();
    for ident in idents
        .iter()
        .filter(|ident| ident.addr.ip().to_canonical() == canonical)
    {
        if !names
            .iter()
            .any(|name| name.eq_ignore_ascii_case(&ident.hostname))
        {
            names.push(&ident.hostname);
        }
    }
    let hostname = match names.as_slice() {
        [] => return Err(PeerRequestRefusal::NoIdentity(ip)),
        [hostname] => *hostname,
        _ => return Err(PeerRequestRefusal::MoreThanOneIdentity(ip)),
    };
    if !matches!(ServerName::try_from(hostname), Ok(ServerName::DnsName(_))) {
        return Err(PeerRequestRefusal::NotDnsName(ip, hostname.to_owned()));
    }
    Ok(format!("{scheme}://{hostname}:{}/graphql", peer.port()))
}

/// Resolves a peer's certificate name to the connected IPs it is recorded at.
#[derive(Clone)]
struct PeerNameResolver {
    peer_idents: PeerIdents,
    peers: Peers,
}

impl PeerNameResolver {
    fn new(peer_idents: PeerIdents, peers: Peers) -> Self {
        Self { peer_idents, peers }
    }

    /// Returns the distinct IPs recorded under `name` that are currently a
    /// key of [`Peers`].
    ///
    /// The two sets are read one after the other, never locked together.
    async fn lookup(&self, name: &str) -> Vec<IpAddr> {
        let recorded: Vec<IpAddr> = self
            .peer_idents
            .read()
            .await
            .iter()
            .filter(|ident| ident.hostname.eq_ignore_ascii_case(name))
            .map(|ident| ident.addr.ip().to_canonical())
            .collect();
        if recorded.is_empty() {
            return recorded;
        }
        let connected: HashSet<IpAddr> = self
            .peers
            .read()
            .await
            .keys()
            .filter_map(|key| key.parse::<IpAddr>().ok())
            .map(|ip| ip.to_canonical())
            .collect();
        let mut ips: Vec<IpAddr> = Vec::new();
        for ip in recorded {
            if connected.contains(&ip) && !ips.contains(&ip) {
                ips.push(ip);
            }
        }
        ips
    }
}

impl Resolve for PeerNameResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.clone();
        Box::pin(async move {
            let ips = resolver.lookup(name.as_str()).await;
            if ips.is_empty() {
                return Err(format!(
                    "no connected peer is recorded under the name {:?}",
                    name.as_str()
                )
                .into());
            }
            // Port 0 is replaced by the URL's port.
            let addrs: Addrs = Box::new(ips.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    use reqwest::dns::{Name, Resolve};
    use tokio::sync::RwLock;

    use super::{PeerNameResolver, PeerRequestRefusal, peer_graphql_url};
    use crate::comm::peer::{PeerIdentity, PeerIdents, PeerInfo, Peers};

    const NAME: &str = "001.giganto.node1.example.test";
    const OTHER_NAME: &str = "001.giganto.node2.example.test";
    const QUIC_PORT: u16 = 38_383;
    const GRAPHQL_PORT: u16 = 8_443;

    fn ident(addr: &str, hostname: &str) -> PeerIdentity {
        PeerIdentity {
            addr: addr.parse().unwrap(),
            hostname: hostname.to_string(),
        }
    }

    fn graphql_addr(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), GRAPHQL_PORT)
    }

    fn peers_at(ips: &[&str]) -> Peers {
        Arc::new(RwLock::new(
            ips.iter()
                .map(|ip| ((*ip).to_string(), PeerInfo::default()))
                .collect::<HashMap<_, _>>(),
        ))
    }

    fn idents_of(idents: Vec<PeerIdentity>) -> PeerIdents {
        Arc::new(RwLock::new(idents.into_iter().collect()))
    }

    async fn resolve(resolver: &PeerNameResolver, name: &str) -> Result<Vec<SocketAddr>, String> {
        resolver
            .resolve(name.parse::<Name>().unwrap())
            .await
            .map(Iterator::collect)
            .map_err(|e| e.to_string())
    }

    #[test]
    fn url_names_the_recorded_peer_with_the_graphql_port() {
        let idents = HashSet::from([ident(&format!("10.0.0.2:{QUIC_PORT}"), NAME)]);
        let url = peer_graphql_url("https", &idents, graphql_addr("10.0.0.2")).unwrap();
        assert_eq!(url, format!("https://{NAME}:{GRAPHQL_PORT}/graphql"));
    }

    #[test]
    fn url_is_refused_without_an_identity_at_the_ip() {
        let idents = HashSet::from([ident(&format!("10.0.0.3:{QUIC_PORT}"), NAME)]);
        let refusal = peer_graphql_url("https", &idents, graphql_addr("10.0.0.2")).unwrap_err();
        assert!(matches!(refusal, PeerRequestRefusal::NoIdentity(_)));
        assert_eq!(
            refusal.to_string(),
            "Peer GraphQL request to 10.0.0.2 refused: no recorded peer identity"
        );
    }

    #[test]
    fn url_is_refused_for_an_identity_at_an_unspecified_address() {
        let idents = HashSet::from([ident(&format!("0.0.0.0:{QUIC_PORT}"), NAME)]);
        let refusal = peer_graphql_url("https", &idents, graphql_addr("10.0.0.2")).unwrap_err();
        assert!(matches!(refusal, PeerRequestRefusal::NoIdentity(_)));
    }

    #[test]
    fn url_is_refused_for_two_names_at_one_ip() {
        let idents = HashSet::from([
            ident(&format!("10.0.0.2:{QUIC_PORT}"), NAME),
            ident(&format!("10.0.0.2:{}", QUIC_PORT + 1), OTHER_NAME),
        ]);
        let refusal = peer_graphql_url("https", &idents, graphql_addr("10.0.0.2")).unwrap_err();
        assert!(matches!(
            refusal,
            PeerRequestRefusal::MoreThanOneIdentity(_)
        ));
        assert_eq!(
            refusal.to_string(),
            "Peer GraphQL request to 10.0.0.2 refused: more than one recorded peer identity"
        );
    }

    #[test]
    fn url_is_refused_for_an_ip_literal_name() {
        let idents = HashSet::from([ident(&format!("10.0.0.2:{QUIC_PORT}"), "10.0.0.2")]);
        let refusal = peer_graphql_url("https", &idents, graphql_addr("10.0.0.2")).unwrap_err();
        assert!(matches!(refusal, PeerRequestRefusal::NotDnsName(_, _)));
        assert_eq!(
            refusal.to_string(),
            "Peer GraphQL request to 10.0.0.2 refused: recorded peer name \"10.0.0.2\" is not a DNS name"
        );
    }

    #[test]
    fn url_matches_an_ipv4_mapped_request_ip() {
        let idents = HashSet::from([ident(&format!("127.0.0.1:{QUIC_PORT}"), NAME)]);
        let url = peer_graphql_url("https", &idents, graphql_addr("::ffff:127.0.0.1")).unwrap();
        assert_eq!(url, format!("https://{NAME}:{GRAPHQL_PORT}/graphql"));
    }

    #[test]
    fn url_counts_names_differing_in_case_as_one() {
        let idents = HashSet::from([
            ident(&format!("10.0.0.2:{QUIC_PORT}"), NAME),
            ident(
                &format!("10.0.0.2:{}", QUIC_PORT + 1),
                &NAME.to_ascii_uppercase(),
            ),
        ]);
        let url = peer_graphql_url("https", &idents, graphql_addr("10.0.0.2")).unwrap();
        assert!(
            url.eq_ignore_ascii_case(&format!("https://{NAME}:{GRAPHQL_PORT}/graphql")),
            "{url}"
        );
    }

    #[tokio::test]
    async fn resolver_answers_a_recorded_connected_name() {
        let resolver = PeerNameResolver::new(
            idents_of(vec![ident(&format!("10.0.0.2:{QUIC_PORT}"), NAME)]),
            peers_at(&["10.0.0.2"]),
        );
        assert_eq!(
            resolve(&resolver, NAME).await.unwrap(),
            [SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), 0)]
        );
    }

    #[tokio::test]
    async fn resolver_compares_names_ignoring_case() {
        let expected = [SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), 0)];

        let lower = PeerNameResolver::new(
            idents_of(vec![ident(&format!("10.0.0.2:{QUIC_PORT}"), NAME)]),
            peers_at(&["10.0.0.2"]),
        );
        assert_eq!(
            resolve(&lower, &NAME.to_ascii_uppercase()).await.unwrap(),
            expected
        );

        let upper = PeerNameResolver::new(
            idents_of(vec![ident(
                &format!("10.0.0.2:{QUIC_PORT}"),
                &NAME.to_ascii_uppercase(),
            )]),
            peers_at(&["10.0.0.2"]),
        );
        assert_eq!(resolve(&upper, NAME).await.unwrap(), expected);
    }

    #[tokio::test]
    async fn resolver_refuses_an_unknown_name() {
        let resolver = PeerNameResolver::new(
            idents_of(vec![ident(&format!("10.0.0.2:{QUIC_PORT}"), NAME)]),
            peers_at(&["10.0.0.2"]),
        );
        let error = resolve(&resolver, OTHER_NAME).await.unwrap_err();
        assert!(error.contains(OTHER_NAME), "{error}");
    }

    #[tokio::test]
    async fn resolver_answers_only_connected_ips() {
        let resolver = PeerNameResolver::new(
            idents_of(vec![
                ident(&format!("10.0.0.2:{QUIC_PORT}"), NAME),
                ident(&format!("10.0.0.9:{QUIC_PORT}"), NAME),
                ident(&format!("0.0.0.0:{QUIC_PORT}"), NAME),
            ]),
            peers_at(&["10.0.0.2", "not an ip"]),
        );
        assert_eq!(
            resolve(&resolver, NAME).await.unwrap(),
            [SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), 0)]
        );
    }

    #[tokio::test]
    async fn resolver_reads_the_live_sets() {
        let peer_idents = idents_of(Vec::new());
        let peers = peers_at(&[]);
        let resolver = PeerNameResolver::new(Arc::clone(&peer_idents), Arc::clone(&peers));
        assert!(resolve(&resolver, NAME).await.is_err());

        peer_idents
            .write()
            .await
            .insert(ident(&format!("10.0.0.2:{QUIC_PORT}"), NAME));
        peers
            .write()
            .await
            .insert("10.0.0.2".to_string(), PeerInfo::default());

        assert_eq!(
            resolve(&resolver, NAME).await.unwrap(),
            [SocketAddr::new(IpAddr::from(Ipv4Addr::new(10, 0, 0, 2)), 0)]
        );
    }
}

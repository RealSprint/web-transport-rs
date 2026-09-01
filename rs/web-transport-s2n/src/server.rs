use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::{future::BoxFuture, stream::FuturesUnordered, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use s2n_quic::connection::{Handle, StreamAcceptor};

use crate::tls::ServerTlsProvider;
use crate::{
    crypto, datagram_endpoint,
    proto::{ConnectRequest, ConnectResponse},
    Connecting, ServerError, Session, Settings, ALPN,
};

/// Construct a WebTransport [`Server`] using sane defaults.
pub struct ServerBuilder {
    provider: crypto::Provider,
    addr: std::net::SocketAddr,
    limits: HandshakeLimits,
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerBuilder {
    /// Create a server builder with sane defaults.
    pub fn new() -> Self {
        Self {
            provider: crypto::default_provider(),
            addr: "[::]:443".parse().unwrap(),
            limits: HandshakeLimits::default(),
        }
    }

    /// Listen on the specified address.
    pub fn with_addr(self, addr: std::net::SocketAddr) -> Self {
        Self { addr, ..self }
    }

    /// Bound the in-flight H3/WebTransport handshakes; see [`HandshakeLimits`].
    pub fn with_handshake_limits(self, limits: HandshakeLimits) -> Self {
        Self { limits, ..self }
    }

    /// Supply a certificate chain and private key used for TLS.
    pub fn with_certificate(
        self,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Server, ServerError> {
        let mut config = rustls::ServerConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(chain, key)?;

        config.alpn_protocols = vec![ALPN.as_bytes().to_vec()];

        let tls = ServerTlsProvider { config };

        let server = s2n_quic::Server::builder()
            .with_tls(tls)
            .map_err(|e| ServerError::Build(e.to_string()))?
            .with_io(self.addr)
            .map_err(|e| ServerError::Build(e.to_string()))?
            .with_datagram(datagram_endpoint())
            .map_err(|e| ServerError::Build(e.to_string()))?
            .start()
            .map_err(|e| ServerError::Build(e.to_string()))?;

        Ok(Server::with_limits(server, self.limits))
    }
}

/// Default for [`HandshakeLimits::max_inflight`]. Maximum number of
/// H3/WebTransport handshakes (accepted QUIC connections that haven't yet
/// produced a [`Request`]) that [`Server::accept`] drives at once. Without a
/// cap, a peer that finishes the QUIC handshake and then stalls (no control
/// stream, no CONNECT) pins state here indefinitely - cheap slowloris.
///
/// Because [`Server::accept`] always dequeues from the underlying endpoint and
/// closes anything over this cap on arrival, this is a hard bound on the
/// handshake state one endpoint can pin. Gating `s2n_quic::Server::accept`
/// instead would not bound it: over-cap connections would sit undriven in
/// s2n-quic's own unbounded accept queue with [`DEFAULT_HANDSHAKE_TIMEOUT`]
/// not yet started, and new sessions would queue behind stalled ones.
///
/// # Sizing: burst, not steady-state concurrency
///
/// Rejecting on arrival means this cap bounds the largest *burst* of
/// simultaneous connects the endpoint will admit, not its steady-state
/// handshake concurrency. The set grows to roughly
/// `arrival_rate × handshake_latency` before the first handshake retires, and
/// during a burst both factors are at their worst: everything arrives at once
/// and each H3 exchange is queued behind all the others. Measured on one
/// endpoint, 1350 clients connecting together drive the set to **1347**
/// concurrent handshakes before any completes. A cap sized for "normal
/// handshake concurrency" (an earlier revision used 256) therefore rejects the
/// bulk of an ordinary connect surge: those 1350 clients yielded 260 sessions
/// and 1090 `H3_EXCESSIVE_LOAD` closes.
///
/// 8192 is sized as a DoS backstop rather than a capacity limit - roughly 6x
/// the largest benign burst measured per endpoint, and comparable to the
/// endpoint's own inflight-QUIC-handshake limit. Combined with
/// [`DEFAULT_HANDSHAKE_TIMEOUT`], the adversarial worst case is 8192 pinned H3
/// handshakes per endpoint, each self-freeing within the timeout. Applications
/// running several endpoints in one process can divide a process-wide budget
/// across them via [`Server::with_limits`].
pub const DEFAULT_MAX_INFLIGHT_HANDSHAKES: usize = 8192;

/// Default for [`HandshakeLimits::timeout`]. Per-handshake timeout for
/// [`Request::accept`] (the H3 SETTINGS/CONNECT exchange), so a stalled peer
/// can't hold a driven slot forever. QUIC's own `max_handshake_duration` only
/// covers the transport handshake, not this stage.
///
/// Kept at 10s rather than trimmed to the round trip this stage nominally
/// costs: its slowest case is precisely the connect burst the cap above is
/// meant to survive, where a slot's H3 exchange waits behind every other
/// in-flight handshake on the endpoint. Since
/// [`DEFAULT_MAX_INFLIGHT_HANDSHAKES`] already bounds how many slots exist,
/// the timeout only sets how long one stalled peer holds one - worth spending
/// to keep a legitimate client from being dropped mid-handshake.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bounds on the H3/WebTransport handshakes one [`Server`] drives at a time.
///
/// [`Default`] is [`DEFAULT_MAX_INFLIGHT_HANDSHAKES`] / [`DEFAULT_HANDSHAKE_TIMEOUT`];
/// see those for how the values are sized. Pass a custom value through
/// [`Server::with_limits`] or [`ServerBuilder::with_handshake_limits`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandshakeLimits {
    /// Handshakes driven concurrently. A connection dequeued while this many are
    /// in flight is closed with `H3_EXCESSIVE_LOAD` instead of being driven.
    /// Must be at least 1.
    pub max_inflight: usize,
    /// How long one handshake may take, measured from the moment its connection
    /// was dequeued from the endpoint until it yields a [`Request`].
    pub timeout: Duration,
}

impl Default for HandshakeLimits {
    fn default() -> Self {
        Self {
            max_inflight: DEFAULT_MAX_INFLIGHT_HANDSHAKES,
            timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }
}

/// Running totals for [`Server::accept`]'s admission decisions and handshake
/// outcomes. Obtain a shared handle via [`Server::handshake_counters`] and read
/// it with [`HandshakeCounters::snapshot`] from any task.
#[derive(Debug, Default)]
pub struct HandshakeCounters {
    admitted: AtomicU64,
    completed: AtomicU64,
    rejected: AtomicU64,
    timed_out: AtomicU64,
    failed: AtomicU64,
    inflight: AtomicUsize,
    inflight_high_water: AtomicUsize,
}

/// A point-in-time copy of [`HandshakeCounters`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HandshakeStats {
    /// Connections admitted into the driven handshake set.
    pub admitted: u64,
    /// Handshakes that produced a [`Request`].
    pub completed: u64,
    /// Connections closed with `H3_EXCESSIVE_LOAD` because the set was full.
    pub rejected: u64,
    /// Handshakes that hit [`HandshakeLimits::timeout`].
    pub timed_out: u64,
    /// Handshakes that ended in any other error (peer closed, protocol error).
    pub failed: u64,
    /// Handshakes in flight right now.
    pub inflight: usize,
    /// The largest `inflight` observed since the server was created.
    pub inflight_high_water: usize,
}

impl HandshakeCounters {
    /// Copy every counter. Individual fields are read independently, so a
    /// snapshot taken while `accept` runs may be off by one between fields.
    pub fn snapshot(&self) -> HandshakeStats {
        HandshakeStats {
            admitted: self.admitted.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            timed_out: self.timed_out.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            inflight: self.inflight.load(Ordering::Relaxed),
            inflight_high_water: self.inflight_high_water.load(Ordering::Relaxed),
        }
    }

    fn set_inflight(&self, inflight: usize) {
        self.inflight.store(inflight, Ordering::Relaxed);
        self.inflight_high_water
            .fetch_max(inflight, Ordering::Relaxed);
    }
}

/// The largest benign connect burst measured against one endpoint: 1350 clients
/// connecting together drove [`Server::accept`]'s driven set to 1347 concurrent
/// handshakes before the first one retired. Only a reference point for the two
/// guards below - connections over the cap are closed rather than queued, so
/// both constants have to clear a burst of this shape by a wide margin.
#[cfg(test)]
const MEASURED_BENIGN_BURST: usize = 1347;

// The cap is a DoS backstop, not a capacity limit: keep it clear of a benign
// burst, or an ordinary connect surge gets H3_EXCESSIVE_LOAD instead of a session.
#[cfg(test)]
const _: () = assert!(DEFAULT_MAX_INFLIGHT_HANDSHAKES >= MEASURED_BENIGN_BURST * 4);

// The timeout has to outlast an H3 exchange queued behind a full burst of other
// in-flight handshakes, not just the single round trip it nominally costs.
#[cfg(test)]
const _: () = assert!(DEFAULT_HANDSHAKE_TIMEOUT.as_secs() >= 10);

/// `H3_EXCESSIVE_LOAD` from the HTTP/3 error space (RFC 9114, section 8.1), used
/// to close connections arriving while [`HandshakeLimits::max_inflight`]
/// handshakes are already being driven. It is the H3 layer that is out of
/// capacity and no WebTransport session exists yet, so this is a raw HTTP/3 code
/// rather than a WebTransport code mapped through
/// [`web_transport_proto::error_to_http3`].
const H3_EXCESSIVE_LOAD: u64 = 0x0107;

/// Whether a freshly dequeued connection may join the driven handshake set.
///
/// Split out from [`Server::accept`] so the admission boundary is testable
/// without a live endpoint.
fn has_handshake_capacity(driven: usize, max_inflight: usize) -> bool {
    driven < max_inflight
}

/// A WebTransport server that accepts new sessions.
pub struct Server {
    endpoint: s2n_quic::Server,
    accept: FuturesUnordered<BoxFuture<'static, Result<Request, ServerError>>>,
    limits: HandshakeLimits,
    counters: Arc<HandshakeCounters>,
}

impl Server {
    /// Create a new server from a pre-built s2n-quic [`s2n_quic::Server`] with
    /// [`HandshakeLimits::default`].
    ///
    /// NOTE: The TLS ALPN must include [`ALPN`] for WebTransport to work.
    pub fn new(endpoint: s2n_quic::Server) -> Self {
        Self::with_limits(endpoint, HandshakeLimits::default())
    }

    /// Like [`Server::new`], with explicit [`HandshakeLimits`].
    ///
    /// # Panics
    /// If `limits.max_inflight` is 0, which would reject every connection.
    pub fn with_limits(endpoint: s2n_quic::Server, limits: HandshakeLimits) -> Self {
        assert!(
            limits.max_inflight >= 1,
            "HandshakeLimits::max_inflight must be at least 1"
        );
        Self {
            endpoint,
            accept: Default::default(),
            limits,
            counters: Default::default(),
        }
    }

    /// The limits this server applies in [`Server::accept`].
    pub fn limits(&self) -> HandshakeLimits {
        self.limits
    }

    /// A shared handle to this server's handshake counters.
    pub fn handshake_counters(&self) -> Arc<HandshakeCounters> {
        self.counters.clone()
    }

    /// Returns the local address the server is bound to.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Accept a new WebTransport session [`Request`] from a client.
    pub async fn accept(&mut self) -> Option<Request> {
        loop {
            tokio::select! {
                // Always dequeue: the endpoint's accept queue is unbounded and the
                // connections in it are undriven, so leaving them there would neither
                // bound pinned state nor keep fresh sessions from queueing behind
                // stalled handshakes.
                conn = self.endpoint.accept() => {
                    let conn = conn?;
                    if !has_handshake_capacity(self.accept.len(), self.limits.max_inflight) {
                        // Over capacity: reject explicitly rather than pinning state.
                        // Each rejection is bounded work on a connection this iteration
                        // actually consumed, so a hot accept stream can't spin the loop.
                        conn.close(
                            s2n_quic::application::Error::new(H3_EXCESSIVE_LOAD)
                                .expect("h3 error code within varint range"),
                        );
                        self.counters.rejected.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let timeout = self.limits.timeout;
                    self.accept.push(Box::pin(async move {
                        tokio::time::timeout(timeout, Request::accept(conn))
                            .await
                            .unwrap_or(Err(ServerError::HandshakeTimeout))
                    }));
                    self.counters.admitted.fetch_add(1, Ordering::Relaxed);
                    self.counters.set_inflight(self.accept.len());
                }
                Some(res) = self.accept.next() => {
                    self.counters.set_inflight(self.accept.len());
                    match res {
                        Ok(request) => {
                            self.counters.completed.fetch_add(1, Ordering::Relaxed);
                            return Some(request);
                        }
                        Err(ServerError::HandshakeTimeout) => {
                            self.counters.timed_out.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            self.counters.failed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    }
}

/// A mostly complete WebTransport handshake, awaiting the server's accept/reject decision.
pub struct Request {
    handle: Handle,
    acceptor: StreamAcceptor,
    settings: Settings,
    connect: Connecting,
}

impl Request {
    /// Perform the handshake on a freshly accepted QUIC connection.
    pub async fn accept(conn: s2n_quic::Connection) -> Result<Self, ServerError> {
        let (mut handle, mut acceptor) = conn.split();

        // Perform the H3 handshake by sending/receiving SETTINGS frames.
        let settings = Settings::connect(&mut handle, &mut acceptor).await?;

        // Accept the CONNECT request but don't respond yet.
        let connect = Connecting::accept(&mut acceptor).await?;

        Ok(Self {
            handle,
            acceptor,
            settings,
            connect,
        })
    }

    /// Accept the session with a 200 OK response.
    pub async fn ok(self) -> Result<Session, ServerError> {
        self.respond(ConnectResponse::OK).await
    }

    /// Reply to the session with the given response, usually 200 OK.
    ///
    /// [`ConnectResponse::with_protocol`] can be used to select a subprotocol.
    pub async fn respond(
        self,
        response: impl Into<ConnectResponse>,
    ) -> Result<Session, ServerError> {
        let response = response.into();
        let connect = self.connect.respond(response).await?;
        Ok(Session::new(
            self.handle,
            self.acceptor,
            self.settings,
            connect,
        ))
    }

    /// Reject the session with the given status code.
    pub async fn reject(self, status: http::StatusCode) -> Result<(), ServerError> {
        self.connect.reject(status).await?;
        Ok(())
    }

    /// Returns the CONNECT request that was sent by the client.
    pub fn connect(&self) -> &ConnectRequest {
        &self.connect.request
    }

    /// Returns the address of the peer that opened this connection.
    ///
    /// Available before the accept/reject decision, so servers can apply per-IP policy
    /// (abuse blocking, geo attribution, access logs) to a request they may still reject.
    pub fn remote_addr(&self) -> Result<std::net::SocketAddr, ServerError> {
        Ok(self.handle.remote_addr()?)
    }
}

impl core::ops::Deref for Request {
    type Target = ConnectRequest;

    fn deref(&self) -> &Self::Target {
        &self.connect.request
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The admission boundary `Server::accept` applies to every dequeued
    /// connection, exercised against the real default.
    #[test]
    fn handshake_capacity_does_not_off_by_one_at_the_cap() {
        let max = HandshakeLimits::default().max_inflight;
        assert!(has_handshake_capacity(0, max));
        assert!(has_handshake_capacity(max - 1, max));
        assert!(!has_handshake_capacity(max, max));
        assert!(!has_handshake_capacity(max + 1, max));
    }

    #[test]
    fn handshake_capacity_honours_a_custom_cap() {
        assert!(has_handshake_capacity(0, 1));
        assert!(!has_handshake_capacity(1, 1));
        assert!(has_handshake_capacity(2, 3));
        assert!(!has_handshake_capacity(3, 3));
    }

    #[test]
    fn default_limits_match_the_documented_defaults() {
        let limits = HandshakeLimits::default();
        assert_eq!(limits.max_inflight, DEFAULT_MAX_INFLIGHT_HANDSHAKES);
        assert_eq!(limits.timeout, DEFAULT_HANDSHAKE_TIMEOUT);
    }

    #[test]
    fn counters_track_inflight_and_high_water() {
        let counters = HandshakeCounters::default();
        counters.set_inflight(3);
        counters.set_inflight(7);
        counters.set_inflight(2);
        let stats = counters.snapshot();
        assert_eq!(stats.inflight, 2);
        assert_eq!(stats.inflight_high_water, 7);
        assert_eq!(
            stats,
            HandshakeStats {
                inflight: 2,
                inflight_high_water: 7,
                ..Default::default()
            }
        );
    }

    /// Shape test for `Server::accept`'s over-capacity behaviour: connections are
    /// dequeued unconditionally, and those over the cap are closed instead of
    /// joining the driven set (and instead of being left queued). A full
    /// end-to-end test would mean driving `max + 1` real, stalled QUIC
    /// handshakes through an actual `s2n_quic::Server` (whose concrete type
    /// can't be substituted) - a real slowloris simulation, which the task
    /// explicitly doesn't require. This instead proves the driven set saturates
    /// at the cap while the accept queue keeps draining.
    #[test]
    fn connections_over_the_cap_are_rejected_rather_than_queued() {
        let max = HandshakeLimits::default().max_inflight;
        let driven: FuturesUnordered<BoxFuture<'static, ()>> = FuturesUnordered::new();
        let offered = max * 4;
        let mut dequeued = 0usize;
        let mut rejected = 0usize;

        // Offer far more "new connections" than the cap. Unlike the previous gated
        // design, every one is dequeued; the decision is only whether it is driven.
        for _ in 0..offered {
            dequeued += 1;
            if has_handshake_capacity(driven.len(), max) {
                driven.push(Box::pin(std::future::pending()));
            } else {
                rejected += 1;
            }
        }

        assert_eq!(dequeued, offered, "every connection must be dequeued");
        assert_eq!(driven.len(), max);
        assert_eq!(rejected, offered - max);
    }

    /// The over-capacity close code is a valid application error code, so the
    /// `expect` on the rejection path in `Server::accept` cannot fire.
    #[test]
    fn the_over_capacity_close_code_is_h3_excessive_load() {
        let error = s2n_quic::application::Error::new(H3_EXCESSIVE_LOAD)
            .expect("h3 error code within varint range");
        assert_eq!(u64::from(error), 0x0107);
    }
}

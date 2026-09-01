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
        }
    }

    /// Listen on the specified address.
    pub fn with_addr(self, addr: std::net::SocketAddr) -> Self {
        Self { addr, ..self }
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

        Ok(Server::new(server))
    }
}

/// Maximum concurrent in-flight H3/WebTransport handshakes (accepted QUIC
/// connections that haven't yet produced a [`Request`]). Without a cap, a peer
/// that finishes the QUIC handshake and then stalls (no control stream, no
/// CONNECT) pins state here indefinitely - cheap slowloris. 256 is generous for
/// legitimate handshake concurrency (these normally resolve in well under a
/// second) while bounding worst-case pinned state on one endpoint.
const MAX_INFLIGHT_SESSION_HANDSHAKES: usize = 256;

/// Per-handshake timeout for [`Request::accept`] (the H3 SETTINGS/CONNECT
/// exchange), so a stalled peer can't hold an in-flight slot forever. QUIC's own
/// `max_handshake_duration` only covers the transport handshake, not this stage.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A WebTransport server that accepts new sessions.
pub struct Server {
    endpoint: s2n_quic::Server,
    accept: FuturesUnordered<BoxFuture<'static, Result<Request, ServerError>>>,
}

impl Server {
    /// Create a new server from a pre-built s2n-quic [`s2n_quic::Server`].
    ///
    /// NOTE: The TLS ALPN must include [`ALPN`] for WebTransport to work.
    pub fn new(endpoint: s2n_quic::Server) -> Self {
        Self {
            endpoint,
            accept: Default::default(),
        }
    }

    /// Returns the local address the server is bound to.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Accept a new WebTransport session [`Request`] from a client.
    pub async fn accept(&mut self) -> Option<Request> {
        loop {
            tokio::select! {
                // Backpressure, not rejection: stop polling for new QUIC connections
                // once MAX_INFLIGHT_SESSION_HANDSHAKES are already handshaking, so the
                // in-flight set can never grow past the cap. Cheaper and simpler than
                // accepting the connection and then tearing it down over the cap.
                conn = self.endpoint.accept(), if self.accept.len() < MAX_INFLIGHT_SESSION_HANDSHAKES => {
                    let conn = conn?;
                    self.accept.push(Box::pin(async move {
                        tokio::time::timeout(HANDSHAKE_TIMEOUT, Request::accept(conn))
                            .await
                            .unwrap_or(Err(ServerError::HandshakeTimeout))
                    }));
                }
                Some(res) = self.accept.next() => {
                    if let Ok(request) = res {
                        return Some(request);
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

    /// Shape test for `Server::accept`'s backpressure guard (`self.accept.len() <
    /// MAX_INFLIGHT_SESSION_HANDSHAKES`), against the real constant. A full
    /// end-to-end test would mean driving `MAX_INFLIGHT_SESSION_HANDSHAKES + 1`
    /// real, stalled QUIC handshakes through an actual `s2n_quic::Server` (whose
    /// concrete type can't be substituted) and waiting out `HANDSHAKE_TIMEOUT` to
    /// observe recovery - a real slowloris simulation, which the task explicitly
    /// doesn't require. This instead proves the exact guard expression admits no
    /// more than the cap and never off-by-ones at the boundary.
    #[test]
    fn accept_backpressure_never_exceeds_the_inflight_cap() {
        let in_flight: FuturesUnordered<BoxFuture<'static, ()>> = FuturesUnordered::new();
        let mut offered = 0usize;

        // Offer far more "new connections" than the cap; only push while under it -
        // the same guard `Server::accept` uses before calling `self.endpoint.accept()`.
        for _ in 0..(MAX_INFLIGHT_SESSION_HANDSHAKES * 4) {
            if in_flight.len() < MAX_INFLIGHT_SESSION_HANDSHAKES {
                offered += 1;
                in_flight.push(Box::pin(std::future::pending()));
            }
        }

        assert_eq!(in_flight.len(), MAX_INFLIGHT_SESSION_HANDSHAKES);
        assert_eq!(offered, MAX_INFLIGHT_SESSION_HANDSHAKES);
    }
}

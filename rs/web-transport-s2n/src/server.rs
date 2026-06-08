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
                conn = self.endpoint.accept() => {
                    let conn = conn?;
                    self.accept.push(Box::pin(Request::accept(conn)));
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
}

impl core::ops::Deref for Request {
    type Target = ConnectRequest;

    fn deref(&self) -> &Self::Target {
        &self.connect.request
    }
}

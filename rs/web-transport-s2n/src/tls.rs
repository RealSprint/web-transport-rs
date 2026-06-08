use s2n_quic::provider::tls as s2n_tls;

/// A [`s2n_tls::Provider`] that hands s2n-quic a pre-built rustls [`rustls::ClientConfig`].
///
/// `start_server` is never called on a client endpoint, so it errors.
pub(crate) struct ClientTlsProvider {
    pub config: rustls::ClientConfig,
}

impl s2n_tls::Provider for ClientTlsProvider {
    type Server = s2n_tls::rustls::Server;
    type Client = s2n_tls::rustls::Client;
    type Error = rustls::Error;

    fn start_server(self) -> Result<Self::Server, Self::Error> {
        Err(rustls::Error::General(
            "this TLS provider is client-only".to_string(),
        ))
    }

    fn start_client(self) -> Result<Self::Client, Self::Error> {
        Ok(self.config.into())
    }
}

/// A [`s2n_tls::Provider`] that hands s2n-quic a pre-built rustls [`rustls::ServerConfig`].
///
/// `start_client` is never called on a server endpoint, so it errors.
pub(crate) struct ServerTlsProvider {
    pub config: rustls::ServerConfig,
}

impl s2n_tls::Provider for ServerTlsProvider {
    type Server = s2n_tls::rustls::Server;
    type Client = s2n_tls::rustls::Client;
    type Error = rustls::Error;

    fn start_server(self) -> Result<Self::Server, Self::Error> {
        Ok(self.config.into())
    }

    fn start_client(self) -> Result<Self::Client, Self::Error> {
        Err(rustls::Error::General(
            "this TLS provider is server-only".to_string(),
        ))
    }
}

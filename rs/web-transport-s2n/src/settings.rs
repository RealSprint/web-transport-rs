use futures::try_join;
use thiserror::Error;

use s2n_quic::connection::{Handle, StreamAcceptor};

#[derive(Error, Debug, Clone)]
pub enum SettingsError {
    #[error("quic stream was closed early")]
    UnexpectedEnd,

    #[error("protocol error: {0}")]
    ProtoError(#[from] web_transport_proto::SettingsError),

    #[error("WebTransport is not supported")]
    WebTransportUnsupported,

    #[error("connection error: {0}")]
    ConnectionError(#[from] s2n_quic::connection::Error),
}

/// Holds the HTTP/3 control streams open for the lifetime of the session.
pub struct Settings {
    #[allow(dead_code)]
    send: s2n_quic::stream::SendStream,

    #[allow(dead_code)]
    recv: s2n_quic::stream::ReceiveStream,
}

impl Settings {
    /// Perform the H3 SETTINGS handshake by sending and receiving SETTINGS frames.
    pub async fn connect(
        handle: &mut Handle,
        acceptor: &mut StreamAcceptor,
    ) -> Result<Self, SettingsError> {
        let send = Self::open(handle);
        let recv = Self::accept(acceptor);

        // Run both concurrently until one errors or they both complete.
        let (send, recv) = try_join!(send, recv)?;
        Ok(Self { send, recv })
    }

    async fn accept(
        acceptor: &mut StreamAcceptor,
    ) -> Result<s2n_quic::stream::ReceiveStream, SettingsError> {
        let mut recv = acceptor
            .accept_receive_stream()
            .await?
            .ok_or(SettingsError::UnexpectedEnd)?;

        let settings = web_transport_proto::Settings::read(&mut recv).await?;
        tracing::debug!(?settings, "received SETTINGS frame");

        if settings.supports_webtransport() == 0 {
            return Err(SettingsError::WebTransportUnsupported);
        }

        Ok(recv)
    }

    async fn open(handle: &mut Handle) -> Result<s2n_quic::stream::SendStream, SettingsError> {
        let mut settings = web_transport_proto::Settings::default();
        settings.enable_webtransport(1);

        tracing::debug!(?settings, "sending SETTINGS frame");

        let mut send = handle.open_send_stream().await?;
        settings.write(&mut send).await?;

        Ok(send)
    }
}

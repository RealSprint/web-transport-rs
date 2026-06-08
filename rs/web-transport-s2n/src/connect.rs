use std::ops::Deref;

use s2n_quic::connection::{Handle, StreamAcceptor};
use thiserror::Error;
use web_transport_proto::{ConnectRequest, ConnectResponse, VarInt};

#[derive(Error, Debug, Clone)]
pub enum ConnectError {
    #[error("quic stream was closed early")]
    UnexpectedEnd,

    #[error("protocol error: {0}")]
    ProtoError(#[from] web_transport_proto::ConnectError),

    #[error("connection error: {0}")]
    ConnectionError(#[from] s2n_quic::connection::Error),

    #[error("http error status: {0}")]
    ErrorStatus(http::StatusCode),

    #[error("server returned protocol not in request: {0}")]
    ProtocolMismatch(String),
}

/// An HTTP/3 CONNECT request that has been received but not yet responded to.
pub struct Connecting {
    pub request: ConnectRequest,

    pub(crate) send: s2n_quic::stream::SendStream,
    pub(crate) recv: s2n_quic::stream::ReceiveStream,
}

impl Connecting {
    /// Accept the bidirectional stream carrying the client's CONNECT request.
    pub async fn accept(acceptor: &mut StreamAcceptor) -> Result<Self, ConnectError> {
        let stream = acceptor
            .accept_bidirectional_stream()
            .await?
            .ok_or(ConnectError::UnexpectedEnd)?;

        let (mut recv, send) = stream.split();

        let request = web_transport_proto::ConnectRequest::read(&mut recv).await?;
        tracing::debug!(?request, "received CONNECT request");

        Ok(Self {
            request,
            send,
            recv,
        })
    }

    /// Send a response to the client, establishing the session.
    pub async fn respond(
        mut self,
        response: impl Into<ConnectResponse>,
    ) -> Result<Connected, ConnectError> {
        let response = response.into();

        // Validate that our protocol was in the client's request.
        if let Some(protocol) = &response.protocol {
            if !self.request.protocols.contains(protocol) {
                return Err(ConnectError::ProtocolMismatch(protocol.clone()));
            }
        }

        tracing::debug!(?response, "sending CONNECT response");
        response.write(&mut self.send).await?;

        Ok(Connected {
            request: self.request,
            response,
            send: self.send,
            recv: self.recv,
        })
    }

    pub async fn reject(self, status: http::StatusCode) -> Result<(), ConnectError> {
        let mut connect = self.respond(status).await?;
        connect.send.finish().ok();
        Ok(())
    }
}

impl Deref for Connecting {
    type Target = ConnectRequest;

    fn deref(&self) -> &Self::Target {
        &self.request
    }
}

pub struct Connected {
    pub request: ConnectRequest,
    pub response: ConnectResponse,

    pub(crate) send: s2n_quic::stream::SendStream,
    pub(crate) recv: s2n_quic::stream::ReceiveStream,
}

impl Connected {
    /// Open a new WebTransport session on the given connection for the given request.
    pub async fn open(
        handle: &mut Handle,
        request: impl Into<ConnectRequest>,
    ) -> Result<Self, ConnectError> {
        let request = request.into();

        let stream = handle.open_bidirectional_stream().await?;
        let (mut recv, mut send) = stream.split();

        tracing::debug!(?request, "sending CONNECT request");
        request.write(&mut send).await?;

        let response = web_transport_proto::ConnectResponse::read(&mut recv).await?;
        tracing::debug!(?response, "received CONNECT response");

        if response.status != http::StatusCode::OK {
            return Err(ConnectError::ErrorStatus(response.status));
        }

        if let Some(protocol) = &response.protocol {
            if !request.protocols.contains(protocol) {
                return Err(ConnectError::ProtocolMismatch(protocol.clone()));
            }
        }

        Ok(Self {
            request,
            response,
            send,
            recv,
        })
    }

    /// The session ID is the stream ID of the CONNECT request.
    pub fn session_id(&self) -> VarInt {
        VarInt::try_from(self.send.id()).expect("stream id out of varint range")
    }
}

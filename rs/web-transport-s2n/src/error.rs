use thiserror::Error;

use crate::{ConnectError, SettingsError};

/// An error returned when connecting to a WebTransport endpoint.
#[derive(Error, Debug, Clone)]
pub enum ClientError {
    #[error("unexpected end of stream")]
    UnexpectedEnd,

    #[error("connection error: {0}")]
    Connection(#[from] s2n_quic::connection::Error),

    #[error("failed to exchange h3 settings: {0}")]
    SettingsError(#[from] SettingsError),

    #[error("failed to exchange h3 connect: {0}")]
    HttpError(#[from] ConnectError),

    #[error("invalid DNS name: {0}")]
    InvalidDnsName(String),

    #[error("failed to build endpoint: {0}")]
    Build(String),

    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),
}

/// Errors returned by [`crate::Session`], split based on whether they are underlying QUIC errors
/// or WebTransport errors.
#[derive(Clone, Error, Debug)]
pub enum SessionError {
    #[error("connection error: {0}")]
    ConnectionError(s2n_quic::connection::Error),

    #[error("webtransport error: {0}")]
    WebTransportError(#[from] WebTransportError),

    #[error("send datagram error: {0}")]
    SendDatagram(#[from] SendDatagramError),

    #[error("locally closed")]
    LocallyClosed,
}

impl From<s2n_quic::connection::Error> for SessionError {
    fn from(e: s2n_quic::connection::Error) -> Self {
        if let s2n_quic::connection::Error::Application { error, .. } = &e {
            // An application close carries an HTTP/3 error code, but no reason on the wire.
            // The reason (if any) arrives via the CloseWebTransportSession capsule, which the
            // session's background task records separately.
            if let Some(code) = web_transport_proto::error_from_http3(u64::from(*error)) {
                return WebTransportError::Closed(code, String::new()).into();
            }
        }
        SessionError::ConnectionError(e)
    }
}

/// An error sending an application datagram.
#[derive(Clone, Error, Debug)]
pub enum SendDatagramError {
    #[error("datagram larger than peer's transport limits")]
    TooLarge,

    #[error("datagram send queue is at capacity")]
    QueueAtCapacity,
}

/// An error reading/writing the WebTransport stream header, or a session-level close.
#[derive(Clone, Error, Debug)]
pub enum WebTransportError {
    #[error("closed: code={0} reason={1}")]
    Closed(u32, String),

    #[error("unknown session")]
    UnknownSession,

    #[error("stream error: {0}")]
    StreamError(s2n_quic::stream::Error),
}

impl From<s2n_quic::stream::Error> for WebTransportError {
    fn from(e: s2n_quic::stream::Error) -> Self {
        WebTransportError::StreamError(e)
    }
}

/// An error when writing to [`crate::SendStream`].
#[derive(Clone, Error, Debug)]
pub enum WriteError {
    #[error("STOP_SENDING: {0}")]
    Stopped(u32),

    #[error("invalid STOP_SENDING: {0}")]
    InvalidStopped(u64),

    #[error("session error: {0}")]
    SessionError(#[from] SessionError),

    #[error("stream closed")]
    ClosedStream,
}

impl From<s2n_quic::stream::Error> for WriteError {
    fn from(e: s2n_quic::stream::Error) -> Self {
        match e {
            s2n_quic::stream::Error::StreamReset { error, .. } => {
                match web_transport_proto::error_from_http3(u64::from(error)) {
                    Some(code) => WriteError::Stopped(code),
                    None => WriteError::InvalidStopped(u64::from(error)),
                }
            }
            s2n_quic::stream::Error::ConnectionError { error, .. } => {
                WriteError::SessionError(error.into())
            }
            _ => WriteError::ClosedStream,
        }
    }
}

/// An error when reading from [`crate::RecvStream`].
#[derive(Clone, Error, Debug)]
pub enum ReadError {
    #[error("session error: {0}")]
    SessionError(#[from] SessionError),

    #[error("RESET_STREAM: {0}")]
    Reset(u32),

    #[error("invalid RESET_STREAM: {0}")]
    InvalidReset(u64),

    #[error("stream closed")]
    ClosedStream,
}

impl From<s2n_quic::stream::Error> for ReadError {
    fn from(e: s2n_quic::stream::Error) -> Self {
        match e {
            s2n_quic::stream::Error::StreamReset { error, .. } => {
                match web_transport_proto::error_from_http3(u64::from(error)) {
                    Some(code) => ReadError::Reset(code),
                    None => ReadError::InvalidReset(u64::from(error)),
                }
            }
            s2n_quic::stream::Error::ConnectionError { error, .. } => {
                ReadError::SessionError(error.into())
            }
            _ => ReadError::ClosedStream,
        }
    }
}

/// An error returned when accepting a new WebTransport session on the server.
#[derive(Error, Debug, Clone)]
pub enum ServerError {
    #[error("unexpected end of stream")]
    UnexpectedEnd,

    #[error("connection error: {0}")]
    Connection(#[from] s2n_quic::connection::Error),

    #[error("failed to exchange h3 settings: {0}")]
    SettingsError(#[from] SettingsError),

    #[error("failed to exchange h3 connect: {0}")]
    ConnectError(#[from] ConnectError),

    #[error("failed to build endpoint: {0}")]
    Build(String),

    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),

    #[error("h3/WebTransport handshake timed out")]
    HandshakeTimeout,
}

/// `H3_NO_ERROR` (RFC 9114, section 8.1).
const H3_NO_ERROR: u64 = 0x0100;

impl ServerError {
    /// Whether the connection ended without an error before a CONNECT request
    /// arrived: a close with no error code, or the idle timer expiring.
    ///
    /// This is what a peer that only checks QUIC reachability looks like, as
    /// opposed to a protocol error or a close carrying an error code.
    pub fn is_abandoned(&self) -> bool {
        match self {
            // s2n reports a clean close or an idle timeout as end-of-stream on
            // the stream acceptors, which the handshake maps to `UnexpectedEnd`.
            Self::UnexpectedEnd
            | Self::SettingsError(SettingsError::UnexpectedEnd)
            | Self::ConnectError(ConnectError::UnexpectedEnd) => true,
            Self::Connection(error)
            | Self::SettingsError(SettingsError::ConnectionError(error))
            | Self::ConnectError(ConnectError::ConnectionError(error)) => is_clean_close(error),
            _ => false,
        }
    }
}

fn is_clean_close(error: &s2n_quic::connection::Error) -> bool {
    use s2n_quic::connection::Error;
    match error {
        Error::Closed { .. } | Error::IdleTimerExpired { .. } => true,
        Error::Application { error, .. } => matches!(u64::from(*error), 0 | H3_NO_ERROR),
        Error::Transport { code, .. } => code.as_u64() == 0,
        _ => false,
    }
}

impl web_transport_trait::Error for SessionError {
    fn session_error(&self) -> Option<(u32, String)> {
        if let SessionError::WebTransportError(WebTransportError::Closed(code, reason)) = self {
            return Some((*code, reason.to_string()));
        }
        None
    }
}

impl web_transport_trait::Error for WriteError {
    fn session_error(&self) -> Option<(u32, String)> {
        if let WriteError::SessionError(e) = self {
            return e.session_error();
        }
        None
    }

    fn stream_error(&self) -> Option<u32> {
        match self {
            WriteError::Stopped(code) => Some(*code),
            _ => None,
        }
    }
}

impl web_transport_trait::Error for ReadError {
    fn session_error(&self) -> Option<(u32, String)> {
        if let ReadError::SessionError(e) = self {
            return e.session_error();
        }
        None
    }

    fn stream_error(&self) -> Option<u32> {
        match self {
            ReadError::Reset(code) => Some(*code),
            _ => None,
        }
    }
}

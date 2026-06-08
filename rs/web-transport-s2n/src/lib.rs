//! WebTransport is a protocol for client-server communication over QUIC.
//! It's [available in the browser](https://caniuse.com/webtransport) as an alternative to HTTP and WebSockets.
//!
//! WebTransport is layered on top of HTTP/3 which is then layered on top of QUIC.
//! This crate implements that layering on top of [s2n-quic](https://github.com/aws/s2n-quic),
//! exposing an API that mirrors the other `web-transport-*` backends and implements
//! the [`web_transport_trait`] interface.
//!
//! # Limitations
//! Like the other backends in this workspace, this crate does the bare minimum to support a
//! single WebTransport session that owns the entire QUIC connection. It does not support
//! pooling multiple sessions (or HTTP/3) over the same connection.
//!
//! s2n-quic differs from Quinn in a few ways that affect this crate:
//!   - TLS is configured via a [`s2n_quic::provider::tls::Provider`]; we build one from rustls.
//!   - Streams have no priority knob, so [`SendStream::set_priority`] is a no-op.
//!   - Datagram support requires the (unstable) default datagram provider, enabled here.

// External
mod client;
mod error;
mod recv;
mod send;
mod server;
mod session;
mod tls;

pub use client::*;
pub use error::*;
pub use recv::*;
pub use send::*;
pub use server::*;
pub use session::*;

// Internal
mod connect;
mod settings;

use connect::*;
use settings::*;

// Required to access the wrapped proto ConnectError.
pub use connect::ConnectError;

/// The HTTP/3 ALPN is required when negotiating a QUIC connection.
pub const ALPN: &str = "h3";

/// Simple rustls crypto provider utilities.
pub mod crypto;

/// Re-export the underlying QUIC implementation.
pub use s2n_quic;

/// Re-export the http crate because it's in the public API.
pub use http;

/// Re-export the generic WebTransport trait.
pub use web_transport_trait as generic;

/// Re-export the WebTransport protocol implementation.
pub use web_transport_proto as proto;

/// Convert a WebTransport `u32` error code into an s2n-quic application error code,
/// mapping it into the reserved HTTP/3 error space.
pub(crate) fn app_error(code: u32) -> s2n_quic::application::Error {
    s2n_quic::application::Error::try_from(web_transport_proto::error_to_http3(code))
        .expect("http3 error code out of range")
}

/// The send/receive queue depth for the datagram provider.
const DATAGRAM_QUEUE_CAPACITY: usize = 1024;

/// Build the default datagram provider endpoint with send and receive queues enabled.
pub(crate) fn datagram_endpoint() -> s2n_quic::provider::datagram::default::Endpoint {
    s2n_quic::provider::datagram::default::Endpoint::builder()
        .with_send_capacity(DATAGRAM_QUEUE_CAPACITY)
        .expect("valid send capacity")
        .with_recv_capacity(DATAGRAM_QUEUE_CAPACITY)
        .expect("valid recv capacity")
        .build()
        .expect("infallible datagram endpoint build")
}

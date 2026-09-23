//! End-to-end tests: an in-process s2n-quic WebTransport server and client exchanging
//! streams, datagrams, and a graceful close.

use std::time::Duration;

use bytes::{Buf, Bytes};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use url::Url;
use web_transport_s2n::{
    crypto, s2n_quic, ClientBuilder, RecvStream, Server, ServerBuilder, Session, SessionError,
    WebTransportError, ALPN,
};

/// Spin up a server + client on loopback and return both ends of an established session.
/// The [`web_transport_s2n::Server`] is returned so the caller keeps the endpoint alive.
async fn connect() -> (Session, Session, web_transport_s2n::Server) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    let server = ServerBuilder::new()
        .with_addr("127.0.0.1:0".parse().unwrap())
        .with_certificate(vec![cert_der.clone()], key_der)
        .unwrap();
    let addr = server.local_addr().unwrap();

    let client = ClientBuilder::new()
        .with_server_certificates(vec![cert_der])
        .unwrap();

    let accept = tokio::spawn(async move {
        let mut server = server;
        let request = server.accept().await.expect("server accept");
        let session = request.ok().await.expect("server respond");
        (session, server)
    });

    let url = Url::parse(&format!("https://127.0.0.1:{}/", addr.port())).unwrap();
    let client_session = client.connect(url).await.expect("client connect");

    let (server_session, server) = accept.await.unwrap();
    (client_session, server_session, server)
}

async fn read_all(recv: &mut RecvStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    while let Some(n) = recv.read(&mut buf).await.unwrap() {
        out.extend_from_slice(&buf[..n]);
    }
    out
}

#[tokio::test]
async fn bidirectional_echo() {
    let (client, server, _guard) = connect().await;

    let server_task = tokio::spawn(async move {
        let (mut send, mut recv) = server.accept_bi().await.unwrap();
        let data = read_all(&mut recv).await;
        send.write_all(&data).await.unwrap();
        send.finish().unwrap();
    });

    let (mut send, mut recv) = client.open_bi().await.unwrap();
    send.write_all(b"hello webtransport").await.unwrap();
    send.finish().unwrap();

    let echoed = read_all(&mut recv).await;
    assert_eq!(echoed, b"hello webtransport");

    server_task.await.unwrap();
}

#[tokio::test]
async fn unidirectional() {
    let (client, server, _guard) = connect().await;

    let server_task = tokio::spawn(async move {
        let mut recv = server.accept_uni().await.unwrap();
        read_all(&mut recv).await
    });

    let mut send = client.open_uni().await.unwrap();
    send.write_all(b"one way").await.unwrap();
    send.finish().unwrap();

    let got = server_task.await.unwrap();
    assert_eq!(got, b"one way");
}

#[tokio::test]
async fn datagrams() {
    let (client, server, _guard) = connect().await;

    // Datagrams are unreliable, so keep sending until one arrives.
    let sender = tokio::spawn(async move {
        loop {
            let _ = client.send_datagram(Bytes::from_static(b"datagram"));
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    let got = tokio::time::timeout(Duration::from_secs(5), server.read_datagram())
        .await
        .expect("datagram timeout")
        .unwrap();
    sender.abort();

    assert_eq!(&got[..], b"datagram");
}

#[tokio::test]
async fn graceful_close() {
    let (client, server, _guard) = connect().await;

    client.close(42, b"goodbye");

    let err = tokio::time::timeout(Duration::from_secs(5), server.closed())
        .await
        .expect("close timeout");

    match err {
        SessionError::WebTransportError(WebTransportError::Closed(code, reason)) => {
            assert_eq!(code, 42);
            assert_eq!(reason, "goodbye");
        }
        other => panic!("unexpected close error: {other:?}"),
    }
}

/// Fill a stream until it stops accepting data, so the next write has to wait.
async fn fill_until_blocked(send: &mut web_transport_s2n::SendStream) {
    let chunk = Bytes::from(vec![0u8; 64 * 1024]);
    for _ in 0..2048 {
        if tokio::time::timeout(Duration::from_millis(200), send.write_chunk(chunk.clone()))
            .await
            .is_err()
        {
            return;
        }
    }
    panic!("stream never stopped accepting data");
}

#[tokio::test]
async fn a_cancelled_write_buf_leaves_the_buffer_unadvanced() {
    let (client, _server, _guard) = connect().await;

    // The peer never reads, so the stream runs out of send capacity and stays there.
    let mut send = client.open_uni().await.expect("open uni");
    fill_until_blocked(&mut send).await;

    let mut buf = Bytes::from(vec![0xab; 4096]);
    let remaining = buf.remaining();

    let result = tokio::time::timeout(Duration::from_millis(200), send.write_buf(&mut buf)).await;

    assert!(result.is_err(), "write_buf resolved on a blocked stream");
    assert_eq!(
        buf.remaining(),
        remaining,
        "a dropped write_buf consumed bytes it never sent"
    );
}

/// Hands s2n-quic a pre-built rustls server config, so a test can set connection
/// limits that [`ServerBuilder`] does not expose.
struct ServerTls {
    config: rustls::ServerConfig,
}

impl s2n_quic::provider::tls::Provider for ServerTls {
    type Server = s2n_quic::provider::tls::rustls::Server;
    type Client = s2n_quic::provider::tls::rustls::Client;
    type Error = rustls::Error;

    fn start_server(self) -> Result<Self::Server, Self::Error> {
        Ok(self.config.into())
    }

    fn start_client(self) -> Result<Self::Client, Self::Error> {
        Err(rustls::Error::General("server-only".into()))
    }
}

/// A server whose connections idle out after `idle_timeout`, plus the certificate a
/// client needs to reach it.
fn server_with_idle_timeout(idle_timeout: Duration) -> (Server, CertificateDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    let mut config = rustls::ServerConfig::builder_with_provider(crypto::default_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    config.alpn_protocols = vec![ALPN.as_bytes().to_vec()];

    let limits = s2n_quic::provider::limits::Limits::default()
        .with_max_idle_timeout(idle_timeout)
        .unwrap();

    let datagrams = s2n_quic::provider::datagram::default::Endpoint::builder()
        .with_send_capacity(64)
        .unwrap()
        .with_recv_capacity(64)
        .unwrap()
        .build()
        .unwrap();

    let endpoint = s2n_quic::Server::builder()
        .with_tls(ServerTls { config })
        .unwrap()
        .with_io("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .with_datagram(datagrams)
        .unwrap()
        .with_limits(limits)
        .unwrap()
        .start()
        .unwrap();

    (Server::new(endpoint), cert_der)
}

/// A peer that vanishes without closing: the connection ends on the idle timer, which
/// s2n reports as end-of-stream rather than as an error. A parked accept has to be
/// failed explicitly or it waits forever.
#[tokio::test]
async fn accept_bi_fails_once_the_connection_times_out() {
    let (mut server, cert_der) = server_with_idle_timeout(Duration::from_millis(500));
    let addr = server.local_addr().unwrap();
    let url = Url::parse(&format!("https://127.0.0.1:{}/", addr.port())).unwrap();

    let accept = tokio::spawn(async move {
        let request = server.accept().await.expect("server accept");
        let session = request.ok().await.expect("server respond");
        session.accept_bi().await
    });

    // Establish the session on its own runtime, then drop that runtime so the peer
    // stops responding without ever sending a close.
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let session = runtime.block_on(async move {
            let client = ClientBuilder::new()
                .with_server_certificates(vec![cert_der])
                .unwrap();
            client.connect(url).await.expect("client connect")
        });
        std::mem::forget(session);
        runtime.shutdown_background();
    });

    let result = tokio::time::timeout(Duration::from_secs(10), accept)
        .await
        .expect("accept_bi never resolved after the connection timed out")
        .expect("accept task panicked");

    assert!(result.is_err(), "expected an error, accepted a stream");
}

#[tokio::test]
async fn accept_uni_fails_once_the_connection_times_out() {
    let (mut server, cert_der) = server_with_idle_timeout(Duration::from_millis(500));
    let addr = server.local_addr().unwrap();
    let url = Url::parse(&format!("https://127.0.0.1:{}/", addr.port())).unwrap();

    let accept = tokio::spawn(async move {
        let request = server.accept().await.expect("server accept");
        let session = request.ok().await.expect("server respond");
        session.accept_uni().await
    });

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let session = runtime.block_on(async move {
            let client = ClientBuilder::new()
                .with_server_certificates(vec![cert_der])
                .unwrap();
            client.connect(url).await.expect("client connect")
        });
        std::mem::forget(session);
        runtime.shutdown_background();
    });

    let result = tokio::time::timeout(Duration::from_secs(10), accept)
        .await
        .expect("accept_uni never resolved after the connection timed out")
        .expect("accept task panicked");

    assert!(result.is_err(), "expected an error, accepted a stream");
}

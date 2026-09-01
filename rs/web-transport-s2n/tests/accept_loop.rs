//! Accept-loop tests against real loopback endpoints: peers that finish the
//! QUIC handshake and then never speak H3, a consumer that stops polling
//! `accept`, and a connect burst larger than the in-flight cap.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use url::Url;
use web_transport_s2n::{
    s2n_quic, ClientBuilder, HandshakeCounters, HandshakeLimits, HandshakeStats, Request, Server,
    ServerBuilder, ALPN,
};

/// Hands s2n-quic a pre-built rustls client config (the crate's own provider is
/// private). Used for peers that complete QUIC but never open the H3 control
/// stream, so the server's handshake for them stalls.
struct StallTls {
    config: rustls::ClientConfig,
}

impl s2n_quic::provider::tls::Provider for StallTls {
    type Server = s2n_quic::provider::tls::rustls::Server;
    type Client = s2n_quic::provider::tls::rustls::Client;
    type Error = rustls::Error;

    fn start_server(self) -> Result<Self::Server, Self::Error> {
        Err(rustls::Error::General("client-only".into()))
    }

    fn start_client(self) -> Result<Self::Client, Self::Error> {
        Ok(self.config.into())
    }
}

struct Harness {
    server: Option<Server>,
    counters: Arc<HandshakeCounters>,
    url: Url,
    addr: std::net::SocketAddr,
    cert: CertificateDer<'static>,
    stall: s2n_quic::Client,
}

impl Harness {
    fn new(limits: HandshakeLimits) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

        let server = ServerBuilder::new()
            .with_addr("127.0.0.1:0".parse().unwrap())
            .with_handshake_limits(limits)
            .with_certificate(vec![cert_der.clone()], key_der)
            .unwrap();
        let addr = server.local_addr().unwrap();
        let counters = server.handshake_counters();
        let url = Url::parse(&format!("https://127.0.0.1:{}/", addr.port())).unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der.clone()).unwrap();
        let provider = web_transport_s2n::crypto::default_provider();
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![ALPN.as_bytes().to_vec()];
        let stall = s2n_quic::Client::builder()
            .with_tls(StallTls { config })
            .unwrap()
            .with_io("127.0.0.1:0")
            .unwrap()
            .start()
            .unwrap();

        Self {
            server: Some(server),
            counters,
            url,
            addr,
            cert: cert_der,
            stall,
        }
    }

    /// Run `Server::accept` in a task, handing out completed requests over a channel.
    fn spawn_accept(&mut self) -> tokio::sync::mpsc::UnboundedReceiver<Request> {
        let mut server = self.server.take().expect("accept task already spawned");
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(request) = server.accept().await {
                if tx.send(request).is_err() {
                    break;
                }
            }
        });
        rx
    }

    /// A peer that completes the QUIC handshake and then never opens a stream.
    async fn stalled_peer(&self) -> s2n_quic::Connection {
        let connect = s2n_quic::client::Connect::new(self.addr).with_server_name("localhost");
        self.stall
            .connect(connect)
            .await
            .expect("stalled peer quic handshake")
    }

    fn real_client(&self) -> web_transport_s2n::Client {
        ClientBuilder::new()
            .with_server_certificates(vec![self.cert.clone()])
            .unwrap()
    }

    /// Poll the counters until `pred` holds or `deadline` elapses.
    async fn wait_for(
        &self,
        deadline: Duration,
        pred: impl Fn(&HandshakeStats) -> bool,
    ) -> HandshakeStats {
        let start = tokio::time::Instant::now();
        loop {
            let stats = self.counters.snapshot();
            if pred(&stats) {
                return stats;
            }
            assert!(
                start.elapsed() < deadline,
                "condition not met within {deadline:?}; last stats: {stats:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

#[tokio::test]
async fn stalled_handshakes_time_out_and_free_their_slots() {
    let limits = HandshakeLimits {
        max_inflight: 2,
        timeout: Duration::from_millis(300),
    };
    let mut h = Harness::new(limits);
    let mut requests = h.spawn_accept();

    let _a = h.stalled_peer().await;
    let _b = h.stalled_peer().await;
    let stats = h
        .wait_for(Duration::from_secs(2), |s| s.inflight == 2)
        .await;
    assert_eq!(stats.admitted, 2);

    // Both slots must be freed by the timeout, not by anything the peers did.
    let stats = h
        .wait_for(Duration::from_secs(2), |s| s.timed_out == 2)
        .await;
    assert_eq!(stats.inflight, 0);
    assert_eq!(stats.rejected, 0);

    // With the slots free again, a real session goes through. The client's
    // connect blocks on the server's CONNECT response, so drive it from a
    // background task while the foreground responds to the completed request.
    let client = h.real_client();
    let url = h.url.clone();
    let connect = tokio::spawn(async move { client.connect(url).await });
    let request = tokio::time::timeout(Duration::from_secs(5), requests.recv())
        .await
        .expect("request not yielded in time")
        .expect("server yields the request");
    let server_session = request.ok().await.expect("server responds");
    let session = tokio::time::timeout(Duration::from_secs(5), connect)
        .await
        .expect("connect timed out")
        .unwrap()
        .expect("connect after slots freed");
    drop(server_session);
    drop(session);
    let stats = h
        .wait_for(Duration::from_secs(2), |s| s.completed == 1)
        .await;
    assert_eq!(stats.inflight_high_water, 2);
}

#[tokio::test]
async fn connections_over_the_cap_are_rejected_until_a_slot_frees() {
    let limits = HandshakeLimits {
        max_inflight: 1,
        timeout: Duration::from_secs(10),
    };
    let mut h = Harness::new(limits);
    let mut requests = h.spawn_accept();

    let occupant = h.stalled_peer().await;
    h.wait_for(Duration::from_secs(2), |s| s.inflight == 1)
        .await;

    // The set is full: a real client is closed on arrival rather than queued.
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        h.real_client().connect(h.url.clone()),
    )
    .await;
    // `Session` isn't `Debug`; project to something printable for the assert message.
    let outcome = result.as_ref().map(|r| r.is_ok());
    assert!(
        matches!(result, Ok(Err(_))),
        "connect must fail while the set is full, got {outcome:?}"
    );
    let stats = h
        .wait_for(Duration::from_secs(2), |s| s.rejected == 1)
        .await;
    assert_eq!(stats.inflight, 1, "rejection must not touch the driven set");
    assert!(
        requests.try_recv().is_err(),
        "no request may reach the application"
    );

    // The occupant leaving frees the slot without waiting for the timeout.
    occupant.close(s2n_quic::application::Error::new(0).unwrap());
    let stats = h.wait_for(Duration::from_secs(5), |s| s.failed == 1).await;
    assert_eq!(stats.inflight, 0);
    assert_eq!(stats.timed_out, 0);

    let client = h.real_client();
    let url = h.url.clone();
    let connect = tokio::spawn(async move { client.connect(url).await });
    let request = tokio::time::timeout(Duration::from_secs(5), requests.recv())
        .await
        .expect("request not yielded in time")
        .expect("server yields the request");
    let server_session = request.ok().await.expect("server responds");
    let _session = tokio::time::timeout(Duration::from_secs(5), connect)
        .await
        .expect("connect timed out")
        .unwrap()
        .expect("connect after the occupant left");
    drop(server_session);
    h.wait_for(Duration::from_secs(2), |s| s.completed == 1)
        .await;
}

#[tokio::test]
async fn a_paused_consumer_drains_its_backlog_without_exceeding_the_cap() {
    let limits = HandshakeLimits {
        max_inflight: 4,
        timeout: Duration::from_secs(10),
    };
    let mut h = Harness::new(limits);

    // Nobody polls `accept` yet: the endpoint's own queue fills with finished
    // QUIC handshakes.
    let mut peers = Vec::new();
    for _ in 0..8 {
        peers.push(h.stalled_peer().await);
    }
    assert_eq!(h.counters.snapshot(), HandshakeStats::default());

    let mut requests = h.spawn_accept();
    let stats = h
        .wait_for(Duration::from_secs(5), |s| s.admitted + s.rejected == 8)
        .await;
    assert_eq!(stats.admitted, 4);
    assert_eq!(stats.rejected, 4);
    assert_eq!(stats.inflight, 4);
    assert_eq!(stats.inflight_high_water, 4);

    // Releasing the backlog frees every slot; a real session then completes.
    // `Connection::drop` alone only flushes gracefully and never notifies the
    // peer within the handshake timeout, so close explicitly (as the occupant
    // does in the cap test above).
    for peer in peers.drain(..) {
        peer.close(s2n_quic::application::Error::new(0).unwrap());
    }
    let stats = h.wait_for(Duration::from_secs(5), |s| s.failed == 4).await;
    assert_eq!(stats.inflight, 0);

    let client = h.real_client();
    let url = h.url.clone();
    let connect = tokio::spawn(async move { client.connect(url).await });
    let request = tokio::time::timeout(Duration::from_secs(5), requests.recv())
        .await
        .expect("request not yielded in time")
        .expect("server yields the request");
    let server_session = request.ok().await.expect("server responds");
    let _session = tokio::time::timeout(Duration::from_secs(5), connect)
        .await
        .expect("connect timed out")
        .unwrap()
        .expect("connect after the backlog cleared");
    drop(server_session);
}

#[tokio::test]
async fn completions_are_returned_while_a_burst_is_being_dequeued() {
    let limits = HandshakeLimits {
        max_inflight: 64,
        timeout: Duration::from_secs(10),
    };
    let mut h = Harness::new(limits);
    let mut requests = h.spawn_accept();

    // A real client connects in the middle of a burst of stalled peers. Its
    // handshake must be returned while the loop is still busy dequeuing.
    let mut peers = Vec::new();
    for _ in 0..20 {
        peers.push(h.stalled_peer().await);
    }
    let client = h.real_client();
    let url = h.url.clone();
    let real = tokio::spawn(async move { client.connect(url).await });
    for _ in 0..20 {
        peers.push(h.stalled_peer().await);
    }

    let request = tokio::time::timeout(Duration::from_secs(5), requests.recv())
        .await
        .expect("request not yielded while the burst was being dequeued")
        .expect("accept loop alive");
    let server_session = request.ok().await.expect("server responds");
    let _session = real
        .await
        .unwrap()
        .expect("real client connects during the burst");
    drop(server_session);

    let stats = h
        .wait_for(Duration::from_secs(2), |s| {
            s.completed == 1 && s.admitted == 41
        })
        .await;
    assert_eq!(stats.rejected, 0, "cap of 64 must admit the whole burst");
    assert_eq!(stats.admitted, 41);
    assert!(
        stats.inflight_high_water >= 2,
        "the burst must have overlapped in the driven set"
    );
    drop(peers);
}

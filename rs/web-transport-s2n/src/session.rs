use std::{
    future::poll_fn,
    io::Cursor,
    pin::Pin,
    sync::{Arc, Mutex, OnceLock},
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use futures::stream::{FuturesUnordered, StreamExt};
use s2n_quic::{
    connection::{BidirectionalStreamAcceptor, Handle, ReceiveStreamAcceptor, StreamAcceptor},
    provider::datagram::default::{Receiver, Sender},
};
use tokio::sync::watch;

use crate::{
    app_error,
    proto::{ConnectRequest, ConnectResponse, Frame, StreamUni, VarInt},
    ClientError, Connected, RecvStream, SendDatagramError, SendStream, SessionError, Settings,
    WebTransportError,
};

/// A conservative datagram payload limit, using the QUIC minimum guaranteed datagram
/// size rather than the peer's actual negotiated limit (available via
/// `Sender::max_packet_space()` on the datagram provider, not read here).
const DEFAULT_MAX_DATAGRAM_SIZE: usize = 1200;

/// An established WebTransport session, acting like a QUIC connection.
///
/// WebTransport is layered on top of QUIC:
///   1. Each stream starts with a few bytes identifying the stream type and session ID.
///   2. Error codes are encoded within a reserved HTTP/3 error space.
///   3. Stream IDs may have gaps, used by HTTP/3 transparently to the application.
#[derive(Clone)]
pub struct Session {
    handle: Handle,

    // The session ID, as determined by the stream ID of the CONNECT request.
    session_id: VarInt,

    // The accept logic is stateful, so share it via Arc<Mutex>.
    accept: Arc<Mutex<SessionAccept>>,

    // Cached headers written in front of each stream/datagram we create.
    header_uni: Vec<u8>,
    header_bi: Vec<u8>,
    header_datagram: Vec<u8>,

    // Keep the settings streams open until the session is dropped.
    #[allow(dead_code)]
    settings: Arc<Settings>,

    // The send side of the CONNECT stream, used to write the CloseWebTransportSession capsule.
    connect_send: Arc<Mutex<Option<s2n_quic::stream::SendStream>>>,

    // Session error, set once by either local close() or the background task.
    error: Arc<OnceLock<SessionError>>,

    // Signalled to `true` when the session has closed; drives `closed()`.
    closed_rx: watch::Receiver<bool>,

    request: ConnectRequest,
    response: ConnectResponse,
}

impl Session {
    pub(crate) fn new(
        handle: Handle,
        acceptor: StreamAcceptor,
        settings: Settings,
        connect: Connected,
    ) -> Self {
        let session_id = connect.session_id();

        let mut header_uni = Vec::new();
        StreamUni::WEBTRANSPORT.encode(&mut header_uni);
        session_id.encode(&mut header_uni);

        let mut header_bi = Vec::new();
        Frame::WEBTRANSPORT.encode(&mut header_bi);
        session_id.encode(&mut header_bi);

        let mut header_datagram = Vec::new();
        session_id.encode(&mut header_datagram);

        let error: Arc<OnceLock<SessionError>> = Arc::new(OnceLock::new());
        let (closed_tx, closed_rx) = watch::channel(false);

        let accept = SessionAccept::new(acceptor, session_id, error.clone());

        let this = Self {
            handle: handle.clone(),
            accept: Arc::new(Mutex::new(accept)),
            session_id,
            header_uni,
            header_bi,
            header_datagram,
            settings: Arc::new(settings),
            connect_send: Arc::new(Mutex::new(Some(connect.send))),
            error: error.clone(),
            closed_rx,
            request: connect.request.clone(),
            response: connect.response.clone(),
        };

        // Background task: read capsules from the CONNECT recv stream until it closes.
        tokio::spawn(Self::run_recv(handle, connect.recv, error, closed_tx));

        this
    }

    /// Connect using an established QUIC connection.
    ///
    /// This only works with a brand new QUIC connection using the HTTP/3 ALPN.
    pub async fn connect(
        conn: s2n_quic::Connection,
        request: impl Into<ConnectRequest>,
    ) -> Result<Session, ClientError> {
        let request = request.into();

        let (mut handle, mut acceptor) = conn.split();

        // Perform the H3 handshake by sending/receiving SETTINGS frames.
        let settings = Settings::connect(&mut handle, &mut acceptor).await?;

        // Send the HTTP/3 CONNECT request.
        let connect = Connected::open(&mut handle, request).await?;

        Ok(Session::new(handle, acceptor, settings, connect))
    }

    // Read capsules from the CONNECT recv stream until it closes, then record the close
    // error and tear down the connection.
    async fn run_recv(
        handle: Handle,
        recv: s2n_quic::stream::ReceiveStream,
        error: Arc<OnceLock<SessionError>>,
        closed_tx: watch::Sender<bool>,
    ) {
        let close_info = Self::read_capsules(recv).await;

        match close_info {
            Some((code, reason)) => {
                let err = WebTransportError::Closed(code, reason);
                let _ = error.set(err.into());
                handle.close(app_error(code));
            }
            None => {
                let _ = error.set(SessionError::LocallyClosed);
                handle.close(app_error(0));
            }
        }

        let _ = closed_tx.send(true);
    }

    async fn read_capsules(recv: s2n_quic::stream::ReceiveStream) -> Option<(u32, String)> {
        let mut reader = web_transport_proto::Http3CapsuleReader::new(recv);
        loop {
            match reader.read().await {
                Ok(Some(web_transport_proto::Capsule::CloseWebTransportSession {
                    code,
                    reason,
                })) => return Some((code, reason)),
                Ok(Some(web_transport_proto::Capsule::Grease { .. })) => {}
                Ok(Some(web_transport_proto::Capsule::Unknown { typ, payload })) => {
                    tracing::warn!(%typ, size = payload.len(), "unknown capsule");
                }
                Ok(None) => return None,
                Err(e) => {
                    tracing::warn!(?e, "failed to read capsule");
                    return None;
                }
            }
        }
    }

    /// Accept a new unidirectional stream.
    pub async fn accept_uni(&self) -> Result<RecvStream, SessionError> {
        poll_fn(|cx| self.accept.lock().unwrap().poll_accept_uni(cx))
            .await
            .map_err(|e| self.map_error(e))
    }

    /// Accept a new bidirectional stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), SessionError> {
        poll_fn(|cx| self.accept.lock().unwrap().poll_accept_bi(cx))
            .await
            .map_err(|e| self.map_error(e))
    }

    /// Open a new unidirectional stream.
    pub async fn open_uni(&self) -> Result<SendStream, SessionError> {
        let mut handle = self.handle.clone();
        let mut send = handle
            .open_send_stream()
            .await
            .map_err(SessionError::from)?;

        send.send(Bytes::copy_from_slice(&self.header_uni))
            .await
            .map_err(|e| self.map_stream_error(e))?;

        Ok(SendStream::new(send, self.error.clone()))
    }

    /// Open a new bidirectional stream.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), SessionError> {
        let mut handle = self.handle.clone();
        let stream = handle
            .open_bidirectional_stream()
            .await
            .map_err(SessionError::from)?;
        let (recv, mut send) = stream.split();

        send.send(Bytes::copy_from_slice(&self.header_bi))
            .await
            .map_err(|e| self.map_stream_error(e))?;

        Ok((
            SendStream::new(send, self.error.clone()),
            RecvStream::new(recv, self.error.clone()),
        ))
    }

    /// Receive an application datagram from the peer.
    pub async fn read_datagram(&self) -> Result<Bytes, SessionError> {
        let mut datagram = poll_fn(|cx| {
            match self
                .handle
                .datagram_mut(|recv: &mut Receiver| recv.poll_recv_datagram(cx))
            {
                Ok(poll) => poll.map(|res| res.map_err(Self::map_datagram_error)),
                Err(_) => Poll::Ready(Err(self.closed_error())),
            }
        })
        .await?;

        let mut cursor = Cursor::new(&datagram);

        // Strip and validate the session ID prefix.
        let actual_id =
            VarInt::decode(&mut cursor).map_err(|_| WebTransportError::UnknownSession)?;
        if actual_id != self.session_id {
            return Err(WebTransportError::UnknownSession.into());
        }

        let datagram = datagram.split_off(cursor.position() as usize);
        Ok(datagram)
    }

    /// Send an application datagram to the peer.
    ///
    /// Datagrams are unreliable and may be dropped or delivered out of order. The data must be
    /// smaller than [`max_datagram_size`](Self::max_datagram_size).
    pub fn send_datagram(&self, data: Bytes) -> Result<(), SessionError> {
        let mut buf = BytesMut::with_capacity(self.header_datagram.len() + data.len());
        buf.extend_from_slice(&self.header_datagram);
        buf.extend_from_slice(&data);
        let payload = buf.freeze();

        match self
            .handle
            .datagram_mut(|sender: &mut Sender| sender.send_datagram(payload))
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(Self::map_datagram_error(e)),
            Err(_) => Err(self.closed_error()),
        }
    }

    /// The maximum size of a datagram that can be sent.
    ///
    /// NOTE: this is a conservative estimate based on the QUIC minimum, not the peer's
    /// actual negotiated limit (see [`DEFAULT_MAX_DATAGRAM_SIZE`]). Larger datagrams may
    /// still succeed.
    pub fn max_datagram_size(&self) -> usize {
        DEFAULT_MAX_DATAGRAM_SIZE.saturating_sub(self.header_datagram.len())
    }

    /// Read this connection's [`Subscriber`](s2n_quic::provider::event::Subscriber)
    /// `ConnectionContext`.
    ///
    /// s2n-quic reports connection statistics by *pushing* events into a subscriber
    /// registered on the endpoint, which is the opposite of quinn's pull-based
    /// `Connection::stats()` accessor. There is no useful
    /// backend-agnostic snapshot this crate could take on its own: the shape of what is
    /// accumulated is entirely up to the subscriber the endpoint was built with. So rather
    /// than pick one here, this exposes the read side generically - the application owns
    /// both the subscriber and the context type `C`.
    ///
    /// Returns `None` when the endpoint has no subscriber whose `ConnectionContext` is `C`
    /// (including the default, event-less endpoint) or when the connection has gone away.
    pub fn query_event_context<C: 'static, R>(&self, query: impl FnOnce(&C) -> R) -> Option<R> {
        self.handle.query_event_context(query).ok()
    }

    /// Returns the address of the peer on the other end of this session.
    pub fn remote_addr(&self) -> Result<std::net::SocketAddr, SessionError> {
        self.handle
            .remote_addr()
            .map_err(SessionError::ConnectionError)
    }

    /// Enable or disable QUIC keep-alive PING frames on this session's connection.
    ///
    /// Idle WebTransport sessions emit no application data, so without keep-alives a short
    /// `max_idle_timeout` reaps quiet-but-live sessions. Enabling this lets servers run
    /// aggressive idle timeouts (e.g. 10 s) without dropping idle sessions.
    pub fn keep_alive(&self, enabled: bool) -> Result<(), SessionError> {
        self.handle
            .clone()
            .keep_alive(enabled)
            .map_err(SessionError::ConnectionError)
    }

    /// Close the session with an error code and reason.
    ///
    /// A `CloseWebTransportSession` capsule is written on the CONNECT stream before the QUIC
    /// connection is closed, so browser clients can observe the code and reason. This happens
    /// asynchronously; `await` [`closed()`](Self::closed) to ensure delivery.
    pub fn close(&self, code: u32, reason: &[u8]) {
        let reason = String::from_utf8_lossy(reason).into_owned();
        let err = SessionError::WebTransportError(WebTransportError::Closed(code, reason.clone()));
        if self.error.set(err).is_err() {
            // Already closing/closed.
            return;
        }

        let send = self.connect_send.lock().unwrap().take();
        if let Some(send) = send {
            let handle = self.handle.clone();
            let capsule = web_transport_proto::Capsule::CloseWebTransportSession { code, reason };
            tokio::spawn(Self::close_with_capsule(
                handle,
                send,
                capsule,
                code,
                Duration::from_secs(1),
            ));
        } else {
            self.handle.close(app_error(code));
        }
    }

    async fn close_with_capsule(
        handle: Handle,
        mut send: s2n_quic::stream::SendStream,
        capsule: web_transport_proto::Capsule,
        code: u32,
        timeout: Duration,
    ) {
        // Encode the capsule, then wrap it in an HTTP/3 DATA frame (RFC 9297 §3.2).
        let mut capsule_bytes = Vec::new();
        capsule.encode(&mut capsule_bytes);

        let mut frame = Vec::new();
        Frame::DATA.encode(&mut frame);
        let Ok(len) = VarInt::try_from(capsule_bytes.len()) else {
            tracing::warn!("capsule too large to encode as DATA frame");
            handle.close(app_error(code));
            return;
        };
        len.encode(&mut frame);
        frame.extend_from_slice(&capsule_bytes);

        let graceful = async {
            let _ = send.send(Bytes::from(frame)).await;
            let _ = send.finish();
            // Wait for the peer to acknowledge the capsule before force-closing.
            let _ = send.flush().await;
        };

        let _ = tokio::time::timeout(timeout, graceful).await;
        handle.close(app_error(code));
    }

    /// Wait until the session is closed, returning the error.
    ///
    /// If the peer sent a `CloseWebTransportSession` capsule, the returned error will be
    /// [`WebTransportError::Closed`] with the code and reason from the capsule.
    pub async fn closed(&self) -> SessionError {
        let mut rx = self.closed_rx.clone();
        let _ = rx.wait_for(|closed| *closed).await;
        self.error
            .get()
            .cloned()
            .unwrap_or(SessionError::LocallyClosed)
    }

    /// Replace connection-level errors with the stored session error if available.
    fn map_error(&self, e: SessionError) -> SessionError {
        if let Some(err) = self.error.get() {
            if matches!(
                &e,
                SessionError::ConnectionError(_)
                    | SessionError::WebTransportError(WebTransportError::Closed(..))
                    | SessionError::LocallyClosed
            ) {
                return err.clone();
            }
        }
        e
    }

    fn map_stream_error(&self, e: s2n_quic::stream::Error) -> SessionError {
        let e = match e {
            s2n_quic::stream::Error::ConnectionError { error, .. } => error.into(),
            other => WebTransportError::StreamError(other).into(),
        };
        self.map_error(e)
    }

    fn closed_error(&self) -> SessionError {
        self.error
            .get()
            .cloned()
            .unwrap_or(SessionError::LocallyClosed)
    }

    fn map_datagram_error(e: s2n_quic::provider::datagram::default::DatagramError) -> SessionError {
        use s2n_quic::provider::datagram::default::DatagramError;
        match e {
            DatagramError::QueueAtCapacity { .. } => SendDatagramError::QueueAtCapacity.into(),
            DatagramError::ExceedsPeerTransportLimits { .. } => SendDatagramError::TooLarge.into(),
            DatagramError::ConnectionError { error, .. } => error.into(),
            _ => SessionError::LocallyClosed,
        }
    }

    /// Returns the CONNECT request.
    pub fn request(&self) -> &ConnectRequest {
        &self.request
    }

    /// Returns the CONNECT response.
    pub fn response(&self) -> &ConnectResponse {
        &self.response
    }
}

impl web_transport_trait::Session for Session {
    type SendStream = SendStream;
    type RecvStream = RecvStream;
    type Error = SessionError;

    async fn accept_uni(&self) -> Result<Self::RecvStream, Self::Error> {
        Self::accept_uni(self).await
    }

    async fn accept_bi(&self) -> Result<(Self::SendStream, Self::RecvStream), Self::Error> {
        Self::accept_bi(self).await
    }

    async fn open_bi(&self) -> Result<(Self::SendStream, Self::RecvStream), Self::Error> {
        Self::open_bi(self).await
    }

    async fn open_uni(&self) -> Result<Self::SendStream, Self::Error> {
        Self::open_uni(self).await
    }

    fn close(&self, code: u32, reason: &str) {
        Self::close(self, code, reason.as_bytes());
    }

    async fn closed(&self) -> Self::Error {
        Self::closed(self).await
    }

    fn send_datagram(&self, data: Bytes) -> Result<(), Self::Error> {
        Self::send_datagram(self, data)
    }

    async fn recv_datagram(&self) -> Result<Bytes, Self::Error> {
        Self::read_datagram(self).await
    }

    fn max_datagram_size(&self) -> usize {
        Self::max_datagram_size(self)
    }

    fn protocol(&self) -> Option<&str> {
        self.response.protocol.as_deref()
    }
}

// Type aliases to keep clippy happy about the future complexity.
type PendingUni = dyn std::future::Future<Output = Result<(StreamUni, s2n_quic::stream::ReceiveStream), SessionError>>
    + Send;
type PendingBi = dyn std::future::Future<
        Output = Result<
            Option<(
                s2n_quic::stream::SendStream,
                s2n_quic::stream::ReceiveStream,
            )>,
            SessionError,
        >,
    > + Send;

/// Accept logic, which is stateful because of the per-stream header decode.
pub struct SessionAccept {
    session_id: VarInt,
    error: Arc<OnceLock<SessionError>>,

    // Keep references to the qpack streams if a (non-conforming) peer creates them, so they
    // aren't closed until the session is dropped.
    qpack_encoder: Option<s2n_quic::stream::ReceiveStream>,
    qpack_decoder: Option<s2n_quic::stream::ReceiveStream>,

    accept_uni: ReceiveStreamAcceptor,
    accept_bi: BidirectionalStreamAcceptor,

    pending_uni: FuturesUnordered<Pin<Box<PendingUni>>>,
    pending_bi: FuturesUnordered<Pin<Box<PendingBi>>>,

    // Wake concurrent callers when one of them makes progress.
    bi_wakers: Vec<Waker>,
    uni_wakers: Vec<Waker>,
}

impl SessionAccept {
    pub(crate) fn new(
        acceptor: StreamAcceptor,
        session_id: VarInt,
        error: Arc<OnceLock<SessionError>>,
    ) -> Self {
        let (accept_bi, accept_uni) = acceptor.split();

        Self {
            session_id,
            error,

            qpack_decoder: None,
            qpack_encoder: None,

            accept_uni,
            accept_bi,

            pending_uni: FuturesUnordered::new(),
            pending_bi: FuturesUnordered::new(),

            bi_wakers: Vec::new(),
            uni_wakers: Vec::new(),
        }
    }

    pub fn poll_accept_uni(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<RecvStream, SessionError>> {
        loop {
            if let Poll::Ready(Some(res)) = self.accept_uni.poll_next_unpin(cx) {
                let recv = match res {
                    Ok(recv) => recv,
                    Err(e) => {
                        for waker in self.uni_wakers.drain(..) {
                            waker.wake();
                        }
                        return Poll::Ready(Err(e.into()));
                    }
                };
                let pending = Self::decode_uni(recv, self.session_id);
                self.pending_uni.push(Box::pin(pending));
                continue;
            }

            let (typ, recv) = match self.pending_uni.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(res))) => res,
                Poll::Ready(Some(Err(err))) => {
                    tracing::warn!(?err, "failed to decode unidirectional stream");
                    continue;
                }
                Poll::Ready(None) | Poll::Pending => {
                    if !self.uni_wakers.iter().any(|w| w.will_wake(cx.waker())) {
                        self.uni_wakers.push(cx.waker().clone());
                    }
                    return Poll::Pending;
                }
            };

            match typ {
                StreamUni::WEBTRANSPORT => {
                    let recv = RecvStream::new(recv, self.error.clone());
                    for waker in self.uni_wakers.drain(..) {
                        waker.wake();
                    }
                    return Poll::Ready(Ok(recv));
                }
                StreamUni::QPACK_DECODER => {
                    self.qpack_decoder = Some(recv);
                }
                StreamUni::QPACK_ENCODER => {
                    self.qpack_encoder = Some(recv);
                }
                _ => {
                    tracing::debug!(?typ, "ignoring unknown unidirectional stream");
                }
            }
        }
    }

    async fn decode_uni(
        mut recv: s2n_quic::stream::ReceiveStream,
        expected_session: VarInt,
    ) -> Result<(StreamUni, s2n_quic::stream::ReceiveStream), SessionError> {
        let typ = VarInt::read(&mut recv)
            .await
            .map_err(|_| WebTransportError::UnknownSession)?;
        let typ = StreamUni(typ);

        if typ == StreamUni::WEBTRANSPORT {
            let session_id = VarInt::read(&mut recv)
                .await
                .map_err(|_| WebTransportError::UnknownSession)?;
            if session_id != expected_session {
                return Err(WebTransportError::UnknownSession.into());
            }
        }

        Ok((typ, recv))
    }

    pub fn poll_accept_bi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(SendStream, RecvStream), SessionError>> {
        loop {
            if let Poll::Ready(Some(res)) = self.accept_bi.poll_next_unpin(cx) {
                let stream = match res {
                    Ok(stream) => stream,
                    Err(e) => {
                        for waker in self.bi_wakers.drain(..) {
                            waker.wake();
                        }
                        return Poll::Ready(Err(e.into()));
                    }
                };
                let pending = Self::decode_bi(stream, self.session_id);
                self.pending_bi.push(Box::pin(pending));
                continue;
            }

            let res = match self.pending_bi.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(res))) => res,
                Poll::Ready(Some(Err(err))) => {
                    tracing::warn!(?err, "failed to decode bidirectional stream");
                    continue;
                }
                Poll::Ready(None) | Poll::Pending => {
                    if !self.bi_wakers.iter().any(|w| w.will_wake(cx.waker())) {
                        self.bi_wakers.push(cx.waker().clone());
                    }
                    return Poll::Pending;
                }
            };

            if let Some((send, recv)) = res {
                let send = SendStream::new(send, self.error.clone());
                let recv = RecvStream::new(recv, self.error.clone());
                for waker in self.bi_wakers.drain(..) {
                    waker.wake();
                }
                return Poll::Ready(Ok((send, recv)));
            }
        }
    }

    async fn decode_bi(
        stream: s2n_quic::stream::BidirectionalStream,
        expected_session: VarInt,
    ) -> Result<
        Option<(
            s2n_quic::stream::SendStream,
            s2n_quic::stream::ReceiveStream,
        )>,
        SessionError,
    > {
        let (mut recv, send) = stream.split();

        let typ = VarInt::read(&mut recv)
            .await
            .map_err(|_| WebTransportError::UnknownSession)?;
        if Frame(typ) != Frame::WEBTRANSPORT {
            tracing::debug!(?typ, "ignoring unknown bidirectional stream");
            return Ok(None);
        }

        let session_id = VarInt::read(&mut recv)
            .await
            .map_err(|_| WebTransportError::UnknownSession)?;
        if session_id != expected_session {
            return Err(WebTransportError::UnknownSession.into());
        }

        Ok(Some((send, recv)))
    }
}

use std::sync::{Arc, OnceLock};

use bytes::{Buf, Bytes};

use crate::{app_error, SessionError, WriteError};

/// A stream that can be used to send bytes. See [`s2n_quic::stream::SendStream`].
///
/// This wrapper exists mainly to map WebTransport `u32` error codes into the reserved
/// HTTP/3 error space.
pub struct SendStream {
    stream: s2n_quic::stream::SendStream,
    error: Arc<OnceLock<SessionError>>,
}

impl SendStream {
    pub(crate) fn new(
        stream: s2n_quic::stream::SendStream,
        error: Arc<OnceLock<SessionError>>,
    ) -> Self {
        Self { stream, error }
    }

    /// Replace connection-level errors with the stored session error if available.
    fn map_error(&self, e: impl Into<WriteError>) -> WriteError {
        let e = e.into();
        if let Some(err) = self.error.get() {
            if matches!(&e, WriteError::SessionError(_)) {
                return WriteError::SessionError(err.clone());
            }
        }
        e
    }

    /// Abruptly reset the stream with the provided error code.
    ///
    /// This is a `u32` because WebTransport shares the error space with HTTP/3.
    pub fn reset(&mut self, code: u32) {
        let _ = self.stream.reset(app_error(code));
    }

    /// Write some data to the stream, returning the number of bytes written.
    ///
    /// s2n-quic's [`s2n_quic::stream::SendStream::send`] enqueues the entire buffer, so this
    /// always writes the full slice once flow control allows.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, WriteError> {
        let chunk = Bytes::copy_from_slice(buf);
        self.stream
            .send(chunk)
            .await
            .map_err(|e| self.map_error(e))?;
        Ok(buf.len())
    }

    /// Write all of the data to the stream.
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        self.write(buf).await?;
        Ok(())
    }

    /// Write a chunk of data to the stream, potentially avoiding a copy.
    pub async fn write_chunk(&mut self, chunk: Bytes) -> Result<(), WriteError> {
        self.stream.send(chunk).await.map_err(|e| self.map_error(e))
    }

    /// Mark the stream as finished, such that no more data can be written.
    pub fn finish(&mut self) -> Result<(), WriteError> {
        self.stream
            .finish()
            .map(|_| ())
            .map_err(|e| self.map_error(e))
    }

    /// Return the underlying QUIC stream ID.
    ///
    /// > **Warning**
    /// >
    /// > WebTransport stream IDs may have gaps and do not increment by 1, since the QUIC
    /// > connection is shared with HTTP/3.
    pub fn id(&self) -> u64 {
        self.stream.id()
    }
}

impl web_transport_trait::SendStream for SendStream {
    type Error = WriteError;

    fn set_priority(&mut self, _order: u8) {
        // s2n-quic does not expose a per-stream priority knob.
    }

    fn reset(&mut self, code: u32) {
        Self::reset(self, code);
    }

    fn finish(&mut self) -> Result<(), Self::Error> {
        Self::finish(self)
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        Self::write(self, buf).await
    }

    async fn write_buf<B: Buf + Send>(&mut self, buf: &mut B) -> Result<usize, Self::Error> {
        // Avoid a copy when the Buf is already Bytes.
        let size = buf.chunk().len();
        let chunk = buf.copy_to_bytes(size);
        self.write_chunk(chunk).await?;
        Ok(size)
    }

    async fn write_chunk(&mut self, chunk: Bytes) -> Result<(), Self::Error> {
        Self::write_chunk(self, chunk).await
    }

    async fn closed(&mut self) -> Result<(), Self::Error> {
        // s2n-quic has no STOP_SENDING/FIN-ack notification on the send side. We approximate
        // by flushing: this resolves once all outstanding data is acknowledged, or errors if
        // the peer reset the stream.
        self.stream.flush().await.map_err(|e| self.map_error(e))
    }
}

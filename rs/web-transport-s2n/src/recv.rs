use std::sync::{Arc, OnceLock};

use bytes::{Buf, Bytes};

use crate::{app_error, ReadError, SessionError};

/// A stream that can be used to receive bytes. See [`s2n_quic::stream::ReceiveStream`].
pub struct RecvStream {
    stream: s2n_quic::stream::ReceiveStream,

    // s2n-quic yields whole chunks via `receive()`, so we buffer the leftover of the current
    // chunk to support byte-oriented reads into a caller-provided buffer.
    buffer: Bytes,

    error: Arc<OnceLock<SessionError>>,
}

impl RecvStream {
    pub(crate) fn new(
        stream: s2n_quic::stream::ReceiveStream,
        error: Arc<OnceLock<SessionError>>,
    ) -> Self {
        Self {
            stream,
            buffer: Bytes::new(),
            error,
        }
    }

    /// Replace connection-level errors with the stored session error if available.
    fn map_error(&self, e: impl Into<ReadError>) -> ReadError {
        let e = e.into();
        if let Some(err) = self.error.get() {
            if matches!(&e, ReadError::SessionError(_)) {
                return ReadError::SessionError(err.clone());
            }
        }
        e
    }

    /// Ensure `self.buffer` holds data, returning `false` if the stream is finished.
    async fn fill(&mut self) -> Result<bool, ReadError> {
        while self.buffer.is_empty() {
            match self.stream.receive().await.map_err(|e| self.map_error(e))? {
                Some(chunk) => self.buffer = chunk,
                None => return Ok(false),
            }
        }
        Ok(true)
    }

    /// Tell the other end to stop sending data with the given error code.
    ///
    /// This is a `u32` because WebTransport shares the error space with HTTP/3.
    pub fn stop(&mut self, code: u32) {
        let _ = self.stream.stop_sending(app_error(code));
    }

    /// Read some data into the buffer, returning the number of bytes read, or `None` on FIN.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ReadError> {
        if !self.fill().await? {
            return Ok(None);
        }
        let n = std::cmp::min(buf.len(), self.buffer.len());
        buf[..n].copy_from_slice(&self.buffer[..n]);
        self.buffer.advance(n);
        Ok(Some(n))
    }

    /// Read the next chunk of data, up to `max` bytes, or `None` on FIN.
    pub async fn read_chunk(&mut self, max: usize) -> Result<Option<Bytes>, ReadError> {
        if !self.fill().await? {
            return Ok(None);
        }
        let n = std::cmp::min(max, self.buffer.len());
        Ok(Some(self.buffer.split_to(n)))
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

impl web_transport_trait::RecvStream for RecvStream {
    type Error = ReadError;

    fn stop(&mut self, code: u32) {
        Self::stop(self, code);
    }

    async fn read(&mut self, dst: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        Self::read(self, dst).await
    }

    async fn read_chunk(&mut self, max: usize) -> Result<Option<Bytes>, Self::Error> {
        Self::read_chunk(self, max).await
    }

    async fn closed(&mut self) -> Result<(), Self::Error> {
        // Drain any remaining data until the stream is finished or reset.
        self.buffer = Bytes::new();
        loop {
            match self.stream.receive().await.map_err(|e| self.map_error(e))? {
                Some(_) => continue,
                None => return Ok(()),
            }
        }
    }
}

//! Simple crypto provider utilities for rustls.
//!
//! s2n-quic's rustls provider pins the `aws-lc-rs` backend, so that's what we use here.

use std::sync::Arc;

use rustls::crypto::hash::{self, HashAlgorithm};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::CertificateDer;

/// A shared reference to a crypto provider.
pub type Provider = Arc<CryptoProvider>;

/// Returns the default crypto provider.
///
/// This checks for a process-wide default provider first, then falls back to `aws-lc-rs`.
pub fn default_provider() -> Provider {
    // See <https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html#using-the-per-process-default-cryptoprovider>
    if let Some(provider) = CryptoProvider::get_default().cloned() {
        return provider;
    }

    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Computes the SHA-256 hash of a certificate using the provided crypto provider.
///
/// # Panics
///
/// Panics if the provider doesn't expose a SHA-256 hash algorithm.
pub fn sha256(provider: &Provider, cert: &CertificateDer<'_>) -> hash::Output {
    let hash_provider = provider.cipher_suites.iter().find_map(|suite| {
        let hash_provider = suite.tls13()?.common.hash_provider;
        if hash_provider.algorithm() == HashAlgorithm::SHA256 {
            Some(hash_provider)
        } else {
            None
        }
    });
    if let Some(hash_provider) = hash_provider {
        return hash_provider.hash(cert);
    }

    panic!("No SHA-256 backend available in the crypto provider.");
}

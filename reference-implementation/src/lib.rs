//! This crate provides a reference implementation of [SFrame].  We implement the protocol logic as
//! well as all of the cipher suites defined in the document.  Cryptographic functions are provided
//! by the [Rust Crypto] family of crates.
//!
//! The main entry point is [SFrameContext]:
//!
//! ```
//! # use sframe_reference::*;
//! let cipher_suite = CipherSuite::AES_128_GCM_SHA_256;
//! let kid = KeyId(0x01);
//! let base_key = b"sixteen byte key";
//! let metadata = b"Beauty is truth, truth beauty";
//! let plaintext = b"that is all // Ye know on earth, and all ye need to know";
//!
//! let mut send = SFrameContext::new(cipher_suite);
//! send.add_send_key(kid, base_key);
//! let (ciphertext, _vals) = send.encrypt(kid, metadata, plaintext).unwrap();
//!
//! let mut recv = SFrameContext::new(cipher_suite);
//! recv.add_recv_key(kid, base_key);
//! let (decrypted, _vals) = recv.decrypt(metadata, &ciphertext).unwrap();
//! assert_eq!(plaintext, decrypted.as_slice());
//! ```
//!
//! [SFrame]: https://datatracker.ietf.org/doc/draft-ietf-sframe-enc/
//! [Rust Crypto]: https://github.com/RustCrypto

#![deny(missing_docs)]

/// The synthetic AEAD composed of AES-CTR and HMAC
pub mod aes_ctr_hmac;

/// SFrame header encoding and decoding
pub mod header;

/// Cipher agility layer
pub mod cipher;

pub use crate::{
    cipher::{new_cipher, Cipher, CipherSuite, SFrameIntermediateValues},
    header::{Counter, Header, KeyId},
};
use std::collections::HashMap;

/// Errors that can result from SFrame operations
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// No send/recv context was configured for the required operation
    NoContext,

    /// A context already exists in the opposite direction
    Conflict,

    /// The ciphertext was too short to contain an encoded header
    InsufficientHeaderData,

    /// The AEAD function reported a failure
    AeadError,
}

/// A Result with the standard error type for this library
pub type Result<T> = std::result::Result<T, Error>;

struct SendKeyContext {
    cipher: Box<dyn Cipher>,
    next_counter: Counter,
}

struct RecvKeyContext {
    cipher: Box<dyn Cipher>,
}

/// SFrameContext is the entry point for SFrame operations.  It tracks a set of send-only and
/// receive-only keys, and encrypts/decrypts payloads with them.
pub struct SFrameContext {
    cipher_suite: CipherSuite,
    send_keys: HashMap<KeyId, SendKeyContext>,
    recv_keys: HashMap<KeyId, RecvKeyContext>,
}

impl SFrameContext {
    /// This function allows the caller to directly specify the CTR value, for use in generating
    /// test vectors.
    pub fn encrypt_raw(
        &mut self,
        kid: KeyId,
        ctr: Counter,
        metadata: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, SFrameIntermediateValues)> {
        let ctx = self.send_keys.get_mut(&kid).unwrap();
        let header = Header::new(kid, ctr);

        let (raw_ciphertext, vals) = ctx.cipher.encrypt(&header, metadata, plaintext)?;

        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(header.as_slice());
        ciphertext.extend_from_slice(raw_ciphertext.as_slice());
        Ok((ciphertext, vals))
    }
}

/// SFrameContextMethods describes the major protocol operations available for SFrame.
pub trait SFrameContextMethods {
    /// Create a new context for this cipher suite, with no keys
    fn new(cipher_suite: CipherSuite) -> Self;

    /// Add a send-only key
    fn add_send_key(&mut self, kid: KeyId, base_key: &[u8]) -> Result<()>;

    /// Add a receive-only key
    fn add_recv_key(&mut self, kid: KeyId, base_key: &[u8]) -> Result<()>;

    /// Access the cipher for a KID.  Panics if the KID value is unknown.
    fn cipher(&self, kid: KeyId) -> &dyn Cipher;

    /// Encrypt with the specified key.  Panics if the KID value is unknown.
    fn encrypt(
        &mut self,
        kid: KeyId,
        metadata: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, SFrameIntermediateValues)>;

    /// Decrypt with the specified key.  Panics if the KID value is unknown.
    fn decrypt(
        &self,
        metadata: &[u8],
        ciphertext: &[u8],
    ) -> Result<(Vec<u8>, SFrameIntermediateValues)>;
}

impl SFrameContextMethods for SFrameContext {
    fn new(cipher_suite: CipherSuite) -> Self {
        Self {
            cipher_suite,
            send_keys: Default::default(),
            recv_keys: Default::default(),
        }
    }

    fn add_send_key(&mut self, kid: KeyId, base_key: &[u8]) -> Result<()> {
        // Verify that the key does not exist as a recv key
        if self.recv_keys.contains_key(&kid) {
            return Err(Error::Conflict);
        }

        // Derive the key and salt, and create the key context
        let key_ctx = SendKeyContext {
            cipher: new_cipher(self.cipher_suite, kid, base_key),
            next_counter: Counter(0),
        };
        self.send_keys.insert(kid, key_ctx);
        Ok(())
    }

    fn add_recv_key(&mut self, kid: KeyId, base_key: &[u8]) -> Result<()> {
        // Verify that the key does not exist as a recv key
        if self.send_keys.contains_key(&kid) {
            return Err(Error::Conflict);
        }

        // Derive the key and salt, and create the key context
        let key_ctx = RecvKeyContext {
            cipher: new_cipher(self.cipher_suite, kid, base_key),
        };
        self.recv_keys.insert(kid, key_ctx);
        Ok(())
    }

    fn cipher(&self, kid: KeyId) -> &dyn Cipher {
        self.send_keys
            .get(&kid)
            .map(|c| c.cipher.as_ref())
            .or(self.recv_keys.get(&kid).map(|c| c.cipher.as_ref()))
            .unwrap()
    }

    fn encrypt(
        &mut self,
        kid: KeyId,
        metadata: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, SFrameIntermediateValues)> {
        let ctx = self.send_keys.get_mut(&kid).ok_or(Error::NoContext)?;
        let ctr = ctx.next_counter;
        ctx.next_counter.0 += 1;

        self.encrypt_raw(kid, ctr, metadata, plaintext)
    }

    fn decrypt(
        &self,
        metadata: &[u8],
        ciphertext: &[u8],
    ) -> Result<(Vec<u8>, SFrameIntermediateValues)> {
        let (header, raw_ciphertext) = Header::parse(ciphertext)?;

        let ctx = self.recv_keys.get(&header.kid).ok_or(Error::NoContext)?;
        ctx.cipher.decrypt(&header, metadata, raw_ciphertext)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cipher::ALL_CIPHER_SUITES;

    fn round_trip_one(cipher_suite: CipherSuite) {
        let kid = KeyId(0x0102030405060708);
        let base_key = b"sixteen byte key";
        let metadata = b"Because I could not stop for Death";
        let plaintext = b"He kindly stopped for me";

        let mut send = SFrameContext::new(cipher_suite);
        send.add_send_key(kid, base_key).unwrap();

        let mut recv = SFrameContext::new(cipher_suite);
        recv.add_recv_key(kid, base_key).unwrap();

        // Verify that an SFrame ciphertext has the proper form
        let (ciphertext, _vals) = send.encrypt(kid, metadata, plaintext).unwrap();

        let header = Header::new(kid, Counter(0)).as_slice().to_vec();
        assert_eq!(header, &ciphertext[..header.len()]);
        assert_eq!(
            ciphertext.len(),
            plaintext.len() + header.len() + send.cipher(kid).overhead()
        );

        // Verify that the receiver can decrypt the ciphertext
        let (decrypted, _vals) = recv.decrypt(metadata, &ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn round_trip() {
        for &cipher_suite in &ALL_CIPHER_SUITES {
            round_trip_one(cipher_suite);
        }
    }

    #[test]
    fn conflict() {
        let cipher_suite = CipherSuite::AES_128_GCM_SHA_256;
        let kid = KeyId(0x0102030405060708);
        let base_key = b"sixteen byte key";

        // Verify that conflict is detected with send first
        let mut send = SFrameContext::new(cipher_suite);
        send.add_send_key(kid, base_key).unwrap();
        assert_eq!(
            send.add_recv_key(kid, base_key).unwrap_err(),
            Error::Conflict
        );

        // Verify that conflict is detected with recv first
        let mut recv = SFrameContext::new(cipher_suite);
        recv.add_recv_key(kid, base_key).unwrap();
        assert_eq!(
            recv.add_send_key(kid, base_key).unwrap_err(),
            Error::Conflict
        );
    }
}

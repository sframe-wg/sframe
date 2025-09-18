use crate::aes_ctr_hmac::AesCtrHmac;
use crate::header::{Header, KeyId};
use crate::{Error, Result};

use aead::{AeadCore, Key, KeyInit, KeySizeUser, Nonce, Payload};
use aes::{Aes128, Aes256};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use cipher::consts::{U10, U4, U8};
use cipher::Unsigned;
use core::ops::Deref;
use crypto_common::BlockSizeUser;
use hkdf::Hkdf;
use hmac::SimpleHmac;
use sha2::{Sha256, Sha512};

/// An SFrame cipher suite
#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone)]
pub struct CipherSuite(pub u16);

impl CipherSuite {
    /// AES-128-CTR with HMAC-SHA-256, with a 10-byte tag
    pub const AES_128_CTR_HMAC_SHA_256_80: CipherSuite = CipherSuite(0x0001);

    /// AES-128-CTR with HMAC-SHA-256, with an 8-byte tag
    pub const AES_128_CTR_HMAC_SHA_256_64: CipherSuite = CipherSuite(0x0002);

    /// AES-128-CTR with HMAC-SHA-256, with an 4-byte tag
    pub const AES_128_CTR_HMAC_SHA_256_32: CipherSuite = CipherSuite(0x0003);

    /// AES-128-GCM, with a full 16-byte tag
    pub const AES_128_GCM_SHA_256: CipherSuite = CipherSuite(0x0004);

    /// AES-256-GCM, with a full 16-byte tag
    pub const AES_256_GCM_SHA_512: CipherSuite = CipherSuite(0x0005);

    /// AES-256-CTR with HMAC-SHA-512, with a 10-byte tag
    pub const AES_256_CTR_HMAC_SHA_512_80: CipherSuite = CipherSuite(0x0006);

    /// AES-256-CTR with HMAC-SHA-512, with an 8-byte tag
    pub const AES_256_CTR_HMAC_SHA_512_64: CipherSuite = CipherSuite(0x0007);

    /// AES-256-CTR with HMAC-SHA-512, with an 4-byte tag
    pub const AES_256_CTR_HMAC_SHA_512_32: CipherSuite = CipherSuite(0x0008);
}

/// A list of all available ciphersuites
pub const ALL_CIPHER_SUITES: [CipherSuite; 8] = [
    CipherSuite::AES_128_CTR_HMAC_SHA_256_80,
    CipherSuite::AES_128_CTR_HMAC_SHA_256_64,
    CipherSuite::AES_128_CTR_HMAC_SHA_256_32,
    CipherSuite::AES_128_GCM_SHA_256,
    CipherSuite::AES_256_GCM_SHA_512,
    CipherSuite::AES_256_CTR_HMAC_SHA_512_80,
    CipherSuite::AES_256_CTR_HMAC_SHA_512_64,
    CipherSuite::AES_256_CTR_HMAC_SHA_512_32,
];

/// A convenience trait summarizing all of the salient aspects of an AEAD cipher.
pub trait Aead: aead::Aead + AeadCore + KeyInit + KeySizeUser {}
impl<T> Aead for T where T: aead::Aead + AeadCore + KeyInit + KeySizeUser {}

/// A convenience trait summarizing all of the salient aspects of a SHA2 digest.
pub trait Digest: BlockSizeUser + Clone + digest::Digest {}
impl<T> Digest for T where T: BlockSizeUser + Clone + digest::Digest {}

fn xor_eq(a: &mut [u8], b: &[u8]) {
    for (b1, b2) in a.iter_mut().zip(b.iter()) {
        *b1 ^= *b2;
    }
}

struct CipherImpl<A: Aead> {
    aead: A,

    /// The label used as info in key derivation
    pub sframe_key_label: Vec<u8>,

    /// The label used as info in salt derivation
    pub sframe_salt_label: Vec<u8>,

    /// The `aead_secret` value used as an HKDF PRK
    pub sframe_secret: Vec<u8>,

    /// The derived AEAD encryption key
    pub sframe_key: Key<A>,

    /// The derived AEAD encryption salt
    pub sframe_salt: Nonce<A>,
}

impl<A: Aead> CipherImpl<A> {
    pub fn new<D: Digest>(cipher_suite: CipherSuite, kid: KeyId, base_key: &[u8]) -> Self {
        static KEY_LABEL: &[u8] = b"SFrame 1.0 Secret key ";
        static SALT_LABEL: &[u8] = b"SFrame 1.0 Secret salt ";

        let (sframe_secret, h) = Hkdf::<D, SimpleHmac<D>>::extract(None, base_key);

        let kid_bytes = kid.0.to_be_bytes();
        let cipher_suite_bytes = cipher_suite.0.to_be_bytes();
        let sframe_key_label = [KEY_LABEL, &kid_bytes, &cipher_suite_bytes].concat();
        let sframe_salt_label = [SALT_LABEL, &kid_bytes, &cipher_suite_bytes].concat();

        let mut sframe_key: Key<A> = Default::default();
        h.expand(&sframe_key_label, &mut sframe_key).unwrap();

        let mut sframe_salt: Nonce<A> = Default::default();
        h.expand(&sframe_salt_label, &mut sframe_salt).unwrap();

        let aead = A::new(&sframe_key);

        Self {
            aead,
            sframe_key_label,
            sframe_salt_label,
            sframe_secret: sframe_secret.to_vec(),
            sframe_key,
            sframe_salt,
        }
    }

    pub fn prepare(&self, header: &Header, metadata: &[u8]) -> (Nonce<A>, Vec<u8>) {
        // Form the nonce
        let mut nonce = self.sframe_salt.clone();
        let ctr_data = header.ctr.0.to_be_bytes();
        let start = nonce.len() - ctr_data.len();
        xor_eq(&mut nonce[start..], &ctr_data);

        // Form the AAD
        let mut aad: Vec<u8> = Vec::new();
        aad.extend_from_slice(header.as_slice());
        aad.extend_from_slice(metadata);

        (nonce, aad)
    }
}

/// Intermediate values in an SFrame encryption/decryption
#[derive(Clone, Debug)]
pub struct SFrameIntermediateValues {
    /// The nonce value
    pub nonce: Vec<u8>,

    /// The AAD value
    pub aad: Vec<u8>,
}

impl SFrameIntermediateValues {
    fn new(nonce: impl Deref<Target = [u8]>, aad: Vec<u8>) -> Self {
        let nonce = nonce.to_vec();
        Self { nonce, aad }
    }
}

/// A cipher for SFrame, which handles the formation of nonces and AAD values from the SFrame salt
/// header, and metadata values, and the resulting AEAD encryption/decryption.  (Key derivation is
/// handled by the implementation struct.)
pub trait Cipher {
    /// The label used as info in key derivation
    fn sframe_key_label(&self) -> Vec<u8>;

    /// The label used as info in salt derivation
    fn sframe_salt_label(&self) -> Vec<u8>;

    /// The `aead_secret` value used as an HKDF PRK
    fn sframe_secret(&self) -> Vec<u8>;

    /// The derived AEAD encryption key
    fn sframe_key(&self) -> Vec<u8>;

    /// The derived AEAD encryption salt
    fn sframe_salt(&self) -> Vec<u8>;

    /// The number of bytes of overhead added to a plaintext on encryption
    fn overhead(&self) -> usize;

    /// Encrypt the plaintext with a nonce and AAD derived from the header and metadata
    fn encrypt(
        &self,
        header: &Header,
        metadata: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, SFrameIntermediateValues)>;

    /// Decrypt the ciphertext with a nonce and AAD derived from the header and metadata.  Returns
    /// [None] on decrypt failure.
    fn decrypt(
        &self,
        header: &Header,
        metadata: &[u8],
        ciphertext: &[u8],
    ) -> Result<(Vec<u8>, SFrameIntermediateValues)>;
}

impl<A: Aead> Cipher for CipherImpl<A> {
    fn sframe_key_label(&self) -> Vec<u8> {
        self.sframe_key_label.clone()
    }

    fn sframe_salt_label(&self) -> Vec<u8> {
        self.sframe_salt_label.clone()
    }

    fn sframe_secret(&self) -> Vec<u8> {
        self.sframe_secret.clone()
    }

    fn sframe_key(&self) -> Vec<u8> {
        self.sframe_key.to_vec()
    }

    fn sframe_salt(&self) -> Vec<u8> {
        self.sframe_salt.to_vec()
    }

    fn overhead(&self) -> usize {
        A::TagSize::to_usize()
    }

    fn encrypt(
        &self,
        header: &Header,
        metadata: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, SFrameIntermediateValues)> {
        let (nonce, aad) = self.prepare(header, metadata);
        let payload = Payload {
            msg: plaintext,
            aad: &aad,
        };

        self.aead
            .encrypt(&nonce, payload)
            .map_err(|_| Error::AeadError)
            .map(|ct| (ct, SFrameIntermediateValues::new(nonce, aad)))
    }

    fn decrypt(
        &self,
        header: &Header,
        metadata: &[u8],
        ciphertext: &[u8],
    ) -> Result<(Vec<u8>, SFrameIntermediateValues)> {
        let (nonce, aad) = self.prepare(header, metadata);
        let payload = Payload {
            msg: ciphertext,
            aad: &aad,
        };

        self.aead
            .decrypt(&nonce, payload)
            .map_err(|_| Error::AeadError)
            .map(|pt| (pt, SFrameIntermediateValues::new(nonce, aad)))
    }
}

type Aes128CtrHmacSha256_80 = CipherImpl<AesCtrHmac<Aes128, Sha256, U10>>;
type Aes128CtrHmacSha256_64 = CipherImpl<AesCtrHmac<Aes128, Sha256, U8>>;
type Aes128CtrHmacSha256_32 = CipherImpl<AesCtrHmac<Aes128, Sha256, U4>>;
type Aes128GcmSha256 = CipherImpl<Aes128Gcm>;
type Aes256GcmSha512 = CipherImpl<Aes256Gcm>;
type Aes256CtrHmacSha512_80 = CipherImpl<AesCtrHmac<Aes256, Sha512, U10>>;
type Aes256CtrHmacSha512_64 = CipherImpl<AesCtrHmac<Aes256, Sha512, U8>>;
type Aes256CtrHmacSha512_32 = CipherImpl<AesCtrHmac<Aes256, Sha512, U4>>;

/// Construct a new cipher for the specified ciphersuite.  The key and salt for the cipher are
/// derived from the `base_key` and `kid`.
pub fn new_cipher(cipher_suite: CipherSuite, kid: KeyId, base_key: &[u8]) -> Box<dyn Cipher> {
    match cipher_suite {
        CipherSuite::AES_128_CTR_HMAC_SHA_256_80 => Box::new(
            Aes128CtrHmacSha256_80::new::<Sha256>(cipher_suite, kid, base_key),
        ),
        CipherSuite::AES_128_CTR_HMAC_SHA_256_64 => Box::new(
            Aes128CtrHmacSha256_64::new::<Sha256>(cipher_suite, kid, base_key),
        ),
        CipherSuite::AES_128_CTR_HMAC_SHA_256_32 => Box::new(
            Aes128CtrHmacSha256_32::new::<Sha256>(cipher_suite, kid, base_key),
        ),
        CipherSuite::AES_128_GCM_SHA_256 => {
            Box::new(Aes128GcmSha256::new::<Sha256>(cipher_suite, kid, base_key))
        }
        CipherSuite::AES_256_GCM_SHA_512 => {
            Box::new(Aes256GcmSha512::new::<Sha512>(cipher_suite, kid, base_key))
        }
        CipherSuite::AES_256_CTR_HMAC_SHA_512_80 => Box::new(
            Aes256CtrHmacSha512_80::new::<Sha512>(cipher_suite, kid, base_key),
        ),
        CipherSuite::AES_256_CTR_HMAC_SHA_512_64 => Box::new(
            Aes256CtrHmacSha512_64::new::<Sha512>(cipher_suite, kid, base_key),
        ),
        CipherSuite::AES_256_CTR_HMAC_SHA_512_32 => Box::new(
            Aes256CtrHmacSha512_32::new::<Sha512>(cipher_suite, kid, base_key),
        ),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Counter;

    fn round_trip_one(cipher_suite: CipherSuite) {
        let kid = KeyId(0x0102030405060708);
        let ctr: Counter = Counter(0x1112131415161718);
        let header = Header::new(kid, ctr);
        let base_key = b"sixteen byte key";
        let metadata = b"How do I love thee? Let me count the ways.";
        let message = b"I love thee freely, as men strive for right.";

        let cipher = new_cipher(cipher_suite, kid, base_key);

        // Verify that an encrypt/decrypt round-trip works
        let (encrypted, _vals) = cipher.encrypt(&header, metadata, message).unwrap();
        assert_eq!(encrypted.len(), message.len() + cipher.overhead());

        let (decrypted, _vals) = cipher.decrypt(&header, metadata, &encrypted).unwrap();
        assert_eq!(&decrypted, message);

        // Verify that changing the KID causes decryption to fail
        let bad_kid = Header::new(KeyId(0), ctr);
        assert_eq!(
            cipher.decrypt(&bad_kid, metadata, &encrypted).unwrap_err(),
            Error::AeadError
        );

        // Verify that changing the CTR causes decryption to fail
        let bad_ctr = Header::new(kid, Counter(0));
        assert_eq!(
            cipher.decrypt(&bad_ctr, metadata, &encrypted).unwrap_err(),
            Error::AeadError
        );

        // Verify that changing the metdata causes decryption to fail
        let bad_metadata = b"I shall but love thee better after death.";
        assert_eq!(
            cipher
                .decrypt(&header, bad_metadata, &encrypted)
                .unwrap_err(),
            Error::AeadError
        );

        // Verify that changing the ciphertext causes decryption to fail
        let mut bad_encrypted = encrypted.clone();
        bad_encrypted[0] ^= 0xff;
        assert_eq!(
            cipher
                .decrypt(&header, metadata, &bad_encrypted)
                .unwrap_err(),
            Error::AeadError
        );
    }

    #[test]
    fn round_trip() {
        for cipher_suite in ALL_CIPHER_SUITES.into_iter() {
            round_trip_one(cipher_suite);
        }
    }
}

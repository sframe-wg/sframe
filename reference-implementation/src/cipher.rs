use crate::aes_ctr_hmac::AesCtrHmac;
use crate::header::{Header, KeyId};
use crate::{Error, Result};

use aead::{AeadCore, Key, KeyInit, KeySizeUser, Nonce, Payload};
use aes::Aes128;
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use cipher::consts::{U10, U4, U8};
use cipher::Unsigned;
use crypto_common::BlockSizeUser;
use hkdf::Hkdf;
use hmac::SimpleHmac;
use sha2::{Sha256, Sha512};

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
    /// The label value used as a salt in HKDF
    pub sframe_label: Vec<u8>,

    /// The `aead_secret` value used as an HKDF PRK
    pub sframe_secret: Vec<u8>,

    /// The derived AEAD encryption key
    pub sframe_key: Key<A>,

    /// The derived AEAD encryption salt
    pub sframe_salt: Nonce<A>,
    aead: A,
}

impl<A: Aead> CipherImpl<A> {
    pub fn new<D: Digest>(kid: KeyId, base_key: &[u8]) -> Self {
        let mut sframe_label = b"SFrame 1.0 ".to_vec();
        sframe_label.extend_from_slice(&kid.0.to_be_bytes());

        let (sframe_secret, h) = Hkdf::<D, SimpleHmac<D>>::extract(Some(&sframe_label), base_key);

        let mut sframe_key: Key<A> = Default::default();
        h.expand(b"key", &mut sframe_key).unwrap();

        let mut sframe_salt: Nonce<A> = Default::default();
        h.expand(b"salt", &mut sframe_salt).unwrap();

        let aead = A::new(&sframe_key);

        Self {
            sframe_label,
            sframe_secret: sframe_secret.to_vec(),
            sframe_key,
            sframe_salt,
            aead,
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

/// A cipher for SFrame, which handles the formation of nonces and AAD values from the SFrame salt
/// header, and metadata values, and the resulting AEAD encryption/decryption.  (Key derivation is
/// handled by the implementation struct.)
pub trait Cipher {
    /// The label value used as a salt in HKDF
    fn sframe_label(&self) -> Vec<u8>;

    /// The `aead_secret` value used as an HKDF PRK
    fn sframe_secret(&self) -> Vec<u8>;

    /// The derived AEAD encryption key
    fn sframe_key(&self) -> Vec<u8>;

    /// The derived AEAD encryption salt
    fn sframe_salt(&self) -> Vec<u8>;

    /// The number of bytes of overhead added to a plaintext on encryption
    fn overhead(&self) -> usize;

    /// Encrypt the plaintext with a nonce and AAD derived from the header and metadata
    fn encrypt(&self, header: &Header, metadata: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt the ciphertext with a nonce and AAD derived from the header and metadata.  Returns
    /// [None] on decrypt failure.
    fn decrypt(&self, header: &Header, metadata: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
}

impl<A: Aead> Cipher for CipherImpl<A> {
    fn sframe_label(&self) -> Vec<u8> {
        self.sframe_label.clone()
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

    fn encrypt(&self, header: &Header, metadata: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let (nonce, aad) = self.prepare(header, metadata);
        let payload = Payload {
            msg: plaintext,
            aad: &aad,
        };

        self.aead
            .encrypt(&nonce, payload)
            .map_err(|_| Error::AeadError)
    }

    fn decrypt(&self, header: &Header, metadata: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let (nonce, aad) = self.prepare(header, metadata);
        let payload = Payload {
            msg: ciphertext,
            aad: &aad,
        };

        self.aead
            .decrypt(&nonce, payload)
            .map_err(|_| Error::AeadError)
    }
}

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
}

/// A list of all available ciphersuites
pub const ALL_CIPHER_SUITES: [CipherSuite; 5] = [
    CipherSuite::AES_128_CTR_HMAC_SHA_256_80,
    CipherSuite::AES_128_CTR_HMAC_SHA_256_64,
    CipherSuite::AES_128_CTR_HMAC_SHA_256_32,
    CipherSuite::AES_128_GCM_SHA_256,
    CipherSuite::AES_256_GCM_SHA_512,
];

type Aes128CtrHmacSha256_80 = CipherImpl<AesCtrHmac<Aes128, Sha256, U10>>;
type Aes128CtrHmacSha256_64 = CipherImpl<AesCtrHmac<Aes128, Sha256, U8>>;
type Aes128CtrHmacSha256_32 = CipherImpl<AesCtrHmac<Aes128, Sha256, U4>>;
type Aes128GcmSha256 = CipherImpl<Aes128Gcm>;
type Aes256GcmSha512 = CipherImpl<Aes256Gcm>;

/// Construct a new cipher for the specified ciphersuite.  The key and salt for the cipher are
/// derived from the `base_key` and `kid`.
pub fn new_cipher(cipher_suite: CipherSuite, kid: KeyId, base_key: &[u8]) -> Box<dyn Cipher> {
    match cipher_suite {
        CipherSuite::AES_128_CTR_HMAC_SHA_256_80 => {
            Box::new(Aes128CtrHmacSha256_80::new::<Sha256>(kid, base_key))
        }
        CipherSuite::AES_128_CTR_HMAC_SHA_256_64 => {
            Box::new(Aes128CtrHmacSha256_64::new::<Sha256>(kid, base_key))
        }
        CipherSuite::AES_128_CTR_HMAC_SHA_256_32 => {
            Box::new(Aes128CtrHmacSha256_32::new::<Sha256>(kid, base_key))
        }
        CipherSuite::AES_128_GCM_SHA_256 => Box::new(Aes128GcmSha256::new::<Sha256>(kid, base_key)),
        CipherSuite::AES_256_GCM_SHA_512 => Box::new(Aes256GcmSha512::new::<Sha512>(kid, base_key)),
        _ => unreachable!(),
    }
}

#[cfg(test)]
pub mod test {
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
        let encrypted = cipher.encrypt(&header, metadata, message).unwrap();
        assert_eq!(encrypted.len(), message.len() + cipher.overhead());

        let decrypted = cipher.decrypt(&header, metadata, &encrypted).unwrap();
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

use aead::{AeadCore, KeyInit, KeySizeUser, Nonce, Payload};
use cipher::consts::{U12, U16};
use cipher::{ArrayLength, BlockCipher, BlockEncryptMut, KeyIvInit, StreamCipher};
use core::convert::TryInto;
use core::marker::PhantomData;
use crypto_common::{Iv, Key};
use ctr::Ctr32BE;
use digest::{Output, Update};
use hmac::{Mac, SimpleHmac};
use std::ops::Add;
use typenum::Sum;

pub use crate::cipher::Digest;

/// A convenience trait summarizing all of the salient aspects of AES with a given key size.
pub trait Cipher: BlockEncryptMut + BlockCipher<BlockSize = U16> + KeySizeUser + KeyInit {}
impl<T> Cipher for T where T: BlockEncryptMut + BlockCipher<BlockSize = U16> + KeySizeUser + KeyInit {}

/// An AEAD algorithm constructed from AES-CTR and HMAC, according to the SFrame specification.
/// This is a basic encrypt-then-MAC construction, with a specific selection of encryption and
/// authentication sub-keys.
pub struct AesCtrHmac<C, D, T>
where
    C: Cipher,
    D: Digest,
    T: ArrayLength<u8>,
{
    /// The derived encryption subkey
    pub enc_key: Key<C>,

    /// The derived authentication subkey
    pub auth_key: Output<D>,

    _marker: PhantomData<(C, T)>,
}

impl<C, D, T> AesCtrHmac<C, D, T>
where
    C: Cipher,
    D: Digest,
    T: ArrayLength<u8>,
{
    fn nonce_to_iv(short_nonce: &Nonce<Self>) -> Iv<Ctr32BE<C>> {
        let mut iv: Iv<Ctr32BE<C>> = Default::default();
        iv[..short_nonce.len()].copy_from_slice(short_nonce);
        iv
    }

    fn cipher(&self, nonce: &Nonce<Self>, pt: &[u8]) -> Vec<u8> {
        let iv = Self::nonce_to_iv(nonce);
        let mut c = Ctr32BE::<C>::new(&self.enc_key, &iv);
        let mut ct = pt.to_vec();
        c.apply_keystream(&mut ct);
        ct
    }

    fn compute_tag(&self, nonce: &[u8], aad: &[u8], ct: &[u8]) -> SimpleHmac<D> {
        let aad_len_u64: u64 = aad.len().try_into().unwrap();
        let ct_len_u64: u64 = ct.len().try_into().unwrap();

        let aad_len = aad_len_u64.to_be_bytes();
        let ct_len = ct_len_u64.to_be_bytes();
        let tag_len = T::to_u64().to_be_bytes();

        let h = <SimpleHmac<D> as Mac>::new_from_slice(self.auth_key.as_slice()).unwrap();
        h.chain(aad_len)
            .chain(ct_len)
            .chain(tag_len)
            .chain(nonce)
            .chain(aad)
            .chain(ct)
    }
}

impl<C, D, T> AeadCore for AesCtrHmac<C, D, T>
where
    C: Cipher,
    D: Digest,
    T: ArrayLength<u8>,
{
    type NonceSize = U12;
    type TagSize = T;
    type CiphertextOverhead = T;
}

// The constraint of KeySize/OutputSize to UInt is necessary because Add is only implemented on
// that specific type.  The constraint is not an issue in practice because all of the required
// ciphers use lengths of that type.
impl<C, D, T> KeySizeUser for AesCtrHmac<C, D, T>
where
    C: Cipher,
    D: Digest,
    T: ArrayLength<u8>,
    C::KeySize: Add<D::OutputSize>,
    <C::KeySize as Add<D::OutputSize>>::Output: ArrayLength<u8>,
{
    type KeySize = Sum<C::KeySize, D::OutputSize>;
}

impl<C, D, T> KeyInit for AesCtrHmac<C, D, T>
where
    C: Cipher,
    D: Digest,
    T: ArrayLength<u8>,
    AesCtrHmac<C, D, T>: KeySizeUser,
{
    fn new(key: &Key<Self>) -> Self {
        let (enc, auth) = key.split_at(C::key_size());
        let enc_key = Key::<C>::clone_from_slice(enc);
        let auth_key = Output::<D>::clone_from_slice(auth);

        Self {
            enc_key,
            auth_key,
            _marker: PhantomData,
        }
    }
}

impl<C, D, T> aead::Aead for AesCtrHmac<C, D, T>
where
    C: Cipher,
    D: Digest,
    T: ArrayLength<u8>,
    AesCtrHmac<C, D, T>: KeySizeUser,
{
    fn encrypt<'msg, 'aad>(
        &self,
        nonce: &Nonce<Self>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, aead::Error> {
        let payload: Payload = plaintext.into();

        let mut ct = self.cipher(nonce, payload.msg);
        let mut tag = self
            .compute_tag(nonce, payload.aad, &ct)
            .finalize()
            .into_bytes()
            .to_vec();
        tag.truncate(T::to_usize());
        ct.append(&mut tag);

        Ok(ct)
    }

    fn decrypt<'msg, 'aad>(
        &self,
        nonce: &Nonce<Self>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, aead::Error> {
        let payload: Payload = ciphertext.into();

        let tag_len = T::to_usize();
        if payload.msg.len() < tag_len {
            return Err(aead::Error);
        }

        let tag_start = payload.msg.len() - tag_len;
        let (ct, tag) = payload.msg.split_at(tag_start);

        self.compute_tag(nonce, payload.aad, ct)
            .verify_truncated_left(tag)
            .map_err(|_| aead::Error)?;

        Ok(self.cipher(nonce, ct))
    }
}

#[cfg(test)]
#[generic_tests::define]
mod test_aes128 {
    use super::*;
    use aead::Aead;
    use aes::Aes128;
    use cipher::consts::{U10, U4, U8};
    use hex_literal::hex;
    use sha2::Sha256;

    #[test]
    fn round_trip<C, D, T>()
    where
        C: Cipher + KeySizeUser<KeySize = U16>,
        D: Digest,
        T: ArrayLength<u8>,
        AesCtrHmac<C, D, T>: KeySizeUser + KeyInit,
    {
        let key = hex!("000102030405060708090a0b0c0d0e0f"
                       "101112131415161718191a1b1c1d1e1f"
                       "202122232425262728292a2b2c2d2e2f");
        let key = Key::<AesCtrHmac<C, D, T>>::clone_from_slice(&key);
        let nonce: Nonce<AesCtrHmac<C, D, T>> = hex!("101112131415161718191a1b").into();
        let msg = b"Never gonna give you up";
        let aad = b"Never gonna let you down";

        let cipher = AesCtrHmac::<C, D, T>::new(&key);

        // Verify that an encrypt/decrypt round-trip works
        let encrypt_payload = Payload { msg, aad };
        let encrypted = cipher.encrypt(&nonce, encrypt_payload).unwrap();
        assert_eq!(encrypted.len(), msg.len() + T::to_usize());

        let decrypt_payload = Payload {
            msg: &encrypted,
            aad,
        };
        let decrypted = cipher.decrypt(&nonce, decrypt_payload).unwrap();
        assert_eq!(&decrypted, msg);

        // Verify that trying to decrypt with different AAD fails
        let different_aad = b"Never gonna run around and hurt you";
        let different_aad_payload = Payload {
            msg: &encrypted,
            aad: different_aad,
        };
        assert!(cipher.decrypt(&nonce, different_aad_payload).is_err());

        // Verify that trying to decrypt with corrupted ciphertext fails
        let mut different_msg = encrypted.clone();
        different_msg[0] ^= 0xff;
        let different_msg_payload = Payload {
            msg: &different_msg,
            aad,
        };
        assert!(cipher.decrypt(&nonce, different_msg_payload).is_err());
    }

    #[instantiate_tests(<Aes128, Sha256, U10>)]
    mod aes_128_ctr_sha_256_80 {}

    #[instantiate_tests(<Aes128, Sha256, U8>)]
    mod aes_128_ctr_sha_256_64 {}

    #[instantiate_tests(<Aes128, Sha256, U4>)]
    mod aes_128_ctr_sha_256_32 {}
}

#[cfg(test)]
#[generic_tests::define]
mod test_aes256 {
    use super::*;
    use aead::Aead;
    use aes::Aes256;
    use cipher::consts::{U10, U4, U8};
    use hex_literal::hex;
    use sha2::Sha512;

    #[test]
    fn round_trip<C, D, T>()
    where
        C: Cipher + KeySizeUser<KeySize = U32>,
        D: Digest,
        T: ArrayLength<u8>,
        AesCtrHmac<C, D, T>: KeySizeUser + KeyInit,
    {
        let key = hex!("000102030405060708090a0b0c0d0e0f"
                       "101112131415161718191a1b1c1d1e1f"
                       "202122232425262728292a2b2c2d2e2f"
                       "303132333435363738393a3b3c3d3e3f"
                       "404142434445464748494a4b4c4d4e4f"
                       "505152535455565758595a5b5c5d5e5f");
        let key = Key::<AesCtrHmac<C, D, T>>::clone_from_slice(&key);
        let nonce: Nonce<AesCtrHmac<C, D, T>> = hex!("101112131415161718191a1b").into();
        let msg = b"Never gonna give you up";
        let aad = b"Never gonna let you down";

        let cipher = AesCtrHmac::<C, D, T>::new(&key);

        // Verify that an encrypt/decrypt round-trip works
        let encrypt_payload = Payload { msg, aad };
        let encrypted = cipher.encrypt(&nonce, encrypt_payload).unwrap();
        assert_eq!(encrypted.len(), msg.len() + T::to_usize());

        let decrypt_payload = Payload {
            msg: &encrypted,
            aad,
        };
        let decrypted = cipher.decrypt(&nonce, decrypt_payload).unwrap();
        assert_eq!(&decrypted, msg);

        // Verify that trying to decrypt with different AAD fails
        let different_aad = b"Never gonna run around and hurt you";
        let different_aad_payload = Payload {
            msg: &encrypted,
            aad: different_aad,
        };
        assert!(cipher.decrypt(&nonce, different_aad_payload).is_err());

        // Verify that trying to decrypt with corrupted ciphertext fails
        let mut different_msg = encrypted.clone();
        different_msg[0] ^= 0xff;
        let different_msg_payload = Payload {
            msg: &different_msg,
            aad,
        };
        assert!(cipher.decrypt(&nonce, different_msg_payload).is_err());
    }

    #[instantiate_tests(<Aes256, Sha512, U10>)]
    mod aes_256_ctr_sha_512_80 {}

    #[instantiate_tests(<Aes256, Sha512, U8>)]
    mod aes_256_ctr_sha_256_64 {}

    #[instantiate_tests(<Aes256, Sha512, U4>)]
    mod aes_256_ctr_sha_512_32 {}
}

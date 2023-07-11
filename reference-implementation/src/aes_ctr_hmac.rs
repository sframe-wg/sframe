use aead::{AeadCore, KeyInit, KeySizeUser, Nonce, Payload};
use cipher::consts::{U12, U16};
use cipher::{ArrayLength, BlockCipher, BlockEncryptMut, KeyIvInit, StreamCipher};
use core::marker::PhantomData;
use crypto_common::{Iv, Key};
use ctr::Ctr32BE;
use digest::{Output, Update};
use hkdf::Hkdf;
use hmac::{Mac, SimpleHmac};

pub use crate::cipher::Digest;

/// A convenience trait summarizing all of the salient aspects of AES with a given key size.
pub trait Cipher: BlockEncryptMut + BlockCipher<BlockSize = U16> + KeySizeUser + KeyInit {}
impl<T> Cipher for T where T: BlockEncryptMut + BlockCipher<BlockSize = U16> + KeySizeUser + KeyInit {}

/// An AEAD algorithm constructed from AES-CTR and HMAC, according to the SFrame specification.
/// This is a basic encrypt-then-MAC construction, with a specific HKDF-based key derivation.
pub struct AesCtrHmac<C, D, T>
where
    C: Cipher,
    D: Digest,
    T: ArrayLength<u8>,
{
    enc_key: Key<C>,
    auth_key: Output<D>,
    _ctr: PhantomData<C>,
    _hmac: PhantomData<D>,
    _tag: PhantomData<T>,
}

impl<C, D, T> AesCtrHmac<C, D, T>
where
    C: Cipher,
    D: Digest,
    T: ArrayLength<u8>,
{
    fn nonce_to_iv(short_nonce: &Nonce<Self>) -> Iv<Ctr32BE<C>> {
        let mut iv: Iv<Ctr32BE<C>> = Default::default();
        iv[..short_nonce.len()].copy_from_slice(&short_nonce);
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
        let aad_len = (aad.len() as u64).to_be_bytes();
        let ct_len = (ct.len() as u64).to_be_bytes();
        let tag_len = T::to_u64().to_be_bytes();

        let h = <SimpleHmac<D> as Mac>::new_from_slice(self.auth_key.as_slice()).unwrap();
        h.chain(&aad_len)
            .chain(&ct_len)
            .chain(&tag_len)
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

impl<C, D, T> KeySizeUser for AesCtrHmac<C, D, T>
where
    C: Cipher,
    D: Digest,
    T: ArrayLength<u8>,
{
    type KeySize = C::KeySize;
}

impl<C, D, T> KeyInit for AesCtrHmac<C, D, T>
where
    C: Cipher,
    D: Digest,
    T: ArrayLength<u8>,
{
    fn new(key: &Key<Self>) -> Self {
        let mut aead_label = b"SFrame 1.0 AES CTR AEAD ".to_vec();
        aead_label.extend_from_slice(&T::to_u64().to_be_bytes());

        let h = Hkdf::<D, SimpleHmac<D>>::new(Some(&aead_label), key);

        let mut enc_key: Key<C> = Default::default();
        h.expand(b"enc", &mut enc_key).unwrap();

        let mut auth_key: Output<D> = Default::default();
        h.expand(b"auth", &mut auth_key).unwrap();

        Self {
            enc_key,
            auth_key,
            _ctr: PhantomData,
            _hmac: PhantomData,
            _tag: PhantomData,
        }
    }
}

impl<C, D, T> aead::Aead for AesCtrHmac<C, D, T>
where
    C: Cipher,
    D: Digest,
    T: ArrayLength<u8>,
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
mod test {
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
    {
        let key: Key<AesCtrHmac<C, D, T>> = hex!("000102030405060708090a0b0c0d0e0f").into();
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

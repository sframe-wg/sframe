mod header {
    use itertools::Itertools;
    use serde::{Deserialize, Serialize};
    use sframe_reference::header::*;

    #[derive(Serialize, Deserialize)]
    pub struct TestVector {
        kid: u64,
        ctr: u64,
        encoded: String,
    }

    impl TestVector {
        fn new(kid: u64, ctr: u64) -> Self {
            let header = Header::new(KeyId(kid), Counter(ctr));
            let encoded = hex::encode(header.as_slice());
            Self { kid, ctr, encoded }
        }

        pub fn make_all() -> Vec<Self> {
            let mut values: Vec<u64> = (0..64)
                .step_by(8)
                .flat_map(|n| [(1 << n) - 1, (1 << n)])
                .collect();
            values.push(u64::MAX);

            let kids = values.clone();
            let ctrs = values.clone();

            kids.into_iter()
                .cartesian_product(ctrs.into_iter())
                .map(|(kid, ctr)| Self::new(kid, ctr))
                .collect()
        }

        pub fn verify(&self) -> bool {
            let encoded_vec = hex::decode(self.encoded.clone()).unwrap();

            let encoded = Header::new(KeyId(self.kid), Counter(self.ctr));
            let encode_pass = encoded.as_slice() == encoded_vec;

            let (decoded, _) = Header::parse(&encoded_vec).unwrap();
            let decode_pass = (decoded.kid.0 == self.kid) && (decoded.ctr.0 == self.ctr);

            encode_pass && decode_pass
        }
    }

    impl super::ToMarkdown for TestVector {
        fn to_markdown(&self) -> String {
            let TestVector { kid, ctr, encoded } = self;
            format!(
                "~~~
kid: 0x{kid:016x}
ctr: 0x{ctr:016x}
header: {encoded}
~~~"
            )
        }
    }
}

mod aes_ctr_hmac {
    use aead::{Aead, Key, KeyInit, KeySizeUser, Nonce, Payload};
    use aes::Aes128;
    use cipher::consts::{U10, U16, U4, U8};
    use cipher::ArrayLength;
    use hex_literal::hex;
    use serde::{Deserialize, Serialize};
    use sframe_reference::aes_ctr_hmac::*;
    use sframe_reference::cipher::CipherSuite;
    use sha2::Sha256;

    #[derive(Serialize, Deserialize)]
    pub struct TestVector {
        cipher_suite: u16,
        key: String,
        aead_label: String,
        aead_secret: String,
        enc_key: String,
        auth_key: String,
        nonce: String,
        aad: String,
        pt: String,
        ct: String,
    }

    impl TestVector {
        fn new<C, D, T>() -> Self
        where
            C: Cipher + KeySizeUser<KeySize = U16>,
            D: Digest,
            T: ArrayLength<u8>,
        {
            let cipher_suite = match T::to_usize() {
                10 => CipherSuite::AES_128_CTR_HMAC_SHA_256_80,
                8 => CipherSuite::AES_128_CTR_HMAC_SHA_256_64,
                4 => CipherSuite::AES_128_CTR_HMAC_SHA_256_32,
                _ => unreachable!(),
            };

            let key: Key<AesCtrHmac<C, D, T>> = hex!("000102030405060708090a0b0c0d0e0f").into();
            let nonce: Nonce<AesCtrHmac<C, D, T>> = hex!("101112131415161718191a1b").into();
            let aad = b"IETF SFrame WG";
            let pt = b"draft-ietf-sframe-enc";

            let cipher = AesCtrHmac::<C, D, T>::new(&key);
            let ct = cipher.encrypt(&nonce, Payload { msg: pt, aad }).unwrap();

            Self {
                cipher_suite: cipher_suite.0,
                key: hex::encode(key),
                aead_label: hex::encode(cipher.aead_label),
                aead_secret: hex::encode(cipher.aead_secret),
                enc_key: hex::encode(cipher.enc_key),
                auth_key: hex::encode(cipher.auth_key),
                nonce: hex::encode(nonce),
                aad: hex::encode(aad),
                pt: hex::encode(pt),
                ct: hex::encode(ct),
            }
        }

        pub fn make_all() -> Vec<Self> {
            vec![
                Self::new::<Aes128, Sha256, U10>(),
                Self::new::<Aes128, Sha256, U8>(),
                Self::new::<Aes128, Sha256, U4>(),
            ]
        }

        fn verify_one<C, D, T>(&self) -> bool
        where
            C: Cipher + KeySizeUser<KeySize = U16>,
            D: Digest,
            T: ArrayLength<u8>,
        {
            let key = hex::decode(self.key.clone()).unwrap();
            let nonce = hex::decode(self.nonce.clone()).unwrap();
            let aad = hex::decode(self.aad.clone()).unwrap();
            let pt = hex::decode(self.pt.clone()).unwrap();
            let ct = hex::decode(self.ct.clone()).unwrap();

            let key = Key::<AesCtrHmac<C, D, T>>::from_slice(&key);
            let nonce = Nonce::<AesCtrHmac<C, D, T>>::from_slice(&nonce);

            let cipher = AesCtrHmac::<C, D, T>::new(&key);

            let payload = Payload {
                msg: &pt,
                aad: &aad,
            };
            let encrypted = cipher.encrypt(&nonce, payload).unwrap();
            let encrypt_pass = encrypted == ct;

            let payload = Payload {
                msg: &ct,
                aad: &aad,
            };
            let decrypted = cipher.decrypt(&nonce, payload).unwrap();
            let decrypt_pass = decrypted == pt;

            encrypt_pass && decrypt_pass
        }

        pub fn verify(&self) -> bool {
            match CipherSuite(self.cipher_suite) {
                CipherSuite::AES_128_CTR_HMAC_SHA_256_80 => {
                    self.verify_one::<Aes128, Sha256, U10>()
                }
                CipherSuite::AES_128_CTR_HMAC_SHA_256_64 => self.verify_one::<Aes128, Sha256, U8>(),
                CipherSuite::AES_128_CTR_HMAC_SHA_256_32 => self.verify_one::<Aes128, Sha256, U4>(),
                _ => unreachable!(),
            }
        }
    }

    impl super::ToMarkdown for TestVector {
        fn to_markdown(&self) -> String {
            let TestVector {
                cipher_suite,
                key,
                aead_label,
                aead_secret,
                enc_key,
                auth_key,
                nonce,
                aad,
                pt,
                ct,
            } = self;

            format!(
                "~~~
cipher_suite: 0x{cipher_suite:04x}
key: {key}
aead_label: {aead_label}
aead_secret: {aead_secret}
enc_key: {enc_key}
auth_key: {auth_key}
nonce: {nonce}
aad: {aad}
pt: {pt}
ct: {ct}
~~~"
            )
        }
    }
}

mod sframe {
    use hex_literal::hex;
    use serde::{Deserialize, Serialize};
    use sframe_reference::*;

    #[derive(Serialize, Deserialize)]
    pub struct TestVector {
        cipher_suite: u16,
        kid: u64,
        ctr: u64,
        base_key: String,
        sframe_key_label: String,
        sframe_salt_label: String,
        sframe_secret: String,
        sframe_key: String,
        sframe_salt: String,
        metadata: String,
        nonce: String,
        aad: String,
        pt: String,
        ct: String,
    }

    impl TestVector {
        fn new(cipher_suite: CipherSuite) -> Self {
            let base_key: Vec<u8> = hex!("000102030405060708090a0b0c0d0e0f").into();
            let kid = KeyId(0x0123);
            let ctr = Counter(0x4567);
            let metadata = b"IETF SFrame WG";
            let pt = b"draft-ietf-sframe-enc";

            let mut ctx = SFrameContext::new(cipher_suite);
            ctx.add_send_key(kid, &base_key).unwrap();
            let (ct, vals) = ctx.encrypt_raw(kid, ctr, metadata, pt).unwrap();

            let cipher = ctx.cipher(kid);

            Self {
                cipher_suite: cipher_suite.0,
                kid: kid.0,
                ctr: ctr.0,
                base_key: hex::encode(base_key),
                sframe_key_label: hex::encode(cipher.sframe_key_label()),
                sframe_salt_label: hex::encode(cipher.sframe_salt_label()),
                sframe_secret: hex::encode(cipher.sframe_secret()),
                sframe_key: hex::encode(cipher.sframe_key()),
                sframe_salt: hex::encode(cipher.sframe_salt()),
                metadata: hex::encode(metadata),
                nonce: hex::encode(vals.nonce),
                aad: hex::encode(vals.aad),
                pt: hex::encode(pt),
                ct: hex::encode(ct),
            }
        }

        pub fn make_all() -> Vec<TestVector> {
            sframe_reference::cipher::ALL_CIPHER_SUITES
                .iter()
                .map(|&cipher_suite| TestVector::new(cipher_suite))
                .collect()
        }

        pub fn verify(&self) -> bool {
            let cipher_suite = CipherSuite(self.cipher_suite);
            let kid = KeyId(self.kid);
            let ctr = Counter(self.ctr);
            let base_key = hex::decode(self.base_key.clone()).unwrap();
            let metadata = hex::decode(self.metadata.clone()).unwrap();
            let pt = hex::decode(self.pt.clone()).unwrap();
            let ct = hex::decode(self.ct.clone()).unwrap();

            let mut ctx = SFrameContext::new(cipher_suite);
            ctx.add_send_key(kid, &base_key).unwrap();
            let (encrypted, _) = ctx.encrypt_raw(kid, ctr, &metadata, &pt).unwrap();
            let encrypt_pass = encrypted == ct;

            let mut ctx = SFrameContext::new(cipher_suite);
            ctx.add_recv_key(kid, &base_key).unwrap();
            let (decrypted, _) = ctx.decrypt(&metadata, &ct).unwrap();
            let decrypt_pass = decrypted == pt;

            encrypt_pass && decrypt_pass
        }
    }

    impl super::ToMarkdown for TestVector {
        fn to_markdown(&self) -> String {
            let TestVector {
                cipher_suite,
                kid,
                ctr,
                base_key,
                sframe_key_label,
                sframe_salt_label,
                sframe_secret,
                sframe_key,
                sframe_salt,
                metadata,
                nonce,
                aad,
                pt,
                ct,
            } = self;

            format!(
                "~~~
cipher_suite: 0x{cipher_suite:04x}
kid: 0x{kid:016x}
ctr: 0x{ctr:016x}
base_key: {base_key}
sframe_key_label: {sframe_key_label}
sframe_salt_label: {sframe_salt_label}
sframe_secret: {sframe_secret}
sframe_key: {sframe_key}
sframe_salt: {sframe_salt}
metadata: {metadata}
nonce: {nonce}
aad: {aad}
pt: {pt}
ct: {ct}
~~~"
            )
        }
    }
}

use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, ValueEnum)]
enum TestVectorType {
    Header,
    AesCtrHmac,
    Sframe,
}

trait ToMarkdown {
    fn to_markdown(&self) -> String;
}

#[derive(Serialize, Deserialize)]
struct TestVectors {
    header: Vec<header::TestVector>,
    aes_ctr_hmac: Vec<aes_ctr_hmac::TestVector>,
    sframe: Vec<sframe::TestVector>,
}

impl TestVectors {
    fn make_all() -> Self {
        Self {
            header: header::TestVector::make_all(),
            aes_ctr_hmac: aes_ctr_hmac::TestVector::make_all(),
            sframe: sframe::TestVector::make_all(),
        }
    }

    fn verify_all(&self) -> bool {
        let header = self.header.iter().map(|tv| tv.verify());
        let aes_ctr_hmac = self.aes_ctr_hmac.iter().map(|tv| tv.verify());
        let sframe = self.sframe.iter().map(|tv| tv.verify());

        header.chain(aes_ctr_hmac).chain(sframe).all(|x| x)
    }

    fn print_md_all<T: ToMarkdown>(vecs: &[T]) {
        for vec in vecs {
            println!("{}\n", vec.to_markdown());
        }
    }

    fn print_md(&self, vec_type: TestVectorType) {
        match vec_type {
            TestVectorType::Header => Self::print_md_all(&self.header),
            TestVectorType::AesCtrHmac => Self::print_md_all(&self.aes_ctr_hmac),
            TestVectorType::Sframe => Self::print_md_all(&self.sframe),
        }
    }
}

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Md { vec_type: TestVectorType },
    Json,
    Verify,
    SelfTest,
}

fn main() -> Result<(), u32> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Md { vec_type } => {
            let vec = TestVectors::make_all();
            vec.print_md(*vec_type);
            Ok(())
        }

        Commands::Json => {
            let vec = TestVectors::make_all();
            println!("{}", serde_json::to_string_pretty(&vec).unwrap());
            Ok(())
        }

        Commands::Verify => {
            let stdin = std::io::stdin();
            let vec: TestVectors = serde_json::from_reader(stdin).unwrap();

            vec.verify_all().then(|| ()).ok_or(1)
        }

        Commands::SelfTest => {
            let vec = TestVectors::make_all();
            let vec_json = serde_json::to_string_pretty(&vec).unwrap();

            let vec: TestVectors = serde_json::from_reader(vec_json.as_bytes()).unwrap();
            vec.verify_all().then(|| ()).ok_or(1)
        }
    }
}

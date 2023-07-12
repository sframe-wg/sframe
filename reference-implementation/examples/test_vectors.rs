mod header {
    use itertools::Itertools;
    use serde::Serialize;
    use sframe_reference::header::*;

    #[derive(Serialize)]
    pub struct TestVector {
        kid: u64,
        ctr: u64,
        encoded: String,
    }

    impl TestVector {
        fn new(kid: u64, ctr: u64) -> Self {
            let header = Header::new(KeyId(kid), Counter(ctr));
            let encoded = hex::encode(header.to_vec());
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
    }

    impl super::ToMarkdown for TestVector {
        fn to_markdown(&self) -> String {
            let TestVector { kid, ctr, encoded } = self;
            format!(
                "~~~
KID: 0x{kid:016x}
CTR: 0x{ctr:016x}
Header: {encoded}
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
    use serde::Serialize;
    use sframe_reference::aes_ctr_hmac::*;
    use sframe_reference::cipher::CipherSuite;
    use sha2::Sha256;

    #[derive(Serialize)]
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
Cipher suite: 0x{cipher_suite:04x}
`key`: {key}
`aead_label`: {aead_label}
`aead_secret`: {aead_secret}
`enc_key`: {enc_key}
`auth_key`: {auth_key}
`nonce`: {nonce}
`aad`: {aad}
`pt`: {pt}
`ct`: {ct}
~~~"
            )
        }
    }
}

mod sframe {
    use hex_literal::hex;
    use serde::Serialize;
    use sframe_reference::*;

    #[derive(Serialize)]
    pub struct TestVector {
        cipher_suite: u16,
        base_key: String,
        sframe_label: String,
        sframe_secret: String,
        sframe_key: String,
        sframe_salt: String,
        kid: u64,
        ctr: u64,
        metadata: String,
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
            ctx.add_send_key(kid, &base_key);
            let ct = ctx.encrypt_raw(kid, ctr, metadata, pt);

            let cipher = ctx.cipher(kid);

            Self {
                cipher_suite: cipher_suite.0,
                base_key: hex::encode(base_key),
                sframe_label: hex::encode(cipher.sframe_label()),
                sframe_secret: hex::encode(cipher.sframe_secret()),
                sframe_key: hex::encode(cipher.sframe_key()),
                sframe_salt: hex::encode(cipher.sframe_salt()),
                kid: kid.0,
                ctr: ctr.0,
                metadata: hex::encode(metadata),
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
    }

    impl super::ToMarkdown for TestVector {
        fn to_markdown(&self) -> String {
            let TestVector {
                cipher_suite,
                base_key,
                sframe_label,
                sframe_secret,
                sframe_key,
                sframe_salt,
                kid,
                ctr,
                metadata,
                pt,
                ct,
            } = self;

            format!(
                "~~~
Cipher suite: 0x{cipher_suite:04x}
`base_key`: {base_key}
`sframe_label`: {sframe_label}
`sframe_secret`: {sframe_secret}
`sframe_key`: {sframe_key}
`sframe_salt`: {sframe_salt}
`kid`: 0x{kid:016x}
`ctr`: 0x{ctr:016x}
`metadata`: {metadata}
`pt`: {pt}
`ct`: {ct}
~~~"
            )
        }
    }
}

use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;

#[derive(Copy, Clone, ValueEnum)]
enum TestVectorType {
    Header,
    AesCtrHmac,
    Sframe,
}

trait ToMarkdown {
    fn to_markdown(&self) -> String;
}

#[derive(Serialize)]
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
}

fn main() {
    let cli = Cli::parse();
    let vec = TestVectors::make_all();

    match &cli.command {
        Commands::Md { vec_type } => {
            vec.print_md(*vec_type);
        }

        Commands::Json => {
            println!("{}", serde_json::to_string_pretty(&vec).unwrap());
        }
    }
}

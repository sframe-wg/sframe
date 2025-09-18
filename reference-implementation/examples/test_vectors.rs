mod header {
    use super::Hex;
    use itertools::Itertools;
    use serde::{Deserialize, Serialize};
    use sframe_reference::header::*;

    #[derive(Serialize, Deserialize)]
    pub struct TestVector {
        kid: u64,
        ctr: u64,
        encoded: Hex,
    }

    impl TestVector {
        fn new(kid: u64, ctr: u64) -> Self {
            let header = Header::new(KeyId(kid), Counter(ctr));
            let encoded = Hex::from(header.as_slice());
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
            let encoded = Header::new(KeyId(self.kid), Counter(self.ctr));
            let encode_pass = self.encoded == encoded.as_slice();

            let (decoded, _) = Header::parse(&self.encoded).unwrap();
            let decode_pass = (decoded.kid.0 == self.kid) && (decoded.ctr.0 == self.ctr);

            encode_pass && decode_pass
        }
    }

    impl super::ToMarkdown for TestVector {
        fn to_markdown(&self) -> String {
            let TestVector { kid, ctr, encoded } = self;
            format!(
                "~~~ test-vectors
kid: 0x{kid:016x}
ctr: 0x{ctr:016x}
header: {encoded:8}
~~~"
            )
        }
    }
}

mod aes_128_ctr_hmac {
    use super::Hex;
    use aead::{Aead, Key, KeyInit, KeySizeUser, Nonce, Payload};
    use aes::Aes128;
    use cipher::{
        consts::{U10, U16, U4, U8},
        ArrayLength,
    };
    use hex_literal::hex;
    use serde::{Deserialize, Serialize};
    use sframe_reference::{aes_ctr_hmac::*, cipher::CipherSuite};
    use sha2::Sha256;

    #[derive(Serialize, Deserialize)]
    pub struct TestVector {
        cipher_suite: u16,
        key: Hex,
        enc_key: Hex,
        auth_key: Hex,
        nonce: Hex,
        aad: Hex,
        pt: Hex,
        ct: Hex,
    }

    impl TestVector {
        fn new<C, D, T>() -> Self
        where
            C: Cipher + KeySizeUser<KeySize = U16>,
            D: Digest,
            T: ArrayLength<u8>,
            AesCtrHmac<C, D, T>: KeySizeUser + KeyInit,
        {
            let cipher_suite = match T::to_usize() {
                10 => CipherSuite::AES_128_CTR_HMAC_SHA_256_80,
                8 => CipherSuite::AES_128_CTR_HMAC_SHA_256_64,
                4 => CipherSuite::AES_128_CTR_HMAC_SHA_256_32,
                _ => unreachable!(),
            };

            let key = hex!("000102030405060708090a0b0c0d0e0f"
                           "101112131415161718191a1b1c1d1e1f"
                           "202122232425262728292a2b2c2d2e2f");
            let key = Key::<AesCtrHmac<C, D, T>>::clone_from_slice(&key);
            let nonce: Nonce<AesCtrHmac<C, D, T>> = hex!("101112131415161718191a1b").into();
            let aad = b"IETF SFrame WG";
            let pt = b"draft-ietf-sframe-enc";

            let cipher = AesCtrHmac::<C, D, T>::new(&key);
            let ct = cipher.encrypt(&nonce, Payload { msg: pt, aad }).unwrap();

            Self {
                cipher_suite: cipher_suite.0,
                key: Hex::from(key),
                enc_key: Hex::from(cipher.enc_key),
                auth_key: Hex::from(cipher.auth_key),
                nonce: Hex::from(nonce),
                aad: Hex::from(aad),
                pt: Hex::from(pt),
                ct: Hex::from(ct),
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
            AesCtrHmac<C, D, T>: KeySizeUser + KeyInit,
        {
            let key = Key::<AesCtrHmac<C, D, T>>::from_slice(&self.key);
            let nonce = Nonce::<AesCtrHmac<C, D, T>>::from_slice(&self.nonce);

            let cipher = AesCtrHmac::<C, D, T>::new(&key);

            let payload = Payload {
                msg: &self.pt,
                aad: &self.aad,
            };
            let encrypted = cipher.encrypt(&nonce, payload).unwrap();
            let encrypt_pass = self.ct == encrypted;

            let payload = Payload {
                msg: &self.ct,
                aad: &self.aad,
            };
            let decrypted = cipher.decrypt(&nonce, payload).unwrap();
            let decrypt_pass = self.pt == decrypted;

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
                enc_key,
                auth_key,
                nonce,
                aad,
                pt,
                ct,
            } = self;

            format!(
                "~~~ test-vectors
cipher_suite: 0x{cipher_suite:04x}
key: {key:5}
enc_key: {enc_key:9}
auth_key: {auth_key:10}
nonce: {nonce:7}
aad: {aad:5}
pt: {pt:4}
ct: {ct:4}
~~~"
            )
        }
    }
}

mod aes_256_ctr_hmac {
    use super::Hex;
    use aead::{Aead, Key, KeyInit, KeySizeUser, Nonce, Payload};
    use aes::Aes256;
    use cipher::{
        consts::{U10, U32, U4, U8},
        ArrayLength,
    };
    use hex_literal::hex;
    use serde::{Deserialize, Serialize};
    use sframe_reference::{aes_ctr_hmac::*, cipher::CipherSuite};
    use sha2::Sha512;

    #[derive(Serialize, Deserialize)]
    pub struct TestVector {
        cipher_suite: u16,
        key: Hex,
        enc_key: Hex,
        auth_key: Hex,
        nonce: Hex,
        aad: Hex,
        pt: Hex,
        ct: Hex,
    }

    impl TestVector {
        fn new<C, D, T>() -> Self
        where
            C: Cipher + KeySizeUser<KeySize = U32>,
            D: Digest,
            T: ArrayLength<u8>,
            AesCtrHmac<C, D, T>: KeySizeUser + KeyInit,
        {
            let cipher_suite = match T::to_usize() {
                10 => CipherSuite::AES_256_CTR_HMAC_SHA_512_80,
                8 => CipherSuite::AES_256_CTR_HMAC_SHA_512_64,
                4 => CipherSuite::AES_256_CTR_HMAC_SHA_512_32,
                _ => unreachable!(),
            };

            let key = hex!("000102030405060708090a0b0c0d0e0f"
                           "101112131415161718191a1b1c1d1e1f"
                           "202122232425262728292a2b2c2d2e2f"
                           "303132333435363738393a3b3c3d3e3f"
                           "404142434445464748494a4b4c4d4e4f"
                           "505152535455565758595a5b5c5d5e5f");
            let key = Key::<AesCtrHmac<C, D, T>>::clone_from_slice(&key);
            let nonce: Nonce<AesCtrHmac<C, D, T>> = hex!("101112131415161718191a1b").into();
            let aad = b"IETF SFrame WG";
            let pt = b"draft-ietf-sframe-enc";

            let cipher = AesCtrHmac::<C, D, T>::new(&key);
            let ct = cipher.encrypt(&nonce, Payload { msg: pt, aad }).unwrap();

            Self {
                cipher_suite: cipher_suite.0,
                key: Hex::from(key),
                enc_key: Hex::from(cipher.enc_key),
                auth_key: Hex::from(cipher.auth_key),
                nonce: Hex::from(nonce),
                aad: Hex::from(aad),
                pt: Hex::from(pt),
                ct: Hex::from(ct),
            }
        }

        pub fn make_all() -> Vec<Self> {
            vec![
                Self::new::<Aes256, Sha512, U10>(),
                Self::new::<Aes256, Sha512, U8>(),
                Self::new::<Aes256, Sha512, U4>(),
            ]
        }

        fn verify_one<C, D, T>(&self) -> bool
        where
            C: Cipher + KeySizeUser<KeySize = U32>,
            D: Digest,
            T: ArrayLength<u8>,
            AesCtrHmac<C, D, T>: KeySizeUser + KeyInit,
        {
            let key = Key::<AesCtrHmac<C, D, T>>::from_slice(&self.key);
            let nonce = Nonce::<AesCtrHmac<C, D, T>>::from_slice(&self.nonce);

            let cipher = AesCtrHmac::<C, D, T>::new(&key);

            let payload = Payload {
                msg: &self.pt,
                aad: &self.aad,
            };
            let encrypted = cipher.encrypt(&nonce, payload).unwrap();
            let encrypt_pass = self.ct == encrypted;

            let payload = Payload {
                msg: &self.ct,
                aad: &self.aad,
            };
            let decrypted = cipher.decrypt(&nonce, payload).unwrap();
            let decrypt_pass = self.pt == decrypted;

            encrypt_pass && decrypt_pass
        }

        pub fn verify(&self) -> bool {
            match CipherSuite(self.cipher_suite) {
                CipherSuite::AES_256_CTR_HMAC_SHA_512_80 => {
                    self.verify_one::<Aes256, Sha512, U10>()
                }
                CipherSuite::AES_256_CTR_HMAC_SHA_512_64 => self.verify_one::<Aes256, Sha512, U8>(),
                CipherSuite::AES_256_CTR_HMAC_SHA_512_32 => self.verify_one::<Aes256, Sha512, U4>(),
                _ => unreachable!(),
            }
        }
    }

    impl super::ToMarkdown for TestVector {
        fn to_markdown(&self) -> String {
            let TestVector {
                cipher_suite,
                key,
                enc_key,
                auth_key,
                nonce,
                aad,
                pt,
                ct,
            } = self;

            format!(
                "~~~ test-vectors
cipher_suite: 0x{cipher_suite:04x}
key: {key:5}
enc_key: {enc_key:9}
auth_key: {auth_key:10}
nonce: {nonce:7}
aad: {aad:5}
pt: {pt:4}
ct: {ct:4}
~~~"
            )
        }
    }
}

mod sframe {
    use super::Hex;
    use hex_literal::hex;
    use serde::{Deserialize, Serialize};
    use sframe_reference::*;

    #[derive(Serialize, Deserialize)]
    pub struct TestVector {
        cipher_suite: u16,
        kid: u64,
        ctr: u64,
        base_key: Hex,
        sframe_key_label: Hex,
        sframe_salt_label: Hex,
        sframe_secret: Hex,
        sframe_key: Hex,
        sframe_salt: Hex,
        metadata: Hex,
        nonce: Hex,
        aad: Hex,
        pt: Hex,
        ct: Hex,
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
                base_key: Hex::from(base_key),
                sframe_key_label: Hex::from(cipher.sframe_key_label()),
                sframe_salt_label: Hex::from(cipher.sframe_salt_label()),
                sframe_secret: Hex::from(cipher.sframe_secret()),
                sframe_key: Hex::from(cipher.sframe_key()),
                sframe_salt: Hex::from(cipher.sframe_salt()),
                metadata: Hex::from(metadata),
                nonce: Hex::from(vals.nonce),
                aad: Hex::from(vals.aad),
                pt: Hex::from(pt),
                ct: Hex::from(ct),
            }
        }

        pub fn make_rfc() -> Vec<TestVector> {
            sframe_reference::cipher::RFC_CIPHER_SUITES
                .iter()
                .map(|&cipher_suite| TestVector::new(cipher_suite))
                .collect()
        }

        pub fn make_aes_256_ctr_hmac() -> Vec<TestVector> {
            sframe_reference::cipher::AES_256_CTR_HMAC_CIPHER_SUITES
                .iter()
                .map(|&cipher_suite| TestVector::new(cipher_suite))
                .collect()
        }

        pub fn verify(&self) -> bool {
            let cipher_suite = CipherSuite(self.cipher_suite);
            let kid = KeyId(self.kid);
            let ctr = Counter(self.ctr);

            let mut ctx = SFrameContext::new(cipher_suite);
            ctx.add_send_key(kid, &self.base_key).unwrap();
            let (encrypted, _) = ctx.encrypt_raw(kid, ctr, &self.metadata, &self.pt).unwrap();
            let encrypt_pass = self.ct == encrypted;

            let mut ctx = SFrameContext::new(cipher_suite);
            ctx.add_recv_key(kid, &self.base_key).unwrap();
            let (decrypted, _) = ctx.decrypt(&self.metadata, &self.ct).unwrap();
            let decrypt_pass = self.pt == decrypted;

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
                "~~~ test-vectors
cipher_suite: 0x{cipher_suite:04x}
kid: 0x{kid:016x}
ctr: 0x{ctr:016x}
base_key: {base_key:10}
sframe_key_label: {sframe_key_label:18}
sframe_salt_label: {sframe_salt_label:19}
sframe_secret: {sframe_secret:15}
sframe_key: {sframe_key:12}
sframe_salt: {sframe_salt:13}
metadata: {metadata:10}
nonce: {nonce:7}
aad: {aad:5}
pt: {pt:4}
ct: {ct:4}
~~~"
            )
        }
    }
}

use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

/// Type Hex encapsulates a byte string that will serialize as a single hex string in JSON, or as a
/// chunked, line-wrapped, and padded hex string in Markdown.
struct Hex(Vec<u8>);

impl Display for Hex {
    // Divide the hex string into 16-byte chunks, each on its own line, and aligned to make space
    // for a field name.  We abuse the "width" formatting parameter to specify how much each line
    // after the first should be indented.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const SIZE: usize = 16;

        let n_chunks = (self.0.len() + (SIZE - 1)) / SIZE;
        for (i, c) in self.0.chunks(SIZE).enumerate() {
            if i > 0 {
                f.pad("")?;
            }

            f.write_str(&hex::encode(c))?;

            if i < n_chunks - 1 {
                f.write_str("\n")?;
            }
        }
        Ok(())
    }
}

impl<T: AsRef<[u8]>> From<T> for Hex {
    fn from(value: T) -> Self {
        Hex(Vec::from(value.as_ref()))
    }
}

impl Serialize for Hex {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Hex {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(
            hex::decode(<String as Deserialize<'de>>::deserialize(deserializer)?)
                .expect("invalid hex"),
            // TODO: this should map to an error, but we can't instantiation `D::Error`.
        ))
    }
}

impl std::ops::Deref for Hex {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: AsRef<[u8]>> PartialEq<T> for Hex {
    fn eq(&self, other: &T) -> bool {
        &self.0 == other.as_ref()
    }
}

#[derive(Copy, Clone, PartialEq, ValueEnum)]
enum TestVectorType {
    Header,
    Aes128CtrHmac,
    Aes256CtrHmac,
    SframeRfc,
    SframeAes256CtrHmac,
}

trait ToMarkdown {
    fn to_markdown(&self) -> String;
}

// The serde directives here are for the following purposes:
// * `default` - allows some types of test vector to be absent on deserialize
// * `skip_serializing_if` - don't serialize empty vectors
// * `rename` - maintain backwards compatibility with the current test vectors
#[derive(Default, Serialize, Deserialize)]
struct TestVectors {
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    header: Vec<header::TestVector>,

    #[serde(
        rename = "aes_ctr_hmac",
        skip_serializing_if = "Vec::is_empty",
        default = "Vec::new"
    )]
    aes_128_ctr_hmac: Vec<aes_128_ctr_hmac::TestVector>,

    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    aes_256_ctr_hmac: Vec<aes_256_ctr_hmac::TestVector>,

    #[serde(
        rename = "sframe",
        skip_serializing_if = "Vec::is_empty",
        default = "Vec::new"
    )]
    sframe_rfc: Vec<sframe::TestVector>,

    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    sframe_aes_256_ctr_hmac: Vec<sframe::TestVector>,
}

impl TestVectors {
    fn make_all() -> Self {
        Self {
            header: header::TestVector::make_all(),
            aes_128_ctr_hmac: aes_128_ctr_hmac::TestVector::make_all(),
            aes_256_ctr_hmac: aes_256_ctr_hmac::TestVector::make_all(),
            sframe_rfc: sframe::TestVector::make_rfc(),
            sframe_aes_256_ctr_hmac: sframe::TestVector::make_aes_256_ctr_hmac(),
        }
    }

    fn make(which: &[TestVectorType]) -> Self {
        let mut tvs = Self::default();

        if which.contains(&TestVectorType::Header) {
            tvs.header = header::TestVector::make_all();
        }

        if which.contains(&TestVectorType::Aes128CtrHmac) {
            tvs.aes_128_ctr_hmac = aes_128_ctr_hmac::TestVector::make_all();
        }

        if which.contains(&TestVectorType::Aes128CtrHmac) {
            tvs.aes_256_ctr_hmac = aes_256_ctr_hmac::TestVector::make_all();
        }

        if which.contains(&TestVectorType::SframeRfc) {
            tvs.sframe_rfc = sframe::TestVector::make_rfc();
        }

        if which.contains(&TestVectorType::SframeAes256CtrHmac) {
            tvs.sframe_aes_256_ctr_hmac = sframe::TestVector::make_aes_256_ctr_hmac();
        }

        tvs
    }

    fn verify_all(&self) -> bool {
        let header = self.header.iter().map(|tv| tv.verify());
        let aes_128_ctr_hmac = self.aes_128_ctr_hmac.iter().map(|tv| tv.verify());
        let aes_256_ctr_hmac = self.aes_256_ctr_hmac.iter().map(|tv| tv.verify());
        let sframe_rfc = self.sframe_rfc.iter().map(|tv| tv.verify());
        let sframe_aes_256_ctr_hmac = self.sframe_aes_256_ctr_hmac.iter().map(|tv| tv.verify());

        header
            .chain(aes_128_ctr_hmac)
            .chain(aes_256_ctr_hmac)
            .chain(sframe_rfc)
            .chain(sframe_aes_256_ctr_hmac)
            .all(|x| x)
    }

    fn print_md_all<T: ToMarkdown>(vecs: &[T]) {
        for vec in vecs {
            println!("{}\n", vec.to_markdown());
        }
    }

    fn print_md(&self) {
        if !self.header.is_empty() {
            Self::print_md_all(&self.header)
        }

        if !self.aes_128_ctr_hmac.is_empty() {
            Self::print_md_all(&self.aes_128_ctr_hmac)
        }

        if !self.aes_256_ctr_hmac.is_empty() {
            Self::print_md_all(&self.aes_256_ctr_hmac)
        }

        if !self.sframe_rfc.is_empty() {
            Self::print_md_all(&self.sframe_rfc)
        }

        if !self.sframe_aes_256_ctr_hmac.is_empty() {
            Self::print_md_all(&self.sframe_aes_256_ctr_hmac)
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
    Md {
        #[clap(default_values = ["header", "aes128-ctr-hmac", "sframe-rfc"])]
        which: Vec<TestVectorType>,
    },
    Json {
        #[clap(default_values = ["header", "aes128-ctr-hmac", "sframe-rfc"])]
        which: Vec<TestVectorType>,
    },
    Verify,
    SelfTest,
}

fn main() -> Result<(), u32> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Md { which } => {
            let vec = TestVectors::make(which);
            vec.print_md();
            Ok(())
        }

        Commands::Json { which } => {
            let vec = TestVectors::make(which);
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

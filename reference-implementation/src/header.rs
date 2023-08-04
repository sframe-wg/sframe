use crate::{Error, Result};

use core::cmp::max;
use std::convert::TryInto;

/// An SFrame key ID
#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone)]
pub struct KeyId(pub u64);

/// An SFrame counter
#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone)]
pub struct Counter(pub u64);

/// The SFrame header.  It stores KID and CTR values for a ciphertext, and the encoded form.
#[derive(PartialEq, Eq, Debug)]
pub struct Header {
    /// The key ID for the key with which the ciphertext was encrypted
    pub kid: KeyId,

    /// The counter used to form a unique nonce for the ciphertext
    pub ctr: Counter,

    encoded: Vec<u8>,
}

fn min_encoded_len(val: u64) -> usize {
    max((u64::BITS - val.leading_zeros() + 7) / 8, 1)
        .try_into()
        .unwrap()
}

fn write_be_bytes(out: &mut [u8], val: u64) {
    let bytes = val.to_be_bytes();
    let start = bytes.len() - out.len();
    out.copy_from_slice(&bytes[start..]);
}

fn parse_be_bytes(data: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    let start = bytes.len() - data.len();
    bytes[start..].copy_from_slice(data);
    u64::from_be_bytes(bytes)
}

impl Header {
    /// Encode a new SFrame header with the specified KID and CTR values
    pub fn new(kid: KeyId, ctr: Counter) -> Self {
        let (kid_len, mut config_byte) = if kid.0 < 0x08 {
            (0, kid.0.try_into().unwrap())
        } else {
            let kid_len = min_encoded_len(kid.0);
            let kid_len_u8: u8 = (kid_len - 1).try_into().unwrap();
            (kid_len, 0x08 | kid_len_u8)
        };

        let ctr_len = min_encoded_len(ctr.0);
        let ctr_len_u8: u8 = (ctr_len - 1).try_into().unwrap();
        config_byte |= ctr_len_u8 << 4;

        let kid_start = 1;
        let ctr_start = kid_start + kid_len;
        let ctr_end = ctr_start + ctr_len;
        let mut encoded = vec![0u8; 1 + kid_len + ctr_len];

        encoded[0] = config_byte;
        write_be_bytes(&mut encoded[kid_start..ctr_start], kid.0);
        write_be_bytes(&mut encoded[ctr_start..ctr_end], ctr.0);

        Self { kid, ctr, encoded }
    }

    /// Decode an SFrame header from the beginning of the ciphertext.  Returns the header and the
    /// part of the ciphertext that remains after the header.
    pub fn parse(ciphertext: &[u8]) -> Result<(Self, &[u8])> {
        let header = ciphertext[0] & 0x7f; // Mask the R bit
        let ctr_len: usize = ((header >> 4) + 1).into();
        let kid_len: usize = if header & 0x08 != 0 {
            ((header & 0x07) + 1).into()
        } else {
            0
        };

        if ciphertext.len() < 1 + kid_len + ctr_len {
            return Err(Error::InsufficientHeaderData);
        }

        let kid_start = 1;
        let ctr_start = kid_start + kid_len;
        let header_end = ctr_start + ctr_len;
        let kid: u64 = if kid_len > 0 {
            parse_be_bytes(&ciphertext[kid_start..ctr_start])
        } else {
            (header & 0x07).into()
        };
        let kid = KeyId(kid);

        let ctr = parse_be_bytes(&ciphertext[ctr_start..header_end]);
        let ctr = Counter(ctr);

        let (header, raw_ciphertext) = ciphertext.split_at(header_end);
        let encoded = header.to_vec();

        Ok((Self { kid, ctr, encoded }, raw_ciphertext))
    }

    /// A view of the encoded header value
    pub fn as_slice(&self) -> &[u8] {
        self.encoded.as_slice()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn round_trip() {
        for log_kid in 0..64 {
            for log_ctr in 0..64 {
                let kid = KeyId(1 << log_kid);
                let ctr = Counter(1 << log_ctr);

                let before = Header::new(kid, ctr);
                let (after, rest) = Header::parse(before.as_slice()).unwrap();
                assert_eq!(rest.len(), 0);
                assert_eq!(before, after);
            }
        }
    }

    #[test]
    fn selective_known_answer() {
        let cases: [(KeyId, Counter, &[u8]); 10] = [
            (KeyId(0), Counter(0), &hex!("0000")),
            (KeyId(0), Counter(7), &hex!("0007")),
            (KeyId(7), Counter(0), &hex!("0700")),
            (KeyId(7), Counter(7), &hex!("0707")),
            (KeyId(0), Counter(8), &hex!("0008")),
            (KeyId(8), Counter(0), &hex!("080800")),
            (KeyId(8), Counter(8), &hex!("080808")),
            (
                KeyId(0xffffffffffffffff),
                Counter(0),
                &hex!("0fffffffffffffffff00"),
            ),
            (
                KeyId(0),
                Counter(0xffffffffffffffff),
                &hex!("70ffffffffffffffff"),
            ),
            (
                KeyId(0xffffffffffffffff),
                Counter(0xffffffffffffffff),
                &hex!("7fffffffffffffffffffffffffffffffff"),
            ),
        ];

        for (kid, ctr, encoded) in cases {
            let constructed = Header::new(kid, ctr);
            assert_eq!(encoded, constructed.as_slice());

            let (parsed, rest) = Header::parse(encoded).unwrap();
            assert_eq!(rest.len(), 0);
            assert_eq!(parsed.kid, kid);
            assert_eq!(parsed.ctr, ctr);
            assert_eq!(parsed.encoded, encoded);
        }
    }
}

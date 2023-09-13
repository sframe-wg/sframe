use crate::{Error, Result};

use core::cmp::max;
use std::convert::TryInto;
use std::io::Read;

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

enum ValueOrLength {
    Value(u64),
    Length(usize),
}

impl ValueOrLength {
    fn len(&self) -> usize {
        use ValueOrLength::*;
        match self {
            Value(_) => 0,
            Length(len) => *len,
        }
    }

    fn read(&self, data: &mut impl Read) -> Result<u64> {
        use ValueOrLength::*;
        match self {
            Value(val) => Ok(*val),
            Length(len) => {
                let start = 8 - len;
                let mut bytes = [0u8; 8];
                data.read(&mut bytes[start..])
                    .map_err(|_| Error::InsufficientHeaderData)?;
                Ok(u64::from_be_bytes(bytes))
            }
        }
    }
}

impl From<u64> for ValueOrLength {
    fn from(x: u64) -> Self {
        use ValueOrLength::*;
        match x {
            x if x < 8 => Value(x),
            x => Length(min_encoded_len(x)),
        }
    }
}

impl From<u8> for ValueOrLength {
    fn from(x: u8) -> Self {
        use ValueOrLength::*;
        match x {
            x if (x & 0x08) == 0 => Value(x.into()),
            x => Length(((x & 0x07) + 1).into()),
        }
    }
}

impl From<ValueOrLength> for u8 {
    fn from(x: ValueOrLength) -> Self {
        use ValueOrLength::*;
        match x {
            Value(val) => (val & 0x07) as u8,
            Length(len) => ((len - 1) | 0x08) as u8,
        }
    }
}

struct ConfigByte {
    kid: ValueOrLength,
    ctr: ValueOrLength,
}

impl ConfigByte {
    fn new(kid: KeyId, ctr: Counter) -> Self {
        Self {
            kid: kid.0.into(),
            ctr: ctr.0.into(),
        }
    }

    fn header_len(&self) -> usize {
        1 + self.kid.len() + self.ctr.len()
    }
}

impl From<u8> for ConfigByte {
    fn from(x: u8) -> Self {
        Self {
            kid: (x >> 4).into(),
            ctr: (x & 0x0f).into(),
        }
    }
}

impl From<ConfigByte> for u8 {
    fn from(x: ConfigByte) -> Self {
        let kid: u8 = x.kid.into();
        let ctr: u8 = x.ctr.into();
        (kid << 4) | ctr
    }
}

impl Header {
    /// Encode a new SFrame header with the specified KID and CTR values
    pub fn new(kid: KeyId, ctr: Counter) -> Self {
        let config = ConfigByte::new(kid, ctr);
        let kid_len = config.kid.len();
        let ctr_len = config.ctr.len();

        let kid_start = 1;
        let ctr_start = kid_start + kid_len;
        let ctr_end = ctr_start + ctr_len;
        let mut encoded = vec![0u8; 1 + kid_len + ctr_len];

        encoded[0] = config.into();
        write_be_bytes(&mut encoded[kid_start..ctr_start], kid.0);
        write_be_bytes(&mut encoded[ctr_start..ctr_end], ctr.0);

        Self { kid, ctr, encoded }
    }

    /// Decode an SFrame header from the beginning of the ciphertext.  Returns the header and the
    /// part of the ciphertext that remains after the header.
    pub fn parse(ciphertext: &[u8]) -> Result<(Self, &[u8])> {
        let config: ConfigByte = ciphertext[0].into();

        let mut reader = &ciphertext[1..];
        let kid = KeyId(config.kid.read(&mut reader)?);
        let ctr = Counter(config.ctr.read(&mut reader)?);

        let (header, raw_ciphertext) = ciphertext.split_at(config.header_len());
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
            (KeyId(0), Counter(0), &hex!("00")),
            (KeyId(0), Counter(7), &hex!("07")),
            (KeyId(7), Counter(0), &hex!("70")),
            (KeyId(7), Counter(7), &hex!("77")),
            (KeyId(0), Counter(8), &hex!("0808")),
            (KeyId(8), Counter(0), &hex!("8008")),
            (KeyId(8), Counter(8), &hex!("880808")),
            (
                KeyId(0xffffffffffffffff),
                Counter(0),
                &hex!("f0ffffffffffffffff"),
            ),
            (
                KeyId(0),
                Counter(0xffffffffffffffff),
                &hex!("0fffffffffffffffff"),
            ),
            (
                KeyId(0xffffffffffffffff),
                Counter(0xffffffffffffffff),
                &hex!("ffffffffffffffffffffffffffffffffff"),
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

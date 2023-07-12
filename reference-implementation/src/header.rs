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

fn to_min_be_bytes(val: u64) -> Vec<u8> {
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&x| x != 0).unwrap_or(7);
    bytes[start..].to_vec()
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
        let mut encoded = vec![0];

        if kid.0 < 0x08 {
            encoded[0] |= kid.0 as u8;
        } else {
            let mut kid_bytes = to_min_be_bytes(kid.0);
            encoded[0] |= 0x08 | ((kid_bytes.len() - 1) as u8);
            encoded.append(&mut kid_bytes);
        }

        let mut ctr_bytes = to_min_be_bytes(ctr.0);
        encoded[0] |= ((ctr_bytes.len() - 1) as u8) << 4;
        encoded.append(&mut ctr_bytes);

        Self { kid, ctr, encoded }
    }

    /// Decode an SFrame header from the beginning of the ciphertext.  Returns the header and the
    /// part of the ciphertext that remains after the header.
    pub fn parse(ciphertext: &[u8]) -> (Self, &[u8]) {
        let header = ciphertext[0] & 0x7f; // Mask the R bit
        let ctr_len = ((header >> 4) + 1) as usize;
        let kid_len = if header & 0x08 != 0 {
            ((header & 0x07) + 1) as usize
        } else {
            0
        };

        let kid_start = 1;
        let ctr_start = kid_start + kid_len;
        let header_end = ctr_start + ctr_len;
        let kid = if kid_len > 0 {
            parse_be_bytes(&ciphertext[kid_start..ctr_start])
        } else {
            (header & 0x07) as u64
        };
        let kid = KeyId(kid);

        let ctr = parse_be_bytes(&ciphertext[ctr_start..header_end]);
        let ctr = Counter(ctr);

        let (header, raw_ciphertext) = ciphertext.split_at(header_end);
        let encoded = header.to_vec();

        (Self { kid, ctr, encoded }, raw_ciphertext)
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
                let (after, rest) = Header::parse(before.as_slice());
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

            let (parsed, rest) = Header::parse(encoded);
            assert_eq!(rest.len(), 0);
            assert_eq!(parsed.kid, kid);
            assert_eq!(parsed.ctr, ctr);
            assert_eq!(parsed.encoded, encoded);
        }
    }
}

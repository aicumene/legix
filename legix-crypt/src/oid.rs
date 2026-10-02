use std::{fmt, str::FromStr};

use crate::Error;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// The id of an encrypted object: the BLAKE3 hash of its bytes, written `blake3:` and 64 lowercase hex digits.
///
/// The id is the hash of the encrypted bytes, not of the document, so anyone can check that an object matches its id
/// — a relay, a backup, a device without the key — and no one learns anything about the document from it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid([u8; 32]);

impl Oid {
    /// The prefix of an id's text form.
    pub const PREFIX: &'static str = "blake3:";

    /// The id of an object with these bytes.
    pub fn of(object: &[u8]) -> Self {
        Oid(*blake3::hash(object).as_bytes())
    }

    /// An id from its 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Oid(bytes)
    }

    /// The id's 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The 64 lowercase hex digits of the id, without the prefix.
    pub fn to_hex(&self) -> String {
        let mut hex = String::with_capacity(64);
        for byte in self.0 {
            hex.push(char::from(HEX[usize::from(byte >> 4)]));
            hex.push(char::from(HEX[usize::from(byte & 0xf)]));
        }
        hex
    }

    /// An id from 64 lowercase hex digits, without the prefix.
    pub fn from_hex(hex: &str) -> Result<Self, Error> {
        let hex = hex.as_bytes();
        if hex.len() != 64 {
            return Err(Error::Oid("expected 64 hex digits"));
        }
        let digit = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        let mut bytes = [0; 32];
        for (byte, [high, low]) in bytes.iter_mut().zip(hex.as_chunks::<2>().0) {
            let (Some(high), Some(low)) = (digit(*high), digit(*low)) else {
                return Err(Error::Oid("expected lowercase hex digits"));
            };
            *byte = (high << 4) | low;
        }
        Ok(Oid(bytes))
    }

    pub(crate) fn from_hasher(hasher: &blake3::Hasher) -> Self {
        Oid(*hasher.finalize().as_bytes())
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", Self::PREFIX, self.to_hex())
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({self})")
    }
}

impl FromStr for Oid {
    type Err = Error;

    /// Read the text form, `blake3:` and 64 lowercase hex digits.
    fn from_str(text: &str) -> Result<Self, Error> {
        let hex = text
            .strip_prefix(Self::PREFIX)
            .ok_or(Error::Oid("expected `blake3:` and 64 hex digits"))?;
        Self::from_hex(hex)
    }
}

use std::{fmt, str::FromStr};

use legix_sign::ssh_key::{HashAlg, PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, hex};

/// The id of a device: the SHA-256 hash of its public key in SSH wire encoding — the digest its `SHA256:` fingerprint
/// shows — written as 64 lowercase hex digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId([u8; 32]);

impl DeviceId {
    /// The id of the device with this public key.
    pub fn of(key: &PublicKey) -> Self {
        let fingerprint = key.fingerprint(HashAlg::Sha256);
        DeviceId(fingerprint.as_bytes().try_into().expect("a SHA-256 digest is 32 bytes"))
    }

    /// An id from its 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        DeviceId(bytes)
    }

    /// The id's 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The 64 lowercase hex digits of the id.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// An id from 64 lowercase hex digits.
    pub fn from_hex(text: &str) -> Result<Self, Error> {
        let mut bytes = [0; 32];
        hex::decode(text, &mut bytes).ok_or(Error::Format("a device id is 64 lowercase hex digits"))?;
        Ok(DeviceId(bytes))
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({self})")
    }
}

impl FromStr for DeviceId {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        Self::from_hex(text)
    }
}

/// The key the members of a repository share. It wraps bundle keys and document keys, and relays never have it.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct GroupKey([u8; 32]);

impl GroupKey {
    /// A new key from the operating system's random numbers.
    pub fn generate() -> Result<Self, Error> {
        let mut key = GroupKey([0; 32]);
        crate::random(&mut key.0)?;
        Ok(key)
    }

    /// A key from its bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        GroupKey(bytes)
    }

    /// The key's bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for GroupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GroupKey(…)")
    }
}

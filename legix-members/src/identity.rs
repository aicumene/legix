//! A device's X25519 keys, and the group keys sealed for them.

use std::{fmt, str::FromStr};

use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit, Nonce, Tag, XChaCha20Poly1305, XNonce};
use curve25519_dalek::montgomery::MontgomeryPoint;
use hkdf::Hkdf;
use legix_sync::GroupKey;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{Error, hex};

/// The length of a group key sealed for a recipient: the ephemeral share, the key and the tag.
pub const SEALED_LEN: usize = 32 + 32 + 16;
/// The length of a previous group key under the next one: nonce, key and tag.
pub const PREVIOUS_LEN: usize = 24 + 32 + 16;

const KEY_INFO: &[u8] = b"legix-members/1 key ";
const PREVIOUS_AAD: &[u8] = b"legix-members/1 previous ";

/// A device's X25519 secret key, which opens the group keys sealed for the device. The device keeps it, like its
/// signing key, in its keychain.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Identity([u8; 32]);

impl Identity {
    /// A new key from the operating system's random numbers.
    pub fn generate() -> Result<Self, Error> {
        let mut identity = Identity([0; 32]);
        crate::random(&mut identity.0)?;
        Ok(identity)
    }

    /// A key from its bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Identity(bytes)
    }

    /// The key's bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The public key that group keys are sealed for.
    pub fn recipient(&self) -> Recipient {
        Recipient(MontgomeryPoint::mul_base_clamped(self.0).to_bytes())
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Identity(…)")
    }
}

/// A device's X25519 public key, written `x25519:` and 64 lowercase hex digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Recipient([u8; 32]);

impl Recipient {
    /// A recipient from its 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Recipient(bytes)
    }

    /// The recipient's 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "x25519:{}", hex::encode(&self.0))
    }
}

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Recipient({self})")
    }
}

impl FromStr for Recipient {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        let mut bytes = [0; 32];
        text.strip_prefix("x25519:")
            .and_then(|hex| hex::decode(hex, &mut bytes))
            .ok_or(Error::Format("a recipient is `x25519:` and 64 lowercase hex digits"))?;
        Ok(Recipient(bytes))
    }
}

/// Seal `key`, the group key of `epoch`, for `recipient`, in the context of the entry's `group` field.
pub(crate) fn seal(
    key: &GroupKey,
    recipient: &Recipient,
    group: &[u8; 32],
    epoch: u64,
) -> Result<[u8; SEALED_LEN], Error> {
    let mut ephemeral = Zeroizing::new([0; 32]);
    crate::random(&mut ephemeral[..])?;
    seal_with_ephemeral(key, recipient, group, epoch, &ephemeral)
}

pub(crate) fn seal_with_ephemeral(
    key: &GroupKey,
    recipient: &Recipient,
    group: &[u8; 32],
    epoch: u64,
    ephemeral: &[u8; 32],
) -> Result<[u8; SEALED_LEN], Error> {
    let share = MontgomeryPoint::mul_base_clamped(*ephemeral).to_bytes();
    let shared = Zeroizing::new(MontgomeryPoint(recipient.0).mul_clamped(*ephemeral).to_bytes());
    if *shared == [0; 32] {
        return Err(Error::Format("the recipient is not a usable X25519 key"));
    }
    let mut sealed = [0; SEALED_LEN];
    let (share_out, rest) = sealed.split_at_mut(32);
    let (key_out, tag_out) = rest.split_at_mut(32);
    share_out.copy_from_slice(&share);
    key_out.copy_from_slice(key.as_bytes());
    let tag = wrap_cipher(&shared, &share, recipient, group, epoch)
        .encrypt_inout_detached(&Nonce::from([0; 12]), &[], key_out.into())
        .expect("32 bytes are far below the cipher's limit");
    tag_out.copy_from_slice(&tag);
    Ok(sealed)
}

/// Open a group key sealed for `identity`.
pub(crate) fn unseal(
    sealed: &[u8; SEALED_LEN],
    identity: &Identity,
    group: &[u8; 32],
    epoch: u64,
) -> Result<GroupKey, Error> {
    let (share, rest) = sealed.split_at(32);
    let (wrapped, tag) = rest.split_at(32);
    let share: [u8; 32] = share.try_into().expect("32 bytes");
    let shared = Zeroizing::new(MontgomeryPoint(share).mul_clamped(identity.0).to_bytes());
    if *shared == [0; 32] {
        return Err(Error::Unseal);
    }
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(wrapped);
    wrap_cipher(&shared, &share, &identity.recipient(), group, epoch)
        .decrypt_inout_detached(
            &Nonce::from([0; 12]),
            &[],
            (&mut key[..]).into(),
            &Tag::try_from(tag).expect("16 bytes"),
        )
        .map_err(|_| Error::Unseal)?;
    Ok(GroupKey::from_bytes(*key))
}

fn wrap_cipher(
    shared: &[u8; 32],
    share: &[u8; 32],
    recipient: &Recipient,
    group: &[u8; 32],
    epoch: u64,
) -> ChaCha20Poly1305 {
    let salt = [&share[..], &recipient.0].concat();
    let info = [KEY_INFO, group, &epoch.to_be_bytes()].concat();
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(&salt), shared)
        .expand(&info, &mut key[..])
        .expect("32 bytes is a valid length");
    ChaCha20Poly1305::new_from_slice(&key[..]).expect("32 bytes is the key length")
}

/// The key of the previous epoch, encrypted under the key of `epoch`, so that holders of a key hold every earlier one.
pub(crate) fn seal_previous(
    previous: &GroupKey,
    next: &GroupKey,
    group: &[u8; 32],
    epoch: u64,
) -> Result<[u8; PREVIOUS_LEN], Error> {
    let mut nonce = [0; 24];
    crate::random(&mut nonce)?;
    Ok(seal_previous_with_nonce(previous, next, group, epoch, &nonce))
}

pub(crate) fn seal_previous_with_nonce(
    previous: &GroupKey,
    next: &GroupKey,
    group: &[u8; 32],
    epoch: u64,
    nonce: &[u8; 24],
) -> [u8; PREVIOUS_LEN] {
    let mut out = [0; PREVIOUS_LEN];
    let (nonce_out, rest) = out.split_at_mut(24);
    let (key_out, tag_out) = rest.split_at_mut(32);
    nonce_out.copy_from_slice(nonce);
    key_out.copy_from_slice(previous.as_bytes());
    let tag = previous_cipher(next)
        .encrypt_inout_detached(&XNonce::from(*nonce), &previous_aad(group, epoch), key_out.into())
        .expect("32 bytes are far below the cipher's limit");
    tag_out.copy_from_slice(&tag);
    out
}

/// The key of the epoch before `epoch`, from the `previous` line of the entry that started `epoch`.
pub(crate) fn open_previous(
    sealed: &[u8; PREVIOUS_LEN],
    next: &GroupKey,
    group: &[u8; 32],
    epoch: u64,
) -> Result<GroupKey, Error> {
    let (nonce, rest) = sealed.split_at(24);
    let (wrapped, tag) = rest.split_at(32);
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(wrapped);
    previous_cipher(next)
        .decrypt_inout_detached(
            &XNonce::try_from(nonce).expect("24 bytes"),
            &previous_aad(group, epoch),
            (&mut key[..]).into(),
            &Tag::try_from(tag).expect("16 bytes"),
        )
        .map_err(|_| Error::Unseal)?;
    Ok(GroupKey::from_bytes(*key))
}

fn previous_cipher(next: &GroupKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(next.as_bytes()).expect("32 bytes is the key length")
}

fn previous_aad(group: &[u8; 32], epoch: u64) -> Vec<u8> {
    [PREVIOUS_AAD, group, &epoch.to_be_bytes()].concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> GroupKey {
        GroupKey::from_bytes(std::array::from_fn(|i| i as u8))
    }

    const GROUP: [u8; 32] = [0x22; 32];

    /// A recipient, a sealed group key and a previous key for known inputs, pinned so that the formats cannot change
    /// unnoticed. The same bytes come out of an independent implementation of FORMAT.md on OpenSSL (Python's
    /// `cryptography`).
    #[test]
    fn known_sealed_keys() {
        let identity = Identity::from_bytes(std::array::from_fn(|i| 0x50 + i as u8));
        assert_eq!(
            identity.recipient().to_string(),
            "x25519:392d174a38b3b1beafaf1fe824870841c5fa531bc6eafdb6402c124664488c1c"
        );
        let sealed = seal_with_ephemeral(
            &key(),
            &identity.recipient(),
            &GROUP,
            2,
            &std::array::from_fn(|i| 0x70 + i as u8),
        )
        .unwrap();
        assert_eq!(
            hex::encode(&sealed),
            "23b7bb8c91ae008711fb12846780bcdf1e065f821bdfec49f57e7c7dcd4c4823b72fba6197a024334748d564b1f29cbfe33727\
             9a7efcecd78b770ff783d260a7285209d395eb4df1e03ae94dd2f1b70f"
        );
        assert_eq!(
            unseal(&sealed, &identity, &GROUP, 2).unwrap().as_bytes(),
            key().as_bytes()
        );
        let stranger = Identity::from_bytes([9; 32]);
        assert!(matches!(unseal(&sealed, &stranger, &GROUP, 2), Err(Error::Unseal)));
        assert!(
            matches!(unseal(&sealed, &identity, &GROUP, 3), Err(Error::Unseal)),
            "bound to its epoch"
        );
        assert!(
            matches!(unseal(&sealed, &identity, &[0; 32], 2), Err(Error::Unseal)),
            "bound to its group"
        );

        let next = GroupKey::from_bytes(std::array::from_fn(|i| 0x40 + i as u8));
        let previous = seal_previous_with_nonce(&key(), &next, &GROUP, 2, &std::array::from_fn(|i| 0x10 + i as u8));
        assert_eq!(
            hex::encode(&previous),
            "101112131415161718191a1b1c1d1e1f2021222324252627524aeb4005f948255478563928585cf9143dd2e3b429d5db09a7b45\
             62c252f0005291fa635c2dbf55c170fa1e77eca89"
        );
        assert_eq!(
            open_previous(&previous, &next, &GROUP, 2).unwrap().as_bytes(),
            key().as_bytes()
        );
        assert!(matches!(
            open_previous(&previous, &key(), &GROUP, 2),
            Err(Error::Unseal)
        ));
        assert!(matches!(open_previous(&previous, &next, &GROUP, 3), Err(Error::Unseal)));
    }

    #[test]
    fn a_recipient_of_low_order_is_refused() {
        let low = Recipient::from_bytes([0; 32]);
        assert!(seal(&key(), &low, &GROUP, 1).is_err());
        assert_eq!(
            "x25519:".to_owned() + &"ab".repeat(32),
            Recipient::from_bytes([0xab; 32]).to_string()
        );
        assert!("x25519:AB".parse::<Recipient>().is_err());
    }
}

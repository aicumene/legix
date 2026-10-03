use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use legix_crypt::{DocumentKey, Oid};
use zeroize::Zeroizing;

use crate::{Access, Error, GroupKey};

const MAGIC: &[u8; 17] = b"legix-envelope/2\n";
const AAD_PREFIX: &[u8] = b"legix-envelope/2 ";
const NONCE_LEN: usize = 24;

/// The length of an envelope.
pub const ENVELOPE_LEN: usize = MAGIC.len() + 8 + NONCE_LEN + 32 + 16;

/// An envelope that carries the key of document `oid` to the members: the key encrypted with `group`, the key of
/// `epoch`, and bound to the document.
pub fn seal_envelope(group: &GroupKey, epoch: u64, oid: &Oid, key: &DocumentKey) -> Result<Vec<u8>, Error> {
    let mut nonce = [0; NONCE_LEN];
    crate::random(&mut nonce)?;
    Ok(seal_with_nonce(group, epoch, oid, key, &nonce))
}

pub(crate) fn seal_with_nonce(
    group: &GroupKey,
    epoch: u64,
    oid: &Oid,
    key: &DocumentKey,
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let mut wrapped = Zeroizing::new(*key.as_bytes());
    let tag = cipher(group)
        .encrypt_inout_detached(&XNonce::from(*nonce), &aad(epoch, oid), (&mut wrapped[..]).into())
        .expect("32 bytes are far below the cipher's limit");
    [&MAGIC[..], &epoch.to_be_bytes(), nonce, &wrapped[..], &tag].concat()
}

/// The epoch whose key an envelope is sealed with.
pub fn envelope_epoch(envelope: &[u8]) -> Result<u64, Error> {
    if envelope.len() != ENVELOPE_LEN || !envelope.starts_with(MAGIC) {
        return Err(Error::Format("not a legix-envelope/2 envelope"));
    }
    Ok(u64::from_be_bytes(
        envelope[MAGIC.len()..MAGIC.len() + 8].try_into().expect("8 bytes"),
    ))
}

/// The key of document `oid` in `envelope`, opened with the key of its epoch from `access`.
pub fn open_envelope(access: &(impl Access + ?Sized), oid: &Oid, envelope: &[u8]) -> Result<DocumentKey, Error> {
    let epoch = envelope_epoch(envelope)?;
    let group = access.key(epoch).ok_or(Error::NoKey(epoch))?;
    let (nonce, rest) = envelope[MAGIC.len() + 8..].split_at(NONCE_LEN);
    let (wrapped, tag) = rest.split_at(32);
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(wrapped);
    cipher(&group)
        .decrypt_inout_detached(
            &XNonce::try_from(nonce).expect("24 bytes"),
            &aad(epoch, oid),
            (&mut key[..]).into(),
            &Tag::try_from(tag).expect("16 bytes"),
        )
        .map_err(|_| Error::Envelope(*oid))?;
    Ok(DocumentKey::from_bytes(*key))
}

fn cipher(group: &GroupKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(group.as_bytes()).expect("32 bytes is the key length")
}

fn aad(epoch: u64, oid: &Oid) -> Vec<u8> {
    [AAD_PREFIX, &epoch.to_be_bytes(), oid.as_bytes()].concat()
}

#[cfg(test)]
mod tests {
    use legix_sign::ssh_key::PublicKey;

    use super::*;
    use crate::{DeviceId, Fixed, Problem};

    /// Access to the key of epoch 3 only.
    struct Epoch3(GroupKey);

    impl Access for Epoch3 {
        fn current(&self) -> Result<(u64, GroupKey), Error> {
            Ok((3, self.0.clone()))
        }

        fn key(&self, epoch: u64) -> Option<GroupKey> {
            (epoch == 3).then(|| self.0.clone())
        }

        fn may_publish(&self, _: &DeviceId, _: &PublicKey, _: u64, _: u64, _: u64) -> Result<String, Problem> {
            unreachable!("envelopes are not bundles")
        }
    }

    /// An envelope for a known group key, epoch, nonce, document and key, pinned so that the format cannot change
    /// unnoticed. The same bytes come out of an independent implementation of FORMAT.md on OpenSSL (Python's
    /// `cryptography`).
    #[test]
    fn a_known_envelope() {
        let group = GroupKey::from_bytes(std::array::from_fn(|i| 0x40 + i as u8));
        let oid: Oid = "blake3:c0d50151e78d1ba23494e2c884809eedd6d770f49ffb4cb797cecb633e0b20b8"
            .parse()
            .unwrap();
        let key = DocumentKey::from_bytes(std::array::from_fn(|i| i as u8));
        let envelope = seal_with_nonce(&group, 3, &oid, &key, &std::array::from_fn(|i| 0x10 + i as u8));
        assert_eq!(
            crate::hex::encode(&envelope),
            "6c656769782d656e76656c6f70652f320a0000000000000003101112131415161718191a1b1c1d1e1f2021222324252627524aeb\
             4005f948255478563928585cf9143dd2e3b429d5db09a7b4562c252f004e8b8e8e1381416b6732f5794f1f16a9"
        );
        assert_eq!(envelope.len(), ENVELOPE_LEN);
        assert_eq!(envelope_epoch(&envelope).unwrap(), 3);
        let access = Epoch3(group);
        assert_eq!(
            open_envelope(&access, &oid, &envelope).unwrap().as_bytes(),
            key.as_bytes()
        );

        let other = Oid::of(b"another document");
        assert!(matches!(
            open_envelope(&access, &other, &envelope),
            Err(Error::Envelope(_))
        ));
        let stranger = Epoch3(GroupKey::from_bytes([9; 32]));
        assert!(matches!(
            open_envelope(&stranger, &oid, &envelope),
            Err(Error::Envelope(_))
        ));
        let epoch_one = Fixed::new(GroupKey::from_bytes([9; 32]), Default::default());
        assert!(matches!(
            open_envelope(&epoch_one, &oid, &envelope),
            Err(Error::NoKey(3))
        ));
        assert!(matches!(
            open_envelope(&access, &oid, &envelope[1..]),
            Err(Error::Format(_))
        ));
    }
}

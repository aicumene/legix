use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use legix_crypt::{DocumentKey, Oid};
use zeroize::Zeroizing;

use crate::{Error, GroupKey};

const MAGIC: &[u8; 17] = b"legix-envelope/1\n";
const AAD_PREFIX: &[u8] = b"legix-envelope/1 ";
const NONCE_LEN: usize = 24;

/// The length of an envelope.
pub const ENVELOPE_LEN: usize = MAGIC.len() + NONCE_LEN + 32 + 16;

/// An envelope that carries the key of document `oid` to the members: the key encrypted with the group key and bound to
/// the document.
pub fn seal_envelope(group: &GroupKey, oid: &Oid, key: &DocumentKey) -> Result<Vec<u8>, Error> {
    let mut nonce = [0; NONCE_LEN];
    crate::random(&mut nonce)?;
    Ok(seal_with_nonce(group, oid, key, &nonce))
}

pub(crate) fn seal_with_nonce(group: &GroupKey, oid: &Oid, key: &DocumentKey, nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut wrapped = Zeroizing::new(*key.as_bytes());
    let tag = cipher(group)
        .encrypt_inout_detached(&XNonce::from(*nonce), &aad(oid), (&mut wrapped[..]).into())
        .expect("32 bytes are far below the cipher's limit");
    [&MAGIC[..], nonce, &wrapped[..], &tag].concat()
}

/// The key of document `oid` in `envelope`.
pub fn open_envelope(group: &GroupKey, oid: &Oid, envelope: &[u8]) -> Result<DocumentKey, Error> {
    if envelope.len() != ENVELOPE_LEN || !envelope.starts_with(MAGIC) {
        return Err(Error::Format("not a legix-envelope/1 envelope"));
    }
    let (nonce, rest) = envelope[MAGIC.len()..].split_at(NONCE_LEN);
    let (wrapped, tag) = rest.split_at(32);
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(wrapped);
    cipher(group)
        .decrypt_inout_detached(
            &XNonce::try_from(nonce).expect("24 bytes"),
            &aad(oid),
            (&mut key[..]).into(),
            &Tag::try_from(tag).expect("16 bytes"),
        )
        .map_err(|_| Error::Envelope(*oid))?;
    Ok(DocumentKey::from_bytes(*key))
}

fn cipher(group: &GroupKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(group.as_bytes()).expect("32 bytes is the key length")
}

fn aad(oid: &Oid) -> Vec<u8> {
    [AAD_PREFIX, oid.as_bytes()].concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An envelope for a known group key, nonce, document and key, pinned so that the format cannot change unnoticed.
    /// The same bytes come out of an independent implementation of FORMAT.md on OpenSSL (Python's `cryptography`).
    #[test]
    fn a_known_envelope() {
        let group = GroupKey::from_bytes(std::array::from_fn(|i| 0x40 + i as u8));
        let oid: Oid = "blake3:c0d50151e78d1ba23494e2c884809eedd6d770f49ffb4cb797cecb633e0b20b8"
            .parse()
            .unwrap();
        let key = DocumentKey::from_bytes(std::array::from_fn(|i| i as u8));
        let envelope = seal_with_nonce(&group, &oid, &key, &std::array::from_fn(|i| 0x10 + i as u8));
        assert_eq!(
            crate::hex::encode(&envelope),
            "6c656769782d656e76656c6f70652f310a101112131415161718191a1b1c1d1e1f2021222324252627524aeb4005f948255478\
             563928585cf9143dd2e3b429d5db09a7b4562c252f00de0b2078796c36dfa19f1eab205c157d"
        );
        assert_eq!(envelope.len(), ENVELOPE_LEN);
        assert_eq!(
            open_envelope(&group, &oid, &envelope).unwrap().as_bytes(),
            key.as_bytes()
        );

        let other = Oid::of(b"another document");
        assert!(matches!(
            open_envelope(&group, &other, &envelope),
            Err(Error::Envelope(_))
        ));
        let stranger = GroupKey::from_bytes([9; 32]);
        assert!(matches!(
            open_envelope(&stranger, &oid, &envelope),
            Err(Error::Envelope(_))
        ));
        assert!(matches!(
            open_envelope(&group, &oid, &envelope[1..]),
            Err(Error::Format(_))
        ));
    }
}

use std::{
    collections::HashMap,
    fmt, fs, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{Error, Oid, fsutil};

/// A document's key: 32 random bytes for one document, kept outside the repository.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DocumentKey([u8; 32]);

impl DocumentKey {
    /// A new key from the operating system's random numbers.
    pub fn generate() -> Result<Self, Error> {
        let mut key = DocumentKey([0; 32]);
        crate::random(&mut key.0)?;
        Ok(key)
    }

    /// A key from its bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        DocumentKey(bytes)
    }

    /// The key's bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for DocumentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DocumentKey(…)")
    }
}

/// The key a [`DirKeyStore`] wraps document keys with. The application keeps it elsewhere — in the operating system's
/// keychain or in hardware — so that a copy of the key store's directory reveals no document key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StoreKey([u8; 32]);

impl StoreKey {
    /// A new key from the operating system's random numbers.
    pub fn generate() -> Result<Self, Error> {
        let mut key = StoreKey([0; 32]);
        crate::random(&mut key.0)?;
        Ok(key)
    }

    /// A key from its bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        StoreKey(bytes)
    }

    /// The key's bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for StoreKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoreKey(…)")
    }
}

/// What a key store holds for an object.
#[derive(Debug)]
pub enum KeyState {
    /// The key of the object.
    Present(DocumentKey),
    /// The key was destroyed here: the document is erased.
    Erased,
    /// There is no key for the object here.
    Missing,
}

/// Where document keys are kept, by the id of their object.
///
/// Keys are destroyable, unlike the history: erasing a key erases the document. A key store remembers what it erased,
/// so that a copy of the key that arrives later — from a backup, from another device — cannot bring the document
/// back.
pub trait KeyStore {
    /// What this store holds for `oid`.
    fn get(&self, oid: &Oid) -> Result<KeyState, Error>;

    /// Keep `key` for `oid`. An object has one key: keeping the same key again is not an error, a different one is
    /// refused with [`Error::KeyConflict`] and the kept key stays. Refused with [`Error::Erased`] if the key of `oid`
    /// was erased here.
    fn put(&self, oid: &Oid, key: &DocumentKey) -> Result<(), Error>;

    /// Destroy the key of `oid` and remember that it was erased. Erasing again, or erasing a key this store never
    /// had, is not an error.
    fn erase(&self, oid: &Oid) -> Result<(), Error>;
}

impl<K: KeyStore + ?Sized> KeyStore for &K {
    fn get(&self, oid: &Oid) -> Result<KeyState, Error> {
        (**self).get(oid)
    }

    fn put(&self, oid: &Oid, key: &DocumentKey) -> Result<(), Error> {
        (**self).put(oid, key)
    }

    fn erase(&self, oid: &Oid) -> Result<(), Error> {
        (**self).erase(oid)
    }
}

impl<K: KeyStore + ?Sized> KeyStore for Arc<K> {
    fn get(&self, oid: &Oid) -> Result<KeyState, Error> {
        (**self).get(oid)
    }

    fn put(&self, oid: &Oid, key: &DocumentKey) -> Result<(), Error> {
        (**self).put(oid, key)
    }

    fn erase(&self, oid: &Oid) -> Result<(), Error> {
        (**self).erase(oid)
    }
}

/// `Ok` if `key` is the key kept for `oid`, compared in constant time.
fn same_key(oid: &Oid, kept: &DocumentKey, key: &DocumentKey) -> Result<(), Error> {
    if bool::from(kept.as_bytes().ct_eq(key.as_bytes())) {
        Ok(())
    } else {
        Err(Error::KeyConflict(*oid))
    }
}

/// Keys in memory, for tests and for applications that keep keys in a store of their own.
#[derive(Default)]
pub struct MemoryKeyStore {
    /// `None` for an erased key.
    keys: Mutex<HashMap<Oid, Option<DocumentKey>>>,
}

impl fmt::Debug for MemoryKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryKeyStore").finish_non_exhaustive()
    }
}

impl KeyStore for MemoryKeyStore {
    fn get(&self, oid: &Oid) -> Result<KeyState, Error> {
        Ok(match self.keys.lock().expect("not poisoned").get(oid) {
            Some(Some(key)) => KeyState::Present(key.clone()),
            Some(None) => KeyState::Erased,
            None => KeyState::Missing,
        })
    }

    fn put(&self, oid: &Oid, key: &DocumentKey) -> Result<(), Error> {
        let mut keys = self.keys.lock().expect("not poisoned");
        match keys.get_mut(oid) {
            Some(None) => Err(Error::Erased(*oid)),
            Some(Some(kept)) => same_key(oid, kept, key),
            None => {
                keys.insert(*oid, Some(key.clone()));
                Ok(())
            }
        }
    }

    fn erase(&self, oid: &Oid) -> Result<(), Error> {
        // Replacing the entry drops the key, which zeroes it.
        self.keys.lock().expect("not poisoned").insert(*oid, None);
        Ok(())
    }
}

/// Keys in a directory, each wrapped with a [`StoreKey`] in a file of its own.
///
/// `keys/` holds a file per key, `erased/` an empty file per erased key, both named by the object's id like an
/// [`ObjectStore`](crate::ObjectStore). A key file is the magic `legix-key/1\n`, a random 24-byte nonce and the key
/// encrypted with XChaCha20-Poly1305 under the store key, authenticated together with the object's id: a key file
/// opens only with its store key and only for its object.
///
/// Erasing overwrites the key file before removing it, but on SSDs and copy-on-write file systems the old bytes can
/// stay on the disk. They are of no use without the store key.
#[derive(Debug)]
pub struct DirKeyStore {
    dir: PathBuf,
    key: StoreKey,
}

const KEY_FILE_MAGIC: &[u8; 12] = b"legix-key/1\n";
const KEY_NONCE_LEN: usize = 24;
const KEY_FILE_LEN: usize = KEY_FILE_MAGIC.len() + KEY_NONCE_LEN + 32 + 16;
const KEY_AAD_PREFIX: &[u8] = b"legix-crypt/1 key ";

impl DirKeyStore {
    /// A key store in `dir`, wrapping keys with `key`. The directory is created when the first key is kept.
    pub fn new(dir: impl Into<PathBuf>, key: StoreKey) -> Self {
        DirKeyStore { dir: dir.into(), key }
    }

    /// The directory of the key store.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn key_path(&self, oid: &Oid) -> PathBuf {
        fsutil::fan_out(&self.dir.join("keys"), oid)
    }

    fn erased_path(&self, oid: &Oid) -> PathBuf {
        fsutil::fan_out(&self.dir.join("erased"), oid)
    }

    fn is_erased(&self, oid: &Oid) -> Result<bool, Error> {
        Ok(self.erased_path(oid).try_exists()?)
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new_from_slice(self.key.as_bytes()).expect("32 bytes is the key length")
    }

    fn aad(oid: &Oid) -> Vec<u8> {
        [KEY_AAD_PREFIX, oid.as_bytes()].concat()
    }

    fn wrap(&self, oid: &Oid, key: &DocumentKey) -> Result<[u8; KEY_FILE_LEN], Error> {
        let mut nonce = [0; KEY_NONCE_LEN];
        crate::random(&mut nonce)?;
        Ok(self.wrap_with_nonce(oid, key, &nonce))
    }

    fn wrap_with_nonce(&self, oid: &Oid, key: &DocumentKey, nonce: &[u8; KEY_NONCE_LEN]) -> [u8; KEY_FILE_LEN] {
        let mut file = [0; KEY_FILE_LEN];
        let (magic, rest) = file.split_at_mut(KEY_FILE_MAGIC.len());
        let (nonce_out, rest) = rest.split_at_mut(KEY_NONCE_LEN);
        let (wrapped, tag) = rest.split_at_mut(32);
        magic.copy_from_slice(KEY_FILE_MAGIC);
        nonce_out.copy_from_slice(nonce);
        wrapped.copy_from_slice(key.as_bytes());
        let computed = self
            .cipher()
            .encrypt_inout_detached(&XNonce::from(*nonce), &Self::aad(oid), wrapped.into())
            .expect("32 bytes are far below the cipher's limit");
        tag.copy_from_slice(&computed);
        file
    }

    fn unwrap(&self, oid: &Oid, file: &[u8]) -> Result<DocumentKey, Error> {
        let invalid = |reason| Error::KeyFile { oid: *oid, reason };
        if file.len() != KEY_FILE_LEN {
            return Err(invalid("it has the wrong length"));
        }
        let (magic, rest) = file.split_at(KEY_FILE_MAGIC.len());
        if magic != KEY_FILE_MAGIC {
            return Err(invalid("it does not start with `legix-key/1`"));
        }
        let (nonce, rest) = rest.split_at(KEY_NONCE_LEN);
        let (wrapped, tag) = rest.split_at(32);
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(wrapped);
        self.cipher()
            .decrypt_inout_detached(
                &XNonce::try_from(nonce).expect("24 bytes"),
                &Self::aad(oid),
                (&mut key[..]).into(),
                &Tag::try_from(tag).expect("16 bytes"),
            )
            .map_err(|_| invalid("it does not open with this store key, or it is the key of another object"))?;
        Ok(DocumentKey::from_bytes(*key))
    }
}

impl KeyStore for DirKeyStore {
    fn get(&self, oid: &Oid) -> Result<KeyState, Error> {
        if self.is_erased(oid)? {
            return Ok(KeyState::Erased);
        }
        match fs::read(self.key_path(oid)) {
            Ok(file) => Ok(KeyState::Present(self.unwrap(oid, &file)?)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(KeyState::Missing),
            Err(err) => Err(err.into()),
        }
    }

    fn put(&self, oid: &Oid, key: &DocumentKey) -> Result<(), Error> {
        if self.is_erased(oid)? {
            return Err(Error::Erased(*oid));
        }
        let path = self.key_path(oid);
        if !fsutil::write_new(&path, &self.wrap(oid, key)?)? {
            return match self.get(oid)? {
                KeyState::Present(kept) => same_key(oid, &kept, key),
                KeyState::Erased => Err(Error::Erased(*oid)),
                // Removed between the write and the read, and not by an erasure, which leaves its record first.
                KeyState::Missing => self.put(oid, key),
            };
        }
        // An erasure that ran while the key was written wins.
        if self.is_erased(oid)? {
            fsutil::destroy(&path)?;
            return Err(Error::Erased(*oid));
        }
        Ok(())
    }

    fn erase(&self, oid: &Oid) -> Result<(), Error> {
        // The tombstone first: from here on the key reads as erased, even if destroying the file is interrupted.
        let erased = self.erased_path(oid);
        if !erased.try_exists()? {
            fsutil::write_atomically(&erased, b"")?;
        }
        fsutil::destroy(&self.key_path(oid))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key file for a known store key, nonce, object and document key, pinned so that the format cannot change
    /// unnoticed. The same bytes come out of an independent implementation of FORMAT.md on OpenSSL (Python's
    /// `cryptography`, with HChaCha20 checked against draft-irtf-cfrg-xchacha).
    #[test]
    fn a_known_key_file() {
        let store = DirKeyStore::new("unused", StoreKey::from_bytes(std::array::from_fn(|i| 0x40 + i as u8)));
        let oid: Oid = "blake3:c0d50151e78d1ba23494e2c884809eedd6d770f49ffb4cb797cecb633e0b20b8"
            .parse()
            .unwrap();
        let key = DocumentKey::from_bytes(std::array::from_fn(|i| i as u8));
        let file = store.wrap_with_nonce(&oid, &key, &std::array::from_fn(|i| 0x10 + i as u8));
        let hex = file.iter().fold(String::new(), |mut hex, byte| {
            use std::fmt::Write;
            write!(hex, "{byte:02x}").unwrap();
            hex
        });
        assert_eq!(
            hex,
            "6c656769782d6b65792f310a101112131415161718191a1b1c1d1e1f2021222324252627524aeb4005f948255478563928585cf9\
             143dd2e3b429d5db09a7b4562c252f00e341ca84d4c848f2fe6c9e4b7f61f045"
        );
        assert_eq!(store.unwrap(&oid, &file).unwrap().as_bytes(), key.as_bytes());
    }
}

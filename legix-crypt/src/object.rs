//! The encrypted object, version 1: how a document is encrypted under its key. `FORMAT.md` specifies it byte by byte.
//!
//! An object is a header followed by the payload:
//!
//! - the header is the magic `legix-crypt/1\n`, a random 16-byte salt and a 32-byte commitment to the key;
//! - the payload is the document in chunks of 64 KiB, each encrypted with ChaCha20-Poly1305 under a key derived from
//!   the document key and the salt, with the chunk's number and a flag for the last chunk in its nonce.
//!
//! Any change to an object, cutting it short, extending it or reordering its chunks makes it fail authentication, and
//! the commitment makes an object open under one key only.

use std::io::{self, Read, Write};

use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit, Nonce, Tag};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{DocumentKey, Error, Oid, Pointer};

/// The first bytes of every object of this version.
pub const MAGIC: &[u8; 14] = b"legix-crypt/1\n";
/// The length of the random salt in the header.
pub const SALT_LEN: usize = 16;
/// The length of the key commitment in the header.
pub const COMMITMENT_LEN: usize = 32;
/// The length of the header: magic, salt and commitment.
pub const HEADER_LEN: usize = MAGIC.len() + SALT_LEN + COMMITMENT_LEN;
/// The length of the document in each chunk but the last.
pub const CHUNK_LEN: usize = 64 * 1024;
/// The length of the authentication tag after each chunk.
pub const TAG_LEN: usize = 16;

const PAYLOAD_INFO: &[u8] = b"legix-crypt/1 payload";
const COMMITMENT_INFO: &[u8] = b"legix-crypt/1 commitment";

/// The length of the object for a document of `document_len` bytes, or `None` if it would not fit in 64 bits.
pub fn sealed_len(document_len: u64) -> Option<u64> {
    let chunks = document_len.div_ceil(CHUNK_LEN as u64).max(1);
    chunks
        .checked_mul(TAG_LEN as u64)?
        .checked_add(document_len)?
        .checked_add(HEADER_LEN as u64)
}

/// The length of the document in an object of `object_len` bytes, or `None` if no object has that length.
pub fn document_len(object_len: u64) -> Option<u64> {
    let payload = object_len.checked_sub(HEADER_LEN as u64)?;
    let full = (CHUNK_LEN + TAG_LEN) as u64;
    let (full_chunks, rest) = (payload / full, payload % full);
    match rest {
        0 if full_chunks == 0 => None,
        0 => Some(full_chunks * CHUNK_LEN as u64),
        rest if rest < TAG_LEN as u64 => None,
        // The last chunk is empty only when it is the only one.
        rest if rest == TAG_LEN as u64 && full_chunks > 0 => None,
        rest => Some(full_chunks * CHUNK_LEN as u64 + rest - TAG_LEN as u64),
    }
}

/// Encrypt everything `document` yields under `key`, write the object to `object` and return the pointer to it.
///
/// Every object gets a new random salt, so encrypting a document twice — even under the same key — gives two
/// different objects.
pub fn seal(key: &DocumentKey, document: impl Read, object: impl Write) -> Result<Pointer, Error> {
    let mut salt = [0; SALT_LEN];
    crate::random(&mut salt)?;
    seal_with_salt(key, &salt, document, object)
}

pub(crate) fn seal_with_salt(
    key: &DocumentKey,
    salt: &[u8; SALT_LEN],
    mut document: impl Read,
    object: impl Write,
) -> Result<Pointer, Error> {
    let keys = Keys::derive(key, salt);
    let mut out = Hashing::new(object);
    out.write_all(MAGIC)?;
    out.write_all(salt)?;
    out.write_all(&keys.commitment[..])?;

    let mut buf = Zeroizing::new(vec![0; CHUNK_LEN]);
    let mut len = read_full(&mut document, &mut buf)?;
    let (mut chunk, mut size) = (0u64, 0u64);
    loop {
        // A full chunk is the last one only if the document ends right after it.
        let mut next = Zeroizing::new([0u8; 1]);
        let more = len == CHUNK_LEN && read_full(&mut document, &mut next[..])? == 1;
        let data = &mut buf[..len];
        let tag = keys
            .payload
            .encrypt_inout_detached(&nonce(chunk, !more), &[], data.into())
            .expect("a chunk is far below the cipher's limit");
        out.write_all(data)?;
        out.write_all(&tag)?;
        size += len as u64;
        if !more {
            break;
        }
        buf[0] = next[0];
        len = 1 + read_full(&mut document, &mut buf[1..])?;
        chunk += 1;
    }
    out.flush()?;
    Ok(Pointer {
        oid: Oid::from_hasher(&out.hasher),
        size,
    })
}

/// Decrypt the object `object` yields with `key`, write the document to `document` and return its length.
///
/// A wrong key is refused before anything is decrypted. Chunks are written as they are authenticated: if opening
/// fails part-way — the object was altered, cut short or extended — what was written is incomplete and must be
/// discarded. [`Documents::read`](crate::Documents::read) checks the object against its id first, so nothing is
/// written unless the object is the one the pointer names.
pub fn open(key: &DocumentKey, mut object: impl Read, mut document: impl Write) -> Result<u64, Error> {
    let keys = read_header(key, &mut object)?;

    // One byte more than a chunk tells whether the chunk is the last one.
    let mut buf = Zeroizing::new(vec![0; CHUNK_LEN + TAG_LEN + 1]);
    let mut len = read_full(&mut object, &mut buf)?;
    let (mut chunk, mut size) = (0u64, 0u64);
    loop {
        let last = len <= CHUNK_LEN + TAG_LEN;
        let chunk_len = if last { len } else { CHUNK_LEN + TAG_LEN };
        // A chunk has at least its tag, and the last chunk is empty only when it is the only one.
        if chunk_len < TAG_LEN || (last && chunk_len == TAG_LEN && chunk > 0) {
            return Err(Error::Authentication { chunk });
        }
        let (data, tag) = buf[..chunk_len].split_at_mut(chunk_len - TAG_LEN);
        let tag = Tag::try_from(&*tag).expect("the tag's length");
        keys.payload
            .decrypt_inout_detached(&nonce(chunk, last), &[], (&mut *data).into(), &tag)
            .map_err(|_| Error::Authentication { chunk })?;
        document.write_all(data)?;
        size += data.len() as u64;
        if last {
            break;
        }
        buf[0] = buf[CHUNK_LEN + TAG_LEN];
        len = 1 + read_full(&mut object, &mut buf[1..])?;
        chunk += 1;
    }
    document.flush()?;
    Ok(size)
}

/// Check that `key` is the key `object` was encrypted with, from the object's header alone: nothing is decrypted.
pub fn check_key(key: &DocumentKey, mut object: impl Read) -> Result<(), Error> {
    read_header(key, &mut object).map(drop)
}

/// Read an object's header and derive its keys from `key`, refusing a key the header does not commit to.
fn read_header(key: &DocumentKey, object: &mut impl Read) -> Result<Keys, Error> {
    let mut header = [0; HEADER_LEN];
    if read_full(object, &mut header)? < HEADER_LEN {
        return Err(Error::Format("shorter than the header"));
    }
    let (magic, rest) = header.split_at(MAGIC.len());
    if magic != MAGIC {
        return Err(Error::Format("it does not start with `legix-crypt/1`"));
    }
    let (salt, commitment) = rest.split_at(SALT_LEN);
    let keys = Keys::derive(key, salt.try_into().expect("the salt's length"));
    if !bool::from(keys.commitment.ct_eq(commitment)) {
        return Err(Error::WrongKey);
    }
    Ok(keys)
}

/// The keys derived from a document key and an object's salt.
struct Keys {
    payload: ChaCha20Poly1305,
    commitment: Zeroizing<[u8; COMMITMENT_LEN]>,
}

impl Keys {
    fn derive(key: &DocumentKey, salt: &[u8; SALT_LEN]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(Some(salt), key.as_bytes());
        let mut payload = Zeroizing::new([0; 32]);
        hkdf.expand(PAYLOAD_INFO, &mut payload[..])
            .expect("32 bytes is a valid length");
        let mut commitment = Zeroizing::new([0; COMMITMENT_LEN]);
        hkdf.expand(COMMITMENT_INFO, &mut commitment[..])
            .expect("32 bytes is a valid length");
        Keys {
            payload: ChaCha20Poly1305::new_from_slice(&payload[..]).expect("32 bytes is the key length"),
            commitment,
        }
    }
}

/// The nonce of a chunk: its number as 11 bytes big-endian, then 1 for the last chunk and 0 for the others.
fn nonce(chunk: u64, last: bool) -> Nonce {
    let mut nonce = [0; 12];
    nonce[3..11].copy_from_slice(&chunk.to_be_bytes());
    nonce[11] = u8::from(last);
    Nonce::from(nonce)
}

/// Read until `buf` is full or the input ends, and return how much was read.
pub(crate) fn read_full(input: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match input.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

/// A writer that hashes what it writes.
pub(crate) struct Hashing<W> {
    inner: W,
    pub(crate) hasher: blake3::Hasher,
}

impl<W> Hashing<W> {
    pub(crate) fn new(inner: W) -> Self {
        Hashing {
            inner,
            hasher: blake3::Hasher::new(),
        }
    }
}

impl<W: Write> Write for Hashing<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> DocumentKey {
        DocumentKey::from_bytes(std::array::from_fn(|i| i as u8))
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut hex, byte| {
            use std::fmt::Write;
            write!(hex, "{byte:02x}").unwrap();
            hex
        })
    }

    /// Objects for a known key, salt and documents, pinned so that the format cannot change unnoticed. The same bytes
    /// come out of an independent implementation of FORMAT.md on OpenSSL (Python's `cryptography`).
    #[test]
    fn known_objects() {
        let salt: [u8; SALT_LEN] = std::array::from_fn(|i| 0xa0 + i as u8);
        let one_chunk = vec![0; CHUNK_LEN];
        let three_chunks: Vec<u8> = (0..2 * CHUNK_LEN + 100).map(|i| (i % 251) as u8).collect();
        for (document, len, oid) in [
            (
                &b"Heads of terms"[..],
                92,
                "blake3:c0d50151e78d1ba23494e2c884809eedd6d770f49ffb4cb797cecb633e0b20b8",
            ),
            (
                &b""[..],
                78,
                "blake3:c0437b88659de4395d4fbca8675386ec875489f0312813467c9c923a91f45840",
            ),
            (
                &one_chunk[..],
                65_614,
                "blake3:f488d0f7fcd6ed32e211192599e380dc967537e44c9b640aee43d5f8d6929fc3",
            ),
            (
                &three_chunks[..],
                131_282,
                "blake3:38de8dc5130e3e5086495b97931b99ba21fc356b02d56bd930e9086c23d3e23c",
            ),
        ] {
            let mut object = Vec::new();
            let pointer = seal_with_salt(&key(), &salt, document, &mut object).unwrap();
            assert_eq!((object.len(), pointer.oid.to_string().as_str()), (len, oid));
            assert_eq!(pointer.oid, Oid::of(&object));
            assert_eq!(pointer.size, document.len() as u64);
            assert_eq!(sealed_len(pointer.size), Some(len as u64));
            assert_eq!(document_len(len as u64), Some(pointer.size));

            let mut opened = Vec::new();
            assert_eq!(open(&key(), &object[..], &mut opened).unwrap(), pointer.size);
            assert_eq!(opened, document);
        }

        let mut object = Vec::new();
        seal_with_salt(&key(), &salt, &b"Heads of terms"[..], &mut object).unwrap();
        assert_eq!(
            hex(&object),
            "6c656769782d63727970742f310aa0a1a2a3a4a5a6a7a8a9aaabacadaeaf7c70a62d5c3ea14354e8cd619ea906bcc20db98891e16c\
             0307f55211da8f2de9377d299cea8535a4bc63d472194a08a5739afd60127b3b1e41331df8050d"
        );
    }

    #[test]
    fn an_empty_last_chunk_after_a_full_one_is_refused() {
        let salt = [7; SALT_LEN];
        let keys = Keys::derive(&key(), &salt);
        let mut object = Vec::new();
        object.extend_from_slice(MAGIC);
        object.extend_from_slice(&salt);
        object.extend_from_slice(&keys.commitment[..]);
        let mut full = vec![1u8; CHUNK_LEN];
        let tag = keys
            .payload
            .encrypt_inout_detached(&nonce(0, false), &[], full.as_mut_slice().into())
            .unwrap();
        object.extend_from_slice(&full);
        object.extend_from_slice(&tag);
        let tag = keys
            .payload
            .encrypt_inout_detached(&nonce(1, true), &[], (&mut [][..]).into())
            .unwrap();
        object.extend_from_slice(&tag);

        assert!(matches!(
            open(&key(), &object[..], io::sink()),
            Err(Error::Authentication { chunk: 1 })
        ));
        assert_eq!(
            document_len(object.len() as u64),
            None,
            "no document has this object length"
        );
    }
}

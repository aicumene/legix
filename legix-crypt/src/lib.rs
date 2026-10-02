//! Encrypted documents for git. The repository holds a pointer; the document is stored encrypted under a key of its
//! own, outside the repository. Destroying the key erases the document wherever the history went, and the history —
//! its ids and its signatures — stays as it is.
//!
//! - [`Documents::add`] encrypts a document under a new random [`DocumentKey`] into an object, in a chunked format
//!   that detects any change, truncation or reordering ([`object`], specified byte by byte in `FORMAT.md`).
//! - The object is named by the BLAKE3 hash of its bytes, its [`Oid`], and kept in an [`ObjectStore`]. Anyone can
//!   check an object against its id without a key: relays and backups can hold objects they cannot read.
//! - A [`Pointer`], three lines of text, takes the document's place in the repository. A commit that holds the pointer
//!   commits to exactly one document: the id names one object, and the object's header commits to its key.
//! - The key is kept in a [`KeyStore`]. [`Documents::erase`] destroys it: copies of the object left in clones, backups
//!   or relays can no longer be read.
//!
//! ```
//! use legix_crypt::{Documents, Error, MemoryKeyStore, ObjectStore, Pointer};
//!
//! let dir = tempfile::tempdir()?;
//! let documents = Documents::new(ObjectStore::new(dir.path().join("objects")), MemoryKeyStore::default());
//!
//! let pointer = documents.add(&b"Heads of terms"[..])?;
//! let text = pointer.to_string(); // what the repository holds in the document's place
//! assert!(text.starts_with("version legix-crypt/1\noid blake3:"));
//! assert_eq!(documents.read_to_vec(&text.parse::<Pointer>()?)?, b"Heads of terms");
//!
//! documents.erase(&pointer.oid)?;
//! assert!(matches!(documents.read_to_vec(&pointer), Err(Error::Erased(_))));
//! # Ok::<_, Box<dyn std::error::Error>>(())
//! ```
//!
//! ## What erasure covers
//!
//! Erasing destroys the key in the key store it is called on and remembers the erasure there, so a copy of the key
//! that arrives later is refused. Other key stores that hold the key — on other devices, in backups of a key store —
//! must erase it too; until they do, they can read the document. A [`DirKeyStore`] wraps every key with a
//! [`StoreKey`] the application keeps elsewhere, in a keychain or in hardware, because on SSDs and copy-on-write file
//! systems a deleted file can stay on the disk.
//!
//! The pointer stays in the history: it tells that a document of its size was there, under the path it was
//! committed at. Choose paths accordingly.
//!
//! ## Stability
//!
//! The formats — the object, the pointer and the key file — are versioned and specified in `FORMAT.md`. A version, once
//! released, is read by every later release. The API follows semantic versioning, and the crate does not depend on the
//! engine. The cryptography has not yet had an independent audit.
#![deny(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

mod documents;
mod error;
mod fsutil;
mod keys;
pub mod object;
mod oid;
mod pointer;
mod store;

pub use documents::{Documents, Status};
pub use error::Error;
pub use keys::{DirKeyStore, DocumentKey, KeyState, KeyStore, MemoryKeyStore, StoreKey};
pub use oid::Oid;
pub use pointer::Pointer;
pub use store::ObjectStore;

/// Fill `buf` from the operating system's random numbers.
pub(crate) fn random(buf: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(buf).map_err(Error::Random)
}

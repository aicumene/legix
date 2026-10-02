use crate::Oid;

/// Errors of this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Reading or writing failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The text is not a pointer of a version this crate reads.
    #[error("not a legix-crypt pointer: {0}")]
    Pointer(&'static str),
    /// The text is not an object id.
    #[error("not an object id: {0}")]
    Oid(&'static str),
    /// The data is not an object of a version this crate reads.
    #[error("not a legix-crypt/1 object: {0}")]
    Format(&'static str),
    /// The document's key was destroyed: the document is erased.
    #[error("{0}: the document was erased")]
    Erased(Oid),
    /// The key store has no key for the document. It may not have reached this device yet.
    #[error("{0}: no key for the document in this key store")]
    KeyMissing(Oid),
    /// The object store has no object with this id.
    #[error("{0}: the object is not in this store")]
    ObjectMissing(Oid),
    /// The stored object does not hash to its id: it was damaged or replaced.
    #[error("{expected}: the stored object hashes to {actual}")]
    Corrupt {
        /// The id the object is stored under.
        expected: Oid,
        /// The id of the bytes that are stored.
        actual: Oid,
    },
    /// The key store keeps a different key for the object. An object has one key, so a different one is corrupt or
    /// forged.
    #[error("{0}: a different key is kept for this object")]
    KeyConflict(Oid),
    /// The key is not the one the object was encrypted with.
    #[error("the key does not open this object")]
    WrongKey,
    /// A chunk of the object fails authentication: the object was altered, cut short or extended.
    #[error("the object fails authentication at chunk {chunk}: it was altered, cut short or extended")]
    Authentication {
        /// The chunk, counted from 0.
        chunk: u64,
    },
    /// A key file cannot be read with the store key.
    #[error("{oid}: the key file cannot be read: {reason}")]
    KeyFile {
        /// The object the key file is for.
        oid: Oid,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The operating system could not provide random numbers.
    #[error("the operating system's random number generator failed: {0}")]
    Random(getrandom::Error),
}

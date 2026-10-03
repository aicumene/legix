use legix::ObjectId;
use legix_crypt::Oid;

use crate::DeviceId;

/// Errors of this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Reading or writing failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Encrypting, decrypting or storing a document or an object failed.
    #[error(transparent)]
    Crypt(#[from] legix_crypt::Error),
    /// Signing failed.
    #[error(transparent)]
    Sign(#[from] legix_sign::Error),
    /// The repository could not be read or written.
    #[error("the repository: {0}")]
    Repository(String),
    /// A head, an envelope or the sync state is not in the form this crate reads.
    #[error("not in the expected form: {0}")]
    Format(&'static str),
    /// The bundle key in a head does not open with the group key.
    #[error("the bundle key does not open with this group key")]
    GroupKey,
    /// An envelope does not open with the group key, or it is the envelope of another document.
    #[error("{0}: the envelope does not open with this group key")]
    Envelope(Oid),
    /// The relay holds a bundle of this device that cannot be read or does not continue its chain.
    #[error("bundle {seq} of this device ({device}) on the relay: {problem}")]
    OwnBundle {
        /// This device.
        device: DeviceId,
        /// The bundle's place in the chain.
        seq: u64,
        /// What is wrong with it.
        problem: Problem,
    },
    /// The relay already has a head at this place: heads are never replaced.
    #[error("the relay already has bundle {seq} of {device}")]
    HeadExists {
        /// The device.
        device: DeviceId,
        /// The bundle's place in the chain.
        seq: u64,
    },
    /// The relay does not have the head before this one: chains have no gaps.
    #[error("the relay does not have bundle {} of {device}, which comes first", seq - 1)]
    HeadGap {
        /// The device.
        device: DeviceId,
        /// The place of the head that was refused.
        seq: u64,
    },
    /// The envelope of the document was erased on the relay, which refuses it from then on.
    #[error("{0}: the document was erased")]
    Erased(Oid),
    /// Another sync of this repository by this device is running.
    #[error("another sync of this repository by this device is running")]
    Locked,
    /// The operating system could not provide random numbers.
    #[error("the operating system's random number generator failed: {0}")]
    Random(getrandom::Error),
}

/// Why a bundle is refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Problem {
    /// The head is not in the form of FORMAT.md.
    #[error("the head is not in the expected form: {0}")]
    Format(&'static str),
    /// The head belongs to another device or to another place in the chain than the relay keeps it at.
    #[error("the head belongs to another device or another place in the chain")]
    Misplaced,
    /// The signature is not good.
    #[error("the signature is not good: {0:?}")]
    Signature(legix_sign::Status),
    /// The signing key is not the key of the device the head names.
    #[error("the signing key is not the device's")]
    WrongDevice,
    /// The members do not allow the signing key to publish at the head's time.
    #[error("the key is not a member's: {0:?}")]
    Untrusted(legix_sign::Trust),
    /// The head does not follow the bundle applied before from the device: the chain forks.
    #[error("the head does not follow the previous bundle: the chain forks")]
    Fork,
    /// The head is dated before the previous bundle of the device.
    #[error("the head is dated before the previous bundle")]
    TimeGoesBack,
    /// The body on the relay is not the one the head names.
    #[error("the body on the relay is not the one the head names")]
    BodyMismatch,
    /// The bundle key does not open with the group key.
    #[error("the bundle key does not open with this group key")]
    GroupKey,
    /// The body does not open, or is not in the form of FORMAT.md.
    #[error("the body: {0}")]
    Body(String),
    /// The git bundle sets a ref that is neither a branch nor a tag.
    #[error("the bundle sets {0}, which is neither a branch nor a tag")]
    ForeignRef(String),
    /// The pack cannot be stored.
    #[error("the pack cannot be stored: {0}")]
    Pack(String),
    /// After the pack is stored, an object the snapshot needs is missing.
    #[error("{0} is missing after the pack is stored")]
    Incomplete(ObjectId),
}

/// An error of the engine, as text: its types change with every engine release.
pub(crate) fn repository(err: impl std::fmt::Display) -> Error {
    Error::Repository(err.to_string())
}

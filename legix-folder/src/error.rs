use std::path::PathBuf;

/// Errors of this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Reading or writing failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A document could not be encrypted, stored or read.
    #[error(transparent)]
    Crypt(#[from] legix_crypt::Error),
    /// A signature could not be made or read.
    #[error(transparent)]
    Sign(#[from] legix_sign::Error),
    /// Sync failed.
    #[error(transparent)]
    Sync(#[from] legix_sync::Error),
    /// The membership could not be read or changed.
    #[error(transparent)]
    Members(#[from] legix_members::Error),
    /// Syncing the mirror with the relay failed.
    #[error(transparent)]
    Relay(#[from] legix_p2p::Error),
    /// The repository could not be read or written.
    #[error("the history: {0}")]
    Repository(String),
    /// The folder's settings are not in the form this crate writes.
    #[error("not in the expected form: {0}")]
    Format(&'static str),
    /// A version is restored only into a folder that is new or holds no documents.
    #[error("{0} holds documents: a version is restored into a new folder, or one without documents")]
    NotEmpty(PathBuf),
    /// There is no version with this id.
    #[error("there is no such version")]
    NoSuchVersion,
    /// The folder holds changes that are not in a version.
    #[error("the folder has changes that are not in a version: save a version first")]
    Unsaved,
    /// Documents of a version this device cannot read: not synced yet, or erased.
    #[error("{} documents of that version cannot be read here: not synced yet, or erased", .0.len())]
    Unreadable(Vec<String>),
    /// The folder has no relay to sync through.
    #[error("no folder to sync through is set")]
    NoRelay,
    /// The shared folder to sync through is not there: not connected, or moved.
    #[error("the shared folder {0} is not there: connect it, then sync again")]
    RelayMissing(PathBuf),
}

/// An error of the engine, as text: its types change with every engine release.
pub(crate) fn repository(err: impl std::fmt::Display) -> Error {
    Error::Repository(err.to_string())
}

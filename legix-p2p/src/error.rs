/// Errors of this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Reading or writing failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The mirror, or a format of sync, failed.
    #[error(transparent)]
    Sync(#[from] legix_sync::Error),
    /// The membership log could not be read.
    #[error(transparent)]
    Members(#[from] legix_members::Error),
    /// Signing failed.
    #[error(transparent)]
    Sign(#[from] legix_sign::Error),
    /// A certificate or an inventory is not in the form this crate reads.
    #[error("not in the expected form: {0}")]
    Format(&'static str),
    /// The connection failed.
    #[error("the connection: {0}")]
    Connection(String),
    /// The peer is not a member of the group.
    #[error("the peer is not a member of the group")]
    NotMember,
    /// The peer's certificate names another endpoint than the one it connected from.
    #[error("the peer's certificate is for another endpoint")]
    WrongEndpoint,
    /// The peer syncs another group.
    #[error("the peer syncs another group")]
    WrongGroup,
    /// The peer did not follow the protocol.
    #[error("the peer broke the protocol: {0}")]
    Protocol(&'static str),
}

/// An error of the connection, as text: its types are iroh's.
#[cfg(feature = "iroh")]
pub(crate) fn connection_error(err: impl std::fmt::Display) -> Error {
    Error::Connection(err.to_string())
}

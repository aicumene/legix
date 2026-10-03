use legix_sync::DeviceId;

/// Errors of this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Reading or writing failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The relay, or a format shared with sync, failed.
    #[error(transparent)]
    Sync(#[from] legix_sync::Error),
    /// Signing failed.
    #[error(transparent)]
    Sign(#[from] legix_sign::Error),
    /// A join request, an entry, a recipient or the pin file is not in the form this crate reads.
    #[error("not in the expected form: {0}")]
    Format(&'static str),
    /// An entry of the log breaks a rule of the log.
    #[error("entry {seq} of the membership log is refused: {rule}")]
    Rule {
        /// The entry's place in the log.
        seq: u64,
        /// The rule it breaks.
        rule: Rule,
    },
    /// The log's first entry is not the group's.
    #[error("the membership log on the relay is not the group's")]
    WrongGroup,
    /// The relay has no membership log.
    #[error("the relay has no membership log")]
    NoLog,
    /// The relay's log is shorter than the one this device checked before.
    #[error("the relay's membership log ends at entry {found}; this device checked it to entry {pinned}")]
    Rollback {
        /// The last entry this device checked before.
        pinned: u64,
        /// The last entry on the relay.
        found: u64,
    },
    /// The relay's log holds another entry than the one this device checked before.
    #[error("entry {seq} of the membership log is not the one this device checked: the log forks")]
    Fork {
        /// The entry's place in the log.
        seq: u64,
    },
    /// A group key sealed for this device does not open with its identity.
    #[error("a group key sealed for this device does not open with its identity")]
    Unseal,
    /// The operating system could not provide random numbers.
    #[error("the operating system's random number generator failed: {0}")]
    Random(getrandom::Error),
}

/// A rule of the membership log that an entry breaks (see FORMAT.md).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Rule {
    /// The entry is not in the form of FORMAT.md.
    #[error("it is not in the expected form: {0}")]
    Format(&'static str),
    /// Its place, the entry before it, or the group does not continue the log.
    #[error("it does not continue the log")]
    Misplaced,
    /// It is dated before the entry before it.
    #[error("it is dated before the entry before it")]
    TimeGoesBack,
    /// Its epoch is neither the epoch before nor the next one; the first entry's is not 1.
    #[error("its epoch is neither the one before nor the next")]
    Epoch,
    /// The signature is not good.
    #[error("the signature is not good: {0:?}")]
    Signature(legix_sign::Status),
    /// The signer is not an admin.
    #[error("it is not signed by an admin")]
    NotAdmin,
    /// The first entry is not signed by an admin it adds.
    #[error("the first entry is not signed by an admin it adds")]
    Founder,
    /// A device appears in more than one change.
    #[error("{0} appears in more than one change")]
    Twice(DeviceId),
    /// A device is added that is or was a member.
    #[error("{0} is added, but is or was a member")]
    Member(DeviceId),
    /// A device that is not a member is changed or removed.
    #[error("{0} is changed or removed, but is not a member")]
    NotMember(DeviceId),
    /// A member is given the role it has.
    #[error("{0} is given the role it has")]
    SameRole(DeviceId),
    /// A cutoff is missing where it is needed, present where it is not, or later than the device's cutoff.
    #[error("the cutoff of {0} is missing, out of place, or later than the one it had")]
    Cutoff(DeviceId),
    /// No admin would be left.
    #[error("no admin would be left")]
    NoAdmin,
    /// A device is removed without moving to a new key.
    #[error("a device is removed without moving to a new key")]
    NoRotation,
    /// The group key is not sealed exactly for the devices it must be sealed for.
    #[error("the group key is not sealed for exactly the devices it must be")]
    Keys,
    /// The previous key is missing, or present where it must not be.
    #[error("the previous key is missing, or out of place")]
    Previous,
}

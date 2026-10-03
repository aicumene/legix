//! Membership for leGix: a signed log of who may read and write a repository, with the group's keys sealed for every
//! member, a new key when a member leaves, and no trust in the relay that keeps the log.
//!
//! - **The log.** Each entry adds devices, changes their roles or removes them, and is signed by an admin of the group as
//!   it stood. Entries are chained by hash, and the id of the first one is the group's id, which every device pins: a
//!   relay can neither forge, reorder nor roll back the log.
//! - **Roles.** Admins change the membership; writers publish bundles; readers read.
//! - **Keys.** The group key of each epoch is sealed for every member's X25519 recipient (as age seals for an X25519
//!   recipient). Removing a member starts a new epoch with a new key, sealed only for those who remain; the removed
//!   device keeps what it could read and reads nothing after. Each new key also encrypts the one before, so a member
//!   added later reads the whole history.
//! - **Revocation without clocks.** Removing a device, or making it a reader, names its last bundle that still counts.
//!   Later bundles are refused, whatever time they claim.
//! - **Joining.** A device signs a [`JoinRequest`] with its keys. The admin compares the device's fingerprint with the
//!   one the device shows, over a channel the relay does not control, and adds it.
//!
//! [`Members`] implements `legix_sync::Access`: give it to a `legix_sync::Replica` and sync follows the membership.
//! `FORMAT.md` specifies the join request, the entries, the rules and the sealing.
//!
//! ## Stability
//!
//! The formats are versioned and specified in `FORMAT.md`; a released version stays readable. The API follows semantic
//! versioning. The cryptography has not yet had an independent audit.
#![deny(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

mod entry;
mod error;
mod hex;
mod identity;
mod join;
mod members;
mod roster;
mod signed;

pub use entry::{Entry, EntryId, GroupId, MAX_LEN, NAMESPACE, Op, Role, VERSION};
pub use error::{Error, Rule};
pub use identity::{Identity, PREVIOUS_LEN, Recipient, SEALED_LEN};
pub use join::JoinRequest;
pub use members::{Change, Members, found};
pub use roster::{Member, Roster};

/// Fill `buf` from the operating system's random numbers.
pub(crate) fn random(buf: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(buf).map_err(Error::Random)
}

/// Seconds since 1970.
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

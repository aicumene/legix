//! Device-to-device sync for leGix over [iroh]: on the local network and through NAT, between members of a group only.
//!
//! Each device keeps a mirror of its group — the bundles, documents, envelopes and membership log it has seen — in a
//! relay of its own, and its `legix_sync::Replica` pushes to and pulls from that mirror. Two devices that reach each
//! other sync their mirrors directly:
//!
//! - **Members only.** iroh authenticates the endpoint at the other end of a connection. A device's [`EndpointCert`],
//!   signed with its key, ties the endpoint to the device, and the group's membership log ties the device to the group.
//!   A device that is not a member is turned away before it is given anything.
//! - **What the other lacks.** The devices exchange [inventories](Inventory) of their mirrors, then give each other the
//!   entries of the log, the bundles, the objects, the envelopes, the join requests and the certificates the other
//!   lacks.
//! - **Checked before it is kept.** Every item is checked as the group would: entries against the log, bundles against
//!   their chains, their signatures and the membership, objects against their ids, envelopes against the group's keys.
//!   A device can pass on the bundles of devices that are offline, and nothing it could alter.
//!
//! `Peer` (feature `iroh`, on by default) dials other devices and, as an iroh `ProtocolHandler` for `ALPN`, answers
//! them; `Peers` answers for several groups on one endpoint. A device that asked to join knocks with its request, which
//! the device it reaches keeps for the admins. The application builds the
//! iroh endpoint — its relays, its discovery on the local network — and finds the devices to dial with [`Peer::peers`].
//! [`replicate`] syncs two relays on one machine, such as a mirror and a synced folder, with the same checks.
//!
//! Outside the groups, devices give each other **letters** (feature `iroh`): [`send_letter`] hands a short note — a
//! card, an invitation — to another device on a connection of its own (`POST_ALPN`), with the sender's certificate,
//! and brings back the answer; [`Post`] answers them on an endpoint, giving each letter to the application's
//! [`Mailbox`].
//! `FORMAT.md` specifies the certificate and the protocol.
//!
//! [iroh]: https://www.iroh.computer
#![deny(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

mod cert;
mod error;
mod hex;
mod intake;
mod inventory;
mod outcome;
#[cfg(feature = "iroh")]
mod peer;
#[cfg(feature = "iroh")]
mod post;
mod replicate;
mod signed;
#[cfg(feature = "iroh")]
mod wire;

pub use cert::{EndpointCert, NAMESPACE, VERSION};
pub use error::Error;
pub use inventory::Inventory;
pub use outcome::{Counts, Refusal, Synced};
#[cfg(feature = "iroh")]
pub use peer::{ALPN, Peer, Peers};
#[cfg(feature = "iroh")]
pub use post::{MAX_LETTER, Mailbox, POST_ALPN, Post, send_letter};
pub use replicate::replicate;

/// Seconds since 1970.
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

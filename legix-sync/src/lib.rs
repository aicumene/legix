//! Sync git repositories through relays that cannot read them.
//!
//! Every device writes only its own branches and tags, and publishes them in bundles: signed by the device, encrypted
//! for the members, chained one after the other. A relay — a shared folder, object storage, a server — keeps the
//! bundles and passes them on. It can check every signature and every chain, and it can read nothing.
//!
//! - A bundle's [head](head) is in the clear: the device, the bundle's place in the device's chain, the hash of the
//!   previous bundle, the body's id, and the bundle key wrapped with the [`GroupKey`] the members share. It is signed in
//!   the SSH signature namespace `legix-bundle`, so it cannot pass for a commit signature.
//! - The body is a [legix-crypt](legix_crypt) object under the bundle key: the documents the new commits point to, the
//!   documents the device erased, and a standard git bundle with the device's refs and a pack of the new objects.
//! - Documents travel as legix-crypt objects, with their keys in envelopes for the members, kept apart from the bundles:
//!   bundles are kept forever, envelopes are deleted when a document is erased.
//!
//! [`Replica::push`] publishes this device's branches and tags; [`Replica::pull`] checks and applies the other devices'
//! bundles, and their branches and tags appear under `refs/legix/devices/<device id>/`. [`Replica::erase`] erases a
//! document here, on the relay, and — with the next bundle — on every member's device. `FORMAT.md` specifies the
//! formats and the checks.
//!
//! ## Stability
//!
//! The formats are versioned and specified in `FORMAT.md`; a released version stays readable. [`Replica`] works on
//! `legix::Repository` and follows the engine's version; the formats and the [`Relay`] interface do not depend on it.
//! The cryptography has not yet had an independent audit.
#![deny(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

mod body;
mod device;
mod envelope;
mod error;
mod fsutil;
pub mod head;
mod hex;
mod pack;
pub mod relay;
mod replica;
mod state;

pub use body::{GitBundle, Manifest};
pub use device::{DeviceId, GroupKey};
pub use envelope::{ENVELOPE_LEN, open_envelope, seal_envelope};
pub use error::{Error, Problem};
pub use head::{BundleId, Head, SignedHead};
pub use legix_sign::AllowedSigners;
pub use relay::{DirRelay, Relay};
pub use replica::{Applied, Pulled, Pushed, Refused, Replica, Wait, Waiting};

/// The SSH signature namespace of bundle heads.
pub const NAMESPACE: &str = "legix-bundle";

/// Fill `buf` from the operating system's random numbers.
pub(crate) fn random(buf: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(buf).map_err(Error::Random)
}

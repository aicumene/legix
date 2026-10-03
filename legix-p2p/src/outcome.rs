//! What a sync did.

use legix_sync::DeviceId;

/// What a sync brought and gave.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Synced {
    /// The device synced with; `None` for [`replicate`].
    pub peer: Option<DeviceId>,
    /// What was kept of what the other side gave.
    pub received: Counts,
    /// What was given.
    pub sent: Counts,
    /// What was refused, and why.
    pub refused: Vec<Refusal>,
}

/// How many items of each kind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Counts {
    /// Entries of the membership log.
    pub entries: usize,
    /// Endpoint certificates.
    pub endpoints: usize,
    /// Join requests.
    pub joins: usize,
    /// Bundle heads.
    pub heads: usize,
    /// Objects: bundle bodies and documents.
    pub objects: usize,
    /// Envelopes of document keys.
    pub envelopes: usize,
}

/// An item that was not kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The item.
    pub item: String,
    /// Why it was not kept.
    pub reason: String,
}

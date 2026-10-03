//! Syncing two relays on one machine.

use std::collections::BTreeMap;

use legix_members::{GroupId, Identity, JoinRequest};
use legix_sync::{DeviceId, Relay};

use crate::{Counts, EndpointCert, Error, Inventory, Synced, intake::Intake, inventory::Item};

/// Bring into `to` what `from` has and `to` lacks — a mirror and a synced folder, two mirrors on one machine — checking
/// each item as one from a peer: the membership log of `group`, whose keys `identity` opens, decides what `to` keeps.
pub fn replicate(
    from: &(impl Relay + ?Sized),
    to: &(impl Relay + ?Sized),
    group: &GroupId,
    identity: &Identity,
) -> Result<Synced, Error> {
    let theirs = Inventory::of(from)?;
    let mine = Inventory::of(to)?;
    let mut intake = Intake::new(to, *group, identity)?;
    let endpoints = by_device(from.endpoints()?, |bytes| {
        EndpointCert::parse(bytes).ok().map(|certificate| certificate.device())
    });
    let joins = by_device(from.joins()?, |bytes| {
        JoinRequest::parse(bytes).ok().map(|request| request.device())
    });
    for item in theirs.plan(&mine) {
        match item {
            Item::Entry(seq) => {
                if let Some(entry) = from.member_entry(seq)? {
                    intake.entry(seq, &entry)?;
                }
            }
            Item::Endpoint(device) => {
                if let Some(certificate) = endpoints.get(&device) {
                    intake.endpoint(device, certificate)?;
                }
            }
            Item::Join(device) => {
                if let Some(request) = joins.get(&device) {
                    intake.join(device, request)?;
                }
            }
            Item::Head(device, seq) => {
                if let Some(head) = from.head(&device, seq)? {
                    intake.head(device, seq, &head)?;
                }
            }
            Item::Object(oid) => {
                if let Some(mut object) = from.open_object(&oid)? {
                    intake.object(oid, &mut object)?;
                }
            }
            Item::Envelope(oid) => {
                if let Some(envelope) = from.envelope(&oid)? {
                    intake.envelope(oid, &envelope)?;
                }
            }
        }
    }
    Ok(Synced {
        peer: None,
        received: intake.received,
        sent: Counts::default(),
        refused: intake.refused,
        knocked: false,
    })
}

pub(crate) fn by_device(
    items: Vec<Vec<u8>>,
    device: impl Fn(&[u8]) -> Option<DeviceId>,
) -> BTreeMap<DeviceId, Vec<u8>> {
    items
        .into_iter()
        .filter_map(|bytes| device(&bytes).map(|device| (device, bytes)))
        .collect()
}

//! Taking what a peer gives: every item is checked before the relay keeps it, so a peer can add only what the group
//! itself would accept.

use std::{collections::BTreeMap, io::Read};

use legix_crypt::Oid;
use legix_members::{Entry, GroupId, Identity, JoinRequest, Members, Roster};
use legix_sync::{BundleId, DeviceId, Relay, SignedHead};

use crate::{Counts, EndpointCert, Error, Refusal};

/// The relay that takes items, and what it knows to check them: the membership log it holds, and the ends of the
/// devices' chains.
pub(crate) struct Intake<'a, R: ?Sized> {
    relay: &'a R,
    group: GroupId,
    identity: &'a Identity,
    members: Members,
    chains: BTreeMap<DeviceId, (u64, BundleId, u64)>,
    pub(crate) received: Counts,
    pub(crate) refused: Vec<Refusal>,
}

impl<'a, R: Relay + ?Sized> Intake<'a, R> {
    /// Taking items into `relay`, for the group `group`, whose keys `identity` opens.
    pub(crate) fn new(relay: &'a R, group: GroupId, identity: &'a Identity) -> Result<Self, Error> {
        let members = match Members::read(relay, &group, identity) {
            Ok(members) => members,
            // A relay without a log yet takes the log from its first entry.
            Err(legix_members::Error::NoLog) => Members::with_identity(Roster::new(), identity)?,
            Err(err) => return Err(err.into()),
        };
        Ok(Intake {
            relay,
            group,
            identity,
            members,
            chains: BTreeMap::new(),
            received: Counts::default(),
            refused: Vec::new(),
        })
    }

    /// The membership as the relay's log, with what was taken, defines it.
    #[cfg(feature = "iroh")]
    pub(crate) fn members(&self) -> &Members {
        &self.members
    }

    /// Note that `item` was not kept, and why; then go on with the next item.
    fn refuse(&mut self, item: String, reason: impl ToString) -> Result<(), Error> {
        self.refused.push(Refusal {
            item,
            reason: reason.to_string(),
        });
        Ok(())
    }

    /// Entry `seq` of the membership log.
    pub(crate) fn entry(&mut self, seq: u64, bytes: &[u8]) -> Result<(), Error> {
        let item = format!("entry {seq} of the membership log");
        if seq != self.members.roster().seq() + 1 {
            return self.refuse(item, "it is not the next entry");
        }
        let entry = match Entry::parse(bytes) {
            Ok(entry) => entry,
            Err(err) => {
                return self.refuse(item, err);
            }
        };
        if seq == 1 && GroupId::from(entry.id()) != self.group {
            return self.refuse(item, "it is not the first entry of this group");
        }
        let mut members = self.members.clone();
        if let Err(err) = members.apply(&entry, self.identity) {
            return self.refuse(item, err);
        }
        match self.relay.put_member_entry(seq, bytes) {
            Ok(()) => {}
            // Written meanwhile by this device itself: kept only if it is the same entry.
            Err(legix_sync::Error::EntryExists { .. }) => {
                if self.relay.member_entry(seq)?.as_deref() != Some(bytes) {
                    return self.refuse(item, "the relay holds another entry at this place");
                }
            }
            Err(err) => return Err(err.into()),
        }
        self.members = members;
        self.received.entries += 1;
        Ok(())
    }

    /// The endpoint certificate of `device`.
    pub(crate) fn endpoint(&mut self, device: DeviceId, bytes: &[u8]) -> Result<(), Error> {
        let item = format!("the endpoint certificate of {device}");
        let certificate = match EndpointCert::parse(bytes) {
            Ok(certificate) if certificate.device() == device => certificate,
            Ok(_) => return self.refuse(item, "it is another device's"),
            Err(err) => return self.refuse(item, err),
        };
        if !certificate.is_member(&self.members) {
            return self.refuse(item, "the device is not a member");
        }
        let newer = self.relay.endpoints()?.iter().all(|kept| {
            EndpointCert::parse(kept).is_ok_and(|kept| kept.device() != device || kept.time() < certificate.time())
        });
        if newer {
            self.relay.put_endpoint(&device, bytes)?;
            self.received.endpoints += 1;
        }
        Ok(())
    }

    /// The join request of `device`.
    pub(crate) fn join(&mut self, device: DeviceId, bytes: &[u8]) -> Result<(), Error> {
        match JoinRequest::parse(bytes) {
            Ok(request) if request.device() == device => {
                self.relay.put_join(&device, bytes)?;
                self.received.joins += 1;
                Ok(())
            }
            Ok(_) => self.refuse(format!("the join request of {device}"), "it is another device's"),
            Err(err) => self.refuse(format!("the join request of {device}"), err),
        }
    }

    /// Head `seq` of `device`: kept only where it continues the device's chain, signed by the device, which the group
    /// allows to publish it.
    pub(crate) fn head(&mut self, device: DeviceId, seq: u64, bytes: &[u8]) -> Result<(), Error> {
        let item = format!("bundle {seq} of {device}");
        let (last, last_id, last_time) = self.chain(device)?;
        if seq != last + 1 {
            return self.refuse(item, "it is not the next bundle of the device");
        }
        let signed = match SignedHead::parse(bytes) {
            Ok(signed) => signed,
            Err(err) => return self.refuse(item, err),
        };
        let head = signed.head();
        if head.device != device || head.seq != seq {
            return self.refuse(item, "it names another device or place");
        }
        if head.prev != last_id {
            return self.refuse(item, "it does not follow the device's previous bundle: the chain forks");
        }
        if head.time < last_time {
            return self.refuse(item, "it is dated before the device's previous bundle");
        }
        if let Err(problem) = signed.verify(&self.members) {
            return self.refuse(item, problem);
        }
        match self.relay.put_head(&device, seq, bytes) {
            Ok(()) => {}
            Err(legix_sync::Error::HeadExists { .. }) if self.relay.head(&device, seq)?.as_deref() == Some(bytes) => {}
            Err(legix_sync::Error::HeadExists { .. }) => {
                return self.refuse(item, "the relay holds another bundle at this place");
            }
            Err(err) => return Err(err.into()),
        }
        self.chains.insert(device, (seq, signed.id(), head.time));
        self.received.heads += 1;
        Ok(())
    }

    /// The object `oid`, kept once it hashes to its id.
    pub(crate) fn object(&mut self, oid: Oid, object: &mut dyn Read) -> Result<(), Error> {
        if self.relay.has_object(&oid)? {
            return Ok(());
        }
        match self.relay.put_object(&oid, object) {
            Ok(()) => self.received.objects += 1,
            Err(legix_sync::Error::Crypt(err @ legix_crypt::Error::Corrupt { .. })) => {
                self.refuse(format!("the object {oid}"), err)?;
            }
            Err(err) => return Err(err.into()),
        }
        Ok(())
    }

    /// The envelope of document `oid`, kept only if it opens with the group's key of its epoch.
    pub(crate) fn envelope(&mut self, oid: Oid, bytes: &[u8]) -> Result<(), Error> {
        if let Err(err) = legix_sync::open_envelope(&self.members, &oid, bytes) {
            return self.refuse(format!("the envelope of {oid}"), err);
        }
        match self.relay.put_envelope(&oid, bytes) {
            Ok(()) => self.received.envelopes += 1,
            // The document was erased here: its envelope stays out.
            Err(legix_sync::Error::Erased(_)) => {}
            Err(err) => return Err(err.into()),
        }
        Ok(())
    }

    /// The last bundle of `device` the relay holds: its place, its id and its time.
    fn chain(&mut self, device: DeviceId) -> Result<(u64, BundleId, u64), Error> {
        if let Some(chain) = self.chains.get(&device) {
            return Ok(*chain);
        }
        let mut chain = (0, BundleId::NONE, 0);
        while let Some(bytes) = self.relay.head(&device, chain.0 + 1)? {
            let signed = SignedHead::parse(&bytes)?;
            chain = (chain.0 + 1, signed.id(), signed.head().time);
        }
        self.chains.insert(device, chain);
        Ok(chain)
    }
}

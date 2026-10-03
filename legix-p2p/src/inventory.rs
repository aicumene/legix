//! Inventories: what a relay holds, and what one relay has to give another.

use std::collections::{BTreeMap, BTreeSet};

use legix_crypt::Oid;
use legix_members::{Entry, EntryId, JoinRequest};
use legix_sync::{DeviceId, Relay};

use crate::{EndpointCert, Error};

/// The largest number of items an inventory may list of one kind.
const MAX_ITEMS: u32 = 1 << 22;

/// What a relay holds: the end of the membership log and of each device's chain, the objects, the envelopes, the join
/// requests and the endpoint certificates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Inventory {
    /// The last entry of the membership log: its place and its id.
    pub log: Option<(u64, EntryId)>,
    /// The last bundle of each device.
    pub heads: BTreeMap<DeviceId, u64>,
    /// The objects: bodies and documents.
    pub objects: BTreeSet<Oid>,
    /// The documents whose envelopes it holds.
    pub envelopes: BTreeSet<Oid>,
    /// The devices whose join requests it holds.
    pub joins: BTreeSet<DeviceId>,
    /// The devices whose endpoint certificates it holds, and when each certificate was made.
    pub endpoints: BTreeMap<DeviceId, u64>,
}

/// One item a relay gives another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Item {
    Entry(u64),
    Endpoint(DeviceId),
    Join(DeviceId),
    Head(DeviceId, u64),
    Object(Oid),
    Envelope(Oid),
}

impl Inventory {
    /// What `relay` holds.
    pub fn of(relay: &(impl Relay + ?Sized)) -> Result<Self, Error> {
        let mut inventory = Inventory::default();
        let mut last = None;
        for seq in 1.. {
            let Some(bytes) = relay.member_entry(seq)? else {
                break;
            };
            last = Some((seq, bytes));
        }
        if let Some((seq, bytes)) = last {
            inventory.log = Some((seq, Entry::parse(&bytes)?.id()));
        }
        for device in relay.devices()? {
            let mut seq = 0;
            while relay.head(&device, seq + 1)?.is_some() {
                seq += 1;
            }
            if seq > 0 {
                inventory.heads.insert(device, seq);
            }
        }
        inventory.objects = relay.object_ids()?.into_iter().collect();
        inventory.envelopes = relay.envelope_ids()?.into_iter().collect();
        for request in relay.joins()? {
            if let Ok(request) = JoinRequest::parse(&request) {
                inventory.joins.insert(request.device());
            }
        }
        for certificate in relay.endpoints()? {
            if let Ok(certificate) = EndpointCert::parse(&certificate) {
                inventory.endpoints.insert(certificate.device(), certificate.time());
            }
        }
        Ok(inventory)
    }

    /// What a relay with this inventory has to give one with the inventory `theirs`, in the order a receiver checks
    /// it: the log first, since it decides what else is kept.
    pub(crate) fn plan(&self, theirs: &Inventory) -> Vec<Item> {
        let mut items = Vec::new();
        let their_log = theirs.log.map_or(0, |(seq, _)| seq);
        if let Some((seq, _)) = self.log {
            items.extend((their_log + 1..=seq).map(Item::Entry));
        }
        for (device, time) in &self.endpoints {
            if theirs.endpoints.get(device).is_none_or(|their_time| their_time < time) {
                items.push(Item::Endpoint(*device));
            }
        }
        items.extend(self.joins.difference(&theirs.joins).copied().map(Item::Join));
        for (device, last) in &self.heads {
            let from = theirs.heads.get(device).copied().unwrap_or(0) + 1;
            items.extend((from..=*last).map(|seq| Item::Head(*device, seq)));
        }
        items.extend(self.objects.difference(&theirs.objects).copied().map(Item::Object));
        items.extend(
            self.envelopes
                .difference(&theirs.envelopes)
                .copied()
                .map(Item::Envelope),
        );
        items
    }

    /// The inventory as it travels.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let (seq, id) = self.log.map_or((0, [0; 32]), |(seq, id)| (seq, *id.as_bytes()));
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&id);
        let count =
            |out: &mut Vec<u8>, n: usize| out.extend_from_slice(&u32::try_from(n).unwrap_or(u32::MAX).to_be_bytes());
        count(&mut out, self.heads.len());
        for (device, seq) in &self.heads {
            out.extend_from_slice(device.as_bytes());
            out.extend_from_slice(&seq.to_be_bytes());
        }
        for set in [&self.objects, &self.envelopes] {
            count(&mut out, set.len());
            for oid in set {
                out.extend_from_slice(oid.as_bytes());
            }
        }
        count(&mut out, self.joins.len());
        for device in &self.joins {
            out.extend_from_slice(device.as_bytes());
        }
        count(&mut out, self.endpoints.len());
        for (device, time) in &self.endpoints {
            out.extend_from_slice(device.as_bytes());
            out.extend_from_slice(&time.to_be_bytes());
        }
        out
    }

    /// Read an inventory as it travels.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader(bytes);
        let mut inventory = Inventory::default();
        let seq = reader.u64()?;
        let id = reader.array()?;
        if seq > 0 {
            inventory.log = Some((seq, EntryId::from_bytes(id)));
        }
        for _ in 0..reader.count()? {
            inventory
                .heads
                .insert(DeviceId::from_bytes(reader.array()?), reader.u64()?);
        }
        for _ in 0..reader.count()? {
            inventory.objects.insert(Oid::from_bytes(reader.array()?));
        }
        for _ in 0..reader.count()? {
            inventory.envelopes.insert(Oid::from_bytes(reader.array()?));
        }
        for _ in 0..reader.count()? {
            inventory.joins.insert(DeviceId::from_bytes(reader.array()?));
        }
        for _ in 0..reader.count()? {
            inventory
                .endpoints
                .insert(DeviceId::from_bytes(reader.array()?), reader.u64()?);
        }
        if !reader.0.is_empty() {
            return Err(Error::Format("an inventory has bytes after its end"));
        }
        Ok(inventory)
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let (head, rest) = self
            .0
            .split_at_checked(N)
            .ok_or(Error::Format("an inventory is cut short"))?;
        self.0 = rest;
        Ok(head.try_into().expect("N bytes"))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn count(&mut self) -> Result<u32, Error> {
        let count = u32::from_be_bytes(self.take()?);
        if count > MAX_ITEMS {
            return Err(Error::Format("an inventory lists too many items"));
        }
        Ok(count)
    }

    fn array(&mut self) -> Result<[u8; 32], Error> {
        self.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_inventory_reads_back_and_plans_what_the_other_lacks() {
        let mut mine = Inventory {
            log: Some((3, EntryId::from_bytes([3; 32]))),
            ..Default::default()
        };
        let (ada, bo) = (DeviceId::from_bytes([1; 32]), DeviceId::from_bytes([2; 32]));
        mine.heads.insert(ada, 4);
        mine.heads.insert(bo, 1);
        mine.objects.extend([Oid::of(b"a"), Oid::of(b"b")]);
        mine.envelopes.insert(Oid::of(b"a"));
        mine.joins.insert(bo);
        mine.endpoints.insert(ada, 100);
        mine.endpoints.insert(bo, 50);
        assert_eq!(Inventory::decode(&mine.encode()).unwrap(), mine);

        let mut theirs = Inventory {
            log: Some((1, EntryId::from_bytes([1; 32]))),
            ..Default::default()
        };
        theirs.heads.insert(ada, 2);
        theirs.objects.insert(Oid::of(b"a"));
        theirs.endpoints.insert(ada, 200);
        theirs.endpoints.insert(bo, 10);
        let plan = mine.plan(&theirs);
        assert_eq!(
            plan,
            vec![
                Item::Entry(2),
                Item::Entry(3),
                Item::Endpoint(bo),
                Item::Join(bo),
                Item::Head(ada, 3),
                Item::Head(ada, 4),
                Item::Head(bo, 1),
                Item::Object(Oid::of(b"b")),
                Item::Envelope(Oid::of(b"a")),
            ]
        );
        assert!(Inventory::decode(&mine.encode()[..20]).is_err());
        assert!(theirs.plan(&theirs).is_empty());
    }
}

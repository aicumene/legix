//! The membership a log defines, entry by entry.

use std::collections::{BTreeMap, BTreeSet};

use legix_sign::ssh_key::PublicKey;
use legix_sync::DeviceId;

use crate::{
    Entry, EntryId, Error, GroupId, Op, Recipient, Role, Rule,
    identity::{PREVIOUS_LEN, SEALED_LEN},
};

/// A device of the group, now or before.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// The device.
    pub device: DeviceId,
    /// What it may do.
    pub role: Role,
    /// The name it joined under.
    pub principal: String,
    /// Its signing key.
    pub key: PublicKey,
    /// The recipient its group keys are sealed for.
    pub recipient: Recipient,
    /// The entry that added it.
    pub added: u64,
    /// The epoch it was added in.
    pub first_epoch: u64,
    /// The last epoch it was a member in, once removed.
    pub last_epoch: Option<u64>,
    /// Its last bundle that may be applied, for a reader or a removed device; `None` when every one may.
    pub cutoff: Option<u64>,
}

/// A sealed group key, or a previous key, with the context it was sealed in.
#[derive(Clone, Debug)]
pub(crate) struct Sealed<const N: usize> {
    pub epoch: u64,
    pub group: [u8; 32],
    pub bytes: [u8; N],
}

/// The membership of a group as its log defines it, checked entry by entry.
#[derive(Clone, Debug, Default)]
pub struct Roster {
    group: Option<GroupId>,
    seq: u64,
    last: EntryId,
    time: u64,
    epoch: u64,
    members: BTreeMap<DeviceId, Member>,
    former: BTreeMap<DeviceId, Member>,
    /// The latest group key sealed for each device, current or former.
    pub(crate) sealed: BTreeMap<DeviceId, Sealed<SEALED_LEN>>,
    /// For each epoch from 2, the key of the epoch before, under its own key.
    pub(crate) previous: BTreeMap<u64, Sealed<PREVIOUS_LEN>>,
}

impl Roster {
    /// The membership before the first entry: nobody.
    pub fn new() -> Self {
        Roster::default()
    }

    /// Apply the next entry of the log, after checking that it follows the log and keeps its rules (see FORMAT.md).
    pub fn apply(&mut self, entry: &Entry) -> Result<(), Error> {
        let refuse = |rule| Error::Rule { seq: entry.seq, rule };
        let first = self.seq == 0;

        if entry.seq != self.seq + 1
            || entry.prev != if first { EntryId::default() } else { self.last }
            || entry.group != self.group.map_or([0; 32], |group| *group.as_bytes())
        {
            return Err(refuse(Rule::Misplaced));
        }
        if entry.time < self.time {
            return Err(refuse(Rule::TimeGoesBack));
        }
        let rotation = first || entry.epoch == self.epoch + 1;
        if (first && entry.epoch != 1) || (!first && entry.epoch != self.epoch && !rotation) {
            return Err(refuse(Rule::Epoch));
        }

        let signer = entry.signing_key().map_err(refuse)?;
        let signer_device = DeviceId::of(&signer);
        if first {
            let founder = entry.ops.iter().any(|op| {
                matches!(op, Op::Add { role: Role::Admin, request } if request.key().key_data() == signer.key_data())
            });
            if !founder {
                return Err(refuse(Rule::Founder));
            }
        } else {
            let admin = self.members.get(&signer_device);
            if !admin.is_some_and(|admin| admin.role == Role::Admin && admin.key.key_data() == signer.key_data()) {
                return Err(refuse(Rule::NotAdmin));
            }
        }

        let mut members = self.members.clone();
        let mut former = self.former.clone();
        let mut seen = BTreeSet::new();
        let mut added = BTreeSet::new();
        let mut removes = false;
        for op in &entry.ops {
            let device = op.device();
            if !seen.insert(device) {
                return Err(refuse(Rule::Twice(device)));
            }
            match op {
                Op::Add { role, request } => {
                    if members.contains_key(&device) || former.contains_key(&device) {
                        return Err(refuse(Rule::Member(device)));
                    }
                    added.insert(device);
                    members.insert(
                        device,
                        Member {
                            device,
                            role: *role,
                            principal: request.principal().to_owned(),
                            key: request.key().clone(),
                            recipient: request.recipient(),
                            added: entry.seq,
                            first_epoch: entry.epoch,
                            last_epoch: None,
                            cutoff: (*role == Role::Reader).then_some(0),
                        },
                    );
                }
                Op::Role { role, cutoff, .. } => {
                    let member = members.get_mut(&device).ok_or(refuse(Rule::NotMember(device)))?;
                    if member.role == *role {
                        return Err(refuse(Rule::SameRole(device)));
                    }
                    // A new reader keeps its bundles up to its cutoff; a new writer or admin publishes again. (Only
                    // readers have a cutoff, and a reader cannot be made a reader again.)
                    let fits = matches!(
                        (role, cutoff),
                        (Role::Reader, Some(_)) | (Role::Admin | Role::Writer, None)
                    );
                    if !fits {
                        return Err(refuse(Rule::Cutoff(device)));
                    }
                    member.role = *role;
                    member.cutoff = *cutoff;
                }
                Op::Remove { cutoff, .. } => {
                    let mut member = members.remove(&device).ok_or(refuse(Rule::NotMember(device)))?;
                    if member.cutoff.is_some_and(|had| *cutoff > had) {
                        return Err(refuse(Rule::Cutoff(device)));
                    }
                    member.cutoff = Some(*cutoff);
                    member.last_epoch = Some(self.epoch);
                    former.insert(device, member);
                    removes = true;
                }
            }
        }
        if !members.values().any(|member| member.role == Role::Admin) {
            return Err(refuse(Rule::NoAdmin));
        }
        if removes && !rotation {
            return Err(refuse(Rule::NoRotation));
        }

        let expected: BTreeSet<DeviceId> = if rotation {
            members.keys().copied().collect()
        } else {
            added
        };
        let sealed_for: BTreeSet<DeviceId> = entry.sealed_for().collect();
        if sealed_for != expected || entry.keys.len() != expected.len() {
            return Err(refuse(Rule::Keys));
        }
        if entry.previous.is_some() != (rotation && !first) {
            return Err(refuse(Rule::Previous));
        }

        let group = self.group.unwrap_or_else(|| entry.id().into());
        for (device, bytes) in &entry.keys {
            self.sealed.insert(
                *device,
                Sealed {
                    epoch: entry.epoch,
                    group: entry.group,
                    bytes: *bytes,
                },
            );
        }
        if let Some(bytes) = entry.previous {
            self.previous.insert(
                entry.epoch,
                Sealed {
                    epoch: entry.epoch,
                    group: entry.group,
                    bytes,
                },
            );
        }
        self.group = Some(group);
        self.seq = entry.seq;
        self.last = entry.id();
        self.time = entry.time;
        self.epoch = entry.epoch;
        self.members = members;
        self.former = former;
        Ok(())
    }

    /// The group's id, once the first entry is applied.
    pub fn group(&self) -> Option<GroupId> {
        self.group
    }

    /// The place of the last entry applied.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The id of the last entry applied.
    pub fn last(&self) -> EntryId {
        self.last
    }

    /// When the last entry was written.
    pub fn time(&self) -> u64 {
        self.time
    }

    /// The current epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The members.
    pub fn members(&self) -> &BTreeMap<DeviceId, Member> {
        &self.members
    }

    /// The devices removed from the group.
    pub fn former(&self) -> &BTreeMap<DeviceId, Member> {
        &self.former
    }

    /// The device, member now or before.
    pub fn device(&self, device: &DeviceId) -> Option<&Member> {
        self.members.get(device).or_else(|| self.former.get(device))
    }
}

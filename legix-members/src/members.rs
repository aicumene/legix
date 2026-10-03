//! A device's view of its group: the checked log, and the group keys its identity opens.

use std::{collections::BTreeMap, path::Path};

use legix_sign::ssh_key::{PublicKey, SigningKey};
use legix_sync::{Access, DeviceId, GroupKey, Problem, Relay};

use crate::{Entry, EntryId, Error, GroupId, Identity, JoinRequest, Member, Op, Recipient, Role, Roster, identity};

/// A device's view of its group: the membership log, checked from its first entry, and the group keys this device's
/// identity opens. It gives a `legix_sync::Replica` who may publish and the keys of every epoch.
#[derive(Clone, Debug)]
pub struct Members {
    roster: Roster,
    me: Option<DeviceId>,
    keys: BTreeMap<u64, GroupKey>,
}

impl Members {
    /// Read the log of the group `group` from `relay`, check it from its first entry, and open the group keys
    /// `identity` holds.
    ///
    /// `pin` is a file where the device keeps the last entry it checked: a log that does not reach it, or holds another
    /// entry there, is refused, so the relay can neither roll the log back nor show this device another one.
    pub fn load(relay: &impl Relay, group: &GroupId, identity: &Identity, pin: &Path) -> Result<Self, Error> {
        let pinned = Pin::read(pin, group)?;
        let mut roster = Roster::new();
        for seq in 1.. {
            let Some(bytes) = relay.member_entry(seq)? else {
                break;
            };
            let entry = Entry::parse(&bytes).map_err(|err| match err {
                Error::Format(reason) => Error::Rule {
                    seq,
                    rule: crate::Rule::Format(reason),
                },
                err => err,
            })?;
            if seq == 1 && GroupId::from(entry.id()) != *group {
                return Err(Error::WrongGroup);
            }
            if pinned.is_some_and(|(pinned_seq, pinned_id)| pinned_seq == seq && pinned_id != entry.id()) {
                return Err(Error::Fork { seq });
            }
            roster.apply(&entry)?;
        }
        if roster.seq() == 0 {
            return Err(Error::NoLog);
        }
        if let Some((pinned_seq, _)) = pinned
            && pinned_seq > roster.seq()
        {
            return Err(Error::Rollback {
                pinned: pinned_seq,
                found: roster.seq(),
            });
        }
        Pin::write(pin, group, roster.seq(), &roster.last())?;
        Self::with_identity(roster, identity)
    }

    /// The membership `roster` defines, and the group keys `identity` opens in it.
    pub fn with_identity(roster: Roster, identity: &Identity) -> Result<Self, Error> {
        let recipient = identity.recipient();
        let me = find(&roster, &recipient);
        let mut keys = BTreeMap::new();
        if let Some(sealed) = me.and_then(|device| roster.sealed.get(&device)) {
            let mut key = identity::unseal(&sealed.bytes, identity, &sealed.group, sealed.epoch)?;
            let mut epoch = sealed.epoch;
            keys.insert(epoch, key.clone());
            while let Some(previous) = roster.previous.get(&epoch) {
                key = identity::open_previous(&previous.bytes, &key, &previous.group, epoch)?;
                epoch -= 1;
                keys.insert(epoch, key.clone());
            }
        }
        Ok(Members { roster, me, keys })
    }

    /// Apply an entry this device wrote or read since, as [`Roster::apply`] does, and open the keys it brings.
    pub fn apply(&mut self, entry: &Entry, identity: &Identity) -> Result<(), Error> {
        let mut roster = self.roster.clone();
        roster.apply(entry)?;
        *self = Self::with_identity(roster, identity)?;
        Ok(())
    }

    /// The membership.
    pub fn roster(&self) -> &Roster {
        &self.roster
    }

    /// This device, if it is or was a member.
    pub fn me(&self) -> Option<&Member> {
        self.me.and_then(|device| self.roster.device(&device))
    }

    /// The epochs whose keys this device holds.
    pub fn epochs(&self) -> impl Iterator<Item = u64> + '_ {
        self.keys.keys().copied()
    }

    /// A change to the membership, for an admin to sign.
    pub fn change(&self) -> Change<'_> {
        Change {
            members: self,
            adds: Vec::new(),
            roles: Vec::new(),
            removes: Vec::new(),
            rotate: false,
        }
    }
}

impl Access for Members {
    fn current(&self) -> Result<(u64, GroupKey), legix_sync::Error> {
        let me = self
            .me
            .and_then(|device| self.roster.members().get(&device))
            .ok_or(legix_sync::Error::NotAllowed(Problem::NotMember))?;
        if !me.role.publishes() {
            return Err(legix_sync::Error::NotAllowed(Problem::PastCutoff {
                cutoff: me.cutoff.unwrap_or(0),
            }));
        }
        let epoch = self.roster.epoch();
        let key = self.keys.get(&epoch).ok_or(legix_sync::Error::NoKey(epoch))?;
        Ok((epoch, key.clone()))
    }

    fn key(&self, epoch: u64) -> Option<GroupKey> {
        self.keys.get(&epoch).cloned()
    }

    fn may_publish(
        &self,
        device: &DeviceId,
        key: &PublicKey,
        seq: u64,
        epoch: u64,
        _time: u64,
    ) -> Result<String, Problem> {
        let member = self.roster.device(device).ok_or(Problem::NotMember)?;
        if member.key.key_data() != key.key_data() {
            return Err(Problem::WrongDevice);
        }
        let last_epoch = member.last_epoch.unwrap_or(self.roster.epoch());
        if epoch < member.first_epoch || epoch > last_epoch {
            return Err(Problem::WrongEpoch(epoch));
        }
        if let Some(cutoff) = member.cutoff
            && seq > cutoff
        {
            return Err(Problem::PastCutoff { cutoff });
        }
        Ok(member.principal.clone())
    }
}

/// A change to the membership: the next entry of the log, which an admin signs.
#[derive(Debug)]
pub struct Change<'a> {
    members: &'a Members,
    adds: Vec<(JoinRequest, Role)>,
    roles: Vec<(DeviceId, Role, Option<u64>)>,
    removes: Vec<(DeviceId, u64)>,
    rotate: bool,
}

impl Change<'_> {
    /// Add the device of `request` with `role`. Compare its fingerprint with the device first.
    #[must_use]
    pub fn add(mut self, request: JoinRequest, role: Role) -> Self {
        self.adds.push((request, role));
        self
    }

    /// Give a member another role. A member made a reader keeps its bundles up to `cutoff`, which is `None` for any
    /// other role.
    #[must_use]
    pub fn set_role(mut self, device: DeviceId, role: Role, cutoff: Option<u64>) -> Self {
        self.roles.push((device, role, cutoff));
        self
    }

    /// Remove a member, keeping its bundles up to `cutoff`. The group moves to a new key, which the device does not get.
    #[must_use]
    pub fn remove(mut self, device: DeviceId, cutoff: u64) -> Self {
        self.removes.push((device, cutoff));
        self.rotate = true;
        self
    }

    /// Move the group to a new key.
    #[must_use]
    pub fn rotate(mut self) -> Self {
        self.rotate = true;
        self
    }

    /// Write the entry, signed with `signer` — an admin's device key — and check it against the log as it stands.
    pub fn sign(self, signer: &impl SigningKey) -> Result<Entry, Error> {
        let roster = self.members.roster();
        let group = *roster.group().ok_or(Error::NoLog)?.as_bytes();
        let epoch = roster.epoch() + u64::from(self.rotate);

        let mut ops = Vec::new();
        let mut recipients: BTreeMap<DeviceId, Recipient> = if self.rotate {
            roster
                .members()
                .values()
                .map(|member| (member.device, member.recipient))
                .collect()
        } else {
            BTreeMap::new()
        };
        for (request, role) in self.adds {
            recipients.insert(request.device(), request.recipient());
            ops.push(Op::Add { role, request });
        }
        for (device, role, cutoff) in self.roles {
            ops.push(Op::Role { device, role, cutoff });
        }
        for (device, cutoff) in self.removes {
            recipients.remove(&device);
            ops.push(Op::Remove { device, cutoff });
        }

        let current = self
            .members
            .keys
            .get(&roster.epoch())
            .ok_or(Error::Sync(legix_sync::Error::NoKey(roster.epoch())))?;
        let key = if self.rotate {
            GroupKey::generate()?
        } else {
            current.clone()
        };
        let mut keys = Vec::new();
        for (device, recipient) in &recipients {
            keys.push((*device, identity::seal(&key, recipient, &group, epoch)?));
        }
        let previous = if self.rotate {
            Some(identity::seal_previous(current, &key, &group, epoch)?)
        } else {
            None
        };
        let text = Entry::text(
            &group,
            roster.seq() + 1,
            &roster.last(),
            crate::now().max(roster.time()),
            epoch,
            &ops,
            &keys,
            previous.as_ref(),
        );
        let entry = Entry::sign(&text, signer)?;
        roster.clone().apply(&entry)?;
        Ok(entry)
    }
}

/// Found a group: its first entry, which adds the device that signs with `signer` and receives with `identity` as an
/// admin named `principal`, and the devices of `requests` with their roles, under the group's first key.
pub fn found(
    signer: &impl SigningKey,
    identity: &Identity,
    principal: &str,
    requests: &[(JoinRequest, Role)],
) -> Result<Entry, Error> {
    let founder = JoinRequest::new(signer, identity, principal)?;
    let mut ops = vec![Op::Add {
        role: Role::Admin,
        request: founder,
    }];
    ops.extend(requests.iter().map(|(request, role)| Op::Add {
        role: *role,
        request: request.clone(),
    }));
    let key = GroupKey::generate()?;
    let group = [0; 32];
    let mut keys = Vec::new();
    for op in &ops {
        if let Op::Add { request, .. } = op {
            keys.push((request.device(), identity::seal(&key, &request.recipient(), &group, 1)?));
        }
    }
    let text = Entry::text(&group, 1, &EntryId::default(), crate::now(), 1, &ops, &keys, None);
    let entry = Entry::sign(&text, signer)?;
    Roster::new().apply(&entry)?;
    Ok(entry)
}

/// The device whose recipient is `recipient`.
fn find(roster: &Roster, recipient: &Recipient) -> Option<DeviceId> {
    roster
        .members()
        .values()
        .chain(roster.former().values())
        .find(|member| member.recipient == *recipient)
        .map(|member| member.device)
}

/// The last entry a device checked, kept in a file.
struct Pin;

impl Pin {
    const VERSION: &'static str = "legix-members-pin/1";

    fn read(path: &Path, group: &GroupId) -> Result<Option<(u64, EntryId)>, Error> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let bad = || Error::Format("the pin file");
        let mut lines = text.lines();
        if lines.next() != Some(Self::VERSION) {
            return Err(bad());
        }
        let pinned_group: GroupId = lines.next().ok_or_else(bad)?.parse()?;
        if pinned_group != *group {
            return Err(Error::WrongGroup);
        }
        let (seq, id) = lines.next().ok_or_else(bad)?.split_once(' ').ok_or_else(bad)?;
        Ok(Some((crate::hex::number(seq).ok_or_else(bad)?, id.parse()?)))
    }

    fn write(path: &Path, group: &GroupId, seq: u64, id: &EntryId) -> Result<(), Error> {
        let dir = path
            .parent()
            .ok_or(Error::Format("the pin file is not in a directory"))?;
        std::fs::create_dir_all(dir)?;
        let mut file = tempfile::Builder::new().prefix(".incoming-").tempfile_in(dir)?;
        std::io::Write::write_all(
            &mut file,
            format!("{}\n{group}\n{seq} {id}\n", Self::VERSION).as_bytes(),
        )?;
        file.as_file().sync_all()?;
        file.persist(path).map_err(|err| err.error)?;
        Ok(())
    }
}

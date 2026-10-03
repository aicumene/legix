//! Entries of the membership log.

use std::{fmt, fmt::Write as _, str::FromStr};

use legix_sign::{
    AllowedSigners, Status,
    ssh_key::{PublicKey, SigningKey},
};
use legix_sync::DeviceId;

use crate::{
    Error, JoinRequest, Rule, hex,
    identity::{PREVIOUS_LEN, SEALED_LEN},
    signed,
};

/// The first line of every entry of this version.
pub const VERSION: &str = "legix-members/1";
/// The SSH signature namespace of entries.
pub const NAMESPACE: &str = "legix-members";
/// The longest an entry may be.
pub const MAX_LEN: usize = 4 << 20;

/// What a member may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    /// Changes the membership, reads, and publishes bundles.
    Admin,
    /// Reads and publishes bundles.
    Writer,
    /// Reads.
    Reader,
}

impl Role {
    /// Whether the role publishes bundles.
    pub fn publishes(self) -> bool {
        !matches!(self, Role::Reader)
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Role::Admin => "admin",
            Role::Writer => "writer",
            Role::Reader => "reader",
        })
    }
}

impl FromStr for Role {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        match text {
            "admin" => Ok(Role::Admin),
            "writer" => Ok(Role::Writer),
            "reader" => Ok(Role::Reader),
            _ => Err(Error::Format("a role is admin, writer or reader")),
        }
    }
}

macro_rules! id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
        pub struct $name([u8; 32]);

        impl $name {
            /// An id from its 32 bytes.
            pub fn from_bytes(bytes: [u8; 32]) -> Self {
                $name(bytes)
            }

            /// The id's 32 bytes.
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// The 64 lowercase hex digits of the id.
            pub fn to_hex(&self) -> String {
                hex::encode(&self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self)
            }
        }

        impl FromStr for $name {
            type Err = Error;

            fn from_str(text: &str) -> Result<Self, Error> {
                let mut bytes = [0; 32];
                hex::decode(text, &mut bytes).ok_or(Error::Format("an id is 64 lowercase hex digits"))?;
                Ok($name(bytes))
            }
        }
    };
}

id!(
    EntryId,
    "The id of an entry: the BLAKE3 hash of the entry, signature included."
);
id!(
    GroupId,
    "The id of a group: the id of the first entry of its membership log."
);

impl From<EntryId> for GroupId {
    fn from(id: EntryId) -> Self {
        GroupId(id.0)
    }
}

/// A change an entry makes to the membership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// Add the device of a join request with a role.
    Add {
        /// The role.
        role: Role,
        /// The device's request.
        request: JoinRequest,
    },
    /// Change a member's role. A member made a reader may still have its bundles up to `cutoff` applied.
    Role {
        /// The member.
        device: DeviceId,
        /// The new role.
        role: Role,
        /// For a new reader, its last bundle that may be applied; `None` otherwise.
        cutoff: Option<u64>,
    },
    /// Remove a member. Its bundles up to `cutoff` may still be applied.
    Remove {
        /// The member.
        device: DeviceId,
        /// Its last bundle that may be applied.
        cutoff: u64,
    },
}

impl Op {
    /// The device the operation is about.
    pub fn device(&self) -> DeviceId {
        match self {
            Op::Add { request, .. } => request.device(),
            Op::Role { device, .. } | Op::Remove { device, .. } => *device,
        }
    }

    fn kind(&self) -> u8 {
        match self {
            Op::Add { .. } => 0,
            Op::Role { .. } => 1,
            Op::Remove { .. } => 2,
        }
    }
}

/// An entry of the membership log, as signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub(crate) group: [u8; 32],
    pub(crate) seq: u64,
    pub(crate) prev: EntryId,
    pub(crate) time: u64,
    pub(crate) epoch: u64,
    pub(crate) ops: Vec<Op>,
    pub(crate) keys: Vec<(DeviceId, [u8; SEALED_LEN])>,
    pub(crate) previous: Option<[u8; PREVIOUS_LEN]>,
    bytes: Vec<u8>,
    signed_len: usize,
}

impl Entry {
    /// Read an entry. Anything but its one text form is refused; the join requests in it are checked. Whether the
    /// entry follows the log is for [`Roster::apply`](crate::Roster::apply).
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_LEN {
            return Err(Error::Format("an entry is longer than an entry may be"));
        }
        let (text, _) = signed::split(bytes)?;
        let signed_len = text.len();
        let text = std::str::from_utf8(text).map_err(|_| Error::Format("an entry is not UTF-8"))?;
        let mut lines = text
            .strip_suffix('\n')
            .ok_or(Error::Format("an entry's last line does not end with a line feed"))?
            .split('\n');
        let mut header = || lines.next().ok_or(Error::Format("an entry has six header lines"));
        if header()? != VERSION {
            return Err(Error::Format("an entry of a version this crate does not read"));
        }
        let mut group = [0; 32];
        hex::decode(field(header()?, "group ")?, &mut group).ok_or(Error::Format("the group"))?;
        let seq = hex::number(field(header()?, "seq ")?)
            .filter(|&seq| seq >= 1)
            .ok_or(Error::Format("the seq"))?;
        let prev: EntryId = field(header()?, "prev ")?.parse()?;
        let time = hex::number(field(header()?, "time ")?).ok_or(Error::Format("the time"))?;
        let epoch = hex::number(field(header()?, "epoch ")?)
            .filter(|&epoch| epoch >= 1)
            .ok_or(Error::Format("the epoch"))?;

        let mut entry = Entry {
            group,
            seq,
            prev,
            time,
            epoch,
            ops: Vec::new(),
            keys: Vec::new(),
            previous: None,
            bytes: bytes.to_vec(),
            signed_len,
        };
        // Lines come in kinds — add, role, remove, key, previous — in this order, each kind sorted by device.
        let mut last: Option<(u8, DeviceId)> = None;
        let mut in_order = |kind: u8, device: Option<DeviceId>| -> Result<(), Error> {
            let fits = match (last, device) {
                (Some((last_kind, _)), _) if kind < last_kind => false,
                (Some((last_kind, last_device)), Some(device)) if kind == last_kind => device > last_device,
                (Some((4, _)), None) => false,
                _ => true,
            };
            if !fits {
                return Err(Error::Format("an entry's lines are out of order, or repeat"));
            }
            last = Some((kind, device.unwrap_or(DeviceId::from_bytes([0; 32]))));
            Ok(())
        };
        for line in lines {
            let (kind, rest) = line.split_once(' ').ok_or(Error::Format("an empty line in an entry"))?;
            match kind {
                "add" => {
                    let (role, request) = rest.split_once(' ').ok_or(Error::Format("an add line"))?;
                    let request = hex::decode_vec(request).ok_or(Error::Format("an add line's request"))?;
                    let request = JoinRequest::parse(&request)?;
                    in_order(0, Some(request.device()))?;
                    entry.ops.push(Op::Add {
                        role: role.parse()?,
                        request,
                    });
                }
                "role" => {
                    let mut parts = rest.split(' ');
                    let (Some(device), Some(role), Some(cutoff), None) =
                        (parts.next(), parts.next(), parts.next(), parts.next())
                    else {
                        return Err(Error::Format("a role line"));
                    };
                    let device: DeviceId = device.parse()?;
                    in_order(1, Some(device))?;
                    let cutoff = match cutoff {
                        "-" => None,
                        number => Some(hex::number(number).ok_or(Error::Format("a role line's cutoff"))?),
                    };
                    entry.ops.push(Op::Role {
                        device,
                        role: role.parse()?,
                        cutoff,
                    });
                }
                "remove" => {
                    let (device, cutoff) = rest.split_once(' ').ok_or(Error::Format("a remove line"))?;
                    let device: DeviceId = device.parse()?;
                    in_order(2, Some(device))?;
                    entry.ops.push(Op::Remove {
                        device,
                        cutoff: hex::number(cutoff).ok_or(Error::Format("a remove line's cutoff"))?,
                    });
                }
                "key" => {
                    let (device, sealed) = rest.split_once(' ').ok_or(Error::Format("a key line"))?;
                    let device: DeviceId = device.parse()?;
                    in_order(3, Some(device))?;
                    let mut bytes = [0; SEALED_LEN];
                    hex::decode(sealed, &mut bytes).ok_or(Error::Format("a key line's sealed key"))?;
                    entry.keys.push((device, bytes));
                }
                "previous" => {
                    in_order(4, None)?;
                    let mut bytes = [0; PREVIOUS_LEN];
                    hex::decode(rest, &mut bytes).ok_or(Error::Format("the previous line"))?;
                    entry.previous = Some(bytes);
                }
                _ => return Err(Error::Format("an entry line of an unknown kind")),
            }
        }
        Ok(entry)
    }

    /// The text of an entry with these parts, in its one form.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn text(
        group: &[u8; 32],
        seq: u64,
        prev: &EntryId,
        time: u64,
        epoch: u64,
        ops: &[Op],
        keys: &[(DeviceId, [u8; SEALED_LEN])],
        previous: Option<&[u8; PREVIOUS_LEN]>,
    ) -> String {
        let mut text = format!(
            "{VERSION}\ngroup {}\nseq {seq}\nprev {prev}\ntime {time}\nepoch {epoch}\n",
            hex::encode(group)
        );
        let mut ops: Vec<&Op> = ops.iter().collect();
        ops.sort_by_key(|op| (op.kind(), op.device()));
        for op in ops {
            match op {
                Op::Add { role, request } => {
                    writeln!(text, "add {role} {}", hex::encode(request.as_bytes())).expect("writing to a string");
                }
                Op::Role { device, role, cutoff } => {
                    let cutoff = cutoff.map_or_else(|| "-".to_owned(), |cutoff| cutoff.to_string());
                    writeln!(text, "role {device} {role} {cutoff}").expect("writing to a string");
                }
                Op::Remove { device, cutoff } => {
                    writeln!(text, "remove {device} {cutoff}").expect("writing to a string");
                }
            }
        }
        let mut keys: Vec<_> = keys.iter().collect();
        keys.sort_by_key(|(device, _)| *device);
        for (device, sealed) in keys {
            writeln!(text, "key {device} {}", hex::encode(sealed)).expect("writing to a string");
        }
        if let Some(previous) = previous {
            writeln!(text, "previous {}", hex::encode(previous)).expect("writing to a string");
        }
        text
    }

    /// Sign `text`, an entry's text, with `signer`.
    pub(crate) fn sign(text: &str, signer: &impl SigningKey) -> Result<Self, Error> {
        let signature = legix_sign::sign_in(NAMESPACE, text.as_bytes(), signer)?;
        Self::parse(format!("{text}{signature}").as_bytes())
    }

    /// The key that signed the entry, if the signature is good.
    pub(crate) fn signing_key(&self) -> Result<PublicKey, Rule> {
        let outcome = legix_sign::verify_in(
            NAMESPACE,
            &self.bytes[self.signed_len..],
            &self.bytes[..self.signed_len],
            None,
            &AllowedSigners::default(),
        );
        if outcome.status != Status::Good {
            return Err(Rule::Signature(outcome.status));
        }
        Ok(outcome.key.expect("a good signature has its key"))
    }

    /// The id of the entry.
    pub fn id(&self) -> EntryId {
        EntryId(*blake3::hash(&self.bytes).as_bytes())
    }

    /// The entry's place in the log, from 1.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// When it was written, in seconds since 1970.
    pub fn time(&self) -> u64 {
        self.time
    }

    /// The epoch after it.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The changes it makes.
    pub fn ops(&self) -> &[Op] {
        &self.ops
    }

    /// The devices it seals a group key for.
    pub fn sealed_for(&self) -> impl Iterator<Item = DeviceId> + '_ {
        self.keys.iter().map(|(device, _)| *device)
    }

    /// The entry as the relay keeps it.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn field<'a>(line: &'a str, name: &str) -> Result<&'a str, Error> {
    line.strip_prefix(name)
        .ok_or(Error::Format("an entry's header lines are out of order"))
}

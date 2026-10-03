//! What a device remembers between syncs: its own chain and snapshot, the chains it applied from other devices, and the
//! erasures it has not announced yet.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    path::Path,
};

use legix::{ObjectId, bstr::BString, hash::Kind};
use legix_crypt::Oid;

use crate::{DeviceId, Error, fsutil, head::BundleId, hex};

const VERSION: &str = "legix-sync-state/1";

/// A place in a device's chain: the last bundle written or applied.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Chain {
    pub seq: u64,
    pub id: BundleId,
    pub time: u64,
}

#[derive(Debug, Default)]
pub(crate) struct State {
    /// This device's chain.
    pub own: Chain,
    /// The snapshot of this device's last bundle.
    pub published: BTreeMap<BString, ObjectId>,
    /// The chains applied from other devices.
    pub devices: BTreeMap<DeviceId, Chain>,
    /// Documents erased here and not yet announced.
    pub erase: BTreeSet<Oid>,
}

impl State {
    /// The state at `path`, or an empty one if there is none.
    pub fn load(path: &Path, kind: Kind) -> Result<Self, Error> {
        let Some(bytes) = fsutil::read_if_present(path)? else {
            return Ok(State::default());
        };
        let text = String::from_utf8(bytes).map_err(|_| Error::Format("the sync state is not UTF-8"))?;
        let mut lines = text.lines();
        if lines.next() != Some(VERSION) {
            return Err(Error::Format("the sync state is not legix-sync-state/1"));
        }
        let bad = || Error::Format("a line of the sync state cannot be read");
        let mut state = State::default();
        for line in lines {
            let (key, rest) = line
                .split_once(' ')
                .ok_or(Error::Format("a line of the sync state is empty"))?;
            match key {
                "own" => state.own = chain(rest).ok_or_else(bad)?,
                "published" => {
                    let (id, name) = rest.split_once(' ').ok_or_else(bad)?;
                    let id = ObjectId::from_hex(id.as_bytes())
                        .ok()
                        .filter(|id| id.kind() == kind)
                        .ok_or_else(bad)?;
                    state.published.insert(name.into(), id);
                }
                "device" => {
                    let (device, rest) = rest.split_once(' ').ok_or_else(bad)?;
                    state
                        .devices
                        .insert(DeviceId::from_hex(device)?, chain(rest).ok_or_else(bad)?);
                }
                "erase" => {
                    state.erase.insert(rest.parse()?);
                }
                _ => return Err(bad()),
            }
        }
        Ok(state)
    }

    /// Write the state to `path`, whole or not at all.
    pub fn save(&self, path: &Path) -> Result<(), Error> {
        let mut text = format!("{VERSION}\n");
        let own = &self.own;
        writeln!(text, "own {} {} {}", own.seq, own.id, own.time).expect("writing to a string");
        for (name, id) in &self.published {
            writeln!(text, "published {id} {name}").expect("writing to a string");
        }
        for (device, chain) in &self.devices {
            writeln!(text, "device {device} {} {} {}", chain.seq, chain.id, chain.time).expect("writing to a string");
        }
        for oid in &self.erase {
            writeln!(text, "erase {oid}").expect("writing to a string");
        }
        fsutil::write_atomically(path, text.as_bytes())?;
        Ok(())
    }
}

fn chain(text: &str) -> Option<Chain> {
    let mut parts = text.split(' ');
    let (Some(seq), Some(id), Some(time), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    Some(Chain {
        seq: hex::number(seq)?,
        id: BundleId::from_hex(id).ok()?,
        time: hex::number(time)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_state_reads_back_as_it_was_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        assert_eq!(
            State::load(&path, Kind::Sha1).unwrap().own,
            Chain::default(),
            "none yet"
        );

        let id = ObjectId::from_bytes_or_panic(&[7; 20]);
        let state = State {
            own: Chain {
                seq: 3,
                id: BundleId::from_bytes([1; 32]),
                time: 1_759_400_000,
            },
            published: [("refs/heads/main".into(), id), ("refs/tags/v1".into(), id)].into(),
            devices: [(
                DeviceId::from_bytes([2; 32]),
                Chain {
                    seq: 5,
                    id: BundleId::from_bytes([4; 32]),
                    time: 1_759_400_100,
                },
            )]
            .into(),
            erase: [Oid::of(b"gone")].into(),
        };
        state.save(&path).unwrap();
        let read = State::load(&path, Kind::Sha1).unwrap();
        assert_eq!(read.own, state.own);
        assert_eq!(read.published, state.published);
        assert_eq!(read.devices, state.devices);
        assert_eq!(read.erase, state.erase);

        std::fs::write(&path, "legix-sync-state/1\nown 1 2\n").unwrap();
        assert!(State::load(&path, Kind::Sha1).is_err());
    }
}

//! Relays: where devices leave bundles, objects and envelopes for each other.

use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

use legix_crypt::{ObjectStore, Oid};

use crate::{DeviceId, Error, fsutil};

/// Where devices leave their bundles, objects and envelopes for each other.
///
/// A relay is trusted to keep what it is given and to delete envelopes when they are erased. It is not trusted with the
/// content, which it cannot read, nor with the order of bundles, which every device checks.
pub trait Relay {
    /// The devices with at least one head on the relay.
    fn devices(&self) -> Result<Vec<DeviceId>, Error>;

    /// Head `seq` of `device`, if the relay has it.
    fn head(&self, device: &DeviceId, seq: u64) -> Result<Option<Vec<u8>>, Error>;

    /// Keep head `seq` of `device`. Heads are never replaced: refused with [`Error::HeadExists`] if the relay has a head
    /// at `seq`, and with [`Error::HeadGap`] if it does not have head `seq - 1`.
    fn put_head(&self, device: &DeviceId, seq: u64, head: &[u8]) -> Result<(), Error>;

    /// Whether the relay has the object `oid`.
    fn has_object(&self, oid: &Oid) -> Result<bool, Error>;

    /// The object `oid`, if the relay has it.
    fn open_object(&self, oid: &Oid) -> Result<Option<Box<dyn Read + '_>>, Error>;

    /// Keep the object `oid` once it is checked to hash to `oid`.
    fn put_object(&self, oid: &Oid, object: &mut dyn Read) -> Result<(), Error>;

    /// Delete the object `oid`. Deleting an object the relay does not have is not an error.
    fn remove_object(&self, oid: &Oid) -> Result<(), Error>;

    /// The envelope of document `oid`, if the relay has it.
    fn envelope(&self, oid: &Oid) -> Result<Option<Vec<u8>>, Error>;

    /// Keep the envelope of document `oid`. The first envelope of a document stays: a later one changes nothing.
    /// Refused with [`Error::Erased`] if the document's envelope was erased.
    fn put_envelope(&self, oid: &Oid, envelope: &[u8]) -> Result<(), Error>;

    /// Delete the envelope of document `oid` and refuse envelopes for it from then on.
    fn erase_envelope(&self, oid: &Oid) -> Result<(), Error>;

    /// Entry `seq` of the membership log, if the relay has it.
    fn member_entry(&self, seq: u64) -> Result<Option<Vec<u8>>, Error>;

    /// Keep entry `seq` of the membership log. Entries are never replaced: refused with [`Error::EntryExists`] if the
    /// relay has an entry at `seq` — another admin wrote first — and with [`Error::EntryGap`] if it does not have entry
    /// `seq - 1`.
    fn put_member_entry(&self, seq: u64, entry: &[u8]) -> Result<(), Error>;

    /// The join requests devices left on the relay.
    fn joins(&self) -> Result<Vec<Vec<u8>>, Error>;

    /// Leave the join request of `device` for the admins, replacing one it left before.
    fn put_join(&self, device: &DeviceId, request: &[u8]) -> Result<(), Error>;
}

impl<R: Relay + ?Sized> Relay for &R {
    fn devices(&self) -> Result<Vec<DeviceId>, Error> {
        (**self).devices()
    }

    fn head(&self, device: &DeviceId, seq: u64) -> Result<Option<Vec<u8>>, Error> {
        (**self).head(device, seq)
    }

    fn put_head(&self, device: &DeviceId, seq: u64, head: &[u8]) -> Result<(), Error> {
        (**self).put_head(device, seq, head)
    }

    fn has_object(&self, oid: &Oid) -> Result<bool, Error> {
        (**self).has_object(oid)
    }

    fn open_object(&self, oid: &Oid) -> Result<Option<Box<dyn Read + '_>>, Error> {
        (**self).open_object(oid)
    }

    fn put_object(&self, oid: &Oid, object: &mut dyn Read) -> Result<(), Error> {
        (**self).put_object(oid, object)
    }

    fn remove_object(&self, oid: &Oid) -> Result<(), Error> {
        (**self).remove_object(oid)
    }

    fn envelope(&self, oid: &Oid) -> Result<Option<Vec<u8>>, Error> {
        (**self).envelope(oid)
    }

    fn put_envelope(&self, oid: &Oid, envelope: &[u8]) -> Result<(), Error> {
        (**self).put_envelope(oid, envelope)
    }

    fn erase_envelope(&self, oid: &Oid) -> Result<(), Error> {
        (**self).erase_envelope(oid)
    }

    fn member_entry(&self, seq: u64) -> Result<Option<Vec<u8>>, Error> {
        (**self).member_entry(seq)
    }

    fn put_member_entry(&self, seq: u64, entry: &[u8]) -> Result<(), Error> {
        (**self).put_member_entry(seq, entry)
    }

    fn joins(&self) -> Result<Vec<Vec<u8>>, Error> {
        (**self).joins()
    }

    fn put_join(&self, device: &DeviceId, request: &[u8]) -> Result<(), Error> {
        (**self).put_join(device, request)
    }
}

/// A relay in a directory that several devices see: a network share, a synced cloud folder, a removable drive.
///
/// ```text
/// heads/<device id>/<seq as 20 digits>
/// objects/<2 hex>/<62 hex>
/// envelopes/<2 hex>/<62 hex>
/// erased/<2 hex>/<62 hex>
/// members/<seq as 20 digits>
/// joins/<device id>
/// ```
///
/// A synced folder that keeps deleted files for a while keeps erased envelopes for as long.
#[derive(Clone, Debug)]
pub struct DirRelay {
    dir: PathBuf,
    objects: ObjectStore,
}

impl DirRelay {
    /// A relay in `dir`. The directories are created as they are needed.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        DirRelay {
            objects: ObjectStore::new(dir.join("objects")),
            dir,
        }
    }

    /// The relay's directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn head_path(&self, device: &DeviceId, seq: u64) -> PathBuf {
        self.dir.join("heads").join(device.to_hex()).join(format!("{seq:020}"))
    }

    fn envelope_path(&self, oid: &Oid) -> PathBuf {
        fsutil::fan_out(&self.dir.join("envelopes"), &oid.to_hex())
    }

    fn erased_path(&self, oid: &Oid) -> PathBuf {
        fsutil::fan_out(&self.dir.join("erased"), &oid.to_hex())
    }

    fn entry_path(&self, seq: u64) -> PathBuf {
        self.dir.join("members").join(format!("{seq:020}"))
    }
}

impl Relay for DirRelay {
    fn devices(&self) -> Result<Vec<DeviceId>, Error> {
        let entries = match fs::read_dir(self.dir.join("heads")) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err.into()),
        };
        let mut devices = Vec::new();
        for entry in entries {
            // Other names — a file browser's own files, for one — are not devices.
            if let Some(device) = entry?.file_name().to_str().and_then(|name| name.parse().ok()) {
                devices.push(device);
            }
        }
        devices.sort();
        Ok(devices)
    }

    fn head(&self, device: &DeviceId, seq: u64) -> Result<Option<Vec<u8>>, Error> {
        Ok(fsutil::read_if_present(&self.head_path(device, seq))?)
    }

    fn put_head(&self, device: &DeviceId, seq: u64, head: &[u8]) -> Result<(), Error> {
        if seq > 1 && !self.head_path(device, seq - 1).try_exists()? {
            return Err(Error::HeadGap { device: *device, seq });
        }
        if !fsutil::write_new(&self.head_path(device, seq), head)? {
            return Err(Error::HeadExists { device: *device, seq });
        }
        Ok(())
    }

    fn has_object(&self, oid: &Oid) -> Result<bool, Error> {
        Ok(self.objects.contains(oid)?)
    }

    fn open_object(&self, oid: &Oid) -> Result<Option<Box<dyn Read + '_>>, Error> {
        match self.objects.open(oid) {
            Ok(file) => Ok(Some(Box::new(file))),
            Err(legix_crypt::Error::ObjectMissing(_)) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    fn put_object(&self, oid: &Oid, object: &mut dyn Read) -> Result<(), Error> {
        Ok(self.objects.insert(oid, object)?)
    }

    fn remove_object(&self, oid: &Oid) -> Result<(), Error> {
        self.objects.remove(oid)?;
        Ok(())
    }

    fn envelope(&self, oid: &Oid) -> Result<Option<Vec<u8>>, Error> {
        Ok(fsutil::read_if_present(&self.envelope_path(oid))?)
    }

    fn put_envelope(&self, oid: &Oid, envelope: &[u8]) -> Result<(), Error> {
        let erased = self.erased_path(oid);
        if erased.try_exists()? {
            return Err(Error::Erased(*oid));
        }
        let path = self.envelope_path(oid);
        fsutil::write_new(&path, envelope)?;
        // An erasure that ran while the envelope was written wins.
        if erased.try_exists()? {
            remove_if_present(&path)?;
            return Err(Error::Erased(*oid));
        }
        Ok(())
    }

    fn erase_envelope(&self, oid: &Oid) -> Result<(), Error> {
        let erased = self.erased_path(oid);
        if !erased.try_exists()? {
            fsutil::write_atomically(&erased, b"")?;
        }
        remove_if_present(&self.envelope_path(oid))?;
        Ok(())
    }

    fn member_entry(&self, seq: u64) -> Result<Option<Vec<u8>>, Error> {
        Ok(fsutil::read_if_present(&self.entry_path(seq))?)
    }

    fn put_member_entry(&self, seq: u64, entry: &[u8]) -> Result<(), Error> {
        if seq > 1 && !self.entry_path(seq - 1).try_exists()? {
            return Err(Error::EntryGap { seq });
        }
        if !fsutil::write_new(&self.entry_path(seq), entry)? {
            return Err(Error::EntryExists { seq });
        }
        Ok(())
    }

    fn joins(&self) -> Result<Vec<Vec<u8>>, Error> {
        let entries = match fs::read_dir(self.dir.join("joins")) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err.into()),
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.parse::<DeviceId>().is_ok())
            {
                names.push(entry.path());
            }
        }
        names.sort();
        names.iter().map(|path| fs::read(path).map_err(Error::from)).collect()
    }

    fn put_join(&self, device: &DeviceId, request: &[u8]) -> Result<(), Error> {
        fsutil::write_atomically(&self.dir.join("joins").join(device.to_hex()), request)?;
        Ok(())
    }
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => Err(err),
        _ => Ok(()),
    }
}

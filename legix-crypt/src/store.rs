use std::{
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use crate::{DocumentKey, Error, Oid, Pointer, fsutil, object};

/// A directory of encrypted objects, each in a file named by its id: `<the first two hex digits>/<the other 62>`.
///
/// An object is written once and never changed. Anyone can check it against its id without a key, so objects can be
/// copied, backed up and relayed by parties that cannot read them.
#[derive(Clone, Debug)]
pub struct ObjectStore {
    dir: PathBuf,
}

impl ObjectStore {
    /// An object store in `dir`. The directory is created when the first object is written.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        ObjectStore { dir: dir.into() }
    }

    /// The directory of the store.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Where the object `oid` is kept.
    pub fn path(&self, oid: &Oid) -> PathBuf {
        fsutil::fan_out(&self.dir, oid)
    }

    /// Whether the object `oid` is here.
    pub fn contains(&self, oid: &Oid) -> Result<bool, Error> {
        Ok(self.path(oid).try_exists()?)
    }

    /// Encrypt `document` under `key` into a new object in this store, and return the pointer to it.
    pub fn seal(&self, key: &DocumentKey, document: impl Read) -> Result<Pointer, Error> {
        let mut file = fsutil::incoming(&self.dir)?;
        let pointer = object::seal(key, document, BufWriter::new(file.as_file_mut()))?;
        fsutil::persist(file, &self.path(&pointer.oid))?;
        Ok(pointer)
    }

    /// Keep an object that comes from elsewhere — another device, a relay, a backup — once it is checked to be the
    /// object `oid` names. Nothing is kept if it is not.
    pub fn insert(&self, oid: &Oid, mut object: impl Read) -> Result<(), Error> {
        let mut file = fsutil::incoming(&self.dir)?;
        let actual = {
            let mut out = object::Hashing::new(BufWriter::new(file.as_file_mut()));
            io::copy(&mut object, &mut out)?;
            out.flush()?;
            Oid::from_hasher(&out.hasher)
        };
        if actual != *oid {
            return Err(Error::Corrupt { expected: *oid, actual });
        }
        fsutil::persist(file, &self.path(oid))?;
        Ok(())
    }

    /// The object `oid` as it is stored, not checked against its id: see [`ObjectStore::verify`].
    pub fn open(&self, oid: &Oid) -> Result<File, Error> {
        File::open(self.path(oid)).map_err(|err| match err.kind() {
            io::ErrorKind::NotFound => Error::ObjectMissing(*oid),
            _ => err.into(),
        })
    }

    /// Check that the stored object `oid` hashes to `oid`.
    pub fn verify(&self, oid: &Oid) -> Result<(), Error> {
        let mut hasher = blake3::Hasher::new();
        io::copy(&mut BufReader::new(self.open(oid)?), &mut hasher)?;
        let actual = Oid::from_hasher(&hasher);
        if actual == *oid {
            Ok(())
        } else {
            Err(Error::Corrupt { expected: *oid, actual })
        }
    }

    /// Remove the object `oid`, and return whether it was here.
    pub fn remove(&self, oid: &Oid) -> Result<bool, Error> {
        match fs::remove_file(self.path(oid)) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(err.into()),
        }
    }
}

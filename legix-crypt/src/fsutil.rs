use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use crate::Oid;

/// `dir/<the first two hex digits of oid>/<the other 62>`.
pub(crate) fn fan_out(dir: &Path, oid: &Oid) -> PathBuf {
    let hex = oid.to_hex();
    dir.join(&hex[..2]).join(&hex[2..])
}

/// A temporary file in `dir`, for content that is moved into place once it is complete.
pub(crate) fn incoming(dir: &Path) -> io::Result<tempfile::NamedTempFile> {
    fs::create_dir_all(dir)?;
    tempfile::Builder::new().prefix(".incoming-").tempfile_in(dir)
}

/// Move a complete temporary file to `path`, durably.
pub(crate) fn persist(file: tempfile::NamedTempFile, path: &Path) -> io::Result<()> {
    file.as_file().sync_all()?;
    let dir = path.parent().expect("a path in a directory");
    fs::create_dir_all(dir)?;
    file.persist(path).map_err(|err| err.error)?;
    sync_dir(dir)
}

/// Write `bytes` to `path` so that `path` holds either what it held before or all of `bytes`.
pub(crate) fn write_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = incoming(path.parent().expect("a path in a directory"))?;
    file.write_all(bytes)?;
    persist(file, path)
}

/// Write `bytes` to `path`, whole, unless `path` exists. Returns whether it was written.
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    let dir = path.parent().expect("a path in a directory");
    let mut file = incoming(dir)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    match file.persist_noclobber(path) {
        Ok(_) => {
            sync_dir(dir)?;
            Ok(true)
        }
        Err(err) if err.error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(err.error),
    }
}

/// Overwrite the file at `path` with zeros and remove it. A missing file is not an error.
pub(crate) fn destroy(path: &Path) -> io::Result<()> {
    let mut file = match OpenOptions::new().write(true).open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    let len = file.metadata()?.len();
    io::copy(&mut io::repeat(0).take(len), &mut file)?;
    file.sync_all()?;
    drop(file);
    match fs::remove_file(path) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
        _ => {}
    }
    sync_dir(path.parent().expect("a path in a directory"))
}

/// Make the entries of `dir` durable. Only Unix-like systems can sync a directory.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

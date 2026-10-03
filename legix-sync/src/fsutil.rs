use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};

/// `dir/<the first two hex digits>/<the others>`.
pub(crate) fn fan_out(dir: &Path, hex: &str) -> PathBuf {
    dir.join(&hex[..2]).join(&hex[2..])
}

/// A temporary file in `dir`, for content that is moved into place once it is complete.
pub(crate) fn incoming(dir: &Path) -> io::Result<tempfile::NamedTempFile> {
    fs::create_dir_all(dir)?;
    tempfile::Builder::new().prefix(".incoming-").tempfile_in(dir)
}

/// Write `bytes` to `path` so that `path` holds either what it held before or all of `bytes`.
pub(crate) fn write_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().expect("a path in a directory");
    let mut file = incoming(dir)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|err| err.error)?;
    sync_dir(dir)
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

/// Make the entries of `dir` durable. Only Unix-like systems can sync a directory.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Read a whole file, or `None` if there is none.
pub(crate) fn read_if_present(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

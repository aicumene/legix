//! The documents of a working folder, and the index that spares re-encrypting the ones that did not change.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use legix_crypt::{Oid, Pointer};

use crate::{Error, settings::write_atomically};

/// Names that are never documents: hidden files, Office's lock files, the system's own files.
pub(crate) fn skipped(name: &str) -> bool {
    name.starts_with('.') || name.starts_with("~$") || matches!(name, "Thumbs.db" | "desktop.ini" | "Icon\r")
}

/// The documents of `work`: their paths relative to it, with `/` between folders, and where they are.
pub(crate) fn documents(work: &Path) -> Result<Vec<(String, PathBuf)>, Error> {
    let mut found = Vec::new();
    walk(work, "", &mut found)?;
    found.sort();
    Ok(found)
}

fn walk(dir: &Path, prefix: &str, found: &mut Vec<(String, PathBuf)>) -> Result<(), Error> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        // A name that is not UTF-8 cannot be a path in the history.
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if skipped(&name) {
            continue;
        }
        let kind = entry.file_type()?;
        let path = format!("{prefix}{name}");
        if kind.is_dir() {
            walk(&entry.path(), &format!("{path}/"), found)?;
        } else if kind.is_file() {
            found.push((path, entry.path()));
        }
    }
    Ok(())
}

/// What the last save knew of each document: its size and time, the hash of its content, and its pointer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Known {
    pub size: u64,
    pub modified: u128,
    pub hash: [u8; 32],
    pub pointer: Pointer,
}

const VERSION: &str = "legix-folder-index/1";

pub(crate) fn read_index(path: &Path) -> BTreeMap<String, Known> {
    let Ok(text) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    let mut lines = text.lines();
    if lines.next() != Some(VERSION) {
        return BTreeMap::new();
    }
    // A line that cannot be read only costs re-reading that document.
    lines
        .filter_map(|line| {
            let mut parts = line.splitn(6, ' ');
            let size = parts.next()?.parse().ok()?;
            let modified = parts.next()?.parse().ok()?;
            let hash = Oid::from_hex(parts.next()?).ok()?;
            let oid = Oid::from_hex(parts.next()?).ok()?;
            let pointer_size = parts.next()?.parse().ok()?;
            let path = parts.next()?.to_owned();
            Some((
                path,
                Known {
                    size,
                    modified,
                    hash: *hash.as_bytes(),
                    pointer: Pointer {
                        oid,
                        size: pointer_size,
                    },
                },
            ))
        })
        .collect()
}

pub(crate) fn write_index(path: &Path, index: &BTreeMap<String, Known>) -> Result<(), Error> {
    let mut text = format!("{VERSION}\n");
    for (name, known) in index {
        if name.contains('\n') {
            continue;
        }
        let _ = writeln!(
            text,
            "{} {} {} {} {} {name}",
            known.size,
            known.modified,
            Oid::from_bytes(known.hash).to_hex(),
            known.pointer.oid.to_hex(),
            known.pointer.size
        );
    }
    write_atomically(path, text.as_bytes())
}

/// The size and the modification time of the file at `path`.
pub(crate) fn stamp(path: &Path) -> Result<(u64, u128), Error> {
    let meta = fs::metadata(path)?;
    let modified = meta
        .modified()?
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    Ok((meta.len(), modified))
}

/// The BLAKE3 hash of the content of the file at `path`.
pub(crate) fn hash(path: &Path) -> Result<[u8; 32], Error> {
    let mut hasher = blake3::Hasher::new();
    let mut file = fs::File::open(path)?;
    let mut buf = vec![0; 1 << 16];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

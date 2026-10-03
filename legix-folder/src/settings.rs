//! A folder's settings, kept next to its history.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use legix_members::GroupId;

use crate::Error;

const VERSION: &str = "legix-folder/1";

/// Where a folder's documents are, which group keeps its history, and the folder it syncs through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// The folder of documents.
    pub work: PathBuf,
    /// The group.
    pub group: GroupId,
    /// A folder the devices share — a network share, a synced cloud folder — that the history syncs through.
    pub relay: Option<PathBuf>,
    /// The name this device joined under.
    pub principal: String,
}

impl Settings {
    pub(crate) fn read(path: &Path) -> Result<Self, Error> {
        let text = fs::read_to_string(path)?;
        let mut lines = text.lines();
        if lines.next() != Some(VERSION) {
            return Err(Error::Format("the folder's settings are not legix-folder/1"));
        }
        let mut field = |name: &str| {
            lines
                .next()
                .and_then(|line| line.strip_prefix(name))
                .and_then(|line| line.strip_prefix(' '))
                .map(str::to_owned)
                .ok_or(Error::Format("a line of the folder's settings"))
        };
        let work = PathBuf::from(field("work")?);
        let group = field("group")?.parse()?;
        let relay = match field("relay")?.as_str() {
            "-" => None,
            path => Some(PathBuf::from(path)),
        };
        let principal = field("principal")?;
        Ok(Settings {
            work,
            group,
            relay,
            principal,
        })
    }

    pub(crate) fn write(&self, path: &Path) -> Result<(), Error> {
        let line = |path: &Path| -> Result<String, Error> {
            let text = path.to_str().ok_or(Error::Format("a folder's path is not UTF-8"))?;
            if text.contains('\n') || text == "-" {
                return Err(Error::Format("a folder's path cannot be kept"));
            }
            Ok(text.to_owned())
        };
        let relay = match &self.relay {
            Some(relay) => line(relay)?,
            None => "-".to_owned(),
        };
        let text = format!(
            "{VERSION}\nwork {}\ngroup {}\nrelay {relay}\nprincipal {}\n",
            line(&self.work)?,
            self.group,
            self.principal
        );
        write_atomically(path, text.as_bytes())
    }
}

pub(crate) fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let dir = path.parent().ok_or(Error::Format("a file outside a folder"))?;
    fs::create_dir_all(dir)?;
    let mut file = tempfile::Builder::new().prefix(".incoming-").tempfile_in(dir)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|err| err.error)?;
    Ok(())
}

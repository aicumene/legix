//! A folder of documents with a signed, encrypted, synced history: leGix for an application in one type.
//!
//! A [`Folder`] keeps the history of a working folder — the documents a person edits — next to it, in a state folder
//! of its own:
//!
//! - [`Folder::save`] takes a version: every document that changed since the last one is encrypted under a key of its
//!   own (legix-crypt), the version's tree holds only pointers, and the commit is signed with the device's key
//!   (legix-sign).
//! - [`Folder::versions`] lists the versions of every device of the group, each with whether a member signed it;
//!   [`Folder::restore`] writes a version's documents into a new folder.
//! - [`Folder::sync`] publishes this device's versions and brings the others', through a folder the devices share —
//!   a network share, a synced cloud folder — that cannot read anything it carries (legix-sync, legix-p2p).
//! - The group decides who may read and write (legix-members): [`Folder::found`] starts a group with this device as
//!   its admin, [`Folder::join`] asks to join one, and admins [admit](Folder::admit) and [remove](Folder::remove)
//!   devices.
//!
//! The application keeps the device's [`Keys`] — in the operating system's keychain — and hands them in.
#![deny(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

mod error;
mod settings;
mod walk;

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet, BinaryHeap},
    fmt::{self, Write as _},
    fs,
    path::{Component, Path, PathBuf},
};

use legix::{
    Repository,
    bstr::ByteSlice,
    objs::tree::EntryKind,
    refs::{Target, transaction::PreviousValue},
};
use legix_crypt::{DirKeyStore, Documents, ObjectStore, Pointer, Status};
use legix_sign::{AllowedSigners, Trust, repository::RepositoryExt, ssh_key::PrivateKey};
use legix_sync::{Relay, Replica};

pub use error::Error;
pub use legix::ObjectId;
pub use legix_crypt::StoreKey;
pub use legix_members::{GroupId, Identity, JoinRequest, Member, Members, Role};
pub use legix_sign::ssh_key;
pub use legix_sync::{DeviceId, DirRelay};
pub use settings::Settings;
pub use zeroize::Zeroizing;
#[cfg(feature = "p2p")]
pub use {
    iroh,
    legix_p2p::{ALPN, Peer, Peers},
};

use error::repository;
use walk::Known;

/// The branch this device's versions are on.
const BRANCH: &str = "refs/heads/main";

/// Whether a file named `name` is a document, which versions keep. Hidden files, Office's lock files and the system's
/// own files are not.
pub fn is_document(name: &str) -> bool {
    !walk::skipped(name)
}

/// The first line of [`Keys::to_secret`].
const KEYS: &str = "legix-folder-keys/1";

/// A device's keys. The application keeps them — in the operating system's keychain — and hands them in.
#[derive(Clone)]
pub struct Keys {
    /// Signs this device's versions, bundles and membership changes.
    pub signing: PrivateKey,
    /// Opens the group keys sealed for this device.
    pub identity: Identity,
    /// Wraps the keys of documents in this device's key store.
    pub store: StoreKey,
}

impl Keys {
    /// New keys from the operating system's random numbers; `comment` names the signing key.
    pub fn generate(comment: &str) -> Result<Self, Error> {
        Ok(Keys {
            signing: legix_sign::generate_ed25519(comment)?,
            identity: Identity::generate()?,
            store: StoreKey::generate()?,
        })
    }

    /// The device these keys belong to.
    pub fn device(&self) -> DeviceId {
        DeviceId::of(self.signing.public_key())
    }

    /// The fingerprint of the signing key, `SHA256:…`, as a join request shows it: what an admin compares with the
    /// device before adding it.
    pub fn fingerprint(&self) -> String {
        self.signing
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string()
    }

    /// The secret key of this device's endpoint for direct sync, derived from its signing key: the same on every
    /// start, with nothing more to keep, and no use for signing.
    pub fn endpoint_key(&self) -> Result<Zeroizing<[u8; 32]>, Error> {
        let keypair = self
            .signing
            .key_data()
            .ed25519()
            .ok_or(Error::Format("the signing key is not an Ed25519 key"))?;
        let seed = Zeroizing::new(keypair.private.to_bytes());
        Ok(Zeroizing::new(blake3::derive_key(
            "legix-folder 2026-10-03 the endpoint key of a device",
            seed.as_slice(),
        )))
    }

    /// The keys as one secret, for one item of the keychain: `legix-folder-keys/1`, the identity and the store key in
    /// hex, then the signing key in OpenSSH's format.
    pub fn to_secret(&self) -> Result<Zeroizing<String>, Error> {
        let signing = self
            .signing
            .to_openssh(ssh_key::LineEnding::LF)
            .map_err(legix_sign::Error::from)?;
        // Room for all of it up front: a string that grows leaves copies of the secret behind.
        let mut secret = Zeroizing::new(String::with_capacity(KEYS.len() + 2 * (10 + 64) + signing.len()));
        secret.push_str(KEYS);
        for (name, bytes) in [("identity", self.identity.as_bytes()), ("store", self.store.as_bytes())] {
            secret.push('\n');
            secret.push_str(name);
            secret.push(' ');
            for byte in bytes {
                let _ = write!(secret, "{byte:02x}");
            }
        }
        secret.push('\n');
        secret.push_str(&signing);
        Ok(secret)
    }

    /// The keys [`Keys::to_secret`] wrote.
    pub fn from_secret(secret: &str) -> Result<Self, Error> {
        const FORM: Error = Error::Format("not keys in the form legix-folder-keys/1");
        let mut lines = secret.splitn(4, '\n');
        if lines.next() != Some(KEYS) {
            return Err(FORM);
        }
        let mut key = |name: &str| -> Result<Zeroizing<[u8; 32]>, Error> {
            let hex = lines
                .next()
                .and_then(|line| line.strip_prefix(name))
                .and_then(|line| line.strip_prefix(' '))
                .filter(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
                .ok_or(FORM)?;
            let mut bytes = Zeroizing::new([0; 32]);
            for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks(2)) {
                let pair = std::str::from_utf8(pair).map_err(|_| FORM)?;
                *byte = u8::from_str_radix(pair, 16).map_err(|_| FORM)?;
            }
            Ok(bytes)
        };
        let identity = Identity::from_bytes(*key("identity")?);
        let store = StoreKey::from_bytes(*key("store")?);
        let signing = PrivateKey::from_openssh(lines.next().ok_or(FORM)?).map_err(legix_sign::Error::from)?;
        if signing.is_encrypted() {
            return Err(Error::Format("the signing key is encrypted"));
        }
        Ok(Keys {
            signing,
            identity,
            store,
        })
    }
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keys({})", self.device())
    }
}

/// One version of the folder.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Version {
    /// The commit.
    pub id: ObjectId,
    /// The device that signed it, if its signature is good.
    pub device: Option<DeviceId>,
    /// The name of that device in the group.
    pub principal: Option<String>,
    /// When it was saved, in seconds since 1970.
    pub time: i64,
    /// What its device said about it.
    pub message: String,
    /// Whether a member signed it.
    pub signed: Signed,
    /// How many documents it holds.
    pub documents: usize,
}

/// Who signed a version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signed {
    /// A device that is or was a member of the group.
    ByMember,
    /// A key the group does not know.
    ByUnknownKey,
    /// The signature does not match the version: it was altered.
    Bad,
    /// Nobody.
    Unsigned,
}

/// What [`Folder::restore`] wrote.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Restored {
    /// The documents written, by their paths in the folder.
    pub written: Vec<String>,
    /// The documents this device cannot read: not synced yet, or erased.
    pub unavailable: Vec<String>,
}

/// What [`Folder::sync`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Synced {
    /// Whether this device is a member of the group — before an admin adds it, it only learns the group's log.
    pub member: bool,
    /// The place in this device's chain of the bundle it published, if it had new versions.
    pub published: Option<u64>,
    /// The devices whose bundles were applied, one entry per bundle.
    pub applied: Vec<DeviceId>,
    /// Bundles that wait for what other devices bring.
    pub waiting: usize,
    /// What was refused, and why.
    pub refused: Vec<String>,
}

/// What [`Folder::bring_in`] did to the documents.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct BroughtIn {
    /// The version the folder is at now: the one brought in, when it held this device's last version, or a new one
    /// with both as its parents. `None` when that version was in already.
    pub version: Option<Version>,
    /// Documents now as the other version has them: changed or added there, and not changed here.
    pub updated: Vec<String>,
    /// Documents the other version removed, and this device had not changed: removed here too.
    pub removed: Vec<String>,
    /// Text documents both changed in different lines: merged, line by line.
    pub merged: Vec<String>,
    /// Documents both changed: this device's stays as it is, the other version's is written next to it — the path
    /// of each, then of the copy.
    pub conflicts: Vec<(String, String)>,
}

/// What [`Folder::sync_direct`] did.
#[cfg(feature = "p2p")]
#[derive(Debug)]
#[non_exhaustive]
pub struct Direct {
    /// The devices dialed, each with what came of it.
    pub reached: Vec<Reached>,
    /// What the folder took from its mirror after the devices synced.
    pub synced: Synced,
}

/// One device dialed by [`Folder::sync_direct`].
#[cfg(feature = "p2p")]
#[derive(Debug)]
#[non_exhaustive]
pub struct Reached {
    /// Its endpoint.
    pub endpoint: [u8; 32],
    /// What the sync gave and took — or `knocked`: this device asked to join, and the other kept the request — or why
    /// it failed.
    pub outcome: Result<legix_p2p::Synced, String>,
}

/// What bringing in a version does to one document.
enum Step {
    /// Write the other version's document, with its pointer.
    Take(String, ObjectId, Vec<u8>),
    Remove(String),
    /// Write a text both changed, merged.
    Merge(String, Vec<u8>),
    /// Write the other version's document next to this device's, under the second path.
    Copy(String, String, ObjectId, Vec<u8>),
}

/// A folder of documents with a history. See the crate's documentation.
pub struct Folder {
    state: PathBuf,
    settings: Settings,
    keys: Keys,
    repo: Repository,
    documents: Documents<DirKeyStore>,
    mirror: DirRelay,
}

impl fmt::Debug for Folder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Folder")
            .field("state", &self.state)
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl Folder {
    /// Start a history for the documents in `work`, kept in `state`: a new group, with this device as its admin
    /// named `principal`.
    pub fn found(
        state: impl Into<PathBuf>,
        work: impl Into<PathBuf>,
        keys: Keys,
        principal: &str,
    ) -> Result<Self, Error> {
        let state = state.into();
        let first = legix_members::found(&keys.signing, &keys.identity, principal, &[])?;
        let settings = Settings {
            work: work.into(),
            group: first.id().into(),
            relay: None,
            principal: principal.to_owned(),
        };
        let folder = Self::create(state, settings, keys)?;
        folder.mirror.put_member_entry(1, first.as_bytes())?;
        Ok(folder)
    }

    /// Ask to join the group `group`, keeping the history of `work` in `state`. With `relay`, the folder the group
    /// syncs through, the request waits there for an admin; without one, it reaches the devices this one syncs with
    /// directly ([`Folder::add_peer`]). Once an admin adds this device and it syncs, it reads the group's history.
    pub fn join(
        state: impl Into<PathBuf>,
        work: impl Into<PathBuf>,
        keys: Keys,
        principal: &str,
        group: GroupId,
        relay: Option<PathBuf>,
    ) -> Result<(Self, JoinRequest), Error> {
        let request = JoinRequest::new(&keys.signing, &keys.identity, principal)?;
        if let Some(relay) = relay.as_ref().filter(|relay| !relay.is_dir()) {
            return Err(Error::RelayMissing(relay.clone()));
        }
        let settings = Settings {
            work: work.into(),
            group,
            relay,
            principal: principal.to_owned(),
        };
        let folder = Self::create(state.into(), settings, keys)?;
        folder.mirror.put_join(&request.device(), request.as_bytes())?;
        if let Some(relay) = folder.relay()? {
            relay.put_join(&request.device(), request.as_bytes())?;
        }
        Ok((folder, request))
    }

    fn create(state: PathBuf, settings: Settings, keys: Keys) -> Result<Self, Error> {
        if state.join("folder").exists() {
            return Err(Error::NotEmpty(state));
        }
        fs::create_dir_all(&state)?;
        legix::init_bare(state.join("repo")).map_err(repository)?;
        settings.write(&state.join("folder"))?;
        Self::open(state, keys)
    }

    /// The folder whose history is kept in `state`.
    pub fn open(state: impl Into<PathBuf>, keys: Keys) -> Result<Self, Error> {
        let state = state.into();
        let settings = Settings::read(&state.join("folder"))?;
        let repo = legix::open_opts(
            state.join("repo"),
            legix::open::Options::isolated().config_overrides([
                format!("user.name={}", settings.principal),
                format!("user.email={}", settings.principal),
            ]),
        )
        .map_err(repository)?;
        Ok(Folder {
            documents: Documents::new(
                ObjectStore::new(state.join("objects")),
                DirKeyStore::new(state.join("keys"), keys.store.clone()),
            ),
            mirror: DirRelay::new(state.join("mirror")),
            state,
            settings,
            keys,
            repo,
        })
    }

    /// Where the documents are, the group, and the folder it syncs through.
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Sync through `relay` from now on, or through nothing. The shared folder has to be there.
    pub fn set_relay(&mut self, relay: Option<PathBuf>) -> Result<(), Error> {
        if let Some(relay) = relay.as_ref().filter(|relay| !relay.is_dir()) {
            return Err(Error::RelayMissing(relay.clone()));
        }
        self.settings.relay = relay;
        self.settings.write(&self.state.join("folder"))
    }

    /// This device.
    pub fn device(&self) -> DeviceId {
        self.keys.device()
    }

    /// The fingerprint of this device's key, which an admin compares with the device's join request.
    pub fn fingerprint(&self) -> String {
        self.keys.fingerprint()
    }

    /// The group's membership, as the log this device holds says.
    pub fn members(&self) -> Result<Members, Error> {
        Ok(Members::load(
            &self.mirror,
            &self.settings.group,
            &self.keys.identity,
            &self.state.join("members.pin"),
        )?)
    }

    /// Save the documents as a new version, signed by this device. Only the documents that changed since the last
    /// version are encrypted again. `None` when nothing changed.
    pub fn save(&self, message: &str) -> Result<Option<Version>, Error> {
        let index_path = self.state.join("index");
        let known = walk::read_index(&index_path);
        let mut index = BTreeMap::new();
        let mut editor = self.repo.edit_tree(self.repo.empty_tree().id).map_err(repository)?;
        for (name, path) in walk::documents(&self.settings.work)? {
            let (size, modified) = walk::stamp(&path)?;
            let unchanged = |known: &Known| -> Result<bool, Error> {
                Ok(self.documents.status(&known.pointer.oid)? == Status::Readable)
            };
            let entry = match known.get(&name) {
                Some(known) if known.size == size && known.modified == modified && unchanged(known)? => known.clone(),
                previous => {
                    let hash = walk::hash(&path)?;
                    match previous {
                        Some(known) if known.hash == hash && unchanged(known)? => Known {
                            size,
                            modified,
                            ..known.clone()
                        },
                        _ => Known {
                            size,
                            modified,
                            hash,
                            pointer: self.documents.add(fs::File::open(&path)?)?,
                        },
                    }
                }
            };
            let blob = self.repo.write_blob(entry.pointer.to_string()).map_err(repository)?;
            editor
                .upsert(name.as_str(), EntryKind::Blob, blob.detach())
                .map_err(repository)?;
            index.insert(name, entry);
        }
        let tree = editor.write().map_err(repository)?.detach();
        let parent = self.head()?;
        if let Some(parent) = parent {
            let parent_tree = self
                .repo
                .find_commit(parent)
                .map_err(repository)?
                .tree_id()
                .map_err(repository)?;
            if parent_tree == tree {
                walk::write_index(&index_path, &index)?;
                return Ok(None);
            }
        }
        let id = self
            .repo
            .commit_signed(BRANCH, message, tree, parent, &self.keys.signing)?;
        walk::write_index(&index_path, &index)?;
        Ok(Some(self.version(id, &self.signers())?))
    }

    /// The versions of every device of the group that this device holds, newest first.
    pub fn versions(&self) -> Result<Vec<Version>, Error> {
        let signers = self.signers();
        let mut tips: Vec<ObjectId> = self.head()?.into_iter().collect();
        tips.extend(self.device_tips()?);
        // Newest first, and never before a version it follows: two versions in one second, or a clock that went
        // back, cannot turn the history around.
        let mut found = BTreeMap::new();
        let mut children = BTreeMap::<ObjectId, usize>::new();
        for info in self.repo.rev_walk(tips).all().map_err(repository)? {
            let info = info.map_err(repository)?;
            for parent in info.parent_ids.iter() {
                *children.entry(*parent).or_default() += 1;
            }
            let parents: Vec<ObjectId> = info.parent_ids.iter().copied().collect();
            found.insert(info.id, (self.version(info.id, &signers)?, parents));
        }
        let mut ready: BinaryHeap<(i64, Reverse<ObjectId>)> = found
            .iter()
            .filter(|(id, _)| !children.contains_key(*id))
            .map(|(id, (version, _))| (version.time, Reverse(*id)))
            .collect();
        let mut versions = Vec::with_capacity(found.len());
        while let Some((_, Reverse(id))) = ready.pop() {
            let Some((version, parents)) = found.remove(&id) else {
                continue;
            };
            for parent in parents {
                if let Some(count) = children.get_mut(&parent) {
                    *count -= 1;
                    if *count == 0
                        && let Some((version, _)) = found.get(&parent)
                    {
                        ready.push((version.time, Reverse(parent)));
                    }
                }
            }
            versions.push(version);
        }
        Ok(versions)
    }

    /// The documents added, changed or removed since the last version, by their paths in the folder.
    pub fn changes(&self) -> Result<Vec<String>, Error> {
        let known = walk::read_index(&self.state.join("index"));
        let mut changed = Vec::new();
        let mut seen = BTreeSet::new();
        for (name, path) in walk::documents(&self.settings.work)? {
            let differs = match known.get(&name) {
                Some(known) => walk::stamp(&path)? != (known.size, known.modified) && walk::hash(&path)? != known.hash,
                None => true,
            };
            if differs {
                changed.push(name.clone());
            }
            seen.insert(name);
        }
        changed.extend(known.into_keys().filter(|name| !seen.contains(name)));
        changed.sort();
        Ok(changed)
    }

    /// The newest version of each other device that this device has not brought in, newest first. A version another
    /// one already holds is left out.
    pub fn incoming(&self) -> Result<Vec<Version>, Error> {
        let head = self.head()?;
        let mut tips = Vec::new();
        for tip in self.device_tips()? {
            if Some(tip) != head && !head.is_some_and(|head| self.holds(head, tip)) && !tips.contains(&tip) {
                tips.push(tip);
            }
        }
        let newest: Vec<ObjectId> = tips
            .iter()
            .copied()
            .filter(|&tip| !tips.iter().any(|&other| other != tip && self.holds(other, tip)))
            .collect();
        let signers = self.signers();
        let mut incoming = newest
            .into_iter()
            .map(|tip| self.version(tip, &signers))
            .collect::<Result<Vec<_>, _>>()?;
        incoming.sort_by(|a, b| b.time.cmp(&a.time).then(a.id.cmp(&b.id)));
        Ok(incoming)
    }

    /// Bring the changes of `version` — another device's — into the folder:
    ///
    /// - what only the other version changed, added or removed is taken as it is there;
    /// - what only this device changed stays;
    /// - a text document (`.md`, `.markdown`, `.txt`) both changed in different lines is merged line by line;
    /// - any other document both changed stays as this device has it, and the other version's is written next to it,
    ///   its name followed by the name of the device that signed it: nothing is lost, and nothing is written over;
    /// - a document one removed and the other changed stays, as changed.
    ///
    /// When `version` holds this device's last version, the folder moves forward to it; otherwise a new version
    /// records it, with `message`, and with this device's last version and `version` as its parents. The folder must
    /// hold no changes outside a version (see [`Folder::changes`]), and every document needed from `version` must be
    /// readable here: nothing is written until both hold.
    pub fn bring_in(&self, version: &ObjectId, message: &str) -> Result<BroughtIn, Error> {
        let theirs_tree = self.tree_of(*version).map_err(|_| Error::NoSuchVersion)?;
        let head = self.head()?;
        if head.is_some_and(|head| head == *version || self.holds(head, *version)) {
            return Ok(BroughtIn::default());
        }
        if !self.changes()?.is_empty() {
            return Err(Error::Unsaved);
        }
        let forward = head.is_none_or(|head| self.holds(*version, head));
        let ours_tree = head.map(|head| self.tree_of(head)).transpose()?;
        let base_tree = match head {
            Some(_) if forward => ours_tree,
            Some(head) => match self.repo.merge_base(head, *version) {
                Ok(base) => Some(self.tree_of(base.detach())?),
                // Histories that never met: everything either one holds is new to the other.
                Err(_) => None,
            },
            None => None,
        };
        let base = self.pointers(base_tree)?;
        let ours = self.pointers(ours_tree)?;
        let theirs = self.pointers(Some(theirs_tree))?;
        let signers = self.signers();
        let label = self
            .version(*version, &signers)?
            .principal
            .unwrap_or_else(|| "another device".to_owned());

        // What happens to each document is decided before anything is written.
        let mut steps = Vec::new();
        let mut unreadable = Vec::new();
        let mut names: BTreeSet<String> = ours.keys().cloned().collect();
        let paths: BTreeSet<&String> = base.keys().chain(ours.keys()).chain(theirs.keys()).collect();
        for path in paths {
            let (b, o, t) = (base.get(path), ours.get(path), theirs.get(path));
            // Nothing new from them: the same as here, or not changed there.
            if t == o || t == b {
                continue;
            }
            // Changed only there — or removed here and changed there: theirs.
            if o == b || o.is_none() {
                match t {
                    None => {
                        names.remove(path);
                        steps.push(Step::Remove(path.clone()));
                    }
                    Some(&blob) => match self.content(blob)? {
                        Some(bytes) => {
                            names.insert(path.clone());
                            steps.push(Step::Take(path.clone(), blob, bytes));
                        }
                        None => unreadable.push(path.clone()),
                    },
                }
                continue;
            }
            // Changed in both. Removed there and changed here: ours stays.
            let (Some(&o), Some(&t)) = (o, t) else {
                continue;
            };
            let Some(theirs_bytes) = self.content(t)? else {
                unreadable.push(path.clone());
                continue;
            };
            let ours_bytes = self.content(o)?;
            // The same content, saved on both devices.
            if ours_bytes.as_deref() == Some(theirs_bytes.as_slice()) {
                continue;
            }
            let base_bytes = match b {
                Some(&b) => self.content(b)?,
                None => None,
            };
            if let (Some(ours_bytes), Some(base_bytes)) = (&ours_bytes, &base_bytes)
                && mergeable(path)
                && let Some(merged) = merge_text(base_bytes, ours_bytes, &theirs_bytes)
            {
                steps.push(Step::Merge(path.clone(), merged));
                continue;
            }
            let copy = copy_name(path, &label, |name| {
                names.contains(name) || self.settings.work.join(name).exists()
            });
            names.insert(copy.clone());
            steps.push(Step::Copy(path.clone(), copy, t, theirs_bytes));
        }
        // Writing the rest would leave these out of the version, as if removed — for every device that takes it.
        if !unreadable.is_empty() {
            return Err(Error::Unreadable(unreadable));
        }

        let index_path = self.state.join("index");
        let mut index = walk::read_index(&index_path);
        let mut result = ours;
        let mut brought = BroughtIn::default();
        for step in steps {
            match step {
                Step::Take(path, blob, bytes) => {
                    let target = self.settings.work.join(&path);
                    settings::write_atomically(&target, &bytes)?;
                    index.insert(path.clone(), self.known(&target, blob)?);
                    result.insert(path.clone(), blob);
                    brought.updated.push(path);
                }
                Step::Remove(path) => {
                    match fs::remove_file(self.settings.work.join(&path)) {
                        Err(err) if err.kind() != std::io::ErrorKind::NotFound => return Err(err.into()),
                        _ => {}
                    }
                    index.remove(&path);
                    result.remove(&path);
                    brought.removed.push(path);
                }
                Step::Merge(path, merged) => {
                    let target = self.settings.work.join(&path);
                    settings::write_atomically(&target, &merged)?;
                    let pointer = self.documents.add(merged.as_slice())?;
                    let blob = self.repo.write_blob(pointer.to_string()).map_err(repository)?.detach();
                    index.insert(path.clone(), self.known(&target, blob)?);
                    result.insert(path.clone(), blob);
                    brought.merged.push(path);
                }
                Step::Copy(path, copy, blob, bytes) => {
                    let target = self.settings.work.join(&copy);
                    settings::write_atomically(&target, &bytes)?;
                    index.insert(copy.clone(), self.known(&target, blob)?);
                    result.insert(copy.clone(), blob);
                    brought.conflicts.push((path, copy));
                }
            }
        }

        let id = if forward {
            // This device's branch moves to theirs: no new version.
            let previous = match head {
                Some(head) => PreviousValue::MustExistAndMatch(Target::Object(head)),
                None => PreviousValue::MustNotExist,
            };
            self.repo
                .reference(BRANCH, *version, previous, "legix-folder: bring in")
                .map_err(repository)?;
            *version
        } else {
            let mut editor = self.repo.edit_tree(self.repo.empty_tree().id).map_err(repository)?;
            for (path, blob) in &result {
                editor
                    .upsert(path.as_str(), EntryKind::Blob, *blob)
                    .map_err(repository)?;
            }
            let tree = editor.write().map_err(repository)?.detach();
            let parents: Vec<ObjectId> = head.into_iter().chain([*version]).collect();
            self.repo
                .commit_signed(BRANCH, message, tree, parents, &self.keys.signing)?
        };
        walk::write_index(&index_path, &index)?;
        brought.version = Some(self.version(id, &signers)?);
        Ok(brought)
    }

    /// Write the documents of `version` into `to`, a folder that is new or holds no documents — a `.DS_Store` the
    /// system left is no document. No file that is there is written over.
    pub fn restore(&self, version: &ObjectId, to: &Path) -> Result<Restored, Error> {
        if to.exists()
            && fs::read_dir(to)?.any(|entry| {
                !entry.is_ok_and(|entry| entry.file_name().to_str().is_some_and(|name| !is_document(name)))
            })
        {
            return Err(Error::NotEmpty(to.to_owned()));
        }
        let tree = self
            .repo
            .find_commit(*version)
            .map_err(|_| Error::NoSuchVersion)?
            .tree_id()
            .map_err(repository)?
            .detach();
        let mut restored = Restored::default();
        for (name, blob) in self.files(tree)? {
            let data = self.repo.find_object(blob).map_err(repository)?.data.clone();
            let Ok(pointer) = Pointer::parse(&data) else {
                restored.unavailable.push(name);
                continue;
            };
            let target = to.join(&name);
            if let Some(dir) = target.parent() {
                fs::create_dir_all(dir)?;
            }
            match self.documents.read(&pointer, fs::File::create_new(&target)?) {
                Ok(_) => restored.written.push(name),
                Err(
                    legix_crypt::Error::Erased(_)
                    | legix_crypt::Error::KeyMissing(_)
                    | legix_crypt::Error::ObjectMissing(_),
                ) => {
                    fs::remove_file(&target)?;
                    restored.unavailable.push(name);
                }
                Err(err) => return Err(err.into()),
            }
        }
        Ok(restored)
    }

    /// Sync with this device's mirror of the group — and the mirror with the shared folder, when there is one: bring
    /// what the other devices published — the group's log, their versions, their documents — and publish this device's
    /// versions. A shared folder that is set has to be there.
    pub fn sync(&self) -> Result<Synced, Error> {
        let relay = self.relay()?;
        let group = self.settings.group;
        let mut synced = Synced::default();
        if let Some(relay) = &relay {
            let into_mirror = legix_p2p::replicate(relay, &self.mirror, &group, &self.keys.identity)?;
            synced.refused.extend(
                into_mirror
                    .refused
                    .iter()
                    .map(|refusal| format!("{}: {}", refusal.item, refusal.reason)),
            );
        }

        let members = match self.members() {
            Ok(members) => members,
            // Not added yet: the group's log has not reached this device.
            Err(Error::Members(legix_members::Error::NoLog)) => return Ok(synced),
            Err(err) => return Err(err),
        };
        synced.member = members.me().is_some_and(|me| me.last_epoch.is_none());
        if synced.member {
            let replica = Replica::new(&self.repo, &self.keys.signing, &members, &self.mirror, &self.documents);
            let pulled = replica.pull()?;
            synced.applied = pulled.applied.iter().map(|applied| applied.device).collect();
            synced.waiting = pulled.waiting.len();
            synced.refused.extend(
                pulled
                    .refused
                    .iter()
                    .map(|refused| format!("bundle {} of {}: {}", refused.seq, refused.device, refused.problem)),
            );
            if members.me().is_some_and(|me| me.role.publishes()) {
                synced.published = replica.push()?.bundle.map(|(seq, _)| seq);
            }
        }

        if let Some(relay) = &relay {
            let into_relay = legix_p2p::replicate(&self.mirror, relay, &group, &self.keys.identity)?;
            synced.refused.extend(
                into_relay
                    .refused
                    .iter()
                    .map(|refusal| format!("{}: {}", refusal.item, refusal.reason)),
            );
        }
        Ok(synced)
    }

    /// Remember `endpoint` — the endpoint of another device of the group, from an invitation — to sync with directly,
    /// besides the members whose endpoints the group's log shows.
    pub fn add_peer(&self, endpoint: &[u8; 32]) -> Result<(), Error> {
        let mut known = self.known_peers();
        if !known.contains(endpoint) {
            known.push(*endpoint);
            let mut text = String::new();
            for peer in &known {
                text.push_str(&hex(peer));
                text.push('\n');
            }
            settings::write_atomically(&self.state.join("peers"), text.as_bytes())?;
        }
        Ok(())
    }

    /// The endpoints to sync with directly: the other members', as their certificates in the mirror say, then the ones
    /// this device was told of.
    pub fn endpoints(&self) -> Result<Vec<[u8; 32]>, Error> {
        let mut endpoints = Vec::new();
        if let Ok(members) = self.members() {
            for bytes in self.mirror.endpoints()? {
                if let Ok(certificate) = legix_p2p::EndpointCert::parse(&bytes)
                    && certificate.is_member(&members)
                    && certificate.device() != self.device()
                    && !endpoints.contains(&certificate.endpoint())
                {
                    endpoints.push(certificate.endpoint());
                }
            }
        }
        for known in self.known_peers() {
            if !endpoints.contains(&known) {
                endpoints.push(known);
            }
        }
        Ok(endpoints)
    }

    fn known_peers(&self) -> Vec<[u8; 32]> {
        fs::read_to_string(self.state.join("peers"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| unhex32(line.trim()))
            .collect()
    }

    /// The devices that asked to join and are not members: their requests, for an admin to check — compare the
    /// fingerprint with the one the device shows — and to [admit](Folder::admit).
    pub fn requests(&self) -> Result<Vec<JoinRequest>, Error> {
        let members = self.members().ok();
        let mut requests = BTreeMap::new();
        let mut sources = self.mirror.joins()?;
        // A shared folder that is not connected leaves the requests this device has seen.
        if let Ok(Some(relay)) = self.relay() {
            sources.extend(relay.joins()?);
        }
        for bytes in sources {
            if let Ok(request) = JoinRequest::parse(&bytes)
                && members
                    .as_ref()
                    .is_none_or(|members| members.roster().device(&request.device()).is_none())
            {
                requests.insert(request.device(), request);
            }
        }
        Ok(requests.into_values().collect())
    }

    /// Add the device of `request` with `role`. This device must be an admin.
    pub fn admit(&self, request: &JoinRequest, role: Role) -> Result<(), Error> {
        self.change(|members| Ok(members.change().add(request.clone(), role).sign(&self.keys.signing)?))
    }

    /// Remove `device` from the group. The versions it published so far stay; the group moves to a new key, which
    /// the device does not get. This device must be an admin.
    pub fn remove(&self, device: &DeviceId) -> Result<(), Error> {
        let mut cutoff = 0;
        while self.mirror.head(device, cutoff + 1)?.is_some() {
            cutoff += 1;
        }
        self.change(|members| Ok(members.change().remove(*device, cutoff).sign(&self.keys.signing)?))
    }

    /// Write a change of the membership into the log, after reading the relay's log: another admin may have written
    /// since.
    fn change(&self, write: impl FnOnce(&Members) -> Result<legix_members::Entry, Error>) -> Result<(), Error> {
        let relay = self.relay()?;
        if let Some(relay) = &relay {
            legix_p2p::replicate(relay, &self.mirror, &self.settings.group, &self.keys.identity)?;
        }
        let entry = write(&self.members()?)?;
        self.mirror.put_member_entry(entry.seq(), entry.as_bytes())?;
        if let Some(relay) = &relay {
            legix_p2p::replicate(&self.mirror, relay, &self.settings.group, &self.keys.identity)?;
        }
        Ok(())
    }

    /// The shared folder, if one is set. It has to be there: one that is not connected — a network share, a disk —
    /// is never made anew where it was, where no other device would see what this one leaves.
    fn relay(&self) -> Result<Option<DirRelay>, Error> {
        match &self.settings.relay {
            None => Ok(None),
            Some(path) if path.is_dir() => Ok(Some(DirRelay::new(path))),
            Some(path) => Err(Error::RelayMissing(path.clone())),
        }
    }

    /// The newest version of every device whose versions reached this one.
    fn device_tips(&self) -> Result<Vec<ObjectId>, Error> {
        let mut tips = Vec::new();
        let references = self.repo.references().map_err(repository)?;
        for reference in references.prefixed("refs/legix/devices/").map_err(repository)? {
            let reference = reference.map_err(repository)?;
            if let Some(id) = reference.try_id() {
                tips.push(id.detach());
            }
        }
        Ok(tips)
    }

    /// Whether the history up to `version` holds `other`.
    fn holds(&self, version: ObjectId, other: ObjectId) -> bool {
        self.repo
            .merge_base(version, other)
            .is_ok_and(|base| base.detach() == other)
    }

    fn tree_of(&self, commit: ObjectId) -> Result<ObjectId, Error> {
        Ok(self
            .repo
            .find_commit(commit)
            .map_err(repository)?
            .tree_id()
            .map_err(repository)?
            .detach())
    }

    /// The documents of a tree, by path, each with the blob of its pointer.
    fn pointers(&self, tree: Option<ObjectId>) -> Result<BTreeMap<String, ObjectId>, Error> {
        Ok(match tree {
            Some(tree) => self.files(tree)?.into_iter().collect(),
            None => BTreeMap::new(),
        })
    }

    /// The content of the document whose pointer is `blob`; `None` when this device cannot read it.
    fn content(&self, blob: ObjectId) -> Result<Option<Vec<u8>>, Error> {
        let data = self.repo.find_object(blob).map_err(repository)?.data.clone();
        let Ok(pointer) = Pointer::parse(&data) else {
            return Ok(None);
        };
        match self.documents.read_to_vec(&pointer) {
            Ok(document) => Ok(Some(document)),
            Err(
                legix_crypt::Error::Erased(_)
                | legix_crypt::Error::KeyMissing(_)
                | legix_crypt::Error::ObjectMissing(_),
            ) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// What the index knows of the document just written at `path`, whose pointer is `blob`.
    fn known(&self, path: &Path, blob: ObjectId) -> Result<Known, Error> {
        let data = self.repo.find_object(blob).map_err(repository)?.data.clone();
        let pointer = Pointer::parse(&data).map_err(|_| Error::Format("a version's pointer"))?;
        let (size, modified) = walk::stamp(path)?;
        Ok(Known {
            size,
            modified,
            hash: walk::hash(path)?,
            pointer,
        })
    }

    fn head(&self) -> Result<Option<ObjectId>, Error> {
        Ok(self
            .repo
            .try_find_reference(BRANCH)
            .map_err(repository)?
            .and_then(|reference| reference.try_id().map(legix::Id::detach)))
    }

    /// The members' keys, and their names by device.
    fn signers(&self) -> (AllowedSigners, BTreeMap<DeviceId, String>) {
        let mut signers = AllowedSigners::default();
        let mut names = BTreeMap::new();
        if let Ok(members) = self.members() {
            let roster = members.roster();
            for member in roster.members().values().chain(roster.former().values()) {
                signers.push(member.principal.clone(), member.key.clone());
                names.insert(member.device, member.principal.clone());
            }
        }
        (signers, names)
    }

    fn version(
        &self,
        id: ObjectId,
        (signers, names): &(AllowedSigners, BTreeMap<DeviceId, String>),
    ) -> Result<Version, Error> {
        let commit = self.repo.find_commit(id).map_err(repository)?;
        let time = commit.time().map_err(repository)?.seconds;
        let message = commit.message_raw_sloppy().to_str_lossy().trim().to_owned();
        let tree = commit.tree_id().map_err(repository)?.detach();
        let (signed, device) = match self.repo.verify_commit_signature(id, signers)? {
            None => (Signed::Unsigned, None),
            Some(outcome) => {
                let device = outcome.key.as_ref().map(DeviceId::of);
                match (outcome.status, outcome.trust) {
                    (legix_sign::Status::Good, Trust::Allowed { .. }) => (Signed::ByMember, device),
                    (legix_sign::Status::Good, _) => (Signed::ByUnknownKey, device),
                    _ => (Signed::Bad, None),
                }
            }
        };
        Ok(Version {
            id,
            principal: device.and_then(|device| names.get(&device).cloned()),
            device,
            time,
            message,
            signed,
            documents: self.files(tree)?.len(),
        })
    }

    /// The documents of a tree: their paths and their blobs. A name that could point outside a folder — `..`, `.`,
    /// one with a separator, a drive — is left out, and so is one that is no document — hidden, a lock file, the
    /// system's own: a version holds what `save` takes, whoever wrote it.
    fn files(&self, tree: ObjectId) -> Result<Vec<(String, ObjectId)>, Error> {
        let mut files = Vec::new();
        let mut pending = vec![(String::new(), tree)];
        while let Some((prefix, id)) = pending.pop() {
            let tree = self.repo.find_tree(id).map_err(repository)?;
            for entry in tree.iter() {
                let entry = entry.map_err(repository)?;
                let Ok(name) = entry.filename().to_str() else {
                    continue;
                };
                let mut components = Path::new(name).components();
                let plain = matches!(components.next(), Some(Component::Normal(one)) if one == name)
                    && components.next().is_none();
                if !plain || name.contains(['/', '\\', '\0']) || !is_document(name) {
                    continue;
                }
                let path = format!("{prefix}{name}");
                if entry.mode().is_tree() {
                    pending.push((format!("{path}/"), entry.oid().to_owned()));
                } else if entry.mode().is_blob() {
                    files.push((path, entry.oid().to_owned()));
                }
            }
        }
        files.sort();
        Ok(files)
    }
}

#[cfg(feature = "p2p")]
impl Folder {
    /// This device's part in syncing directly through its endpoint `endpoint` — whose secret key is
    /// [`Keys::endpoint_key`]: its certificate goes into the mirror, for the other devices to find.
    pub fn peer(&self, endpoint: &[u8; 32]) -> Result<Peer<DirRelay>, Error> {
        let certificate = legix_p2p::EndpointCert::new(&self.keys.signing, endpoint)?;
        Ok(Peer::new(
            DirRelay::new(self.state.join("mirror")),
            self.settings.group,
            self.keys.identity.clone(),
            certificate,
        )?)
    }

    /// Sync directly with the devices of the group that `endpoint` reaches ([`Folder::endpoints`]), each given `wait`:
    /// this device's versions go into its mirror first, the mirrors sync, then what came is pulled. A device that asked
    /// to join knocks: its request reaches the admins of the devices it reaches. One that learns in the sync that it
    /// has been added — and so gave nothing yet — syncs once more, to give the others its own.
    pub async fn sync_direct(
        &self,
        endpoint: &iroh::Endpoint,
        peer: &Peer<DirRelay>,
        wait: std::time::Duration,
    ) -> Result<Direct, Error> {
        let before = self.sync()?;
        let mut reached = self.dial_all(endpoint, peer, wait).await?;
        let mut synced = self.sync()?;
        if synced.member && !before.member {
            reached = self.dial_all(endpoint, peer, wait).await?;
            synced = self.sync()?;
        }
        Ok(Direct { reached, synced })
    }

    async fn dial_all(
        &self,
        endpoint: &iroh::Endpoint,
        peer: &Peer<DirRelay>,
        wait: std::time::Duration,
    ) -> Result<Vec<Reached>, Error> {
        let mut reached = Vec::new();
        for id in self.endpoints()? {
            let Ok(remote) = iroh::EndpointId::from_bytes(&id) else {
                continue;
            };
            if remote == endpoint.id() {
                continue;
            }
            let outcome = match tokio::time::timeout(wait, peer.sync_with(endpoint, remote)).await {
                Ok(Ok(synced)) => Ok(synced),
                Ok(Err(err)) => Err(err.to_string()),
                Err(_) => Err("it did not answer in time".to_owned()),
            };
            reached.push(Reached { endpoint: id, outcome });
        }
        Ok(reached)
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn unhex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0; 32];
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(bytes)
}

/// Whether a document is text that merges line by line.
fn mergeable(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    [".md", ".markdown", ".txt"].iter().any(|ext| name.ends_with(ext))
}

/// `ours` and `theirs` merged line by line against `base`, unless a line was changed on both sides, or one is not text.
fn merge_text(base: &[u8], ours: &[u8], theirs: &[u8]) -> Option<Vec<u8>> {
    use legix::merge::blob::{Resolution, builtin_driver};
    if [base, ours, theirs].iter().any(|text| text.contains(&0)) {
        return None;
    }
    let mut merged = Vec::new();
    let mut input = legix::diff::blob::InternedInput::default();
    let resolution = builtin_driver::text(
        &mut merged,
        &mut input,
        Default::default(),
        ours,
        base,
        theirs,
        Default::default(),
    );
    (resolution != Resolution::Conflict).then_some(merged)
}

/// The path the other side's copy of `path` takes: its name, then `(label)`, before the extension — `Heads of
/// terms (bo@example.com).docx` — and a number when that is taken.
fn copy_name(path: &str, label: &str, taken: impl Fn(&str) -> bool) -> String {
    let label: String = label
        .chars()
        .map(|c| {
            if matches!(c, '/' | '\\' | ':') || c.is_control() {
                '-'
            } else {
                c
            }
        })
        .collect();
    let (dir, name) = match path.rsplit_once('/') {
        Some((dir, name)) => (format!("{dir}/"), name),
        None => (String::new(), path),
    };
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, format!(".{ext}")),
        _ => (name, String::new()),
    };
    let mut n = 1;
    loop {
        let candidate = match n {
            1 => format!("{dir}{stem} ({label}){ext}"),
            n => format!("{dir}{stem} ({label} {n}){ext}"),
        };
        if !taken(&candidate) {
            return candidate;
        }
        n += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_copy_is_named_after_the_device_and_never_takes_a_name() {
        let taken = |name: &str| name == "Evidence/Invoice (bo@example.com).pdf";
        assert_eq!(
            copy_name("Heads of terms.docx", "bo@example.com", |_| false),
            "Heads of terms (bo@example.com).docx"
        );
        assert_eq!(
            copy_name("Evidence/Invoice.pdf", "bo@example.com", taken),
            "Evidence/Invoice (bo@example.com 2).pdf"
        );
        assert_eq!(copy_name("README", "a/b:c", |_| false), "README (a-b-c)");
        assert_eq!(copy_name(".profile", "bo", |_| false), ".profile (bo)");
    }

    #[test]
    fn only_text_merges_line_by_line() {
        assert!(mergeable("Notes.md") && mergeable("a/B.TXT") && mergeable("x.markdown"));
        assert!(!mergeable("Heads of terms.docx") && !mergeable("md"));
        let merged = merge_text(b"a\nb\nc\n", b"A\nb\nc\n", b"a\nb\nC\n").unwrap();
        assert_eq!(merged, b"A\nb\nC\n");
        assert_eq!(merge_text(b"a\n", b"A\n", b"B\n"), None, "the same line, two ways");
        assert_eq!(merge_text(b"a\0", b"A\0", b"a\0"), None, "not text");
    }
}

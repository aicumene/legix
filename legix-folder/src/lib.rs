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
    collections::{BTreeMap, BinaryHeap},
    fmt::{self, Write as _},
    fs,
    path::{Component, Path, PathBuf},
};

use legix::{ObjectId, Repository, bstr::ByteSlice, objs::tree::EntryKind};
use legix_crypt::{DirKeyStore, Documents, ObjectStore, Pointer, Status};
use legix_sign::{AllowedSigners, Trust, repository::RepositoryExt, ssh_key::PrivateKey};
use legix_sync::{DirRelay, Relay, Replica};

pub use error::Error;
pub use legix_crypt::StoreKey;
pub use legix_members::{GroupId, Identity, JoinRequest, Member, Members, Role};
pub use legix_sign::ssh_key;
pub use legix_sync::DeviceId;
pub use settings::Settings;
pub use zeroize::Zeroizing;

use error::repository;
use walk::Known;

/// The branch this device's versions are on.
const BRANCH: &str = "refs/heads/main";

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

    /// Ask to join the group `group`, which syncs through `relay`, keeping the history of `work` in `state`. The
    /// request waits on the relay for an admin; once one adds this device and it syncs, it reads the group's history.
    pub fn join(
        state: impl Into<PathBuf>,
        work: impl Into<PathBuf>,
        keys: Keys,
        principal: &str,
        group: GroupId,
        relay: impl Into<PathBuf>,
    ) -> Result<(Self, JoinRequest), Error> {
        let request = JoinRequest::new(&keys.signing, &keys.identity, principal)?;
        let settings = Settings {
            work: work.into(),
            group,
            relay: Some(relay.into()),
            principal: principal.to_owned(),
        };
        let folder = Self::create(state.into(), settings, keys)?;
        folder.mirror.put_join(&request.device(), request.as_bytes())?;
        if let Some(relay) = folder.relay() {
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

    /// Sync through `relay` from now on, or through nothing.
    pub fn set_relay(&mut self, relay: Option<PathBuf>) -> Result<(), Error> {
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
        let references = self.repo.references().map_err(repository)?;
        for reference in references.prefixed("refs/legix/devices/").map_err(repository)? {
            let reference = reference.map_err(repository)?;
            if let Some(id) = reference.try_id() {
                tips.push(id.detach());
            }
        }
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

    /// Write the documents of `version` into `to`, a folder that is new or empty.
    pub fn restore(&self, version: &ObjectId, to: &Path) -> Result<Restored, Error> {
        if to.exists() && fs::read_dir(to)?.next().is_some() {
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
            match self.documents.read(&pointer, fs::File::create(&target)?) {
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

    /// Sync through the shared folder: bring what the other devices published — the group's log, their versions,
    /// their documents — and publish this device's versions.
    pub fn sync(&self) -> Result<Synced, Error> {
        let relay = self.relay().ok_or(Error::NoRelay)?;
        let group = self.settings.group;
        let mut synced = Synced::default();
        let into_mirror = legix_p2p::replicate(&relay, &self.mirror, &group, &self.keys.identity)?;
        synced.refused.extend(
            into_mirror
                .refused
                .iter()
                .map(|refusal| format!("{}: {}", refusal.item, refusal.reason)),
        );

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

        let into_relay = legix_p2p::replicate(&self.mirror, &relay, &group, &self.keys.identity)?;
        synced.refused.extend(
            into_relay
                .refused
                .iter()
                .map(|refusal| format!("{}: {}", refusal.item, refusal.reason)),
        );
        Ok(synced)
    }

    /// The devices that asked to join and are not members: their requests, for an admin to check — compare the
    /// fingerprint with the one the device shows — and to [admit](Folder::admit).
    pub fn requests(&self) -> Result<Vec<JoinRequest>, Error> {
        let members = self.members().ok();
        let mut requests = BTreeMap::new();
        let mut sources = self.mirror.joins()?;
        if let Some(relay) = self.relay() {
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
        let relay = self.relay();
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

    fn relay(&self) -> Option<DirRelay> {
        self.settings.relay.as_ref().map(DirRelay::new)
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
    /// one with a separator, a drive — is left out.
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
                if !plain || name.contains(['/', '\\', '\0']) {
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

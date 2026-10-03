use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, BufReader, BufWriter, Seek, SeekFrom, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use legix::{ObjectId, Repository, bstr::BString};
use legix_crypt::{DocumentKey, Documents, KeyState, KeyStore, Oid, Status};
use legix_sign::{
    AllowedSigners,
    ssh_key::{PublicKey, SigningKey},
};

use crate::{
    DeviceId, Error, GroupKey, Problem, Relay,
    body::{self, GitBundle, Manifest},
    envelope,
    head::{BundleId, Head, SignedHead},
    pack,
    state::{Chain, State},
};

/// A repository on one device, kept in sync with the other members' devices through a relay.
///
/// Each device publishes only its own branches and tags; the branches and tags of another device appear here under
/// `refs/legix/devices/<its device id>/`, to merge from as one would from a remote.
pub struct Replica<'a, R: ?Sized, K, S> {
    repo: &'a Repository,
    signer: &'a S,
    device: DeviceId,
    group: &'a GroupKey,
    members: &'a AllowedSigners,
    relay: &'a R,
    documents: &'a Documents<K>,
}

/// What [`Replica::push`] published.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Pushed {
    /// The bundle's place in this device's chain and its id, or `None` when there was nothing new to publish.
    pub bundle: Option<(u64, BundleId)>,
    /// How many objects the bundle's pack holds.
    pub objects: usize,
    /// The documents the new commits point to, each with whether this device holds it and put it on the relay.
    pub documents: Vec<(Oid, bool)>,
    /// The documents whose erasure the bundle announces.
    pub erased: Vec<Oid>,
}

/// What [`Replica::pull`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Pulled {
    /// The bundles applied, in the order they were applied.
    pub applied: Vec<Applied>,
    /// Bundles that wait: their body is not on the relay yet, or objects they need are not here yet.
    pub waiting: Vec<Waiting>,
    /// Bundles refused, and why. Nothing more is applied from their devices.
    pub refused: Vec<Refused>,
}

/// A bundle applied by [`Replica::pull`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Applied {
    /// The device that wrote it.
    pub device: DeviceId,
    /// Its place in the device's chain.
    pub seq: u64,
    /// The principals the members list for the device's key.
    pub principals: String,
    /// The device's branches and tags after the bundle.
    pub refs: Vec<(BString, ObjectId)>,
    /// The documents the bundle's commits point to that are readable here now.
    pub documents: Vec<Oid>,
    /// The documents the bundle's commits point to that are not: not on the relay, erased, or without their key.
    pub unavailable: Vec<Oid>,
    /// The documents erased here because the device erased them.
    pub erased: Vec<Oid>,
}

/// A bundle that waits.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Waiting {
    /// The device that wrote it.
    pub device: DeviceId,
    /// Its place in the device's chain.
    pub seq: u64,
    /// What it waits for.
    pub reason: Wait,
}

/// What a bundle waits for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Wait {
    /// Its body is not on the relay yet.
    Body,
    /// These objects, which the bundles of other devices bring, are not here yet.
    Prerequisites(Vec<ObjectId>),
}

/// A bundle that was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Refused {
    /// The device it claims to come from.
    pub device: DeviceId,
    /// Its place in the device's chain.
    pub seq: u64,
    /// Why it was refused.
    pub problem: Problem,
}

/// The outcome of one step of applying a bundle that is not success.
enum Step {
    Wait(Wait),
    Refuse(Problem),
    Fail(Error),
}

impl From<Error> for Step {
    fn from(err: Error) -> Self {
        Step::Fail(err)
    }
}

impl From<legix_crypt::Error> for Step {
    fn from(err: legix_crypt::Error) -> Self {
        Step::Fail(err.into())
    }
}

impl From<io::Error> for Step {
    fn from(err: io::Error) -> Self {
        Step::Fail(err.into())
    }
}

impl<'a, R: Relay + ?Sized, K: KeyStore, S: SigningKey> Replica<'a, R, K, S> {
    /// The replica of `repo` on the device that signs with `signer`, syncing with the `members` through `relay`. The
    /// documents of the repository are in `documents`, and `group` is the key the members share.
    pub fn new(
        repo: &'a Repository,
        signer: &'a S,
        group: &'a GroupKey,
        members: &'a AllowedSigners,
        relay: &'a R,
        documents: &'a Documents<K>,
    ) -> Self {
        Replica {
            repo,
            signer,
            device: DeviceId::of(&PublicKey::from(signer.public_key())),
            group,
            members,
            relay,
            documents,
        }
    }

    /// This device's id.
    pub fn device(&self) -> DeviceId {
        self.device
    }

    /// Publish this device's branches and tags, the documents their new commits point to, and the erasures not yet
    /// announced, in a new bundle. When there is nothing new, nothing is published.
    pub fn push(&self) -> Result<Pushed, Error> {
        let _lock = self.lock()?;
        let mut state = self.load()?;
        self.adopt_own(&mut state)?;

        let snapshot = pack::refs_under(self.repo, "refs/heads/")?
            .into_iter()
            .chain(pack::refs_under(self.repo, "refs/tags/")?)
            .collect::<BTreeMap<_, _>>();
        let erased: Vec<Oid> = state.erase.iter().copied().collect();
        for oid in &erased {
            self.relay.erase_envelope(oid)?;
            self.relay.remove_object(oid)?;
        }
        if snapshot == state.published && erased.is_empty() {
            return Ok(Pushed::default());
        }

        let mut haves: Vec<ObjectId> = state.published.values().copied().collect();
        haves.extend(pack::refs_under(self.repo, "refs/legix/devices/")?.into_values());
        let outgoing = pack::outgoing(self.repo, &snapshot, &haves)?;
        let mut documents = Vec::new();
        for oid in &outgoing.documents {
            documents.push((*oid, self.upload_document(oid)?));
        }
        let manifest = Manifest {
            documents: outgoing.documents,
            erased: state.erase.clone(),
        };
        let bundle = GitBundle {
            prerequisites: outgoing.prerequisites,
            refs: snapshot.iter().map(|(name, id)| (name.clone(), *id)).collect(),
        };
        let objects = outgoing.counts.len();

        // The body is written in the clear to a temporary file, then encrypted under a new bundle key.
        let mut plain = self.temp()?;
        {
            let mut out = BufWriter::new(&mut plain);
            body::write_header(&mut out, &manifest, &bundle, self.repo.object_hash())?;
            pack::write_pack(self.repo, &outgoing.counts, &mut out)?;
            out.flush()?;
        }
        plain.seek(SeekFrom::Start(0))?;
        let key = DocumentKey::generate()?;
        let mut sealed = self.temp()?;
        let body = legix_crypt::object::seal(&key, BufReader::new(&mut plain), BufWriter::new(&mut sealed))?;
        sealed.seek(SeekFrom::Start(0))?;
        self.relay.put_object(&body.oid, &mut sealed)?;

        let seq = state.own.seq + 1;
        let head = Head {
            device: self.device,
            seq,
            prev: state.own.id,
            time: now().max(state.own.time),
            body: body.oid,
            body_len: body.object_len().expect("a sealed body has a length"),
            key: Head::wrap_key(self.group, &self.device, seq, &body.oid, &key)?,
        };
        let signed = head.sign(self.signer)?;
        self.relay.put_head(&self.device, seq, signed.as_bytes())?;

        state.own = Chain {
            seq,
            id: signed.id(),
            time: head.time,
        };
        state.published = snapshot;
        state.erase.clear();
        state.save(&self.state_path())?;
        Ok(Pushed {
            bundle: Some((seq, signed.id())),
            objects,
            documents,
            erased,
        })
    }

    /// Apply the bundles of the other devices that are on the relay, in each device's order, as far as their
    /// prerequisites allow.
    pub fn pull(&self) -> Result<Pulled, Error> {
        let _lock = self.lock()?;
        let mut state = self.load()?;
        let devices: Vec<DeviceId> = self
            .relay
            .devices()?
            .into_iter()
            .filter(|device| *device != self.device)
            .collect();
        let mut pulled = Pulled::default();
        let mut waiting = BTreeMap::new();
        let mut refused = BTreeSet::new();
        // A bundle may need what another device's bundle brings, so devices are gone through until none progresses.
        loop {
            let mut progressed = false;
            for device in &devices {
                if refused.contains(device) {
                    continue;
                }
                loop {
                    let chain = state.devices.get(device).copied().unwrap_or_default();
                    let seq = chain.seq + 1;
                    let Some(head) = self.relay.head(device, seq)? else {
                        break;
                    };
                    match self.apply(device, seq, &head, chain) {
                        Ok((applied, chain)) => {
                            state.devices.insert(*device, chain);
                            state.save(&self.state_path())?;
                            waiting.remove(device);
                            pulled.applied.push(applied);
                            progressed = true;
                        }
                        Err(Step::Wait(reason)) => {
                            waiting.insert(
                                *device,
                                Waiting {
                                    device: *device,
                                    seq,
                                    reason,
                                },
                            );
                            break;
                        }
                        Err(Step::Refuse(problem)) => {
                            refused.insert(*device);
                            waiting.remove(device);
                            pulled.refused.push(Refused {
                                device: *device,
                                seq,
                                problem,
                            });
                            break;
                        }
                        Err(Step::Fail(err)) => return Err(err),
                    }
                }
            }
            if !progressed {
                break;
            }
        }
        pulled.waiting = waiting.into_values().collect();
        Ok(pulled)
    }

    /// Erase document `oid`: destroy its key here, delete its envelope and its object on the relay, and announce the
    /// erasure in this device's next bundle, so that every member destroys its key too.
    pub fn erase(&self, oid: &Oid) -> Result<(), Error> {
        let _lock = self.lock()?;
        let mut state = self.load()?;
        self.documents.erase(oid)?;
        state.erase.insert(*oid);
        state.save(&self.state_path())?;
        self.relay.erase_envelope(oid)?;
        self.relay.remove_object(oid)?;
        Ok(())
    }

    /// Check and apply bundle `seq` of `device`, which follows `chain`.
    fn apply(&self, device: &DeviceId, seq: u64, bytes: &[u8], chain: Chain) -> Result<(Applied, Chain), Step> {
        let signed = SignedHead::parse(bytes).map_err(|err| Step::Refuse(format_problem(&err)))?;
        let head = signed.head();
        if head.device != *device || head.seq != seq {
            return Err(Step::Refuse(Problem::Misplaced));
        }
        let principals = signed.verify(self.members).map_err(Step::Refuse)?;
        if head.prev != chain.id {
            return Err(Step::Refuse(Problem::Fork));
        }
        if head.time < chain.time {
            return Err(Step::Refuse(Problem::TimeGoesBack));
        }

        let (manifest, bundle, mut pack) = self.open_body(&signed)?;
        for (name, _) in &bundle.refs {
            let allowed = (name.starts_with(b"refs/heads/") || name.starts_with(b"refs/tags/"))
                && legix::refs::FullName::try_from(name.clone()).is_ok();
            if !allowed {
                return Err(Step::Refuse(Problem::ForeignRef(name.to_string())));
            }
        }
        let missing: Vec<ObjectId> = bundle
            .prerequisites
            .iter()
            .filter(|id| !self.repo.has_object(*id))
            .copied()
            .collect();
        if !missing.is_empty() {
            return Err(Step::Wait(Wait::Prerequisites(missing)));
        }
        pack::store_pack(self.repo, &mut pack).map_err(Step::Refuse)?;
        pack::check_complete(self.repo, &bundle.refs, &bundle.prerequisites).map_err(Step::Refuse)?;
        pack::set_device_refs(self.repo, device, seq, &bundle.refs)?;

        let (mut documents, mut unavailable) = (Vec::new(), Vec::new());
        for oid in &manifest.documents {
            if self.fetch_document(oid)? {
                documents.push(*oid);
            } else {
                unavailable.push(*oid);
            }
        }
        for oid in &manifest.erased {
            self.documents.erase(oid)?;
        }
        Ok((
            Applied {
                device: *device,
                seq,
                principals,
                refs: bundle.refs,
                documents,
                unavailable,
                erased: manifest.erased.into_iter().collect(),
            },
            Chain {
                seq,
                id: signed.id(),
                time: head.time,
            },
        ))
    }

    /// Fetch the body of a head from the relay, check it against the head and open it: the manifest, the git bundle's
    /// header, and the pack to read next.
    fn open_body(&self, signed: &SignedHead) -> Result<(Manifest, GitBundle, BufReader<File>), Step> {
        let head = signed.head();
        let Some(mut object) = self.relay.open_object(&head.body)? else {
            return Err(Step::Wait(Wait::Body));
        };
        let mut sealed = self.temp()?;
        let len = io::copy(&mut object, &mut sealed)?;
        drop(object);
        sealed.seek(SeekFrom::Start(0))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update_reader(&mut sealed)?;
        if len != head.body_len || Oid::from_bytes(*hasher.finalize().as_bytes()) != head.body {
            return Err(Step::Refuse(Problem::BodyMismatch));
        }
        sealed.seek(SeekFrom::Start(0))?;
        let key = head
            .unwrap_key(self.group)
            .map_err(|_| Step::Refuse(Problem::GroupKey))?;
        let mut plain = self.temp()?;
        legix_crypt::object::open(&key, BufReader::new(&mut sealed), BufWriter::new(&mut plain))
            .map_err(|err| Step::Refuse(Problem::Body(err.to_string())))?;
        plain.seek(SeekFrom::Start(0))?;
        let mut reader = BufReader::new(plain);
        let (manifest, bundle) = body::read_header(&mut reader, self.repo.object_hash())
            .map_err(|err| Step::Refuse(Problem::Body(err.into())))?;
        Ok((manifest, bundle, reader))
    }

    /// Take this device's bundles on the relay that the state does not know — written by a push that stopped before it
    /// saved — as published.
    fn adopt_own(&self, state: &mut State) -> Result<(), Error> {
        let mut me = AllowedSigners::default();
        me.push("*", PublicKey::from(self.signer.public_key()));
        loop {
            let seq = state.own.seq + 1;
            let Some(bytes) = self.relay.head(&self.device, seq)? else {
                return Ok(());
            };
            let refuse = |problem| Error::OwnBundle {
                device: self.device,
                seq,
                problem,
            };
            let signed = SignedHead::parse(&bytes).map_err(|err| refuse(format_problem(&err)))?;
            let head = signed.head();
            if head.device != self.device || head.seq != seq {
                return Err(refuse(Problem::Misplaced));
            }
            signed.verify(&me).map_err(refuse)?;
            if head.prev != state.own.id {
                return Err(refuse(Problem::Fork));
            }
            let (manifest, bundle, _) = match self.open_body(&signed) {
                Ok(opened) => opened,
                Err(Step::Fail(err)) => return Err(err),
                Err(Step::Refuse(problem)) => return Err(refuse(problem)),
                Err(Step::Wait(_)) => return Err(refuse(Problem::BodyMismatch)),
            };
            state.published = bundle.refs.into_iter().collect();
            for oid in &manifest.erased {
                state.erase.remove(oid);
            }
            state.own = Chain {
                seq,
                id: signed.id(),
                time: head.time,
            };
            state.save(&self.state_path())?;
        }
    }

    /// Put a document this device holds on the relay: its object and an envelope with its key. Returns whether it
    /// holds the document.
    fn upload_document(&self, oid: &Oid) -> Result<bool, Error> {
        let KeyState::Present(key) = self.documents.keys().get(oid)? else {
            return Ok(false);
        };
        if !self.relay.has_object(oid)? {
            if !self.documents.objects().contains(oid)? {
                return Ok(false);
            }
            let mut object = self.documents.objects().open(oid)?;
            self.relay.put_object(oid, &mut object)?;
        }
        if self.relay.envelope(oid)?.is_none() {
            match self
                .relay
                .put_envelope(oid, &envelope::seal_envelope(self.group, oid, &key)?)
            {
                Ok(()) => {}
                Err(Error::Erased(_)) => return Ok(false),
                Err(err) => return Err(err),
            }
        }
        Ok(true)
    }

    /// Bring a document here from the relay: its object and its key. Returns whether it is readable here.
    fn fetch_document(&self, oid: &Oid) -> Result<bool, Error> {
        match self.documents.status(oid)? {
            Status::Readable => return Ok(true),
            Status::Erased => return Ok(false),
            _ => {}
        }
        if !self.documents.objects().contains(oid)? {
            let Some(mut object) = self.relay.open_object(oid)? else {
                return Ok(false);
            };
            match self.documents.objects().insert(oid, &mut object) {
                Ok(()) => {}
                Err(legix_crypt::Error::Corrupt { .. }) => return Ok(false),
                Err(err) => return Err(err.into()),
            }
        }
        if matches!(self.documents.keys().get(oid)?, KeyState::Missing) {
            let Some(envelope) = self.relay.envelope(oid)? else {
                return Ok(false);
            };
            let Ok(key) = envelope::open_envelope(self.group, oid, &envelope) else {
                return Ok(false);
            };
            // A key that does not open the document is not kept: it would stand in for the right one.
            if legix_crypt::object::check_key(&key, self.documents.objects().open(oid)?).is_err() {
                return Ok(false);
            }
            match self.documents.keys().put(oid, &key) {
                Ok(()) => {}
                Err(legix_crypt::Error::Erased(_)) => return Ok(false),
                Err(err) => return Err(err.into()),
            }
        }
        Ok(self.documents.status(oid)? == Status::Readable)
    }

    fn dir(&self) -> PathBuf {
        self.repo.git_dir().join("legix").join("sync")
    }

    fn state_path(&self) -> PathBuf {
        self.dir().join(format!("{}.state", self.device))
    }

    fn load(&self) -> Result<State, Error> {
        State::load(&self.state_path(), self.repo.object_hash())
    }

    /// Only one sync of a repository by a device runs at a time.
    fn lock(&self) -> Result<legix::lock::Marker, Error> {
        fs::create_dir_all(self.dir())?;
        legix::lock::Marker::acquire_to_hold_resource(self.state_path(), legix::lock::acquire::Fail::Immediately, None)
            .map_err(|_| Error::Locked)
    }

    /// A temporary file next to the repository, removed when it is dropped.
    fn temp(&self) -> Result<File, Error> {
        let dir = self.dir().join("tmp");
        fs::create_dir_all(&dir)?;
        Ok(tempfile::tempfile_in(dir)?)
    }
}

fn format_problem(err: &Error) -> Problem {
    match err {
        Error::Format(reason) => Problem::Format(reason),
        _ => Problem::Format("the head cannot be read"),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

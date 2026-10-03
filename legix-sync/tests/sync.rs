//! Devices that sync repositories through a relay in a directory. Repositories are made and checked with `git`.

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use legix_crypt::{DirKeyStore, Documents, KeyStore, ObjectStore, Oid, Pointer, Status, StoreKey};
use legix_sign::{Entry, Trust, ssh_key::PrivateKey};
use legix_sync::{
    Access, AllowedSigners, BundleId, DeviceId, DirRelay, Error, Fixed, GroupKey, Head, Problem, Pulled, Pushed, Relay,
    Replica, SignedHead, Wait,
};

/// `git` in `dir`, isolated from the system's and the user's configuration.
fn git_output(dir: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .args([
            "-c",
            "user.name=Ada",
            "-c",
            "user.email=ada@example.com",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", dir.join("no-global-config"))
        .env("HOME", dir)
        .stdin(Stdio::null())
        .output()
        .expect("git runs")
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = git_output(dir, args);
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

struct Device {
    repo: PathBuf,
    key: PrivateKey,
    documents: Documents<DirKeyStore>,
}

impl Device {
    fn new(root: &Path, name: &str) -> Self {
        git(root, &["init", "-q", name]);
        let repo = root.join(name);
        let git_dir = repo.join(".git");
        Device {
            key: legix_sign::generate_ed25519(&format!("{name}@example.com")).unwrap(),
            documents: Documents::new(
                ObjectStore::new(git_dir.join("legix/objects")),
                DirKeyStore::new(git_dir.join("legix/keys"), StoreKey::generate().unwrap()),
            ),
            repo,
        }
    }

    fn id(&self) -> DeviceId {
        DeviceId::of(self.key.public_key())
    }

    fn commit(&self, file: &str, content: &str, message: &str) -> String {
        fs::write(self.repo.join(file), content).unwrap();
        git(&self.repo, &["add", file]);
        git(&self.repo, &["commit", "-q", "-m", message]);
        git(&self.repo, &["rev-parse", "HEAD"])
    }

    fn with<A: Access, T>(
        &self,
        access: &A,
        relay: &DirRelay,
        f: impl FnOnce(&Replica<'_, DirRelay, A, DirKeyStore, PrivateKey>) -> T,
    ) -> T {
        let repo = legix::open_opts(&self.repo, legix::open::Options::isolated()).unwrap();
        f(&Replica::new(&repo, &self.key, access, relay, &self.documents))
    }

    fn push(&self, net: &Net) -> Pushed {
        self.with(&net.access(), &net.relay, |replica| replica.push().unwrap())
    }

    fn pull(&self, net: &Net) -> Pulled {
        self.with(&net.access(), &net.relay, |replica| replica.pull().unwrap())
    }

    fn pull_from(&self, net: &Net, relay: &DirRelay) -> Pulled {
        self.with(&net.access(), relay, |replica| replica.pull().unwrap())
    }

    fn erase(&self, net: &Net, oid: &Oid) {
        self.with(&net.access(), &net.relay, |replica| replica.erase(oid).unwrap());
    }

    /// Where this device keeps the branch or tag `name` (`heads/main`, `tags/v1`) of `other`, if it has it.
    fn of(&self, other: &Device, name: &str) -> Option<String> {
        let output = git_output(
            &self.repo,
            &[
                "rev-parse",
                "--verify",
                "-q",
                &format!("refs/legix/devices/{}/{name}", other.id()),
            ],
        );
        output
            .status
            .success()
            .then(|| String::from_utf8(output.stdout).unwrap().trim().to_owned())
    }

    fn fsck(&self) {
        git(&self.repo, &["fsck", "--strict", "--no-dangling"]);
    }
}

struct Net {
    root: PathBuf,
    relay: DirRelay,
    group: GroupKey,
    members: AllowedSigners,
    _dir: tempfile::TempDir,
}

impl Net {
    /// The group key and the members, as access for a replica.
    fn access(&self) -> Fixed {
        Fixed::new(self.group.clone(), self.members.clone())
    }
}

/// Devices with these names, all members, and a relay.
fn setup<const N: usize>(names: [&str; N]) -> (Net, [Device; N]) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_owned();
    let devices = names.map(|name| Device::new(&root, name));
    let mut members = AllowedSigners::default();
    for (name, device) in names.iter().zip(&devices) {
        members.push(format!("{name}@example.com"), device.key.public_key().clone());
    }
    let net = Net {
        relay: DirRelay::new(root.join("relay")),
        root,
        group: GroupKey::generate().unwrap(),
        members,
        _dir: dir,
    };
    (net, devices)
}

fn files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(self::files(&path));
        } else {
            files.push(path);
        }
    }
    files
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn head_path(net: &Net, device: &Device, seq: u64) -> PathBuf {
    net.root
        .join("relay/heads")
        .join(device.id().to_hex())
        .join(format!("{seq:020}"))
}

fn signed_head(net: &Net, device: &Device, seq: u64) -> SignedHead {
    SignedHead::parse(&net.relay.head(&device.id(), seq).unwrap().expect("the head is there")).unwrap()
}

#[test]
fn branches_reach_the_other_devices_and_only_new_objects_travel() {
    let (net, [ada, bo]) = setup(["ada", "bo"]);
    let first = ada.commit("terms.md", "Heads of terms\n", "Heads of terms");
    let pushed = ada.push(&net);
    assert_eq!(pushed.bundle.map(|(seq, _)| seq), Some(1));
    assert_eq!(pushed.objects, 3, "a commit, its tree and its blob");

    let pulled = bo.pull(&net);
    assert!(pulled.refused.is_empty() && pulled.waiting.is_empty(), "{pulled:?}");
    assert_eq!(pulled.applied.len(), 1);
    assert_eq!(pulled.applied[0].principals, "ada@example.com");
    assert_eq!(bo.of(&ada, "heads/main"), Some(first.clone()));
    bo.fsck();

    assert_eq!(ada.push(&net).bundle, None, "nothing new");
    assert!(bo.pull(&net).applied.is_empty(), "nothing new");

    let second = ada.commit("terms.md", "Heads of terms, revised\n", "Revise the terms");
    let pushed = ada.push(&net);
    assert_eq!(pushed.bundle.map(|(seq, _)| seq), Some(2));
    assert_eq!(pushed.objects, 3, "only the new commit, its tree and its blob");
    let pulled = bo.pull(&net);
    assert_eq!(pulled.applied.len(), 1);
    assert_eq!(pulled.applied[0].seq, 2);
    assert_eq!(bo.of(&ada, "heads/main"), Some(second));
    bo.fsck();
    assert_eq!(
        git(
            &bo.repo,
            &[
                "log",
                "--format=%s",
                &format!("refs/legix/devices/{}/heads/main", ada.id())
            ]
        ),
        "Revise the terms\nHeads of terms"
    );
}

#[test]
fn documents_travel_with_their_commits_and_their_erasure_reaches_every_device() {
    let (net, [ada, bo, cy]) = setup(["ada", "bo", "cy"]);
    let text = b"Settlement terms: 12,000 within 30 days";
    let pointer = ada.documents.add(&text[..]).unwrap();
    ada.commit("settlement.docx", &pointer.to_string(), "Settlement terms");
    let pushed = ada.push(&net);
    assert_eq!(pushed.documents, vec![(pointer.oid, true)]);
    assert!(net.relay.envelope(&pointer.oid).unwrap().is_some());
    assert!(net.relay.has_object(&pointer.oid).unwrap());

    let pulled = bo.pull(&net);
    assert_eq!(pulled.applied[0].documents, vec![pointer.oid]);
    let committed = git(
        &bo.repo,
        &[
            "show",
            &format!("refs/legix/devices/{}/heads/main:settlement.docx", ada.id()),
        ],
    );
    let committed = Pointer::parse(format!("{committed}\n").as_bytes()).unwrap();
    assert_eq!(bo.documents.read_to_vec(&committed).unwrap(), text);

    ada.erase(&net, &pointer.oid);
    assert!(net.relay.envelope(&pointer.oid).unwrap().is_none());
    assert!(!net.relay.has_object(&pointer.oid).unwrap());
    let pushed = ada.push(&net);
    assert_eq!(
        pushed.bundle.map(|(seq, _)| seq),
        Some(2),
        "the erasure alone makes a bundle"
    );
    assert_eq!(pushed.erased, vec![pointer.oid]);

    let pulled = bo.pull(&net);
    assert_eq!(pulled.applied[0].erased, vec![pointer.oid]);
    assert_eq!(bo.documents.status(&pointer.oid).unwrap(), Status::Erased);
    assert!(matches!(
        bo.documents.read_to_vec(&committed),
        Err(legix_crypt::Error::Erased(_))
    ));
    let key = legix_crypt::DocumentKey::generate().unwrap();
    assert!(matches!(
        bo.documents.keys().put(&pointer.oid, &key),
        Err(legix_crypt::Error::Erased(_))
    ));
    bo.fsck();

    // A device that pulls only now gets the history and never the document.
    let pulled = cy.pull(&net);
    assert_eq!(pulled.applied.len(), 2);
    assert_eq!(pulled.applied[0].unavailable, vec![pointer.oid]);
    assert_eq!(cy.documents.status(&pointer.oid).unwrap(), Status::Erased);
    assert!(cy.of(&ada, "heads/main").is_some());
}

#[test]
fn a_bundle_waits_for_the_bundles_it_builds_on() {
    let (net, [ada, bo, cy]) = setup(["ada", "bo", "cy"]);
    let first = ada.commit("terms.md", "Heads of terms\n", "Heads of terms");
    ada.push(&net);
    bo.pull(&net);
    git(
        &bo.repo,
        &[
            "checkout",
            "-q",
            "-b",
            "review",
            &format!("refs/legix/devices/{}/heads/main", ada.id()),
        ],
    );
    let second = bo.commit("notes.md", "Clause 4 needs a cap\n", "Review notes");
    let pushed = bo.push(&net);
    assert_eq!(pushed.objects, 3, "its commit, tree and blob: nothing of ada's");

    // A relay that has bo's bundle and not yet ada's.
    let partial = DirRelay::new(net.root.join("partial"));
    let copy = |device: &Device| {
        let head = signed_head(&net, device, 1);
        let mut body = net.relay.open_object(&head.head().body).unwrap().unwrap();
        partial.put_object(&head.head().body, &mut body).unwrap();
        partial.put_head(&device.id(), 1, head.as_bytes()).unwrap();
    };
    copy(&bo);
    let pulled = cy.pull_from(&net, &partial);
    assert!(pulled.applied.is_empty());
    assert_eq!(pulled.waiting.len(), 1);
    assert_eq!(pulled.waiting[0].device, bo.id());
    let first_id = legix::ObjectId::from_hex(first.as_bytes()).unwrap();
    assert_eq!(pulled.waiting[0].reason, Wait::Prerequisites(vec![first_id]));

    copy(&ada);
    let pulled = cy.pull_from(&net, &partial);
    assert_eq!(pulled.applied.len(), 2, "{pulled:?}");
    assert!(pulled.waiting.is_empty());
    assert_eq!(cy.of(&bo, "heads/review"), Some(second));
    assert_eq!(cy.of(&bo, "heads/main"), None, "bo has no main of its own");
    cy.fsck();
}

#[test]
fn a_merge_of_both_devices_work_goes_back() {
    let (net, [ada, bo]) = setup(["ada", "bo"]);
    ada.commit("terms.md", "Heads of terms\n", "Heads of terms");
    ada.push(&net);
    bo.pull(&net);
    git(
        &bo.repo,
        &[
            "reset",
            "-q",
            "--hard",
            &format!("refs/legix/devices/{}/heads/main", ada.id()),
        ],
    );
    bo.commit("notes.md", "Clause 4 needs a cap\n", "Review notes");
    bo.push(&net);
    ada.commit("terms.md", "Heads of terms, revised\n", "Revise the terms");
    ada.push(&net);

    bo.pull(&net);
    git(
        &bo.repo,
        &[
            "merge",
            "-q",
            "--no-edit",
            &format!("refs/legix/devices/{}/heads/main", ada.id()),
        ],
    );
    let merge = git(&bo.repo, &["rev-parse", "HEAD"]);
    bo.push(&net);

    let pulled = ada.pull(&net);
    assert!(pulled.refused.is_empty() && pulled.waiting.is_empty(), "{pulled:?}");
    assert_eq!(ada.of(&bo, "heads/main"), Some(merge.clone()));
    ada.fsck();
    git(&ada.repo, &["merge", "-q", "--ff-only", &merge]);
    assert_eq!(
        fs::read_to_string(ada.repo.join("notes.md")).unwrap(),
        "Clause 4 needs a cap\n"
    );
}

#[test]
fn deleted_branches_disappear_and_tags_travel() {
    let (net, [ada, bo]) = setup(["ada", "bo"]);
    ada.commit("terms.md", "Heads of terms\n", "Heads of terms");
    git(&ada.repo, &["branch", "draft"]);
    git(&ada.repo, &["tag", "-a", "v1", "-m", "Sent to the client"]);
    ada.push(&net);
    bo.pull(&net);
    assert!(bo.of(&ada, "heads/draft").is_some());
    let tag = bo.of(&ada, "tags/v1").unwrap();
    assert_eq!(git(&bo.repo, &["cat-file", "-t", &tag]), "tag");
    bo.fsck();

    git(&ada.repo, &["branch", "-D", "draft"]);
    ada.push(&net);
    bo.pull(&net);
    assert_eq!(bo.of(&ada, "heads/draft"), None);
    assert_eq!(bo.of(&ada, "tags/v1"), Some(tag));
}

#[test]
fn the_relay_holds_nothing_readable() {
    let (net, [ada]) = setup(["ada"]);
    let pointer = ada.documents.add(&b"Ada Example settles for 12,000"[..]).unwrap();
    ada.commit("settlement.docx", &pointer.to_string(), "Settlement with Bo Sample");
    ada.commit(
        "notes.md",
        "Bo Sample asked for a cap on clause 4\n",
        "Notes on the call",
    );
    ada.push(&net);
    let relay_files = files(&net.root.join("relay"));
    assert!(relay_files.len() >= 4, "a head, a body, a document and its envelope");
    for file in relay_files {
        let bytes = fs::read(&file).unwrap();
        for secret in [
            &b"Bo Sample"[..],
            b"Ada Example settles",
            b"refs/heads",
            b"settlement.docx",
            b"Notes on the call",
        ] {
            assert!(
                !contains(&bytes, secret),
                "{} holds {:?}",
                file.display(),
                String::from_utf8_lossy(secret)
            );
        }
    }
}

#[test]
fn bundles_of_devices_that_are_not_members_are_refused() {
    let (net, [ada, bo]) = setup(["ada", "bo"]);
    let mallory = Device::new(&net.root, "mallory");
    let mut with_mallory = net.members.clone();
    with_mallory.push("mallory@example.com", mallory.key.public_key().clone());
    mallory.commit("terms.md", "Other terms\n", "Other terms");
    let access = Fixed::new(net.group.clone(), with_mallory);
    mallory.with(&access, &net.relay, |replica| replica.push().unwrap());
    ada.commit("terms.md", "Heads of terms\n", "Heads of terms");
    ada.push(&net);

    let pulled = bo.pull(&net);
    assert_eq!(pulled.applied.len(), 1, "ada's bundle is applied");
    assert_eq!(pulled.refused.len(), 1);
    assert_eq!(pulled.refused[0].device, mallory.id());
    assert_eq!(pulled.refused[0].problem, Problem::Untrusted(Trust::UnknownKey));
    assert_eq!(bo.of(&mallory, "heads/main"), None);

    // A key the members allow only for commit signatures cannot publish bundles.
    let mut git_only = AllowedSigners::default();
    git_only.push_entry(Entry {
        namespaces: Some("git".into()),
        ..Entry::new("ada@example.com", ada.key.public_key().clone())
    });
    let cy = Device::new(&net.root, "cy");
    let access = Fixed::new(net.group.clone(), git_only);
    let pulled = cy.with(&access, &net.relay, |replica| replica.pull().unwrap());
    assert!(pulled.applied.is_empty());
    assert!(
        pulled
            .refused
            .iter()
            .any(|refused| refused.device == ada.id() && refused.problem == Problem::Untrusted(Trust::UnknownKey))
    );
}

#[test]
fn what_the_relay_alters_is_refused() {
    // The body.
    let (net, [ada, bo]) = setup(["ada", "bo"]);
    ada.commit("terms.md", "Heads of terms\n", "Heads of terms");
    ada.push(&net);
    let body = signed_head(&net, &ada, 1).head().body;
    let body_path = net
        .root
        .join("relay/objects")
        .join(&body.to_hex()[..2])
        .join(&body.to_hex()[2..]);
    let original = fs::read(&body_path).unwrap();
    let mut altered = original.clone();
    altered[100] ^= 1;
    fs::write(&body_path, &altered).unwrap();
    assert_eq!(bo.pull(&net).refused[0].problem, Problem::BodyMismatch);

    // The head.
    let (net, [ada, bo]) = setup(["ada", "bo"]);
    ada.commit("terms.md", "Heads of terms\n", "Heads of terms");
    ada.push(&net);
    let path = head_path(&net, &ada, 1);
    let head = fs::read_to_string(&path).unwrap();
    let time = signed_head(&net, &ada, 1).head().time;
    fs::write(
        &path,
        head.replace(&format!("time {time}"), &format!("time {}", time + 1)),
    )
    .unwrap();
    assert_eq!(
        bo.pull(&net).refused[0].problem,
        Problem::Signature(legix_sign::Status::Bad)
    );

    // A head moved to another place in the chain, or to another device.
    let (net, [ada, bo]) = setup(["ada", "bo"]);
    ada.commit("terms.md", "Heads of terms\n", "Heads of terms");
    ada.push(&net);
    let head = fs::read(head_path(&net, &ada, 1)).unwrap();
    fs::create_dir_all(head_path(&net, &bo, 1).parent().unwrap()).unwrap();
    fs::write(head_path(&net, &bo, 1), &head).unwrap();
    let pulled = ada.pull(&net);
    assert_eq!(pulled.refused[0].device, bo.id());
    assert_eq!(pulled.refused[0].problem, Problem::Misplaced);
}

#[test]
fn a_device_that_writes_two_histories_is_caught() {
    let (net, [ada, bo]) = setup(["ada", "bo"]);
    ada.commit("terms.md", "Heads of terms\n", "Heads of terms");
    ada.push(&net);
    ada.commit("terms.md", "Heads of terms, revised\n", "Revise the terms");
    ada.push(&net);
    bo.pull(&net);

    // Ada's key signs a third bundle that does not follow the second, and one dated before it.
    let second = signed_head(&net, &ada, 2);
    let forge = |prev: BundleId, time: u64| {
        let key = legix_crypt::DocumentKey::generate().unwrap();
        let head = Head {
            device: ada.id(),
            seq: 3,
            prev,
            time,
            epoch: 1,
            body: second.head().body,
            body_len: second.head().body_len,
            key: Head::wrap_key(&net.group, &ada.id(), 3, 1, &second.head().body, &key).unwrap(),
        };
        fs::write(head_path(&net, &ada, 3), head.sign(&ada.key).unwrap().as_bytes()).unwrap();
    };
    forge(BundleId::from_bytes([7; 32]), second.head().time);
    let pulled = bo.pull(&net);
    assert_eq!(pulled.refused[0].problem, Problem::Fork);
    assert!(pulled.applied.is_empty());

    forge(second.id(), second.head().time - 1);
    assert_eq!(bo.pull(&net).refused[0].problem, Problem::TimeGoesBack);
}

#[test]
fn another_group_key_opens_nothing() {
    let (net, [ada, bo]) = setup(["ada", "bo"]);
    ada.commit("terms.md", "Heads of terms\n", "Heads of terms");
    ada.push(&net);
    let outsider = Net {
        group: GroupKey::generate().unwrap(),
        members: net.members.clone(),
        relay: net.relay.clone(),
        root: net.root.clone(),
        _dir: tempfile::tempdir().unwrap(),
    };
    let pulled = bo.pull(&outsider);
    assert_eq!(pulled.refused[0].problem, Problem::GroupKey);
    assert_eq!(bo.of(&ada, "heads/main"), None);
}

#[test]
fn a_bundle_whose_body_has_not_arrived_waits() {
    let (net, [ada, bo]) = setup(["ada", "bo"]);
    ada.commit("terms.md", "Heads of terms\n", "Heads of terms");
    ada.push(&net);
    let body = signed_head(&net, &ada, 1).head().body;
    let mut bytes = Vec::new();
    net.relay
        .open_object(&body)
        .unwrap()
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    net.relay.remove_object(&body).unwrap();

    let pulled = bo.pull(&net);
    assert!(pulled.applied.is_empty());
    assert_eq!(pulled.waiting[0].reason, Wait::Body);

    net.relay.put_object(&body, &mut &bytes[..]).unwrap();
    assert_eq!(bo.pull(&net).applied.len(), 1);
}

#[test]
fn a_push_that_stopped_before_it_saved_is_taken_up() {
    let (net, [ada, bo]) = setup(["ada", "bo"]);
    ada.commit("terms.md", "Heads of terms\n", "Heads of terms");
    let first = ada.push(&net).bundle.unwrap();
    fs::remove_file(ada.repo.join(format!(".git/legix/sync/{}.state", ada.id()))).unwrap();

    ada.commit("terms.md", "Heads of terms, revised\n", "Revise the terms");
    let second = ada.push(&net).bundle.unwrap();
    assert_eq!(second.0, 2);
    assert_eq!(signed_head(&net, &ada, 2).head().prev, first.1);
    assert_eq!(bo.pull(&net).applied.len(), 2);
    bo.fsck();
}

#[test]
fn only_one_sync_of_a_repository_runs_at_a_time() {
    let (net, [ada]) = setup(["ada"]);
    let sync_dir = ada.repo.join(".git/legix/sync");
    fs::create_dir_all(&sync_dir).unwrap();
    let _held = legix::lock::Marker::acquire_to_hold_resource(
        sync_dir.join(format!("{}.state", ada.id())),
        legix::lock::acquire::Fail::Immediately,
        None,
    )
    .unwrap();
    let refused = ada.with(&net.access(), &net.relay, |replica| replica.pull().err());
    assert!(matches!(refused, Some(Error::Locked)));
}

#[test]
fn the_body_holds_a_git_bundle_that_git_reads() {
    let (net, [ada, bo]) = setup(["ada", "bo"]);
    ada.commit("terms.md", "Heads of terms\n", "Heads of terms");
    let main = ada.commit("terms.md", "Heads of terms, revised\n", "Revise the terms");
    ada.push(&net);

    let head = signed_head(&net, &ada, 1);
    let key = head.head().unwrap_key(&net.group).unwrap();
    let object = net.relay.open_object(&head.head().body).unwrap().unwrap();
    let mut plain = Vec::new();
    legix_crypt::object::open(&key, object, &mut plain).unwrap();
    let start = if plain.starts_with(b"\n") {
        1
    } else {
        plain.windows(2).position(|w| w == b"\n\n").unwrap() + 2
    };
    let bundle = net.root.join("ada.bundle");
    fs::write(&bundle, &plain[start..]).unwrap();

    let bundle = bundle.to_str().unwrap();
    assert_eq!(
        git(&net.root, &["bundle", "list-heads", bundle]),
        format!("{main} refs/heads/main")
    );
    git(&bo.repo, &["bundle", "verify", "-q", bundle]);
    git(&bo.repo, &["fetch", "-q", bundle, "main:from-the-bundle"]);
    assert_eq!(git(&bo.repo, &["rev-parse", "from-the-bundle"]), main);
    bo.fsck();
}

/// Bundle 2 of `device`, written with its key, whose body is the plaintext of bundle 1 changed by `change`.
fn republish(net: &Net, device: &Device, change: impl FnOnce(Vec<u8>) -> Vec<u8>) {
    let first = signed_head(net, device, 1);
    let key = first.head().unwrap_key(&net.group).unwrap();
    let object = net.relay.open_object(&first.head().body).unwrap().unwrap();
    let mut plain = Vec::new();
    legix_crypt::object::open(&key, object, &mut plain).unwrap();
    let plain = change(plain);

    let key = legix_crypt::DocumentKey::generate().unwrap();
    let mut body = Vec::new();
    let sealed = legix_crypt::object::seal(&key, &plain[..], &mut body).unwrap();
    net.relay.put_object(&sealed.oid, &mut &body[..]).unwrap();
    let head = Head {
        device: device.id(),
        seq: 2,
        prev: first.id(),
        time: first.head().time,
        epoch: 1,
        body: sealed.oid,
        body_len: body.len() as u64,
        key: Head::wrap_key(&net.group, &device.id(), 2, 1, &sealed.oid, &key).unwrap(),
    };
    net.relay
        .put_head(&device.id(), 2, head.sign(&device.key).unwrap().as_bytes())
        .unwrap();
}

fn replace(haystack: Vec<u8>, from: &[u8], to: &[u8]) -> Vec<u8> {
    let at = haystack.windows(from.len()).position(|w| w == from).expect("found");
    [&haystack[..at], to, &haystack[at + from.len()..]].concat()
}

#[test]
fn a_member_cannot_set_refs_other_than_branches_and_tags() {
    let (net, [ada, bo]) = setup(["ada", "bo"]);
    ada.commit("terms.md", "Heads of terms\n", "Heads of terms");
    ada.push(&net);
    republish(&net, &ada, |plain| {
        replace(plain, b" refs/heads/main\n", b" refs/notes/main\n")
    });
    let pulled = bo.pull(&net);
    assert_eq!(pulled.applied.len(), 1);
    assert_eq!(pulled.refused[0].problem, Problem::ForeignRef("refs/notes/main".into()));
    assert!(!git(&bo.repo, &["for-each-ref"]).contains("notes"));
}

#[test]
fn a_bundle_whose_pack_misses_objects_is_refused() {
    let (net, [ada, bo]) = setup(["ada", "bo"]);
    ada.commit("terms.md", "Heads of terms\n", "Heads of terms");
    ada.push(&net);
    let main = ada.commit("terms.md", "Heads of terms, revised\n", "Revise the terms");
    // Bundle 2 claims the new main, with a pack that holds nothing.
    republish(&net, &ada, |plain| {
        let first = git(&ada.repo, &["rev-parse", "HEAD~1"]);
        let plain = replace(
            plain,
            format!("{first} refs/heads/main").as_bytes(),
            format!("{main} refs/heads/main").as_bytes(),
        );
        let pack = plain.windows(4).position(|w| w == b"PACK").unwrap();
        [&plain[..pack], b"PACK\0\0\0\x02\0\0\0\0", &[0; 20]].concat()
    });
    let pulled = bo.pull(&net);
    assert_eq!(pulled.applied.len(), 1);
    let main = legix::ObjectId::from_hex(main.as_bytes()).unwrap();
    assert_eq!(pulled.refused[0].problem, Problem::Incomplete(main));
    assert_eq!(
        bo.of(&ada, "heads/main"),
        Some(git(&ada.repo, &["rev-parse", "HEAD~1"]))
    );
    bo.fsck();
}

#[test]
fn an_envelope_with_another_key_is_not_kept() {
    let (net, [ada, bo]) = setup(["ada", "bo"]);
    let pointer = ada.documents.add(&b"Heads of terms"[..]).unwrap();
    ada.commit("terms.docx", &pointer.to_string(), "Heads of terms");
    // An envelope that opens with the group key but holds another key gets to the relay first.
    let wrong = legix_crypt::DocumentKey::generate().unwrap();
    net.relay
        .put_envelope(
            &pointer.oid,
            &legix_sync::seal_envelope(&net.group, 1, &pointer.oid, &wrong).unwrap(),
        )
        .unwrap();
    ada.push(&net);

    let pulled = bo.pull(&net);
    assert_eq!(pulled.applied[0].unavailable, vec![pointer.oid]);
    assert!(matches!(
        bo.documents.keys().get(&pointer.oid).unwrap(),
        legix_crypt::KeyState::Missing
    ));
}

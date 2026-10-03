//! Sync that follows the membership: devices of a group sync repositories through a relay, and the group's log decides
//! who publishes and who reads.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use legix_crypt::{DirKeyStore, Documents, ObjectStore, Status, StoreKey};
use legix_members::{GroupId, Identity, JoinRequest, Members, Role, found};
use legix_sign::ssh_key::PrivateKey;
use legix_sync::{DeviceId, DirRelay, Problem, Pulled, Pushed, Relay, Replica};

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
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
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

struct Device {
    name: &'static str,
    repo: PathBuf,
    key: PrivateKey,
    identity: Identity,
    documents: Documents<DirKeyStore>,
}

struct Net {
    root: PathBuf,
    relay: DirRelay,
    group: GroupId,
    _dir: tempfile::TempDir,
}

impl Device {
    fn new(root: &Path, name: &'static str) -> Self {
        git(root, &["init", "-q", name]);
        let repo = root.join(name);
        let git_dir = repo.join(".git");
        Device {
            name,
            key: legix_sign::generate_ed25519(&format!("{name}@example.com")).unwrap(),
            identity: Identity::generate().unwrap(),
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

    fn request(&self) -> JoinRequest {
        JoinRequest::new(&self.key, &self.identity, &format!("{}@example.com", self.name)).unwrap()
    }

    fn members(&self, net: &Net) -> Members {
        let pin = self.repo.join(".git/legix/members.pin");
        Members::load(&net.relay, &net.group, &self.identity, &pin).unwrap()
    }

    fn commit(&self, file: &str, content: &str) -> String {
        fs::write(self.repo.join(file), content).unwrap();
        git(&self.repo, &["add", file]);
        git(&self.repo, &["commit", "-q", "-m", &format!("{file} by {}", self.name)]);
        git(&self.repo, &["rev-parse", "HEAD"])
    }

    fn push_with(&self, net: &Net, members: &Members) -> Result<Pushed, legix_sync::Error> {
        let repo = legix::open_opts(&self.repo, legix::open::Options::isolated()).unwrap();
        Replica::new(&repo, &self.key, members, &net.relay, &self.documents).push()
    }

    fn push(&self, net: &Net) -> Result<Pushed, legix_sync::Error> {
        self.push_with(net, &self.members(net))
    }

    fn pull(&self, net: &Net) -> Pulled {
        let members = self.members(net);
        let repo = legix::open_opts(&self.repo, legix::open::Options::isolated()).unwrap();
        Replica::new(&repo, &self.key, &members, &net.relay, &self.documents)
            .pull()
            .unwrap()
    }

    fn has(&self, other: &Device, commit: &str) -> bool {
        git(
            &self.repo,
            &["rev-parse", &format!("refs/legix/devices/{}/heads/main", other.id())],
        ) == commit
    }
}

/// A group that `founder` founds with `others`, and a relay.
fn group(root: &Path, founder: &Device, others: &[(&Device, Role)]) -> DirRelay {
    let relay = DirRelay::new(root.join("relay"));
    let requests: Vec<_> = others.iter().map(|(device, role)| (device.request(), *role)).collect();
    let first = found(
        &founder.key,
        &founder.identity,
        &format!("{}@example.com", founder.name),
        &requests,
    )
    .unwrap();
    relay.put_member_entry(1, first.as_bytes()).unwrap();
    relay
}

fn setup(names: [&'static str; 3]) -> (Net, [Device; 3]) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_owned();
    let devices = names.map(|name| Device::new(&root, name));
    let relay = group(
        &root,
        &devices[0],
        &[(&devices[1], Role::Writer), (&devices[2], Role::Writer)],
    );
    let group: GroupId = legix_members::Entry::parse(&relay.member_entry(1).unwrap().unwrap())
        .unwrap()
        .id()
        .into();
    (
        Net {
            root,
            relay,
            group,
            _dir: dir,
        },
        devices,
    )
}

fn publish(net: &Net, entry: &legix_members::Entry) {
    net.relay.put_member_entry(entry.seq(), entry.as_bytes()).unwrap();
}

#[test]
fn a_removed_device_reads_nothing_new_and_its_later_bundles_are_refused() {
    let (net, [ada, bo, cy]) = setup(["ada", "bo", "cy"]);
    let first = ada.commit("terms.md", "Heads of terms\n");
    ada.push(&net).unwrap();
    let cys = cy.commit("notes.md", "Clause 4 needs a cap\n");
    cy.push(&net).unwrap();
    assert_eq!(bo.pull(&net).applied.len(), 2);
    assert!(bo.has(&ada, &first) && bo.has(&cy, &cys));
    let before_removal = cy.members(&net);

    // Ada removes Cy, keeping Cy's bundle 1: the group moves to epoch 2.
    publish(
        &net,
        &ada.members(&net).change().remove(cy.id(), 1).sign(&ada.key).unwrap(),
    );
    let bos = bo.commit("draft.md", "Draft settlement\n");
    let pushed = bo.push(&net).unwrap();
    assert!(pushed.bundle.is_some());

    // Cy holds only the key of epoch 1, and cannot read Bo's bundle.
    let pulled = cy.pull(&net);
    assert_eq!(pulled.refused.len(), 1);
    assert_eq!(
        (pulled.refused[0].device, pulled.refused[0].problem.clone()),
        (bo.id(), Problem::NoKey(2))
    );
    assert!(
        !git(&cy.repo, &["for-each-ref"]).contains(&bo.id().to_hex()),
        "nothing of Bo's"
    );

    // Cy may not publish any more; a bundle it writes with what it knew before is refused by the others.
    assert!(matches!(
        cy.push(&net),
        Err(legix_sync::Error::NotAllowed(Problem::NotMember))
    ));
    cy.commit("notes.md", "Clause 4 needs no cap\n");
    let stale = cy.push_with(&net, &before_removal).unwrap();
    assert_eq!(stale.bundle.map(|(seq, _)| seq), Some(2));
    let pulled = ada.pull(&net);
    assert!(pulled.applied.iter().any(|applied| applied.device == bo.id()));
    assert_eq!(pulled.refused.len(), 1);
    assert_eq!(
        (
            pulled.refused[0].device,
            pulled.refused[0].seq,
            pulled.refused[0].problem.clone()
        ),
        (cy.id(), 2, Problem::PastCutoff { cutoff: 1 })
    );
    assert!(ada.has(&cy, &cys), "Cy's bundle 1 stays");
    assert!(ada.has(&bo, &bos));
}

#[test]
fn a_device_added_after_a_rotation_reads_the_whole_history_and_its_documents() {
    let (net, [ada, bo, cy]) = setup(["ada", "bo", "cy"]);
    let text = b"Settlement terms: 12,000 within 30 days";
    let pointer = ada.documents.add(&text[..]).unwrap();
    let first = ada.commit("settlement.docx", &pointer.to_string());
    ada.push(&net).unwrap();
    publish(
        &net,
        &ada.members(&net).change().remove(cy.id(), 0).sign(&ada.key).unwrap(),
    );
    let second = bo.commit("draft.md", "Draft\n");
    bo.push(&net).unwrap();

    let dee = Device::new(&net.root, "dee");
    publish(
        &net,
        &ada.members(&net)
            .change()
            .add(dee.request(), Role::Writer)
            .sign(&ada.key)
            .unwrap(),
    );
    let members = dee.members(&net);
    assert_eq!(members.epochs().collect::<Vec<_>>(), vec![1, 2]);
    let pulled = dee.pull(&net);
    assert!(pulled.refused.is_empty() && pulled.waiting.is_empty(), "{pulled:?}");
    assert!(dee.has(&ada, &first) && dee.has(&bo, &second));
    assert_eq!(dee.documents.status(&pointer.oid).unwrap(), Status::Readable);
    assert_eq!(dee.documents.read_to_vec(&pointer).unwrap(), text);
}

#[test]
fn a_reader_reads_and_cannot_publish() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_owned();
    let (ada, eve) = (Device::new(&root, "ada"), Device::new(&root, "eve"));
    let relay = group(&root, &ada, &[(&eve, Role::Reader)]);
    let group: GroupId = legix_members::Entry::parse(&relay.member_entry(1).unwrap().unwrap())
        .unwrap()
        .id()
        .into();
    let net = Net {
        root,
        relay,
        group,
        _dir: dir,
    };
    let first = ada.commit("terms.md", "Heads of terms\n");
    ada.push(&net).unwrap();
    assert_eq!(eve.pull(&net).applied.len(), 1);
    assert!(eve.has(&ada, &first));
    eve.commit("notes.md", "A reader's note\n");
    assert!(matches!(
        eve.push(&net),
        Err(legix_sync::Error::NotAllowed(Problem::PastCutoff { cutoff: 0 }))
    ));
}

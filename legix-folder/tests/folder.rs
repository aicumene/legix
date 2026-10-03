//! Folders of documents with a history, on one device and between devices that share a folder.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use legix_folder::{BroughtIn, Error, Folder, Keys, Role, Signed};

struct Device {
    name: &'static str,
    work: PathBuf,
    state: PathBuf,
}

impl Device {
    fn new(root: &Path, name: &'static str) -> Self {
        let work = root.join(name).join("Matter 2041");
        fs::create_dir_all(&work).unwrap();
        Device {
            name,
            work,
            state: root.join(name).join("history"),
        }
    }

    fn principal(&self) -> String {
        format!("{}@example.com", self.name)
    }

    fn write(&self, path: &str, content: &str) {
        let path = self.work.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }
}

fn read_all(dir: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_owned()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push((path.to_string_lossy().into_owned(), fs::read_to_string(&path).unwrap()));
            }
        }
    }
    files.sort();
    files
}

fn contents(dir: &Path) -> Vec<(String, String)> {
    read_all(dir)
        .into_iter()
        .map(|(path, content)| {
            (
                Path::new(&path)
                    .strip_prefix(dir)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                content,
            )
        })
        .collect()
}

#[test]
fn a_folder_keeps_signed_versions_and_restores_them() {
    let dir = tempfile::tempdir().unwrap();
    let ada = Device::new(dir.path(), "ada");
    ada.write("Heads of terms.docx", "Heads of terms\n");
    ada.write("Evidence/Invoice 17.pdf", "Invoice 17\n");
    ada.write(".DS_Store", "finder's own\n");
    ada.write("~$ads of terms.docx", "a lock file\n");
    let folder = Folder::found(&ada.state, &ada.work, Keys::generate("ada").unwrap(), &ada.principal()).unwrap();

    let first = folder
        .save("Heads of terms and the invoice")
        .unwrap()
        .expect("a first version");
    assert_eq!(
        first.documents, 2,
        "hidden files and Office's lock files are not documents"
    );
    assert_eq!(first.signed, Signed::ByMember);
    assert_eq!(first.principal.as_deref(), Some("ada@example.com"));
    assert_eq!(first.device, Some(folder.device()));
    assert!(folder.save("Nothing changed").unwrap().is_none());

    ada.write("Heads of terms.docx", "Heads of terms, revised\n");
    fs::remove_file(ada.work.join("Evidence/Invoice 17.pdf")).unwrap();
    let second = folder.save("Revised; the invoice went to the client").unwrap().unwrap();
    assert_eq!(second.documents, 1);

    let versions = folder.versions().unwrap();
    assert_eq!(
        versions.iter().map(|version| version.id).collect::<Vec<_>>(),
        [second.id, first.id]
    );
    assert_eq!(versions[1].message, "Heads of terms and the invoice");

    let restored = dir.path().join("restored-first");
    let outcome = folder.restore(&first.id, &restored).unwrap();
    assert_eq!(outcome.written.len(), 2);
    assert!(outcome.unavailable.is_empty());
    assert_eq!(
        contents(&restored),
        [
            ("Evidence/Invoice 17.pdf".to_owned(), "Invoice 17\n".to_owned()),
            ("Heads of terms.docx".to_owned(), "Heads of terms\n".to_owned()),
        ]
    );
    assert!(
        matches!(folder.restore(&first.id, &restored), Err(Error::NotEmpty(_))),
        "never over documents"
    );
    let opened = dir.path().join("opened-in-finder");
    fs::create_dir_all(&opened).unwrap();
    fs::write(opened.join(".DS_Store"), "finder's own\n").unwrap();
    assert_eq!(
        folder.restore(&first.id, &opened).unwrap().written.len(),
        2,
        "what the system leaves in a folder is no document"
    );
    assert_eq!(fs::read_to_string(opened.join(".DS_Store")).unwrap(), "finder's own\n");

    // The history holds pointers, never a document.
    let objects = Command::new("git")
        .args([
            "--git-dir",
            ada.state.join("repo").to_str().unwrap(),
            "cat-file",
            "--batch-all-objects",
            "--batch",
        ])
        .output()
        .unwrap();
    assert!(objects.status.success());
    let objects = String::from_utf8_lossy(&objects.stdout);
    assert!(objects.contains("version legix-crypt/1"));
    assert!(!objects.contains("Heads of terms, revised") && !objects.contains("Invoice 17\n"));
    let verify = Command::new("git")
        .args([
            "--git-dir",
            ada.state.join("repo").to_str().unwrap(),
            "log",
            "--format=%G? %s",
            "refs/heads/main",
        ])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&verify.stdout).contains("Revised; the invoice went to the client"));
}

#[test]
fn devices_share_their_versions_through_a_shared_folder() {
    let dir = tempfile::tempdir().unwrap();
    let shared = dir.path().join("Shared");
    fs::create_dir_all(&shared).unwrap();
    let (ada, bo) = (Device::new(dir.path(), "ada"), Device::new(dir.path(), "bo"));
    ada.write("Heads of terms.docx", "Heads of terms\n");
    let mut adas = Folder::found(&ada.state, &ada.work, Keys::generate("ada").unwrap(), &ada.principal()).unwrap();
    adas.set_relay(Some(shared.clone())).unwrap();
    let first = adas.save("Heads of terms").unwrap().unwrap();
    assert_eq!(adas.sync().unwrap().published, Some(1));

    // Bo asks to join; until Ada adds Bo, Bo learns only the group's log.
    let (bos, request) = Folder::join(
        &bo.state,
        &bo.work,
        Keys::generate("bo").unwrap(),
        &bo.principal(),
        adas.settings().group,
        &shared,
    )
    .unwrap();
    let synced = bos.sync().unwrap();
    assert!(!synced.member);
    assert!(bos.versions().unwrap().is_empty());

    let requests = adas.requests().unwrap();
    assert_eq!(requests, vec![request.clone()]);
    assert_eq!(
        requests[0].fingerprint(),
        bos.fingerprint(),
        "what Ada compares with what Bo's device shows"
    );
    adas.admit(&requests[0], Role::Writer).unwrap();
    assert!(adas.requests().unwrap().is_empty());

    let synced = bos.sync().unwrap();
    assert!(synced.member);
    assert_eq!(synced.applied, vec![adas.device()]);
    let versions = bos.versions().unwrap();
    assert_eq!(versions.len(), 1);
    assert_eq!((versions[0].id, versions[0].signed), (first.id, Signed::ByMember));
    assert_eq!(versions[0].principal.as_deref(), Some("ada@example.com"));
    let restored = dir.path().join("bo-restored");
    assert_eq!(
        bos.restore(&first.id, &restored).unwrap().written,
        ["Heads of terms.docx"]
    );
    assert_eq!(
        fs::read_to_string(restored.join("Heads of terms.docx")).unwrap(),
        "Heads of terms\n"
    );

    // Bo's own version goes back.
    bo.write("Review notes.md", "Clause 4 needs a cap\n");
    let bos_version = bos.save("Review notes").unwrap().unwrap();
    assert_eq!(bos.sync().unwrap().published, Some(1));
    let synced = adas.sync().unwrap();
    assert_eq!(synced.applied, vec![bos.device()]);
    let versions = adas.versions().unwrap();
    assert_eq!(versions.len(), 2);
    assert!(
        versions
            .iter()
            .any(|version| version.id == bos_version.id && version.principal.as_deref() == Some("bo@example.com"))
    );

    // Nothing in the shared folder is readable.
    for (path, _) in read_all_bytes(&shared) {
        let bytes = fs::read(&path).unwrap();
        for secret in [&b"Heads of terms\n"[..], b"Clause 4 needs a cap", b"Review notes.md"] {
            assert!(
                !bytes.windows(secret.len()).any(|w| w == secret),
                "{path} holds a document"
            );
        }
    }
}

fn read_all_bytes(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_owned()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push((path.to_string_lossy().into_owned(), fs::read(&path).unwrap()));
            }
        }
    }
    files
}

/// Ada and Bo, Bo added as a writer, both synced once.
fn two_devices(root: &Path) -> (Device, Folder, Device, Folder) {
    let shared = root.join("Shared");
    fs::create_dir_all(&shared).unwrap();
    let (ada, bo) = (Device::new(root, "ada"), Device::new(root, "bo"));
    ada.write("Heads of terms.docx", "Heads of terms\n");
    let mut adas = Folder::found(&ada.state, &ada.work, Keys::generate("ada").unwrap(), &ada.principal()).unwrap();
    adas.set_relay(Some(shared.clone())).unwrap();
    adas.save("Heads of terms").unwrap();
    let (bos, request) = Folder::join(
        &bo.state,
        &bo.work,
        Keys::generate("bo").unwrap(),
        &bo.principal(),
        adas.settings().group,
        &shared,
    )
    .unwrap();
    adas.sync().unwrap();
    adas.admit(&request, Role::Writer).unwrap();
    bos.sync().unwrap();
    (ada, adas, bo, bos)
}

#[test]
fn a_removed_device_gets_nothing_new() {
    let dir = tempfile::tempdir().unwrap();
    let (ada, adas, _bo, bos) = two_devices(dir.path());
    assert_eq!(bos.versions().unwrap().len(), 1);
    adas.remove(&bos.device()).unwrap();
    ada.write("Settlement.docx", "Settlement terms\n");
    let after = adas.save("Settlement").unwrap().unwrap();
    adas.sync().unwrap();

    let synced = bos.sync().unwrap();
    assert!(!synced.member);
    assert!(bos.versions().unwrap().iter().all(|version| version.id != after.id));
    let members = adas.members().unwrap();
    assert!(members.roster().former().contains_key(&bos.device()));
}

#[test]
fn only_admins_change_the_membership() {
    let dir = tempfile::tempdir().unwrap();
    let (_ada, adas, _bo, bos) = two_devices(dir.path());
    let cy = Device::new(dir.path(), "cy");
    let (_cys, request) = Folder::join(
        &cy.state,
        &cy.work,
        Keys::generate("cy").unwrap(),
        &cy.principal(),
        adas.settings().group,
        bos.settings().relay.clone().unwrap(),
    )
    .unwrap();
    assert!(matches!(
        bos.admit(&request, Role::Reader),
        Err(Error::Members(legix_members::Error::Rule {
            rule: legix_members::Rule::NotAdmin,
            ..
        }))
    ));
    assert!(matches!(bos.remove(&adas.device()), Err(Error::Members(_))));
    adas.admit(&request, Role::Reader).unwrap();
}

#[test]
fn a_version_cannot_write_outside_the_folder_it_is_restored_into() {
    use legix::objs::{Tree, tree};
    use legix_sign::repository::RepositoryExt;

    let dir = tempfile::tempdir().unwrap();
    let ada = Device::new(dir.path(), "ada");
    ada.write("Heads of terms.docx", "Heads of terms\n");
    let keys = Keys::generate("ada").unwrap();
    let signing = keys.signing.clone();
    let folder = Folder::found(&ada.state, &ada.work, keys, &ada.principal()).unwrap();
    let first = folder.save("Heads of terms").unwrap().unwrap();

    // A version written around the folder: its tree names `..` and `.`, which would lead outside.
    let repo = legix::open_opts(
        ada.state.join("repo"),
        legix::open::Options::isolated().config_overrides(["user.name=ada", "user.email=ada"]),
    )
    .unwrap();
    let real = repo.find_commit(first.id).unwrap().tree_id().unwrap().detach();
    let blob = repo
        .find_tree(real)
        .unwrap()
        .iter()
        .next()
        .unwrap()
        .unwrap()
        .oid()
        .to_owned();
    let entry = |name: &str, mode: tree::EntryKind, oid| tree::Entry {
        mode: mode.into(),
        filename: name.into(),
        oid,
    };
    let inner = repo
        .write_object(Tree {
            entries: vec![entry("escaped.docx", tree::EntryKind::Blob, blob)],
        })
        .unwrap()
        .detach();
    let mut entries = vec![
        entry("..", tree::EntryKind::Tree, inner),
        entry(".", tree::EntryKind::Tree, inner),
        entry("Heads of terms.docx", tree::EntryKind::Blob, blob),
    ];
    entries.sort();
    let tree = repo.write_object(Tree { entries }).unwrap().detach();
    let forged = repo
        .commit_signed("refs/heads/main", "Around the folder", tree, [first.id], &signing)
        .unwrap();

    let into = dir.path().join("restored").join("here");
    let restored = folder.restore(&forged, &into).unwrap();
    assert_eq!(restored.written, ["Heads of terms.docx"]);
    assert!(!dir.path().join("restored").join("escaped.docx").exists());
    assert!(!into.join("escaped.docx").exists());

    // Nor anything that is no document: a version holds what `save` takes, whoever wrote it.
    let hooks = repo
        .write_object(Tree {
            entries: vec![entry("post-checkout", tree::EntryKind::Blob, blob)],
        })
        .unwrap()
        .detach();
    let git = repo
        .write_object(Tree {
            entries: vec![entry("hooks", tree::EntryKind::Tree, hooks)],
        })
        .unwrap()
        .detach();
    let mut entries = vec![
        entry(".DS_Store", tree::EntryKind::Blob, blob),
        entry(".git", tree::EntryKind::Tree, git),
        entry("Heads of terms.docx", tree::EntryKind::Blob, blob),
    ];
    entries.sort();
    let tree = repo.write_object(Tree { entries }).unwrap().detach();
    let hidden = repo
        .commit_signed("refs/heads/main", "Hidden files", tree, [forged], &signing)
        .unwrap();
    let opened = dir.path().join("opened");
    fs::create_dir_all(opened.join(".git")).unwrap();
    fs::write(opened.join(".DS_Store"), "finder's own\n").unwrap();
    let restored = folder.restore(&hidden, &opened).unwrap();
    assert_eq!(restored.written, ["Heads of terms.docx"]);
    assert_eq!(fs::read_to_string(opened.join(".DS_Store")).unwrap(), "finder's own\n");
    assert!(!opened.join(".git").join("hooks").exists());

    // And never over a file: of two names a case-insensitive disk takes for one, the first written stays.
    ada.write("Invoice 17.pdf", "Invoice 17\n");
    let second = folder.save("The invoice").unwrap().unwrap();
    let second_tree = repo.find_commit(second.id).unwrap().tree_id().unwrap().detach();
    let invoice = repo
        .find_tree(second_tree)
        .unwrap()
        .iter()
        .map(Result::unwrap)
        .find(|entry| entry.filename() == "Invoice 17.pdf")
        .unwrap()
        .oid()
        .to_owned();
    let mut entries = vec![
        entry("HEADS OF TERMS.docx", tree::EntryKind::Blob, invoice),
        entry("Heads of terms.docx", tree::EntryKind::Blob, blob),
    ];
    entries.sort();
    let tree = repo.write_object(Tree { entries }).unwrap().detach();
    let twice = repo
        .commit_signed("refs/heads/main", "One name twice", tree, [second.id], &signing)
        .unwrap();
    let into = dir.path().join("twice");
    let _ = folder.restore(&twice, &into);
    assert_eq!(
        fs::read_to_string(into.join("HEADS OF TERMS.docx")).unwrap(),
        "Invoice 17\n"
    );
}

#[test]
fn keys_keep_as_one_secret() {
    let dir = tempfile::tempdir().unwrap();
    let ada = Device::new(dir.path(), "ada");
    ada.write("Heads of terms.docx", "Heads of terms\n");
    let keys = Keys::generate("ada").unwrap();
    let secret = keys.to_secret().unwrap();
    assert!(secret.starts_with("legix-folder-keys/1\nidentity "));
    let folder = Folder::found(&ada.state, &ada.work, keys, &ada.principal()).unwrap();
    let version = folder.save("Heads of terms").unwrap().unwrap();
    let device = folder.device();
    drop(folder);

    // The keys from the keychain open the folder, read its documents and sign as the same device.
    let folder = Folder::open(&ada.state, Keys::from_secret(&secret).unwrap()).unwrap();
    assert_eq!(folder.device(), device);
    let restored = dir.path().join("restored");
    assert_eq!(
        folder.restore(&version.id, &restored).unwrap().written,
        ["Heads of terms.docx"]
    );
    ada.write("Heads of terms.docx", "Heads of terms, revised\n");
    let next = folder.save("Revised").unwrap().unwrap();
    assert_eq!((next.signed, next.device), (Signed::ByMember, Some(device)));

    for damaged in [
        secret.replacen("legix-folder-keys/1", "legix-folder-keys/2", 1),
        secret.replacen("identity ", "identity +", 1),
        secret.replacen("store ", "store x", 1),
        secret.lines().take(3).collect::<Vec<_>>().join("\n"),
        String::new(),
    ] {
        assert!(Keys::from_secret(&damaged).is_err(), "{damaged:?}");
    }
}

#[test]
fn a_shared_folder_that_is_not_connected_is_never_made_anew() {
    let dir = tempfile::tempdir().unwrap();
    let shared = dir.path().join("Shared");
    fs::create_dir_all(&shared).unwrap();
    let ada = Device::new(dir.path(), "ada");
    ada.write("Heads of terms.docx", "Heads of terms\n");
    let mut folder = Folder::found(&ada.state, &ada.work, Keys::generate("ada").unwrap(), &ada.principal()).unwrap();
    folder.set_relay(Some(shared.clone())).unwrap();
    folder.save("Heads of terms").unwrap();
    folder.sync().unwrap();

    let away = dir.path().join("Shared, not connected");
    fs::rename(&shared, &away).unwrap();
    assert!(matches!(folder.sync(), Err(Error::RelayMissing(_))));
    assert!(!shared.exists(), "nothing is left where the shared folder was");
    assert!(
        folder.requests().unwrap().is_empty(),
        "the requests this device has seen"
    );
    let bo = Device::new(dir.path(), "bo");
    assert!(matches!(
        Folder::join(
            &bo.state,
            &bo.work,
            Keys::generate("bo").unwrap(),
            &bo.principal(),
            folder.settings().group,
            &shared
        ),
        Err(Error::RelayMissing(_))
    ));
    assert!(!bo.state.exists());

    assert!(matches!(
        folder.set_relay(Some(shared.clone())),
        Err(Error::RelayMissing(_))
    ));

    fs::rename(&away, &shared).unwrap();
    assert_eq!(folder.sync().unwrap().published, None, "nothing new since");
}

#[test]
fn devices_bring_in_each_others_changes() {
    let dir = tempfile::tempdir().unwrap();
    let (ada, adas, bo, bos) = two_devices(dir.path());
    ada.write("Notes.md", "alpha\nbeta\ngamma\n");
    ada.write("Old memo.txt", "An old memo\n");
    ada.write("Timetable.docx", "Timetable\n");
    ada.write("Clauses.docx", "Clauses\n");
    adas.save("Notes and a memo").unwrap();
    adas.sync().unwrap();
    bos.sync().unwrap();

    // Bo's empty folder moves forward to Ada's version: no version of its own.
    let incoming = bos.incoming().unwrap();
    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].principal.as_deref(), Some("ada@example.com"));
    let first = bos.bring_in(&incoming[0].id, "Ada's notes").unwrap();
    assert_eq!(
        first.updated,
        [
            "Clauses.docx",
            "Heads of terms.docx",
            "Notes.md",
            "Old memo.txt",
            "Timetable.docx"
        ]
    );
    assert_eq!(first.version.unwrap().id, incoming[0].id, "forward, no new version");
    assert_eq!(contents(&bo.work), contents(&ada.work));
    assert!(bos.incoming().unwrap().is_empty() && bos.changes().unwrap().is_empty());
    assert_eq!(bos.bring_in(&incoming[0].id, "again").unwrap(), BroughtIn::default());

    // Both change the folder, apart.
    ada.write("Heads of terms.docx", "Heads of terms, Ada's revision\n");
    ada.write("Notes.md", "ALPHA\nbeta\ngamma\n");
    fs::remove_file(ada.work.join("Old memo.txt")).unwrap();
    ada.write("Timetable.docx", "Timetable, Ada's dates\n");
    fs::remove_file(ada.work.join("Clauses.docx")).unwrap();
    adas.save("Ada's revision").unwrap();
    adas.sync().unwrap();
    bo.write("Heads of terms.docx", "Heads of terms, Bo's revision\n");
    bo.write("Notes.md", "alpha\nbeta\nGAMMA\n");
    bo.write("Review.md", "Clause 4 needs a cap\n");
    fs::remove_file(bo.work.join("Timetable.docx")).unwrap();
    bo.write("Clauses.docx", "Clauses, Bo's cap\n");
    assert_eq!(
        bos.changes().unwrap(),
        [
            "Clauses.docx",
            "Heads of terms.docx",
            "Notes.md",
            "Review.md",
            "Timetable.docx"
        ]
    );
    bos.sync().unwrap();
    let incoming = bos.incoming().unwrap();
    assert_eq!(incoming.len(), 1);
    assert!(matches!(
        bos.bring_in(&incoming[0].id, "Ada's revision"),
        Err(Error::Unsaved)
    ));
    bos.save("Bo's revision").unwrap();
    let brought = bos.bring_in(&incoming[0].id, "Ada's revision").unwrap();
    assert_eq!(brought.removed, ["Old memo.txt"]);
    assert_eq!(brought.merged, ["Notes.md"]);
    assert_eq!(
        brought.conflicts,
        [(
            "Heads of terms.docx".to_owned(),
            "Heads of terms (ada@example.com).docx".to_owned()
        )]
    );
    assert_eq!(
        brought.updated,
        ["Timetable.docx"],
        "changed there wins over removed here"
    );
    let read = |name: &str| fs::read_to_string(bo.work.join(name)).unwrap();
    assert_eq!(read("Timetable.docx"), "Timetable, Ada's dates\n");
    assert_eq!(
        read("Clauses.docx"),
        "Clauses, Bo's cap\n",
        "changed here wins over removed there"
    );
    assert_eq!(read("Notes.md"), "ALPHA\nbeta\nGAMMA\n");
    assert_eq!(read("Heads of terms.docx"), "Heads of terms, Bo's revision\n");
    assert_eq!(
        read("Heads of terms (ada@example.com).docx"),
        "Heads of terms, Ada's revision\n"
    );
    assert_eq!(read("Review.md"), "Clause 4 needs a cap\n");
    assert!(!bo.work.join("Old memo.txt").exists());
    let merge = brought.version.unwrap();
    assert_eq!(merge.signed, Signed::ByMember);
    assert_eq!(merge.principal.as_deref(), Some("bo@example.com"));
    assert!(bos.changes().unwrap().is_empty(), "the folder is as its new version");
    assert!(bos.save("Nothing").unwrap().is_none());

    // Bo's version holds Ada's: Ada's folder moves forward to it, and both end the same.
    bos.sync().unwrap();
    adas.sync().unwrap();
    let incoming = adas.incoming().unwrap();
    assert_eq!(incoming.iter().map(|v| v.id).collect::<Vec<_>>(), [merge.id]);
    let back = adas.bring_in(&merge.id, "Bo's merge").unwrap();
    assert_eq!(back.version.unwrap().id, merge.id, "forward");
    assert_eq!(contents(&ada.work), contents(&bo.work));
    adas.sync().unwrap();
    bos.sync().unwrap();
    assert!(adas.incoming().unwrap().is_empty());
    assert!(bos.incoming().unwrap().is_empty(), "the two have met");
}

#[test]
fn the_same_document_saved_on_both_sides_is_no_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let (ada, adas, bo, bos) = two_devices(dir.path());
    bo.write("Agenda.md", "1. Price\n2. Timetable\n");
    ada.write("Agenda.md", "1. Price\n2. Timetable\n");
    bos.save("Bo's agenda").unwrap();
    adas.save("Ada's agenda").unwrap();
    adas.sync().unwrap();
    bos.sync().unwrap();
    let incoming = bos.incoming().unwrap();
    let brought = bos.bring_in(&incoming[0].id, "Ada's agenda").unwrap();
    assert!(brought.conflicts.is_empty(), "{brought:?}");
    assert_eq!(brought.updated, ["Heads of terms.docx"]);
    assert!(!bo.work.join("Agenda (ada@example.com).md").exists());
}

#[test]
fn nothing_is_written_while_a_document_cannot_be_read() {
    let dir = tempfile::tempdir().unwrap();
    let (ada, adas, bo, bos) = two_devices(dir.path());
    ada.write("Notes.md", "Notes\n");
    adas.save("Notes").unwrap();
    adas.sync().unwrap();
    bos.sync().unwrap();
    // The documents have not reached Bo's device.
    fs::remove_dir_all(bo.state.join("objects")).unwrap();
    let incoming = bos.incoming().unwrap();
    match bos.bring_in(&incoming[0].id, "Ada's notes") {
        Err(Error::Unreadable(paths)) => assert_eq!(paths, ["Heads of terms.docx", "Notes.md"]),
        other => panic!("{other:?}"),
    }
    assert!(contents(&bo.work).is_empty(), "nothing written");
    assert!(bos.incoming().unwrap().len() == 1, "still to bring in");
}

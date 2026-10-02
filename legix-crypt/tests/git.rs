//! With git: the repository holds the pointer and never the document, and erasing the document leaves the history,
//! its ids and its integrity as they were. Needs `git`.

use std::{
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

use legix_crypt::{DirKeyStore, Documents, Error, ObjectStore, Pointer, Status, StoreKey};

const DOCUMENT: &[u8] = b"Settlement terms between Ada Example and Bo Sample: 12,000 within 30 days.";

/// `git` in `dir`, isolated from the system's and the user's configuration.
fn git(dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut child = Command::new("git")
        .args(["-c", "user.name=Ada", "-c", "user.email=ada@example.com"])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", dir.join("no-global-config"))
        .env("HOME", dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("git runs");
    if let Some(input) = stdin {
        child.stdin.take().unwrap().write_all(input).unwrap();
    }
    child.wait_with_output().unwrap()
}

fn ok(output: Output) -> Vec<u8> {
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    output.stdout
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn erasing_a_document_leaves_the_history_as_it_was() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    ok(git(dir.path(), &["init", "-q", "-b", "main", "repo"], None));
    let documents = Documents::new(
        ObjectStore::new(dir.path().join("crypt/objects")),
        DirKeyStore::new(dir.path().join("crypt/keys"), StoreKey::generate().unwrap()),
    );

    let pointer = documents.add(DOCUMENT).unwrap();
    std::fs::write(repo.join("terms.docx"), pointer.to_string()).unwrap();
    ok(git(&repo, &["add", "terms.docx"], None));
    ok(git(&repo, &["commit", "-q", "-m", "Settlement terms"], None));
    let head = ok(git(&repo, &["rev-parse", "HEAD"], None));

    // Every object in the repository, decompressed: the pointer is there, the document is not.
    let objects = ok(git(&repo, &["cat-file", "--batch-all-objects", "--batch"], None));
    assert!(contains(&objects, pointer.to_string().as_bytes()));
    assert!(!contains(&objects, b"Settlement terms between"));
    // Nor is it in the clear in the object store.
    let stored = std::fs::read(documents.objects().path(&pointer.oid)).unwrap();
    assert!(!contains(&stored, b"Settlement terms between"));

    let committed = Pointer::parse(&ok(git(&repo, &["show", "HEAD:terms.docx"], None))).unwrap();
    assert_eq!(committed, pointer);
    assert_eq!(documents.read_to_vec(&committed).unwrap(), DOCUMENT);

    documents.erase(&committed.oid).unwrap();

    assert_eq!(
        ok(git(&repo, &["rev-parse", "HEAD"], None)),
        head,
        "the history is not rewritten"
    );
    ok(git(&repo, &["fsck", "--strict", "--no-dangling"], None));
    let committed = Pointer::parse(&ok(git(&repo, &["show", "HEAD:terms.docx"], None))).unwrap();
    assert_eq!(documents.status(&committed.oid).unwrap(), Status::Erased);
    assert!(matches!(documents.read_to_vec(&committed), Err(Error::Erased(_))));
    assert!(!documents.objects().contains(&committed.oid).unwrap());
}

//! Interoperability with git and `ssh-keygen`: signatures made here verify with `git verify-commit`, and
//! signatures made by `git commit -S` verify here. Needs `git` 2.34 or newer and OpenSSH's `ssh-keygen`.

use std::{
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

use bstr::ByteSlice;
use legix_sign::{AllowedSigners, ObjectFormat, ssh_key::LineEnding};

const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

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

fn ok(output: Output) -> String {
    assert!(output.status.success(), "{}", output.stderr.as_bstr());
    output.stdout.to_str().unwrap().trim().to_owned()
}

/// A repository and a key for ada@example.com, with an allowed-signers file listing it.
struct Setup {
    _dir: tempfile::TempDir,
    repo: std::path::PathBuf,
    key: legix_sign::ssh_key::PrivateKey,
    signers: AllowedSigners,
    allowed_signers_file: String,
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    ok(git(dir.path(), &["init", "-q", "-b", "main", "repo"], None));
    let key = legix_sign::generate_ed25519("ada@example.com").unwrap();
    let mut signers = AllowedSigners::default();
    signers.push("ada@example.com", key.public_key().clone());
    let allowed_signers_file = dir.path().join("allowed_signers");
    std::fs::write(&allowed_signers_file, signers.to_string()).unwrap();
    Setup {
        _dir: dir,
        repo,
        key,
        signers,
        allowed_signers_file: allowed_signers_file.to_str().unwrap().to_owned(),
    }
}

fn git_verifies(setup: &Setup, commit: &str) -> String {
    let output = git(
        &setup.repo,
        &[
            "-c",
            &format!("gpg.ssh.allowedSignersFile={}", setup.allowed_signers_file),
            "verify-commit",
            commit,
        ],
        None,
    );
    let stderr = output.stderr.to_str().unwrap().to_owned();
    assert!(output.status.success(), "git verify-commit failed: {stderr}");
    stderr
}

#[test]
fn a_commit_signed_here_verifies_with_git() {
    let setup = setup();
    assert_eq!(ok(git(&setup.repo, &["hash-object", "-t", "tree", "-w", "--stdin"], Some(b""))), EMPTY_TREE);
    let commit = format!(
        "tree {EMPTY_TREE}\nauthor Ada <ada@example.com> 1759400000 +0000\n\
         committer Ada <ada@example.com> 1759400000 +0000\n\nSigned by legix\n"
    );
    let signed = legix_sign::sign_commit(commit.as_bytes(), ObjectFormat::Sha1, &setup.key).unwrap();
    let id = ok(git(&setup.repo, &["hash-object", "-t", "commit", "-w", "--stdin"], Some(&signed)));
    assert_eq!(
        git(&setup.repo, &["cat-file", "commit", &id], None).stdout,
        signed,
        "stored as signed"
    );

    let report = git_verifies(&setup, &id);
    let fingerprint = setup.key.public_key().fingerprint(Default::default()).to_string();
    assert!(
        report.contains(&format!(
            "Good \"git\" signature for ada@example.com with ED25519 key {fingerprint}"
        )),
        "{report}"
    );
}

#[test]
fn a_commit_signed_by_git_verifies_here() {
    let setup = setup();
    let key_file = setup.repo.join("../signing-key");
    std::fs::write(&key_file, setup.key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    ok(git(
        &setup.repo,
        &[
            "-c",
            "gpg.format=ssh",
            "-c",
            &format!("user.signingKey={}", key_file.to_str().unwrap()),
            "commit",
            "-q",
            "-S",
            "--allow-empty",
            "-m",
            "Signed by git",
        ],
        None,
    ));
    let commit = git(&setup.repo, &["cat-file", "commit", "HEAD"], None).stdout;
    let outcome = legix_sign::verify_commit(&commit, ObjectFormat::Sha1, &setup.signers)
        .unwrap()
        .expect("git signed it");
    assert!(outcome.is_trusted(), "{outcome:?}");

    let altered = commit.replace("Signed by git", "Signed by someone else");
    let outcome = legix_sign::verify_commit(&altered, ObjectFormat::Sha1, &setup.signers)
        .unwrap()
        .unwrap();
    assert_eq!(outcome.status, legix_sign::Status::Bad);
}

#[cfg(feature = "repository")]
#[test]
fn a_repository_commit_signed_here_verifies_with_git_and_here() {
    use legix_sign::repository::RepositoryExt;

    let setup = setup();
    ok(git(&setup.repo, &["config", "user.name", "Ada"], None));
    ok(git(&setup.repo, &["config", "user.email", "ada@example.com"], None));
    let repo = legix::open_opts(&setup.repo, legix::open::Options::isolated()).unwrap();
    let tree = repo.empty_tree().id;
    let first = repo
        .commit_signed("HEAD", "First signed commit", tree, Vec::<legix::ObjectId>::new(), &setup.key)
        .unwrap();
    let second = repo
        .commit_signed("HEAD", "Second signed commit", tree, [first], &setup.key)
        .unwrap();

    assert_eq!(ok(git(&setup.repo, &["rev-parse", "main"], None)), second.to_string());
    git_verifies(&setup, "HEAD");
    git_verifies(&setup, "HEAD~1");
    let reflog = ok(git(&setup.repo, &["reflog", "-1", "--format=%gs", "main"], None));
    assert_eq!(reflog, "commit: Second signed commit");

    let outcome = repo.verify_commit_signature(second, &setup.signers).unwrap().unwrap();
    assert!(outcome.is_trusted());
}

//! Signed history for git: sign and verify commits in git's SSH signature format, in process.
//!
//! The signatures are the ones `git commit -S` writes with `gpg.format = ssh`: an SSHSIG over the commit without its
//! signature header, in the `git` namespace, stored armored in the `gpgsig` header (`gpgsig-sha256` in SHA-256
//! repositories). They verify with `git verify-commit` and `ssh-keygen -Y verify`, and signatures made by git verify
//! here. Unlike git, nothing runs as a separate program and a private key never has to be a file: anything that
//! implements [`ssh_key::SigningKey`] signs — a key held in memory, in a keychain or in hardware.
//!
//! Trust follows git's allowed-signers file ([`AllowedSigners`]): a good signature is trusted when its key is listed
//! for a principal, may sign in the `git` namespace, and was valid at the time of the commit.
//!
//! ```
//! use legix_sign::{AllowedSigners, ObjectFormat, Trust};
//!
//! let key = legix_sign::generate_ed25519("ada@example.com")?;
//! let commit = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
//!     author Ada <ada@example.com> 1759400000 +0000\n\
//!     committer Ada <ada@example.com> 1759400000 +0000\n\nFirst draft\n";
//! let signed = legix_sign::sign_commit(commit, ObjectFormat::Sha1, &key)?;
//!
//! let mut signers = AllowedSigners::default();
//! signers.push("ada@example.com", key.public_key().clone());
//! let outcome = legix_sign::verify_commit(&signed, ObjectFormat::Sha1, &signers)?.expect("signed");
//! assert!(outcome.is_trusted());
//! assert_eq!(outcome.trust, Trust::Allowed { principals: "ada@example.com".into() });
//! # Ok::<_, legix_sign::Error>(())
//! ```
//!
//! ## Stability
//!
//! This crate's API works on git's stable formats — the content of a commit object, armored SSH signatures and the
//! allowed-signers file — and on its own types. It does not expose the engine's types and follows semantic
//! versioning. The [`repository`] module is the exception: it extends `legix::Repository` and moves with the engine.
#![deny(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

use bstr::ByteSlice;
use legix_object::WriteTo;
pub use ssh_key;
use ssh_key::{HashAlg, LineEnding, PublicKey, SigningKey, SshSig};

mod allowed_signers;
pub use allowed_signers::{AllowedSigners, Entry};

#[cfg(feature = "repository")]
pub mod repository;

/// The SSHSIG namespace git signs and verifies objects in.
pub const NAMESPACE: &str = "git";

/// The object format of a repository, which decides the commit header that holds a signature.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum ObjectFormat {
    /// SHA-1 repositories: the signature is in the `gpgsig` header.
    #[default]
    Sha1,
    /// SHA-256 repositories: the signature is in the `gpgsig-sha256` header.
    Sha256,
}

impl ObjectFormat {
    /// The commit header that holds the signature.
    pub fn signature_header(self) -> &'static str {
        match self {
            ObjectFormat::Sha1 => legix_object::commit::SIGNATURE_FIELD_NAME,
            ObjectFormat::Sha256 => legix_object::commit::SIGNATURE_FIELD_NAME_SHA256,
        }
    }

    fn hash_kind(self) -> legix_hash::Kind {
        match self {
            ObjectFormat::Sha1 => legix_hash::Kind::Sha1,
            ObjectFormat::Sha256 => legix_hash::Kind::Sha256,
        }
    }
}

/// Whether a signature is cryptographically valid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Status {
    /// The key in the signature signed exactly this commit, in the `git` namespace.
    Good,
    /// The commit or the signature was altered, or the signature was made for another namespace.
    Bad,
    /// An OpenPGP or X.509 signature: verify it with git's own tools.
    UnsupportedFormat,
    /// An SSH signature that could not be read, or made with a key type this build does not verify (RSA, DSA).
    Unreadable(String),
}

/// What the allowed signers say about the key of a signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Trust {
    /// The key may sign for these principals (as written in the allowed signers) at the time of the commit.
    Allowed {
        /// The principals of the first matching entry, comma-separated patterns as written.
        principals: String,
    },
    /// The key is not listed for the `git` namespace.
    UnknownKey,
    /// The key is listed, but was not valid at the time of the commit (`valid-after`, `valid-before`).
    OutsideValidity {
        /// The principals of the first entry that lists the key.
        principals: String,
    },
    /// Trust was not looked at because the signature is not [`Status::Good`].
    NotEvaluated,
}

/// The result of verifying one signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Outcome {
    /// Whether the signature is cryptographically valid.
    pub status: Status,
    /// What the allowed signers say about its key.
    pub trust: Trust,
    /// The public key embedded in the signature, if it could be read.
    pub key: Option<PublicKey>,
    /// The SHA-256 fingerprint of that key, as git and `ssh-keygen` print it (`SHA256:…`).
    pub fingerprint: Option<String>,
}

impl Outcome {
    /// A good signature by a key the allowed signers trust at the time of the commit.
    pub fn is_trusted(&self) -> bool {
        self.status == Status::Good && matches!(self.trust, Trust::Allowed { .. })
    }
}

/// Errors of this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The data is not a valid commit object.
    #[error("not a valid commit: {0}")]
    Commit(String),
    /// The key could not sign, or a key could not be created or read.
    #[error(transparent)]
    Key(#[from] ssh_key::Error),
    /// A line of an allowed-signers file is not valid.
    #[error("allowed signers, line {line}: {message}")]
    AllowedSigners {
        /// The line, counted from 1.
        line: usize,
        /// What is wrong with it.
        message: String,
    },
    /// The repository could not be read or written.
    #[cfg(feature = "repository")]
    #[error("repository: {0}")]
    Repository(String),
}

/// A new Ed25519 key — the usual choice for a device or a person — from the operating system's random numbers.
pub fn generate_ed25519(comment: &str) -> Result<ssh_key::PrivateKey, Error> {
    let mut key = ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)?;
    key.set_comment(comment);
    Ok(key)
}

/// Sign `payload` in the `git` namespace with SHA-512, as `ssh-keygen -Y sign -n git` does, and return the armored
/// signature git stores.
pub fn sign(payload: &[u8], key: &impl SigningKey) -> Result<String, Error> {
    let signature = SshSig::sign(key, NAMESPACE, HashAlg::Sha512, payload)?;
    Ok(signature.to_pem(LineEnding::LF)?)
}

/// Sign `commit`, the content of a commit object (without the `commit <size>` header git hashes with it), and
/// return the signed content. A signature already in the header for `format` is replaced; the new one is placed
/// after the other headers, where git puts it.
pub fn sign_commit(commit: &[u8], format: ObjectFormat, key: &impl SigningKey) -> Result<Vec<u8>, Error> {
    let commit = legix_object::CommitRef::from_bytes(commit, format.hash_kind())
        .map_err(|err| Error::Commit(err.to_string()))?
        .into_owned()
        .map_err(|err| Error::Commit(err.to_string()))?;
    let signed = sign_object(commit, format, key)?;
    let mut out = Vec::new();
    signed.write_to(&mut out).map_err(|err| Error::Commit(err.to_string()))?;
    Ok(out)
}

pub(crate) fn sign_object(
    mut commit: legix_object::Commit,
    format: ObjectFormat,
    key: &impl SigningKey,
) -> Result<legix_object::Commit, Error> {
    let header = format.signature_header();
    commit.extra_headers.retain(|(name, _)| name != header);
    let mut payload = Vec::new();
    commit.write_to(&mut payload).map_err(|err| Error::Commit(err.to_string()))?;
    let signature = sign(&payload, key)?;
    commit.extra_headers.push((header.into(), signature.into()));
    Ok(commit)
}

/// Verify the signature on `commit`, the content of a commit object, and look its key up in `signers` at the
/// committer's time. `Ok(None)` means the commit is not signed.
pub fn verify_commit(commit: &[u8], format: ObjectFormat, signers: &AllowedSigners) -> Result<Option<Outcome>, Error> {
    let kind = format.hash_kind();
    let Some((signature, signed_data)) =
        legix_object::CommitRefIter::signature(commit, kind).map_err(|err| Error::Commit(err.to_string()))?
    else {
        return Ok(None);
    };
    let time = legix_object::CommitRefIter::from_bytes(commit, kind)
        .committer()
        .map_err(|err| Error::Commit(err.to_string()))?
        .time()
        .map_err(|err| Error::Commit(err.to_string()))?
        .seconds;
    Ok(Some(verify(signature.as_bytes(), &signed_data.to_bstring(), Some(time), signers)))
}

/// Verify an armored SSH `signature` over `signed_data` in the `git` namespace, and look its key up in `signers`
/// at `time` (Unix seconds; `None` ignores `valid-after` and `valid-before`).
pub fn verify(signature: &[u8], signed_data: &[u8], time: Option<i64>, signers: &AllowedSigners) -> Outcome {
    let not_evaluated = |status| Outcome {
        status,
        trust: Trust::NotEvaluated,
        key: None,
        fingerprint: None,
    };
    if !signature.trim_start().starts_with(b"-----BEGIN SSH SIGNATURE-----") {
        return not_evaluated(Status::UnsupportedFormat);
    }
    let signature = match SshSig::from_pem(signature) {
        Ok(signature) => signature,
        Err(err) => return not_evaluated(Status::Unreadable(err.to_string())),
    };
    let key = PublicKey::from(signature.public_key().clone());
    let fingerprint = Some(key.fingerprint(HashAlg::Sha256).to_string());
    let status = if signature.namespace() != NAMESPACE {
        Status::Bad
    } else {
        match key.verify(NAMESPACE, signed_data, &signature) {
            Ok(()) => Status::Good,
            Err(ssh_key::Error::Crypto) => Status::Bad,
            Err(err) => Status::Unreadable(err.to_string()),
        }
    };
    let trust = if status == Status::Good {
        signers.trust(&key, time)
    } else {
        Trust::NotEvaluated
    };
    Outcome {
        status,
        trust,
        key: Some(key),
        fingerprint,
    }
}

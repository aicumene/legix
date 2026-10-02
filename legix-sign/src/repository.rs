//! Signed commits in a `legix::Repository`.
//!
//! These helpers extend the engine and follow its API, unlike the rest of this crate.

use legix::{ObjectId, Repository, refs::FullName};
use legix_ref::{
    Target,
    transaction::{PreviousValue, RefEdit},
};
use ssh_key::SigningKey;

use crate::{AllowedSigners, Error, ObjectFormat, Outcome};

/// Create and verify signed commits.
pub trait RepositoryExt {
    /// Like `Repository::commit()`: create a commit with `message`, `tree` and `parents` by the configured author
    /// and committer, and point `reference` at it — but sign it with `key` first.
    ///
    /// `reference` can be `"HEAD"`, which writes through to the branch `HEAD` points to. The first parent must be
    /// the current target of `reference`; without parents, `reference` must not exist yet.
    fn commit_signed<Name, E>(
        &self,
        reference: Name,
        message: &str,
        tree: impl Into<ObjectId>,
        parents: impl IntoIterator<Item = impl Into<ObjectId>>,
        key: &impl SigningKey,
    ) -> Result<ObjectId, Error>
    where
        Name: TryInto<FullName, Error = E>,
        E: std::error::Error + Send + Sync + 'static;

    /// Verify the signature on the commit `id` and look its key up in `signers` at the committer's time.
    /// `Ok(None)` means the commit is not signed.
    fn verify_commit_signature(
        &self,
        id: impl Into<ObjectId>,
        signers: &AllowedSigners,
    ) -> Result<Option<Outcome>, Error>;
}

impl RepositoryExt for Repository {
    fn commit_signed<Name, E>(
        &self,
        reference: Name,
        message: &str,
        tree: impl Into<ObjectId>,
        parents: impl IntoIterator<Item = impl Into<ObjectId>>,
        key: &impl SigningKey,
    ) -> Result<ObjectId, Error>
    where
        Name: TryInto<FullName, Error = E>,
        E: std::error::Error + Send + Sync + 'static,
    {
        let reference = reference.try_into().map_err(repository_error)?;
        let author = self
            .author()
            .ok_or_else(|| Error::Repository("the author identity is not configured".into()))?
            .map_err(repository_error)?;
        let committer = self
            .committer()
            .ok_or_else(|| Error::Repository("the committer identity is not configured".into()))?
            .map_err(repository_error)?;
        let commit = legix_object::Commit {
            message: message.into(),
            tree: tree.into(),
            author: author.into(),
            committer: committer.into(),
            encoding: None,
            parents: parents.into_iter().map(Into::into).collect(),
            extra_headers: Vec::new(),
        };
        let commit = crate::sign_object(commit, object_format(self), key)?;
        let id = self.write_object(&commit).map_err(repository_error)?.detach();

        let expected = match commit.parents.first() {
            Some(previous) if reference.as_bstr() == "HEAD" => PreviousValue::MustExistAndMatch(Target::Object(*previous)),
            Some(previous) => PreviousValue::ExistingMustMatch(Target::Object(*previous)),
            None => PreviousValue::MustNotExist,
        };
        let log_message = legix::reference::log::message("commit", commit.message.as_ref(), commit.parents.len());
        self.edit_references_as(
            Some(RefEdit::update(reference, id, expected, log_message).with_deref(true)),
            Some(committer),
        )
        .map_err(repository_error)?;
        Ok(id)
    }

    fn verify_commit_signature(
        &self,
        id: impl Into<ObjectId>,
        signers: &AllowedSigners,
    ) -> Result<Option<Outcome>, Error> {
        let commit = self.find_commit(id.into()).map_err(repository_error)?;
        crate::verify_commit(&commit.data, object_format(self), signers)
    }
}

fn object_format(repo: &Repository) -> ObjectFormat {
    match repo.object_hash() {
        legix_hash::Kind::Sha256 => ObjectFormat::Sha256,
        _ => ObjectFormat::Sha1,
    }
}

fn repository_error(err: impl std::fmt::Display) -> Error {
    Error::Repository(err.to_string())
}

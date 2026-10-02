use crate::Result;
use legix_error::ExnResult;
use legix_ref::file;

// TODO: when ready, add a new test entry point with a feature toggle to switch this to `legix_ref::Store`.
//       That way all tests can run against the new general store to validate its truly working.
//       The same can be done when RefTable is available, and its corresponding tests.
pub type Store = file::Store;

fn store() -> Result<Store> {
    store_at("make_ref_repository.sh")
}

pub fn store_with_packed_refs() -> Result<Store> {
    store_at("make_packed_ref_repository.sh")
}

pub fn store_at(name: &str) -> Result<Store> {
    named_store_at(name, "")
}

pub fn named_store_at(script_name: &str, name: &str) -> Result<Store> {
    let path = crate::scripted_fixture_read_only(script_name)?;
    Ok(Store::at(path.join(name).join(".git"), crate::fixture_hash_kind()))
}

pub fn store_at_with_args(name: &str, args: impl IntoIterator<Item = impl Into<String>>) -> Result<Store> {
    let path = crate::scripted_fixture_read_only_with_args(name, args)?;
    Ok(Store::at(path.join(".git"), crate::fixture_hash_kind()))
}

fn store_writable(name: &str) -> Result<(legix_testtools::tempfile::TempDir, Store)> {
    let dir = crate::scripted_fixture_writable(name)?;
    let git_dir = dir.path().join(".git");
    Ok((dir, Store::at(git_dir, crate::fixture_hash_kind())))
}

pub fn odb_at(objects_dir: impl Into<std::path::PathBuf>) -> std::io::Result<legix_odb::Handle> {
    legix_odb::at(objects_dir, crate::fixture_hash_kind())
}

struct EmptyCommit;
impl legix_object::Find for EmptyCommit {
    fn try_find<'a>(&self, id: &legix_hash::oid, _buffer: &'a mut Vec<u8>) -> ExnResult<Option<legix_object::Data<'a>>> {
        Ok(Some(legix_object::Data {
            kind: legix_object::Kind::Commit,
            object_hash: id.kind(),
            data: &[],
        }))
    }
}

mod log;
mod reference;
mod store;
pub(crate) mod transaction;
mod worktree;

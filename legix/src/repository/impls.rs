use std::ops::DerefMut;

use crate::ExnResult;

use legix_error::{ErrorExt, ResultExt};
use legix_hash::ObjectId;
use legix_object::Exists;

impl Clone for crate::Repository {
    fn clone(&self) -> Self {
        let mut new = crate::Repository::from_refs_and_objects(
            self.refs.clone(),
            self.objects.clone(),
            self.work_tree.clone(),
            self.index_path.clone(),
            self.common_dir.clone(),
            self.config.clone(),
            self.options.clone(),
            #[cfg(feature = "index")]
            self.index.clone(),
            self.shallow_commits.clone(),
            #[cfg(feature = "attributes")]
            self.modules.clone(),
        );

        if self.bufs.is_none() {
            new.bufs.take();
        }

        new
    }
}

impl std::fmt::Debug for crate::Repository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Repository")
            .field("kind", &self.kind())
            .field("git_dir", &self.git_dir())
            .field("workdir", &self.workdir())
            .finish()
    }
}

impl PartialEq<crate::Repository> for crate::Repository {
    fn eq(&self, other: &crate::Repository) -> bool {
        let realpath = |repo: &crate::Repository, path| {
            legix_path::realpath_opts(path, repo.current_dir(), legix_path::realpath::MAX_SYMLINKS).ok()
        };
        realpath(self, self.git_dir()) == realpath(other, other.git_dir())
            && self.work_tree.as_deref().and_then(|path| realpath(self, path))
                == other.work_tree.as_deref().and_then(|path| realpath(other, path))
    }
}

impl From<&crate::ThreadSafeRepository> for crate::Repository {
    fn from(repo: &crate::ThreadSafeRepository) -> Self {
        crate::Repository::from_refs_and_objects(
            repo.refs.clone(),
            legix_odb::memory::Proxy::from(legix_odb::Cache::from(repo.objects.to_handle())).with_write_passthrough(),
            repo.work_tree.clone(),
            repo.index_path.clone(),
            repo.common_dir.clone(),
            repo.config.clone(),
            repo.linked_worktree_options.clone(),
            #[cfg(feature = "index")]
            repo.index.clone(),
            repo.shallow_commits.clone(),
            #[cfg(feature = "attributes")]
            repo.modules.clone(),
        )
    }
}

impl From<crate::ThreadSafeRepository> for crate::Repository {
    fn from(repo: crate::ThreadSafeRepository) -> Self {
        crate::Repository::from_refs_and_objects(
            repo.refs,
            legix_odb::memory::Proxy::from(legix_odb::Cache::from(repo.objects.to_handle())).with_write_passthrough(),
            repo.work_tree,
            repo.index_path,
            repo.common_dir,
            repo.config,
            repo.linked_worktree_options,
            #[cfg(feature = "index")]
            repo.index,
            repo.shallow_commits,
            #[cfg(feature = "attributes")]
            repo.modules.clone(),
        )
    }
}

impl From<crate::Repository> for crate::ThreadSafeRepository {
    fn from(r: crate::Repository) -> Self {
        crate::ThreadSafeRepository {
            refs: r.refs,
            objects: r.objects.into_inner().store(),
            work_tree: r.work_tree,
            index_path: r.index_path,
            common_dir: r.common_dir,
            config: r.config,
            linked_worktree_options: r.options,
            #[cfg(feature = "index")]
            index: r.index,
            #[cfg(feature = "attributes")]
            modules: r.modules,
            shallow_commits: r.shallow_commits,
        }
    }
}

impl legix_object::Write for crate::Repository {
    fn write(&self, object: &dyn legix_object::WriteTo) -> ExnResult<legix_hash::ObjectId> {
        let mut buf = self.empty_reusable_buffer();
        object.write_to(buf.deref_mut()).or_erased()?;
        self.write_buf(object.kind(), &buf)
    }

    fn write_buf(&self, object: legix_object::Kind, from: &[u8]) -> ExnResult<legix_hash::ObjectId> {
        let oid = legix_object::compute_hash(self.object_hash(), object, from).or_erased()?;
        if self.objects.exists(&oid) {
            return Ok(oid);
        }
        self.objects.write_buf_with_known_id(object, from, oid)
    }

    fn write_stream(
        &self,
        kind: legix_object::Kind,
        size: u64,
        from: &mut dyn std::io::Read,
    ) -> ExnResult<legix_hash::ObjectId> {
        let mut buf = self.empty_reusable_buffer();
        let bytes = std::io::copy(from, buf.deref_mut()).or_erased()?;
        if size != bytes {
            return Err(
                legix_error::message!("Found {bytes} bytes in stream, but had {size} bytes declared").raise_erased(),
            );
        }
        self.write_buf(kind, &buf)
    }

    fn write_buf_with_known_id(
        &self,
        object: legix_object::Kind,
        from: &[u8],
        id: legix_hash::ObjectId,
    ) -> ExnResult<legix_hash::ObjectId> {
        if self.objects.exists(&id) {
            return Ok(id);
        }
        self.objects.write_buf_with_known_id(object, from, id)
    }

    fn write_stream_with_known_id(
        &self,
        kind: legix_object::Kind,
        size: u64,
        from: &mut dyn std::io::Read,
        id: legix_hash::ObjectId,
    ) -> ExnResult<legix_hash::ObjectId> {
        let mut buf = self.empty_reusable_buffer();
        let bytes = std::io::copy(from, buf.deref_mut()).or_erased()?;
        if size != bytes {
            return Err(
                legix_error::message!("Found {bytes} bytes in stream, but had {size} bytes declared").raise_erased(),
            );
        }
        self.write_buf_with_known_id(kind, &buf, id)
    }
}

impl legix_object::FindHeader for crate::Repository {
    fn try_header(&self, id: &legix_hash::oid) -> ExnResult<Option<legix_object::Header>> {
        if id == ObjectId::empty_tree(self.object_hash()) {
            return Ok(Some(legix_object::Header {
                kind: legix_object::Kind::Tree,
                size: 0,
            }));
        }
        self.objects.try_header(id)
    }
}

impl legix_object::Find for crate::Repository {
    fn try_find<'a>(&self, id: &legix_hash::oid, buffer: &'a mut Vec<u8>) -> ExnResult<Option<legix_object::Data<'a>>> {
        if id == ObjectId::empty_tree(self.object_hash()) {
            buffer.clear();
            return Ok(Some(legix_object::Data {
                kind: legix_object::Kind::Tree,
                object_hash: self.object_hash(),
                data: &[],
            }));
        }
        self.objects.try_find(id, buffer)
    }
}

impl legix_object::Exists for crate::Repository {
    fn exists(&self, id: &legix_hash::oid) -> bool {
        if id == ObjectId::empty_tree(self.object_hash()) {
            return true;
        }
        self.objects.exists(id)
    }
}

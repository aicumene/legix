use legix_error::ResultExt;

use legix_blame::Start;
use legix_hash::ObjectId;
use legix_ref::bstr::BStr;

use crate::{Repository, Result, repository::blame_file};

impl Repository {
    /// Produce a list of consecutive [`legix_blame::BlameEntry`] instances. Each `BlameEntry`
    /// corresponds to a hunk of consecutive lines of the file at `suspect:<file_path>` that got
    /// introduced by a specific commit.
    ///
    /// For details, see the documentation of [`legix_blame::file()`].
    pub fn blame_file(
        &self,
        file_path: &BStr,
        suspect: impl Into<ObjectId>,
        options: blame_file::Options,
    ) -> Result<legix_blame::Outcome> {
        let cache = self.commit_graph_if_enabled()?;
        let mut resource_cache = self.diff_resource_cache_for_tree_diff()?;

        let blame_file::Options {
            diff_algorithm,
            ranges,
            since,
            rewrites,
        } = options;
        let diff_algorithm = match diff_algorithm {
            Some(diff_algorithm) => diff_algorithm,
            None => self.diff_algorithm().or_erased()?,
        };

        let options = legix_blame::Options {
            diff_algorithm,
            ranges,
            since,
            rewrites,
            debug_track_path: false,
        };

        let outcome = legix_blame::file(
            &self.objects,
            Start::Commit(suspect.into()),
            cache,
            &mut resource_cache,
            file_path,
            options,
        )?;

        Ok(outcome)
    }
}

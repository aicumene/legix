use crate::{Repository, Result};

impl Repository {
    /// Return options that can be used to drive a low-level checkout operation.
    /// Use `attributes_source` to determine where `.gitattributes` files should be read from, which depends on
    /// the presence of a worktree to begin with.
    /// Here, typically this value would be [`legix_worktree::stack::state::attributes::Source::IdMapping`]
    pub fn checkout_options(
        &self,
        attributes_source: legix_worktree::stack::state::attributes::Source,
    ) -> Result<legix_worktree_state::checkout::Options> {
        self.config.checkout_options(self, attributes_source)
    }
}

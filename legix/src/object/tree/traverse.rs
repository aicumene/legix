use crate::{Result, Tree};

/// Traversal
impl<'repo> Tree<'repo> {
    /// Obtain a platform for initiating a variety of traversals.
    pub fn traverse(&self) -> Platform<'_, 'repo> {
        Platform {
            root: self,
            breadthfirst: BreadthFirstPresets { root: self },
        }
    }
}

/// An intermediate object to start traversing the parent tree from.
pub struct Platform<'a, 'repo> {
    root: &'a Tree<'repo>,
    /// Provides easy access to presets for common breadth-first traversal.
    // TODO: remove this - it's a bit too much of a fixed function, or go all in once it's clear it's needed,
    //       but probably with depth-first.
    pub breadthfirst: BreadthFirstPresets<'a, 'repo>,
}

/// Presets for common choices in breadth-first traversal.
#[derive(Copy, Clone)]
pub struct BreadthFirstPresets<'a, 'repo> {
    root: &'a Tree<'repo>,
}

impl BreadthFirstPresets<'_, '_> {
    /// Returns all entries and their file paths, recursively, as reachable from this tree.
    pub fn files(&self) -> Result<Vec<legix_traverse::tree::recorder::Entry>> {
        let mut recorder = legix_traverse::tree::Recorder::default();
        Platform {
            root: self.root,
            breadthfirst: *self,
        }
        .breadthfirst(&mut recorder)?;
        Ok(recorder.records)
    }
}

impl Platform<'_, '_> {
    /// Start a breadth-first, recursive traversal using `delegate`, for which a [`Recorder`](legix_traverse::tree::Recorder) can be used to get started.
    ///
    /// # Note
    ///
    /// - Results are returned in sort order as per tree-sorting rules, files first, then directories, one level at a time.
    /// - for obtaining the direct children of the tree, use [Tree::iter()] instead.
    pub fn breadthfirst<V>(&self, delegate: &mut V) -> Result<()>
    where
        V: legix_traverse::tree::Visit,
    {
        let root = legix_object::TreeRefIter::from_bytes(&self.root.data, self.root.id.kind());
        let state = legix_traverse::tree::breadthfirst::State::default();
        legix_traverse::tree::breadthfirst(root, state, &self.root.repo.objects, delegate)
            .map_err(legix_error::Exn::into_error)
    }

    /// Start a depth-first, recursive traversal using `delegate`, for which a [`Recorder`](legix_traverse::tree::Recorder) can be used to get started.
    ///
    /// # Note
    ///
    /// For obtaining the direct children of the tree, use [Tree::iter()] instead.
    pub fn depthfirst<V>(&self, delegate: &mut V) -> Result<()>
    where
        V: legix_traverse::tree::Visit,
    {
        let state = legix_traverse::tree::depthfirst::State::default();
        legix_traverse::tree::depthfirst(self.root.id, state, &self.root.repo.objects, delegate)
            .map_err(legix_error::Exn::into_error)
    }
}

pub(crate) type CommitsStorage =
    legix_features::threading::OwnShared<legix_fs::SharedFileSnapshotMut<nonempty::NonEmpty<legix_hash::ObjectId>>>;
/// A lazily loaded and auto-updated list of commits which are at the shallow boundary (behind which there are no commits available),
/// sorted to allow bisecting.
pub type Commits = legix_fs::SharedFileSnapshot<nonempty::NonEmpty<legix_hash::ObjectId>>;

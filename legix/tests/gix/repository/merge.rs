use crate::Result;
use crate::util::named_repo;

#[test]
fn tree_merge_options() -> Result {
    let repo = named_repo("make_basic_repo.sh")?;
    let opts: legix::merge::plumbing::tree::Options = repo.tree_merge_options()?.into();
    assert_eq!(
        opts.rewrites,
        Some(legix::diff::Rewrites::default()),
        "If merge options aren't set, it defaults to diff options, and these default to doing rename tracking"
    );
    Ok(())
}

use crate::Result;
use bstr::ByteSlice;
use legix_attributes::glob::pattern::Case;
use legix_filter::{eol, pipeline::convert::to_worktree};

mod convert_to_git;
mod convert_to_worktree;

#[test]
fn default() -> Result {
    let mut filters = legix_filter::Pipeline::default();
    let out = filters.convert_to_worktree(
        b"hi",
        "file".into(),
        &mut |_, _| {},
        to_worktree::Options {
            can_delay: legix_filter::driver::apply::Delay::Allow,
            unknown_encoding: to_worktree::UnknownEncoding::Fail,
        },
    )?;
    assert_eq!(
        out.as_bytes().expect("unchanged").as_bstr(),
        "hi",
        "default-pipelines can be used like normal, they have not effect"
    );
    Ok(())
}

fn attribute_cache(name: &str) -> legix_testtools::Result<legix_worktree::Stack> {
    let dir = legix_testtools::scripted_fixture_read_only("pipeline_repos.sh")?.join(name);
    Ok(legix_worktree::Stack::new(
        dir,
        legix_worktree::stack::State::for_add(
            legix_worktree::stack::state::Attributes::new(
                Default::default(),
                None,
                legix_worktree::stack::state::attributes::Source::WorktreeThenIdMapping,
                Default::default(),
            ),
            legix_worktree::stack::state::Ignore::new(
                Default::default(),
                Default::default(),
                None,
                legix_worktree::stack::state::ignore::Source::WorktreeThenIdMappingIfNotSkipped,
                Default::default(),
            ),
        ),
        Case::Sensitive,
        Vec::new(),
        Default::default(),
    ))
}

fn pipeline(
    name: &str,
    init: impl FnOnce() -> (
        Vec<legix_filter::Driver>,
        Vec<&'static encoding_rs::Encoding>,
        legix_filter::pipeline::CrlfRoundTripCheck,
        eol::Configuration,
    ),
) -> legix_testtools::Result<(legix_worktree::Stack, legix_filter::Pipeline)> {
    let cache = attribute_cache(name)?;
    let (drivers, encodings_with_roundtrip_check, crlf_roundtrip_check, eol_config) = init();
    let pipe = legix_filter::Pipeline::new(
        Default::default(),
        legix_filter::pipeline::Options {
            drivers,
            eol_config,
            encodings_with_roundtrip_check,
            crlf_roundtrip_check,
            object_hash: legix_testtools::object_hash(),
        },
    );
    Ok((cache, pipe))
}

#[cfg(feature = "parallel")]
#[test]
fn is_send_with_parallel_enabled() {
    fn assert_send<T: Send>() {}
    assert_send::<legix_filter::Pipeline>();
}

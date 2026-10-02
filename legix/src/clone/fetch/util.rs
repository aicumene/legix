use std::io::Write;

use legix_error::{ExnMessageResult, ResultExt};
use legix_ref::{
    Category, FullNameRef, PartialName,
    transaction::{LogChange, RefLog},
};

use crate::{
    Error, Repository, Result,
    bstr::{BStr, BString, ByteSlice},
};

enum WriteMode {
    Overwrite,
    Append,
}
pub fn append_remote_to_local_config_file(
    remote: &mut crate::Remote<'_>,
    remote_name: BString,
) -> Result<legix_config::File> {
    let mut config = legix_config::File::new(local_config_meta(remote.repo));
    remote
        .save_as_to(remote_name, &mut config)
        .or_raise(|| legix_error::message("Failed to store configured remote in memory"))?;

    write_to_local_config(&config, WriteMode::Append)
        .or_raise(|| legix_error::message("Failed to write repository configuration to disk"))?;
    Ok(config)
}

/// Reconfigure the freshly-initialized, still-empty repository `repo` to use `object_hash`
/// by rewriting the object-format related entries in its local configuration file on disk,
/// and reload the repository handle.
///
/// This relies on the initial reference database not having persisted any hash-format-dependent
/// state. That is true for the current file-based ref store, but a future reftable backend must
/// not be initialized with the wrong hash and then reused. If clone learns the remote hash only
/// after repository creation, initialize a non-reftable reference database first, then convert it
/// to reftable once the remote hash is known.
///
/// Existing local configuration, including the remote section written during clone setup,
/// is preserved. Only local sections are written back to `.git/config`,
///
/// The returned repository is reopened from disk so the object hash change affects all
/// hash-dependent state. Callers that need in-memory configuration from `repo` must
/// transfer it to the returned handle.
#[cfg(feature = "sha256")]
pub(super) fn reinitialize_with_object_hash(
    repo: &crate::Repository,
    object_hash: legix_hash::Kind,
) -> Result<crate::Repository> {
    let git_dir = repo.git_dir();
    let config_path = git_dir.join("config");

    let mut config = legix_config::File::from_path_no_includes(config_path.clone(), legix_config::Source::Local)
        .or_raise(|| legix_error::message("Failed to load repo-local git configuration before writing"))?;
    // Mirror what `crate::create` writes at init time: only SHA-256 repositories get
    // `repositoryformatversion = 1` along with the `objectformat` extension.
    let is_sha256 = object_hash == legix_hash::Kind::Sha256;
    config
        .section_mut("core", None)
        .expect("freshly initialized repository has a core section")
        .set("repositoryformatversion", if is_sha256 { "1" } else { "0" })
        .or_erased()?;
    if is_sha256 {
        config
            .section_mut_or_create_new("extensions", None)
            .expect("valid section name")
            .set("objectformat", object_hash.to_string())
            .or_erased()?;
    } else {
        // In a freshly initialized repository, this section exists solely to carry `objectformat`.
        config.remove_section("extensions", None);
    }
    let mut lock = legix_lock::File::acquire_to_update_resource(&config_path, legix_lock::acquire::Fail::Immediately, None)
        .or_raise(|| legix_error::message("Failed to acquire lock to write repository configuration to disk"))?;
    config
        .write_to_filter(&mut lock, |section| section.meta().source == legix_config::Source::Local)
        .or_raise(|| legix_error::message("Failed to write repository configuration to disk"))?;
    lock.commit()
        .or_raise(|| legix_error::message("Failed to commit lock after writing repository configuration to disk"))?;

    Ok(crate::ThreadSafeRepository::open_opts(git_dir, repo.options.clone())
        .or_raise(|| {
            legix_error::message("Failed to reopen the local repository after adopting the remote's object format")
        })?
        .to_thread_local())
}

fn local_config_meta(repo: &Repository) -> legix_config::file::Metadata {
    let meta = repo.config.resolved.meta().clone();
    assert_eq!(
        meta.source,
        legix_config::Source::Local,
        "local path is the default for new sections"
    );
    meta
}

fn write_to_local_config(config: &legix_config::File, mode: WriteMode) -> std::io::Result<()> {
    assert_eq!(
        config.meta().source,
        legix_config::Source::Local,
        "made for appending to local configuration file"
    );
    let mut local_config = std::fs::OpenOptions::new()
        .create(false)
        .write(matches!(mode, WriteMode::Overwrite))
        .append(matches!(mode, WriteMode::Append))
        .open(config.meta().path.as_deref().expect("local config with path set"))?;
    local_config.write_all(config.detect_newline_style())?;
    config.write_to_filter(&mut local_config, |s| s.meta().source == legix_config::Source::Local)
}

/// Append `config` to `repo`'s in-memory resolved configuration.
///
/// This is used after writing clone-specific local configuration to `.git/config`,
/// as the `repo` handle was opened before that write and won't observe it until
/// it is either updated in memory or reopened.
pub fn append_config_to_repo_config(repo: &mut Repository, config: legix_config::File) -> ExnMessageResult {
    let repo_config = legix_features::threading::OwnShared::make_mut(&mut repo.config.resolved);
    repo_config.append(config)?;
    Ok(())
}

/// HEAD cannot be written by means of refspec by design, so we have to do it manually here. Also create the pointed-to ref
/// if we have to, as it might not have been naturally included in the ref-specs.
/// Lastly, use `ref_name` if it was provided instead, and let `HEAD` point to it.
pub fn update_head(
    repo: &mut Repository,
    ref_map: &crate::remote::fetch::RefMap,
    reflog_message: &BStr,
    remote_name: &BStr,
    ref_name: Option<&PartialName>,
    revision: Option<&legix_refspec::RefSpec>,
) -> Result<()> {
    use legix_ref::transaction::{PreviousValue, RefEdit};
    let revision_head_id = revision
        .map(|revision| -> Result<legix_hash::ObjectId> {
            let mapping = find_revision(ref_map, revision)?;
            let id = mapping.remote.peeled_id().ok_or_else(|| revision_missing(revision))?;
            Ok(repo
                .find_object(id)
                .or_raise(|| legix_error::message("The requested revision could not be read"))?
                .peel_to_commit()
                .or_raise(|| legix_error::message("The requested revision did not peel to a commit"))?
                .id)
        })
        .transpose()?;
    let head_info = match revision_head_id.as_ref() {
        Some(id) => Some((Some(id.as_ref()), None)),
        None => match ref_name {
            Some(ref_name) => {
                let (target, full_ref_name) = find_custom_refname(ref_map, ref_name)?;
                Some((Some(target), Some(full_ref_name)))
            }
            None => ref_map.remote_refs.iter().find_map(|r| {
                Some(match r {
                    legix_protocol::handshake::Ref::Symbolic {
                        full_ref_name,
                        target,
                        tag: _,
                        object,
                    } if full_ref_name == "HEAD" => (Some(object.as_ref()), Some(target.as_bstr())),
                    legix_protocol::handshake::Ref::Direct { full_ref_name, object } if full_ref_name == "HEAD" => {
                        (Some(object.as_ref()), None)
                    }
                    legix_protocol::handshake::Ref::Unborn { full_ref_name, target } if full_ref_name == "HEAD" => {
                        (None, Some(target.as_bstr()))
                    }
                    _ => return None,
                })
            }),
        },
    };
    let Some((head_peeled_id, head_ref)) = head_info else {
        return Ok(());
    };

    let head: legix_ref::FullName = "HEAD".try_into().expect("valid");
    let reflog_message = || LogChange {
        mode: RefLog::AndReference,
        force_create_reflog: false,
        message: reflog_message.to_owned(),
    };
    match head_ref {
        Some(referent) => {
            let referent: legix_ref::FullName = legix_ref::FullName::try_from(referent).or_raise(|| {
                legix_error::validation(format!(
                    "The remote HEAD points to a reference named {referent:?} which is invalid."
                ))
            })?;
            repo.refs
                .transaction()
                .packed_refs(legix_ref::file::transaction::PackedRefs::DeletionsAndNonSymbolicUpdates(
                    Box::new(&repo.objects),
                ))
                .prepare(
                    {
                        let mut edits = vec![RefEdit::update_with_log(
                            head.clone(),
                            referent.clone(),
                            PreviousValue::Any,
                            reflog_message(),
                        )];
                        if let Some(head_peeled_id) = head_peeled_id {
                            edits.push(RefEdit::update_with_log(
                                referent.clone(),
                                head_peeled_id.to_owned(),
                                PreviousValue::Any,
                                reflog_message(),
                            ));
                        }
                        edits
                    },
                    legix_lock::acquire::Fail::Immediately,
                    legix_lock::acquire::Fail::Immediately,
                )
                .or_raise(|| legix_error::message("Failed to update HEAD with values from remote"))?
                .commit(
                    repo.committer()
                        .transpose()
                        .or_raise(|| legix_error::message("Failed to update HEAD with values from remote"))?,
                )
                .or_raise(|| legix_error::message("Failed to update HEAD with values from remote"))?;

            if let Some(head_peeled_id) = head_peeled_id {
                let mut log = reflog_message();
                log.mode = RefLog::Only;
                repo.edit_reference(RefEdit::update_with_log(
                    head,
                    head_peeled_id.to_owned(),
                    PreviousValue::Any,
                    log,
                ))
                .or_raise(|| legix_error::message("Failed to update HEAD with values from remote"))?;
            }

            setup_branch_config(repo, referent.as_ref(), head_peeled_id, remote_name)?;
        }
        None => {
            repo.edit_reference(RefEdit::update_with_log(
                head,
                head_peeled_id
                    .expect("detached heads always point to something")
                    .to_owned(),
                PreviousValue::Any,
                reflog_message(),
            ))
            .or_raise(|| legix_error::message("Failed to update HEAD with values from remote"))?;
        }
    }
    Ok(())
}

/// Find the mapping produced by the exact refspec used to request `revision`.
///
/// Returns an error if the remote did not map that refspec.
pub(super) fn find_revision<'a>(
    ref_map: &'a crate::remote::fetch::RefMap,
    revision: &legix_refspec::RefSpec,
) -> Result<&'a legix_protocol::fetch::refmap::Mapping> {
    ref_map
        .mappings
        .iter()
        .find(|mapping| {
            mapping
                .spec_index
                .get(&ref_map.refspecs, &ref_map.extra_refspecs)
                .is_some_and(|spec| spec == revision)
        })
        .ok_or_else(|| revision_missing(revision))
}

fn revision_missing(revision: &legix_refspec::RefSpec) -> Error {
    Error::from_error(legix_error::not_found(format!(
        "The remote didn't have the requested revision {:?}",
        revision.to_ref().source().expect("validated revision")
    )))
}

/// Resolve `ref_name` to its object ID and full name among the mapped remote references.
///
/// Full names match directly. Partial names prefer branches over tags, then use normal refspec matching.
/// Returns an error when there is no unique match.
/// Ambiguous matches include the requested reference name bytes as `input` [metadata](legix_error::Error::metadata()).
pub(super) fn find_custom_refname<'a>(
    ref_map: &'a crate::remote::fetch::RefMap,
    ref_name: &PartialName,
) -> Result<(&'a legix_hash::oid, &'a BStr)> {
    let group = legix_refspec::MatchGroup::from_fetch_specs(Some(
        legix_refspec::parse(ref_name.as_ref().as_bstr(), legix_refspec::parse::Operation::Fetch)
            .expect("partial names are valid refs"),
    ));
    let filtered_items: Vec<_> = ref_map
        .mappings
        .iter()
        .filter_map(|m| m.remote.as_name().zip(m.remote.as_id()))
        .map(|(full_ref_name, target)| legix_refspec::match_group::Item {
            full_ref_name,
            target,
            object: None,
        })
        .collect();

    let requested_name = ref_name.as_ref().as_bstr();
    let find_item = |name: &BStr| filtered_items.iter().find(|item| item.full_ref_name == name).copied();
    // Preserve gix's documented full-ref support, then match git clone --branch by trying heads before tags.
    if let Some(item) = find_item(requested_name) {
        return Ok((item.target, item.full_ref_name));
    }
    if !requested_name.starts_with(b"refs/") {
        let branch_name = Category::LocalBranch.to_full_name(requested_name).or_erased()?;
        if let Some(item) = find_item(branch_name.as_bstr()) {
            return Ok((item.target, item.full_ref_name));
        }

        let tag_name = Category::Tag.to_full_name(requested_name).or_erased()?;
        if let Some(item) = find_item(tag_name.as_bstr()) {
            return Ok((item.target, item.full_ref_name));
        }
    }

    let res = group.match_lhs(filtered_items.iter().copied());
    match res.mappings.len() {
        0 => Err(Error::from_error(legix_error::not_found(format!(
            "The remote didn't have any ref that matched '{requested_name}'"
        )))),
        1 => {
            let item = filtered_items[res.mappings[0]
                .item_index
                .expect("we map by name only and have no object-id in refspec")];
            Ok((item.target, item.full_ref_name))
        }
        _ => {
            let candidates = res
                .mappings
                .into_iter()
                .filter_map(|m| match m.lhs {
                    legix_refspec::match_group::SourceRef::FullName(name) => Some(name.into_owned()),
                    legix_refspec::match_group::SourceRef::ObjectId(_) => None,
                })
                .collect::<Vec<_>>();
            Err(Error::from_error(
                legix_error::validation(format!(
                    "The remote has {} refs for '{requested_name}', try to use a specific name: {}",
                    candidates.len(),
                    candidates
                        .iter()
                        .filter_map(|name| name.to_str().ok())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
                .with("input", ref_name.as_ref().as_bstr().to_owned()),
            ))
        }
    }
}

/// Set up the remote configuration for `branch` so that it points to itself, but on the remote, if and only if currently
/// saved refspecs are able to match it.
/// For that we reload the remote of `remote_name` and use its `ref_specs` for match.
fn setup_branch_config(
    repo: &mut Repository,
    branch: &FullNameRef,
    branch_id: Option<&legix_hash::oid>,
    remote_name: &BStr,
) -> Result<()> {
    let short_name = match branch.category_and_short_name() {
        Some((legix_ref::Category::LocalBranch, shortened)) => match shortened.to_str() {
            Ok(s) => s,
            Err(_) => return Ok(()),
        },
        _ => return Ok(()),
    };
    let remote = repo
        .find_remote(remote_name)
        .expect("remote was just created and must be visible in config");
    let group = legix_refspec::MatchGroup::from_fetch_specs(remote.fetch_specs.iter().map(legix_refspec::RefSpec::to_ref));
    let null = legix_hash::ObjectId::null(repo.object_hash());
    let res = group.match_lhs(
        Some(legix_refspec::match_group::Item {
            full_ref_name: branch.as_bstr(),
            target: branch_id.unwrap_or(&null),
            object: None,
        })
        .into_iter(),
    );
    if !res.mappings.is_empty() {
        let mut config = repo.config_snapshot_mut();
        let mut section = config
            .new_section("branch", short_name)
            .expect("section header name is always valid per naming rules, our input branch name is valid");
        section.push("remote", remote_name).or_erased()?;
        section.push("merge", branch.as_bstr()).or_erased()?;
        write_to_local_config(&config, WriteMode::Overwrite).or_erased()?;
        config.commit().expect("configuration we set is valid");
    }
    Ok(())
}

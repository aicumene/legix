#![allow(clippy::result_large_err)]

use super::util;
use crate::{
    Error, Result,
    config::{
        cache::util::{ApplyLeniency, ApplyLeniencyDefaultValue},
        tree::{Core, Extensions, gitoxide},
    },
};
use legix_error::{ErrorExt, ResultExt};

/// A utility to deal with the cyclic dependency between the ref store and the configuration. The ref-store needs the
/// object hash kind, and the configuration needs the current branch name to resolve conditional includes with `onbranch`.
pub(crate) struct StageOne {
    pub git_dir_config: legix_config::File,
    pub buf: Vec<u8>,

    pub is_bare: Option<bool>,
    pub lossy: bool,
    pub object_hash: legix_hash::Kind,
    pub reflog: Option<legix_ref::store::WriteReflog>,
    pub precompose_unicode: bool,
    pub protect_windows: bool,
}

/// Initialization
impl StageOne {
    pub fn new(
        common_dir: &std::path::Path,
        git_dir: &std::path::Path,
        git_dir_trust: legix_sec::Trust,
        lossy: bool,
        lenient: bool,
    ) -> Result<Self> {
        let mut buf = Vec::with_capacity(512);
        let mut config = load_config(
            common_dir.join("config"),
            &mut buf,
            legix_config::Source::Local,
            git_dir_trust,
            lossy,
            lenient,
        )?;

        let is_bare = util::config_bool_opt(&config, &Core::BARE, "core.bare", lenient)?;
        let repo_format_version = Core::REPOSITORY_FORMAT_VERSION
            .try_into_usize(config.integer("core.repositoryFormatVersion"))?
            .unwrap_or_default();
        let object_hash = match (repo_format_version, config.string(Extensions::OBJECT_FORMAT)) {
            // objectFormat is a repository format version 1 extension.
            (1, Some(format)) => Extensions::OBJECT_FORMAT.try_into_object_format(format)?,
            (0, Some(_)) => {
                return Err(Error::from_error(legix_error::validation(
                    "extensions.objectFormat is a v1-only extension, but the repository format version is 0; set core.repositoryFormatVersion=1 to use it, or remove extensions.objectFormat to fall back to the default Sha1 format (if supported by this build)",
                )));
            }
            (0 | 1, None) => legacy_object_hash()?,
            (version, _) => {
                return Err(Error::from_error(legix_error::validation(format!(
                    "Unsupported repository format version {version}; only versions 0 and 1 are supported"
                ))));
            }
        };

        let extension_worktree = util::config_bool(
            &config,
            &Extensions::WORKTREE_CONFIG,
            "extensions.worktreeConfig",
            false,
            lenient,
        )?;
        if extension_worktree {
            let worktree_config = load_config(
                git_dir.join("config.worktree"),
                &mut buf,
                legix_config::Source::Worktree,
                git_dir_trust,
                lossy,
                lenient,
            )?;
            config.append(worktree_config).or_erased()?;
        }
        let precompose_unicode = Core::PRECOMPOSE_UNICODE
            .enrich_error(config.boolean(Core::PRECOMPOSE_UNICODE))
            .with_leniency(lenient)?
            .unwrap_or_default();

        const IS_WINDOWS: bool = cfg!(windows);
        let protect_windows = gitoxide::Core::PROTECT_WINDOWS
            .enrich_error(config.boolean(gitoxide::Core::PROTECT_WINDOWS))
            .with_lenient_default_value(lenient, Some(IS_WINDOWS))?
            .unwrap_or(IS_WINDOWS);

        let reflog = util::query_refupdates(&config, lenient)?;
        Ok(StageOne {
            git_dir_config: config,
            buf,
            is_bare,
            lossy,
            object_hash,
            reflog,
            precompose_unicode,
            protect_windows,
        })
    }
}

/// Return the object hash for a repository that does not set `extensions.objectFormat`.
///
/// Git interprets a missing objectFormat as the original Sha1 layout, so we return
/// legix_hash::Kind::Sha1 whenever this build can handle it.
/// In Sha256-only builds we cannot open such a repository, so return an error instead.
fn legacy_object_hash() -> Result<legix_hash::Kind> {
    #[cfg(feature = "sha1")]
    {
        Ok(legix_hash::Kind::Sha1)
    }
    #[cfg(not(feature = "sha1"))]
    {
        Err(Error::from_error(legix_error::validation(
            "Cannot handle objects formatted as \"sha1\"",
        )))
    }
}

fn load_config(
    config_path: std::path::PathBuf,
    buf: &mut Vec<u8>,
    source: legix_config::Source,
    git_dir_trust: legix_sec::Trust,
    lossy: bool,
    lenient: bool,
) -> Result<legix_config::File> {
    let metadata = legix_config::file::Metadata::from(source)
        .at(&config_path)
        .with(git_dir_trust);
    let mut file = match std::fs::File::open(&config_path) {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(legix_config::File::new(metadata)),
        Err(err) => {
            let err = Error::from(err.and_raise(legix_error::message!(
                "Could not read configuration file at \"{}\"",
                config_path.display()
            )));
            if lenient {
                legix_trace::warn!("ignoring: {err:#?}");
                return Ok(legix_config::File::new(metadata));
            } else {
                return Err(err);
            }
        }
    };

    buf.clear();
    if let Err(err) = std::io::copy(&mut file, buf) {
        let err = Error::from(err.and_raise(legix_error::message!(
            "Could not read configuration file at \"{}\"",
            config_path.display()
        )));
        if lenient {
            legix_trace::warn!("ignoring: {err:#?}");
            buf.clear();
        } else {
            return Err(err);
        }
    }

    let config = legix_config::File::from_bytes_owned(
        buf,
        metadata,
        legix_config::file::init::Options {
            includes: legix_config::file::includes::Options::no_follow(),
            ..util::base_options(lossy, lenient)
        },
    )?;

    Ok(config)
}

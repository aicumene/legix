use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail};
use legix::{NestedProgress, Progress, worktree::archive};

pub struct Options {
    pub format: Option<archive::Format>,
    pub files: Vec<(String, String)>,
    pub prefix: Option<String>,
    pub add_paths: Vec<PathBuf>,
}

pub fn stream(
    repo: legix::Repository,
    destination_path: &Path,
    rev_spec: Option<&str>,
    mut progress: impl NestedProgress,
    Options {
        format,
        prefix,
        add_paths,
        files,
    }: Options,
) -> anyhow::Result<()> {
    let format = format.map_or_else(|| format_from_ext(destination_path), Ok)?;
    let object = repo.rev_parse_single(rev_spec.unwrap_or("HEAD"))?.object()?;
    let (modification_date, tree) = fetch_rev_info(object)?;

    let start = std::time::Instant::now();
    let (mut stream, index) = repo.worktree_stream(tree)?;
    if !add_paths.is_empty() {
        let root = legix::path::realpath(
            repo.workdir()
                .ok_or_else(|| anyhow!("Adding files requires a worktree directory that contains them"))?,
        )?;
        for path in add_paths {
            stream.add_entry_from_path(&root, &legix::path::realpath(&path)?, repo.object_hash())?;
        }
    }
    for (path, content) in files {
        stream.add_entry(legix::worktree::stream::AdditionalEntry {
            id: legix::hash::Kind::Sha1.null(),
            mode: legix::object::tree::EntryKind::Blob.into(),
            relative_path: path.into(),
            source: legix::worktree::stream::entry::Source::Memory(content.into()),
        });
    }

    let mut entries = progress.add_child("entries");
    entries.init(Some(index.entries().len()), legix::progress::count("entries"));
    let mut bytes = progress.add_child("written");
    bytes.init(None, legix::progress::bytes());

    let mut file = legix::progress::Write {
        inner: std::io::BufWriter::with_capacity(128 * 1024, std::fs::File::create(destination_path)?),
        progress: &mut bytes,
    };
    repo.worktree_archive(
        stream,
        &mut file,
        &mut entries,
        &legix::interrupt::IS_INTERRUPTED,
        legix::worktree::archive::Options {
            format,
            tree_prefix: prefix.map(legix::bstr::BString::from),
            modification_time: modification_date.unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or_default() as legix::date::SecondsSinceUnixEpoch
            }),
        },
    )?;

    entries.show_throughput(start);
    bytes.show_throughput(start);

    Ok(())
}

fn fetch_rev_info(
    object: legix::Object<'_>,
) -> anyhow::Result<(Option<legix::date::SecondsSinceUnixEpoch>, legix::ObjectId)> {
    Ok(match object.kind {
        legix::object::Kind::Commit => {
            let commit = object.into_commit();
            (Some(commit.committer()?.seconds()), commit.tree_id()?.detach())
        }
        legix::object::Kind::Tree => (None, object.id),
        legix::object::Kind::Tag => fetch_rev_info(object.peel_to_kind(legix::object::Kind::Commit)?)?,
        legix::object::Kind::Blob => bail!("Cannot derive commit or tree from blob at {}", object.id),
    })
}

fn format_from_ext(path: &Path) -> anyhow::Result<archive::Format> {
    Ok(match path.extension().and_then(std::ffi::OsStr::to_str) {
        None => bail!("Cannot derive archive format from a file without extension"),
        Some("tar") => archive::Format::Tar,
        Some("gz") => archive::Format::TarGz {
            compression_level: None,
        },
        Some("zip") => archive::Format::Zip {
            compression_level: None,
        },
        Some("stream") => archive::Format::InternalTransientNonPersistable,
        Some(ext) => bail!("Format for extension '{ext}' is unsupported"),
    })
}

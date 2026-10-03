//! Packs: the objects a bundle carries, counted and written from the repository, and stored into it on arrival.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    io::{self, BufRead, Read, Write},
    sync::atomic::AtomicBool,
};

use legix::{
    ObjectId, Repository,
    bstr::{BString, ByteSlice},
    objs::Kind,
    refs::{
        FullName, Target,
        transaction::{Change, LogChange, PreviousValue, RefEdit, RefLog},
    },
};
use legix_crypt::{Oid, Pointer};
use legix_pack::data::output;

use crate::{DeviceId, Error, Problem, error::repository};

/// What a bundle carries.
pub(crate) struct Outgoing {
    /// The objects to pack.
    pub counts: Vec<output::Count>,
    /// The objects outside the pack that the snapshot needs.
    pub prerequisites: Vec<ObjectId>,
    /// The documents the new blobs point to.
    pub documents: BTreeSet<Oid>,
}

/// The objects new in `snapshot` compared with `haves`: the new commits, their trees and what they add compared with
/// their parents, and new annotated tags.
pub(crate) fn outgoing(
    repo: &Repository,
    snapshot: &BTreeMap<BString, ObjectId>,
    haves: &[ObjectId],
) -> Result<Outgoing, Error> {
    let have_ids: HashSet<ObjectId> = haves.iter().copied().collect();
    let mut have_commits = Vec::new();
    for id in haves {
        if let Some((commit, _)) = peel(repo, *id)? {
            have_commits.push(commit);
        }
    }

    let mut tips = Vec::new();
    let mut tags = Vec::new();
    for id in snapshot.values() {
        let Some((commit, chain)) = peel(repo, *id)? else {
            continue;
        };
        tips.push(commit);
        tags.extend(chain.into_iter().filter(|tag| !have_ids.contains(tag)));
    }

    let mut new_commits = Vec::new();
    let mut parents = Vec::new();
    let walk = repo
        .rev_walk(tips)
        .with_hidden(have_commits)
        .all()
        .map_err(repository)?;
    for info in walk {
        let info = info.map_err(repository)?;
        new_commits.push(info.id);
        parents.extend(info.parent_ids.iter().copied());
    }
    let new: HashSet<ObjectId> = new_commits.iter().copied().collect();

    let db: &dyn legix_pack::Find = &*repo.objects;
    let mut inputs = new_commits
        .iter()
        .chain(&tags)
        .map(|id| -> legix::ExnResult<ObjectId> { Ok(*id) });
    let (counts, _) = output::count::objects_unthreaded(
        db,
        &mut inputs,
        &legix::progress::Discard,
        &AtomicBool::new(false),
        output::count::objects::ObjectExpansion::TreeAdditionsComparedToAncestor,
    )
    .map_err(repository)?;
    // Counting adds the parents of new commits and their trees, which the other devices have: they are left out.
    let boundary: BTreeSet<ObjectId> = parents.into_iter().filter(|id| !new.contains(id)).collect();
    let mut old = HashSet::new();
    for commit in &boundary {
        old.insert(*commit);
        let tree = repo
            .find_commit(*commit)
            .map_err(repository)?
            .tree_id()
            .map_err(repository)?;
        old.insert(tree.detach());
    }
    let mut counts = counts;
    counts.retain(|count| !old.contains(&count.id));
    let counted: HashSet<ObjectId> = counts.iter().map(|count| count.id).collect();

    let mut prerequisites = boundary;
    prerequisites.extend(snapshot.values().filter(|id| !counted.contains(*id)));
    for tag in &tags {
        if let Some((commit, _)) = peel(repo, *tag)?
            && !new.contains(&commit)
        {
            prerequisites.insert(commit);
        }
    }

    let mut documents = BTreeSet::new();
    for count in &counts {
        let header = repo.find_header(count.id).map_err(repository)?;
        if header.kind() == Kind::Blob && header.size() <= Pointer::MAX_LEN as u64 {
            let object = repo.find_object(count.id).map_err(repository)?;
            if let Ok(pointer) = Pointer::parse(&object.data) {
                documents.insert(pointer.oid);
            }
        }
    }

    Ok(Outgoing {
        counts,
        prerequisites: prerequisites.into_iter().collect(),
        documents,
    })
}

/// Write the counted objects as a pack of whole objects, one after the other.
pub(crate) fn write_pack(repo: &Repository, counts: &[output::Count], out: &mut dyn Write) -> Result<(), Error> {
    let entries = u32::try_from(counts.len()).map_err(|_| Error::Repository("too many objects for one pack".into()))?;
    let compression = repo.pack_compression().map_err(repository)?;
    let kind = repo.object_hash();
    let mut failure = None;
    let input = counts.iter().map_while(|count| {
        let entry = repo.find_object(count.id).map_err(repository).and_then(|object| {
            output::Entry::from_data(
                count,
                &legix::objs::Data::new(&object.data, object.kind, kind),
                compression,
            )
            .map_err(repository)
        });
        match entry {
            Ok(entry) => Some(Ok(vec![entry])),
            Err(err) => {
                failure = Some(err);
                None
            }
        }
    });
    let mut pack = output::bytes::FromEntriesIter::new(input, out, entries, legix_pack::data::Version::default(), kind);
    let mut written = Ok(());
    for result in pack.by_ref() {
        if let Err(err) = result {
            written = Err(repository(err));
            break;
        }
    }
    drop(pack);
    match failure {
        Some(err) => Err(err),
        None => written,
    }
}

/// Store a pack into the repository's object database, and return how many objects it holds.
pub(crate) fn store_pack(repo: &Repository, pack: &mut dyn BufRead) -> Result<u32, Problem> {
    let mut header = [0; 12];
    pack.read_exact(&mut header)
        .map_err(|_| Problem::Pack("it is shorter than a pack header".into()))?;
    if &header[..4] != b"PACK" {
        return Err(Problem::Pack("it does not start with `PACK`".into()));
    }
    let objects = u32::from_be_bytes(header[8..].try_into().expect("4 bytes"));
    if objects == 0 {
        return Ok(0);
    }
    let mut stream = io::BufReader::new(io::Cursor::new(header).chain(pack));
    legix_pack::Bundle::write_to_directory(
        &mut stream,
        Some(&repo.objects.store_ref().path().join("pack")),
        &mut legix::progress::Discard,
        &AtomicBool::new(false),
        Some(repo.objects.clone()),
        repo.object_hash(),
        Default::default(),
    )
    .map_err(|err| Problem::Pack(err.to_string()))?;
    Ok(objects)
}

/// Check that every ref leads to a commit and that the commits new compared with `prerequisites` are complete: their
/// trees and everything in them are in the repository.
pub(crate) fn check_complete(
    repo: &Repository,
    refs: &[(BString, ObjectId)],
    prerequisites: &[ObjectId],
) -> Result<(), Problem> {
    let mut tips = Vec::new();
    for (name, id) in refs {
        match peel(repo, *id) {
            Ok(Some((commit, _))) => tips.push(commit),
            Ok(None) => return Err(Problem::Body(format!("{name} does not lead to a commit"))),
            Err(_) => return Err(Problem::Incomplete(*id)),
        }
    }
    let mut hidden = Vec::new();
    for id in prerequisites {
        if let Ok(Some((commit, _))) = peel(repo, *id) {
            hidden.push(commit);
        }
    }
    let walk = repo
        .rev_walk(tips)
        .with_hidden(hidden)
        .all()
        .map_err(|err| Problem::Pack(err.to_string()))?;
    let mut seen = HashSet::new();
    for info in walk {
        let info = info.map_err(|err| Problem::Pack(err.to_string()))?;
        let commit = repo.find_commit(info.id).map_err(|_| Problem::Incomplete(info.id))?;
        let tree = commit.tree_id().map_err(|_| Problem::Incomplete(info.id))?.detach();
        check_tree(repo, tree, &mut seen)?;
    }
    Ok(())
}

fn check_tree(repo: &Repository, id: ObjectId, seen: &mut HashSet<ObjectId>) -> Result<(), Problem> {
    if !seen.insert(id) {
        return Ok(());
    }
    let tree = repo.find_tree(id).map_err(|_| Problem::Incomplete(id))?;
    for entry in tree.iter() {
        let entry = entry.map_err(|_| Problem::Incomplete(id))?;
        let oid = entry.oid().to_owned();
        let mode = entry.mode();
        if mode.is_tree() {
            check_tree(repo, oid, seen)?;
        } else if mode.is_commit() {
            // A submodule's commit lives in another repository.
        } else if seen.insert(oid) && !repo.has_object(oid) {
            return Err(Problem::Incomplete(oid));
        }
    }
    Ok(())
}

/// Set the refs of `device` to its snapshot: `refs/heads/x` becomes `refs/legix/devices/<device>/heads/x`, and refs of
/// the device that are not in the snapshot are deleted.
pub(crate) fn set_device_refs(
    repo: &Repository,
    device: &DeviceId,
    seq: u64,
    refs: &[(BString, ObjectId)],
) -> Result<(), Error> {
    let namespace = device_namespace(device);
    let message: BString = format!("legix-sync: bundle {seq} of {device}").into();
    let mut keep = HashSet::new();
    let mut edits = Vec::new();
    for (name, id) in refs {
        let rest = name.strip_prefix(b"refs/").expect("checked to be a branch or a tag");
        let full = FullName::try_from(BString::from([namespace.as_bytes(), rest].concat())).map_err(repository)?;
        keep.insert(full.clone());
        edits.push(RefEdit {
            change: Change::Update {
                log: LogChange {
                    mode: RefLog::AndReference,
                    force_create_reflog: false,
                    message: message.clone(),
                },
                expected: PreviousValue::Any,
                new: Target::Object(*id),
            },
            name: full,
            deref: false,
        });
    }
    let references = repo.references().map_err(repository)?;
    for reference in references.prefixed(namespace.as_str()).map_err(repository)? {
        let reference = reference.map_err(repository)?;
        if !keep.contains(reference.name()) {
            edits.push(RefEdit {
                change: Change::Delete {
                    expected: PreviousValue::Any,
                    log: RefLog::AndReference,
                },
                name: reference.name().to_owned(),
                deref: false,
            });
        }
    }
    repo.edit_references(edits).map_err(repository)?;
    Ok(())
}

/// Where the refs of `device` are kept.
pub(crate) fn device_namespace(device: &DeviceId) -> String {
    format!("refs/legix/devices/{device}/")
}

/// Whether `id` leads to a commit, through any annotated tags.
pub(crate) fn peels_to_commit(repo: &Repository, id: ObjectId) -> Result<bool, Error> {
    Ok(peel(repo, id)?.is_some())
}

/// Follow `id` through annotated tags: the commit it leads to and the tags on the way, or `None` if it leads to
/// something else.
fn peel(repo: &Repository, mut id: ObjectId) -> Result<Option<(ObjectId, Vec<ObjectId>)>, Error> {
    let mut tags = Vec::new();
    loop {
        let object = repo.find_object(id).map_err(repository)?;
        match object.kind {
            Kind::Commit => return Ok(Some((id, tags))),
            Kind::Tag => {
                tags.push(id);
                id = object
                    .try_into_tag()
                    .map_err(repository)?
                    .target_id()
                    .map_err(repository)?
                    .detach();
            }
            Kind::Tree | Kind::Blob => return Ok(None),
        }
    }
}

/// The branches and tags under `namespace` that lead to commits, by full name.
pub(crate) fn refs_under(repo: &Repository, namespace: &str) -> Result<BTreeMap<BString, ObjectId>, Error> {
    let mut refs = BTreeMap::new();
    let references = repo.references().map_err(repository)?;
    for reference in references.prefixed(namespace).map_err(repository)? {
        let reference = reference.map_err(repository)?;
        let Some(id) = reference.try_id() else {
            continue;
        };
        let name = reference.name().as_bstr();
        // The sync state keeps names as text.
        if name.to_str().is_err() {
            continue;
        }
        if peels_to_commit(repo, id.detach())? {
            refs.insert(name.to_owned(), id.detach());
        }
    }
    Ok(refs)
}

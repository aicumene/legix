//! The plaintext of a body: the documents and erasures, then a git bundle — its header here, its pack after it.

use std::{
    collections::BTreeSet,
    io::{self, BufRead, Read, Write},
};

use legix::{ObjectId, bstr::BString, hash::Kind};
use legix_crypt::Oid;

/// What a body says besides its git bundle.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Manifest {
    /// The documents the bundle's new commits point to.
    pub documents: BTreeSet<Oid>,
    /// The documents the device erased since its previous bundle.
    pub erased: BTreeSet<Oid>,
}

/// The header of the git bundle in a body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GitBundle {
    /// Objects the snapshot needs that are not in the pack.
    pub prerequisites: Vec<ObjectId>,
    /// The device's branches and tags.
    pub refs: Vec<(BString, ObjectId)>,
}

/// The longest line a body's header may have.
const MAX_LINE: u64 = 4096;

/// Write the manifest and the header of the git bundle; the pack follows.
pub(crate) fn write_header(
    out: &mut impl Write,
    manifest: &Manifest,
    bundle: &GitBundle,
    kind: Kind,
) -> io::Result<()> {
    for oid in &manifest.documents {
        writeln!(out, "document {oid}")?;
    }
    for oid in &manifest.erased {
        writeln!(out, "erased {oid}")?;
    }
    out.write_all(b"\n")?;
    if kind == Kind::Sha1 {
        out.write_all(b"# v2 git bundle\n")?;
    } else {
        out.write_all(b"# v3 git bundle\n@object-format=sha256\n")?;
    }
    for id in &bundle.prerequisites {
        writeln!(out, "-{id} ")?;
    }
    for (name, id) in &bundle.refs {
        write!(out, "{id} ")?;
        out.write_all(name)?;
        out.write_all(b"\n")?;
    }
    out.write_all(b"\n")
}

/// Read the manifest and the header of the git bundle, and leave `input` at the start of the pack.
pub(crate) fn read_header(input: &mut impl BufRead, kind: Kind) -> Result<(Manifest, GitBundle), &'static str> {
    let mut manifest = Manifest::default();
    loop {
        let line = read_line(input)?;
        if line.is_empty() {
            break;
        }
        if let Some(oid) = line.strip_prefix("document ") {
            if !manifest.erased.is_empty() {
                return Err("`document` lines come before `erased` lines");
            }
            push_sorted(&mut manifest.documents, oid)?;
        } else if let Some(oid) = line.strip_prefix("erased ") {
            push_sorted(&mut manifest.erased, oid)?;
        } else {
            return Err("a line before the git bundle is neither `document` nor `erased`");
        }
    }

    let signature = read_line(input)?;
    let expected = if kind == Kind::Sha1 {
        signature == "# v2 git bundle"
    } else {
        signature == "# v3 git bundle" && read_line(input)? == "@object-format=sha256"
    };
    if !expected {
        return Err("the git bundle is not of the repository's version and object format");
    }

    let hex_len = kind.len_in_hex();
    let parse_id = |hex: &str| {
        ObjectId::from_hex(hex.as_bytes())
            .ok()
            .filter(|id| id.kind() == kind && hex.bytes().all(|b| !b.is_ascii_uppercase()))
            .ok_or("an object id in the git bundle is not of the repository's object format")
    };
    let mut bundle = GitBundle::default();
    loop {
        let line = read_line(input)?;
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line.strip_prefix('-') {
            if !bundle.refs.is_empty() {
                return Err("prerequisites come before refs");
            }
            let (hex, comment) = rest.split_at_checked(hex_len).ok_or("a prerequisite is cut short")?;
            if !(comment.is_empty() || comment.starts_with(' ')) {
                return Err("a prerequisite's id is followed by more than a comment");
            }
            bundle.prerequisites.push(parse_id(hex)?);
        } else {
            let (hex, name) = line.split_once(' ').ok_or("a ref line is not `<id> <name>`")?;
            bundle.refs.push((name.into(), parse_id(hex)?));
        }
    }
    Ok((manifest, bundle))
}

fn push_sorted(set: &mut BTreeSet<Oid>, text: &str) -> Result<(), &'static str> {
    let oid: Oid = text
        .parse()
        .map_err(|_| "a document id is not `blake3:` and 64 hex digits")?;
    if set.last().is_some_and(|last| *last >= oid) {
        return Err("document ids are not sorted, or repeat");
    }
    set.insert(oid);
    Ok(())
}

/// A line without its line feed. A line that does not end before [`MAX_LINE`] bytes or before the input does is refused.
fn read_line(input: &mut impl BufRead) -> Result<String, &'static str> {
    let mut line = Vec::new();
    input
        .by_ref()
        .take(MAX_LINE)
        .read_until(b'\n', &mut line)
        .map_err(|_| "it cannot be read")?;
    if line.pop() != Some(b'\n') {
        return Err("a line is cut short or too long");
    }
    String::from_utf8(line).map_err(|_| "a line is not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha1(n: u8) -> ObjectId {
        ObjectId::from_bytes_or_panic(&[n; 20])
    }

    fn sha256(n: u8) -> ObjectId {
        ObjectId::from_bytes_or_panic(&[n; 32])
    }

    fn header(manifest: &Manifest, bundle: &GitBundle, kind: Kind) -> Vec<u8> {
        let mut out = Vec::new();
        write_header(&mut out, manifest, bundle, kind).unwrap();
        out
    }

    fn read(text: &[u8], kind: Kind) -> Result<(Manifest, GitBundle), &'static str> {
        read_header(&mut &text[..], kind)
    }

    #[test]
    fn a_header_reads_back_and_its_git_bundle_part_is_gits_format() {
        let manifest = Manifest {
            documents: [Oid::of(b"a"), Oid::of(b"b")].into(),
            erased: [Oid::of(b"c")].into(),
        };
        for (kind, id, signature) in [
            (Kind::Sha1, sha1 as fn(u8) -> ObjectId, "# v2 git bundle\n"),
            (Kind::Sha256, sha256, "# v3 git bundle\n@object-format=sha256\n"),
        ] {
            let bundle = GitBundle {
                prerequisites: vec![id(1)],
                refs: vec![("refs/heads/main".into(), id(2)), ("refs/tags/v1".into(), id(3))],
            };
            let text = header(&manifest, &bundle, kind);
            let git_part = &text[text.windows(2).position(|w| w == b"\n\n").unwrap() + 2..];
            assert!(git_part.starts_with(signature.as_bytes()));
            assert!(git_part.ends_with(format!("\n{} refs/tags/v1\n\n", id(3)).as_bytes()));
            assert_eq!(read(&text, kind).unwrap(), (manifest.clone(), bundle));
        }
        let empty = header(&Manifest::default(), &GitBundle::default(), Kind::Sha1);
        assert_eq!(empty, b"\n# v2 git bundle\n\n");
        assert_eq!(read(&empty, Kind::Sha1).unwrap(), Default::default());
    }

    #[test]
    fn anything_else_before_the_pack_is_refused() {
        let (a, b) = (Oid::of(b"a").max(Oid::of(b"b")), Oid::of(b"a").min(Oid::of(b"b")));
        let line = "x".repeat(5000);
        for (text, what) in [
            (
                format!("document {a}\ndocument {b}\n\n# v2 git bundle\n\n"),
                "unsorted documents",
            ),
            (
                format!("document {b}\ndocument {b}\n\n# v2 git bundle\n\n"),
                "a repeated document",
            ),
            (
                format!("erased {b}\ndocument {a}\n\n# v2 git bundle\n\n"),
                "erased before documents",
            ),
            (format!("comment {b}\n\n# v2 git bundle\n\n"), "another line"),
            ("\n# v3 git bundle\n\n".into(), "another version"),
            (
                format!("\n# v2 git bundle\n{} refs/heads/main\n-{}\n\n", sha1(1), sha1(2)),
                "a ref before a prerequisite",
            ),
            (
                format!(
                    "\n# v2 git bundle\n{} refs/heads/main\n\n",
                    sha1(0xab).to_string().to_uppercase()
                ),
                "upper-case hex",
            ),
            (
                format!("\n# v2 git bundle\n{} refs/heads/main\n\n", sha256(1)),
                "another object format",
            ),
            (
                format!("\n# v2 git bundle\n-{}x\n\n", sha1(1)),
                "a prerequisite without a space before its comment",
            ),
            ("\n# v2 git bundle\n".into(), "cut short"),
            (format!("{line}\n\n# v2 git bundle\n\n"), "a line too long"),
        ] {
            assert!(read(text.as_bytes(), Kind::Sha1).is_err(), "{what}");
        }
        let with_comment = format!("\n# v2 git bundle\n-{} the commit's subject\n\n", sha1(1));
        assert_eq!(
            read(with_comment.as_bytes(), Kind::Sha1).unwrap().1.prerequisites,
            vec![sha1(1)]
        );
    }
}

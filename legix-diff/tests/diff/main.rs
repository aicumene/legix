use legix_testtools::Result;
pub use legix_testtools::{normalize_debug_snapshot, scripted_fixture_read_only, scripted_fixture_read_only_with_args};
use std::collections::HashMap;

fn hex_to_id(hex_sha1: &str, hex_sha256: &str) -> legix_hash::ObjectId {
    match legix_testtools::object_hash() {
        legix_hash::Kind::Sha1 => legix_hash::ObjectId::from_hex(hex_sha1.as_bytes()).expect("40 bytes hex"),
        legix_hash::Kind::Sha256 => legix_hash::ObjectId::from_hex(hex_sha256.as_bytes()).expect("64 bytes hex"),
        _ => unimplemented!(),
    }
}

fn fixture_hash_kind() -> legix_hash::Kind {
    legix_testtools::object_hash()
}

fn open_odb(objects_dir: impl Into<std::path::PathBuf>) -> std::io::Result<legix_odb::Handle> {
    legix_odb::at(objects_dir, fixture_hash_kind())
}

fn normalize_patch_snapshot(input: &str) -> String {
    fn normalize_hex_token<'a>(token: &'a str, seen: &mut HashMap<&'a str, usize>, next_id: &mut usize) -> String {
        if token == "0000000" || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return token.to_owned();
        }
        let normalized = *seen.entry(token).or_insert_with(|| {
            let current = *next_id;
            *next_id += 1;
            current
        });
        format!("Oid({normalized})")
    }

    let mut seen = HashMap::<&str, usize>::new();
    let mut next_id = 1usize;

    input
        .lines()
        .map(|line| {
            if let Some(commit) = line.strip_prefix("commit ") {
                return format!("commit {}", normalize_hex_token(commit, &mut seen, &mut next_id));
            }

            if let Some(index) = line.strip_prefix("index ") {
                let (range, mode) = index
                    .split_once(' ')
                    .map_or((index, None), |(range, mode)| (range, Some(mode)));
                if let Some((lhs, rhs)) = range.split_once("..") {
                    let lhs = normalize_hex_token(lhs, &mut seen, &mut next_id);
                    let rhs = normalize_hex_token(rhs, &mut seen, &mut next_id);
                    return match mode {
                        Some(mode) => format!("index {lhs}..{rhs} {mode}"),
                        None => format!("index {lhs}..{rhs}"),
                    };
                }
            }

            line.to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_owned()
}

fn assert_hash_agnostic_patch_eq(actual: &str, expected: &str) {
    pretty_assertions::assert_eq!(normalize_patch_snapshot(expected), normalize_patch_snapshot(actual));
}

mod blob;
mod index;
mod rewrites;
mod tree;
mod tree_with_rewrites;

mod util {
    use legix_error::ExnResult;
    use legix_object::Write;

    pub type ObjectDb = legix_odb::memory::Proxy<legix_object::find::Never>;

    pub fn object_db() -> ObjectDb {
        legix_odb::memory::Proxy::new(legix_object::find::Never, super::fixture_hash_kind())
    }

    /// Insert `data` and return its hash. That can be used to find it again.
    pub fn insert(db: &ObjectDb, data: &str) -> ExnResult<legix_hash::ObjectId> {
        db.write_buf(legix_object::Kind::Blob, data.as_bytes())
    }
}

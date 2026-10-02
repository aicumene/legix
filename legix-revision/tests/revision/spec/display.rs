use crate::hex_to_id;

fn oid() -> legix_hash::ObjectId {
    hex_to_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
}

fn oid2() -> legix_hash::ObjectId {
    hex_to_id("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
}

#[test]
fn include() {
    let expected = match legix_testtools::object_hash() {
        legix_hash::Kind::Sha1 => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        legix_hash::Kind::Sha256 => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        _ => unimplemented!(),
    };
    assert_eq!(legix_revision::Spec::Include(oid()).to_string(), expected);
}

#[test]
fn exclude() {
    let expected = match legix_testtools::object_hash() {
        legix_hash::Kind::Sha1 => "^aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        legix_hash::Kind::Sha256 => "^aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        _ => unimplemented!(),
    };
    assert_eq!(legix_revision::Spec::Exclude(oid()).to_string(), expected);
}

#[test]
fn range() {
    let expected = match legix_testtools::object_hash() {
        legix_hash::Kind::Sha1 => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa..bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        legix_hash::Kind::Sha256 => {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa..bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }
        _ => unimplemented!(),
    };
    assert_eq!(
        legix_revision::Spec::Range {
            from: oid(),
            to: oid2()
        }
        .to_string(),
        expected
    );
}

#[test]
fn merge() {
    let expected = match legix_testtools::object_hash() {
        legix_hash::Kind::Sha1 => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa...bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        legix_hash::Kind::Sha256 => {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa...bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }
        _ => unimplemented!(),
    };
    assert_eq!(
        legix_revision::Spec::Merge {
            theirs: oid(),
            ours: oid2()
        }
        .to_string(),
        expected
    );
}

#[test]
fn include_parents() {
    let expected = match legix_testtools::object_hash() {
        legix_hash::Kind::Sha1 => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa^@",
        legix_hash::Kind::Sha256 => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa^@",
        _ => unimplemented!(),
    };
    assert_eq!(legix_revision::Spec::IncludeOnlyParents(oid()).to_string(), expected);
}

#[test]
fn exclude_parents() {
    let expected = match legix_testtools::object_hash() {
        legix_hash::Kind::Sha1 => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa^!",
        legix_hash::Kind::Sha256 => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa^!",
        _ => unimplemented!(),
    };
    assert_eq!(legix_revision::Spec::ExcludeParents(oid()).to_string(), expected);
}

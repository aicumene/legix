use std::collections::{BTreeSet, HashSet};

use legix_refspec::{RefSpec, parse::Operation};

fn pair() -> Vec<RefSpec> {
    let lhs = legix_refspec::parse("refs/heads/foo".into(), Operation::Push).unwrap();
    let rhs = legix_refspec::parse("refs/heads/foo:refs/heads/foo".into(), Operation::Push).unwrap();
    vec![lhs.to_owned(), rhs.to_owned()]
}

#[test]
fn cmp() {
    assert_eq!(BTreeSet::from_iter(pair()).len(), 1);
}

#[test]
fn hash() {
    let set: HashSet<_> = pair().into_iter().collect();
    assert_eq!(set.len(), 1);
}

#[test]
fn eq() {
    let specs = pair();
    assert_eq!(&specs[0], &specs[1]);
}

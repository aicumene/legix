use crate::Result;
use legix_object::Write;

use crate::store::loose::{locate_oid, object_ids};

#[test]
fn write() -> Result {
    let mut buf = Vec::new();
    for oid in object_ids() {
        let obj = locate_oid(oid, &mut buf);
        let actual = legix_odb::sink(legix_hash::Kind::Sha1).write(&obj.decode()?)?;
        assert_eq!(actual, oid);
    }
    Ok(())
}

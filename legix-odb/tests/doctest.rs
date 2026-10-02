// Shared setup for crate-level doctests in `src/lib.rs`.
// This file is included there, and not part of the test harness.

/// Return an empty object database that lives as long as its temporary directory.
pub fn empty_store() -> Result<(tempfile::TempDir, legix_odb::Handle), std::io::Error> {
    let dir = tempfile::tempdir()?;
    let store = legix_odb::at(dir.path(), legix_testtools::object_hash())?;
    Ok((dir, store))
}

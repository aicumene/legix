mod builtin_driver;
mod pipeline;
mod platform;

mod util {
    use legix_error::ExnResult;
    use legix_object::Write;

    pub type ObjectDb = legix_odb::memory::Proxy<legix_object::find::Never>;

    pub fn object_db() -> ObjectDb {
        legix_odb::memory::Proxy::new(legix_object::find::Never, legix_hash::Kind::Sha1)
    }

    /// Insert `data` and return its hash. That can be used to find it again.
    pub fn insert(db: &ObjectDb, data: &str) -> ExnResult<legix_hash::ObjectId> {
        db.write_buf(legix_object::Kind::Blob, data.as_bytes())
    }
}

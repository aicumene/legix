pub(crate) fn existing_error(err: legix_error::Exn) -> legix_error::Error {
    err.into_error()
}

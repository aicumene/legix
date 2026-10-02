///
pub mod entry;
///
pub mod header;

/// A ref-delta base that could not be resolved.
///
/// Its source is a classification-only [`legix_error::ClassificationMarker`].
/// Use [`legix_error::classify()`] or `is_not_found()` on [`legix_error::Exn`] and [`legix_error::Error`] to check the
/// classification, without depending on the concrete diagnostic type. Downcast to this type for the base object ID.
#[derive(Debug)]
pub struct DeltaBaseUnresolved(
    /// The object ID named by the ref-delta.
    pub legix_hash::ObjectId,
);

impl std::fmt::Display for DeltaBaseUnresolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "A delta chain could not be followed as the ref base with id {} could not be found",
            self.0
        )
    }
}

impl std::error::Error for DeltaBaseUnresolved {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(const { &legix_error::ClassificationMarker::NOT_FOUND })
    }
}

#[cold]
pub(super) fn allocation_error(kind: legix_error::ResourceExhaustionKind) -> legix_error::Exn {
    use legix_error::ErrorExt;
    legix_error::resource_exhaustion(kind, "Entry too large to fit in memory").raise_erased()
}

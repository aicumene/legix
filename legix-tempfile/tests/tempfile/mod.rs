mod handle;

#[cfg(feature = "signals")]
mod setup {
    #[test]
    fn can_be_called_multiple_times() {
        // we could probably be smart and figure out that this does the right thing, but… it's good enough it won't fail ;).
        legix_tempfile::signal::setup(legix_tempfile::signal::handler::Mode::DeleteTempfilesOnTermination);
        legix_tempfile::signal::setup(
            legix_tempfile::signal::handler::Mode::DeleteTempfilesOnTerminationAndRestoreDefaultBehaviour,
        );
    }
}

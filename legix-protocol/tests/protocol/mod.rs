pub type Result = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

pub fn fixture_bytes(path: &str) -> Vec<u8> {
    std::fs::read(std::path::PathBuf::from("tests").join("fixtures").join(path))
        .expect("fixture to be present and readable")
}

mod command;
pub mod fetch;
mod handshake;
pub use fetch::_impl::{FetchConnection, fetch};
pub mod remote_progress;

#[legix_protocol::bisync::bisync]
#[cfg_attr(feature = "blocking-client", test)]
#[cfg_attr(all(feature = "async-client", not(feature = "blocking-client")), async_std::test)]
async fn the_same_test_body_runs_in_both_client_modes() {
    #[legix_protocol::bisync::only_sync]
    fn identity(value: u8) -> u8 {
        value
    }
    #[legix_protocol::bisync::only_async]
    fn identity(value: u8) -> impl std::future::Future<Output = u8> {
        std::future::ready(value)
    }

    assert_eq!(identity(42).await, 42);
}

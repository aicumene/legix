#![deny(unsafe_code)]

#[cfg(feature = "pretty-cli")]
fn main() -> anyhow::Result<()> {
    legix_cli::plumbing::main()
}

#[cfg(not(feature = "pretty-cli"))]
compile_error!("Please set 'pretty-cli' feature flag");

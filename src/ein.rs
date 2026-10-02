#![deny(unsafe_code)]

fn main() -> anyhow::Result<()> {
    legix_cli::porcelain::main()
}

#[cfg(not(feature = "pretty-cli"))]
compile_error!("Please set 'pretty-cli' feature flag");

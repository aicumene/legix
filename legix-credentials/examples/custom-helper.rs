use legix_credentials::{program, protocol};
use legix_error::ErrorExt;
use legix_error::ExnResult;

/// Run like this `echo url=https://example.com | cargo run --example custom-helper -- get`
pub fn main() -> ExnResult {
    legix_credentials::program::main(
        std::env::args_os().skip(1),
        std::io::stdin(),
        std::io::stdout(),
        protocol::ContextOptions::default(),
        |action, context| -> ExnResult<_> {
            match action {
                program::main::Action::Get => Ok(Some(protocol::Context {
                    username: Some("user".into()),
                    password: Some("pass".into()),
                    ..context
                })),
                program::main::Action::Erase => {
                    Err(legix_error::message("Refusing to delete credentials for demo purposes").raise_erased())
                }
                program::main::Action::Store => Ok(None),
            }
        },
    )
}

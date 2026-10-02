use legix_error::ExnResult;
/// Run like this `echo url=https://example.com | cargo run --example git-credential-light -- fill`
pub fn main() -> ExnResult {
    legix_credentials::program::main(
        std::env::args_os().skip(1),
        std::io::stdin(),
        std::io::stdout(),
        legix_credentials::protocol::ContextOptions::default(),
        |action, context| {
            use legix_credentials::program::main::Action::*;
            legix_credentials::helper::Cascade::default()
                .invoke(
                    match action {
                        Get => legix_credentials::helper::Action::Get(context),
                        Erase => legix_credentials::helper::Action::Erase(context.to_bstring()),
                        Store => legix_credentials::helper::Action::Store(context.to_bstring()),
                    },
                    legix_prompt::Options::default().apply_environment(true, true, true),
                )
                .map(|outcome| outcome.and_then(|outcome| (&outcome.next).try_into().ok()))
        },
    )
}

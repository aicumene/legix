use legix::ExnResult;
pub fn function(repo: Option<legix::Repository>, action: legix::credentials::program::main::Action) -> anyhow::Result<()> {
    use legix::credentials::program::main::Action::*;
    use legix::error::{OptionExt, ResultExt, message};
    legix::credentials::program::main(
        Some(action.as_str().into()),
        std::io::stdin(),
        std::io::stdout(),
        legix::credentials::protocol::ContextOptions::default(),
        |action, context| -> ExnResult<_> {
            let url = context
                .url
                .clone()
                .or_else(|| context.to_url())
                .ok_or_raise_erased(|| {
                    legix::error::validation("Either 'url' field or both 'protocol' and 'host' fields must be provided")
                })?;

            let url = legix::url::parse(&url).or_erased()?;
            let (mut cascade, _action, prompt_options) = match repo {
                Some(ref repo) => repo
                    .config_snapshot()
                    .credential_helpers(url)
                    .or_raise_erased(|| message("Could not configure credential helpers"))?,
                None => {
                    let config = legix::config::File::from_globals()
                        .or_raise_erased(|| message("Could not load global configuration"))?;
                    let environment = legix::open::permissions::Environment::all();
                    legix::config::credential_helpers(
                        url,
                        &config,
                        false,    /* lenient config */
                        |_| true, /* section filter */
                        environment,
                        false, /* use http path (override, uses configuration now)*/
                    )
                    .or_raise_erased(|| message("Could not configure credential helpers"))?
                }
            };
            cascade
                .invoke(
                    match action {
                        Get => legix::credentials::helper::Action::Get(context),
                        Erase => legix::credentials::helper::Action::Erase(context.to_bstring()),
                        Store => legix::credentials::helper::Action::Store(context.to_bstring()),
                    },
                    prompt_options,
                )
                .map(|outcome| outcome.and_then(|outcome| (&outcome.next).try_into().ok()))
        },
    )
    .map_err(legix::Exn::into_error)?;
    Ok(())
}

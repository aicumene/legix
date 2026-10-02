/// Invokes `git credential` with the passed url as argument and prints obtained credentials.
pub fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let out = legix_credentials::builtin(legix_credentials::helper::Action::get_for_url(
        std::env::args()
            .nth(1)
            .ok_or("First argument must be the URL to obtain credentials for")?,
    ))?
    .ok_or("Did not obtain credentials")?;
    let ctx: legix_credentials::protocol::Context = (&out.next).try_into()?;
    ctx.write_to(std::io::stdout())?;
    Ok(())
}

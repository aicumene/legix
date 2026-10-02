use legix_error::ExnMessageResult;
fn main() -> ExnMessageResult {
    let user = legix_prompt::openly("Username: ")?;
    eprintln!("{user:?}");
    let pass = legix_prompt::securely("Password: ")?;
    eprintln!("{pass:?}");
    Ok(())
}

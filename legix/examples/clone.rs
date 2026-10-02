// Clone a repository from any URL or Path to a given target directory

use anyhow::Context;

fn main() -> anyhow::Result<()> {
    let repo_url = std::env::args_os()
        .nth(1)
        .context("The first argument is the repository URL")?;

    let dst = std::env::args_os()
        .nth(2)
        .context("The second argument is the directory to clone the repository into")?;

    // SAFETY: The closure doesn't use mutexes or memory allocation, so it should be safe to call from a signal handler.
    unsafe {
        legix::interrupt::init_handler(1, || {})?;
    }
    std::fs::create_dir_all(&dst)?;
    let repo_url = repo_url.to_str().context("The repository URL must be valid UTF-8")?;
    let url = legix::url::parse(repo_url).map_err(legix::Exn::into_error)?;

    println!("Url: {:?}", url.to_bstring());
    let mut prepare_clone = legix::prepare_clone(url, &dst)?;

    println!("Cloning {} into {}...", repo_url, dst.display());
    let (mut prepare_checkout, _) =
        prepare_clone.fetch_then_checkout(legix::progress::Discard, &legix::interrupt::IS_INTERRUPTED)?;

    println!(
        "Checking out into {} ...",
        prepare_checkout.repo().workdir().expect("should be there").display()
    );

    let (repo, _) = prepare_checkout.main_worktree(legix::progress::Discard, &legix::interrupt::IS_INTERRUPTED)?;
    println!(
        "Repo cloned into {}",
        repo.workdir().expect("directory pre-created").display()
    );

    let remote = repo
        .find_default_remote(legix::remote::Direction::Fetch)
        .expect("always present after clone")?;

    println!(
        "Default remote: {} -> {}",
        remote.name().expect("default remote is always named").as_bstr(),
        remote
            .url(legix::remote::Direction::Fetch)
            .expect("should be the remote URL")
            .to_bstring(),
    );

    Ok(())
}

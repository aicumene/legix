pub fn basic_repo_dir() -> Result<std::path::PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    legix_testtools::scripted_fixture_read_only("make_basic_repo.sh")
}

pub fn open_repo(path: impl Into<std::path::PathBuf>) -> Result<legix::Repository, legix_error::Error> {
    legix::open_opts(path, legix::open::Options::isolated())
}

pub fn discover_repo(path: impl AsRef<std::path::Path>) -> Result<legix::Repository, legix_error::Error> {
    let opts = legix::open::Options::isolated();
    legix::ThreadSafeRepository::discover_opts(
        path,
        Default::default(),
        legix::sec::trust::Mapping {
            full: opts.clone(),
            reduced: opts,
        },
    )
    .map(Into::into)
}

pub fn basic_subrepo_dir(name: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    Ok(basic_repo_dir()?.join(name))
}

pub fn remote_repo_dir(name: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    Ok(legix_testtools::scripted_fixture_read_only("make_remote_repos.sh")?.join(name))
}

pub fn worktree_repo_dir() -> Result<std::path::PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    Ok(legix_testtools::scripted_fixture_read_only("make_worktree_repo.sh")?.join("repo"))
}

pub fn tempdir() -> std::io::Result<legix_testtools::tempfile::TempDir> {
    legix_testtools::tempfile::TempDir::new()
}

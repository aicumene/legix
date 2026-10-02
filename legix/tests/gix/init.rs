mod bare {
    use crate::Result;
    use legix_testtools::tempfile;

    #[test]
    #[serial_test::serial]
    fn init_into_non_existing_directory_creates_it() -> Result {
        let _environment = legix_testtools::isolate_git_environment()?;
        let tmp = tempfile::tempdir()?;
        let git_dir = tmp.path().join("bare.git");
        let repo = legix::init_bare(&git_dir)?;
        assert_eq!(repo.kind(), legix::repository::Kind::Common);
        assert!(
            repo.workdir().is_none(),
            "a worktree isn't present in bare repositories"
        );
        assert_eq!(
            repo.git_dir(),
            git_dir,
            "the repository is placed into the given directory without added sub-directories"
        );
        assert_eq!(legix::open_opts(repo.git_dir(), crate::restricted())?, repo);
        Ok(())
    }

    #[test]
    #[serial_test::serial]
    fn init_into_empty_directory_uses_it_directly() -> Result {
        let _environment = legix_testtools::isolate_git_environment()?;
        let tmp = tempfile::tempdir()?;
        let repo = legix::init_bare(tmp.path())?;
        assert_eq!(repo.kind(), legix::repository::Kind::Common);
        assert!(
            repo.workdir().is_none(),
            "a worktree isn't present in bare repositories"
        );
        assert_eq!(
            repo.git_dir(),
            tmp.path(),
            "the repository is placed into the directory itself"
        );
        assert_eq!(legix::open_opts(repo.git_dir(), crate::restricted())?, repo);
        Ok(())
    }

    #[test]
    fn init_into_non_empty_directory_is_not_allowed() -> Result {
        let tmp = tempfile::tempdir()?;
        std::fs::write(tmp.path().join("existing.txt"), b"I was here before you")?;

        insta::assert_debug_snapshot!(legix_testtools::redact_debug_snapshot(&(legix::init_bare(tmp.path())
                .expect_err("init into non empty directory is not allowed")), &[(&(tmp.path()).to_string_lossy(), "<destination>")]), "init into non empty directory is not allowed", @r#"
        Message {
            message: "Refusing to initialize the non-empty directory as",
            class: Validation,
            values: {"input": Bytes("<destination>")},
        }
        "#);
        Ok(())
    }
}

mod non_bare {
    use crate::Result;
    use legix_testtools::tempfile;

    #[test]
    fn init_bare_with_custom_branch_name() -> Result {
        let tmp = tempfile::tempdir()?;
        let repo: legix::Repository = legix::ThreadSafeRepository::init_opts(
            tmp.path(),
            legix::create::Kind::Bare,
            legix::create::Options::default(),
            legix::open::Options::isolated().config_overrides([
                "user.name=a",
                "user.email=b",
                "init.defaultBranch=special",
            ]),
        )?
        .into();
        assert_eq!(repo.head()?.referent_name().expect("name"), "refs/heads/special");
        Ok(())
    }

    #[test]
    fn init_bare_with_fully_qualified_custom_branch_name_is_not_prefixed_again() -> Result {
        let tmp = tempfile::tempdir()?;
        let repo: legix::Repository = legix::ThreadSafeRepository::init_opts(
            tmp.path(),
            legix::create::Kind::Bare,
            legix::create::Options::default(),
            legix::open::Options::isolated().config_overrides([
                "user.name=a",
                "user.email=b",
                "init.defaultBranch=refs/heads/special",
            ]),
        )?
        .into();
        assert_eq!(repo.head()?.referent_name().expect("name"), "refs/heads/special");
        assert_eq!(
            repo.is_pristine(),
            Some(true),
            "the expected default ref uses the de-duplicated fully qualified branch name"
        );
        Ok(())
    }

    #[test]
    fn init_bare_rejects_reserved_branch_name() -> Result {
        let tmp = tempfile::tempdir()?;
        let err = legix::ThreadSafeRepository::init_opts(
            tmp.path(),
            legix::create::Kind::Bare,
            legix::create::Options::default(),
            legix::open::Options::isolated().config_overrides(["user.name=a", "user.email=b", "init.defaultBranch=HEAD"]),
        )
        .unwrap_err();
        insta::assert_debug_snapshot!(err, "init bare rejects reserved branch name", @r#"
        Invalid default branch name, "input"="HEAD"
        |
        └─ Reference name is reserved and cannot be used: "refs/heads/HEAD"
        "#);
        assert!(matches!(
            err.classify().filter(|classification| classification.class() == legix_error::Class::Validation)
                .find_map(|classification| classification.error().downcast_ref::<legix_error::Message>()),
            Some(legix_error::Message { values, .. }) if values.get("input") == Some(&legix_error::MetadataValue::Bytes("HEAD".into()))
        ));
        assert!(matches!(
            err.downcast_any_ref(),
            Some(legix_validate::reference::name::Error::Reserved { name }) if name == "refs/heads/HEAD"
        ));
        Ok(())
    }

    #[test]
    fn init_bare_rejects_reserved_fully_qualified_branch_name() -> Result {
        let tmp = tempfile::tempdir()?;
        let err = legix::ThreadSafeRepository::init_opts(
            tmp.path(),
            legix::create::Kind::Bare,
            legix::create::Options::default(),
            legix::open::Options::isolated().config_overrides([
                "user.name=a",
                "user.email=b",
                "init.defaultBranch=refs/heads/HEAD",
            ]),
        )
        .unwrap_err();
        insta::assert_debug_snapshot!(err, "init bare rejects reserved fully qualified branch name", @r#"
        Invalid default branch name, "input"="refs/heads/HEAD"
        |
        └─ Reference name is reserved and cannot be used: "refs/heads/HEAD"
        "#);
        assert!(matches!(
            err.classify().filter(|classification| classification.class() == legix_error::Class::Validation)
                .find_map(|classification| classification.error().downcast_ref::<legix_error::Message>()),
            Some(legix_error::Message { values, .. }) if values.get("input") == Some(&legix_error::MetadataValue::Bytes("refs/heads/HEAD".into()))
        ));
        assert!(matches!(
            err.downcast_any_ref(),
            Some(legix_validate::reference::name::Error::Reserved { name }) if name == "refs/heads/HEAD"
        ));
        Ok(())
    }

    #[test]
    #[serial_test::serial]
    fn init_into_empty_directory_creates_a_dot_git_dir() -> Result {
        let _environment = legix_testtools::isolate_git_environment()?;
        let tmp = tempfile::tempdir()?;
        let repo = legix::init(tmp.path())?;
        assert_eq!(repo.kind(), legix::repository::Kind::Common);
        assert_eq!(repo.workdir(), Some(tmp.path()), "there is a work tree by default");
        assert_eq!(
            repo.git_dir(),
            tmp.path().join(".git"),
            "there is a work tree by default"
        );
        assert_eq!(legix::open_opts(repo.git_dir(), crate::restricted())?, repo);
        assert_eq!(
            legix::open_opts(repo.workdir().as_ref().expect("non-bare repo"), crate::restricted())?,
            repo
        );
        Ok(())
    }

    #[test]
    fn init_into_non_empty_directory_is_allowed_if_option_is_none_or_false() -> Result {
        for destination_must_be_empty in [None, Some(false)] {
            let tmp = tempfile::tempdir()?;
            std::fs::write(tmp.path().join("existing.txt"), b"I was here before you")?;
            let repo: legix::Repository = legix::ThreadSafeRepository::init_opts(
                tmp.path(),
                legix::create::Kind::WithWorktree,
                legix::create::Options {
                    destination_must_be_empty,
                    ..Default::default()
                },
                legix::open::Options::isolated(),
            )?
            .into();
            assert_eq!(repo.workdir().expect("present"), tmp.path());
            assert_eq!(
                repo.git_dir(),
                tmp.path().join(".git"),
                "gitdir is inside of the workdir"
            );
        }
        Ok(())
    }

    #[test]
    fn init_into_non_empty_directory_is_not_allowed_if_option_is_true() -> Result {
        let tmp = tempfile::tempdir()?;
        std::fs::write(tmp.path().join("existing.txt"), b"I was here before you")?;

        let err = legix::ThreadSafeRepository::init_opts(
            tmp.path(),
            legix::create::Kind::WithWorktree,
            legix::create::Options {
                destination_must_be_empty: Some(true),
                ..Default::default()
            },
            legix::open::Options::isolated(),
        )
        .unwrap_err();
        insta::assert_debug_snapshot!(legix_testtools::redact_debug_snapshot(&(err), &[(&(tmp.path()).to_string_lossy(), "<destination>")]), "init into non empty directory is not allowed if option is true", @r#"
        Message {
            message: "Refusing to initialize the non-empty directory as",
            class: Validation,
            values: {"input": Bytes("<destination>")},
        }
        "#);
        Ok(())
    }
}

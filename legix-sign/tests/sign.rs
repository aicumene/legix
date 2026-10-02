use bstr::ByteSlice;
use legix_sign::{AllowedSigners, Entry, ObjectFormat, Status, Trust};

const COMMIT: &[u8] = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
author Ada <ada@example.com> 1759400000 +0000\n\
committer Ada <ada@example.com> 1759400000 +0000\n\
\n\
First draft\n";

/// 2025-10-02T10:13:20Z, the commit time above.
const COMMIT_TIME: i64 = 1_759_400_000;

fn key(comment: &str) -> legix_sign::ssh_key::PrivateKey {
    legix_sign::generate_ed25519(comment).expect("a key")
}

fn signers_for(key: &legix_sign::ssh_key::PrivateKey) -> AllowedSigners {
    let mut signers = AllowedSigners::default();
    signers.push("ada@example.com", key.public_key().clone());
    signers
}

#[test]
fn a_signed_commit_verifies_and_is_trusted_for_its_principal() {
    let key = key("ada@example.com");
    let signed = legix_sign::sign_commit(COMMIT, ObjectFormat::Sha1, &key).unwrap();
    let outcome = legix_sign::verify_commit(&signed, ObjectFormat::Sha1, &signers_for(&key))
        .unwrap()
        .expect("signed");
    assert_eq!(outcome.status, Status::Good);
    assert_eq!(
        outcome.trust,
        Trust::Allowed {
            principals: "ada@example.com".into()
        }
    );
    assert!(outcome.is_trusted());
    assert_eq!(
        outcome.fingerprint.as_deref(),
        Some(key.public_key().fingerprint(Default::default()).to_string().as_str())
    );
}

#[test]
fn the_signature_follows_the_other_headers_as_git_writes_it() {
    let signed = legix_sign::sign_commit(COMMIT, ObjectFormat::Sha1, &key("ada")).unwrap();
    let text = signed.to_str().unwrap();
    let (headers, message) = text.split_once("\n\n").unwrap();
    assert_eq!(message, "First draft\n");
    let lines: Vec<_> = headers.lines().collect();
    assert_eq!(lines[2], "committer Ada <ada@example.com> 1759400000 +0000");
    assert_eq!(lines[3], "gpgsig -----BEGIN SSH SIGNATURE-----");
    assert_eq!(*lines.last().unwrap(), " -----END SSH SIGNATURE-----");
    assert!(
        lines[4..].iter().all(|line| line.starts_with(' ')),
        "continuation lines"
    );
}

#[test]
fn signing_again_replaces_the_signature() {
    let (first, second) = (key("first"), key("second"));
    let signed = legix_sign::sign_commit(COMMIT, ObjectFormat::Sha1, &first).unwrap();
    let resigned = legix_sign::sign_commit(&signed, ObjectFormat::Sha1, &second).unwrap();
    assert_eq!(resigned.find_iter("gpgsig ").count(), 1);
    let outcome = legix_sign::verify_commit(&resigned, ObjectFormat::Sha1, &signers_for(&second))
        .unwrap()
        .unwrap();
    assert!(outcome.is_trusted());
}

#[test]
fn an_altered_commit_is_bad() {
    let key = key("ada");
    let signed = legix_sign::sign_commit(COMMIT, ObjectFormat::Sha1, &key).unwrap();
    let altered = signed.replace("First draft", "Final draft");
    let outcome = legix_sign::verify_commit(&altered, ObjectFormat::Sha1, &signers_for(&key))
        .unwrap()
        .unwrap();
    assert_eq!(outcome.status, Status::Bad);
    assert_eq!(outcome.trust, Trust::NotEvaluated);
    assert!(!outcome.is_trusted());
}

#[test]
fn an_unsigned_commit_has_no_outcome() {
    assert_eq!(
        legix_sign::verify_commit(COMMIT, ObjectFormat::Sha1, &AllowedSigners::default()).unwrap(),
        None
    );
}

#[test]
fn a_key_that_is_not_allowed_signs_well_but_is_not_trusted() {
    let signed = legix_sign::sign_commit(COMMIT, ObjectFormat::Sha1, &key("stranger")).unwrap();
    let outcome = legix_sign::verify_commit(&signed, ObjectFormat::Sha1, &signers_for(&key("ada")))
        .unwrap()
        .unwrap();
    assert_eq!(outcome.status, Status::Good);
    assert_eq!(outcome.trust, Trust::UnknownKey);
    assert!(!outcome.is_trusted());
}

#[test]
fn a_key_is_trusted_only_within_its_validity_at_the_commit_time() {
    let key = key("ada");
    let signed = legix_sign::sign_commit(COMMIT, ObjectFormat::Sha1, &key).unwrap();
    let with = |valid_after: Option<i64>, valid_before: Option<i64>| {
        let mut signers = AllowedSigners::default();
        signers.push_entry(Entry {
            valid_after,
            valid_before,
            ..Entry::new("ada@example.com", key.public_key().clone())
        });
        legix_sign::verify_commit(&signed, ObjectFormat::Sha1, &signers)
            .unwrap()
            .unwrap()
            .trust
    };
    let allowed = Trust::Allowed {
        principals: "ada@example.com".into(),
    };
    let outside = Trust::OutsideValidity {
        principals: "ada@example.com".into(),
    };
    assert_eq!(with(Some(COMMIT_TIME - 60), Some(COMMIT_TIME + 60)), allowed);
    assert_eq!(
        with(Some(COMMIT_TIME), Some(COMMIT_TIME)),
        allowed,
        "both bounds are inclusive"
    );
    assert_eq!(
        with(Some(COMMIT_TIME + 1), None),
        outside,
        "rotated in after the commit"
    );
    assert_eq!(
        with(None, Some(COMMIT_TIME - 1)),
        outside,
        "rotated out before the commit"
    );
}

#[test]
fn a_key_limited_to_other_namespaces_is_not_allowed_for_git() {
    let key = key("ada");
    let signed = legix_sign::sign_commit(COMMIT, ObjectFormat::Sha1, &key).unwrap();
    let mut signers = AllowedSigners::default();
    signers.push_entry(Entry {
        namespaces: Some("file,email".into()),
        ..Entry::new("ada@example.com", key.public_key().clone())
    });
    let outcome = legix_sign::verify_commit(&signed, ObjectFormat::Sha1, &signers)
        .unwrap()
        .unwrap();
    assert_eq!(outcome.trust, Trust::UnknownKey);
}

#[test]
fn sha256_repositories_keep_the_signature_in_gpgsig_sha256() {
    let commit = b"tree 6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321\n\
author Ada <ada@example.com> 1759400000 +0000\n\
committer Ada <ada@example.com> 1759400000 +0000\n\
\n\
First draft\n";
    let key = key("ada");
    let signed = legix_sign::sign_commit(commit, ObjectFormat::Sha256, &key).unwrap();
    assert!(signed.contains_str("\ngpgsig-sha256 -----BEGIN SSH SIGNATURE-----\n"));
    assert!(!signed.contains_str("\ngpgsig "));
    let outcome = legix_sign::verify_commit(&signed, ObjectFormat::Sha256, &signers_for(&key))
        .unwrap()
        .unwrap();
    assert!(outcome.is_trusted());
}

#[test]
fn openpgp_signatures_are_left_to_git() {
    let commit = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
author Ada <ada@example.com> 1759400000 +0000\n\
committer Ada <ada@example.com> 1759400000 +0000\n\
gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEz\n -----END PGP SIGNATURE-----\n\
\n\
First draft\n";
    let outcome = legix_sign::verify_commit(commit, ObjectFormat::Sha1, &AllowedSigners::default())
        .unwrap()
        .unwrap();
    assert_eq!(outcome.status, Status::UnsupportedFormat);
    assert_eq!(outcome.key, None);
}

#[test]
fn allowed_signers_read_options_patterns_and_comments() {
    let ada = key("ada");
    let bob = key("bob");
    let text = format!(
        "# the team\n\
         \n\
         ada@example.com {}\n\
         \"*@example.com,!ex@example.com\" namespaces=\"git\",valid-after=\"20250101Z\",valid-before=\"202512312359Z\" {}\n",
        ada.public_key().to_openssh().unwrap(),
        bob.public_key().to_openssh().unwrap(),
    );
    let signers = AllowedSigners::parse(&text).unwrap();
    assert_eq!(signers.entries().len(), 2);
    let bob_entry = &signers.entries()[1];
    assert_eq!(bob_entry.principals, "*@example.com,!ex@example.com");
    assert_eq!(bob_entry.namespaces.as_deref(), Some("git"));
    assert_eq!(bob_entry.valid_after, Some(1_735_689_600), "2025-01-01T00:00:00Z");
    assert_eq!(bob_entry.valid_before, Some(1_767_225_540), "2025-12-31T23:59:00Z");

    let bob_key = bob.public_key();
    assert!(signers.allows("bob@example.com", bob_key, Some(COMMIT_TIME)));
    assert!(!signers.allows("ex@example.com", bob_key, Some(COMMIT_TIME)), "negated");
    assert!(!signers.allows("bob@example.org", bob_key, Some(COMMIT_TIME)));
    assert!(
        !signers.allows("bob@example.com", bob_key, Some(1_800_000_000)),
        "expired"
    );
    assert!(
        !signers.allows("bob@example.com", ada.public_key(), Some(COMMIT_TIME)),
        "another key"
    );
    assert_eq!(signers.principals_for(ada.public_key(), None), Some("ada@example.com"));

    assert_eq!(
        AllowedSigners::parse(&signers.to_string()).unwrap(),
        signers,
        "written back as read"
    );
}

#[test]
fn allowed_signers_refuse_lines_they_cannot_read() {
    let key = key("ada").public_key().to_openssh().unwrap();
    for (text, line) in [
        (
            format!("ada@example.com {key}\nada@example.com no-touch-required {key}"),
            2,
        ),
        (format!("ada@example.com valid-after=\"tomorrow\" {key}"), 1),
        (format!("\"ada@example.com {key}"), 1),
        ("ada@example.com ssh-ed25519 AAAAnotakey".to_string(), 1),
    ] {
        match AllowedSigners::parse(&text) {
            Err(legix_sign::Error::AllowedSigners { line: at, .. }) => assert_eq!(at, line, "{text}"),
            other => panic!("{text}: {other:?}"),
        }
    }
}

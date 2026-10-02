use legix_crypt::{Error, Oid, Pointer};

const OID: &str = "blake3:c0d50151e78d1ba23494e2c884809eedd6d770f49ffb4cb797cecb633e0b20b8";

#[test]
fn a_pointer_reads_back_as_it_was_written() {
    let pointer = Pointer {
        oid: OID.parse().unwrap(),
        size: 14,
    };
    let text = pointer.to_string();
    assert_eq!(text, format!("version legix-crypt/1\noid {OID}\nsize 14\n"));
    assert_eq!(Pointer::parse(text.as_bytes()).unwrap(), pointer);
    assert!(Pointer::is_pointer(text.as_bytes()));
    assert_eq!(pointer.object_len(), Some(92));

    let longest = Pointer {
        oid: pointer.oid,
        size: 10_000_000_000_000_000_000,
    };
    assert_eq!(longest.to_string().len(), Pointer::MAX_LEN);
    assert_eq!(Pointer::parse(longest.to_string().as_bytes()).unwrap(), longest);
}

#[test]
fn anything_but_the_one_text_form_is_refused() {
    let valid = format!("version legix-crypt/1\noid {OID}\nsize 14\n");
    let upper = valid.replace("c0d5", "C0D5");
    let crlf = valid.replace('\n', "\r\n");
    let no_newline = valid.trim_end().to_string();
    let extra_line = format!("{valid}extra\n");
    let reordered = format!("version legix-crypt/1\nsize 14\noid {OID}\n");
    let other_version = valid.replace("legix-crypt/1", "legix-crypt/2");
    let lfs = valid.replace("version legix-crypt/1", "version https://git-lfs.github.com/spec/v1");
    let short_oid = valid.replace("b20b8", "b20b");
    let sha256 = valid.replace("blake3:", "sha256:");
    let leading_zero = valid.replace("size 14", "size 014");
    let signed = valid.replace("size 14", "size -14");
    let spaced = valid.replace("size 14", "size  14");
    let empty_size = valid.replace("size 14", "size ");
    let too_large = valid.replace("size 14", &format!("size {}", u64::MAX));
    for (text, what) in [
        (&upper, "upper-case hex"),
        (&crlf, "CRLF"),
        (&no_newline, "no final line feed"),
        (&extra_line, "an extra line"),
        (&reordered, "lines out of order"),
        (&other_version, "another version"),
        (&lfs, "a git-lfs pointer"),
        (&short_oid, "a short id"),
        (&sha256, "another hash"),
        (&leading_zero, "a leading zero"),
        (&signed, "a sign"),
        (&spaced, "two spaces"),
        (&empty_size, "no size"),
        (&too_large, "a size no object can have"),
    ] {
        assert!(
            matches!(Pointer::parse(text.as_bytes()), Err(Error::Pointer(_) | Error::Oid(_))),
            "{what}: {text:?}"
        );
    }
    assert!(!Pointer::is_pointer(&vec![b'x'; 10_000]));
    assert!(!Pointer::is_pointer(b"PK\x03\x04 a document, not a pointer"));
}

#[test]
fn ids_have_one_text_form() {
    let oid: Oid = OID.parse().unwrap();
    assert_eq!(oid.to_string(), OID);
    assert_eq!(Oid::from_hex(&oid.to_hex()).unwrap(), oid);
    assert_eq!(Oid::from_bytes(*oid.as_bytes()), oid);
    assert!(matches!(OID.to_uppercase().parse::<Oid>(), Err(Error::Oid(_))));
    assert!(matches!(OID.replace("blake3:", "").parse::<Oid>(), Err(Error::Oid(_))));
    assert!(matches!(Oid::from_hex("g".repeat(64).as_str()), Err(Error::Oid(_))));
}

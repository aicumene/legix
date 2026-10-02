use std::{fs, io};

use legix_crypt::{
    DirKeyStore, DocumentKey, Documents, Error, KeyState, KeyStore, MemoryKeyStore, ObjectStore, Oid, Status, StoreKey,
    object::{self, CHUNK_LEN, HEADER_LEN, TAG_LEN},
};

const SIZES: &[usize] = &[
    0,
    1,
    1000,
    CHUNK_LEN - 1,
    CHUNK_LEN,
    CHUNK_LEN + 1,
    2 * CHUNK_LEN,
    3 * CHUNK_LEN + 5,
];

fn document(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 256) as u8).collect()
}

fn sealed(len: usize) -> (DocumentKey, Vec<u8>) {
    let key = DocumentKey::generate().unwrap();
    let mut object = Vec::new();
    object::seal(&key, &document(len)[..], &mut object).unwrap();
    (key, object)
}

fn open(key: &DocumentKey, object: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    object::open(key, object, &mut out).map(|_| out)
}

fn in_dir() -> (tempfile::TempDir, Documents<DirKeyStore>) {
    let dir = tempfile::tempdir().unwrap();
    let documents = Documents::new(
        ObjectStore::new(dir.path().join("objects")),
        DirKeyStore::new(dir.path().join("keys"), StoreKey::generate().unwrap()),
    );
    (dir, documents)
}

#[test]
fn documents_of_every_size_come_back_as_they_were() {
    let (_dir, documents) = in_dir();
    for &len in SIZES {
        let pointer = documents.add(&document(len)[..]).unwrap();
        assert_eq!(pointer.size, len as u64);
        let stored = fs::read(documents.objects().path(&pointer.oid)).unwrap();
        assert_eq!(Some(stored.len() as u64), pointer.object_len(), "{len}");
        assert_eq!(Oid::of(&stored), pointer.oid);
        assert_eq!(documents.read_to_vec(&pointer).unwrap(), document(len), "{len}");
        assert_eq!(documents.status(&pointer.oid).unwrap(), Status::Readable);
    }
}

#[test]
fn the_same_document_twice_gives_two_objects_under_two_keys() {
    let (_dir, documents) = in_dir();
    let first = documents.add(&b"Heads of terms"[..]).unwrap();
    let second = documents.add(&b"Heads of terms"[..]).unwrap();
    assert_ne!(first.oid, second.oid);
    let key = |oid| match documents.keys().get(oid).unwrap() {
        KeyState::Present(key) => *key.as_bytes(),
        other => panic!("{other:?}"),
    };
    assert_ne!(key(&first.oid), key(&second.oid));
}

#[test]
fn a_wrong_key_is_refused_before_anything_is_decrypted() {
    let (_, object) = sealed(3 * CHUNK_LEN);
    let mut out = Vec::new();
    let other = DocumentKey::generate().unwrap();
    assert!(matches!(
        object::open(&other, &object[..], &mut out),
        Err(Error::WrongKey)
    ));
    assert!(out.is_empty());
}

#[test]
fn any_altered_byte_is_detected() {
    let (key, object) = sealed(2 * CHUNK_LEN + 10);
    let second = HEADER_LEN + CHUNK_LEN + TAG_LEN;
    for (at, expected) in [
        (0, "format"),                 // magic
        (14, "key"),                   // salt
        (30, "key"),                   // commitment
        (HEADER_LEN, "chunk 0"),       // the first chunk
        (second - 1, "chunk 0"),       // its tag
        (second, "chunk 1"),           // the second chunk
        (object.len() - 1, "chunk 2"), // the last tag
    ] {
        let mut altered = object.clone();
        altered[at] ^= 0x01;
        let found = match open(&key, &altered) {
            Err(Error::Format(_)) => "format".to_string(),
            Err(Error::WrongKey) => "key".to_string(),
            Err(Error::Authentication { chunk }) => format!("chunk {chunk}"),
            other => panic!("byte {at}: {other:?}"),
        };
        assert_eq!(found, expected, "byte {at}");
    }
}

#[test]
fn cutting_extending_or_reordering_an_object_is_detected() {
    let (key, object) = sealed(3 * CHUNK_LEN);
    let chunk = CHUNK_LEN + TAG_LEN;
    let chunks = |o: &[u8]| -> Vec<Vec<u8>> { o[HEADER_LEN..].chunks(chunk).map(<[u8]>::to_vec).collect() };
    let header = &object[..HEADER_LEN];
    let parts = chunks(&object);
    assert_eq!(parts.len(), 3);

    let without_last = [header, &parts[0], &parts[1]].concat();
    assert!(matches!(
        open(&key, &without_last),
        Err(Error::Authentication { chunk: 1 })
    ));
    let cut_inside = &object[..object.len() - 100];
    assert!(matches!(
        open(&key, cut_inside),
        Err(Error::Authentication { chunk: 2 })
    ));
    let header_only = &object[..HEADER_LEN];
    assert!(matches!(
        open(&key, header_only),
        Err(Error::Authentication { chunk: 0 })
    ));
    let extended = [&object[..], b"more"].concat();
    assert!(matches!(open(&key, &extended), Err(Error::Authentication { chunk: 2 })));
    let repeated = [&object[..], &parts[2]].concat();
    assert!(matches!(open(&key, &repeated), Err(Error::Authentication { chunk: 2 })));
    let swapped = [header, &parts[1], &parts[0], &parts[2]].concat();
    assert!(matches!(open(&key, &swapped), Err(Error::Authentication { chunk: 0 })));
    assert_eq!(open(&key, &object).unwrap(), document(3 * CHUNK_LEN));
}

#[test]
fn an_erased_document_cannot_be_read_and_its_key_cannot_come_back() {
    let (dir, documents) = in_dir();
    let pointer = documents.add(&b"Heads of terms"[..]).unwrap();
    let KeyState::Present(key) = documents.keys().get(&pointer.oid).unwrap() else {
        panic!("the key is kept");
    };
    let object = fs::read(documents.objects().path(&pointer.oid)).unwrap();

    documents.erase(&pointer.oid).unwrap();
    assert_eq!(documents.status(&pointer.oid).unwrap(), Status::Erased);
    assert!(matches!(documents.read_to_vec(&pointer), Err(Error::Erased(oid)) if oid == pointer.oid));
    assert!(!documents.objects().contains(&pointer.oid).unwrap());
    let key_files: Vec<_> = walk(&dir.path().join("keys/keys"));
    assert!(key_files.is_empty(), "no key file is left: {key_files:?}");

    // A copy of the key from elsewhere is refused, and the object brought back from a backup stays unreadable.
    assert!(matches!(
        documents.keys().put(&pointer.oid, &key),
        Err(Error::Erased(_))
    ));
    documents.objects().insert(&pointer.oid, &object[..]).unwrap();
    assert!(matches!(documents.read_to_vec(&pointer), Err(Error::Erased(_))));

    documents.erase(&pointer.oid).unwrap();
    assert_eq!(
        documents.status(&pointer.oid).unwrap(),
        Status::Erased,
        "erasing again is not an error"
    );
}

#[test]
fn erasure_in_memory_works_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let documents = Documents::new(ObjectStore::new(dir.path()), MemoryKeyStore::default());
    let pointer = documents.add(&b"Heads of terms"[..]).unwrap();
    let KeyState::Present(key) = documents.keys().get(&pointer.oid).unwrap() else {
        panic!("the key is kept");
    };
    documents.erase(&pointer.oid).unwrap();
    assert!(matches!(documents.read_to_vec(&pointer), Err(Error::Erased(_))));
    assert!(matches!(
        documents.keys().put(&pointer.oid, &key),
        Err(Error::Erased(_))
    ));
    let never_kept = Oid::of(b"never kept");
    documents.erase(&never_kept).unwrap();
    assert_eq!(documents.status(&never_kept).unwrap(), Status::Erased);
}

#[test]
fn a_document_needs_both_its_key_and_its_object() {
    let (_dir, documents) = in_dir();
    let pointer = documents.add(&b"Heads of terms"[..]).unwrap();

    let elsewhere = tempfile::tempdir().unwrap();
    let without_key = Documents::new(documents.objects().clone(), MemoryKeyStore::default());
    assert_eq!(without_key.status(&pointer.oid).unwrap(), Status::KeyMissing);
    assert!(matches!(without_key.read_to_vec(&pointer), Err(Error::KeyMissing(_))));

    let without_object = Documents::new(ObjectStore::new(elsewhere.path()), documents.keys());
    assert_eq!(without_object.status(&pointer.oid).unwrap(), Status::ObjectMissing);
    assert!(matches!(
        without_object.read_to_vec(&pointer),
        Err(Error::ObjectMissing(_))
    ));

    // The object travels without a key, and is checked on arrival.
    let object = fs::read(documents.objects().path(&pointer.oid)).unwrap();
    let mut damaged = object.clone();
    damaged[70] ^= 1;
    assert!(matches!(
        without_object.objects().insert(&pointer.oid, &damaged[..]),
        Err(Error::Corrupt { expected, .. }) if expected == pointer.oid
    ));
    assert!(
        !without_object.objects().contains(&pointer.oid).unwrap(),
        "nothing kept"
    );
    without_object.objects().insert(&pointer.oid, &object[..]).unwrap();
    assert_eq!(without_object.read_to_vec(&pointer).unwrap(), b"Heads of terms");
}

#[test]
fn a_damaged_object_is_found_without_its_key() {
    let (_dir, documents) = in_dir();
    let pointer = documents.add(&document(CHUNK_LEN + 3)[..]).unwrap();
    let path = documents.objects().path(&pointer.oid);
    let mut stored = fs::read(&path).unwrap();
    stored[HEADER_LEN + 5] ^= 0x80;
    fs::write(&path, &stored).unwrap();

    assert!(matches!(
        documents.objects().verify(&pointer.oid),
        Err(Error::Corrupt { .. })
    ));
    let mut out = Vec::new();
    assert!(matches!(documents.read(&pointer, &mut out), Err(Error::Corrupt { .. })));
    assert!(
        out.is_empty(),
        "nothing is decrypted from an object that is not the one named"
    );
}

#[test]
fn a_pointer_whose_size_does_not_match_its_object_is_refused() {
    let (_dir, documents) = in_dir();
    let mut pointer = documents.add(&b"Heads of terms"[..]).unwrap();
    pointer.size += 1;
    assert!(matches!(documents.read_to_vec(&pointer), Err(Error::Pointer(_))));
}

#[test]
fn key_files_open_only_with_their_store_key_and_for_their_object() {
    let dir = tempfile::tempdir().unwrap();
    let store_key = StoreKey::generate().unwrap();
    let keys = DirKeyStore::new(dir.path(), store_key.clone());
    let key = DocumentKey::generate().unwrap();
    let (a, b) = (Oid::of(b"a"), Oid::of(b"b"));
    keys.put(&a, &key).unwrap();

    let files = walk(&dir.path().join("keys"));
    assert_eq!(files.len(), 1);
    let file = fs::read(&files[0]).unwrap();
    assert!(file.starts_with(b"legix-key/1\n"));
    assert!(
        !file.windows(32).any(|w| w == key.as_bytes()),
        "the key file does not hold the key in clear"
    );

    let other_store = DirKeyStore::new(dir.path(), StoreKey::generate().unwrap());
    assert!(matches!(other_store.get(&a), Err(Error::KeyFile { .. })));

    // The key file of `a` under the name of `b`.
    let b_path = dir.path().join("keys").join(&b.to_hex()[..2]).join(&b.to_hex()[2..]);
    fs::create_dir_all(b_path.parent().unwrap()).unwrap();
    fs::write(&b_path, &file).unwrap();
    assert!(matches!(keys.get(&b), Err(Error::KeyFile { oid, .. }) if oid == b));

    let KeyState::Present(back) = DirKeyStore::new(dir.path(), store_key).get(&a).unwrap() else {
        panic!("the key is there");
    };
    assert_eq!(back.as_bytes(), key.as_bytes());
    assert!(matches!(keys.get(&Oid::of(b"c")).unwrap(), KeyState::Missing));
}

#[test]
fn objects_are_written_whole_or_not_at_all() {
    struct Failing;
    impl io::Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("the document could not be read"))
        }
    }
    let (dir, documents) = in_dir();
    assert!(matches!(documents.add(Failing), Err(Error::Io(_))));
    assert!(
        walk(&dir.path().join("objects")).is_empty(),
        "no partial object is left"
    );
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return files;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(walk(&path));
        } else {
            files.push(path);
        }
    }
    files
}

#[test]
fn an_object_has_one_key() {
    let dir = tempfile::tempdir().unwrap();
    let in_dir = DirKeyStore::new(dir.path(), StoreKey::generate().unwrap());
    let in_memory = MemoryKeyStore::default();
    let stores: [&dyn KeyStore; 2] = [&in_dir, &in_memory];
    for keys in stores {
        let documents = Documents::new(ObjectStore::new(dir.path().join("objects")), keys);
        let pointer = documents.add(&b"Heads of terms"[..]).unwrap();
        let KeyState::Present(key) = keys.get(&pointer.oid).unwrap() else {
            panic!("the key is kept");
        };
        keys.put(&pointer.oid, &key).unwrap();
        let other = DocumentKey::generate().unwrap();
        assert!(matches!(keys.put(&pointer.oid, &other), Err(Error::KeyConflict(oid)) if oid == pointer.oid));
        assert_eq!(
            documents.read_to_vec(&pointer).unwrap(),
            b"Heads of terms",
            "the kept key stays"
        );
    }
}

# legix-crypt

Encrypted documents for git. The repository holds a pointer; the document is stored encrypted under a key of its own,
outside the repository. Destroying the key erases the document wherever the history went, and the history — its ids and
its signatures — stays as it is.

- **A key per document.** Every document is encrypted under a new random key with ChaCha20-Poly1305, in 64 KiB chunks
  that detect any change, truncation or reordering. The header commits to the key, so an object opens under one key only.
- **Content-addressed.** An object is named by the BLAKE3 hash of its encrypted bytes. Relays, backups and devices
  without the key can check objects they cannot read.
- **A pointer in the history.** Three lines of text take the document's place in the repository. A signed commit that
  holds the pointer commits to exactly one document.
- **Erasure without rewriting history.** Destroying the key makes every copy of the object unreadable. Key stores remember
  what they erased, so a copy of the key that arrives later cannot bring the document back.

```rust
use legix_crypt::{DirKeyStore, Documents, ObjectStore, StoreKey};

let store_key = StoreKey::generate()?; // keep it in the keychain or in hardware
let documents = Documents::new(
    ObjectStore::new(".git/legix/objects"),
    DirKeyStore::new(".git/legix/keys", store_key),
);

let pointer = documents.add(std::fs::File::open("contract.docx")?)?;
std::fs::write("contract.docx", pointer.to_string())?; // commit the pointer in the document's place
let document = documents.read_to_vec(&pointer)?;

documents.erase(&pointer.oid)?; // the document is gone; the history is unchanged
```

Erasure covers the key stores it runs on. Other key stores that hold the key, on other devices or in backups, must erase
it too.

## Formats and stability

The object, the pointer and the key file are versioned and specified byte by byte in [FORMAT.md](FORMAT.md), with test
vectors that an independent implementation on OpenSSL reproduces. A released version stays readable by every later
release. The API follows semantic versioning, and the crate does not depend on the git engine.

The cryptography has not yet had an independent audit.

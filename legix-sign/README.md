# legix-sign

Signed history for git: sign and verify commits in git's SSH signature format, in process.

- **git-compatible.** Signatures are the ones `git commit -S` writes with `gpg.format = ssh`. They verify with
  `git verify-commit` and `ssh-keygen -Y verify`, and git's signatures verify here. SHA-1 and SHA-256
  repositories are both supported.
- **In process.** No `ssh-keygen` or `gpg` process is started, and a private key never has to be a file. Anything
  that implements `ssh_key::SigningKey` signs: a key in memory, in a keychain, in hardware. Ed25519 and ECDSA P-256
  keys are supported.
- **Trust you can audit.** Trust comes from git's allowed-signers file: principals, `namespaces`, and
  `valid-after`/`valid-before` checked at the commit's time. Key rotation therefore does not invalidate history
  that was signed while a key was valid.
- **Namespaces.** `sign_in`, `verify_in` and `AllowedSigners::trust_in` work in another SSH signature namespace than
  `git`, for data that must never pass for a commit signature — leGix signs its sync bundles in `legix-bundle`.

```rust
use legix_sign::{AllowedSigners, ObjectFormat};

let key = legix_sign::generate_ed25519("ada@example.com")?;
let signed = legix_sign::sign_commit(commit_bytes, ObjectFormat::Sha1, &key)?;

let mut signers = AllowedSigners::default();
signers.push("ada@example.com", key.public_key().clone());
let outcome = legix_sign::verify_commit(&signed, ObjectFormat::Sha1, &signers)?.expect("signed");
assert!(outcome.is_trusted());
```

With the default `repository` feature, `RepositoryExt` adds `commit_signed()` and `verify_commit_signature()` to
`legix::Repository`.

## Stability

The API works on git's stable formats: commit objects, armored SSH signatures and the allowed-signers file. It
also uses this crate's own types, and it follows semantic versioning. The `repository` module extends the engine
and follows its version.

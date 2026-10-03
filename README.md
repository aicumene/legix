# leGix

**Distributed git for the enterprise.** leGix is version control for organizations that cannot hand their history
to a server they have to trust. Every commit is signed by the device or person that made it. Documents are encrypted,
each under a key of its own, and devices sync with each other through relays that cannot read what they carry.
leGix is written in Rust and embeds in your product as a library. It needs no git installation and offers a
stable API.

Repositories, objects and signatures are standard git, so teams keep their tools — `git log --show-signature`
reads leGix history, and leGix reads theirs.

## Why leGix

- **Signed history, verified in process.** Commits are signed with SSH keys that live in memory, a keychain or
  hardware. Trust comes from an allowed-signers list that is checked at commit time, so rotating a key never
  invalidates history it signed while it was valid. Signatures verify with stock git.
- **No server to trust.** Every device holds the full history. Devices sync through encrypted, signed, append-only
  bundles that any relay can keep and forward, in the cloud or on premises — or directly, device to device, on the
  local network and through NAT.
- **Encryption you can delete.** Documents are kept outside the history, each encrypted under a key of its own, and
  the history holds a pointer. Destroying the key erases the document wherever its copies went — retention and
  right-to-erasure without rewriting history.
- **Built to embed.** A library rather than a program to install. It runs inside desktop, mobile and server
  applications, offline first, on macOS, Linux and Windows.
- **Audit by construction.** Signed commits answer who changed what and when. A signed membership log answers under
  whose authority: who added each device, with which role, and when it was removed.

leGix serves regulated industries — legal, finance, healthcare, the public sector — and products that version
documents for their users. It also serves teams that work offline or across sites without shared
infrastructure.

## What is available

| Capability | Status |
|---|---|
| git engine: repositories, objects, references, history, diff, merge, network | Available — `legix`, `legix-*` |
| Signed history: sign and verify commits in git's SSH format, in process; allowed-signers trust with validity windows; SHA-1 and SHA-256 repositories | Available — [`legix-sign`](legix-sign) |
| Encrypted documents: a key per document, content-addressed objects any relay can check, erasure by destroying the key; formats specified byte by byte | Available — [`legix-crypt`](legix-crypt) |
| Sync without a trusted server: encrypted, signed, append-only bundles per device through any relay; standard git bundles inside; documents and their erasure travel too | Available — [`legix-sync`](legix-sync) |
| Membership and key rotation: a signed log of who may read and write; group keys sealed for every device; a new key when a device leaves; revocation without trusting clocks | Available — [`legix-members`](legix-members) |
| Device-to-device sync on the local network and through NAT, over iroh: members only, every item checked before it is kept, devices carrying each other's bundles | Available — [`legix-p2p`](legix-p2p) |
| A folder of documents with a history, for an application in one type: versions, restore, sync through a shared folder, members | Available — [`legix-folder`](legix-folder) |

Signed history:

```rust
use legix_sign::{AllowedSigners, repository::RepositoryExt};

let repo = legix::open(".")?;
let key = legix_sign::generate_ed25519("ada@example.com")?;
let tree = repo.empty_tree().id;
let id = repo.commit_signed("HEAD", "Signed by legix", tree, Vec::<legix::ObjectId>::new(), &key)?;

let mut signers = AllowedSigners::default();
signers.push("ada@example.com", key.public_key().clone());
assert!(repo.verify_commit_signature(id, &signers)?.expect("signed").is_trusted());
```

Encrypted documents:

```rust
use legix_crypt::{DirKeyStore, Documents, ObjectStore, StoreKey};

let store_key = StoreKey::generate()?; // kept in the keychain or in hardware
let documents = Documents::new(
    ObjectStore::new(repo.git_dir().join("legix/objects")),
    DirKeyStore::new(repo.git_dir().join("legix/keys"), store_key),
);
let pointer = documents.add(std::fs::File::open("contract.docx")?)?;
let blob = repo.write_blob(pointer.to_string())?; // the history holds the pointer, never the document

documents.erase(&pointer.oid)?; // destroys the key: the document cannot be read, the history is unchanged
```

Sync through a relay:

```rust
use legix_members::Members;
use legix_sync::{DirRelay, Replica};

let relay = DirRelay::new("/Volumes/Shared/matter-2041"); // any folder the devices share
let members = Members::load(&relay, &group_id, &identity, &repo.git_dir().join("legix/members.pin"))?;
let replica = Replica::new(&repo, &key, &members, &relay, &documents);
replica.push()?; // this device's branches, tags and documents, in a signed, encrypted bundle
replica.pull()?; // the other devices' bundles, checked and applied under refs/legix/devices/
```

Device to device, over iroh — each device's replica works on its own mirror, and devices sync their mirrors:

```rust
use legix_p2p::{ALPN, EndpointCert, Peer};

let certificate = EndpointCert::new(&key, endpoint.id())?; // ties the iroh endpoint to the device
let peer = Arc::new(Peer::new(mirror, group_id, identity, certificate)?);
let router = iroh::protocol::Router::builder(endpoint.clone()).accept(ALPN, peer.clone()).spawn();
for (_, other) in peer.peers()? {
    peer.sync_with(&endpoint, other).await?; // members only; every item is checked before it is kept
}
```

## Stable API

Applications build on leGix for years, so its API is held to a contract:

- **leGix's own crates** (`legix-sign`, `legix-crypt`, `legix-sync`, `legix-members`, `legix-p2p` and
  `legix-folder`) work on git's stable formats, on formats of their own that are specified and versioned, and on their
  own types. They follow semantic versioning strictly.
- **Deprecation before removal.** An API is deprecated for at least one minor release, with its replacement
  named, before it goes away in the next major version.
- **Toolchain.** A minimum supported Rust version is raised only in minor releases and is stated in each crate.
- **1.0** of a crate is its stable API. Before 1.0, breaking changes come only in 0.x minor releases, with
  migration notes.
- **The engine** (`legix`, `legix-*`) follows the gitoxide release it is built on (see below). Code that uses
  leGix's own crates is shielded from engine changes. Helpers that extend the engine, such as
  `legix_sign::repository` and `legix_sync::Replica`, follow the engine's version.

## Support

- **Questions and bugs:** [GitHub issues](https://github.com/aicumene/legix/issues).
- **Security:** report privately through [GitHub security advisories](https://github.com/aicumene/legix/security/advisories/new);
  see [SECURITY.md](SECURITY.md).
- **Commercial support** is available from [AiCumene](https://aicumene.com): integration into your product, long-term
  maintenance with security backports, and priority fixes. Write to [info@aicumene.com](mailto:info@aicumene.com).

## Built on gitoxide

leGix's git engine is [gitoxide](https://github.com/GitoxideLabs/gitoxide), the pure-Rust implementation of git by
Sebastian Thiel and the gitoxide contributors. leGix carries its full history and follows its releases.

- **Base:** gitoxide v0.59.0 (`gix` 0.88.0, 25 September 2026).
- **Names:** the engine is renamed so that leGix and gitoxide can live in one dependency graph:
  - `gix` → `legix`, `gix-*` → `legix-*` (crates, libraries and directories);
  - `gitoxide-core` → `legix-core`, the CLI package `gitoxide` → `legix-cli`;
  - the plumbing binary `gix` → `legix`; the porcelain binary `ein` keeps its name.
- **Left as they are:** the git configuration section `gitoxide.*` (users' configuration names these keys),
  environment variables (`GIX_*`), the user agent, test data, fixture scripts and changelogs.
- **New gitoxide releases:** check out the tag, run [`etc/legix-rename.py`](etc/legix-rename.py) on the clean
  tree, and re-apply leGix's commits on top. Engine versions are those of the gitoxide release they come from.
- **Upstream first:** a fix that is not specific to leGix goes to gitoxide, and gitoxide's security fixes are
  taken as they are released.

gitoxide's own documentation, [GITOXIDE-README.md](GITOXIDE-README.md) and [DEVELOPMENT.md](DEVELOPMENT.md),
applies to the engine under the new names.

## Building

```sh
cargo build
cargo test --workspace
```

The workspace builds with Rust 1.98 (`rust-toolchain.toml`), which was stable when gitoxide v0.59.0 was
released. The `legix` library keeps gitoxide's minimum supported Rust version, 1.88; `legix-p2p` with its `iroh`
feature needs 1.91, as iroh does. Many tests create fixture
repositories with the system's `git` and `bash`. The signing tests also need OpenSSH's `ssh-keygen`.

## License

MIT OR Apache-2.0 ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)). The engine is gitoxide's code;
see [NOTICE](NOTICE).

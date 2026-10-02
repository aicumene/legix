# leGix

leGix is a fork of [gitoxide](https://github.com/GitoxideLabs/gitoxide), the pure-Rust implementation of
git by Sebastian Thiel and the gitoxide contributors. It exists for version control of legal matters on
the machines of law firms: local-first, inside a desktop app, with no git installation and no server at
the firm. gitoxide does the git; leGix adds what such a setting needs on top of it.

## Relationship to gitoxide

- **Fork point:** gitoxide v0.59.0 (`gix` 0.88.0, 25 September 2026), with gitoxide's full history.
- **Names:** everything is renamed so that leGix and gitoxide can live in one dependency graph:
  - `gix` → `legix`, `gix-*` → `legix-*` (crates, libraries and directories);
  - `gitoxide-core` → `legix-core`, the CLI package `gitoxide` → `legix-cli`;
  - the plumbing binary `gix` → `legix`; the porcelain binary `ein` keeps its name.
- **What is not renamed:** the git configuration section `gitoxide.*` (users' configuration names
  these keys), environment variables (`GIX_*`), the user agent, test data, fixture scripts and changelogs.
- **How:** [`etc/legix-rename.py`](etc/legix-rename.py). Taking a new gitoxide release means checking out
  its tag, running the script on the clean tree and re-applying the leGix commits on top.
- **Versions** are those of the gitoxide release a crate comes from: `legix` 0.88.0 is `gix` 0.88.0
  with the leGix changes.
- **Upstream first:** a fix that is not specific to leGix goes to gitoxide. Security fixes released by
  gitoxide are taken into leGix as they come.

## What leGix adds

None of this is in yet — so far the fork is the rename alone. Planned, in this order:

1. Commits signed by per-device keys in git's SSH signature format, verified on read.
2. Documents (DOCX, PDF) stored outside the object database, addressed by their BLAKE3 hash and each
   encrypted with its own key; git keeps a small pointer. Deleting a document means destroying its key.
3. Encrypted, signed, append-only bundles for store-and-forward sync through a relay that cannot read them.
4. A signed membership log: who may read a matter, key rotation when a device leaves.
5. Direct sync between devices on the same network or through NAT ([iroh](https://www.iroh.computer)).

## Building

The workspace builds with Rust 1.98, stable when gitoxide v0.59.0 was released (`rust-toolchain.toml`);
the `legix` library keeps gitoxide's minimum supported Rust version, 1.88.

```sh
cargo build
cargo test -p legix
```

Many tests create fixture repositories with the system `git` and `bash`. See
[DEVELOPMENT.md](DEVELOPMENT.md) and [GITOXIDE-README.md](GITOXIDE-README.md) — gitoxide's own
documentation, which applies to leGix under the new names.

## License

MIT OR Apache-2.0, like gitoxide ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)). The code
is gitoxide's except where the history shows otherwise; see [NOTICE](NOTICE).

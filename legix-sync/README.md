# legix-sync

Sync git repositories through relays that cannot read them. Every device publishes its own branches and tags in
bundles: signed by the device, encrypted for the members, chained one after the other. A relay — a shared folder,
object storage, a server — keeps the bundles and passes them on. It can check every signature and every chain, and it
can read nothing.

- **Signed, per device.** A bundle's head names the device, the bundle's place in its chain and the hash of the bundle
  before it, and is signed with the device's SSH key in its own namespace, `legix-bundle`. Who may publish, and the
  group's keys, come from the group's membership log ([legix-members](../legix-members)) or from the application.
- **Keys that follow the membership.** Every bundle names the epoch of the group key it is written under. When a device
  leaves, the group moves to a new key, and the device reads nothing written after.
- **Encrypted end to end.** The body is encrypted under a new key for every bundle, wrapped with the key the members
  share. Inside is a standard git bundle — refs and a pack of the new objects — that `git bundle verify` and `git fetch`
  read once decrypted.
- **Append-only.** Readers refuse a bundle that does not follow the one before it, that is dated before it, or that sits
  at another place than it claims. A device that writes two histories is caught.
- **Documents and erasure.** Documents travel as [legix-crypt](../legix-crypt) objects, their keys in envelopes kept
  apart from the bundles. Erasing a document deletes its envelope on the relay and is announced in the next bundle, so
  that every member destroys its key.
- **Any relay.** `DirRelay` syncs through a directory several devices see. Other relays implement the `Relay` trait.

```rust
use legix_crypt::{DirKeyStore, Documents, ObjectStore};
use legix_members::Members;
use legix_sync::{DirRelay, Replica};

let repo = legix::open(".")?;
let documents = Documents::new(
    ObjectStore::new(repo.git_dir().join("legix/objects")),
    DirKeyStore::new(repo.git_dir().join("legix/keys"), store_key),
);
let relay = DirRelay::new("/Volumes/Shared/matter-2041");
let members = Members::load(&relay, &group_id, &identity, &repo.git_dir().join("legix/members.pin"))?;
let replica = Replica::new(&repo, &device_key, &members, &relay, &documents);

replica.push()?;            // publish this device's branches, tags and documents
let pulled = replica.pull()?; // apply the others' bundles: refs/legix/devices/<device id>/heads/…
for refused in &pulled.refused {
    eprintln!("bundle {} of {}: {}", refused.seq, refused.device, refused.problem);
}
```

The branches and tags of another device appear under `refs/legix/devices/<its device id>/`, to merge from as one would
from a remote. Each device writes only its own refs, so syncing never conflicts; merging is the user's, as in git.

## Formats and stability

The head, the body, the envelope and the relay's layout are specified in [FORMAT.md](FORMAT.md), with what a reader
checks and in which order. The formats are versioned; a released version stays readable. `Replica` works on
`legix::Repository` and follows the engine's version; the formats, the `Access` and `Relay` interfaces do not depend on
it.

Access comes from [legix-members](../legix-members), or — `Fixed` — from one group key and an allowed-signers list that
the application hands in. The cryptography has not yet had an independent audit.

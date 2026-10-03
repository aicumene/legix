# legix-folder

A folder of documents with a signed, encrypted, synced history: leGix for an application in one type.

A `Folder` keeps the history of the folder a person works in — drafts, letters, evidence — in a state folder of its own,
apart from the documents:

- **Versions.** `save` takes a version of the folder. Every document that changed since the last version is encrypted
  under a key of its own ([legix-crypt](../legix-crypt)); the version holds only pointers to the encrypted documents,
  and the device signs it ([legix-sign](../legix-sign)). A document that did not change is not encrypted again.
- **Restore.** `versions` lists the versions of every device of the group, newest first, each with whether a member
  signed it. `restore` writes a version's documents into a new folder or one without documents, never over a file
  and never outside the folder, whatever the version holds.
- **Sync through a shared folder.** `sync` publishes this device's versions and brings the other devices', through a
  folder they share — a network share, a synced cloud folder. The shared folder holds only what is encrypted and
  signed: it can read none of it, and the devices check everything they take from it ([legix-sync](../legix-sync),
  [legix-p2p](../legix-p2p)).
- **Members.** The group decides who reads and who writes ([legix-members](../legix-members)). `found` starts a group
  with this device as its admin, and `join` asks to join one. An admin compares the request's fingerprint with the one
  the new device shows and `admit`s it as a writer or a reader; `remove` takes a device out, and the group moves to a
  key the device does not get.

The application keeps the device's `Keys` — in the operating system's keychain, as one secret — and hands them in.

```rust
use legix_folder::{Folder, Keys, Role};

// The first device starts the history and syncs it through a shared folder.
let keys = Keys::generate("laptop")?;
keychain.store(&keys.to_secret()?)?;
let mut folder = Folder::found(state, documents, keys, "ada@example.com")?;
folder.set_relay(Some(shared.clone()))?;
folder.save("Heads of terms")?;
folder.sync()?;

// Another device asks to join, and shows its fingerprint.
let (other, _) = Folder::join(other_state, other_documents, Keys::generate("desktop")?, "bo@example.com",
    folder.settings().group, shared)?;
println!("{}", other.fingerprint());

// The admin compares it with the request, and adds the device.
for request in folder.requests()? {
    if request.fingerprint() == fingerprint_on_the_other_screen {
        folder.admit(&request, Role::Writer)?;
    }
}
other.sync()?; // now a member: it reads the history
for version in other.versions()? {
    println!("{} {} {:?}", version.time, version.message, version.signed);
}
```

## Layout and stability

The state folder holds a bare repository of the versions, the encrypted documents, their keys wrapped with the store
key, the device's mirror of its group, and two small text files: the folder's settings and an index that spares
re-reading unchanged documents. The formats of everything shared are those of the crates above, specified in their
FORMAT.md files; the settings and the index are local to the device and versioned.

The API follows semantic versioning. The crate needs Rust 1.88: it syncs through shared folders with `legix-p2p`'s
`replicate`, without iroh.

The cryptography has not yet had an independent audit.

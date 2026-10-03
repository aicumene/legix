# legix-folder

A folder of documents with a signed, encrypted, synced history: leGix for an application in one type.

A `Folder` keeps the history of the folder a person works in — drafts, letters, evidence — in a state folder of its own,
apart from the documents:

- **Versions.** `save` takes a version of the folder. Every document that changed since the last version is encrypted
  under a key of its own ([legix-crypt](../legix-crypt)); the version holds only pointers to the encrypted documents,
  and the device signs it ([legix-sign](../legix-sign)). A document that did not change is not encrypted again.
- **Moved.** A folder that moved — to another disk, or with an app's container on iOS when the app is updated —
  keeps its history: `set_work` tells the history where its documents are now. A folder that is not there is never
  saved as one without documents.
- **Notes.** An application keeps its notes about the documents — a reading copy, a comment — in `.legix/` at the
  top of the folder: versioned, synced, encrypted and signed with the documents, hidden from the person, and never
  counted as a document (`is_note` tells them apart). Every other hidden file stays out of the history.
- **Restore.** `versions` lists the versions of every device of the group, newest first, each with whether a member
  signed it. `restore` writes a version's documents into a new folder or one without documents, never over a file
  and never outside the folder, whatever the version holds.
- **Bring in.** `incoming` lists the newest version of each other device that this one has not taken in, and
  `bring_in` takes it into the folder: what only the other device changed, added or removed comes in as it is there;
  what only this one changed stays; a text document (`.md`, `.txt`) both changed in different lines is merged line by
  line; any other document both changed stays, and the other device's is written next to it, named after that device.
  A document one removed and the other changed stays, as changed. When the other version already holds this device's
  last one, the folder simply moves forward to it; otherwise a new version, with both as parents, records the merge.
  Nothing is written while the folder holds unsaved changes (`changes` lists them) or a document needed from the
  other version cannot be read here yet.
- **Sync through a shared folder.** `sync` publishes this device's versions and brings the other devices', through a
  folder they share — a network share, a synced cloud folder. The shared folder holds only what is encrypted and
  signed: it can read none of it, and the devices check everything they take from it ([legix-sync](../legix-sync),
  [legix-p2p](../legix-p2p)). One that is not connected is never made anew where it was: sync waits for it.
- **Sync directly** (feature `p2p`). Devices also sync device to device over iroh — on one network or across the
  internet, through NAT and, failing that, through relays that carry only ciphertext. `Keys::endpoint_key` gives the
  device's endpoint key, derived from its signing key; `Folder::peer` is the device's part for the application's
  endpoint (`Peers` answers for every history on it), and `Folder::sync_direct` syncs with every device the group's log
  shows, and with those this device was told of (`Folder::add_peer` — the endpoint in an invitation). A device that
  asked to join without a shared folder knocks: its request reaches the admins of the devices it reaches, and once
  added, its next sync brings the history. `sync_direct_holding` takes the application's lock and holds it only
  while the device works on its folder, not while it waits on the network.
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
`replicate`, without iroh; with the feature `p2p` it needs Rust 1.91, as iroh does.

The cryptography has not yet had an independent audit.

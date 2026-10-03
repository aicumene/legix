# legix-members

Membership for leGix: a signed log of who may read and write a repository, the group's keys sealed for every member, a
new key when a member leaves — and no trust in the relay that keeps the log.

- **A signed log.** Each entry adds devices, changes their roles or removes them, and is signed by an admin of the group
  as it stood. Entries are chained by hash; the id of the first is the group's id, which every device pins. The relay
  can neither forge, reorder nor roll back the log, nor show a device another one.
- **Roles.** Admins change the membership; writers publish; readers read.
- **Keys per epoch.** The group key is sealed for every member's X25519 recipient, as age seals for an X25519 recipient.
  Removing a device starts a new epoch whose key the device does not get: it reads nothing written after. Each new key
  encrypts the one before, so a member added later reads the whole history.
- **Revocation without clocks.** Removing a device, or making it a reader, names its last bundle that counts. Later
  bundles are refused, whatever time they claim.
- **Joining.** A device signs a join request with its keys and leaves it on the relay. The admin compares the device's
  fingerprint with the one the device shows — in person, by phone — and adds it; the signature guarantees nobody swapped
  the recipient on the way.

```rust
use legix_members::{Identity, JoinRequest, Members, Role, found};

// The founder: the first entry makes it an admin; its id is the group's id.
let first = found(&ada_key, &ada_identity, "ada@example.com", &[])?;
relay.put_member_entry(1, first.as_bytes())?;
let group = first.id().into();

// A device asks to join; an admin checks its fingerprint and adds it.
let request = JoinRequest::new(&bo_key, &bo_identity, "bo@example.com")?;
relay.put_join(&request.device(), request.as_bytes())?;
let members = Members::load(&relay, &group, &ada_identity, &pin)?;
let entry = members.change().add(request, Role::Writer).sign(&ada_key)?;
relay.put_member_entry(entry.seq(), entry.as_bytes())?;

// Later: remove a device, keeping its bundles up to 12. The group moves to a new key.
let entry = members.change().remove(lost_laptop, 12).sign(&ada_key)?;
```

`Members` implements `legix_sync::Access`: give it to a `legix_sync::Replica`, and sync publishes under the current key
and applies only the bundles the membership allows.

## Formats and stability

The join request, the entries, the rules and the sealing are specified in [FORMAT.md](FORMAT.md), with test vectors that
an independent implementation on OpenSSL reproduces. The formats are versioned; a released version stays readable. The
API follows semantic versioning.

A removed device keeps what it could read before its removal. The cryptography has not yet had an independent audit.

# legix-sync formats, version 2

This document specifies how leGix devices sync a repository through a relay they do not trust: what a device writes,
what the relay keeps and what a device checks before it applies anything. Another implementation that follows it
interoperates with `legix-sync`.

Version 2 adds epochs: the group's key changes when its membership does. Version 1, which no release carried, is not
read.

## Overview

Every device writes only its own branches and tags. It publishes them in **bundles**: each bundle carries the git
objects that are new since the device's previous bundle, a snapshot of the device's branches and tags, the documents the
new commits point to and the documents the device erased. A device's bundles form a chain: each names the previous one
by its hash, so a relay cannot reorder or replace a device's bundles, or drop one from the middle of its chain, without
the readers noticing. It can hold back the newest ones; readers then see the chain up to where it stops.

A bundle is two parts:

- the **head**, small and in the clear, signed by the device: who wrote it, its place in the chain, and which body it
  belongs to;
- the **body**, encrypted: the list of documents and erasures, then a standard git bundle — the device's refs, the
  prerequisites and a pack.

The relay can check every signature, every chain and every object's integrity, and can read none of the content.

Documents travel as [legix-crypt](../legix-crypt/FORMAT.md) objects, which are already encrypted under a key per
document. Their keys travel in **envelopes**, encrypted for the members, one per document and kept apart from the
bundles: bundles are kept forever, envelopes are deleted when a document is erased.

## Primitives and keys

The primitives are those of legix-crypt: XChaCha20-Poly1305, BLAKE3, and the legix-crypt/1 object format. Signatures are
SSH signatures ([SSHSIG](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig)) with SHA-512, as
`ssh-keygen -Y sign` makes them.

- **Device key**: an SSH signing key (Ed25519 or ECDSA P-256) per device.
- **Device id**: the SHA-256 hash of the device's public key in SSH wire encoding — the digest of its `SHA256:`
  fingerprint — written as 64 lowercase hex digits.
- **Group key**: 32 random bytes the members share for one **epoch**. It wraps bundle keys and document keys. The relay
  never has it.
- **Access**: who may publish, and the group key of each epoch. It comes from one of two places:
  - the group's membership log ([legix-members](../legix-members/FORMAT.md)), which starts a new epoch with a new key
    whenever a device is removed, and names for each device the epochs it may publish in and its last bundle that
    counts;
  - or the application: one group key, in epoch 1, and the members as an allowed-signers list (the format of
    `ssh-keygen`), where a key may publish when an entry lists it for the namespace `legix-bundle` (or for every
    namespace) and is valid at the bundle's time.
- **Bundle key**: 32 random bytes, new for every bundle; the body is encrypted under it.

## Head

A head is UTF-8 text: eight lines, each ending in a line feed, then the armored signature.

```
legix-bundle/2
device <device id>
seq <n>
prev <64 lowercase hex digits>
time <Unix seconds>
epoch <e>
body blake3:<64 lowercase hex digits> <length>
key <144 lowercase hex digits>
-----BEGIN SSH SIGNATURE-----
…
-----END SSH SIGNATURE-----
```

- `seq` counts the device's bundles from 1. `prev` is the id of bundle `seq - 1` of the same device, and 64 zeros for
  bundle 1.
- `time` is when the bundle was written. It never decreases along a device's chain.
- `epoch` is the epoch whose group key wraps the bundle key, from 1.
- `body` is the id and the length of the body object.
- `key` is `nonce || ciphertext || tag`, 72 bytes in hex:

  ```
  nonce = 24 random bytes
  ciphertext || tag = XChaCha20-Poly1305-Encrypt(group key of the epoch, nonce, bundle key,
      associated data = "legix-bundle/2 key " || device id (32 bytes) || seq (8 bytes, big-endian)
                        || epoch (8 bytes, big-endian) || body id (32 bytes))
  ```

- The signature is an SSHSIG by the device key in the namespace `legix-bundle` over the eight lines, line feeds included.
- Numbers are decimal without leading zeros. No other lines, spaces or carriage returns are allowed, so a head has
  exactly one text form.
- The **id** of a bundle is the BLAKE3 hash of its whole head, signature included.

## Body

The body is a legix-crypt/1 object encrypted under the bundle key. Its plaintext is:

```
document blake3:<64 hex digits>      zero or more, sorted, no duplicates
erased blake3:<64 hex digits>        zero or more, sorted, no duplicates
<empty line>
<git bundle>
```

- `document` lines name the documents the bundle's new commits point to: the legix-crypt pointers among the blobs of the
  pack.
- `erased` lines name the documents the device erased since its previous bundle.
- The git bundle is in git's [bundle format](https://git-scm.com/docs/gitformat-bundle): version 2 for SHA-1 repositories,
  version 3 with the capability `@object-format=sha256` for SHA-256 repositories.
  - Its references are the device's complete snapshot: every branch (`refs/heads/…`) and every tag (`refs/tags/…`),
    and no other refs. A ref that is missing from the snapshot was deleted.
  - Its prerequisites are the objects outside the pack that the snapshot needs: the parents of new commits that are not
    new themselves, the commits new annotated tags point to when they are not new, and the targets of refs that are not
    in the pack. The comment after a prerequisite is empty.
  - Its pack holds the objects that are new since the device's previous bundle and since the bundles the device had
    applied from other devices. A bundle with no new objects has a pack with no entries.

Once decrypted, the git bundle is an ordinary git bundle: `git bundle verify` and `git fetch` read it.

## Envelope

An envelope carries a document key to the members:

```
envelope = "legix-envelope/2\n" || epoch || nonce || ciphertext || tag       17 + 8 + 24 + 32 + 16 = 97 bytes
epoch    = the epoch whose group key seals the envelope, 8 bytes, big-endian
nonce    = 24 random bytes
ciphertext || tag = XChaCha20-Poly1305-Encrypt(group key of the epoch, nonce, document key,
                        associated data = "legix-envelope/2 " || epoch (8 bytes, big-endian) || document id (32 bytes))
```

An envelope opens only with the group key of its epoch and only as the key of its document. A device writes envelopes in
the current epoch; an envelope keeps its epoch, and members read it with the key of that epoch.

## Relay

A relay keeps six kinds of things. The directory layout below is that of a relay in a shared folder; another relay
keeps the same things under the same names.

```
heads/<device id>/<seq as 20 digits, zero-padded>    heads, never replaced
objects/<2 hex>/<62 hex>                              bodies and documents, legix-crypt objects named by their id
envelopes/<2 hex>/<62 hex>                            envelopes, by document id
erased/<2 hex>/<62 hex>                               empty: the envelope of this document was erased
members/<seq as 20 digits, zero-padded>               the entries of the membership log, never replaced
joins/<device id>                                     the latest join request of each device
```

A relay:

- keeps heads append-only: it never replaces a head, and never accepts head `n` of a device before head `n - 1`;
- keeps an object only if it hashes to its id;
- keeps the first envelope of a document — a later one changes nothing — deletes it when it is erased, and refuses
  envelopes for erased documents from then on;
- keeps the membership log append-only, as it keeps heads: it never replaces an entry, and never accepts entry `n`
  before entry `n - 1` — of two admins that write entry `n` at once, it keeps the first;
- may check every head's signature against the members, and refuse heads that are not from a member.

## Writing a bundle

A device:

1. takes its snapshot: every branch and tag;
2. finds the new commits: those reachable from the snapshot but not from its previous snapshot or from the refs it
   applied from other devices; and the new objects: the new commits, their trees and what they add compared with their
   parents, and new annotated tags;
3. uploads the objects and the envelopes of the documents the new blobs point to, where it holds them;
4. deletes the envelopes and the objects of the documents it erased, from the relay;
5. writes the body, encrypts it under a new bundle key and uploads it;
6. writes the head, signs it and uploads it last, so that a head is never visible before its body.

## Reading a bundle

A device reads each other device's chain in order, from the bundle after the last one it applied. For each head it
checks, and refuses the head on the first failure:

1. the head has exactly the form above, `device` is the chain's device and `seq` the next number;
2. the signature is good, in the namespace `legix-bundle`, by a key whose device id is `device`;
3. the access allows the device to publish this bundle: for a membership log, the device is or was a member, `epoch`
   is one of its epochs and `seq` is not past its cutoff; for an allowed-signers list, an entry allows the key in the
   namespace `legix-bundle` at `time`, and `epoch` is 1;
4. `prev` is the id of the bundle it applied before from this device, and `time` is not earlier than that bundle's;
5. the body has the id and the length in the head;
6. the reader holds the group key of `epoch`, the bundle key opens with it, and the body opens under the bundle key. A
   device removed from the group holds no key for the epochs after its removal, and reads nothing written in them.

Then it applies the body:

7. the git bundle refers only to branches and tags, and every prerequisite is present — if not, the bundle waits until
   the bundles of other devices that provide them are applied;
8. it stores the pack, and checks that the commits and trees of the snapshot are complete;
9. it sets the device's refs to the snapshot under `refs/legix/devices/<device id>/heads/…` and `…/tags/…`, and deletes
   those that are no longer in the snapshot;
10. it fetches the documents and their envelopes that are on the relay, and keeps a key only if the document's object
    commits to it (legix-crypt's key commitment);
11. it erases the documents in `erased` lines: their keys are destroyed and refused from then on.

A device that finds a head whose `prev` is not the bundle it applied before has found a fork: the device or the relay
wrote two different bundles at one place in the chain. It applies nothing more from that device.

## Erasure

Erasing a document destroys its key on the erasing device, deletes its envelope and its object from the relay, and is
announced in the device's next bundle; every member that applies the bundle destroys its copy of the key and refuses the
key from then on. Bundles never carry document keys, so the relay's copies of bundles reveal no key after erasure.

The guarantee depends on the relay deleting the envelope and on every member applying the erasure. A relay that keeps a
deleted envelope keeps it readable to holders of the key of its epoch: the members of that epoch and, because each new
key encrypts the one before, every later member. A device removed from the group holds no key of the epochs after its
removal, so envelopes written since are closed to it.

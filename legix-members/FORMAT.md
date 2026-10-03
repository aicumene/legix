# legix-members formats, version 1

This document specifies, byte by byte, the membership of a leGix group: the join request a device sends, the log of
entries that adds, changes and removes devices, the rules every entry keeps, and how the group's keys are sealed for
the members. Another implementation that follows it reads and writes the same bytes. The test vectors at the end come
out of `legix-members` and out of an independent implementation on OpenSSL.

## Overview

A group is the set of devices that share a repository. Its membership is a log: a chain of entries, each signed by an
admin of the group as it stood before the entry. The first entry founds the group, and its id is the **group id**,
which every device pins. A relay keeps the log; it cannot forge an entry, reorder entries or roll the log back without
the devices noticing.

- **Roles.** An admin changes the membership, reads and publishes bundles. A writer reads and publishes. A reader reads.
- **Epochs.** The group has one key per epoch, from epoch 1. Each key is sealed for every member's recipient. Removing
  a device starts a new epoch whose key is sealed only for the devices that remain, so the removed device reads nothing
  written after. Each new key also encrypts the one before, so a device that holds the current key holds every earlier
  one, and a member added later reads the whole history.
- **Cutoffs.** Removing a device, or making it a reader, names its last bundle that still counts. Readers apply its
  bundles up to that one and refuse later ones, whatever time they claim.

## Primitives and keys

The primitives are those of legix-sync: SSH signatures (SSHSIG, SHA-512), BLAKE3, ChaCha20-Poly1305 and
XChaCha20-Poly1305, HKDF-SHA-256; and X25519 ([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)).

- **Device key**: the device's SSH signing key, and its **device id**, as in legix-sync.
- **Identity**: an X25519 secret key per device, 32 random bytes. Its public key is the device's **recipient**, written
  `x25519:` and 64 lowercase hex digits.
- **Group key** of an epoch: 32 random bytes.

## Join request

A device asks to join with a join request: UTF-8 text, six lines each ending in a line feed, then the armored signature.

```
legix-join/1
device <device id>
key <the device's public key, in OpenSSH form without a comment: type, space, base64>
recipient x25519:<64 lowercase hex digits>
principal <a name: 1 to 200 bytes, no spaces, no control characters>
time <Unix seconds>
-----BEGIN SSH SIGNATURE-----
…
-----END SSH SIGNATURE-----
```

- `device` is the device id of `key`.
- The signature is an SSHSIG by `key` in the namespace `legix-join` over the six lines.

An admin adds a device only after comparing the fingerprint of `key` (`SHA256:…`, as `ssh-keygen -l` shows it) with the
one the device shows, over a channel the relay does not control. The signature then guarantees that the recipient is
the device's own: nobody on the way can substitute theirs.

## Entry

An entry is UTF-8 text: six header lines, the change lines, then the armored signature.

```
legix-members/1
group <group id>                              64 zeros in entry 1
seq <n>                                       from 1
prev <id of entry n - 1>                      64 zeros in entry 1
time <Unix seconds>
epoch <e>                                     the epoch after the entry; 1 in entry 1
add <role> <the join request, hex>            zero or more
role <device id> <role> <cutoff or ->         zero or more
remove <device id> <cutoff>                   zero or more
key <device id> <sealed group key, hex>       zero or more
previous <previous group key, hex>            zero or one
-----BEGIN SSH SIGNATURE-----
…
-----END SSH SIGNATURE-----
```

- Roles are `admin`, `writer` and `reader`. A cutoff is a bundle's place in the device's chain, in decimal.
- Lines come in this order of kinds: `add`, `role`, `remove`, `key`, `previous`. Within a kind they are sorted by device
  id (for `add`, the device id inside the request), with no device twice.
- `add` carries the whole join request, its bytes in lowercase hex.
- The signature is an SSHSIG in the namespace `legix-members` over all lines before it.
- Numbers are decimal without leading zeros. Nothing else is allowed, so an entry has exactly one text form.
- The **id** of an entry is the BLAKE3 hash of the whole entry, signature included. The **group id** is the id of
  entry 1.
- An entry is at most 4 MiB.

## Rules

Entry `n` is applied to the membership after entry `n - 1` — for entry 1, to a group with no members, no epoch and the
time 0 — and is refused unless:

1. `seq` is `n`, `prev` is the id of entry `n - 1`, and `group` is the group id (64 zeros in entry 1);
2. `time` is not earlier than the time of entry `n - 1`;
3. `epoch` is 1 in entry 1; later, it is the epoch before or the one after. An entry that moves to the next epoch is a
   **rotation**; entry 1 counts as one;
4. the signature is good and made by an admin of the group before the entry, with the key the group knows for that
   admin. Entry 1 is signed by a device that it adds as an admin;
5. no device appears in more than one `add`, `role` or `remove` line;
6. `add`: the join request is valid, and its device is not and never was a member. A device added as a reader has the
   cutoff 0;
7. `role`: the device is a member and the role is not the one it has. Making it a reader names a cutoff; making it an
   admin or a writer names none (`-`) and ends its cutoff;
8. `remove`: the device is a member, and the cutoff is not later than a cutoff the device has. The device leaves the
   group; its last epoch is the epoch before the entry;
9. at least one admin remains;
10. an entry that removes a device is a rotation;
11. `key` lines: in a rotation, exactly one for every member after the entry; otherwise exactly one for every device the
    entry adds. They seal the key of the entry's epoch;
12. `previous`: present exactly in rotations after entry 1.

## Sealed group key

A group key is sealed for a recipient as [age](https://age-encryption.org/v1) seals a file key for an X25519 recipient,
with leGix's own labels and the entry's context:

```
ephemeral secret = 32 random bytes
ephemeral share  = X25519(ephemeral secret, 9)
shared secret    = X25519(ephemeral secret, recipient)              refused if it is 32 zero bytes
wrap key = HKDF-SHA-256(ikm = shared secret, salt = ephemeral share || recipient,
                        info = "legix-members/1 key " || group || epoch (8 bytes, big-endian))
sealed   = ephemeral share || ChaCha20-Poly1305-Encrypt(wrap key, nonce = 12 zero bytes, group key)     80 bytes
```

`group` is the 32 bytes of the entry's `group` line — zeros in entry 1 — and `epoch` the entry's epoch. To open it, the
recipient computes the shared secret from its identity and the ephemeral share.

## Previous key

A rotation carries the key of the epoch before, encrypted under the new one:

```
previous = nonce || XChaCha20-Poly1305-Encrypt(new group key, nonce, previous group key,
                        associated data = "legix-members/1 previous " || group || epoch (8 bytes, big-endian))
nonce    = 24 random bytes                                                                        72 bytes
```

## A device's keys

A device opens the `key` line sealed for it in the latest entry that has one: that is the key of that entry's epoch.
With it, it opens the `previous` line of the entry that started that epoch, which gives the key of the epoch before,
and so on back to epoch 1. A removed device keeps the keys up to its last epoch and has none after.

## Sync

The group decides who publishes bundles in legix-sync. A bundle of device `D`, at place `s` in its chain, written in
epoch `e`, is applied only if:

- `D` is or was a member, and the bundle is signed with the key the group knows for it;
- `e` lies from the epoch `D` was added in to its last epoch — the current epoch while it is a member;
- `s` is not later than `D`'s cutoff, if it has one.

A device publishes in the current epoch, with its key, and only while it is an admin or a writer.

## Relay

The relay keeps the log next to the bundles (legix-sync, version 2):

```
members/<seq as 20 digits, zero-padded>    entries, never replaced, without gaps
joins/<device id>                          the latest join request of each device
```

Two admins that write entry `n` at once: the relay keeps the first, and refuses the second, whose admin reads the log
again and writes its change as entry `n + 1`.

## Pinning

A device keeps the group id and the place and id of the last entry it checked. It refuses a log whose first entry does
not have the group id, that ends before that place, or that holds another entry there. A device that joins gets the
group id from an admin, over a channel the relay does not control, with the relay's address.

## Test vectors

Identity `50 51 … 6f`:

```
recipient x25519:392d174a38b3b1beafaf1fe824870841c5fa531bc6eafdb6402c124664488c1c
```

Group key `00 01 … 1f` sealed for that recipient with the ephemeral secret `70 71 … 8f`, `group` = 32 bytes `22`,
epoch 2:

```
23b7bb8c91ae008711fb12846780bcdf1e065f821bdfec49f57e7c7dcd4c4823b72fba6197a024334748d564b1f29cbfe33727
9a7efcecd78b770ff783d260a7285209d395eb4df1e03ae94dd2f1b70f
```

Previous key `00 01 … 1f` under the group key `40 41 … 5f`, nonce `10 11 … 27`, `group` = 32 bytes `22`, epoch 2:

```
101112131415161718191a1b1c1d1e1f2021222324252627524aeb4005f948255478563928585cf9143dd2e3b429d5db09a7b45
62c252f0005291fa635c2dbf55c170fa1e77eca89
```

# legix-p2p formats, version 1

This document specifies how two devices of a leGix group sync directly over [iroh](https://www.iroh.computer): the
endpoint certificate that ties a device to its iroh endpoint, the protocol on the connection, and the checks a device
makes before it keeps anything. Another implementation that follows it interoperates with `legix-p2p`.

## Mirrors

Each device keeps a **mirror** of its group: a relay (legix-sync, version 2) that only this device writes to, holding
the membership log, the bundles of every device, the objects, the envelopes, the join requests and the endpoint
certificates it has seen. The device's replica pushes to and pulls from its mirror. Syncing two devices brings each
mirror what the other has; syncing a mirror with a shared folder or another relay does the same, with the same checks.

A device that was online when others were not carries their bundles to the next device it meets. Bundles are signed
by their authors and checked by every device that keeps them, so the device in between can pass on only what their
authors wrote.

## Endpoint certificate

iroh identifies an endpoint by an Ed25519 public key, its **endpoint id**, and authenticates it on every connection. A
device ties its endpoint to itself with a certificate: UTF-8 text, four lines each ending in a line feed, then the
armored signature.

```
legix-endpoint/1
device <device id>
endpoint <the endpoint id: its 32 bytes, 64 lowercase hex digits>
time <Unix seconds>
-----BEGIN SSH SIGNATURE-----
…
-----END SSH SIGNATURE-----
```

- The signature is an SSHSIG in the namespace `legix-endpoint` over the four lines, by the key whose device id is
  `device`.
- The certificate counts while the device is a member of the group with that key.
- A device leaves its certificate on its relays (`endpoints/<device id>`); of two certificates of a device, the later
  one counts.

## Connection

A device dials another with the ALPN `legix/sync/1`. On the connection, the dialer opens one bidirectional stream;
everything travels on it as **frames**:

```
frame = kind (1 byte) || length of the payload (8 bytes, big-endian) || payload
```

| Kind | Name | Payload | Longest payload |
|---|---|---|---|
| 1 | hello | group id (32 bytes) ‖ the sender's endpoint certificate | 32 + 64 KiB |
| 2 | inventory | the sender's inventory | 256 MiB |
| 3 | entry | place (8 bytes) ‖ the entry | 8 + 4 MiB |
| 4 | endpoint | device id (32) ‖ the certificate | 32 + 64 KiB |
| 5 | join | device id (32) ‖ the join request | 32 + 64 KiB |
| 6 | head | device id (32) ‖ place (8) ‖ the head | 40 + 64 KiB |
| 7 | object | object id (32); the object follows in chunks | 32 |
| 8 | chunk | up to 1 MiB of the object | 1 MiB |
| 9 | object end | — | 0 |
| 10 | envelope | document id (32) ‖ the envelope | 32 + 1 KiB |
| 11 | end | — | 0 |
| 12 | done | — | 0 |

A frame of another kind, or longer than its kind allows, ends the connection.

## Inventory

An inventory says what a mirror holds:

```
inventory = log place (8) || log id (32)                         0 and 32 zeros for a mirror without a log
            || n (4) || n × (device id (32) || last head place (8))
            || n (4) || n × object id (32)
            || n (4) || n × document id (32)                     envelopes
            || n (4) || n × device id (32)                       join requests
            || n (4) || n × (device id (32) || time (8))         endpoint certificates
```

Numbers are big-endian; at most 4,194,304 items of a kind. A sender gives the receiver what it holds and the receiver
does not: the entries after the receiver's last; the certificates the receiver lacks or holds older; the join
requests it lacks; for each device, the heads after the receiver's last; the objects and the envelopes it lacks — in
this order, so that the log arrives before what it decides.

## Protocol

1. The dialer sends **hello**. The other device, the **acceptor**, checks that the group id is its group, that the
   certificate is good, that it names the endpoint at the other end of the connection, and that its device is a
   member — by the acceptor's own log. If not, it closes the connection and gives nothing.
2. The acceptor sends **hello**; the dialer checks the group and the certificate the same way. If the dialer's log
   does not show the acceptor as a member — a device that just joined has no log yet — it decides once the acceptor's
   log has arrived, and gives nothing in this sync.
3. Both send their **inventory**.
4. Both give, at once, the items the other lacks, then **end**. Until a device knows the other to be a member, it takes
   only entries; the first other frame from a peer that the log, as it then stands, does not show as a member ends the
   sync.
5. Both send **done** once they have taken everything up to the other's **end**, and finish the stream. The dialer
   closes the connection after the acceptor's **done**.

## What a device keeps

A device checks every item before its mirror keeps it, and refuses the item otherwise; a refused item is reported and
the sync goes on.

- **Entry** `n`: it is the next entry of the mirror's log, it is entry 1 of the group (its id is the group id) when the
  log is empty, and it keeps the rules of the membership log ([legix-members](../legix-members/FORMAT.md)).
- **Endpoint certificate**: it is good, its device is a member, and it is later than the one the mirror holds.
- **Join request**: it is good and it is the device's own.
- **Head** `n` of a device: it is the next head of the device in the mirror; it names that device and place; its
  `prev` is the id of the head before it and its time is not earlier; its signature is good; and the membership allows
  the device to publish it — its epoch and its place within the device's epochs and cutoff.
- **Object**: it hashes to its id.
- **Envelope**: it opens with the group's key of its epoch, as the key of its document. An envelope of a document the
  mirror erased stays out.

A mirror therefore never holds an item that its own device would refuse, and nothing a peer sends can take the place
of an item its author has yet to send.

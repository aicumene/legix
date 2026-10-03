# legix-p2p

Device-to-device sync for leGix over [iroh](https://www.iroh.computer): on the local network and through NAT, between
members of a group only, with nothing to trust in between.

- **Mirrors.** Each device keeps a mirror of its group — the log, the bundles, the documents it has seen — and its
  `legix_sync::Replica` pushes to and pulls from it. Two devices that reach each other sync their mirrors directly.
- **Members only.** iroh authenticates the endpoint at the other end; an endpoint certificate, signed with the device's
  key, ties that endpoint to the device; the group's membership log ties the device to the group. A device that is not
  a member is turned away before it is given anything.
- **Checked before it is kept.** Entries are checked against the log, bundles against their chains, their signatures
  and the membership, objects against their ids, envelopes against the group's keys. A device carries the bundles of
  devices that are offline to the next device it meets, and can alter none of them.
- **Joining over the network.** A device that asked to join and is not a member yet *knocks*: it gives its own signed
  request, the device it reached keeps it for the admins and gives nothing else. Once an admin adds the device, its
  next sync brings the log and the history.
- **One endpoint, many groups.** `Peers` answers for every group a device keeps, each from its own mirror, and groups
  come and go while the endpoint answers.
- **Any path.** iroh connects directly, punching through NAT, and falls back to relays; the application chooses its
  relays and its discovery, on the local network or beyond. `replicate` syncs a mirror with a shared folder or another
  relay on the same machine, with the same checks.

```rust
use std::sync::Arc;

use iroh::{Endpoint, endpoint::presets, protocol::Router};
use legix_p2p::{ALPN, EndpointCert, Peer};

let endpoint = Endpoint::builder(presets::N0).secret_key(secret_key).alpns(vec![ALPN.to_vec()]).bind().await?;
let certificate = EndpointCert::new(&device_key, endpoint.id())?;
let peer = Arc::new(Peer::new(mirror, group_id, identity, certificate)?);
let router = Router::builder(endpoint.clone()).accept(ALPN, peer.clone()).spawn(); // answer the others

for (device, endpoint_id) in peer.peers()? {
    let synced = peer.sync_with(&endpoint, endpoint_id).await?; // and dial them
}
```

## Formats and stability

The endpoint certificate, the frames, the inventory, the protocol and the checks are specified in
[FORMAT.md](FORMAT.md). The formats are versioned; a released version stays readable. The API follows semantic
versioning, and follows iroh's for the types it takes from iroh. With its default feature `iroh` the crate needs Rust
1.91, as iroh does; without it, it offers `replicate` and its checks, and needs Rust 1.88.

The cryptography has not yet had an independent audit.

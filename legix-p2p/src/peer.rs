//! A device's part in device-to-device sync.

use std::collections::BTreeMap;

use iroh::{
    Endpoint, EndpointAddr, EndpointId,
    endpoint::{Connection, RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler},
};
use legix_crypt::Oid;
use legix_members::{GroupId, Identity, JoinRequest, Members};
use legix_sync::{DeviceId, Relay};

use crate::{EndpointCert, Error, Inventory, error::connection_error, intake::Intake, inventory::Item, wire};

/// The ALPN of leGix's device-to-device sync.
pub const ALPN: &[u8] = b"legix/sync/1";

/// What a sync brought and gave.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Synced {
    /// The device synced with; `None` for [`replicate`].
    pub peer: Option<DeviceId>,
    /// What was kept of what the other side gave.
    pub received: Counts,
    /// What was given.
    pub sent: Counts,
    /// What was refused, and why.
    pub refused: Vec<Refusal>,
}

/// How many items of each kind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Counts {
    /// Entries of the membership log.
    pub entries: usize,
    /// Endpoint certificates.
    pub endpoints: usize,
    /// Join requests.
    pub joins: usize,
    /// Bundle heads.
    pub heads: usize,
    /// Objects: bundle bodies and documents.
    pub objects: usize,
    /// Envelopes of document keys.
    pub envelopes: usize,
}

/// An item that was not kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The item.
    pub item: String,
    /// Why it was not kept.
    pub reason: String,
}

/// A device's part in device-to-device sync: its mirror of the group — a relay it alone writes to, which its
/// `legix_sync::Replica` pushes to and pulls from — and the keys and certificate it syncs with.
///
/// Two devices that sync check that each is a member of the group, then give each other what the other's mirror lacks.
/// Every item is checked before a mirror keeps it, so a device that carries the bundles of others — because it was
/// online when they were not — can pass on only what their owners wrote.
#[derive(Debug)]
pub struct Peer<R> {
    mirror: R,
    group: GroupId,
    identity: Identity,
    certificate: EndpointCert,
}

impl<R: Relay + Send + Sync + 'static> Peer<R> {
    /// This device's part in syncing the group `group`, with its mirror `mirror`, its `identity` and its endpoint
    /// certificate, which the mirror keeps for the other devices to find.
    pub fn new(mirror: R, group: GroupId, identity: Identity, certificate: EndpointCert) -> Result<Self, Error> {
        mirror.put_endpoint(&certificate.device(), certificate.as_bytes())?;
        Ok(Peer {
            mirror,
            group,
            identity,
            certificate,
        })
    }

    /// The mirror.
    pub fn mirror(&self) -> &R {
        &self.mirror
    }

    /// The members' devices whose endpoint certificates the mirror holds, but this one: the devices to sync with.
    pub fn peers(&self) -> Result<Vec<(DeviceId, EndpointId)>, Error> {
        let members = Members::read(&self.mirror, &self.group, &self.identity)?;
        let mut peers = Vec::new();
        for bytes in self.mirror.endpoints()? {
            if let Ok(certificate) = EndpointCert::parse(&bytes)
                && certificate.is_member(&members)
                && certificate.device() != self.certificate.device()
            {
                peers.push((certificate.device(), certificate.endpoint()));
            }
        }
        Ok(peers)
    }

    /// Sync with the device at `addr`, through `endpoint`: check that it is a member, and give each other what the
    /// other lacks.
    pub async fn sync_with(&self, endpoint: &Endpoint, addr: impl Into<EndpointAddr>) -> Result<Synced, Error> {
        let connection = endpoint.connect(addr, ALPN).await.map_err(connection_error)?;
        let result = self.dial(&connection).await;
        let (code, reason): (u32, &[u8]) = if result.is_ok() { (0, b"done") } else { (1, b"refused") };
        connection.close(code.into(), reason);
        result
    }

    /// Sync with the device that connected through `connection`. A device that is not a member is turned away before
    /// it is given anything.
    pub async fn serve(&self, connection: Connection) -> Result<Synced, Error> {
        let (mut send, mut recv) = connection.accept_bi().await.map_err(connection_error)?;
        let certificate = self.hello(&connection, &mut recv).await?;
        let mut intake = Intake::new(&self.mirror, self.group, &self.identity)?;
        if !certificate.is_member(intake.members()) {
            connection.close(2u32.into(), b"not a member");
            return Err(Error::NotMember);
        }
        self.say_hello(&mut send).await?;
        let result = self
            .exchange(&mut send, &mut recv, &certificate, &mut intake, true)
            .await;
        if result.is_ok() {
            // The device that dialed closes the connection once both sides have everything.
            connection.closed().await;
        }
        result
    }

    async fn dial(&self, connection: &Connection) -> Result<Synced, Error> {
        let (mut send, mut recv) = connection.open_bi().await.map_err(connection_error)?;
        self.say_hello(&mut send).await?;
        let certificate = self.hello(connection, &mut recv).await?;
        let mut intake = Intake::new(&self.mirror, self.group, &self.identity)?;
        // A device whose log does not show the peer as a member — one that just joined — learns the log from the
        // peer, and gives nothing in this sync.
        let verified = certificate.is_member(intake.members());
        self.exchange(&mut send, &mut recv, &certificate, &mut intake, verified)
            .await
    }

    async fn say_hello(&self, send: &mut SendStream) -> Result<(), Error> {
        wire::write(send, wire::HELLO, &[self.group.as_bytes(), self.certificate.as_bytes()]).await
    }

    /// The peer's hello: its group, which must be this one, and its certificate, which must be for the endpoint that
    /// connected.
    async fn hello(&self, connection: &Connection, recv: &mut RecvStream) -> Result<EndpointCert, Error> {
        let (kind, payload) = wire::read(recv).await?;
        if kind != wire::HELLO || payload.len() < 32 {
            return Err(Error::Protocol("expected a hello"));
        }
        let (group, certificate) = payload.split_at(32);
        if group != self.group.as_bytes() {
            return Err(Error::WrongGroup);
        }
        let certificate = EndpointCert::parse(certificate)?;
        if certificate.endpoint() != connection.remote_id() {
            return Err(Error::WrongEndpoint);
        }
        Ok(certificate)
    }

    async fn exchange(
        &self,
        send: &mut SendStream,
        recv: &mut RecvStream,
        certificate: &EndpointCert,
        intake: &mut Intake<'_, R>,
        verified: bool,
    ) -> Result<Synced, Error> {
        let mine = Inventory::of(&self.mirror)?;
        wire::write(send, wire::INVENTORY, &[&mine.encode()]).await?;
        let theirs = match wire::read(recv).await? {
            (wire::INVENTORY, payload) => Inventory::decode(&payload)?,
            _ => return Err(Error::Protocol("expected an inventory")),
        };
        let plan = if verified { mine.plan(&theirs) } else { Vec::new() };
        let (sent, taken) = tokio::join!(self.give(send, &plan), take(recv, intake, certificate, verified));
        let sent = sent?;
        taken?;
        // Each side says that it has taken everything; the side that dialed then closes the connection.
        wire::write(send, wire::DONE, &[]).await?;
        send.finish().map_err(connection_error)?;
        if wire::read(recv).await?.0 != wire::DONE {
            return Err(Error::Protocol("expected done"));
        }
        Ok(Synced {
            peer: Some(certificate.device()),
            received: intake.received,
            sent,
            refused: std::mem::take(&mut intake.refused),
        })
    }

    /// Give the items of `plan` from the mirror, then the end.
    async fn give(&self, send: &mut SendStream, plan: &[Item]) -> Result<Counts, Error> {
        let endpoints = by_device(self.mirror.endpoints()?, |bytes| {
            EndpointCert::parse(bytes).ok().map(|certificate| certificate.device())
        });
        let joins = by_device(self.mirror.joins()?, |bytes| {
            JoinRequest::parse(bytes).ok().map(|request| request.device())
        });
        let mut sent = Counts::default();
        for item in plan {
            match *item {
                Item::Entry(seq) => {
                    if let Some(entry) = self.mirror.member_entry(seq)? {
                        wire::write(send, wire::ENTRY, &[&seq.to_be_bytes(), &entry]).await?;
                        sent.entries += 1;
                    }
                }
                Item::Endpoint(device) => {
                    if let Some(certificate) = endpoints.get(&device) {
                        wire::write(send, wire::ENDPOINT, &[device.as_bytes(), certificate]).await?;
                        sent.endpoints += 1;
                    }
                }
                Item::Join(device) => {
                    if let Some(request) = joins.get(&device) {
                        wire::write(send, wire::JOIN, &[device.as_bytes(), request]).await?;
                        sent.joins += 1;
                    }
                }
                Item::Head(device, seq) => {
                    if let Some(head) = self.mirror.head(&device, seq)? {
                        wire::write(send, wire::HEAD, &[device.as_bytes(), &seq.to_be_bytes(), &head]).await?;
                        sent.heads += 1;
                    }
                }
                Item::Object(oid) => {
                    if let Some(mut object) = self.mirror.open_object(&oid)? {
                        wire::write_object(send, &oid, &mut *object).await?;
                        sent.objects += 1;
                    }
                }
                Item::Envelope(oid) => {
                    if let Some(envelope) = self.mirror.envelope(&oid)? {
                        wire::write(send, wire::ENVELOPE, &[oid.as_bytes(), &envelope]).await?;
                        sent.envelopes += 1;
                    }
                }
            }
        }
        wire::write(send, wire::END, &[]).await?;
        Ok(sent)
    }
}

impl<R: Relay + Send + Sync + std::fmt::Debug + 'static> ProtocolHandler for Peer<R> {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        self.serve(connection).await.map(drop).map_err(AcceptError::from_err)
    }
}

/// Take what the peer gives, up to its end. Until the peer is known to be a member, only entries of the log are taken:
/// the log that arrives says whether it is one.
async fn take<R: Relay + ?Sized>(
    recv: &mut RecvStream,
    intake: &mut Intake<'_, R>,
    certificate: &EndpointCert,
    mut verified: bool,
) -> Result<(), Error> {
    loop {
        let (kind, payload) = wire::read(recv).await?;
        if kind != wire::ENTRY && !verified {
            if !certificate.is_member(intake.members()) {
                return Err(Error::NotMember);
            }
            verified = true;
        }
        match kind {
            wire::END => return Ok(()),
            wire::ENTRY => {
                let (seq, entry) = split_u64(&payload)?;
                intake.entry(seq, entry)?;
            }
            wire::ENDPOINT => {
                let (device, certificate) = split_device(&payload)?;
                intake.endpoint(device, certificate)?;
            }
            wire::JOIN => {
                let (device, request) = split_device(&payload)?;
                intake.join(device, request)?;
            }
            wire::HEAD => {
                let (device, rest) = split_device(&payload)?;
                let (seq, head) = split_u64(rest)?;
                intake.head(device, seq, head)?;
            }
            wire::OBJECT => {
                let oid = Oid::from_bytes(payload.try_into().map_err(|_| Error::Protocol("an object's id"))?);
                let mut object = wire::read_object(recv).await?;
                intake.object(oid, &mut object)?;
            }
            wire::ENVELOPE => {
                let (oid, envelope) = payload
                    .split_at_checked(32)
                    .ok_or(Error::Protocol("an envelope frame"))?;
                intake.envelope(Oid::from_bytes(oid.try_into().expect("32 bytes")), envelope)?;
            }
            _ => return Err(Error::Protocol("an unexpected frame")),
        }
    }
}

/// Bring into `to` what `from` has and `to` lacks — a mirror and a synced folder, two mirrors on one machine — checking
/// each item as one from a peer: the membership log of `group`, whose keys `identity` opens, decides what `to` keeps.
pub fn replicate(
    from: &(impl Relay + ?Sized),
    to: &(impl Relay + ?Sized),
    group: &GroupId,
    identity: &Identity,
) -> Result<Synced, Error> {
    let theirs = Inventory::of(from)?;
    let mine = Inventory::of(to)?;
    let mut intake = Intake::new(to, *group, identity)?;
    let endpoints = by_device(from.endpoints()?, |bytes| {
        EndpointCert::parse(bytes).ok().map(|certificate| certificate.device())
    });
    let joins = by_device(from.joins()?, |bytes| {
        JoinRequest::parse(bytes).ok().map(|request| request.device())
    });
    for item in theirs.plan(&mine) {
        match item {
            Item::Entry(seq) => {
                if let Some(entry) = from.member_entry(seq)? {
                    intake.entry(seq, &entry)?;
                }
            }
            Item::Endpoint(device) => {
                if let Some(certificate) = endpoints.get(&device) {
                    intake.endpoint(device, certificate)?;
                }
            }
            Item::Join(device) => {
                if let Some(request) = joins.get(&device) {
                    intake.join(device, request)?;
                }
            }
            Item::Head(device, seq) => {
                if let Some(head) = from.head(&device, seq)? {
                    intake.head(device, seq, &head)?;
                }
            }
            Item::Object(oid) => {
                if let Some(mut object) = from.open_object(&oid)? {
                    intake.object(oid, &mut object)?;
                }
            }
            Item::Envelope(oid) => {
                if let Some(envelope) = from.envelope(&oid)? {
                    intake.envelope(oid, &envelope)?;
                }
            }
        }
    }
    Ok(Synced {
        peer: None,
        received: intake.received,
        sent: Counts::default(),
        refused: intake.refused,
    })
}

fn by_device(items: Vec<Vec<u8>>, device: impl Fn(&[u8]) -> Option<DeviceId>) -> BTreeMap<DeviceId, Vec<u8>> {
    items
        .into_iter()
        .filter_map(|bytes| device(&bytes).map(|device| (device, bytes)))
        .collect()
}

fn split_u64(payload: &[u8]) -> Result<(u64, &[u8]), Error> {
    let (number, rest) = payload
        .split_at_checked(8)
        .ok_or(Error::Protocol("a frame is cut short"))?;
    Ok((u64::from_be_bytes(number.try_into().expect("8 bytes")), rest))
}

fn split_device(payload: &[u8]) -> Result<(DeviceId, &[u8]), Error> {
    let (device, rest) = payload
        .split_at_checked(32)
        .ok_or(Error::Protocol("a frame is cut short"))?;
    Ok((DeviceId::from_bytes(device.try_into().expect("32 bytes")), rest))
}

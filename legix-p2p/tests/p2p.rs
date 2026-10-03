//! Devices of a group that sync directly over iroh, on this machine: endpoints on 127.0.0.1, without iroh's relays.

use std::{
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use iroh::{Endpoint, EndpointAddr, endpoint::presets, protocol::Router};
use legix_crypt::{DirKeyStore, Documents, ObjectStore, Status, StoreKey};
use legix_members::{GroupId, Identity, JoinRequest, Members, Role, found};
use legix_p2p::{ALPN, EndpointCert, Error, Peer, Peers, Synced, replicate};
use legix_sign::ssh_key::PrivateKey;
use legix_sync::{DeviceId, DirRelay, Head, Pulled, Pushed, Relay, Replica};

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args([
            "-c",
            "user.name=Ada",
            "-c",
            "user.email=ada@example.com",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", dir.join("no-global-config"))
        .env("HOME", dir)
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

struct Device {
    name: &'static str,
    repo: PathBuf,
    key: PrivateKey,
    identity: Identity,
    documents: Documents<DirKeyStore>,
}

impl Device {
    fn new(root: &Path, name: &'static str) -> Self {
        git(root, &["init", "-q", name]);
        let repo = root.join(name);
        let git_dir = repo.join(".git");
        Device {
            name,
            key: legix_sign::generate_ed25519(&format!("{name}@example.com")).unwrap(),
            identity: Identity::generate().unwrap(),
            documents: Documents::new(
                ObjectStore::new(git_dir.join("legix/objects")),
                DirKeyStore::new(git_dir.join("legix/keys"), StoreKey::generate().unwrap()),
            ),
            repo,
        }
    }

    fn id(&self) -> DeviceId {
        DeviceId::of(self.key.public_key())
    }

    fn request(&self) -> JoinRequest {
        JoinRequest::new(&self.key, &self.identity, &format!("{}@example.com", self.name)).unwrap()
    }

    /// The device's own mirror of the group.
    fn mirror(&self) -> DirRelay {
        DirRelay::new(self.repo.join(".git/legix/mirror"))
    }

    fn members(&self, group: &GroupId) -> Members {
        Members::load(
            &self.mirror(),
            group,
            &self.identity,
            &self.repo.join(".git/legix/members.pin"),
        )
        .unwrap()
    }

    fn commit(&self, file: &str, content: &str) -> String {
        fs::write(self.repo.join(file), content).unwrap();
        git(&self.repo, &["add", file]);
        git(&self.repo, &["commit", "-q", "-m", &format!("{file} by {}", self.name)]);
        git(&self.repo, &["rev-parse", "HEAD"])
    }

    fn with<T>(
        &self,
        group: &GroupId,
        f: impl FnOnce(&Replica<'_, DirRelay, Members, DirKeyStore, PrivateKey>) -> T,
    ) -> T {
        let members = self.members(group);
        let mirror = self.mirror();
        let repo = legix::open_opts(&self.repo, legix::open::Options::isolated()).unwrap();
        f(&Replica::new(&repo, &self.key, &members, &mirror, &self.documents))
    }

    fn push(&self, group: &GroupId) -> Pushed {
        self.with(group, |replica| replica.push().unwrap())
    }

    fn pull(&self, group: &GroupId) -> Pulled {
        self.with(group, |replica| replica.pull().unwrap())
    }

    fn has(&self, other: &Device, commit: &str) -> bool {
        let output = Command::new("git")
            .args(["rev-parse", &format!("refs/legix/devices/{}/heads/main", other.id())])
            .current_dir(&self.repo)
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).trim() == commit
    }
}

/// A device online: its iroh endpoint on 127.0.0.1, answering other devices of the group.
struct Online {
    endpoint: Endpoint,
    peer: Arc<Peer<DirRelay>>,
    router: Router,
}

impl Online {
    async fn start(device: &Device, group: GroupId) -> Self {
        Self::start_with(device, group, None).await
    }

    /// Online with `certificate` in place of the device's own: to stand in for another device.
    async fn start_with(device: &Device, group: GroupId, certificate: Option<EndpointCert>) -> Self {
        let endpoint = Endpoint::builder(presets::Minimal)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let certificate =
            certificate.unwrap_or_else(|| EndpointCert::new(&device.key, endpoint.id().as_bytes()).unwrap());
        let peer = Arc::new(Peer::new(device.mirror(), group, device.identity.clone(), certificate).unwrap());
        let router = Router::builder(endpoint.clone()).accept(ALPN, peer.clone()).spawn();
        Online { endpoint, peer, router }
    }

    /// Where other devices on this machine reach it.
    fn addr(&self) -> EndpointAddr {
        let port = self
            .endpoint
            .bound_sockets()
            .into_iter()
            .find(SocketAddr::is_ipv4)
            .expect("an IPv4 socket")
            .port();
        EndpointAddr::new(self.endpoint.id()).with_ip_addr(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port))
    }

    async fn sync_with(&self, other: &Online) -> Result<Synced, Error> {
        self.peer.sync_with(&self.endpoint, other.addr()).await
    }

    async fn stop(self) {
        self.router.shutdown().await.unwrap();
    }
}

/// A group that `founder` founds with `others`; the log starts in the founder's mirror only.
fn found_group(founder: &Device, others: &[(&Device, Role)]) -> GroupId {
    let requests: Vec<_> = others.iter().map(|(device, role)| (device.request(), *role)).collect();
    let first = found(
        &founder.key,
        &founder.identity,
        &format!("{}@example.com", founder.name),
        &requests,
    )
    .unwrap();
    founder.mirror().put_member_entry(1, first.as_bytes()).unwrap();
    first.id().into()
}

#[tokio::test(flavor = "multi_thread")]
async fn two_devices_sync_directly_both_ways() {
    let dir = tempfile::tempdir().unwrap();
    let (ada, bo) = (Device::new(dir.path(), "ada"), Device::new(dir.path(), "bo"));
    let group = found_group(&ada, &[(&bo, Role::Writer)]);
    let adas = ada.commit("terms.md", "Heads of terms\n");
    ada.push(&group);
    let (ada_online, bo_online) = (Online::start(&ada, group).await, Online::start(&bo, group).await);

    // Bo has no log yet: it learns it from Ada, checks Ada against it, and takes the rest.
    let synced = bo_online.sync_with(&ada_online).await.unwrap();
    assert_eq!(synced.peer, Some(ada.id()));
    assert!(synced.refused.is_empty(), "{:?}", synced.refused);
    assert_eq!((synced.received.entries, synced.received.heads), (1, 1));
    assert!(synced.received.objects >= 1, "the bundle's body");
    assert_eq!(
        synced.sent.heads, 0,
        "nothing given before Ada was known to be a member"
    );
    assert_eq!(bo.pull(&group).applied.len(), 1);
    assert!(bo.has(&ada, &adas));
    git(&bo.repo, &["fsck", "--strict", "--no-dangling"]);

    // Bo's work goes back the same way, now that each knows the other.
    let bos = bo.commit("notes.md", "Clause 4 needs a cap\n");
    bo.push(&group);
    let synced = bo_online.sync_with(&ada_online).await.unwrap();
    assert_eq!(synced.sent.heads, 1);
    assert_eq!(ada.pull(&group).applied.len(), 1);
    assert!(ada.has(&bo, &bos));

    let again = ada_online.sync_with(&bo_online).await.unwrap();
    assert_eq!(
        (again.received, again.sent),
        (Default::default(), Default::default()),
        "nothing new either way"
    );
    assert_eq!(
        ada_online.peer.peers().unwrap(),
        vec![(bo.id(), bo_online.endpoint.id())]
    );
    ada_online.stop().await;
    bo_online.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_in_between_carries_the_bundles_of_one_that_is_offline() {
    let dir = tempfile::tempdir().unwrap();
    let (ada, bo, cy) = (
        Device::new(dir.path(), "ada"),
        Device::new(dir.path(), "bo"),
        Device::new(dir.path(), "cy"),
    );
    let group = found_group(&ada, &[(&bo, Role::Writer), (&cy, Role::Writer)]);
    let adas = ada.commit("terms.md", "Heads of terms\n");
    ada.push(&group);
    let (ada_online, bo_online) = (Online::start(&ada, group).await, Online::start(&bo, group).await);
    bo_online.sync_with(&ada_online).await.unwrap();
    ada_online.stop().await;

    // Ada is offline; Cy gets Ada's bundle from Bo, signed by Ada.
    let cy_online = Online::start(&cy, group).await;
    let synced = cy_online.sync_with(&bo_online).await.unwrap();
    assert!(synced.refused.is_empty(), "{:?}", synced.refused);
    let pulled = cy.pull(&group);
    assert_eq!(pulled.applied.len(), 1);
    assert_eq!(pulled.applied[0].device, ada.id());
    assert!(cy.has(&ada, &adas));
    bo_online.stop().await;
    cy_online.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn devices_outside_the_group_are_turned_away() {
    let dir = tempfile::tempdir().unwrap();
    let (ada, bo, cy, mallory) = (
        Device::new(dir.path(), "ada"),
        Device::new(dir.path(), "bo"),
        Device::new(dir.path(), "cy"),
        Device::new(dir.path(), "mallory"),
    );
    let group = found_group(&ada, &[(&bo, Role::Writer), (&cy, Role::Writer)]);
    ada.commit("terms.md", "Heads of terms\n");
    ada.push(&group);
    let ada_online = Online::start(&ada, group).await;
    let heads_before = ada.mirror().devices().unwrap();

    // A device that is not a member.
    let mallory_online = Online::start(&mallory, group).await;
    assert!(mallory_online.sync_with(&ada_online).await.is_err());
    assert!(mallory.mirror().head(&ada.id(), 1).unwrap().is_none(), "given nothing");

    // A device that holds a member's certificate, but not its endpoint.
    let bo_online = Online::start(&bo, group).await;
    bo_online.sync_with(&ada_online).await.unwrap();
    let bos_certificate = EndpointCert::new(&bo.key, bo_online.endpoint.id().as_bytes()).unwrap();
    let impostor = Online::start_with(&mallory, group, Some(bos_certificate)).await;
    assert!(impostor.sync_with(&ada_online).await.is_err());

    // A device removed from the group.
    let cy_online = Online::start(&cy, group).await;
    cy_online.sync_with(&ada_online).await.unwrap();
    let members = ada.members(&group);
    let removal = members.change().remove(cy.id(), 0).sign(&ada.key).unwrap();
    ada.mirror()
        .put_member_entry(removal.seq(), removal.as_bytes())
        .unwrap();
    assert!(cy_online.sync_with(&ada_online).await.is_err());

    assert_eq!(
        ada.mirror().devices().unwrap(),
        heads_before,
        "nothing came in from them"
    );
    for online in [ada_online, bo_online, cy_online, mallory_online, impostor] {
        online.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn documents_and_their_erasure_travel_device_to_device() {
    let dir = tempfile::tempdir().unwrap();
    let (ada, bo) = (Device::new(dir.path(), "ada"), Device::new(dir.path(), "bo"));
    let group = found_group(&ada, &[(&bo, Role::Writer)]);
    let text = b"Settlement terms: 12,000 within 30 days";
    let pointer = ada.documents.add(&text[..]).unwrap();
    ada.commit("settlement.docx", &pointer.to_string());
    ada.push(&group);
    let (ada_online, bo_online) = (Online::start(&ada, group).await, Online::start(&bo, group).await);
    bo_online.sync_with(&ada_online).await.unwrap();
    assert_eq!(bo.pull(&group).applied[0].documents, vec![pointer.oid]);
    assert_eq!(bo.documents.read_to_vec(&pointer).unwrap(), text);

    ada.with(&group, |replica| replica.erase(&pointer.oid).unwrap());
    ada.push(&group);
    bo_online.sync_with(&ada_online).await.unwrap();
    let pulled = bo.pull(&group);
    assert_eq!(pulled.applied[0].erased, vec![pointer.oid]);
    assert_eq!(bo.documents.status(&pointer.oid).unwrap(), Status::Erased);
    assert!(
        bo.mirror().envelope(&pointer.oid).unwrap().is_none(),
        "gone from Bo's mirror too"
    );
    assert!(!bo.mirror().has_object(&pointer.oid).unwrap());
    ada_online.stop().await;
    bo_online.stop().await;
}

#[test]
fn a_device_cannot_slip_in_what_the_group_would_refuse() {
    let dir = tempfile::tempdir().unwrap();
    let (ada, bo, mallory) = (
        Device::new(dir.path(), "ada"),
        Device::new(dir.path(), "bo"),
        Device::new(dir.path(), "mallory"),
    );
    let group = found_group(&ada, &[(&bo, Role::Writer)]);
    let adas = ada.commit("terms.md", "Heads of terms\n");
    ada.push(&group);

    // A copy of Ada's mirror, with what a device in between could add to it.
    let forged = DirRelay::new(dir.path().join("forged"));
    replicate(&ada.mirror(), &forged, &group, &ada.identity).unwrap();
    let members = ada.members(&group);
    let not_by_an_admin = members.change().rotate().sign(&bo.key);
    assert!(not_by_an_admin.is_err(), "the change itself is refused");
    // An entry signed by a writer, written around the change's own check.
    let entry = members.change().rotate().sign(&ada.key).unwrap();
    let text = String::from_utf8(entry.as_bytes().to_vec()).unwrap();
    let text = text.split("-----BEGIN").next().unwrap();
    let by_bo = legix_sign::sign_in(legix_members::NAMESPACE, text.as_bytes(), &bo.key).unwrap();
    forged.put_member_entry(2, format!("{text}{by_bo}").as_bytes()).unwrap();
    // A bundle of a device that is not a member, and one of Ada's that does not follow her chain.
    mallory.commit("terms.md", "Other terms\n");
    let first = legix_sync::SignedHead::parse(&ada.mirror().head(&ada.id(), 1).unwrap().unwrap()).unwrap();
    let key = legix_crypt::DocumentKey::generate().unwrap();
    let group_key = legix_sync::Access::key(&members, 1).unwrap();
    let fork = Head {
        prev: legix_sync::BundleId::from_bytes([7; 32]),
        seq: 2,
        key: Head::wrap_key(&group_key, &ada.id(), 2, 1, &first.head().body, &key).unwrap(),
        ..first.head().clone()
    };
    forged
        .put_head(&ada.id(), 2, fork.sign(&ada.key).unwrap().as_bytes())
        .unwrap();
    let outsider = Head {
        device: mallory.id(),
        prev: legix_sync::BundleId::NONE,
        seq: 1,
        key: Head::wrap_key(&group_key, &mallory.id(), 1, 1, &first.head().body, &key).unwrap(),
        ..first.head().clone()
    };
    forged
        .put_head(&mallory.id(), 1, outsider.sign(&mallory.key).unwrap().as_bytes())
        .unwrap();
    // An envelope that opens with nothing the group holds, and the certificate of a device that is not a member.
    let garbage =
        legix_sync::seal_envelope(&legix_sync::GroupKey::generate().unwrap(), 1, &first.head().body, &key).unwrap();
    forged.put_envelope(&first.head().body, &garbage).unwrap();
    let endpoint = iroh::SecretKey::generate().public();
    forged
        .put_endpoint(
            &mallory.id(),
            EndpointCert::new(&mallory.key, endpoint.as_bytes()).unwrap().as_bytes(),
        )
        .unwrap();

    let synced = replicate(&forged, &bo.mirror(), &group, &bo.identity).unwrap();
    assert_eq!(synced.received.entries, 1, "only the founding entry");
    assert_eq!(synced.received.heads, 1, "only Ada's own first bundle");
    assert_eq!(synced.received.envelopes, 0);
    assert_eq!(synced.received.endpoints, 0);
    let refused: Vec<&str> = synced.refused.iter().map(|refusal| refusal.item.as_str()).collect();
    assert!(refused.iter().any(|item| item.starts_with("entry 2")), "{refused:?}");
    assert!(
        refused.iter().any(|item| item.starts_with("bundle 2 of")),
        "{refused:?}"
    );
    assert!(
        refused
            .iter()
            .any(|item| item.starts_with("bundle 1 of") && item.contains(&mallory.id().to_hex()))
    );
    assert!(
        refused.iter().any(|item| item.starts_with("the envelope")),
        "{refused:?}"
    );
    assert!(
        refused.iter().any(|item| item.starts_with("the endpoint certificate")),
        "{refused:?}"
    );

    // What was kept is the group's own, and nothing stands in the place of what Ada writes next.
    assert_eq!(bo.pull(&group).applied.len(), 1);
    assert!(bo.has(&ada, &adas));
    let next = ada.commit("terms.md", "Heads of terms, revised\n");
    ada.push(&group);
    let synced = replicate(&ada.mirror(), &bo.mirror(), &group, &bo.identity).unwrap();
    assert_eq!(synced.received.heads, 1);
    bo.pull(&group);
    assert!(bo.has(&ada, &next));
}

#[test]
fn mirrors_sync_through_a_shared_folder_with_the_same_checks() {
    let dir = tempfile::tempdir().unwrap();
    let (ada, bo) = (Device::new(dir.path(), "ada"), Device::new(dir.path(), "bo"));
    let group = found_group(&ada, &[(&bo, Role::Writer)]);
    let adas = ada.commit("terms.md", "Heads of terms\n");
    ada.push(&group);
    // A folder that holds another group's log cannot put it in Bo's empty mirror.
    let mallory = Device::new(dir.path(), "mallory");
    let other_group = found_group(&mallory, &[(&bo, Role::Writer)]);
    assert_ne!(other_group, group);
    let other = replicate(&mallory.mirror(), &bo.mirror(), &group, &bo.identity).unwrap();
    assert_eq!(other.received.entries, 0);
    assert!(
        other.refused[0].reason.contains("not the first entry of this group"),
        "{:?}",
        other.refused
    );
    assert!(bo.mirror().member_entry(1).unwrap().is_none());

    let folder = DirRelay::new(dir.path().join("shared-folder"));
    let into_folder = replicate(&ada.mirror(), &folder, &group, &ada.identity).unwrap();
    assert!(into_folder.refused.is_empty(), "{:?}", into_folder.refused);
    let into_bo = replicate(&folder, &bo.mirror(), &group, &bo.identity).unwrap();
    assert_eq!((into_bo.received.entries, into_bo.received.heads), (1, 1));
    assert_eq!(bo.pull(&group).applied.len(), 1);
    assert!(bo.has(&ada, &adas));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_that_only_holds_a_copy_of_the_log_gets_nothing_and_gives_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (ada, bo, mallory) = (
        Device::new(dir.path(), "ada"),
        Device::new(dir.path(), "bo"),
        Device::new(dir.path(), "mallory"),
    );
    let group = found_group(&ada, &[(&bo, Role::Writer)]);
    ada.commit("terms.md", "Heads of terms\n");
    ada.push(&group);
    let ada_online = Online::start(&ada, group).await;
    let bo_online = Online::start(&bo, group).await;
    bo_online.sync_with(&ada_online).await.unwrap();
    bo.commit("notes.md", "Clause 4 needs a cap\n");
    bo.push(&group);

    // Mallory copies what a relay would show — the log, Ada's bundle — and adds an object of its own.
    replicate(&ada.mirror(), &mallory.mirror(), &group, &mallory.identity).unwrap();
    let planted = legix_crypt::Oid::of(b"planted");
    mallory.mirror().put_object(&planted, &mut &b"planted"[..]).unwrap();
    let mallory_online = Online::start(&mallory, group).await;

    let result = bo_online.sync_with(&mallory_online).await;
    assert!(matches!(result, Err(Error::NotMember)), "{result:?}");
    assert!(!bo.mirror().has_object(&planted).unwrap(), "nothing taken from it");
    assert!(
        mallory.mirror().head(&bo.id(), 1).unwrap().is_none(),
        "nothing given to it"
    );
    for online in [ada_online, bo_online, mallory_online] {
        online.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_that_asked_to_join_knocks_and_comes_in_once_added() {
    let dir = tempfile::tempdir().unwrap();
    let (ada, bo) = (Device::new(dir.path(), "ada"), Device::new(dir.path(), "bo"));
    let group = found_group(&ada, &[]);
    let adas = ada.commit("terms.md", "Heads of terms\n");
    ada.push(&group);
    let ada_online = Online::start(&ada, group).await;

    // Bo asked to join: its mirror holds its own request, and no log. It knocks, and is given nothing.
    let request = bo.request();
    bo.mirror().put_join(&bo.id(), request.as_bytes()).unwrap();
    let bo_online = Online::start(&bo, group).await;
    let knocked = bo_online.sync_with(&ada_online).await.unwrap();
    assert!(knocked.knocked);
    assert!(
        ada.mirror().joins().unwrap().contains(&request.as_bytes().to_vec()),
        "the request is with the admin"
    );
    assert!(bo.mirror().member_entry(1).unwrap().is_none() && bo.mirror().head(&ada.id(), 1).unwrap().is_none());

    // Ada adds Bo: Bo's next sync brings the log and the history.
    let entry = ada
        .members(&group)
        .change()
        .add(request, Role::Writer)
        .sign(&ada.key)
        .unwrap();
    ada.mirror().put_member_entry(entry.seq(), entry.as_bytes()).unwrap();
    let synced = bo_online.sync_with(&ada_online).await.unwrap();
    assert!(!synced.knocked);
    assert_eq!((synced.received.entries, synced.received.heads), (2, 1));
    bo.pull(&group);
    assert!(bo.has(&ada, &adas));
    ada_online.stop().await;
    bo_online.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_without_a_request_still_gets_nothing_in() {
    let dir = tempfile::tempdir().unwrap();
    let (ada, mallory) = (Device::new(dir.path(), "ada"), Device::new(dir.path(), "mallory"));
    let group = found_group(&ada, &[]);
    let ada_online = Online::start(&ada, group).await;
    // Mallory knocks with Ada's own request: the request is not Mallory's, and is not kept.
    let adas_request = ada.request();
    mallory
        .mirror()
        .put_join(&mallory.id(), adas_request.as_bytes())
        .unwrap();
    let mallory_online = Online::start(&mallory, group).await;
    assert!(mallory_online.sync_with(&ada_online).await.is_err());
    assert!(ada.mirror().joins().unwrap().is_empty());
    ada_online.stop().await;
    mallory_online.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn one_endpoint_answers_for_several_groups() {
    let dir = tempfile::tempdir().unwrap();
    let (ada, bo, cy) = (
        Device::new(dir.path(), "ada"),
        Device::new(dir.path(), "bo"),
        Device::new(dir.path(), "cy"),
    );
    // Ada keeps two groups, each in a mirror of its own: one with Bo, one with Cy.
    let with_bo = found_group(&ada, &[(&bo, Role::Writer)]);
    let second = DirRelay::new(ada.repo.join(".git/legix/second"));
    let first_of_second = found(
        &ada.key,
        &ada.identity,
        "ada@example.com",
        &[(cy.request(), Role::Writer)],
    )
    .unwrap();
    second.put_member_entry(1, first_of_second.as_bytes()).unwrap();
    let with_cy: GroupId = first_of_second.id().into();

    let endpoint = Endpoint::builder(presets::Minimal)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let certificate = EndpointCert::new(&ada.key, endpoint.id().as_bytes()).unwrap();
    let peers = Arc::new(Peers::new());
    peers.insert(Arc::new(
        Peer::new(ada.mirror(), with_bo, ada.identity.clone(), certificate.clone()).unwrap(),
    ));
    peers.insert(Arc::new(
        Peer::new(second, with_cy, ada.identity.clone(), certificate).unwrap(),
    ));
    let router = Router::builder(endpoint.clone()).accept(ALPN, peers.clone()).spawn();
    let port = endpoint
        .bound_sockets()
        .into_iter()
        .find(SocketAddr::is_ipv4)
        .unwrap()
        .port();
    let adas = EndpointAddr::new(endpoint.id()).with_ip_addr(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port));

    let bo_online = Online::start(&bo, with_bo).await;
    let cy_online = Online::start(&cy, with_cy).await;
    let bo_synced = bo_online
        .peer
        .sync_with(&bo_online.endpoint, adas.clone())
        .await
        .unwrap();
    let cy_synced = cy_online
        .peer
        .sync_with(&cy_online.endpoint, adas.clone())
        .await
        .unwrap();
    assert_eq!((bo_synced.received.entries, cy_synced.received.entries), (1, 1));
    assert_eq!(bo.members(&with_bo).roster().group(), Some(with_bo));
    assert_eq!(cy.members(&with_cy).roster().group(), Some(with_cy));

    // A group the endpoint no longer answers for.
    peers.remove(&with_bo);
    assert!(matches!(
        bo_online.peer.sync_with(&bo_online.endpoint, adas).await,
        Err(Error::Connection(_) | Error::Protocol(_))
    ));
    router.shutdown().await.unwrap();
    bo_online.stop().await;
    cy_online.stop().await;
}

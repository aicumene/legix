//! Devices that sync their folders directly, over iroh on this machine: each with its own endpoint, finding the other
//! by its endpoint id alone, without a shared folder.

use std::{
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use legix_folder::{
    ALPN, DirRelay, Folder, Keys, Peers, Role,
    iroh::{Endpoint, EndpointAddr, SecretKey, address_lookup::MemoryLookup, endpoint::presets, protocol::Router},
};

const WAIT: Duration = Duration::from_secs(20);

struct Device {
    name: &'static str,
    work: PathBuf,
    state: PathBuf,
}

impl Device {
    fn new(root: &Path, name: &'static str) -> Self {
        let work = root.join(name).join("Matter 2041");
        fs::create_dir_all(&work).unwrap();
        Device {
            name,
            work,
            state: root.join(name).join("history"),
        }
    }

    fn principal(&self) -> String {
        format!("{}@example.com", self.name)
    }

    fn write(&self, path: &str, content: &str) {
        fs::write(self.work.join(path), content).unwrap();
    }

    fn read(&self, path: &str) -> String {
        fs::read_to_string(self.work.join(path)).unwrap()
    }
}

/// A device's endpoint, answering for its histories; others find it in `lookup`, as iroh's discovery would.
struct Online {
    endpoint: Endpoint,
    peers: Arc<Peers<DirRelay>>,
    router: Router,
}

impl Online {
    async fn start(keys: &Keys, lookup: &MemoryLookup) -> Self {
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&keys.endpoint_key().unwrap()))
            .address_lookup(lookup.clone())
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let port = endpoint
            .bound_sockets()
            .into_iter()
            .find(SocketAddr::is_ipv4)
            .unwrap()
            .port();
        lookup.add_endpoint_info(
            EndpointAddr::new(endpoint.id()).with_ip_addr(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)),
        );
        let peers = Arc::new(Peers::new());
        let router = Router::builder(endpoint.clone()).accept(ALPN, peers.clone()).spawn();
        Online {
            endpoint,
            peers,
            router,
        }
    }

    fn id(&self) -> [u8; 32] {
        *self.endpoint.id().as_bytes()
    }

    /// Answer for `folder`'s history, and sync it with the devices it knows.
    async fn sync(&self, folder: &Folder) -> legix_folder::Direct {
        let peer = folder.peer(&self.id()).unwrap();
        self.peers.insert(Arc::new(folder.peer(&self.id()).unwrap()));
        folder.sync_direct(&self.endpoint, &peer, WAIT).await.unwrap()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn devices_sync_their_folders_directly_from_an_invitation() {
    let dir = tempfile::tempdir().unwrap();
    let lookup = MemoryLookup::new();
    let (ada, bo) = (Device::new(dir.path(), "ada"), Device::new(dir.path(), "bo"));
    let (ada_keys, bo_keys) = (Keys::generate("ada").unwrap(), Keys::generate("bo").unwrap());
    assert_eq!(
        ada_keys.endpoint_key().unwrap(),
        ada_keys.endpoint_key().unwrap(),
        "the same on every start"
    );
    let (ada_online, bo_online) = (
        Online::start(&ada_keys, &lookup).await,
        Online::start(&bo_keys, &lookup).await,
    );

    ada.write("Heads of terms.docx", "Heads of terms\n");
    let adas = Folder::found(&ada.state, &ada.work, ada_keys, &ada.principal()).unwrap();
    adas.save("Heads of terms").unwrap().unwrap();
    ada_online.sync(&adas).await;

    // The invitation: the group, and Ada's endpoint. No shared folder anywhere.
    let (bos, request) = Folder::join(
        &bo.state,
        &bo.work,
        bo_keys,
        &bo.principal(),
        adas.settings().group,
        None,
    )
    .unwrap();
    bos.add_peer(&ada_online.id()).unwrap();
    let knocked = bo_online.sync(&bos).await;
    assert_eq!(knocked.reached.len(), 1);
    assert!(knocked.reached[0].outcome.as_ref().unwrap().knocked);
    assert!(!knocked.synced.member);
    assert_eq!(
        adas.requests().unwrap(),
        vec![request.clone()],
        "Bo's request is with Ada"
    );

    // Ada adds Bo; Bo's next sync brings the log, Ada's version and its documents.
    adas.admit(&request, Role::Writer).unwrap();
    let synced = bo_online.sync(&bos).await;
    assert!(synced.synced.member);
    let incoming = bos.incoming().unwrap();
    assert_eq!(incoming.len(), 1);
    assert_eq!(
        bos.bring_in(&incoming[0].id, "Ada's").unwrap().updated,
        ["Heads of terms.docx"]
    );
    assert_eq!(bo.read("Heads of terms.docx"), "Heads of terms\n");

    // Bo's version reaches Ada when Ada syncs: the log now tells Ada where Bo is.
    bo.write("Review.md", "Clause 4 needs a cap\n");
    bos.save("Review").unwrap().unwrap();
    bos.sync().unwrap();
    assert!(adas.endpoints().unwrap().contains(&bo_online.id()));
    let ada_synced = ada_online.sync(&adas).await;
    assert!(ada_synced.reached.iter().all(|reached| reached.outcome.is_ok()));
    let incoming = adas.incoming().unwrap();
    assert_eq!(incoming[0].principal.as_deref(), Some("bo@example.com"));
    adas.bring_in(&incoming[0].id, "Bo's review").unwrap();
    assert_eq!(ada.read("Review.md"), "Clause 4 needs a cap\n");

    ada_online.router.shutdown().await.unwrap();
    bo_online.router.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_out_of_reach_is_reported_and_the_rest_goes_on() {
    let dir = tempfile::tempdir().unwrap();
    let lookup = MemoryLookup::new();
    let ada = Device::new(dir.path(), "ada");
    let keys = Keys::generate("ada").unwrap();
    let online = Online::start(&keys, &lookup).await;
    ada.write("Notes.md", "Notes\n");
    let adas = Folder::found(&ada.state, &ada.work, keys, &ada.principal()).unwrap();
    adas.save("Notes").unwrap().unwrap();
    // An endpoint nobody answers for.
    adas.add_peer(SecretKey::generate().public().as_bytes()).unwrap();
    let peer = adas.peer(&online.id()).unwrap();
    let direct = adas
        .sync_direct(&online.endpoint, &peer, Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(direct.reached.len(), 1);
    assert!(direct.reached[0].outcome.is_err());
    assert!(direct.synced.member, "the folder still synced with its mirror");
    online.router.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "goes over the internet: n0's relays and address lookup"]
async fn devices_on_different_networks_sync_through_a_relay() {
    let dir = tempfile::tempdir().unwrap();
    let (ada, bo) = (Device::new(dir.path(), "ada"), Device::new(dir.path(), "bo"));
    let (ada_keys, bo_keys) = (Keys::generate("ada").unwrap(), Keys::generate("bo").unwrap());
    let bind = |keys: &Keys, relay_only: bool| {
        let mut builder = Endpoint::builder(presets::N0)
            .secret_key(SecretKey::from_bytes(&keys.endpoint_key().unwrap()))
            .alpns(vec![ALPN.to_vec()]);
        if relay_only {
            // No path but the relay, as between networks that cannot reach each other directly.
            builder = builder.clear_ip_transports();
        }
        builder.bind()
    };
    let ada_endpoint = bind(&ada_keys, false).await.unwrap();
    let bo_endpoint = bind(&bo_keys, true).await.unwrap();
    for endpoint in [&ada_endpoint, &bo_endpoint] {
        tokio::time::timeout(Duration::from_secs(30), endpoint.online())
            .await
            .expect("a relay");
    }
    let online = |endpoint: &Endpoint| {
        let peers = Arc::new(Peers::new());
        let router = Router::builder(endpoint.clone()).accept(ALPN, peers.clone()).spawn();
        Online {
            endpoint: endpoint.clone(),
            peers,
            router,
        }
    };
    let (ada_online, bo_online) = (online(&ada_endpoint), online(&bo_endpoint));

    ada.write("Heads of terms.docx", "Heads of terms\n");
    let adas = Folder::found(&ada.state, &ada.work, ada_keys, &ada.principal()).unwrap();
    adas.save("Heads of terms").unwrap().unwrap();
    ada_online.sync(&adas).await;
    let (bos, request) = Folder::join(
        &bo.state,
        &bo.work,
        bo_keys,
        &bo.principal(),
        adas.settings().group,
        None,
    )
    .unwrap();
    bos.add_peer(&ada_online.id()).unwrap();

    let knocked = bo_online.sync(&bos).await;
    assert!(knocked.reached[0].outcome.as_ref().unwrap().knocked, "{knocked:?}");
    adas.admit(&request, Role::Writer).unwrap();
    let synced = bo_online.sync(&bos).await;
    assert!(synced.synced.member, "{synced:?}");
    let incoming = bos.incoming().unwrap();
    bos.bring_in(&incoming[0].id, "Ada's").unwrap();
    assert_eq!(bo.read("Heads of terms.docx"), "Heads of terms\n");

    // And back, Ada dialing Bo, whom it finds by Bo's endpoint id alone.
    bo.write("Review.md", "Clause 4 needs a cap\n");
    bos.save("Review").unwrap().unwrap();
    bos.sync().unwrap();
    let ada_synced = ada_online.sync(&adas).await;
    assert!(
        ada_synced.reached.iter().all(|reached| reached.outcome.is_ok()),
        "{ada_synced:?}"
    );
    let incoming = adas.incoming().unwrap();
    adas.bring_in(&incoming[0].id, "Bo's review").unwrap();
    assert_eq!(ada.read("Review.md"), "Clause 4 needs a cap\n");

    ada_online.router.shutdown().await.unwrap();
    bo_online.router.shutdown().await.unwrap();
}

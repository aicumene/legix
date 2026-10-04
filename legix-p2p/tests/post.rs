//! Letters between devices, over iroh on this machine.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};

use iroh::{Endpoint, EndpointAddr, endpoint::presets, protocol::Router};
use legix_p2p::{EndpointCert, Error, MAX_LETTER, Mailbox, POST_ALPN, Post, send_letter};
use legix_sign::ssh_key::PrivateKey;
use legix_sync::DeviceId;

/// A mailbox that keeps what it is given and answers with `answer`, or refuses with it.
struct Kept {
    letters: Mutex<Vec<(DeviceId, Vec<u8>)>>,
    answer: Result<Vec<u8>, String>,
}

impl Mailbox for Kept {
    fn receive(&self, from: &EndpointCert, letter: &[u8]) -> Result<Vec<u8>, String> {
        self.letters.lock().unwrap().push((from.device(), letter.to_vec()));
        self.answer.clone()
    }
}

struct Device {
    key: PrivateKey,
    endpoint: Endpoint,
}

impl Device {
    async fn new(name: &str, alpns: Vec<Vec<u8>>) -> Self {
        let key = legix_sign::generate_ed25519(name).unwrap();
        let endpoint = Endpoint::builder(presets::Minimal).alpns(alpns).bind().await.unwrap();
        Device { key, endpoint }
    }

    fn device(&self) -> DeviceId {
        DeviceId::of(self.key.public_key())
    }

    fn certificate(&self) -> EndpointCert {
        EndpointCert::new(&self.key, self.endpoint.id().as_bytes()).unwrap()
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
}

/// Ada's endpoint, taking letters into a mailbox that answers with `answer`.
async fn ada_with(answer: Result<Vec<u8>, String>) -> (Device, Arc<Kept>, Router) {
    let ada = Device::new("ada", vec![POST_ALPN.to_vec()]).await;
    let kept = Arc::new(Kept {
        letters: Mutex::new(Vec::new()),
        answer,
    });
    let router = Router::builder(ada.endpoint.clone())
        .accept(POST_ALPN, Post::new(kept.clone()))
        .spawn();
    (ada, kept, router)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_letter_reaches_the_mailbox_and_its_answer_comes_back() {
    let (ada, kept, router) = ada_with(Ok(b"thank you".to_vec())).await;
    let bo = Device::new("bo", Vec::new()).await;

    let answer = send_letter(&bo.endpoint, ada.addr(), &bo.certificate(), b"a card")
        .await
        .unwrap();
    assert_eq!(answer, b"thank you");
    assert_eq!(*kept.letters.lock().unwrap(), vec![(bo.device(), b"a card".to_vec())]);
    router.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_letter_comes_back_with_the_reason() {
    let (ada, kept, router) = ada_with(Err("not from a contact".to_owned())).await;
    let bo = Device::new("bo", Vec::new()).await;

    let refused = send_letter(&bo.endpoint, ada.addr(), &bo.certificate(), b"an invitation").await;
    assert!(
        matches!(&refused, Err(Error::Refused(reason)) if reason == "not from a contact"),
        "{refused:?}"
    );
    assert_eq!(kept.letters.lock().unwrap().len(), 1);
    router.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_letter_under_another_devices_certificate_is_not_taken() {
    let (ada, kept, router) = ada_with(Ok(Vec::new())).await;
    let bo = Device::new("bo", Vec::new()).await;
    let cy = Device::new("cy", Vec::new()).await;

    // Bo sends from his endpoint with Cy's certificate: it names Cy's endpoint, not the one that connected.
    let sent = send_letter(&bo.endpoint, ada.addr(), &cy.certificate(), b"from Cy, says Bo").await;
    assert!(sent.is_err());
    assert!(kept.letters.lock().unwrap().is_empty(), "the mailbox never saw it");
    router.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_letter_too_long_for_the_post_is_not_sent() {
    let bo = Device::new("bo", Vec::new()).await;
    let ada = Device::new("ada", vec![POST_ALPN.to_vec()]).await;
    let long = vec![b'x'; MAX_LETTER + 1];
    assert!(matches!(
        send_letter(&bo.endpoint, ada.addr(), &bo.certificate(), &long).await,
        Err(Error::Format(_))
    ));
}

//! Letters between devices: one device gives another a short note — its card, an invitation — on a connection of its
//! own, outside the groups the two sync.

use std::{fmt, sync::Arc, time::Duration};

use iroh::{
    Endpoint, EndpointAddr,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};

use crate::{EndpointCert, Error, error::connection_error, wire};

/// The ALPN of letters between devices.
pub const POST_ALPN: &[u8] = b"legix/post/1";

/// The longest a letter, or its answer, may be.
pub const MAX_LETTER: usize = 64 << 10;

/// The longest reason for a refusal that goes back.
const MAX_REASON: usize = 1 << 10;

/// How long the device that answers waits for the letter, and then for the sender to close.
const WAIT: Duration = Duration::from_secs(10);

/// What a device does with the letters other devices give it.
pub trait Mailbox: Send + Sync + 'static {
    /// The device of `from` gives `letter`: iroh authenticated the endpoint at the other end of the connection, and the
    /// certificate ties that endpoint to the device. What this returns goes back to the sender as the answer; an error
    /// refuses the letter, and its text is the reason the sender reads.
    fn receive(&self, from: &EndpointCert, letter: &[u8]) -> Result<Vec<u8>, String>;
}

/// The post of an endpoint, as an iroh `ProtocolHandler` for [`POST_ALPN`]: every letter goes to the mailbox, and its
/// answer back to the sender.
pub struct Post<M: ?Sized> {
    mailbox: Arc<M>,
}

impl<M: Mailbox + ?Sized> Post<M> {
    /// Letters go to `mailbox`.
    pub fn new(mailbox: Arc<M>) -> Self {
        Post { mailbox }
    }

    /// Take the letter of the device that connected through `connection`, and answer it.
    pub async fn serve(&self, connection: Connection) -> Result<(), Error> {
        let (mut send, mut recv) = connection.accept_bi().await.map_err(connection_error)?;
        let from = match tokio::time::timeout(WAIT, wire::read(&mut recv)).await {
            Ok(Ok((wire::FROM, payload))) => EndpointCert::parse(&payload)?,
            _ => return Err(Error::Protocol("expected the sender's certificate")),
        };
        if from.endpoint_id() != connection.remote_id() {
            connection.close(3u32.into(), b"wrong endpoint");
            return Err(Error::WrongEndpoint);
        }
        let letter = match tokio::time::timeout(WAIT, wire::read(&mut recv)).await {
            Ok(Ok((wire::LETTER, payload))) => payload,
            _ => return Err(Error::Protocol("expected a letter")),
        };
        match self.mailbox.receive(&from, &letter) {
            Ok(answer) if answer.len() <= MAX_LETTER => wire::write(&mut send, wire::ANSWER, &[&answer]).await?,
            Ok(_) => wire::write(&mut send, wire::REFUSED, &[b"the answer is longer than the post takes"]).await?,
            Err(reason) => wire::write(&mut send, wire::REFUSED, &[cut(&reason, MAX_REASON).as_bytes()]).await?,
        }
        send.finish().map_err(connection_error)?;
        // The sender closes the connection once it has read the answer.
        let _ = tokio::time::timeout(WAIT, connection.closed()).await;
        Ok(())
    }
}

impl<M: ?Sized> fmt::Debug for Post<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Post").finish_non_exhaustive()
    }
}

impl<M: Mailbox + ?Sized> ProtocolHandler for Post<M> {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        self.serve(connection).await.map_err(AcceptError::from_err)
    }
}

/// Give `letter` to the device at `to`, from this device's endpoint `endpoint`, whose certificate is `from`. The
/// device's answer, or [`Error::Refused`] with its reason.
pub async fn send_letter(
    endpoint: &Endpoint,
    to: impl Into<EndpointAddr>,
    from: &EndpointCert,
    letter: &[u8],
) -> Result<Vec<u8>, Error> {
    if letter.len() > MAX_LETTER {
        return Err(Error::Format("a letter longer than the post takes"));
    }
    let connection = endpoint.connect(to, POST_ALPN).await.map_err(connection_error)?;
    let result = async {
        let (mut send, mut recv) = connection.open_bi().await.map_err(connection_error)?;
        wire::write(&mut send, wire::FROM, &[from.as_bytes()]).await?;
        wire::write(&mut send, wire::LETTER, &[letter]).await?;
        send.finish().map_err(connection_error)?;
        match wire::read(&mut recv).await? {
            (wire::ANSWER, answer) => Ok(answer),
            (wire::REFUSED, reason) => Err(Error::Refused(String::from_utf8_lossy(&reason).into_owned())),
            _ => Err(Error::Protocol("expected an answer")),
        }
    }
    .await;
    connection.close(0u32.into(), b"done");
    result
}

/// `text`, cut to at most `max` bytes at a character's boundary.
fn cut(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

//! Join requests: a device asks to join a group, with the keys it signs and receives with.

use legix_sign::{
    AllowedSigners, Status,
    ssh_key::{HashAlg, PublicKey, SigningKey},
};
use legix_sync::DeviceId;

use crate::{Error, Identity, Recipient, hex, signed};

/// The first line of every join request of this version.
pub const VERSION: &str = "legix-join/1";
/// The SSH signature namespace of join requests.
pub const NAMESPACE: &str = "legix-join";

/// A device's request to join a group: its signing key, the recipient group keys are sealed for, and a name, signed by
/// the device.
///
/// An admin adds a device only after comparing the [fingerprint](JoinRequest::fingerprint) of its key with the one the
/// device shows, over a channel the relay does not control: in person, by phone. The signature then ensures that
/// nobody on the way swapped the recipient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRequest {
    device: DeviceId,
    key: PublicKey,
    recipient: Recipient,
    principal: String,
    time: u64,
    bytes: Vec<u8>,
}

impl JoinRequest {
    /// The request of the device that signs with `signer` and receives with `identity`, under the name `principal`
    /// (no spaces, at most 200 bytes).
    pub fn new(signer: &impl SigningKey, identity: &Identity, principal: &str) -> Result<Self, Error> {
        if !valid_principal(principal) {
            return Err(Error::Format(
                "a principal is 1 to 200 bytes without spaces or control characters",
            ));
        }
        let key = PublicKey::new(signer.public_key(), "");
        let text = format!(
            "{VERSION}\ndevice {}\nkey {}\nrecipient {}\nprincipal {principal}\ntime {}\n",
            DeviceId::of(&key),
            key.to_openssh().map_err(legix_sign::Error::from)?,
            identity.recipient(),
            crate::now(),
        );
        let signature = legix_sign::sign_in(NAMESPACE, text.as_bytes(), signer)?;
        Self::parse(format!("{text}{signature}").as_bytes())
    }

    /// Read a join request and check its signature. Anything but its one text form is refused.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let (text, signature) = signed::split(bytes)?;
        let text = std::str::from_utf8(text).map_err(|_| Error::Format("a join request is not UTF-8"))?;
        let lines: Vec<&str> = text
            .strip_suffix('\n')
            .ok_or(Error::Format(
                "a join request's last line does not end with a line feed",
            ))?
            .split('\n')
            .collect();
        let [version, device, key, recipient, principal, time] = lines[..] else {
            return Err(Error::Format("a join request has six lines"));
        };
        if version != VERSION {
            return Err(Error::Format("a join request of a version this crate does not read"));
        }
        let device = field(device, "device ")?
            .parse()
            .map_err(|_| Error::Format("the device id"))?;
        let key_text = field(key, "key ")?;
        let key =
            PublicKey::from_openssh(key_text).map_err(|_| Error::Format("the key is not an OpenSSH public key"))?;
        if key.to_openssh().map_err(legix_sign::Error::from)? != key_text || DeviceId::of(&key) != device {
            return Err(Error::Format(
                "the key is not written as OpenSSH writes it, or is not the device's",
            ));
        }
        let recipient = field(recipient, "recipient ")?.parse()?;
        let principal = field(principal, "principal ")?;
        if !valid_principal(principal) {
            return Err(Error::Format("the principal"));
        }
        let time = hex::number(field(time, "time ")?).ok_or(Error::Format("the time"))?;

        let outcome = legix_sign::verify_in(
            NAMESPACE,
            signature,
            &bytes[..text.len()],
            None,
            &AllowedSigners::default(),
        );
        if outcome.status != Status::Good || outcome.key.as_ref().map(PublicKey::key_data) != Some(key.key_data()) {
            return Err(Error::Format("the join request is not signed by its own key"));
        }
        Ok(JoinRequest {
            device,
            key,
            recipient,
            principal: principal.to_owned(),
            time,
            bytes: bytes.to_vec(),
        })
    }

    /// The device that asks.
    pub fn device(&self) -> DeviceId {
        self.device
    }

    /// Its signing key.
    pub fn key(&self) -> &PublicKey {
        &self.key
    }

    /// The fingerprint of its signing key, `SHA256:…`, as `ssh-keygen -l` shows it: what the admin compares with the
    /// device before adding it.
    pub fn fingerprint(&self) -> String {
        self.key.fingerprint(HashAlg::Sha256).to_string()
    }

    /// The recipient group keys are sealed for.
    pub fn recipient(&self) -> Recipient {
        self.recipient
    }

    /// The name it asks to join under.
    pub fn principal(&self) -> &str {
        &self.principal
    }

    /// When it asked, in seconds since 1970.
    pub fn time(&self) -> u64 {
        self.time
    }

    /// The request as it travels and is kept in the log.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn field<'a>(line: &'a str, name: &str) -> Result<&'a str, Error> {
    line.strip_prefix(name)
        .ok_or(Error::Format("a join request's lines are out of order"))
}

fn valid_principal(principal: &str) -> bool {
    !principal.is_empty() && principal.len() <= 200 && !principal.chars().any(|c| c.is_whitespace() || c.is_control())
}

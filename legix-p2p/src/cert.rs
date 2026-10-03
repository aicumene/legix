//! Endpoint certificates: a device says, with its own key, at which iroh endpoint it is reached.

use legix_members::Members;
use legix_sign::{
    AllowedSigners, Status,
    ssh_key::{PublicKey, SigningKey},
};
use legix_sync::DeviceId;

use crate::{Error, hex, signed};

/// The first line of every endpoint certificate of this version.
pub const VERSION: &str = "legix-endpoint/1";
/// The SSH signature namespace of endpoint certificates.
pub const NAMESPACE: &str = "legix-endpoint";

/// A device's endpoint certificate: the iroh endpoint the device is reached at, signed with the device's key.
///
/// iroh authenticates the endpoint at the other end of a connection; the certificate ties that endpoint to a device,
/// and the membership log ties the device to the group. Devices leave their certificates on the relay, where the others
/// find them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointCert {
    device: DeviceId,
    endpoint: [u8; 32],
    time: u64,
    key: PublicKey,
    bytes: Vec<u8>,
}

impl EndpointCert {
    /// The certificate of the device that signs with `signer`, for the iroh endpoint whose id — an Ed25519 public
    /// key — is `endpoint`.
    pub fn new(signer: &impl SigningKey, endpoint: &[u8; 32]) -> Result<Self, Error> {
        let key = PublicKey::from(signer.public_key());
        let text = format!(
            "{VERSION}\ndevice {}\nendpoint {}\ntime {}\n",
            DeviceId::of(&key),
            hex::encode(endpoint),
            crate::now()
        );
        let signature = legix_sign::sign_in(NAMESPACE, text.as_bytes(), signer)?;
        Self::parse(format!("{text}{signature}").as_bytes())
    }

    /// Read a certificate and check its signature. Anything but its one text form is refused.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let (signed_text, signature) = signed::split(bytes)?;
        let text = std::str::from_utf8(signed_text).map_err(|_| Error::Format("a certificate is not UTF-8"))?;
        let lines: Vec<&str> = text
            .strip_suffix('\n')
            .ok_or(Error::Format("a certificate's last line does not end with a line feed"))?
            .split('\n')
            .collect();
        let [version, device, endpoint, time] = lines[..] else {
            return Err(Error::Format("a certificate has four lines"));
        };
        if version != VERSION {
            return Err(Error::Format("a certificate of a version this crate does not read"));
        }
        let device: DeviceId = device
            .strip_prefix("device ")
            .ok_or(Error::Format("a certificate's device line"))?
            .parse()
            .map_err(|_| Error::Format("a certificate's device id"))?;
        let mut endpoint_bytes = [0; 32];
        endpoint
            .strip_prefix("endpoint ")
            .and_then(|hex| hex::decode(hex, &mut endpoint_bytes))
            .ok_or(Error::Format("a certificate's endpoint line"))?;
        if ed25519_dalek::VerifyingKey::from_bytes(&endpoint_bytes).is_err() {
            return Err(Error::Format(
                "a certificate's endpoint id is not an Ed25519 public key",
            ));
        }
        let time = time
            .strip_prefix("time ")
            .and_then(hex::number)
            .ok_or(Error::Format("a certificate's time"))?;

        let outcome = legix_sign::verify_in(NAMESPACE, signature, signed_text, None, &AllowedSigners::default());
        let key = match (outcome.status, outcome.key) {
            (Status::Good, Some(key)) if DeviceId::of(&key) == device => key,
            _ => return Err(Error::Format("the certificate is not signed by its device")),
        };
        Ok(EndpointCert {
            device,
            endpoint: endpoint_bytes,
            time,
            key,
            bytes: bytes.to_vec(),
        })
    }

    /// The device.
    pub fn device(&self) -> DeviceId {
        self.device
    }

    /// The id of the iroh endpoint it is reached at: an Ed25519 public key.
    pub fn endpoint(&self) -> [u8; 32] {
        self.endpoint
    }

    /// The iroh endpoint it is reached at.
    #[cfg(feature = "iroh")]
    pub fn endpoint_id(&self) -> iroh::EndpointId {
        iroh::EndpointId::from_bytes(&self.endpoint).expect("checked when the certificate was read")
    }

    /// When the certificate was made, in seconds since 1970.
    pub fn time(&self) -> u64 {
        self.time
    }

    /// The device's key, which signed the certificate.
    pub fn key(&self) -> &PublicKey {
        &self.key
    }

    /// The certificate as it is kept and sent.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Whether the device is a member of the group now, with the key the group knows for it.
    pub fn is_member(&self, members: &Members) -> bool {
        members
            .roster()
            .members()
            .get(&self.device)
            .is_some_and(|member| member.key.key_data() == self.key.key_data())
    }
}

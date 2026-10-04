//! What a device tells another outside the groups they share: who it is and where it is reached — its card — and that
//! it added the other to a group — an invitation. Devices give them to each other by post (legix-p2p's letters).

use legix_members::{GroupId, JoinRequest, Role};
use legix_p2p::EndpointCert;
use legix_sign::{
    AllowedSigners, Status,
    ssh_key::{PublicKey, SigningKey},
};
use legix_sync::DeviceId;

use crate::{Error, Keys};

/// The first line of every card of this version.
pub const CARD: &str = "legix-card/1";
/// The first line of every invitation of this version.
pub const INVITATION: &str = "legix-invitation/1";
/// The SSH signature namespace of invitations.
pub const INVITATION_NAMESPACE: &str = "legix-invitation";

const ARMOR_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----\n";
const ARMOR_END: &str = "-----END SSH SIGNATURE-----\n";

/// A device's card: its join request — its keys and principal, signed by it — its endpoint certificate, and the name
/// its owner goes by. With a device's card, an admin adds the device to a group without its asking
/// ([`Folder::invite`](crate::Folder::invite)), and reaches it directly.
///
/// ```text
/// legix-card/1
/// name <the name its owner goes by>
/// <the join request><the endpoint certificate>
/// ```
///
/// The request and the certificate are signed by the device; the name is its owner's to choose, and is not. A card is
/// taken from the device itself, on a connection iroh authenticates, whose endpoint the certificate must name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Card {
    name: String,
    request: JoinRequest,
    certificate: EndpointCert,
    bytes: Vec<u8>,
}

impl Card {
    /// The card of the device with `keys`: its join request under `principal`, its certificate for its endpoint
    /// `endpoint` — whose secret key is [`Keys::endpoint_key`] — and `name`.
    pub fn new(keys: &Keys, principal: &str, name: &str, endpoint: &[u8; 32]) -> Result<Self, Error> {
        let request = JoinRequest::new(&keys.signing, &keys.identity, principal)?;
        let certificate = EndpointCert::new(&keys.signing, endpoint)?;
        Self::of(name, request, certificate)
    }

    /// The card of a device from what is known of it: its request — from a group's log, say — its certificate, and
    /// a name.
    pub fn of(name: &str, request: JoinRequest, certificate: EndpointCert) -> Result<Self, Error> {
        let name = name.trim();
        if !valid_name(name) {
            return Err(Error::Format("a name on a card is 1 to 100 characters, on one line"));
        }
        if request.device() != certificate.device() {
            return Err(Error::Format("a card's request and certificate are of two devices"));
        }
        let mut bytes = format!("{CARD}\nname {name}\n").into_bytes();
        bytes.extend_from_slice(request.as_bytes());
        bytes.extend_from_slice(certificate.as_bytes());
        Ok(Card {
            name: name.to_owned(),
            request,
            certificate,
            bytes,
        })
    }

    /// Read a card and check the signatures of its request and certificate.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        const FORM: Error = Error::Format("not a card in the form legix-card/1");
        let text = std::str::from_utf8(bytes).map_err(|_| FORM)?;
        let rest = text
            .strip_prefix(CARD)
            .and_then(|rest| rest.strip_prefix('\n'))
            .ok_or(FORM)?;
        let (name, rest) = rest.split_once('\n').ok_or(FORM)?;
        let name = name.strip_prefix("name ").ok_or(FORM)?;
        let at = rest.find(ARMOR_END).ok_or(FORM)? + ARMOR_END.len();
        let (request, certificate) = rest.split_at(at);
        let card = Self::of(
            name,
            JoinRequest::parse(request.as_bytes())?,
            EndpointCert::parse(certificate.as_bytes())?,
        )?;
        if card.bytes != bytes {
            return Err(FORM);
        }
        Ok(card)
    }

    /// The device.
    pub fn device(&self) -> DeviceId {
        self.request.device()
    }

    /// The name its owner goes by.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The device's join request: its keys and its principal.
    pub fn request(&self) -> &JoinRequest {
        &self.request
    }

    /// The device's endpoint certificate.
    pub fn certificate(&self) -> &EndpointCert {
        &self.certificate
    }

    /// The id of the endpoint the device is reached at.
    pub fn endpoint(&self) -> [u8; 32] {
        self.certificate.endpoint()
    }

    /// The fingerprint of the device's key, `SHA256:…`: what two people compare to be sure of each other's devices.
    pub fn fingerprint(&self) -> String {
        self.request.fingerprint()
    }

    /// The card as it is kept and given.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// An invitation: a device of an admin of a group tells another device that it added it to the group, and where to
/// sync it from — signed by the inviting device ([`Folder::invite`](crate::Folder::invite)). The invited device joins
/// with it ([`Folder::join_invited`](crate::Folder::join_invited)), and its first sync brings the group's history.
///
/// ```text
/// legix-invitation/1
/// group <group id>
/// from <the inviting device's id>
/// endpoint <the inviting device's endpoint id: 64 lowercase hex digits>
/// to <the invited device's id>
/// role <admin, writer or reader>
/// kind <what the group is to the application: 1 to 32 of a-z, 0-9 and ->
/// title <what the application calls it: up to 200 bytes, on one line>
/// time <Unix seconds>
/// -----BEGIN SSH SIGNATURE-----
/// …
/// -----END SSH SIGNATURE-----
/// ```
///
/// The signature is an SSHSIG in the namespace `legix-invitation` over the nine lines, by the key whose device id is
/// `from`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invitation {
    group: GroupId,
    from: DeviceId,
    endpoint: [u8; 32],
    to: DeviceId,
    role: Role,
    kind: String,
    title: String,
    time: u64,
    bytes: Vec<u8>,
}

impl Invitation {
    /// The invitation the device that signs with `signer` gives `to`: into `group` as `role`, to be synced from the
    /// signer's endpoint `endpoint`.
    pub(crate) fn new(
        signer: &impl SigningKey,
        group: GroupId,
        endpoint: &[u8; 32],
        to: DeviceId,
        role: Role,
        kind: &str,
        title: &str,
    ) -> Result<Self, Error> {
        let from = DeviceId::of(&PublicKey::from(signer.public_key()));
        let text = format!(
            "{INVITATION}\ngroup {group}\nfrom {from}\nendpoint {}\nto {to}\nrole {role}\nkind {kind}\ntitle {}\ntime {}\n",
            crate::hex(endpoint),
            title.trim(),
            now(),
        );
        let signature = legix_sign::sign_in(INVITATION_NAMESPACE, text.as_bytes(), signer)?;
        Self::parse(format!("{text}{signature}").as_bytes())
    }

    /// Read an invitation and check its signature. Anything but its one text form is refused.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        const FORM: Error = Error::Format("not an invitation in the form legix-invitation/1");
        let text = std::str::from_utf8(bytes).map_err(|_| FORM)?;
        let at = text.find(ARMOR_BEGIN).ok_or(FORM)?;
        let (signed, signature) = text.split_at(at);
        if !signature.ends_with(ARMOR_END) || signature[ARMOR_BEGIN.len()..].contains(ARMOR_BEGIN) {
            return Err(FORM);
        }
        let lines: Vec<&str> = signed.strip_suffix('\n').ok_or(FORM)?.split('\n').collect();
        let [version, group, from, endpoint, to, role, kind, title, time] = lines[..] else {
            return Err(FORM);
        };
        let value = |line: &str, name: &str| -> Result<String, Error> {
            line.strip_prefix(name)
                .and_then(|rest| rest.strip_prefix(' '))
                .map(str::to_owned)
                .ok_or(FORM)
        };
        if version != INVITATION {
            return Err(FORM);
        }
        let group: GroupId = value(group, "group")?.parse().map_err(|_| FORM)?;
        let from: DeviceId = value(from, "from")?.parse().map_err(|_| FORM)?;
        // An endpoint id is an Ed25519 public key.
        let endpoint = crate::unhex32(&value(endpoint, "endpoint")?)
            .filter(|bytes| ed25519_dalek::VerifyingKey::from_bytes(bytes).is_ok())
            .ok_or(FORM)?;
        let to: DeviceId = value(to, "to")?.parse().map_err(|_| FORM)?;
        let role: Role = value(role, "role")?.parse().map_err(|_| FORM)?;
        let kind = value(kind, "kind")?;
        if kind.is_empty()
            || kind.len() > 32
            || !kind
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(Error::Format("an invitation's kind is 1 to 32 of a-z, 0-9 and -"));
        }
        let title = value(title, "title")?;
        if title.len() > 200 || title.chars().any(char::is_control) || title != title.trim() {
            return Err(Error::Format("an invitation's title is up to 200 bytes, on one line"));
        }
        let time = value(time, "time")?;
        if time.is_empty() || (time.len() > 1 && time.starts_with('0')) {
            return Err(FORM);
        }
        let time: u64 = time.parse().map_err(|_| FORM)?;

        let outcome = legix_sign::verify_in(
            INVITATION_NAMESPACE,
            signature.as_bytes(),
            signed.as_bytes(),
            None,
            &AllowedSigners::default(),
        );
        match (outcome.status, outcome.key) {
            (Status::Good, Some(key)) if DeviceId::of(&key) == from => {}
            _ => return Err(Error::Format("the invitation is not signed by the device it is from")),
        }
        Ok(Invitation {
            group,
            from,
            endpoint,
            to,
            role,
            kind,
            title,
            time,
            bytes: bytes.to_vec(),
        })
    }

    /// The group.
    pub fn group(&self) -> GroupId {
        self.group
    }

    /// The inviting device.
    pub fn from(&self) -> DeviceId {
        self.from
    }

    /// The id of the inviting device's endpoint: the device to sync with first.
    pub fn endpoint(&self) -> [u8; 32] {
        self.endpoint
    }

    /// The invited device.
    pub fn to(&self) -> DeviceId {
        self.to
    }

    /// The role the invited device was added with.
    pub fn role(&self) -> Role {
        self.role
    }

    /// What the group is to the application.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// What the application calls the group.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// When the invitation was made, in seconds since 1970.
    pub fn time(&self) -> u64 {
        self.time
    }

    /// The invitation as it is kept and given.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// What one device gives another by post: a card or an invitation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Letter {
    /// The sender's card: who it is, and where it is reached.
    Card(Card),
    /// An invitation into a group.
    Invitation(Invitation),
}

impl Letter {
    /// Read a letter: by its first line, a card or an invitation.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let first = bytes.split(|b| *b == b'\n').next().unwrap_or_default();
        if first == CARD.as_bytes() {
            Card::parse(bytes).map(Letter::Card)
        } else if first == INVITATION.as_bytes() {
            Invitation::parse(bytes).map(Letter::Invitation)
        } else {
            Err(Error::Format("not a letter this crate reads"))
        }
    }

    /// The letter as it is given.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Letter::Card(card) => card.as_bytes(),
            Letter::Invitation(invitation) => invitation.as_bytes(),
        }
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.chars().count() <= 100 && !name.chars().any(char::is_control)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(name: &str) -> Keys {
        Keys::generate(name).unwrap()
    }

    /// An endpoint id: an Ed25519 public key.
    fn endpoint() -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes()
    }

    #[test]
    fn a_card_is_read_back_as_it_was_given() {
        let ada = keys("ada");
        let card = Card::new(&ada, "ada@example.com", "  Ada Lovelace ", &endpoint()).unwrap();
        assert_eq!(card.name(), "Ada Lovelace");
        assert_eq!(Card::parse(card.as_bytes()).unwrap(), card);
        assert_eq!(
            (card.device(), card.fingerprint(), card.endpoint()),
            (ada.device(), ada.fingerprint(), endpoint())
        );
        assert_eq!(card.request().principal(), "ada@example.com");
        assert!(matches!(Letter::parse(card.as_bytes()), Ok(Letter::Card(_))));
    }

    #[test]
    fn a_card_of_two_devices_or_without_a_name_is_refused() {
        let (ada, bo) = (keys("ada"), keys("bo"));
        let request = JoinRequest::new(&ada.signing, &ada.identity, "ada@example.com").unwrap();
        let bos = EndpointCert::new(&bo.signing, &endpoint()).unwrap();
        assert!(Card::of("Ada", request.clone(), bos).is_err());
        let own = EndpointCert::new(&ada.signing, &endpoint()).unwrap();
        assert!(Card::of(" ", request.clone(), own.clone()).is_err());
        assert!(Card::of("Ada\nLovelace", request.clone(), own.clone()).is_err());

        // The name is its owner's word, and not signed; the request and the certificate are.
        let text = String::from_utf8(Card::of("Ada", request, own).unwrap().as_bytes().to_vec()).unwrap();
        assert_eq!(
            Card::parse(text.replace("name Ada", "name Eve").as_bytes())
                .unwrap()
                .name(),
            "Eve"
        );
        assert!(Card::parse(text.replace("principal ada@", "principal eve@").as_bytes()).is_err());
        assert!(
            Card::parse(format!("{text}\n").as_bytes()).is_err(),
            "nothing after the certificate"
        );
    }

    #[test]
    fn an_invitation_is_signed_by_the_device_it_is_from() {
        let (ada, bo) = (keys("ada"), keys("bo"));
        let group: GroupId = "ab".repeat(32).parse().unwrap();
        let invitation = Invitation::new(
            &ada.signing,
            group,
            &endpoint(),
            bo.device(),
            Role::Reader,
            "chat",
            " Ada and Bo ",
        )
        .unwrap();
        assert_eq!(
            (
                invitation.group(),
                invitation.from(),
                invitation.to(),
                invitation.endpoint()
            ),
            (group, ada.device(), bo.device(), endpoint())
        );
        assert_eq!(
            (invitation.role(), invitation.kind(), invitation.title()),
            (Role::Reader, "chat", "Ada and Bo")
        );
        assert_eq!(Invitation::parse(invitation.as_bytes()).unwrap(), invitation);
        assert!(matches!(
            Letter::parse(invitation.as_bytes()),
            Ok(Letter::Invitation(_))
        ));

        let text = String::from_utf8(invitation.as_bytes().to_vec()).unwrap();
        assert!(
            Invitation::parse(text.replace("role reader", "role admin").as_bytes()).is_err(),
            "changed on the way"
        );
        let from_bo = text.replace(&format!("from {}", ada.device()), &format!("from {}", bo.device()));
        assert!(
            Invitation::parse(from_bo.as_bytes()).is_err(),
            "signed by another device than it names"
        );
        assert!(Invitation::new(&ada.signing, group, &endpoint(), bo.device(), Role::Reader, "Chat!", "").is_err());
        assert!(Letter::parse(b"legix-something/1\nwhat\n").is_err());
    }
}

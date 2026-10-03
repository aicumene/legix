//! The head of a bundle: seven lines of text and a signature, in the clear, so that relays can check them.

use std::fmt;

use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use legix_crypt::{DocumentKey, Oid};
use legix_sign::{
    AllowedSigners, Status, Trust,
    ssh_key::{PublicKey, SigningKey},
};
use zeroize::Zeroizing;

use crate::{DeviceId, Error, GroupKey, NAMESPACE, Problem, hex};

/// The first line of every head of this version.
pub const VERSION: &str = "legix-bundle/1";
/// The length of a wrapped bundle key: nonce, key and tag.
pub const WRAPPED_KEY_LEN: usize = NONCE_LEN + 32 + 16;

const NONCE_LEN: usize = 24;
const KEY_AAD_PREFIX: &[u8] = b"legix-bundle/1 key ";
const ARMOR_BEGIN: &[u8] = b"-----BEGIN SSH SIGNATURE-----\n";
const ARMOR_END: &[u8] = b"-----END SSH SIGNATURE-----\n";

/// The id of a bundle: the BLAKE3 hash of its head, signature included.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct BundleId([u8; 32]);

impl BundleId {
    /// What the first bundle of a device names as the bundle before it.
    pub const NONE: BundleId = BundleId([0; 32]);

    /// The id of a bundle with this head.
    pub fn of(head: &[u8]) -> Self {
        BundleId(*blake3::hash(head).as_bytes())
    }

    /// An id from its 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        BundleId(bytes)
    }

    /// The id's 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The 64 lowercase hex digits of the id.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// An id from 64 lowercase hex digits.
    pub fn from_hex(text: &str) -> Result<Self, Error> {
        let mut bytes = [0; 32];
        hex::decode(text, &mut bytes).ok_or(Error::Format("a bundle id is 64 lowercase hex digits"))?;
        Ok(BundleId(bytes))
    }
}

impl fmt::Display for BundleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for BundleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BundleId({self})")
    }
}

/// The signed part of a bundle's head: who wrote the bundle, its place in the device's chain, and its body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    /// The device that wrote the bundle.
    pub device: DeviceId,
    /// The bundle's place in the device's chain, counted from 1.
    pub seq: u64,
    /// The id of the device's bundle before this one; [`BundleId::NONE`] for the first.
    pub prev: BundleId,
    /// When the bundle was written, in seconds since 1970.
    pub time: u64,
    /// The id of the body, a legix-crypt object.
    pub body: Oid,
    /// The length of the body.
    pub body_len: u64,
    /// The bundle key wrapped with the group key: nonce, key and tag.
    pub key: [u8; WRAPPED_KEY_LEN],
}

impl Head {
    /// The seven lines that are signed.
    pub fn to_text(&self) -> String {
        format!(
            "{VERSION}\ndevice {}\nseq {}\nprev {}\ntime {}\nbody {} {}\nkey {}\n",
            self.device,
            self.seq,
            self.prev,
            self.time,
            self.body,
            self.body_len,
            hex::encode(&self.key)
        )
    }

    /// Read the seven signed lines. Anything but their one text form is refused.
    pub fn parse(text: &[u8]) -> Result<Self, Error> {
        parse_lines(text).map_err(Error::Format)
    }

    /// Wrap `key`, the bundle key, for the bundle `seq` of `device` with body `body`.
    pub fn wrap_key(
        group: &GroupKey,
        device: &DeviceId,
        seq: u64,
        body: &Oid,
        key: &DocumentKey,
    ) -> Result<[u8; WRAPPED_KEY_LEN], Error> {
        let mut nonce = [0; NONCE_LEN];
        crate::random(&mut nonce)?;
        Ok(wrap_key_with_nonce(group, device, seq, body, key, &nonce))
    }

    /// The bundle key, unwrapped with the group key.
    pub fn unwrap_key(&self, group: &GroupKey) -> Result<DocumentKey, Error> {
        let (nonce, rest) = self.key.split_at(NONCE_LEN);
        let (wrapped, tag) = rest.split_at(32);
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(wrapped);
        cipher(group)
            .decrypt_inout_detached(
                &XNonce::try_from(nonce).expect("24 bytes"),
                &key_aad(&self.device, self.seq, &self.body),
                (&mut key[..]).into(),
                &Tag::try_from(tag).expect("16 bytes"),
            )
            .map_err(|_| Error::GroupKey)?;
        Ok(DocumentKey::from_bytes(*key))
    }

    /// Sign the head with the device's key.
    pub fn sign(&self, signer: &impl SigningKey) -> Result<SignedHead, Error> {
        if DeviceId::of(&PublicKey::from(signer.public_key())) != self.device {
            return Err(Error::Format("the head names another device than the signing key"));
        }
        let text = self.to_text();
        let signature = legix_sign::sign_in(NAMESPACE, text.as_bytes(), signer)?;
        SignedHead::parse(format!("{text}{signature}").as_bytes())
    }
}

/// A head with its signature, as a relay keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedHead {
    head: Head,
    bytes: Vec<u8>,
    signed_len: usize,
}

impl SignedHead {
    /// Read a head and its armored signature. The signature is not checked: see [`SignedHead::verify`].
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let signed_len = bytes
            .windows(ARMOR_BEGIN.len())
            .position(|window| window == ARMOR_BEGIN)
            .ok_or(Error::Format("the head has no signature"))?;
        let signature = &bytes[signed_len..];
        if !signature.ends_with(ARMOR_END)
            || signature[ARMOR_BEGIN.len()..]
                .windows(ARMOR_BEGIN.len())
                .any(|window| window == ARMOR_BEGIN)
        {
            return Err(Error::Format("the head does not end with one armored signature"));
        }
        let head = Head::parse(&bytes[..signed_len])?;
        Ok(SignedHead {
            head,
            bytes: bytes.to_vec(),
            signed_len,
        })
    }

    /// The signed part.
    pub fn head(&self) -> &Head {
        &self.head
    }

    /// The head as a relay keeps it: the signed lines and the signature.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The armored signature.
    pub fn signature(&self) -> &[u8] {
        &self.bytes[self.signed_len..]
    }

    /// The id of the bundle.
    pub fn id(&self) -> BundleId {
        BundleId::of(&self.bytes)
    }

    /// Check that a member signed the head: a good signature in the `legix-bundle` namespace, by the key of the device
    /// the head names, which `members` allow at the head's time. Returns the principals the members list for the key.
    pub fn verify(&self, members: &AllowedSigners) -> Result<String, Problem> {
        let time = i64::try_from(self.head.time).map_err(|_| Problem::Format("the time is too large"))?;
        let outcome = legix_sign::verify_in(
            NAMESPACE,
            self.signature(),
            &self.bytes[..self.signed_len],
            Some(time),
            members,
        );
        if outcome.status != Status::Good {
            return Err(Problem::Signature(outcome.status));
        }
        let key = outcome.key.as_ref().expect("a good signature has its key");
        if DeviceId::of(key) != self.head.device {
            return Err(Problem::WrongDevice);
        }
        match outcome.trust {
            Trust::Allowed { principals } => Ok(principals),
            other => Err(Problem::Untrusted(other)),
        }
    }
}

pub(crate) fn wrap_key_with_nonce(
    group: &GroupKey,
    device: &DeviceId,
    seq: u64,
    body: &Oid,
    key: &DocumentKey,
    nonce: &[u8; NONCE_LEN],
) -> [u8; WRAPPED_KEY_LEN] {
    let mut wrapped = [0; WRAPPED_KEY_LEN];
    let (nonce_out, rest) = wrapped.split_at_mut(NONCE_LEN);
    let (key_out, tag_out) = rest.split_at_mut(32);
    nonce_out.copy_from_slice(nonce);
    key_out.copy_from_slice(key.as_bytes());
    let tag = cipher(group)
        .encrypt_inout_detached(&XNonce::from(*nonce), &key_aad(device, seq, body), key_out.into())
        .expect("32 bytes are far below the cipher's limit");
    tag_out.copy_from_slice(&tag);
    wrapped
}

fn cipher(group: &GroupKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(group.as_bytes()).expect("32 bytes is the key length")
}

fn key_aad(device: &DeviceId, seq: u64, body: &Oid) -> Vec<u8> {
    [KEY_AAD_PREFIX, device.as_bytes(), &seq.to_be_bytes(), body.as_bytes()].concat()
}

fn parse_lines(text: &[u8]) -> Result<Head, &'static str> {
    let text = std::str::from_utf8(text).map_err(|_| "not UTF-8")?;
    let text = text
        .strip_suffix('\n')
        .ok_or("the last line does not end with a line feed")?;
    let lines: Vec<&str> = text.split('\n').collect();
    let [version, device, seq, prev, time, body, key] = lines[..] else {
        return Err("expected seven lines");
    };
    if version != VERSION {
        return Err("a version this crate does not read");
    }
    let value = |line: &str, name: &str| line.strip_prefix(name).map(str::to_owned);

    let device = value(device, "device ").ok_or("the second line is not `device …`")?;
    let device = DeviceId::from_hex(&device).map_err(|_| "the device is not 64 lowercase hex digits")?;
    let seq = value(seq, "seq ").ok_or("the third line is not `seq …`")?;
    let seq = hex::number(&seq)
        .filter(|&n| n >= 1)
        .ok_or("the seq is not a number from 1")?;
    let prev = value(prev, "prev ").ok_or("the fourth line is not `prev …`")?;
    let prev = BundleId::from_hex(&prev).map_err(|_| "prev is not 64 lowercase hex digits")?;
    if (seq == 1) != (prev == BundleId::NONE) {
        return Err("prev is zeros exactly for the first bundle");
    }
    let time = value(time, "time ").ok_or("the fifth line is not `time …`")?;
    let time = hex::number(&time).ok_or("the time is not a number")?;
    let body = value(body, "body ").ok_or("the sixth line is not `body …`")?;
    let (oid, len) = body
        .split_once(' ')
        .ok_or("the body line is not `body <id> <length>`")?;
    let body: Oid = oid
        .parse()
        .map_err(|_| "the body id is not `blake3:` and 64 hex digits")?;
    let body_len = hex::number(len).ok_or("the body length is not a number")?;
    let key = value(key, "key ").ok_or("the seventh line is not `key …`")?;
    let mut wrapped = [0; WRAPPED_KEY_LEN];
    hex::decode(&key, &mut wrapped).ok_or("the key is not 144 lowercase hex digits")?;
    Ok(Head {
        device,
        seq,
        prev,
        time,
        body,
        body_len,
        key: wrapped,
    })
}

#[cfg(test)]
mod tests {
    use legix_sign::ssh_key::PrivateKey;

    use super::*;

    fn group() -> GroupKey {
        GroupKey::from_bytes(std::array::from_fn(|i| 0x40 + i as u8))
    }

    fn body() -> Oid {
        "blake3:c0d50151e78d1ba23494e2c884809eedd6d770f49ffb4cb797cecb633e0b20b8"
            .parse()
            .unwrap()
    }

    /// A bundle key wrapped for a known group key, nonce, device, place and body, pinned so that the format cannot
    /// change unnoticed. The same bytes come out of an independent implementation of FORMAT.md on OpenSSL.
    #[test]
    fn a_known_wrapped_bundle_key() {
        let device = DeviceId::from_bytes([0x11; 32]);
        let key = DocumentKey::from_bytes(std::array::from_fn(|i| i as u8));
        let nonce = std::array::from_fn(|i| 0x10 + i as u8);
        let wrapped = wrap_key_with_nonce(&group(), &device, 7, &body(), &key, &nonce);
        assert_eq!(
            hex::encode(&wrapped),
            "101112131415161718191a1b1c1d1e1f2021222324252627524aeb4005f948255478563928585cf9143dd2e3b429d5db09a7b45\
             62c252f00b81e833278b2d7c2124bd783a20a3fb4"
        );
        let mut head = Head {
            device,
            seq: 7,
            prev: BundleId::from_bytes([1; 32]),
            time: 1_759_400_000,
            body: body(),
            body_len: 92,
            key: wrapped,
        };
        assert_eq!(head.unwrap_key(&group()).unwrap().as_bytes(), key.as_bytes());
        assert!(matches!(
            head.unwrap_key(&GroupKey::from_bytes([9; 32])),
            Err(Error::GroupKey)
        ));
        head.seq = 8;
        assert!(
            matches!(head.unwrap_key(&group()), Err(Error::GroupKey)),
            "bound to its place"
        );
    }

    fn signed_head(signer: &PrivateKey, seq: u64) -> SignedHead {
        let device = DeviceId::of(signer.public_key());
        let bundle_key = DocumentKey::generate().unwrap();
        Head {
            device,
            seq,
            prev: if seq == 1 {
                BundleId::NONE
            } else {
                BundleId::from_bytes([3; 32])
            },
            time: 1_759_400_000,
            body: body(),
            body_len: 92,
            key: Head::wrap_key(&group(), &device, seq, &body(), &bundle_key).unwrap(),
        }
        .sign(signer)
        .unwrap()
    }

    #[test]
    fn a_head_reads_back_as_it_was_written_and_is_checked_against_the_members() {
        let ada = legix_sign::generate_ed25519("ada").unwrap();
        let signed = signed_head(&ada, 1);
        let read = SignedHead::parse(signed.as_bytes()).unwrap();
        assert_eq!(read, signed);
        assert_eq!(read.id(), BundleId::of(signed.as_bytes()));
        assert!(signed.as_bytes().starts_with(signed.head().to_text().as_bytes()));

        let mut members = AllowedSigners::default();
        members.push("ada@example.com", ada.public_key().clone());
        assert_eq!(read.verify(&members).unwrap(), "ada@example.com");
        assert!(matches!(
            read.verify(&AllowedSigners::default()),
            Err(Problem::Untrusted(Trust::UnknownKey))
        ));

        // A head that names one device and is signed by another.
        let bob = legix_sign::generate_ed25519("bob").unwrap();
        let text = signed.head().to_text();
        let by_bob = legix_sign::sign_in(NAMESPACE, text.as_bytes(), &bob).unwrap();
        let forged = SignedHead::parse(format!("{text}{by_bob}").as_bytes()).unwrap();
        members.push("bob@example.com", bob.public_key().clone());
        assert_eq!(forged.verify(&members), Err(Problem::WrongDevice));

        // A commit signature over the same lines does not make a head.
        let as_commit = legix_sign::sign(text.as_bytes(), &ada).unwrap();
        let in_git = SignedHead::parse(format!("{text}{as_commit}").as_bytes()).unwrap();
        assert_eq!(in_git.verify(&members), Err(Problem::Signature(Status::Bad)));

        // One changed character of the signed lines.
        let altered = String::from_utf8(signed.as_bytes().to_vec())
            .unwrap()
            .replace("time 1759400000", "time 1759400001");
        let altered = SignedHead::parse(altered.as_bytes()).unwrap();
        assert_eq!(altered.verify(&members), Err(Problem::Signature(Status::Bad)));
    }

    #[test]
    fn anything_but_the_one_text_form_of_a_head_is_refused() {
        let ada = legix_sign::generate_ed25519("ada").unwrap();
        let first = String::from_utf8(signed_head(&ada, 1).as_bytes().to_vec()).unwrap();
        let second = String::from_utf8(signed_head(&ada, 2).as_bytes().to_vec()).unwrap();
        let zeros = "0".repeat(64);
        for (text, what) in [
            (first.replace('\n', "\r\n"), "CRLF"),
            (first.replace("seq 1", "seq 01"), "a leading zero"),
            (first.replace("seq 1", "seq 0"), "seq 0"),
            (second.replace(&"03".repeat(32), &zeros), "a later bundle without prev"),
            (
                first.replace(&format!("prev {zeros}"), &format!("prev {}", "03".repeat(32))),
                "a first bundle with prev",
            ),
            (first.replace("time ", "time  "), "two spaces"),
            (first.replace("legix-bundle/1", "legix-bundle/2"), "another version"),
            (first.replacen("\nkey ", "\nextra line\nkey ", 1), "an extra line"),
            (
                first.replace("-----END SSH SIGNATURE-----\n", "-----END SSH SIGNATURE-----\nmore\n"),
                "text after the signature",
            ),
            (first.split("-----BEGIN").next().unwrap().to_string(), "no signature"),
            (first.replacen("device ", "device A", 1), "an upper-case device id"),
        ] {
            assert!(SignedHead::parse(text.as_bytes()).is_err(), "{what}");
        }
    }
}

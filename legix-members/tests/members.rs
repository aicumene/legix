//! The membership log: founding, joining, roles, removal and rotation, the rules, and what a relay can and cannot do.

use std::{fs, path::PathBuf};

use legix_members::{Entry, Error, GroupId, Identity, JoinRequest, Members, Op, Role, Rule, found};
use legix_sign::ssh_key::PrivateKey;
use legix_sync::{Access, DeviceId, DirRelay, Problem, Relay};

struct Device {
    name: &'static str,
    key: PrivateKey,
    identity: Identity,
}

impl Device {
    fn new(name: &'static str) -> Self {
        Device {
            name,
            key: legix_sign::generate_ed25519(&format!("{name}@example.com")).unwrap(),
            identity: Identity::generate().unwrap(),
        }
    }

    fn id(&self) -> DeviceId {
        DeviceId::of(self.key.public_key())
    }

    fn request(&self) -> JoinRequest {
        JoinRequest::new(&self.key, &self.identity, &format!("{}@example.com", self.name)).unwrap()
    }
}

struct Group {
    relay: DirRelay,
    group: GroupId,
    dir: tempfile::TempDir,
}

impl Group {
    /// A group that `founder` founds on a new relay, with `others` added at once.
    fn found(founder: &Device, others: &[(&Device, Role)]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let relay = DirRelay::new(dir.path().join("relay"));
        let requests: Vec<_> = others.iter().map(|(device, role)| (device.request(), *role)).collect();
        let first = found(
            &founder.key,
            &founder.identity,
            &format!("{}@example.com", founder.name),
            &requests,
        )
        .unwrap();
        relay.put_member_entry(1, first.as_bytes()).unwrap();
        Group {
            relay,
            group: first.id().into(),
            dir,
        }
    }

    fn pin(&self, device: &Device) -> PathBuf {
        self.dir.path().join(format!("{}.pin", device.name))
    }

    fn load(&self, device: &Device) -> Result<Members, Error> {
        Members::load(&self.relay, &self.group, &device.identity, &self.pin(device))
    }

    fn members(&self, device: &Device) -> Members {
        self.load(device).unwrap()
    }

    /// Publish the next entry.
    fn publish(&self, entry: &Entry) {
        self.relay.put_member_entry(entry.seq(), entry.as_bytes()).unwrap();
    }

    fn entry_path(&self, seq: u64) -> PathBuf {
        self.dir.path().join("relay/members").join(format!("{seq:020}"))
    }
}

#[test]
fn a_group_is_founded_and_a_device_joins_by_its_request() {
    let (ada, bo) = (Device::new("ada"), Device::new("bo"));
    let group = Group::found(&ada, &[]);
    let members = group.members(&ada);
    assert_eq!(members.me().unwrap().role, Role::Admin);
    assert_eq!(members.roster().epoch(), 1);
    assert_eq!(members.current().unwrap().0, 1);

    // Bo leaves a request on the relay; Ada checks its fingerprint with Bo and adds Bo.
    let request = bo.request();
    assert_eq!(
        request.fingerprint(),
        bo.key.public_key().fingerprint(Default::default()).to_string()
    );
    group.relay.put_join(&bo.id(), request.as_bytes()).unwrap();
    let waiting = JoinRequest::parse(&group.relay.joins().unwrap()[0]).unwrap();
    assert_eq!(waiting, request);
    let entry = members.change().add(waiting, Role::Writer).sign(&ada.key).unwrap();
    assert_eq!(entry.epoch(), 1, "adding a device keeps the key");
    group.publish(&entry);

    let for_bo = group.members(&bo);
    assert_eq!(for_bo.me().unwrap().device, bo.id());
    assert_eq!(for_bo.me().unwrap().role, Role::Writer);
    assert_eq!(
        for_bo.key(1).unwrap().as_bytes(),
        group.members(&ada).key(1).unwrap().as_bytes(),
        "both hold the group key"
    );
    assert_eq!(group.members(&ada).roster().members().len(), 2);
}

#[test]
fn a_removed_device_gets_no_new_key_and_its_later_bundles_are_refused() {
    let (ada, bo, cy) = (Device::new("ada"), Device::new("bo"), Device::new("cy"));
    let group = Group::found(&ada, &[(&bo, Role::Writer), (&cy, Role::Writer)]);
    let entry = group.members(&ada).change().remove(cy.id(), 3).sign(&ada.key).unwrap();
    assert_eq!(entry.epoch(), 2);
    assert!(!entry.sealed_for().any(|device| device == cy.id()));
    group.publish(&entry);

    let for_bo = group.members(&bo);
    assert!(for_bo.key(2).is_some() && for_bo.key(1).is_some());
    assert_ne!(for_bo.key(2).unwrap().as_bytes(), for_bo.key(1).unwrap().as_bytes());
    assert_eq!(for_bo.current().unwrap().0, 2);

    let for_cy = group.members(&cy);
    assert!(for_cy.key(1).is_some(), "what it could read");
    assert!(for_cy.key(2).is_none(), "nothing after");
    let me = for_cy.me().unwrap();
    assert_eq!((me.last_epoch, me.cutoff), (Some(1), Some(3)));
    assert!(matches!(
        for_cy.current(),
        Err(legix_sync::Error::NotAllowed(Problem::NotMember))
    ));

    let key = cy.key.public_key();
    assert_eq!(for_bo.may_publish(&cy.id(), key, 3, 1, 0).unwrap(), "cy@example.com");
    assert_eq!(
        for_bo.may_publish(&cy.id(), key, 4, 1, 0),
        Err(Problem::PastCutoff { cutoff: 3 })
    );
    assert_eq!(for_bo.may_publish(&cy.id(), key, 2, 2, 0), Err(Problem::WrongEpoch(2)));
    let stranger = Device::new("mallory");
    assert_eq!(
        for_bo.may_publish(&stranger.id(), stranger.key.public_key(), 1, 1, 0),
        Err(Problem::NotMember)
    );
}

#[test]
fn a_member_added_later_reads_the_whole_history() {
    let (ada, dee) = (Device::new("ada"), Device::new("dee"));
    let group = Group::found(&ada, &[]);
    for _ in 0..2 {
        group.publish(&group.members(&ada).change().rotate().sign(&ada.key).unwrap());
    }
    let entry = group
        .members(&ada)
        .change()
        .add(dee.request(), Role::Writer)
        .sign(&ada.key)
        .unwrap();
    assert_eq!(
        entry.sealed_for().collect::<Vec<_>>(),
        vec![dee.id()],
        "sealed for the new device only"
    );
    group.publish(&entry);

    let for_ada = group.members(&ada);
    let for_dee = group.members(&dee);
    assert_eq!(for_dee.epochs().collect::<Vec<_>>(), vec![1, 2, 3]);
    for epoch in 1..=3 {
        assert_eq!(
            for_dee.key(epoch).unwrap().as_bytes(),
            for_ada.key(epoch).unwrap().as_bytes()
        );
    }
}

#[test]
fn readers_read_and_publish_nothing_after_their_cutoff() {
    let (ada, bo, eve) = (Device::new("ada"), Device::new("bo"), Device::new("eve"));
    let group = Group::found(&ada, &[(&bo, Role::Writer), (&eve, Role::Reader)]);
    let for_eve = group.members(&eve);
    assert!(for_eve.key(1).is_some(), "a reader reads");
    assert!(matches!(
        for_eve.current(),
        Err(legix_sync::Error::NotAllowed(Problem::PastCutoff { cutoff: 0 }))
    ));
    let members = group.members(&ada);
    assert_eq!(
        members.may_publish(&eve.id(), eve.key.public_key(), 1, 1, 0),
        Err(Problem::PastCutoff { cutoff: 0 })
    );

    // A writer made a reader keeps the bundles it wrote up to its cutoff.
    group.publish(
        &members
            .change()
            .set_role(bo.id(), Role::Reader, Some(5))
            .sign(&ada.key)
            .unwrap(),
    );
    let members = group.members(&ada);
    assert!(members.may_publish(&bo.id(), bo.key.public_key(), 5, 1, 0).is_ok());
    assert_eq!(
        members.may_publish(&bo.id(), bo.key.public_key(), 6, 1, 0),
        Err(Problem::PastCutoff { cutoff: 5 })
    );
    group.publish(
        &members
            .change()
            .set_role(bo.id(), Role::Writer, None)
            .sign(&ada.key)
            .unwrap(),
    );
    assert!(
        group
            .members(&ada)
            .may_publish(&bo.id(), bo.key.public_key(), 6, 1, 0)
            .is_ok()
    );
}

fn refused(result: Result<Entry, Error>) -> Rule {
    match result {
        Err(Error::Rule { rule, .. }) => rule,
        other => panic!("expected a rule to be broken: {other:?}"),
    }
}

#[test]
fn changes_that_break_the_rules_are_refused() {
    let (ada, bo, cy) = (Device::new("ada"), Device::new("bo"), Device::new("cy"));
    let group = Group::found(&ada, &[(&bo, Role::Writer)]);
    let members = group.members(&ada);
    assert_eq!(refused(members.change().rotate().sign(&bo.key)), Rule::NotAdmin);
    assert_eq!(
        refused(members.change().remove(ada.id(), 0).sign(&ada.key)),
        Rule::NoAdmin
    );
    assert_eq!(
        refused(members.change().add(bo.request(), Role::Reader).sign(&ada.key)),
        Rule::Member(bo.id())
    );
    assert_eq!(
        refused(members.change().remove(cy.id(), 0).sign(&ada.key)),
        Rule::NotMember(cy.id())
    );
    assert_eq!(
        refused(members.change().set_role(bo.id(), Role::Writer, None).sign(&ada.key)),
        Rule::SameRole(bo.id())
    );
    assert_eq!(
        refused(members.change().set_role(bo.id(), Role::Reader, None).sign(&ada.key)),
        Rule::Cutoff(bo.id())
    );
    assert_eq!(
        refused(members.change().set_role(bo.id(), Role::Admin, Some(1)).sign(&ada.key)),
        Rule::Cutoff(bo.id())
    );
    assert_eq!(
        refused(
            members
                .change()
                .set_role(bo.id(), Role::Reader, Some(1))
                .remove(bo.id(), 1)
                .sign(&ada.key)
        ),
        Rule::Twice(bo.id())
    );

    // A reader removed keeps no bundle later than it kept as a reader.
    let eve = Device::new("eve");
    group.publish(
        &members
            .change()
            .add(eve.request(), Role::Reader)
            .sign(&ada.key)
            .unwrap(),
    );
    let members = group.members(&ada);
    assert_eq!(
        refused(members.change().remove(eve.id(), 5).sign(&ada.key)),
        Rule::Cutoff(eve.id())
    );

    // A removed device stays removed: its key cannot come back.
    group.publish(&members.change().remove(bo.id(), 1).sign(&ada.key).unwrap());
    let members = group.members(&ada);
    assert_eq!(
        refused(members.change().add(bo.request(), Role::Writer).sign(&ada.key)),
        Rule::Member(bo.id())
    );
}

/// The text of `entry` without its signature, changed by `change`, signed again with `key`.
fn resigned(entry: &Entry, key: &PrivateKey, change: impl FnOnce(String) -> String) -> Entry {
    let text = String::from_utf8(entry.as_bytes().to_vec()).unwrap();
    let text = text.split("-----BEGIN SSH SIGNATURE-----").next().unwrap().to_owned();
    let text = change(text);
    let signature = legix_sign::sign_in(legix_members::NAMESPACE, text.as_bytes(), key).unwrap();
    Entry::parse(format!("{text}{signature}").as_bytes()).unwrap()
}

fn applies(group: &Group, device: &Device, entry: &Entry) -> Result<(), Error> {
    let mut members = group.members(device);
    members.apply(entry, &device.identity)
}

fn rule(result: Result<(), Error>) -> Rule {
    match result {
        Err(Error::Rule { rule, .. }) => rule,
        other => panic!("expected a rule to be broken: {other:?}"),
    }
}

#[test]
fn entries_written_around_the_rules_are_refused() {
    let (ada, bo, cy) = (Device::new("ada"), Device::new("bo"), Device::new("cy"));
    let group = Group::found(&ada, &[(&bo, Role::Writer), (&cy, Role::Writer)]);
    let members = group.members(&ada);
    let rotation = members.change().remove(cy.id(), 0).sign(&ada.key).unwrap();
    let addition = members
        .change()
        .add(Device::new("dee").request(), Role::Writer)
        .sign(&ada.key)
        .unwrap();
    applies(&group, &ada, &rotation).unwrap();

    let key_line = |text: &str, device: DeviceId| {
        text.lines()
            .find(|line| line.starts_with(&format!("key {device} ")))
            .unwrap()
            .to_owned()
            + "\n"
    };
    let previous_line = |text: &str| {
        text.lines()
            .find(|line| line.starts_with("previous "))
            .unwrap()
            .to_owned()
            + "\n"
    };
    let header = |text: String, field: &str, value: &str| -> String {
        text.lines()
            .map(|line| {
                if line.starts_with(&format!("{field} ")) {
                    format!("{field} {value}\n")
                } else {
                    format!("{line}\n")
                }
            })
            .collect()
    };
    for (entry, expected) in [
        (
            resigned(&rotation, &ada.key, |text| text.replace(&key_line(&text, bo.id()), "")),
            Rule::Keys,
        ),
        (
            resigned(&rotation, &ada.key, |text| text.replace(&previous_line(&text), "")),
            Rule::Previous,
        ),
        (
            resigned(&rotation, &ada.key, |text| header(text, "epoch", "1")),
            Rule::NoRotation,
        ),
        (
            resigned(&rotation, &ada.key, |text| header(text, "epoch", "3")),
            Rule::Epoch,
        ),
        (
            resigned(&rotation, &ada.key, |text| header(text, "seq", "3")),
            Rule::Misplaced,
        ),
        (
            resigned(&rotation, &ada.key, |text| header(text, "prev", &"0".repeat(64))),
            Rule::Misplaced,
        ),
        (
            resigned(&rotation, &ada.key, |text| header(text, "group", &"0".repeat(64))),
            Rule::Misplaced,
        ),
        (
            resigned(&rotation, &ada.key, |text| header(text, "time", "1")),
            Rule::TimeGoesBack,
        ),
        (resigned(&rotation, &bo.key, |text| text), Rule::NotAdmin),
        (
            resigned(&addition, &ada.key, |text| {
                text + &previous_line(&rotation_text(&rotation))
            }),
            Rule::Previous,
        ),
    ] {
        assert_eq!(rule(applies(&group, &ada, &entry)), expected, "{expected:?}");
    }

    // One changed character after signing.
    let altered = String::from_utf8(rotation.as_bytes().to_vec())
        .unwrap()
        .replacen("epoch 2", "epoch 1", 1);
    let altered = Entry::parse(altered.as_bytes()).unwrap();
    assert!(matches!(rule(applies(&group, &ada, &altered)), Rule::Signature(_)));

    // A first entry that does not add its signer as an admin.
    let mallory = Device::new("mallory");
    let first = found(&ada.key, &ada.identity, "ada@example.com", &[]).unwrap();
    let forged = resigned(&first, &mallory.key, |text| text);
    assert_eq!(rule(legix_members::Roster::new().apply(&forged)), Rule::Founder);
}

fn rotation_text(entry: &Entry) -> String {
    String::from_utf8(entry.as_bytes().to_vec()).unwrap()
}

#[test]
fn the_relay_can_neither_swap_nor_roll_back_the_log() {
    let (ada, bo) = (Device::new("ada"), Device::new("bo"));
    let group = Group::found(&ada, &[(&bo, Role::Writer)]);
    group.publish(&group.members(&ada).change().rotate().sign(&ada.key).unwrap());
    let third = group.members(&ada).change().rotate().sign(&ada.key).unwrap();
    group.publish(&third);
    assert_eq!(
        group.members(&bo).roster().seq(),
        3,
        "bo has checked the log to entry 3"
    );

    // The relay drops the last entry.
    fs::remove_file(group.entry_path(3)).unwrap();
    assert!(matches!(group.load(&bo), Err(Error::Rollback { pinned: 3, found: 2 })));

    // The relay holds another, valid, third entry.
    let other = group.members(&ada).change().rotate().sign(&ada.key).unwrap();
    group.publish(&other);
    assert_ne!(other.id(), third.id());
    assert!(matches!(group.load(&bo), Err(Error::Fork { seq: 3 })));

    // A log that is not the group's.
    let elsewhere = Group::found(&Device::new("mallory"), &[]);
    let wrong = Members::load(&elsewhere.relay, &group.group, &bo.identity, &group.pin(&bo));
    assert!(matches!(wrong, Err(Error::WrongGroup)));
}

#[test]
fn two_admins_writing_at_once_take_turns() {
    let (ada, bo) = (Device::new("ada"), Device::new("bo"));
    let group = Group::found(&ada, &[(&bo, Role::Admin)]);
    let by_ada = group
        .members(&ada)
        .change()
        .add(Device::new("cy").request(), Role::Writer)
        .sign(&ada.key)
        .unwrap();
    let dee = Device::new("dee");
    let by_bo = group
        .members(&bo)
        .change()
        .add(dee.request(), Role::Reader)
        .sign(&bo.key)
        .unwrap();
    group.publish(&by_ada);
    assert!(matches!(
        group.relay.put_member_entry(by_bo.seq(), by_bo.as_bytes()),
        Err(legix_sync::Error::EntryExists { seq: 2 })
    ));
    // Bo reads the log again and writes the change after Ada's.
    let by_bo = group
        .members(&bo)
        .change()
        .add(dee.request(), Role::Reader)
        .sign(&bo.key)
        .unwrap();
    assert_eq!(by_bo.seq(), 3);
    group.publish(&by_bo);
    assert_eq!(group.members(&ada).roster().members().len(), 4);
}

#[test]
fn a_join_request_cannot_be_changed_on_the_way() {
    let (bo, mallory) = (Device::new("bo"), Device::new("mallory"));
    let request = String::from_utf8(bo.request().as_bytes().to_vec()).unwrap();
    let swapped = request.replace(
        &bo.identity.recipient().to_string(),
        &mallory.identity.recipient().to_string(),
    );
    assert!(JoinRequest::parse(swapped.as_bytes()).is_err(), "another recipient");
    let renamed = request.replace("principal bo@example.com", "principal admin@example.com");
    assert!(JoinRequest::parse(renamed.as_bytes()).is_err(), "another name");
    assert!(JoinRequest::new(&bo.key, &bo.identity, "two words").is_err());

    // The entry that adds a device carries its request whole.
    let ada = Device::new("ada");
    let group = Group::found(&ada, &[(&bo, Role::Writer)]);
    let first = Entry::parse(&group.relay.member_entry(1).unwrap().unwrap()).unwrap();
    assert!(
        first
            .ops()
            .iter()
            .any(|op| matches!(op, Op::Add { request, .. } if request.device() == bo.id()))
    );
}

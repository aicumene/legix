//! Who may publish bundles, and the keys of the group.

use legix_sign::{AllowedSigners, Trust, ssh_key::PublicKey};

use crate::{DeviceId, Error, GroupKey, NAMESPACE, Problem};

/// Who may publish bundles, and the keys of the group's epochs.
///
/// A membership log — the `legix-members` crate — provides both, with a new key whenever a member leaves. [`Fixed`] is
/// one key and one list of members that the application hands in.
pub trait Access {
    /// The epoch this device writes bundles and envelopes in, and its key. An error if this device may not publish.
    fn current(&self) -> Result<(u64, GroupKey), Error>;

    /// The key of `epoch`, if this device holds it.
    fn key(&self, epoch: u64) -> Option<GroupKey>;

    /// Whether bundle `seq` of `device`, signed with `key`, written in `epoch` at `time`, may be applied. Returns the
    /// principals of the device.
    fn may_publish(
        &self,
        device: &DeviceId,
        key: &PublicKey,
        seq: u64,
        epoch: u64,
        time: u64,
    ) -> Result<String, Problem>;
}

impl<A: Access + ?Sized> Access for &A {
    fn current(&self) -> Result<(u64, GroupKey), Error> {
        (**self).current()
    }

    fn key(&self, epoch: u64) -> Option<GroupKey> {
        (**self).key(epoch)
    }

    fn may_publish(
        &self,
        device: &DeviceId,
        key: &PublicKey,
        seq: u64,
        epoch: u64,
        time: u64,
    ) -> Result<String, Problem> {
        (**self).may_publish(device, key, seq, epoch, time)
    }
}

/// One group key, in epoch 1, and the members in an allowed-signers list: a key may publish when an entry allows it in
/// the namespace `legix-bundle` at the bundle's time.
#[derive(Clone, Debug)]
pub struct Fixed {
    group: GroupKey,
    members: AllowedSigners,
}

impl Fixed {
    /// Access with `group` as the key and `members` as the devices that may publish.
    pub fn new(group: GroupKey, members: AllowedSigners) -> Self {
        Fixed { group, members }
    }

    /// The members.
    pub fn members(&self) -> &AllowedSigners {
        &self.members
    }
}

impl Access for Fixed {
    fn current(&self) -> Result<(u64, GroupKey), Error> {
        Ok((1, self.group.clone()))
    }

    fn key(&self, epoch: u64) -> Option<GroupKey> {
        (epoch == 1).then(|| self.group.clone())
    }

    fn may_publish(
        &self,
        _device: &DeviceId,
        key: &PublicKey,
        _seq: u64,
        epoch: u64,
        time: u64,
    ) -> Result<String, Problem> {
        if epoch != 1 {
            return Err(Problem::WrongEpoch(epoch));
        }
        let time = i64::try_from(time).map_err(|_| Problem::Format("the time is too large"))?;
        match self.members.trust_in(NAMESPACE, key, Some(time)) {
            Trust::Allowed { principals } => Ok(principals),
            other => Err(Problem::Untrusted(other)),
        }
    }
}

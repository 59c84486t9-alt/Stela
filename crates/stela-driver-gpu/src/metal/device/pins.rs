//! Which unfinished command buffers may still read what is released.
//!
//! A command buffer reads what its own connection held when it was
//! committed: handles resolve at commit, and the resources a Mac's kernel
//! keeps for a command buffer (those its encoders bound or used) exist by
//! then. An object a connection releases at serial `r` that it made at
//! serial `c` is therefore read only by that connection's command buffers
//! committed as `c + 1..=r`. A shared object is read by every connection
//! that ever held a handle to it, and the device's CPU-copy uploads ride
//! any connection's commit, so a carried texture adds the carrier's
//! connection. What the device shares among connections itself, and what
//! it frees on its own, keeps the device-wide [`Scope::DEVICE`]: every
//! command buffer committed through `r`.
use alloc::{sync::Arc, vec::Vec};

/// The connections whose command buffers may read a released object.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Reach {
    /// Any connection's.
    #[default]
    All,
    One(u64),
    /// Several, in no order and without repeats.
    Many(Arc<[u64]>),
}

impl Reach {
    pub fn covers(&self, key: u64) -> bool {
        match self {
            Self::All => true,
            Self::One(one) => *one == key,
            Self::Many(keys) => keys.contains(&key),
        }
    }

    /// The connections `self` names and `key`.
    pub fn with(&self, key: u64) -> Self {
        match self {
            _ if self.covers(key) => self.clone(),
            Self::All => Self::All,
            Self::One(one) => Self::Many([*one, key].into()),
            Self::Many(keys) => {
                let mut keys: Vec<u64> = keys.to_vec();
                keys.push(key);
                Self::Many(keys.into())
            }
        }
    }

    /// The connections either names.
    pub fn union(&self, other: &Self) -> Self {
        match other {
            Self::All => Self::All,
            Self::One(key) => self.with(*key),
            Self::Many(keys) => keys
                .iter()
                .fold(self.clone(), |reach, &key| reach.with(key)),
        }
    }
}

/// Who may read what a release frees: command buffers of `reach` committed
/// after serial `created`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scope {
    pub created: u64,
    pub reach: Reach,
}

impl Default for Scope {
    fn default() -> Self {
        Self::DEVICE
    }
}

impl Scope {
    /// Every command buffer: what the device frees on its own or shares
    /// among connections.
    pub const DEVICE: Self = Self {
        created: 0,
        reach: Reach::All,
    };

    /// Connection `key`'s command buffers committed after `created`.
    pub fn connection(key: u64, created: u64) -> Self {
        Self {
            created,
            reach: Reach::One(key),
        }
    }

    /// Readers of either.
    pub fn union(&self, other: &Self) -> Self {
        Self {
            created: self.created.min(other.created),
            reach: self.reach.union(&other.reach),
        }
    }
}

/// A release at the newest submitted `serial`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Release {
    pub serial: u64,
    pub scope: Scope,
}

impl Release {
    /// A device-wide release: freed once every command buffer through
    /// `serial` is done.
    pub fn device(serial: u64) -> Self {
        Self {
            serial,
            scope: Scope::DEVICE,
        }
    }

    /// Whether connection `key`'s command buffer committed as `serial` may
    /// read what this release frees.
    pub fn read_by(&self, key: u64, serial: u64) -> bool {
        serial > self.scope.created && serial <= self.serial && self.scope.reach.covers(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connection_release_is_read_by_its_own_work_since_the_object_was_made() {
        let release = Release {
            serial: 10,
            scope: Scope::connection(2, 4),
        };
        assert!(release.read_by(2, 5) && release.read_by(2, 10));
        assert!(
            !release.read_by(2, 4),
            "committed before the object existed"
        );
        assert!(!release.read_by(2, 11), "committed after the release");
        assert!(!release.read_by(1, 7), "another connection's");
        let device = Release::device(10);
        assert!(device.read_by(1, 1) && device.read_by(7, 10) && !device.read_by(1, 11));
    }

    #[test]
    fn reaches_join_without_repeats() {
        let reach = Reach::One(1)
            .with(2)
            .with(1)
            .union(&Reach::Many([3, 2].into()));
        assert_eq!(reach, Reach::Many([1, 2, 3].into()));
        assert_eq!(Reach::One(4).union(&Reach::All), Reach::All);
        let scope = Scope::connection(1, 9).union(&Scope::connection(2, 3));
        assert_eq!(scope.created, 3);
        assert!(scope.reach.covers(1) && scope.reach.covers(2) && !scope.reach.covers(3));
    }
}

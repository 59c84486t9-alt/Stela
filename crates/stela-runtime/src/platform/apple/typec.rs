//! Shared digital Type-C cable state, independent of HPM, PHY and USB drivers.
//!
//! The J473AP ADT links `hpm0`, `atc-phy0` and `usb-drd0` through dock
//! phandle 0xff; `port-number` identifies the connector. A connection belongs
//! to that connector, never to one controller's independent status constant.
//! The native bus peer supplies physical cable transitions. HPM observes the
//! same snapshots as DWC3; PHY readiness is a separate prerequisite for USB
//! signaling and cannot invent attachment. No SuperSpeed/DP/USB4 link is
//! supported by this initial USB2 profile.
use alloc::rc::Rc;
use core::cell::Cell;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Orientation {
    Normal,
    Flipped,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataRole {
    Ufp,
    Dfp,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Usb2Speed {
    Low,
    Full,
    High,
}

/// Electrical attachment supplied by the external peer. `source` describes
/// this port's power role independently of its USB data role (USB PD permits
/// the roles to differ). VBUS need not be present immediately upon attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attached {
    pub orientation: Orientation,
    pub role: DataRole,
    pub source: bool,
    pub vbus: bool,
    pub speed: Usb2Speed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub generation: u64,
    pub connection: Option<Attached>,
}

/// Clones reference one authoritative connection generation. A snapshot is a
/// copy for one bounded controller operation; keep its generation with queued
/// USB work and cancel that work if the current generation differs. Detach,
/// reattach, orientation, role, VBUS and speed changes each advance generation;
/// observing or repeating a state does not. No generation is ever reused.
#[derive(Debug, Clone)]
pub struct Port(Rc<Cell<State>>);
#[derive(Debug, Clone, Copy)]
struct State {
    snapshot: Snapshot,
    changed: [u64; 4],
}
impl Default for Port {
    fn default() -> Self {
        Self::new()
    }
}
impl Port {
    pub fn new() -> Self {
        Self(Rc::new(Cell::new(State {
            snapshot: Snapshot {
                generation: 0,
                connection: None,
            },
            changed: [0; 4],
        })))
    }
    pub fn snapshot(&self) -> Snapshot {
        self.0.get().snapshot
    }
    /// Attachment, status, power and data changes since one observer's last
    /// generation. Per-category stamps keep intervening cable bounce even
    /// when the electrical state returns to its previous value.
    pub(crate) fn changes_since(&self, generation: u64) -> [bool; 4] {
        self.0.get().changed.map(|at| at > generation)
    }
    pub fn set_connection(&self, connection: Option<Attached>) -> Result<Snapshot, &'static str> {
        let previous = self.snapshot();
        if previous.connection == connection {
            return Ok(previous);
        }
        let generation = previous
            .generation
            .checked_add(1)
            .ok_or("Type-C connection generation exhausted")?;
        let next = Snapshot {
            generation,
            connection,
        };
        let mut state = self.0.get();
        let before = previous.connection;
        let after = next.connection;
        let plug = before.is_some() != after.is_some();
        let status = plug
            || before.map(|c| (c.orientation, c.role, c.source, c.vbus))
                != after.map(|c| (c.orientation, c.role, c.source, c.vbus));
        let power = plug || before.map(|c| (c.source, c.vbus)) != after.map(|c| (c.source, c.vbus));
        let data = plug
            || before.map(|c| (c.orientation, c.role, c.speed))
                != after.map(|c| (c.orientation, c.role, c.speed));
        for (stamp, changed) in state.changed.iter_mut().zip([plug, status, power, data]) {
            if changed {
                *stamp = generation;
            }
        }
        state.snapshot = next;
        self.0.set(state);
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn host() -> Attached {
        Attached {
            orientation: Orientation::Normal,
            role: DataRole::Ufp,
            source: false,
            vbus: true,
            speed: Usb2Speed::High,
        }
    }
    #[test]
    fn all_observers_share_attach_detach_bounce_and_role_generations() {
        let hpm = Port::new();
        let controller = hpm.clone();
        assert_eq!(controller.snapshot().connection, None);
        assert_eq!(hpm.set_connection(Some(host())).unwrap().generation, 1);
        assert_eq!(controller.snapshot(), hpm.snapshot());
        assert_eq!(hpm.set_connection(Some(host())).unwrap().generation, 1);
        assert_eq!(controller.set_connection(None).unwrap().generation, 2);
        assert_eq!(hpm.set_connection(Some(host())).unwrap().generation, 3);
        let flipped = Attached {
            orientation: Orientation::Flipped,
            ..host()
        };
        assert_eq!(hpm.set_connection(Some(flipped)).unwrap().generation, 4);
        let dfp = Attached {
            role: DataRole::Dfp,
            source: true,
            ..flipped
        };
        assert_eq!(hpm.set_connection(Some(dfp)).unwrap().generation, 5);
        let no_vbus = Attached { vbus: false, ..dfp };
        assert_eq!(hpm.set_connection(Some(no_vbus)).unwrap().generation, 6);
        let full = Attached {
            speed: Usb2Speed::Full,
            ..no_vbus
        };
        assert_eq!(controller.set_connection(Some(full)).unwrap().generation, 7);
    }
    #[test]
    fn overflow_refuses_without_reusing_a_generation() {
        let port = Port::new();
        port.0.set(State {
            snapshot: Snapshot {
                generation: u64::MAX,
                connection: None,
            },
            changed: [0; 4],
        });
        assert!(port.set_connection(Some(host())).is_err());
        assert_eq!(
            port.snapshot(),
            Snapshot {
                generation: u64::MAX,
                connection: None
            }
        );
    }
}

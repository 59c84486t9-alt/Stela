//! Source-native auxiliary control tail and its state transitions.
//!
//! Original26A434 T8112 PMP SHA256
//! b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//!101b464..101b8fc,101bb08..101c05c. This module does not execute firmware.
//! Local reads use kept Frames. Shared bank2 reads and concrete
//! controller/control-loop calls require their owners, never defaults.
//! Evidence: .stela/goal-20261023/memory/control-tail-r1.
pub mod controller;
mod model;
mod owner;
mod packed;

use super::super::owner::Completion;
use super::{Pair, Request};
use crate::ptd::transport::notifications::LocalNotifications;
use alloc::rc::Rc;
pub use model::{Configuration, SlotImage, SoftwareImage};
pub use owner::{AuxiliaryBinding, Owner};
use stela_contracts::bus::Access;

/// Identity of the resource composition; no completion rights.
#[derive(Clone)]
pub struct Identity(Rc<()>);
impl Default for Identity {
    fn default() -> Self {
        Self::new()
    }
}
impl Identity {
    pub fn new() -> Self {
        Self(Rc::new(()))
    }
    pub(super) fn same(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

/// Exact virtual slots, rather than guessed register or power-state aliases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlagsMethod {
    Store58,
    Enable60,
    Disable68,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// Actual101cff0 callback/context registration. Backend binds the same
    /// Owner's AuxiliaryBinding; retirement means registry storage.
    RegisterAuxiliary {
        slot: usize,
        source: u32,
    },
    Flags70 {
        provider: u32,
        member: u32,
    },
    Flags {
        provider: u32,
        member: u32,
        method: FlagsMethod,
        value: u16,
    },
    Member28 {
        provider: u32,
        member: u32,
    },
    /// Source provider object+8 -> mapping+18 -> word+400.
    Packed400 {
        provider: u32,
    },
    /// Must reuse the same101ba6c bank2 cache as all other native providers.
    ExtendedFrame {
        bank: u32,
        index: u32,
    },
    /// Source P178+10 object's slots20/28 tail-call the global native RTKit
    /// IRQ owner1079f00+28 with this source IRQ and enable1/0. This is neither
    /// a PTD entry nor an AP AIC number or PMGR domain; root owns that recipient.
    Signal {
        source: u32,
        enable: bool,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceValue {
    Word(u32),
    Pair(Pair),
    Complete,
}

/// Inner operation identity. Repeated calls after Busy refer to this same
/// operation and preserve the provider's consuming/write prefix.
#[derive(Clone)]
pub struct ResourceRequest {
    identity: Identity,
    sequence: u64,
    step: u64,
}
impl ResourceRequest {
    pub fn same_operation(&self, other: &Self) -> bool {
        self.identity.same(&other.identity)
            && self.sequence == other.sequence
            && self.step == other.step
    }
}
/// Required real owners. Refused means no retirement; Retired-with-refusal
/// supplies the real result and keeps the completed prefix. No absent resource
/// has a successful implementation. Controller slots cannot use a copied word
/// image instead of the mapped source provider. Shared ExtendedFrame
/// must keep its existing consuming-read cache and manager-cycle binding.
pub trait Resources {
    fn identity(&self) -> &Identity;
    fn notifications(&self) -> &LocalNotifications;
    fn call(
        &mut self,
        request: &ResourceRequest,
        operation: Operation,
        access: &mut Access<'_>,
    ) -> Completion<ResourceValue>;
}

/// Identity of one source caller, not an invented lifecycle/ACK receipt.
#[derive(Clone)]
pub(super) enum Caller {
    Tail(Request),
    Transition(super::super::owner::Request, u64),
}
impl Caller {
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Tail(a), Self::Tail(b)) => a.same_operation(b),
            (Self::Transition(a, x), Self::Transition(b, y)) => x == y && a.same_operation(b),
            _ => false,
        }
    }
}

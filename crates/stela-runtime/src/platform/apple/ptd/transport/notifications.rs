//! PMP-local PTD source levels on the publication owner. Original
//! t6000pmp table 0x81300 and IRQ wrappers 0x12618..0x12660 register route r
//! through RTKit-local IRQ 1+r, encoded in namespace 0x10000. These are not AP
//! AIC numbers or ASC messages. See docs/research/apple-mcc.md.
use super::{NotificationOwner, Ptd, ROUTES, Range};
use alloc::rc::Rc;
use stela_contracts::bus::LifecycleState;
use stela_soc_data::ptd::Geometry;

/// Original native descriptor geometry, independently cross-checked by the
/// source DeviceTree's 0xc00-byte update alias.
const LOCAL_ENTRIES: u32 = 384;
const RTKIT_LOCAL_NAMESPACE: u32 = 0x10000;
const FIRST_LOCAL_IRQ: u32 = 1;

/// Native implemented entries, independently of the addressable update alias.
/// T6000 file0x57780 declares 384/16; T8112 file0x355f8 declares 256/16.
/// Both original test objects register route r on RTKit-local IRQ 1+r.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeProfile {
    T6000,
    T8112,
}
impl NativeProfile {
    pub fn entries(self) -> u32 {
        match self {
            Self::T6000 => LOCAL_ENTRIES,
            Self::T8112 => 256,
        }
    }
}

/// A PTD output in the original PMP-local interrupt namespace. A number alone
/// grants no permission to clear a pending publication or report service ACKs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalIrq(u8);

impl LocalIrq {
    pub fn from_route(route: u8) -> Option<Self> {
        (usize::from(route) < ROUTES).then_some(Self(route))
    }

    pub fn route(self) -> u8 {
        self.0
    }

    pub fn rtkit_number(self) -> u32 {
        RTKIT_LOCAL_NAMESPACE | (FIRST_LOCAL_IRQ + u32::from(self.0))
    }
}

/// The source levels lent to a native PMP owner from this exact PTD object.
/// There is no copied line bank, event-erasing pop, callback execution, RTKit
/// enable mask or acknowledgement here. Pending entries/control on the same
/// publication bank determine these levels. RTKit callback registration and
/// native service effects remain the recipient's obligations.
#[derive(Clone)]
pub struct LocalNotifications(Ptd);

impl LocalNotifications {
    /// Admit exactly one native recipient before any publication. Aliases keep
    /// this admission for the bank's whole lifetime, including after an
    /// abandoned recipient. Dropping a native owner is not a checked reset.
    pub(crate) fn claim_pmp_recipient(&self) -> Result<(), &'static str> {
        let mut state = self.0.0.borrow_mut();
        if state.pmp_recipient_admitted {
            return Err("PTD actual bank already admitted its native PMP recipient");
        }
        if state.serial != 0 {
            return Err("native PMP recipient must precede actual PTD publication admission");
        }
        state.pmp_recipient_admitted = true;
        Ok(())
    }

    /// Check backing identity, including after cloning an alias. Equal
    /// numeric ranges on a different object do not satisfy this check.
    pub fn owns(&self, bank: &Ptd) -> bool {
        Rc::ptr_eq(&self.0.0, &bank.0)
    }

    /// The bank whose source levels this recipient observes.
    pub fn bank(&self) -> &Ptd {
        &self.0
    }

    /// Raw level bitmap before recipient RTKit masking or callback dispatch.
    /// Pauses keep existing source levels; this does not authorize
    /// running a paused recipient or invent a completed callback.
    pub fn asserted(&self) -> u16 {
        self.0
            .0
            .borrow()
            .asserted
            .iter()
            .enumerate()
            .fold(0, |bits, (route, &level)| {
                bits | (u16::from(level) << route)
            })
    }

    pub fn level(&self, irq: LocalIrq) -> bool {
        self.0.0.borrow().asserted[usize::from(irq.0)]
    }
}

impl Ptd {
    /// Admit the caller's source-checked native profile on the bank.
    /// An alias can address more update positions than this controller implements;
    /// that larger extent never creates additional entries or local sources.
    pub fn initialized_local_profile(
        profile: NativeProfile,
        geometry: Geometry,
        ranges: &[Range],
        lifecycle: LifecycleState,
    ) -> Result<(Self, LocalNotifications), &'static str> {
        let entries = profile.entries();
        if entries as usize > geometry.entries() {
            return Err("native PTD implemented entries exceed its physical update alias");
        }
        Self::new_local(entries, ranges, lifecycle)
    }

    /// Allocate the checked native geometry and its PMP-local output
    /// owner together, before admitting any source/client. This is explicit
    /// Stela initialization, not kept Apple reset or RTOS-ready state.
    /// Every entry is unpublished, interrupts disabled, and local levels low.
    pub fn initialized_local(
        entries: u32,
        ranges: &[Range],
        lifecycle: LifecycleState,
    ) -> Result<(Self, LocalNotifications), &'static str> {
        if entries != LOCAL_ENTRIES {
            return Err("PMP-local PTD notification geometry is not qualified");
        }
        Self::new_local(entries, ranges, lifecycle)
    }

    fn new_local(
        entries: u32,
        ranges: &[Range],
        lifecycle: LifecycleState,
    ) -> Result<(Self, LocalNotifications), &'static str> {
        let bank = Self::initialized(entries, ranges, lifecycle, [None; ROUTES])?;
        bank.0.borrow_mut().notification_owner = NotificationOwner::PmpLocal;
        let notifications = LocalNotifications(bank.clone());
        Ok((bank, notifications))
    }
}

#[cfg(test)]
mod tests;

//! ASCv4's separate IORVBAR aperture, owned by its ASC, not by RTKit.
//!
//! Original 26A434 mac13j AppleASCWrapV4::initialize maps provider reg[1]
//! (VA 0xfffffe0008bc8274), then reads/writes a doubleword at offset zero
//! (_setIORVBAR 8bc82ec, _isIORVBARLocked 8bc8308). J314s mBoot-20457.1.29
//! file 0x6750 checks lock bit 0 before programming, writes entry|1, and
//! verifies readback address mask 0x3fffffff800 and lock. Its DCPEXT0 record
//! at 0x1fbf60 selects core 0x289800000 + 0x50000, matching ADT reg[1].
//!
//! These consumers do not establish a reset value, unlock operation, physical
//! lock-write behavior, or any current boot's ARM firmware entry. Initial
//! state is unknown. A machine boot owner may explicitly initialize modeled
//! state from an owned firmware resource and captured/established register
//! word. Geometry checks here cannot authenticate or materialize that resource.
//! All writes to a locked register refuse; no ignored hardware write is
//! invented. Destructive lifecycle changes invalidate knowledge rather than
//! fabricating a reset value. Native protocol firmware alone supplies no word.
use super::super::bus::{Access, Direction, LifecycleState, MmioDevice, MmioError, Width, refuse};
use alloc::rc::Rc;
use core::cell::RefCell;

const NAME: &str = "asc-iorvbar";
const LOCK: u64 = 1;
const ADDRESS: u64 = 0x3ff_ffff_f800;

/// Which boot owner established the initial word. A native boot-resource
/// initialization is an emulated-machine choice, not an Apple observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    PhysicalCapture,
    NativeBootResource,
}

/// An explicit boot-resource authorization, separate from native RTKit state.
/// The register word is supplied by its owner, never inferred from `running`.
#[derive(Debug, Clone, Copy)]
pub struct EntryHandoff {
    entry: u64,
    word: u64,
    origin: Origin,
}

impl EntryHandoff {
    /// Authorize an entry in an actually owned firmware backing region.
    /// `word` is an independently established/captured register value. Its
    /// opaque bits are retained on reads. Supplying addresses alone does not
    /// establish the image's bytes, identity, mapping, or initial lock state.
    pub fn from_backing(
        entry: u64,
        base: u64,
        bytes: u64,
        word: u64,
        origin: Origin,
    ) -> Result<Self, &'static str> {
        let end = base
            .checked_add(bytes)
            .ok_or("ASC firmware backing range overflows")?;
        let instruction_end = entry.checked_add(4).ok_or("ASC firmware entry overflows")?;
        if entry == 0 || entry & !ADDRESS != 0 {
            return Err("ASC firmware entry is outside the qualified aligned address field");
        }
        if entry < base || instruction_end > end {
            return Err("ASC firmware entry is outside its backing region");
        }
        if word & LOCK != 0 && word & ADDRESS != entry {
            return Err("ASC locked entry disagrees with the firmware backing");
        }
        if origin == Origin::NativeBootResource && word & !(ADDRESS | LOCK) != 0 {
            return Err("ASC native boot resource cannot establish opaque entry-register bits");
        }
        Ok(Self {
            entry,
            word,
            origin,
        })
    }

    pub const fn origin(self) -> Origin {
        self.origin
    }
}

struct State {
    handoff: Option<EntryHandoff>,
    entry_required: bool,
    running: bool,
    lifecycle: LifecycleState,
}

/// A second MMIO handle sharing one ASC owner's entry state and lifecycle.
#[derive(Clone)]
pub struct Auxiliary(Rc<RefCell<State>>);

impl Auxiliary {
    pub(super) fn unknown(running: bool) -> Self {
        Self(Rc::new(RefCell::new(State {
            handoff: None,
            entry_required: false,
            running,
            lifecycle: LifecycleState {
                powered: true,
                clocked: true,
                quiesced: false,
                reset: false,
                retention: false,
            },
        })))
    }

    pub(super) fn establish(&self, handoff: EntryHandoff) -> Result<(), &'static str> {
        let mut state = self.0.borrow_mut();
        if state.handoff.is_some() {
            return Err("ASC entry handoff is already established");
        }
        if state.running && handoff.word & LOCK == 0 {
            return Err("ASC running firmware has no established locked entry");
        }
        if state.lifecycle.reset || !state.lifecycle.powered || !state.lifecycle.clocked {
            return Err("ASC entry handoff while its owner is inaccessible");
        }
        state.handoff = Some(handoff);
        state.entry_required = true;
        Ok(())
    }

    pub(super) fn check_start(&self) -> Result<(), &'static str> {
        let state = self.0.borrow();
        // Existing native protocol constructors do not claim an ARM image.
        // Once an explicit image handoff exists, its entry must be locked.
        if state.entry_required && state.handoff.is_none_or(|h| h.word & LOCK == 0) {
            return Err("ASC firmware entry has not been programmed and locked");
        }
        Ok(())
    }

    pub(super) fn set_running(&self, running: bool) {
        self.0.borrow_mut().running = running;
    }

    pub(super) fn set_lifecycle(&self, proposed: LifecycleState) {
        let mut state = self.0.borrow_mut();
        if proposed.reset && !state.lifecycle.reset
            || !proposed.powered && state.lifecycle.powered && !proposed.retention
        {
            state.handoff = None;
            state.running = false;
        }
        state.lifecycle = proposed;
    }
}

impl State {
    fn accessible(&self) -> Result<(), &'static str> {
        if self.lifecycle.reset || !self.lifecycle.powered || !self.lifecycle.clocked {
            return Err("ASC auxiliary owner is reset, unpowered or unclocked");
        }
        Ok(())
    }
}

impl MmioDevice for Auxiliary {
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        let state = self.0.borrow();
        state.accessible().map_err(fail)?;
        if (offset, width) != (0, Width::Double) {
            return Err(fail(
                "ASC auxiliary register or access width is not qualified",
            ));
        }
        state
            .handoff
            .map(|h| h.word)
            .ok_or_else(|| fail("ASC firmware entry handoff is unknown"))
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        let mut state = self.0.borrow_mut();
        state.accessible().map_err(fail)?;
        if (offset, width) != (0, Width::Double) {
            return Err(fail(
                "ASC auxiliary register or access width is not qualified",
            ));
        }
        let handoff = state
            .handoff
            .ok_or_else(|| fail("ASC firmware entry handoff is unknown"))?;
        if handoff.word & LOCK != 0 {
            return Err(fail("ASC locked entry write effects are not qualified"));
        }
        if state.running {
            return Err(fail("ASC entry programming while firmware is running"));
        }
        if value != (handoff.entry | LOCK) {
            return Err(fail(
                "ASC entry write is not the authorized firmware entry and lock",
            ));
        }
        state.handoff = Some(EntryHandoff {
            word: value,
            ..handoff
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::asc::{Asc, Firmware, Lines, Message};
    use crate::platform::apple::bus::Lifecycle;
    use crate::platform::apple::interrupt::{AicInput, InterruptLatch};
    use alloc::{boxed::Box, vec::Vec};

    struct Peer;
    impl Firmware for Peer {
        fn start(&mut self, _: &mut Vec<Message>) -> Result<(), &'static str> {
            Ok(())
        }
        fn receive(&mut self, _: Message, _: &mut Vec<Message>) -> Result<(), &'static str> {
            Ok(())
        }
        fn check_reset(&self) -> Result<(), &'static str> {
            Ok(())
        }
        fn reset(&mut self) -> Result<(), &'static str> {
            Ok(())
        }
        fn stop(&mut self) -> Result<(), &'static str> {
            Ok(())
        }
        fn resume(&mut self, _: &mut Vec<Message>) -> Result<(), &'static str> {
            Ok(())
        }
    }
    const ENTRY: u64 = 0x8000_0000;

    fn handoff(word: u64) -> EntryHandoff {
        EntryHandoff::from_backing(ENTRY, ENTRY, 0x4000, word, Origin::NativeBootResource).unwrap()
    }
    fn owner(running: bool) -> Asc {
        Asc::new(
            Box::new(Peer),
            running,
            Lines::from_interrupts([1, 2, 3, 4].map(|irq| AicInput::new(0, irq))),
        )
        .unwrap()
    }

    #[test]
    fn native_running_protocol_has_no_invented_arm_entry() {
        let mut asc = owner(true);
        let mut aux = asc.auxiliary();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        assert!(aux.read(0, Width::Double, &mut access).is_err());
        assert!(
            aux.write(0, Width::Double, ENTRY | LOCK, &mut access)
                .is_err()
        );
        assert!(asc.establish_entry(handoff(0)).is_err());
        assert!(aux.read(0, Width::Double, &mut access).is_err());
        asc.establish_entry(handoff(ENTRY | LOCK)).unwrap();
        assert_eq!(
            aux.read(0, Width::Double, &mut access).unwrap(),
            ENTRY | LOCK
        );
        assert!(asc.establish_entry(handoff(ENTRY | LOCK)).is_err());
    }

    #[test]
    fn authorized_programming_precedes_start_and_locked_writes_refuse() {
        let mut asc = owner(false);
        asc.establish_entry(handoff(0)).unwrap();
        let mut aux = asc.auxiliary();
        let mut second = asc.auxiliary();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        assert!(asc.write(0x44, Width::Word, 0x10, &mut access).is_err());
        assert!(!asc.running);
        for value in [
            ENTRY,
            (ENTRY + 0x800) | LOCK,
            ENTRY | LOCK | 2,
            1 << 63 | ENTRY | LOCK,
        ] {
            assert!(aux.write(0, Width::Double, value, &mut access).is_err());
            assert_eq!(second.read(0, Width::Double, &mut access).unwrap(), 0);
        }
        for (offset, width) in [(8, Width::Double), (0, Width::Word)] {
            assert!(aux.write(offset, width, ENTRY | LOCK, &mut access).is_err());
            assert!(aux.read(offset, width, &mut access).is_err());
        }
        aux.write(0, Width::Double, ENTRY | LOCK, &mut access)
            .unwrap();
        assert_eq!(
            second.read(0, Width::Double, &mut access).unwrap(),
            ENTRY | LOCK
        );
        assert!(
            aux.write(0, Width::Double, ENTRY | LOCK, &mut access)
                .is_err()
        );
        asc.write(0x44, Width::Word, 0x10, &mut access).unwrap();
        assert!(asc.running);
    }

    #[test]
    fn one_owner_retains_or_invalidates_every_auxiliary_handle() {
        let mut asc = owner(true);
        // Capture may include opaque bits the consumers never decode.
        let opaque = 1 << 63;
        let captured = EntryHandoff::from_backing(
            ENTRY,
            ENTRY,
            0x4000,
            ENTRY | LOCK | opaque,
            Origin::PhysicalCapture,
        )
        .unwrap();
        assert_eq!(captured.origin(), Origin::PhysicalCapture);
        asc.establish_entry(captured).unwrap();
        let mut aux = asc.auxiliary();
        let active = asc.lifecycle;
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        asc.write(0x44, Width::Word, 0, &mut access).unwrap();
        assert_eq!(
            aux.read(0, Width::Double, &mut access).unwrap(),
            captured.word
        );
        let retained = LifecycleState {
            powered: false,
            clocked: false,
            retention: true,
            ..active
        };
        asc.check_lifecycle(retained).unwrap();
        asc.set_lifecycle(retained, &mut access);
        assert!(aux.read(0, Width::Double, &mut access).is_err());
        asc.set_lifecycle(active, &mut access);
        assert_eq!(
            aux.read(0, Width::Double, &mut access).unwrap(),
            captured.word
        );
        for destructive in [
            LifecycleState {
                reset: true,
                ..active
            },
            LifecycleState {
                powered: false,
                ..active
            },
        ] {
            asc.check_lifecycle(destructive).unwrap();
            asc.set_lifecycle(destructive, &mut access);
            asc.set_lifecycle(active, &mut access);
            assert!(aux.read(0, Width::Double, &mut access).is_err());
            assert!(
                aux.write(0, Width::Double, ENTRY | LOCK, &mut access)
                    .is_err()
            );
            assert!(asc.write(0x44, Width::Word, 0x10, &mut access).is_err());
            assert!(!asc.running);
            asc.establish_entry(captured).unwrap();
        }
    }

    #[test]
    fn resource_geometry_and_locked_identity_are_checked() {
        let origin = Origin::NativeBootResource;
        for (entry, base, bytes, word) in [
            (0, 0, 0x4000, 0),
            (ENTRY + 4, ENTRY, 0x4000, 0),
            (1 << 42, 1 << 42, 0x4000, 0),
            (ENTRY, ENTRY + 0x800, 0x4000, 0),
            (ENTRY, ENTRY, 3, 0),
            (ENTRY, ENTRY, u64::MAX, 0),
            (ENTRY, ENTRY, 0x4000, (ENTRY + 0x800) | LOCK),
            (ENTRY, ENTRY, 0x4000, ENTRY | LOCK | (1 << 63)),
        ] {
            assert!(EntryHandoff::from_backing(entry, base, bytes, word, origin).is_err());
        }
        assert_eq!(handoff(0).origin(), Origin::NativeBootResource);
    }
}

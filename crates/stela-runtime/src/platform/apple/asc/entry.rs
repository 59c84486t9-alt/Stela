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

/// One contiguous source/mapping interval, in three separate address domains.
/// Geometry describes a requirement; the actual firmware backend must still
/// prove current allocation/mapping ownership and perform the instruction fetch.
#[derive(Debug, Clone, Copy)]
pub struct EntryMapping {
    pub linked_base: u64,
    pub physical_base: u64,
    pub iop_base: u64,
    pub bytes: u64,
}

/// Actual result from a firmware backend's current owned instruction mapping.
/// Protocol-only peers must retain Firmware::fetch_entry's default refusal.
#[derive(Debug, Clone, Copy)]
pub struct EntryFetch {
    pub physical: u64,
    pub instruction: u32,
}

/// Required mapping, expected source instruction, and independently established
/// register word. Constructing this value does not authorize execution.
#[derive(Debug, Clone, Copy)]
pub struct EntryHandoff {
    mapping: EntryMapping,
    offset: u64,
    instruction: u32,
    entry: u64,
    word: u64,
    origin: Origin,
}

impl EntryHandoff {
    /// Describe a complete entry instruction in a linked image interval, its
    /// physical backing and its IOP mapping. Original iBoot154cf4 programs the
    /// TEXT remap/DVA. Zero is a valid IOP address when the actual backend owns
    /// and fetches that mapping; neither PC0 nor PA alone establishes it.
    ///
    /// `word` is separately established/captured. Geometry and source bytes do
    /// not establish initial lock state, vendor trust or an execution backend.
    pub fn from_mapping(
        mapping: EntryMapping,
        offset: u64,
        instruction: u32,
        word: u64,
        origin: Origin,
    ) -> Result<Self, &'static str> {
        for base in [mapping.linked_base, mapping.physical_base, mapping.iop_base] {
            base.checked_add(mapping.bytes)
                .ok_or("ASC firmware mapping range overflows")?;
        }
        if offset.checked_add(4).is_none_or(|end| end > mapping.bytes) {
            return Err("ASC complete entry instruction is outside its mapping");
        }
        let linked = mapping.linked_base + offset;
        let physical = mapping.physical_base + offset;
        let entry = mapping.iop_base + offset;
        if linked & 3 != 0 || physical & 3 != 0 || entry & !ADDRESS != 0 {
            return Err("ASC firmware entry is outside the qualified aligned address fields");
        }
        if word & LOCK != 0 && word & ADDRESS != entry {
            return Err("ASC locked entry disagrees with the IOP mapping");
        }
        if origin == Origin::NativeBootResource && word & !(ADDRESS | LOCK) != 0 {
            return Err("ASC native boot resource cannot establish opaque entry-register bits");
        }
        Ok(Self {
            mapping,
            offset,
            instruction,
            entry,
            word,
            origin,
        })
    }

    pub const fn origin(self) -> Origin {
        self.origin
    }
    pub const fn mapping(self) -> EntryMapping {
        self.mapping
    }
    pub const fn linked_entry(self) -> u64 {
        self.mapping.linked_base + self.offset
    }
    pub const fn physical_entry(self) -> u64 {
        self.mapping.physical_base + self.offset
    }
    pub const fn iop_entry(self) -> u64 {
        self.entry
    }
    pub const fn instruction(self) -> u32 {
        self.instruction
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

    pub(super) fn check_start(&self) -> Result<Option<EntryHandoff>, &'static str> {
        let state = self.0.borrow();
        // Existing native protocol constructors do not claim an ARM image.
        // Once an explicit image handoff exists, its entry must be locked.
        if state.entry_required && state.handoff.is_none_or(|h| h.word & LOCK == 0) {
            return Err("ASC firmware entry has not been programmed and locked");
        }
        Ok(state.handoff)
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
    use crate::platform::dma::{Memory, tests::Ram};
    use alloc::{boxed::Box, vec::Vec};

    struct FetchOwner {
        ram: Ram,
        mapping: Option<(u64, u64, u64)>,
        allocated: bool,
    }
    struct Peer(Rc<RefCell<FetchOwner>>);
    impl Firmware for Peer {
        fn fetch_entry(&mut self, iop: u64) -> Result<EntryFetch, &'static str> {
            let mut owner = self.0.borrow_mut();
            if !owner.allocated {
                return Err("test allocation owner released");
            }
            let (base, physical, bytes) = owner.mapping.ok_or("test IOP mapping is absent")?;
            let offset = iop.checked_sub(base).ok_or("test fetch precedes mapping")?;
            if offset.checked_add(4).is_none_or(|end| end > bytes) {
                return Err("test complete fetch exceeds mapping");
            }
            let physical = physical
                .checked_add(offset)
                .ok_or("test fetch physical overflow")?;
            let mut raw = [0; 4];
            if !owner.ram.read(physical, &mut raw) {
                return Err("test fetch is not owned RAM");
            }
            Ok(EntryFetch {
                physical,
                instruction: u32::from_le_bytes(raw),
            })
        }

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
    const ENTRY: u64 = 0x20_0000;
    const PHYSICAL: u64 = 0x8000_0000;
    const INSTRUCTION: u32 = 0x1400_0081;

    fn mapping(iop_base: u64) -> EntryMapping {
        EntryMapping {
            linked_base: 0,
            physical_base: PHYSICAL,
            iop_base,
            bytes: 0x4000,
        }
    }
    fn handoff(word: u64) -> EntryHandoff {
        EntryHandoff::from_mapping(
            mapping(ENTRY),
            0,
            INSTRUCTION,
            word,
            Origin::NativeBootResource,
        )
        .unwrap()
    }
    fn owner_with_mapping(running: bool, iop: u64) -> (Asc, Rc<RefCell<FetchOwner>>) {
        let mut ram = Ram::new(PHYSICAL, 0x4000);
        assert!(ram.write(PHYSICAL, &INSTRUCTION.to_le_bytes()));
        let owned = Rc::new(RefCell::new(FetchOwner {
            ram,
            mapping: Some((iop, PHYSICAL, 0x4000)),
            allocated: true,
        }));
        let asc = Asc::new(
            Box::new(Peer(owned.clone())),
            running,
            Lines::from_interrupts([1, 2, 3, 4].map(|irq| AicInput::new(0, irq))),
        )
        .unwrap();
        (asc, owned)
    }
    fn owner(running: bool) -> Asc {
        owner_with_mapping(running, ENTRY).0
    }

    #[test]
    fn running_requires_locked_and_fetched_entry() {
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
        let captured = EntryHandoff::from_mapping(
            mapping(ENTRY),
            0,
            INSTRUCTION,
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
        for (mapping, offset, word) in [
            (mapping(ENTRY + 4), 0, 0),
            (mapping(1 << 42), 0, 0),
            (mapping(ENTRY), 0x4000 - 3, 0),
            (
                EntryMapping {
                    bytes: 3,
                    ..mapping(ENTRY)
                },
                0,
                0,
            ),
            (
                EntryMapping {
                    physical_base: u64::MAX,
                    ..mapping(ENTRY)
                },
                0,
                0,
            ),
            (
                EntryMapping {
                    linked_base: u64::MAX,
                    ..mapping(ENTRY)
                },
                0,
                0,
            ),
            (mapping(ENTRY), 0, (ENTRY + 0x800) | LOCK),
            (mapping(ENTRY), 0, ENTRY | LOCK | (1 << 63)),
        ] {
            assert!(
                EntryHandoff::from_mapping(mapping, offset, INSTRUCTION, word, origin).is_err()
            );
        }
        let h = handoff(0);
        assert_eq!(h.origin(), origin);
        assert_eq!(
            (h.linked_entry(), h.physical_entry(), h.iop_entry()),
            (0, PHYSICAL, ENTRY)
        );
    }

    #[test]
    fn mapped_iop_zero_requires_current_allocation_mapping_and_actual_instruction() {
        let (mut asc, owned) = owner_with_mapping(false, 0);
        let h = EntryHandoff::from_mapping(
            mapping(0),
            0,
            INSTRUCTION,
            LOCK,
            Origin::NativeBootResource,
        )
        .unwrap();
        assert_eq!(
            (h.linked_entry(), h.physical_entry(), h.iop_entry()),
            (0, PHYSICAL, 0)
        );
        asc.establish_entry(h).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut aux = asc.auxiliary();
        assert_eq!(aux.read(0, Width::Double, &mut access).unwrap(), LOCK);
        owned.borrow_mut().mapping = None;
        assert!(asc.write(0x44, Width::Word, 0x10, &mut access).is_err());
        assert!(!asc.running);
        owned.borrow_mut().mapping = Some((0, PHYSICAL, 0x4000));
        owned.borrow_mut().allocated = false;
        assert!(asc.write(0x44, Width::Word, 0x10, &mut access).is_err());
        owned.borrow_mut().allocated = true;
        assert!(
            owned
                .borrow_mut()
                .ram
                .write(PHYSICAL, &0xd503201fu32.to_le_bytes())
        );
        assert!(asc.write(0x44, Width::Word, 0x10, &mut access).is_err());
        assert!(!asc.running);
        assert!(
            owned
                .borrow_mut()
                .ram
                .write(PHYSICAL, &INSTRUCTION.to_le_bytes())
        );
        asc.write(0x44, Width::Word, 0x10, &mut access).unwrap();
        assert!(asc.running);
        asc.write(0x44, Width::Word, 0, &mut access).unwrap();
        owned.borrow_mut().mapping = None;
        assert!(asc.write(0x44, Width::Word, 0x10, &mut access).is_err());
        assert!(!asc.running);
    }

    #[test]
    fn source_instruction_or_resolved_physical_mismatch_refuses_handoff() {
        let (mut asc, owned) = owner_with_mapping(false, ENTRY);
        let wrong = EntryHandoff::from_mapping(
            mapping(ENTRY),
            0,
            INSTRUCTION ^ 1,
            0,
            Origin::NativeBootResource,
        )
        .unwrap();
        assert!(asc.establish_entry(wrong).is_err());
        owned.borrow_mut().mapping = Some((ENTRY, PHYSICAL + 0x800, 0x3800));
        assert!(
            owned
                .borrow_mut()
                .ram
                .write(PHYSICAL + 0x800, &INSTRUCTION.to_le_bytes())
        );
        assert!(asc.establish_entry(handoff(0)).is_err());
        let mut aux = asc.auxiliary();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        assert!(aux.read(0, Width::Double, &mut access).is_err());
    }

    #[test]
    fn protocol_only_peer_cannot_claim_original_entry_ownership() {
        struct Protocol;
        impl Firmware for Protocol {
            fn start(&mut self, _: &mut Vec<Message>) -> Result<(), &'static str> {
                Ok(())
            }
            fn receive(&mut self, _: Message, _: &mut Vec<Message>) -> Result<(), &'static str> {
                Ok(())
            }
        }
        let mut asc = Asc::new(
            Box::new(Protocol),
            false,
            Lines::from_interrupts([1, 2, 3, 4].map(|irq| AicInput::new(0, irq))),
        )
        .unwrap();
        assert_eq!(
            asc.establish_entry(handoff(ENTRY | LOCK)),
            Err("original coprocessor instruction fetch ownership is not modeled")
        );
    }
}

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
//! inventing a reset value. Native protocol firmware alone supplies no word.
use alloc::rc::Rc;
use core::cell::RefCell;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction,
    stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::bus::Width, stela_contracts::bus::refuse,
};

const NAME: &str = "asc-iorvbar";
const LOCK: u64 = 1;
#[cfg(test)]
const ADDRESS: u64 = 0x3ff_ffff_f800;

/// Which boot owner established the initial word. A native boot-resource
/// initialization is an emulated-machine choice, not an Apple observation.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    PhysicalCapture,
    NativeBootResource,
}

/// One contiguous source/mapping interval, in three separate address domains.
/// Geometry describes a requirement; the firmware backend must still
/// prove current allocation/mapping ownership and perform the instruction fetch.
#[derive(Debug, Clone, Copy)]
pub struct EntryMapping {
    #[cfg(test)]
    pub linked_base: u64,
    pub physical_base: u64,
    #[cfg(test)]
    pub iop_base: u64,
    #[cfg(test)]
    pub bytes: u64,
}

/// Result from a firmware backend's current owned instruction mapping.
/// Protocol-only peers must keep Firmware::fetch_entry's default refusal.
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
    #[cfg(test)]
    origin: Origin,
}

impl EntryHandoff {
    /// Describe a complete entry instruction in a linked image interval, its
    /// physical backing and its IOP mapping. Original iBoot154cf4 programs the
    /// TEXT remap/DVA. Zero is a valid IOP address when the backend owns
    /// and fetches that mapping; neither PC0 nor PA alone establishes it.
    ///
    /// `word` is separately established/captured. Geometry and source bytes do
    /// not establish initial lock state, vendor trust or an execution backend.
    #[cfg(test)]
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
    #[cfg(test)]
    pub const fn origin(self) -> Origin {
        self.origin
    }
    #[cfg(test)]
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

    #[cfg(test)]
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
mod tests;

//! Source-bounded cache-as-RAM allocation, S3_3_C15_C7_0.
//!
//! Original J473 26A434 LLB (SHA256 d6c695d2…e75e77) source 0x29470..0x29528
//! reads the allocation count [5:0], unit exponent [13:8], maximum count
//! [21:16] and completion [63]. Its release at 0x2d860..0x2d878 clears the
//! count and waits for completion to clear. iBoot 082cf7b4…a3a3b source
//! 0x368a8/0x3c2a0 independently has the size and release consumers.
//!
//! These consumers do NOT disclose an original initial register value, the
//! unit/limit, physical sharing, or untouched memory contents. No chip
//! supplies defaults here. A register image and kept aperture owner
//! must agree before this component exists. No production backing is checked.
use stela_engine::memory::backing::BackingId;
use stela_engine::memory::backing::MappingId;

const COUNT: u64 = 0x3f;
const READY: u64 = 1 << 63;
const EXPONENT: u32 = 8;
const LIMIT: u32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    base: u64,
    unit_exponent: u8,
    maximum_units: u8,
    capacity: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CramError {
    Exponent,
    MaximumUnits,
    AddressOverflow,
    InitialGeometry,
    InitialCompletion,
    AllocationTooLarge,
    BackingChanged,
    UnknownFields(u64),
    ResizeUnqualified,
    GenerationExhausted,
    BackingContract,
}

impl Geometry {
    /// An explicit descriptor, never an inferred hardware observation. The
    /// backing registration separately proves the physical range and rights.
    pub fn new(base: u64, unit_exponent: u8, maximum_units: u8) -> Result<Self, CramError> {
        let unit = 1u64
            .checked_shl(u32::from(unit_exponent))
            .ok_or(CramError::Exponent)?;
        if maximum_units == 0 || u64::from(maximum_units) > COUNT {
            return Err(CramError::MaximumUnits);
        }
        let capacity = unit
            .checked_mul(u64::from(maximum_units))
            .ok_or(CramError::AddressOverflow)?;
        base.checked_add(capacity)
            .ok_or(CramError::AddressOverflow)?;
        Ok(Self {
            base,
            unit_exponent,
            maximum_units,
            capacity,
        })
    }
    pub fn base(self) -> u64 {
        self.base
    }
    pub fn capacity(self) -> u64 {
        self.capacity
    }
    pub fn unit_bytes(self) -> u64 {
        1 << self.unit_exponent
    }
    pub fn maximum_units(self) -> u8 {
        self.maximum_units
    }
    pub fn register_fields(self) -> u64 {
        u64::from(self.unit_exponent) << EXPONENT | u64::from(self.maximum_units) << LIMIT
    }
}

/// Read-only identity of a canonical backing and its current aperture
/// mapping. This metadata grants no completion permission and has no public
/// constructor. The kept backing capability, not this snapshot, owns RAM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackingState {
    pub(crate) backing: BackingId,
    pub(crate) mapping: Option<MappingId>,
    pub(crate) base: u64,
    pub(crate) capacity: u64,
    pub(crate) active_bytes: u64,
    pub(crate) generation: u64,
}

// Only the canonical RAM owner can implement these boundaries. In particular
// external device adapters cannot mint a receipt or complete from a bool.
pub(crate) mod sealed {
    pub trait Backing {}
    pub trait Prepared {}
}

/// Keeps the canonical aperture reservation/view. Initialization must
/// come from admitted allocation permission, separately from loaded file bytes.
/// No allocation, copy, second RAM layer or zero initialization is implied.
pub trait ApertureBacking: sealed::Backing {
    type Error;
    type Prepared<'a>: PreparedAperture
    where
        Self: 'a;
    /// Read the live backing/view identity and allocation generation,
    /// not a cached expected state or a claim derived from the written count.
    /// A retired/replaced view must no longer appear active.
    fn state(&self) -> BackingState;
    /// Check the complete old identity/generation and target extent before any
    /// mapping effect. The guard keeps exclusive ownership through
    /// commit, including all-worker quiescence and dispatch/map invalidation.
    /// Failure or dropping the guard must leave the mapping unchanged.
    fn prepare(
        &mut self,
        before: &BackingState,
        active_bytes: u64,
    ) -> Result<Self::Prepared<'_>, Self::Error>;
}

/// A prepared canonical-RAM mapping mutation, not a status ACK.
/// Commit must be infallible after preflight, activate/revoke the view,
/// preserve the backing identity/reservation and advance its generation once.
pub trait PreparedAperture: sealed::Prepared {
    fn commit(self) -> BackingState;
}

#[derive(Debug)]
pub struct Initialization<B> {
    pub error: CramError,
    /// Refusal returns the backing permission to its caller.
    pub backing: B,
}

#[derive(Debug)]
pub enum WriteError<E> {
    Register(CramError),
    Backing(E),
}

/// One explicitly supplied cache owner. Sharing it between PEs requires
/// separately checked physical ownership; MPIDR/core type is not a selector.
/// It has no Default, Clone, implicit initial state, reset or power-loss model.
#[derive(Debug)]
pub struct Cram<B> {
    geometry: Geometry,
    word: u64,
    state: BackingState,
    backing: B,
    poisoned: bool,
}

impl<B: ApertureBacking> Cram<B> {
    pub fn new(
        geometry: Geometry,
        initial_word: u64,
        backing: B,
    ) -> Result<Self, Initialization<B>> {
        let state = backing.state();
        let validate = || {
            if initial_word >> EXPONENT & COUNT != u64::from(geometry.unit_exponent)
                || initial_word >> LIMIT & COUNT != u64::from(geometry.maximum_units)
            {
                return Err(CramError::InitialGeometry);
            }
            let units = initial_word & COUNT;
            if units > u64::from(geometry.maximum_units) {
                return Err(CramError::AllocationTooLarge);
            }
            if (initial_word & READY != 0) != (units != 0) {
                return Err(CramError::InitialCompletion);
            }
            if state.base != geometry.base
                || state.capacity != geometry.capacity
                || state.active_bytes != units * geometry.unit_bytes()
                || state.mapping.is_some() != (units != 0)
            {
                return Err(CramError::BackingChanged);
            }
            Ok(())
        };
        if let Err(error) = validate() {
            return Err(Initialization { error, backing });
        }
        Ok(Self {
            geometry,
            word: initial_word,
            state,
            backing,
            poisoned: false,
        })
    }

    fn check(&self) -> Result<(), CramError> {
        if self.poisoned {
            return Err(CramError::BackingContract);
        }
        if self.backing.state() != self.state {
            return Err(CramError::BackingChanged);
        }
        Ok(())
    }

    /// Reads never allocate, clear memory, poll completion forward or set Ready.
    /// Opaque initial fields remain readable and immutable, not RAZ/WI.
    pub fn read(&self) -> Result<u64, CramError> {
        self.check()?;
        Ok(self.word)
    }

    pub fn geometry(&self) -> Geometry {
        self.geometry
    }
    pub fn backing(&self) -> &B {
        &self.backing
    }

    /// Source-checked preserved-field RMW: allocate from empty, or release
    /// fully. Other field changes and nonzero reconfiguration refuse before
    /// any backing effect. Ready follows commit, never the written bit.
    pub fn write(&mut self, value: u64) -> Result<(), WriteError<B::Error>> {
        self.check().map_err(WriteError::Register)?;
        let changed = (value ^ self.word) & !COUNT;
        if changed != 0 {
            return Err(WriteError::Register(CramError::UnknownFields(changed)));
        }
        let units = value & COUNT;
        if units > u64::from(self.geometry.maximum_units) {
            return Err(WriteError::Register(CramError::AllocationTooLarge));
        }
        if units != 0 && self.word & COUNT != 0 {
            return Err(WriteError::Register(CramError::ResizeUnqualified));
        }
        if units == 0 && self.word & COUNT == 0 {
            return Ok(());
        }
        let generation = self
            .state
            .generation
            .checked_add(1)
            .ok_or(WriteError::Register(CramError::GenerationExhausted))?;
        let active_bytes = units * self.geometry.unit_bytes();
        let prepared = self
            .backing
            .prepare(&self.state, active_bytes)
            .map_err(WriteError::Backing)?;
        let committed = prepared.commit();
        if committed.backing != self.state.backing
            || committed.base != self.state.base
            || committed.capacity != self.state.capacity
            || committed.active_bytes != active_bytes
            || committed.mapping.is_some() != (units != 0)
            || committed.generation != generation
            || self.backing.state() != committed
        {
            // Keep partial/broken-owner effects, report failure, and
            // never expose the old or invented Ready as a successful result.
            self.poisoned = true;
            return Err(WriteError::Register(CramError::BackingContract));
        }
        self.state = committed;
        self.word = self.word & !(COUNT | READY) | units | if units == 0 { 0 } else { READY };
        Ok(())
    }
}

#[cfg(test)]
mod tests;

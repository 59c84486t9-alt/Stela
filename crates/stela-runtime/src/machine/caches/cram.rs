//! Source-bounded cache-as-RAM allocation, S3_3_C15_C7_0.
//!
//! Original J473 26A434 LLB (SHA256 d6c695d2…e75e77) source 0x29470..0x29528
//! reads the allocation count [5:0], unit exponent [13:8], maximum count
//! [21:16] and completion [63]. Its release at 0x2d860..0x2d878 clears the
//! count and waits for completion to clear. iBoot 082cf7b4…a3a3b source
//! 0x368a8/0x3c2a0 independently has the size and release consumers.
//!
//! These consumers do NOT disclose an original initial register value, the
//! actual unit/limit, physical sharing, or untouched memory contents. No chip
//! supplies defaults here. A register image and actual retained aperture owner
//! must agree before this component exists. No production backing is qualified.
use crate::memory::backing::{BackingId, MappingId};

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

/// Read-only identity of an actual canonical backing and its current aperture
/// mapping. This metadata grants no completion authority and has no public
/// constructor. The retained backing capability, not this snapshot, owns RAM.
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

/// Retains the actual canonical aperture reservation/view. Initialization must
/// come from actual admitted allocation authority, separately from loaded file bytes.
/// No allocation, copy, second RAM layer or zero initialization is implied.
pub trait ApertureBacking: sealed::Backing {
    type Error;
    type Prepared<'a>: PreparedAperture
    where
        Self: 'a;
    /// Read the actual live backing/view identity and allocation generation,
    /// not a cached expected state or a claim derived from the written count.
    /// A retired/replaced view must no longer appear active.
    fn state(&self) -> BackingState;
    /// Check the complete old identity/generation and target extent before any
    /// mapping effect. The guard retains exclusive actual ownership through
    /// commit, including all-worker quiescence and dispatch/map invalidation.
    /// Failure or dropping the guard must leave the mapping unchanged.
    fn prepare(
        &mut self,
        before: &BackingState,
        active_bytes: u64,
    ) -> Result<Self::Prepared<'_>, Self::Error>;
}

/// An actual prepared canonical-RAM mapping mutation, not a status ACK.
/// Commit must be infallible after preflight, activate/revoke the actual view,
/// preserve the backing identity/reservation and advance its generation once.
pub trait PreparedAperture: sealed::Prepared {
    fn commit(self) -> BackingState;
}

#[derive(Debug)]
pub struct Initialization<B> {
    pub error: CramError,
    /// Refusal returns the actual backing authority to its caller.
    pub backing: B,
}

#[derive(Debug)]
pub enum WriteError<E> {
    Register(CramError),
    Backing(E),
}

/// One explicitly supplied cache owner. Sharing it between PEs requires
/// separately qualified physical ownership; MPIDR/core type is not a selector.
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

    /// Source-qualified preserved-field RMW: allocate from empty, or release
    /// fully. Other field changes and nonzero reconfiguration refuse before
    /// any backing effect. Ready follows actual commit, never the written bit.
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
            // Retain actual partial/broken-owner effects, report failure, and
            // never expose the old or fabricated Ready as a successful result.
            self.poisoned = true;
            return Err(WriteError::Register(CramError::BackingContract));
        }
        self.state = committed;
        self.word = self.word & !(COUNT | READY) | units | if units == 0 { 0 } else { READY };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{
        backing::{AccessKind, AccessPermissions, MemoryBacking, MemoryView},
        domain::{MappingAttributes, MemoryDomain, MemorySystem},
        source_ram::{
            OwnedRamExtent, PhysicalRamRange, SourceRamDeclaration, SourceRamPermissions,
            SourceRamSystemConfig, materialize_source_ram,
        },
    };
    use alloc::{sync::Arc, vec};
    use stela_compiler::TargetCpu;

    const RIGHTS: AccessPermissions = AccessPermissions {
        readable: true,
        writable: true,
        executable: false,
    };

    /// Test-only canonical backing/view owner. Bytes are explicit synthetic
    /// fixture input, not a claim about untouched CRAM or BootROM contents.
    struct Owned {
        backing: Arc<MemoryBacking>,
        geometry: Geometry,
        view: Option<Arc<MemoryView>>,
        domain: Option<Arc<MemoryDomain>>,
        system: Arc<MemorySystem>,
        generation: u64,
        commits: usize,
        fail: bool,
        bad_receipt: bool,
    }
    impl core::fmt::Debug for Owned {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Owned")
                .field("state", &self.state())
                .finish()
        }
    }
    const ATTRIBUTES: MappingAttributes = MappingAttributes {
        tagged: false,
        shareable: true,
    };
    impl Owned {
        fn new(geometry: Geometry, units: u8) -> Self {
            let ram = materialize_source_ram(
                SourceRamDeclaration {
                    address_space: 8,
                    target: TargetCpu::Baseline,
                    declared_capacity: vec![PhysicalRamRange {
                        source_pa: geometry.base(),
                        bytes: geometry.capacity(),
                    }],
                    initialized: vec![OwnedRamExtent {
                        source_pa: geometry.base(),
                        bytes: vec![0xa5; geometry.capacity() as usize],
                        permissions: SourceRamPermissions {
                            readable: true,
                            writable: true,
                            executable: false,
                        },
                    }],
                },
                SourceRamSystemConfig {
                    reservation_granule_bytes: 16,
                    reservation_stripe_count: 16,
                },
            )
            .unwrap();
            let original = ram.test_view(geometry.base()).unwrap();
            let backing = original.backing().clone();
            drop(ram);
            let system = MemorySystem::new(16, 16).unwrap();
            let original_domain = MemoryDomain::new(
                system.clone(),
                vec![(original.clone(), ATTRIBUTES)],
                TargetCpu::Baseline,
            )
            .unwrap();
            original_domain.retire(&original).unwrap();
            drop(original_domain);
            let view = (units != 0).then(|| {
                MemoryView::new(
                    backing.clone(),
                    geometry.base(),
                    0,
                    (u64::from(units) * geometry.unit_bytes()) as usize,
                    RIGHTS,
                )
                .unwrap()
            });
            let domain = view.as_ref().map(|view| {
                MemoryDomain::new(
                    system.clone(),
                    vec![(view.clone(), ATTRIBUTES)],
                    TargetCpu::Baseline,
                )
                .unwrap()
            });
            Self {
                backing,
                geometry,
                view,
                domain,
                system,
                generation: 37,
                commits: 0,
                fail: false,
                bad_receipt: false,
            }
        }
        fn read(&self, address: u64) -> Option<u8> {
            let access = self
                .view
                .as_ref()?
                .resolve(address, 1, AccessKind::Read)
                .ok()?;
            // No native execution or other writer exists in this test owner;
            // resolution retains the actual view/backing for the access.
            Some(unsafe { access.host_ptr().as_ptr().read() })
        }
        fn write(&mut self, address: u64, value: u8) {
            let access = self
                .view
                .as_ref()
                .unwrap()
                .resolve(address, 1, AccessKind::Write)
                .unwrap();
            // This test exclusively owns the backing and no access overlaps
            // mutation, remapping or retirement. No executable view exists.
            unsafe {
                access.host_ptr().as_ptr().write(value);
            }
        }
    }
    struct Prepared<'a> {
        owner: &'a mut Owned,
        view: Option<Arc<MemoryView>>,
        domain: Option<Arc<MemoryDomain>>,
    }
    impl sealed::Backing for Owned {}
    impl sealed::Prepared for Prepared<'_> {}
    impl ApertureBacking for Owned {
        type Error = &'static str;
        type Prepared<'a> = Prepared<'a>;
        fn state(&self) -> BackingState {
            BackingState {
                backing: self.backing.id(),
                mapping: self
                    .view
                    .as_ref()
                    .filter(|view| view.is_current())
                    .map(|view| view.id()),
                base: self.geometry.base(),
                capacity: self.geometry.capacity(),
                active_bytes: self
                    .view
                    .as_ref()
                    .filter(|view| view.is_current())
                    .map_or(0, |view| view.bytes() as u64),
                generation: self.generation,
            }
        }
        fn prepare(
            &mut self,
            before: &BackingState,
            active_bytes: u64,
        ) -> Result<Prepared<'_>, Self::Error> {
            if before != &self.state() {
                return Err("actual owner changed");
            }
            if self.fail {
                return Err("native mapping preflight refused");
            }
            let view = (active_bytes != 0).then(|| {
                MemoryView::new(
                    self.backing.clone(),
                    self.geometry.base(),
                    0,
                    active_bytes as usize,
                    RIGHTS,
                )
                .unwrap()
            });
            let domain = view.as_ref().map(|view| {
                MemoryDomain::new(
                    self.system.clone(),
                    vec![(view.clone(), ATTRIBUTES)],
                    TargetCpu::Baseline,
                )
                .unwrap()
            });
            Ok(Prepared {
                owner: self,
                view,
                domain,
            })
        }
    }
    impl PreparedAperture for Prepared<'_> {
        fn commit(self) -> BackingState {
            if let Some(old) = self.owner.view.take() {
                // This test retains no native/execution loans. The real
                // production guard must preflight all native/map owners.
                self.owner.domain.as_ref().unwrap().retire(&old).unwrap();
            }
            self.owner.view = self.view;
            self.owner.domain = self.domain;
            self.owner.generation += 1;
            self.owner.commits += 1;
            let mut actual = self.owner.state();
            if self.owner.bad_receipt {
                actual.active_bytes += 1;
            }
            actual
        }
    }
    fn geometry() -> Geometry {
        Geometry::new(0x1000_0000, 12, 4).unwrap()
    }
    fn component(units: u8) -> Cram<Owned> {
        let geometry = geometry();
        let word = geometry.register_fields()
            | u64::from(units)
            | if units == 0 { 0 } else { READY }
            | 1 << 47;
        Cram::new(geometry, word, Owned::new(geometry, units)).unwrap()
    }

    #[test]
    fn geometry_is_explicit_and_every_encoded_boundary_is_checked() {
        assert_eq!(Geometry::new(0, 64, 1), Err(CramError::Exponent));
        assert_eq!(Geometry::new(0, 12, 0), Err(CramError::MaximumUnits));
        assert_eq!(Geometry::new(0, 12, 64), Err(CramError::MaximumUnits));
        assert_eq!(Geometry::new(0, 63, 2), Err(CramError::AddressOverflow));
        assert_eq!(
            Geometry::new(u64::MAX, 0, 1),
            Err(CramError::AddressOverflow)
        );
        let geometry = Geometry::new(0, 63, 1).unwrap();
        assert_eq!(geometry.capacity(), 1 << 63);
        assert_eq!(geometry.register_fields(), 63 << 8 | 1 << 16);
    }

    #[test]
    fn initial_register_and_actual_aperture_must_agree_without_mutation() {
        let geometry = geometry();
        for (word, units, expected) in [
            (
                geometry.register_fields() ^ 1 << 8,
                0,
                CramError::InitialGeometry,
            ),
            (
                geometry.register_fields() | 5 | READY,
                4,
                CramError::AllocationTooLarge,
            ),
            (
                geometry.register_fields() | 1,
                1,
                CramError::InitialCompletion,
            ),
            (
                geometry.register_fields() | READY,
                0,
                CramError::InitialCompletion,
            ),
            (
                geometry.register_fields() | 1 | READY,
                0,
                CramError::BackingChanged,
            ),
        ] {
            let backing = Owned::new(geometry, units);
            let original = backing.state();
            let failed = Cram::new(geometry, word, backing).unwrap_err();
            assert_eq!(failed.error, expected);
            assert_eq!(failed.backing.state(), original);
            assert_eq!(failed.backing.commits, 0);
        }
        let component = component(2);
        assert_eq!(component.read().unwrap() & (COUNT | READY), 2 | READY);
        assert_eq!(component.backing().read(geometry.base()), Some(0xa5));
    }

    #[test]
    fn allocation_and_release_change_actual_view_before_ready_and_preserve_data() {
        let mut component = component(0);
        let base = component.geometry().base();
        let empty = component.read().unwrap();
        let before = component.backing().state();
        assert_eq!(component.backing().read(base), None);
        component.write(empty | 2).unwrap();
        assert_eq!(component.read().unwrap(), empty | 2 | READY);
        assert_eq!(
            component.backing().state().generation,
            before.generation + 1
        );
        assert_eq!(component.backing().state().backing, before.backing);
        assert_eq!(component.backing().read(base), Some(0xa5));
        assert_eq!(
            component
                .backing()
                .read(base + 2 * component.geometry().unit_bytes()),
            None
        );
        component.backing.write(base, 0x7e);
        assert_eq!(component.backing().read(base), Some(0x7e));
        let old = component.backing().view.as_ref().unwrap().clone();
        let allocated = component.read().unwrap();
        // The original release preserves the written Ready=1, but actual
        // committed revocation clears it. Writing Ready is not completion.
        component.write(allocated & !COUNT).unwrap();
        assert_eq!(component.read().unwrap(), empty);
        assert_eq!(component.backing().read(base), None);
        assert!(!old.is_current());
        assert!(old.resolve(base, 1, AccessKind::Read).is_err());
        assert_eq!(
            component.backing().state().generation,
            before.generation + 2
        );
        assert_eq!(component.backing().commits, 2);
    }

    #[test]
    fn reads_and_failed_or_abandoned_preflight_never_advance_completion() {
        let mut component = component(0);
        let word = component.read().unwrap();
        let before = component.backing().state();
        for _ in 0..100 {
            assert_eq!(component.read().unwrap(), word);
        }
        component.backing.fail = true;
        assert!(matches!(
            component.write(word | 1),
            Err(WriteError::Backing("native mapping preflight refused"))
        ));
        assert_eq!(component.read().unwrap(), word);
        assert_eq!(component.backing().state(), before);
        component.backing.fail = false;
        let guard = component
            .backing
            .prepare(&before, component.geometry.unit_bytes())
            .unwrap();
        drop(guard);
        assert_eq!(component.read().unwrap(), word);
        assert_eq!(component.backing().state(), before);
        assert_eq!(component.backing().commits, 0);
    }

    #[test]
    fn unknown_field_changes_and_unqualified_resize_refuse_atomically() {
        let mut component = component(0);
        let word = component.read().unwrap();
        for bit in [6, 7, 8, 13, 14, 16, 21, 22, 47, 63] {
            assert!(
                matches!(component.write(word ^ 1 << bit), Err(WriteError::Register(CramError::UnknownFields(mask))) if mask == 1 << bit)
            );
            assert_eq!(component.read().unwrap(), word);
            assert_eq!(component.backing().commits, 0);
        }
        assert!(matches!(
            component.write(word | 5),
            Err(WriteError::Register(CramError::AllocationTooLarge))
        ));
        component.write(word | 1).unwrap();
        let old = component.read().unwrap();
        let state = component.backing().state();
        for count in [1, 2, 4] {
            assert!(matches!(
                component.write(old & !COUNT | count),
                Err(WriteError::Register(CramError::ResizeUnqualified))
            ));
            assert_eq!(component.read().unwrap(), old);
            assert_eq!(component.backing().state(), state);
        }
        component.write(old & !COUNT).unwrap();
        let state = component.backing().state();
        component.write(component.read().unwrap()).unwrap();
        assert_eq!(component.backing().state(), state);
    }

    #[test]
    fn stale_backing_generation_identity_or_mapping_never_exposes_ready() {
        for tamper in 0..4 {
            let mut component = component(1);
            match tamper {
                0 => component.backing.generation += 1,
                1 => component.backing.backing = Owned::new(geometry(), 0).backing,
                2 => component.backing.view = None,
                _ => component
                    .backing
                    .domain
                    .as_ref()
                    .unwrap()
                    .retire(component.backing.view.as_ref().unwrap())
                    .unwrap(),
            }
            assert_eq!(component.read(), Err(CramError::BackingChanged));
            assert!(matches!(
                component.write(0),
                Err(WriteError::Register(CramError::BackingChanged))
            ));
            assert_eq!(component.backing().commits, 0);
        }
    }

    #[test]
    fn exhausted_or_invalid_completion_does_not_invent_progress_or_rollback_actual_effects() {
        let mut component = component(0);
        component.backing.generation = u64::MAX;
        component.state = component.backing.state();
        assert!(matches!(
            component.write(component.word | 1),
            Err(WriteError::Register(CramError::GenerationExhausted))
        ));
        assert_eq!(component.backing().commits, 0);
        let mut component = self::component(0);
        component.backing.bad_receipt = true;
        let old_word = component.word;
        assert!(matches!(
            component.write(old_word | 1),
            Err(WriteError::Register(CramError::BackingContract))
        ));
        assert_eq!(component.word, old_word);
        assert_eq!(component.backing().commits, 1);
        assert_eq!(
            component.backing().read(component.geometry().base()),
            Some(0xa5)
        );
        assert_eq!(component.read(), Err(CramError::BackingContract));
        assert!(matches!(
            component.write(old_word),
            Err(WriteError::Register(CramError::BackingContract))
        ));
    }

    #[cfg(all(feature = "std", target_os = "macos", target_arch = "x86_64"))]
    mod original {
        use super::*;
        use crate::{
            execution::platform::Mapping,
            hosted::host::NativeRunner,
            machine::{
                Chip, Cpu, CpuProfile, DeviceError, Devices, FaultCause, Host, InstallError, Lines,
                Machine, NativeCode, NativeExit, Regime, RequirementKind, Stop,
                exception::Pstate,
                registers::{Identity, encodings::MPIDR_EL1},
            },
        };
        use stela_compiler::{GuestState, aarch64::system::registers::Encoding};

        const BASE: u64 = 0x8_0000_0000;
        #[derive(Clone, Copy)]
        struct Input {
            environment: &'static str,
            sha256: &'static str,
            chip: Chip,
            midr: u64,
            allocation: u64,
            returned: u64,
            short: u64,
            release: u64,
            released: u64,
        }
        const J473: Input = Input {
            environment: "STELA_TEST_PMGR_LLB",
            sha256: "d6c695d26e5d816a2ecd523c0be20a15307af24c404b1603d74a970b53e75e77",
            chip: Chip::AppleM2,
            midr: 0x611f_0320,
            allocation: 0x29470,
            returned: BASE + 0x2952c,
            short: BASE + 0x294d4,
            release: 0x2d860,
            released: BASE + 0x2d878,
        };
        const J314S: Input = Input {
            environment: "STELA_TEST_CRAM_J314S_LLB",
            sha256: "f45549025d8cb4aa5e1cdb6107a25f90999f6b96da0b31a2f3cfb90561653ae1",
            chip: Chip::AppleM1,
            midr: 0x611f_0220,
            allocation: 0x282c0,
            returned: BASE + 0x2837c,
            short: BASE + 0x28324,
            release: 0x2c908,
            released: BASE + 0x2c920,
        };

        struct NativeHost {
            original: alloc::vec::Vec<u8>,
            entry: Option<std::rc::Rc<std::cell::RefCell<EntryRam>>>,
            regime: Option<Regime>,
            code: alloc::vec::Vec<(Mapping, usize)>,
            output_prefix: alloc::string::String,
            patches: usize,
            runner: NativeRunner,
        }
        impl Host for NativeHost {
            fn read_ram(&mut self, physical: u64, out: &mut [u8]) -> bool {
                if let Some(entry) = &self.entry {
                    return entry.borrow_mut().read(physical, out);
                }
                let Some(start) = physical
                    .checked_sub(BASE)
                    .and_then(|start| usize::try_from(start).ok())
                else {
                    return false;
                };
                let Some(end) = start.checked_add(out.len()) else {
                    return false;
                };
                let Some(bytes) = self.original.get(start..end) else {
                    return false;
                };
                out.copy_from_slice(bytes);
                true
            }
            fn write_ram(&mut self, physical: u64, bytes: &[u8]) -> bool {
                self.entry
                    .as_ref()
                    .is_some_and(|entry| entry.borrow_mut().write(physical, bytes))
            }
            fn install(&mut self, bytes: &[u8]) -> Result<NativeCode, InstallError> {
                let mapping = Mapping::new(bytes).unwrap();
                let address = mapping.entry();
                self.code.push((mapping, bytes.len()));
                if let Some(directory) = std::env::var_os("STELA_TEST_CRAM_OUTPUT") {
                    use std::io::Write;
                    let directory = std::path::PathBuf::from(directory);
                    std::fs::create_dir_all(&directory).unwrap();
                    let path = directory.join(alloc::format!(
                        "{}-block-{}.bin",
                        self.output_prefix,
                        self.code.len()
                    ));
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(path)
                        .unwrap()
                        .write_all(bytes)
                        .unwrap();
                }
                // Register-window fixtures reject data faults; full entry routes
                // them through the actual Machine regime and canonical backing.
                self.runner.set_ranges(
                    self.code
                        .iter()
                        .map(|(code, bytes)| {
                            (code.entry() as u64, code.entry() as u64 + *bytes as u64)
                        })
                        .collect(),
                );
                Ok(NativeCode(address))
            }
            fn patch(&mut self, code: NativeCode, bytes: &[u8]) {
                let (mapping, length) = self
                    .code
                    .iter()
                    .find(|(mapping, length)| {
                        code.0 >= mapping.entry()
                            && code
                                .0
                                .checked_add(bytes.len())
                                .is_some_and(|end| end <= mapping.entry() + length)
                    })
                    .expect("patch is inside an installed native image");
                let entry = mapping.entry();
                // Machine requests patches only outside native invocation.
                // This mapping owns the complete page-rounded OS extent; no
                // Rust byte reference or concurrent code execution exists.
                unsafe {
                    assert_eq!(
                        libc::mprotect(
                            entry as *mut _,
                            *length,
                            libc::PROT_READ | libc::PROT_WRITE
                        ),
                        0
                    );
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), code.0 as *mut u8, bytes.len());
                    assert_eq!(
                        libc::mprotect(entry as *mut _, *length, libc::PROT_READ | libc::PROT_EXEC),
                        0
                    );
                }
                self.patches += 1;
                if let Some(directory) = std::env::var_os("STELA_TEST_CRAM_OUTPUT") {
                    use std::io::Write;
                    let directory = std::path::PathBuf::from(directory);
                    let path = directory.join(alloc::format!(
                        "{}-patch-{}.bin",
                        self.output_prefix,
                        self.patches
                    ));
                    // This exact installed RX image remains owned and idle.
                    let image = unsafe { core::slice::from_raw_parts(entry as *const u8, *length) };
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(path)
                        .unwrap()
                        .write_all(image)
                        .unwrap();
                }
            }
            fn discard_code(&mut self) {
                self.code.clear();
            }
            unsafe fn execute(&mut self, code: NativeCode, state: &mut GuestState) -> NativeExit {
                // Machine installed this immutable mapping with its block ABI.
                match unsafe { self.runner.run(code.0, state) } {
                    Ok(exit) => NativeExit::Exit {
                        next_pc: exit.next_pc,
                        kind: exit.kind,
                    },
                    Err(fault) => {
                        let cause = if let Some(entry) = &self.entry
                            && fault.trap == 14
                        {
                            let regime = self
                                .regime
                                .as_ref()
                                .expect("Machine publishes actual regime");
                            match crate::machine::mmu::translate(
                                &regime.controls,
                                fault.address,
                                if fault.write {
                                    crate::machine::mmu::Access::Write
                                } else {
                                    crate::machine::mmu::Access::Read
                                },
                                regime.requester,
                                &mut EntryTables(entry.clone()),
                            ) {
                                crate::machine::mmu::Outcome::Mapped(mapping) => {
                                    FaultCause::Device {
                                        physical: mapping.physical,
                                    }
                                }
                                crate::machine::mmu::Outcome::Fault(fault) => {
                                    FaultCause::Guest(fault)
                                }
                                crate::machine::mmu::Outcome::Unsupported(reason) => {
                                    FaultCause::Translation(reason)
                                }
                            }
                        } else {
                            fault.check_cause().unwrap_or(FaultCause::InvalidOpcode)
                        };
                        NativeExit::Fault(
                            fault.native(fault.rip.wrapping_sub(code.0 as u64) as usize, cause),
                        )
                    }
                }
            }
            fn set_regime(&mut self, regime: &Regime) {
                self.regime = Some(*regime);
            }
            fn invalidate_translations(&mut self) {}
            fn counter(&mut self) -> u64 {
                0
            }
            fn arm_timer(&mut self, _: Option<u64>) {}
            fn wait_for_interrupt(&mut self) {
                panic!("bounded register fixture cannot wait");
            }
        }
        struct Bus<'a> {
            cram: &'a mut Cram<Owned>,
            reads: usize,
            writes: usize,
        }
        impl Devices for Bus<'_> {
            fn read(&mut self, _: usize, _: u64, _: u8, _: u64) -> Result<u64, DeviceError> {
                Err(DeviceError::Refused(
                    "source fixture has no peripheral input".into(),
                ))
            }
            fn write(
                &mut self,
                _: usize,
                _: u64,
                _: u8,
                _: u64,
                _: u64,
            ) -> Result<(), DeviceError> {
                Err(DeviceError::Refused(
                    "source fixture has no peripheral effect".into(),
                ))
            }
            fn lines(&mut self, _: usize, _: u64) -> Lines {
                Lines::default()
            }
            fn system_register(
                &mut self,
                _: usize,
                encoding: Encoding,
                write: Option<u64>,
                _: u64,
            ) -> Option<Result<u64, &'static str>> {
                if encoding != Encoding::new(3, 3, 15, 7, 0) {
                    return None;
                }
                Some(match write {
                    None => {
                        self.reads += 1;
                        self.cram
                            .read()
                            .map_err(|_| "actual CRAM owner refused read")
                    }
                    Some(value) => {
                        self.writes += 1;
                        self.cram
                            .write(value)
                            .map(|()| 0)
                            .map_err(|_| "actual CRAM owner refused write")
                    }
                })
            }
        }
        fn original(input: Input) -> alloc::vec::Vec<u8> {
            let bytes = std::fs::read(std::env::var(input.environment).expect("original LLB path"))
                .unwrap();
            assert_eq!(crate::sha256(&bytes), input.sha256);
            bytes
        }
        fn replay(
            input: Input,
            cram: &mut Cram<Owned>,
            aff2: u64,
            entry: u64,
            breaks: &[u64],
        ) -> (u64, usize, usize) {
            let host = NativeHost {
                original: original(input),
                entry: None,
                regime: None,
                code: alloc::vec::Vec::new(),
                output_prefix: alloc::format!(
                    "entry-{entry:x}-aff2-{aff2:x}-descriptor-{:x}",
                    cram.word
                ),
                patches: 0,
                runner: NativeRunner::new(alloc::vec::Vec::new()),
            };
            let mut cpu = Cpu::of(input.chip, BASE + entry, Pstate::reset(2));
            cpu.state.x[30] = input.returned;
            let profile = CpuProfile {
                name: "explicit synthetic CRAM descriptor, original consumer replay",
                chip: input.chip,
                counter_frequency: 24_000_000,
                fixed: vec![(MPIDR_EL1, 0x8000_0000 | aff2 << 16)],
                processors: vec![Identity {
                    midr: input.midr,
                    mpidr: 0x8000_0000 | aff2 << 16,
                    clock: None,
                    caches: None,
                }],
            };
            let mut machine = Machine::new(
                cpu,
                host,
                Bus {
                    cram,
                    reads: 0,
                    writes: 0,
                },
                profile,
                TargetCpu::Baseline,
            );
            machine.set_breakpoints(breaks);
            let stop = machine.run(128);
            assert!(
                matches!(stop, Stop::Breakpoint(_)),
                "unexpected original consumer stop: {stop:?}"
            );
            (
                machine.cpu.pc,
                machine.devices.reads,
                machine.devices.writes,
            )
        }

        fn allocation_and_release(input: Input) {
            for (aff2, expected) in [(0, 15), (1, 16)] {
                // Chosen test descriptor only, not an Apple reset value or
                // production physical aperture authority.
                let geometry = Geometry::new(0x1000_0000, 18, 16).unwrap();
                let mut cram = Cram::new(
                    geometry,
                    geometry.register_fields(),
                    Owned::new(geometry, 0),
                )
                .unwrap();
                assert_eq!(
                    replay(
                        input,
                        &mut cram,
                        aff2,
                        input.allocation,
                        &[input.returned, input.short]
                    ),
                    (input.returned, 2, 1)
                );
                assert_eq!(cram.read().unwrap() & (COUNT | READY), expected | READY);
                assert_eq!(
                    cram.backing().state().active_bytes,
                    expected * geometry.unit_bytes()
                );
                assert_eq!(cram.backing().commits, 1);
                let view = cram.backing().view.as_ref().unwrap().clone();
                assert_eq!(
                    replay(input, &mut cram, aff2, input.release, &[input.released]),
                    (input.released, 2, 1)
                );
                assert_eq!(cram.read().unwrap() & (COUNT | READY), 0);
                assert_eq!(cram.backing().commits, 2);
                assert!(!view.is_current());
            }
        }
        fn capacity_and_initial_completion(input: Input) {
            let geometry = Geometry::new(0x1000_0000, 18, 14).unwrap();
            let mut small = Cram::new(
                geometry,
                geometry.register_fields(),
                Owned::new(geometry, 0),
            )
            .unwrap();
            assert_eq!(
                replay(
                    input,
                    &mut small,
                    0,
                    input.allocation,
                    &[input.returned, input.short]
                ),
                (input.short, 1, 0)
            );
            assert_eq!(small.backing().commits, 0);
            let geometry = Geometry::new(0x1000_0000, 18, 16).unwrap();
            let mut complete = Cram::new(
                geometry,
                geometry.register_fields() | READY | 15,
                Owned::new(geometry, 15),
            )
            .unwrap();
            assert_eq!(
                replay(
                    input,
                    &mut complete,
                    0,
                    input.allocation,
                    &[input.returned, input.short]
                ),
                (input.returned, 1, 0)
            );
            assert_eq!(complete.backing().commits, 0);
        }

        const ENTRY_BASE: u64 = 0x1fc058000;
        const APERTURE: u64 = 0x1fc000000;
        const CAPACITY: usize = 0x3c0000;
        const GUARD_BYTES: usize = (0x400000000 - APERTURE) as usize;
        static ENTRY_EXECUTION: std::sync::Mutex<()> = std::sync::Mutex::new(());
        struct EntryGuard(*mut libc::c_void);
        impl EntryGuard {
            fn new() -> Self {
                // Reserve only; never replace host mappings or expose guest RAM
                // directly to native code. Actual accesses use the canonical view.
                let pointer = unsafe {
                    libc::mmap(
                        APERTURE as *mut _,
                        GUARD_BYTES,
                        libc::PROT_NONE,
                        libc::MAP_PRIVATE | libc::MAP_ANON,
                        -1,
                        0,
                    )
                };
                assert_ne!(pointer, libc::MAP_FAILED);
                if pointer as u64 != APERTURE {
                    unsafe {
                        libc::munmap(pointer, GUARD_BYTES);
                    }
                    panic!("guest aperture guard is occupied");
                }
                Self(pointer)
            }
        }
        impl Drop for EntryGuard {
            fn drop(&mut self) {
                unsafe {
                    libc::munmap(self.0, GUARD_BYTES);
                }
            }
        }
        struct EntryRam {
            cram: Cram<Owned>,
            known: Vec<bool>,
            source_reads: usize,
            committed: Vec<(u64, Vec<u8>)>,
            unknown: Vec<(u64, usize)>,
            registers: Vec<(Encoding, Option<u64>)>,
        }
        impl EntryRam {
            fn range(&self, address: u64, count: usize) -> Option<core::ops::Range<usize>> {
                let start = usize::try_from(address.checked_sub(APERTURE)?).ok()?;
                let end = start.checked_add(count)?;
                (end <= self.known.len()).then_some(start..end)
            }
            fn read(&mut self, address: u64, out: &mut [u8]) -> bool {
                let Some(range) = self.range(address, out.len()) else {
                    self.unknown.push((address, out.len()));
                    return false;
                };
                if !self.known[range].iter().all(|known| *known) {
                    self.unknown.push((address, out.len()));
                    return false;
                }
                let Some(view) = self.cram.backing().view.as_ref() else {
                    return false;
                };
                let Ok(access) = view.resolve(address, out.len(), AccessKind::Read) else {
                    return false;
                };
                // One thread owns this live canonical backing; native accesses
                // always fault and no remap/retirement overlaps this host copy.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        access.host_ptr().as_ptr(),
                        out.as_mut_ptr(),
                        out.len(),
                    );
                }
                self.source_reads += 1;
                true
            }
            fn write(&mut self, address: u64, bytes: &[u8]) -> bool {
                let Some(range) = self.range(address, bytes.len()) else {
                    return false;
                };
                let Some(view) = self.cram.backing().view.as_ref() else {
                    return false;
                };
                let Ok(access) = view.resolve(address, bytes.len(), AccessKind::Write) else {
                    return false;
                };
                // Same exclusive canonical route as source loading. No second
                // RAM image or successful byte initialization is substituted.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        access.host_ptr().as_ptr(),
                        bytes.len(),
                    );
                }
                self.known[range].fill(true);
                self.committed.push((address, bytes.to_vec()));
                true
            }
        }
        struct EntryTables(std::rc::Rc<std::cell::RefCell<EntryRam>>);
        impl crate::machine::mmu::TableMemory for EntryTables {
            fn read_descriptor(&mut self, address: u64) -> Option<u64> {
                let mut bytes = [0; 8];
                self.0
                    .borrow_mut()
                    .read(address, &mut bytes)
                    .then(|| u64::from_le_bytes(bytes))
            }
            fn update_descriptor(&mut self, address: u64, old: u64, new: u64) -> Option<bool> {
                if self.read_descriptor(address)? != old {
                    return Some(false);
                }
                self.0
                    .borrow_mut()
                    .write(address, &new.to_le_bytes())
                    .then_some(true)
            }
        }
        struct EntryBus(std::rc::Rc<std::cell::RefCell<EntryRam>>);
        impl Devices for EntryBus {
            fn read(
                &mut self,
                _: usize,
                address: u64,
                bytes: u8,
                _: u64,
            ) -> Result<u64, DeviceError> {
                let mut value = [0; 8];
                if bytes > 8
                    || !self
                        .0
                        .borrow_mut()
                        .read(address, &mut value[..usize::from(bytes)])
                {
                    return Err(DeviceError::Refused(
                        "original entry physical input is unknown".into(),
                    ));
                }
                Ok(u64::from_le_bytes(value))
            }
            fn write(
                &mut self,
                _: usize,
                address: u64,
                bytes: u8,
                value: u64,
                _: u64,
            ) -> Result<(), DeviceError> {
                if bytes > 8
                    || !self
                        .0
                        .borrow_mut()
                        .write(address, &value.to_le_bytes()[..usize::from(bytes)])
                {
                    return Err(DeviceError::Refused(
                        "original entry target has no live qualified RAM/MMIO owner".into(),
                    ));
                }
                Ok(())
            }
            fn lines(&mut self, _: usize, _: u64) -> Lines {
                Lines::default()
            }
            fn system_register(
                &mut self,
                _: usize,
                encoding: Encoding,
                written: Option<u64>,
                _: u64,
            ) -> Option<Result<u64, &'static str>> {
                let mut entry = self.0.borrow_mut();
                entry.registers.push((encoding, written));
                if encoding != Encoding::new(3, 3, 15, 7, 0) {
                    return None;
                }
                Some(match written {
                    None => entry
                        .cram
                        .read()
                        .map_err(|_| "actual canonical CRAM owner refused read"),
                    Some(value) => entry
                        .cram
                        .write(value)
                        .map(|()| 0)
                        .map_err(|_| "actual canonical CRAM owner refused write"),
                })
            }
        }
        #[test]
        #[ignore = "requires pinned J314s LLB; declared live CRAM is an emulated entry handoff, not Apple reset state"]
        fn unchanged_j314s_entry_fetches_from_live_canonical_aperture_before_original_consumers() {
            let _serial = ENTRY_EXECUTION.lock().unwrap();
            let _guard = EntryGuard::new();
            let bytes = original(J314S);
            assert_eq!(
                u64::from_le_bytes(bytes[0x380..0x388].try_into().unwrap()),
                ENTRY_BASE
            );
            assert_eq!(
                u64::from_le_bytes(bytes[0x226c8..0x226d0].try_into().unwrap()),
                APERTURE
            );
            assert_eq!(
                u64::from_le_bytes(bytes[0x226d0..0x226d8].try_into().unwrap()),
                APERTURE + CAPACITY as u64
            );
            // Declared emulated resource, not guessed native hardware geometry.
            // Its initial allocation is ACTUALLY LIVE before any image loading.
            let geometry = Geometry::new(APERTURE, 16, 60).unwrap();
            assert_eq!(geometry.capacity(), CAPACITY as u64);
            let owner = Owned::new(geometry, 60);
            let mut entry = EntryRam {
                cram: Cram::new(geometry, geometry.register_fields() | READY | 60, owner).unwrap(),
                known: vec![false; CAPACITY],
                source_reads: 0,
                committed: vec![],
                unknown: vec![],
                registers: vec![],
            };
            let before = entry.cram.backing().state();
            let view = entry.cram.backing().view.as_ref().unwrap().clone();
            assert!(view.is_current());
            assert_eq!(view.permissions(), RIGHTS);
            // System Machine fetches physical instruction bytes through
            // Host::read_ram, then enforces architectural execute permission.
            // This is not a process SourceExecutor Execute-view admission; the
            // original RW physical backing contract remains unchanged.
            assert_eq!(before.active_bytes, CAPACITY as u64);
            assert!(entry.write(ENTRY_BASE, &bytes));
            // Underlying fixture storage has an explicit synthetic pattern, but
            // only original loaded bytes and subsequently committed stores may
            // answer guest reads. Untouched bytes remain UNKNOWN in this run.
            let mut untouched = [0; 8];
            assert!(!entry.read(APERTURE, &mut untouched));
            entry.unknown.clear();
            entry.committed.clear(); // source loading is separate from guest stores
            drop(bytes); // no parallel original-code RAM buffer survives
            let shared = std::rc::Rc::new(std::cell::RefCell::new(entry));
            let host = NativeHost {
                original: vec![],
                entry: Some(shared.clone()),
                regime: None,
                code: vec![],
                output_prefix: "j314s-live-entry".into(),
                patches: 0,
                runner: NativeRunner::new(vec![]),
            };
            let target = TargetCpu::Baseline;
            let mut fixed = crate::machine::identification::derive(
                Chip::AppleM1,
                target,
                true,
                crate::machine::identification::Speculation::NONE,
            );
            fixed.push((MPIDR_EL1, 0x80000000));
            let profile = CpuProfile {
                name: "J314s original entry with explicitly declared live canonical CRAM",
                chip: Chip::AppleM1,
                counter_frequency: 24_000_000,
                fixed,
                processors: vec![],
            };
            let mut machine = Machine::new(
                Cpu::of(Chip::AppleM1, ENTRY_BASE, Pstate::reset(2)),
                host,
                EntryBus(shared.clone()),
                profile,
                target,
            );
            machine.set_strict(true);
            machine.set_watches(&[(APERTURE, APERTURE + GUARD_BYTES as u64 - 1)]);
            let mut watch = vec![];
            let stop = (1..=32768).find_map(|budget| {
                let stop = machine.run(budget);
                for hit in machine.take_watch_hits() {
                    assert_eq!(hit.dropped, 0);
                    watch.push(serde_json::json!({"pc":hit.pc,"physical":hit.physical,"bytes":hit.bytes,
                        "value":hit.value,"write":hit.write,"completed":hit.completed}));
                }
                (stop != Stop::Budget).then_some(stop)
            }).unwrap_or(Stop::Budget);
            let entry = shared.borrow();
            eprintln!(
                "original J314s live entry stop {stop:?}, pc={:#x}, blocks={}, writes={}",
                machine.cpu.pc,
                machine.statistics.blocks,
                entry.committed.len()
            );
            assert_ne!(machine.cpu.pc, ENTRY_BASE + J314S.allocation);
            assert_eq!(entry.cram.backing().state(), before);
            assert_eq!(entry.cram.backing().commits, 0);
            assert!(view.is_current());
            assert!(entry.source_reads > 0);
            assert!(entry.registers.iter().any(|(encoding, value)| *encoding
                == Encoding::new(3, 3, 15, 7, 0)
                && value.is_none()));
            let Stop::Unsupported(requirement) = &stop else {
                panic!(
                    "original entry did not reach its actual unknown storage boundary: {stop:?}"
                );
            };
            assert_eq!(requirement.pc, ENTRY_BASE + 0xcf27c);
            assert!(matches!(&requirement.kind, RequirementKind::Device {
                physical: 0x1fc2c65e0, write: false, detail,
            } if detail == "original entry physical input is unknown"));
            assert_eq!(entry.unknown.last(), Some(&(0x1fc2c65e0, 1)));
            assert_eq!(machine.statistics.exceptions, 0);
            assert!(!entry.committed.is_empty());
            if let Some(path) = std::env::var_os("STELA_TEST_CRAM_ENTRY_REPORT") {
                use std::io::Write as _;
                let report = serde_json::json!({"schema":1,"source_sha256":J314S.sha256,"entry":ENTRY_BASE,
                    "scope":"unchanged original entry; explicit emulated active canonical CRAM, not Apple initial state or completed PMGR handoff",
                    "aperture_base":APERTURE,"aperture_bytes":CAPACITY,"unit_exponent":16,"limit":60,"initial_units":60,
                    "initial_mapping":format!("{before:?}"),"final_mapping":format!("{:?}",entry.cram.backing().state()),
                    "backing_commits":entry.cram.backing().commits,"stop":format!("{stop:?}"),"pc":machine.cpu.pc,
                    "blocks":machine.statistics.blocks,"exceptions":machine.statistics.exceptions,
                    "registers":machine.cpu.state.x,"sp":machine.cpu.state.sp,
                    "source_reads":entry.source_reads,"guest_stores":entry.committed,"unknown_reads":entry.unknown,
                    "system_accesses":entry.registers.iter().map(|(e,v)|(format!("{e:?}"),v)).collect::<Vec<_>>(),"watch":watch,
                    "knownness":"only actual original image copy and successful guest stores initialize bytes; underlying synthetic pattern is never supplied as original input"});
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .unwrap();
                file.write_all(&serde_json::to_vec_pretty(&report).unwrap())
                    .unwrap();
                file.write_all(b"\n").unwrap();
            }
        }
        #[test]
        #[ignore = "requires pinned J473 LLB; synthetic resource is not an Apple handoff observation"]
        fn unchanged_original_allocation_and_release_execute_against_actual_view_owner() {
            allocation_and_release(J473);
        }
        #[test]
        #[ignore = "requires pinned J473 LLB; source capacity and already-complete branches"]
        fn unchanged_original_capacity_and_initial_completion_branches_remain_distinct() {
            capacity_and_initial_completion(J473);
        }
        #[test]
        #[ignore = "requires pinned J314s LLB; synthetic resource is not an Apple handoff observation"]
        fn unchanged_j314s_allocation_and_release_execute_against_actual_view_owner() {
            allocation_and_release(J314S);
        }
        #[test]
        #[ignore = "requires pinned J314s LLB; source capacity and already-complete branches"]
        fn unchanged_j314s_capacity_and_initial_completion_branches_remain_distinct() {
            capacity_and_initial_completion(J314S);
        }
    }
}

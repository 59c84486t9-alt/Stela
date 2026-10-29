use super::*;
use alloc::{sync::Arc, vec};
use std::alloc::{Layout, alloc, dealloc};
use std::ptr::NonNull;
use stela_compiler::TargetCpu;
use stela_engine::memory::backing::AccessKind;
use stela_engine::memory::backing::AccessPermissions;
use stela_engine::memory::backing::MemoryBacking;
use stela_engine::memory::backing::MemoryView;
use stela_engine::memory::domain::MappingAttributes;
use stela_engine::memory::domain::MemoryDomain;
use stela_engine::memory::domain::MemorySystem;

const PAGE_BYTES: usize = 4096;

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

/// Heap RAM behind a test backing.
struct Storage {
    pointer: NonNull<u8>,
    layout: Layout,
}
// SAFETY: storage only owns raw allocation; byte access uses native helpers.
unsafe impl Send for Storage {}
// SAFETY: storage lends no Rust references and accesses use one writer domain.
unsafe impl Sync for Storage {}
impl Drop for Storage {
    fn drop(&mut self) {
        // SAFETY: this owner keeps its allocation and layout.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}
impl Owned {
    fn new(geometry: Geometry, units: u8) -> Self {
        let bytes = geometry.capacity() as usize;
        let layout = Layout::from_size_align(bytes, PAGE_BYTES).unwrap();
        // SAFETY: nonempty valid layout kept by Storage for deallocation.
        let pointer = NonNull::new(unsafe { alloc(layout) }).unwrap();
        // SAFETY: the allocation is `bytes` long and nothing else refers to it.
        unsafe { pointer.as_ptr().write_bytes(0xa5, bytes) };
        let storage = Arc::new(Storage { pointer, layout });
        // SAFETY: Storage pins raw coherent RAM with no aliasing Rust references.
        let backing = unsafe { MemoryBacking::new(pointer, bytes, RIGHTS, storage) }.unwrap();
        let system = MemorySystem::new(16, 16).unwrap();
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
        // SAFETY: No native execution or other writer exists in this test owner;
        // resolution keeps the view/backing for the access.
        Some(unsafe { access.host_ptr().as_ptr().read() })
    }
    fn write(&mut self, address: u64, value: u8) {
        let access = self
            .view
            .as_ref()
            .unwrap()
            .resolve(address, 1, AccessKind::Write)
            .unwrap();
        // SAFETY: This test exclusively owns the backing and no access overlaps
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
            // This test keeps no native/execution loans. The real
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
fn initial_register_and_aperture_must_agree_without_mutation() {
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
fn allocation_and_release_change_view_before_ready_and_preserve_data() {
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
    // The original release preserves the written Ready=1, but
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
fn exhausted_or_invalid_completion_does_not_invent_progress_or_rollback_effects() {
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

#[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
mod original {
    use super::*;
    use stela_compiler::{GuestState, aarch64::system::registers::Encoding};
    use stela_contracts::Chip;
    use stela_contracts::identity::Identity;
    use stela_engine::execution::platform::Mapping;
    use stela_engine::execution::reference::NativeRunner;
    use stela_engine::machine::Cpu;
    use stela_engine::machine::CpuProfile;
    use stela_engine::machine::DeviceError;
    use stela_engine::machine::Devices;
    use stela_engine::machine::FaultCause;
    use stela_engine::machine::Host;
    use stela_engine::machine::InstallError;
    use stela_engine::machine::Lines;
    use stela_engine::machine::Machine;
    use stela_engine::machine::NativeCode;
    use stela_engine::machine::NativeExit;
    use stela_engine::machine::Regime;
    use stela_engine::machine::RequirementKind;
    use stela_engine::machine::Stop;
    use stela_engine::machine::exception::Pstate;
    use stela_engine::machine::registers::encodings::MPIDR_EL1;

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
        clock: Option<std::time::Instant>,
        code: alloc::vec::Vec<(Mapping, usize)>,
        output_prefix: alloc::string::String,
        patches: usize,
        runner: NativeRunner,
    }
    impl Host for NativeHost {
        fn read_ram(&mut self, physical: u64, out: &mut [u8]) -> bool {
            if let Some(entry) = &self.entry {
                let mut entry = entry.borrow_mut();
                // A failed RAM probe outside the reservation may
                // belong to a real peripheral provider, not unknown RAM.
                return entry.range(physical, out.len()).is_some() && entry.read(physical, out);
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
            // them through the Machine regime and canonical backing.
            self.runner.set_ranges(
                self.code
                    .iter()
                    .map(|(code, bytes)| (code.entry() as u64, code.entry() as u64 + *bytes as u64))
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
            // SAFETY: Machine requests patches only outside native invocation.
            // This mapping owns the complete page-rounded OS extent; no
            // Rust byte reference or concurrent code execution exists.
            unsafe {
                assert_eq!(
                    libc::mprotect(entry as *mut _, *length, libc::PROT_READ | libc::PROT_WRITE),
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
                // SAFETY: This installed RX image remains owned and idle.
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
            // SAFETY: Machine installed this immutable mapping with its block ABI.
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
                        match stela_engine::machine::mmu::translate(
                            &regime.controls,
                            fault.address,
                            if fault.write {
                                stela_engine::machine::mmu::Access::Write
                            } else {
                                stela_engine::machine::mmu::Access::Read
                            },
                            regime.requester,
                            &mut EntryTables(entry.clone()),
                        ) {
                            stela_engine::machine::mmu::Outcome::Mapped(mapping) => {
                                FaultCause::Device {
                                    physical: mapping.physical,
                                }
                            }
                            stela_engine::machine::mmu::Outcome::Fault(fault) => {
                                FaultCause::Guest(fault)
                            }
                            stela_engine::machine::mmu::Outcome::Unsupported(reason) => {
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
            // Full entry receives elapsed host time in the declared
            // 24MHz counter domain; bounded isolated register replays keep
            // their explicit fixed-time scenario. Never tick from a poll.
            self.clock.as_ref().map_or(0, |clock| {
                (clock.elapsed().as_nanos() * 24_000_000 / 1_000_000_000) as u64
            })
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
        fn write(&mut self, _: usize, _: u64, _: u8, _: u64, _: u64) -> Result<(), DeviceError> {
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
        let bytes =
            std::fs::read(std::env::var(input.environment).expect("original LLB path")).unwrap();
        assert_eq!(stela_formats::sha256(&bytes), input.sha256);
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
            clock: None,
            code: alloc::vec::Vec::new(),
            output_prefix: alloc::format!(
                "entry-{entry:x}-aff2-{aff2:x}-descriptor-{:x}",
                cram.word
            ),
            patches: 0,
            runner: NativeRunner::new(alloc::vec::Vec::new()).expect("reference fault handlers"),
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
            // production physical aperture permission.
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
            // SAFETY: Reserve only; never replace host mappings or expose guest RAM
            // directly to native code. Accesses use the canonical view.
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
                // SAFETY: the reservation at `pointer` is not the requested aperture and is
                // released once.
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
            // SAFETY: `self.0` is the guard reservation this value owns, unmapped once.
            unsafe {
                libc::munmap(self.0, GUARD_BYTES);
            }
        }
    }
    struct RegisterEvent {
        encoding: Encoding,
        write: bool,
        value: Option<u64>,
    }
    struct EntryRam {
        cram: Cram<Owned>,
        known: Vec<bool>,
        source_reads: usize,
        committed: Vec<(u64, Vec<u8>)>,
        redacted_stores: Vec<(u64, usize)>,
        redact: bool,
        unknown: Vec<(u64, usize)>,
        registers: Vec<RegisterEvent>,
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
            // SAFETY: One thread owns this live canonical backing; native accesses
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
            // SAFETY: Same exclusive canonical route as source loading. No second
            // RAM image or successful byte initialization is substituted.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    access.host_ptr().as_ptr(),
                    bytes.len(),
                );
            }
            self.known[range].fill(true);
            if self.redact {
                self.redacted_stores.push((address, bytes.len()));
            } else {
                self.committed.push((address, bytes.to_vec()));
            }
            true
        }
    }
    struct EntryTables(std::rc::Rc<std::cell::RefCell<EntryRam>>);
    impl stela_engine::machine::mmu::TableMemory for EntryTables {
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
    struct EntryBus {
        ram: std::rc::Rc<std::cell::RefCell<EntryRam>>,
        peripherals: stela_contracts::bus::Bus,
        interrupts: stela_contracts::interrupt::InterruptLatch,
        sep: Option<stela_contracts::bus::DeviceId>,
        effects: Vec<serde_json::Value>,
        irq_changes: Vec<serde_json::Value>,
        entropy_calls: std::rc::Rc<std::cell::Cell<usize>>,
    }
    impl EntryBus {
        fn new(ram: std::rc::Rc<std::cell::RefCell<EntryRam>>, mount_sep: bool) -> Self {
            use crate::platform::apple::asc;
            use crate::platform::apple::sep;
            use crate::platform::apple::sep::Sep;
            use stela_contracts::bus;
            use stela_contracts::interrupt::AicInput;
            use stela_contracts::interrupt::InterruptLatch;
            let mut peripherals = bus::Bus::new();
            let entropy_calls = std::rc::Rc::new(std::cell::Cell::new(0));
            let sep = mount_sep.then(|| {
                let supplied = entropy_calls.clone();
                use sha2::Digest as _;
                use std::io::Read as _;
                let adt = std::fs::read(
                    std::env::var("STELA_TEST_PMGR_M1_ADT").expect("matching original J314s ADT"),
                )
                .unwrap();
                assert_eq!(
                    hex::encode(sha2::Sha256::digest(&adt)),
                    "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
                );
                let root = stela_contracts::adt::Node::root(&adt).unwrap();
                let io = root.child("arm-io").unwrap();
                let node = io.child("sep").unwrap();
                assert_eq!(
                    node.property("compatible"),
                    Some(&b"iop-sep,ascwrap-v4\0"[..])
                );
                let irqs: [u32; 4] = node.cells32("interrupts").unwrap().try_into().unwrap();
                let lines = asc::Lines::from_interrupts(
                    irqs.map(|irq| AicInput::new(0, u16::try_from(irq).unwrap())),
                );
                let mut random = std::fs::File::open("/dev/urandom").unwrap();
                let model = Sep::booted_rom(
                    Box::new(move |bytes: &mut [u8]| {
                        random
                            .read_exact(bytes)
                            .map_err(|_| "actual host entropy source failed")?;
                        supplied.set(supplied.get() + 1);
                        Ok(())
                    }),
                    lines,
                    None,
                    0x5354454c41544553,
                    false,
                    sep::state::Location::Volatile,
                )
                .unwrap();
                let device = peripherals.add(Box::new(model));
                let ranges = io.ranges().unwrap();
                let registers = node.pairs("reg").unwrap();
                assert_eq!(registers.len(), 2);
                for (index, (address, bytes)) in registers.into_iter().enumerate() {
                    let &(child, parent, _) = ranges
                        .iter()
                        .find(|&&(child, _, length)| address >= child && address - child < length)
                        .unwrap();
                    let offset = if index == 0 { 0 } else { sep::AUXILIARY_OFFSET };
                    peripherals
                        .map(device, parent + address - child, bytes, offset)
                        .unwrap();
                }
                device
            });
            Self {
                ram,
                peripherals,
                interrupts: InterruptLatch::new(),
                sep,
                effects: vec![],
                irq_changes: vec![],
                entropy_calls,
            }
        }
        fn collect_irqs(&mut self) {
            self.irq_changes.extend(self.interrupts.take_aic_inputs().into_iter().map(|(input, level)|
                    serde_json::json!({"die":input.die,"irq":input.irq,"asserted":level})));
        }
    }
    impl Devices for EntryBus {
        fn read(
            &mut self,
            cpu: usize,
            address: u64,
            bytes: u8,
            now: u64,
        ) -> Result<u64, DeviceError> {
            use stela_contracts::bus::Access;
            use stela_contracts::bus::MmioError;
            use stela_contracts::bus::Width;
            let width = Width::from_bytes(u64::from(bytes)).ok_or_else(|| {
                DeviceError::Refused("original entry unsupported access width".into())
            })?;
            let result = self.peripherals.read(
                address,
                width,
                &mut Access::new(cpu, now, &mut self.interrupts),
            );
            if !matches!(result, Err(MmioError::Unmapped { .. })) {
                self.effects
                    .push(serde_json::json!({"address":address,"bytes":bytes,
                        "write":false,"result":format!("{:?}", result.as_ref().map(|_| ()))}));
                self.collect_irqs();
                return result.map_err(|error| DeviceError::Refused(format!("{error:?}")));
            }
            let mut value = [0; 8];
            if !self
                .ram
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
            cpu: usize,
            address: u64,
            bytes: u8,
            value: u64,
            now: u64,
        ) -> Result<(), DeviceError> {
            use stela_contracts::bus::Access;
            use stela_contracts::bus::MmioError;
            use stela_contracts::bus::Width;
            let width = Width::from_bytes(u64::from(bytes)).ok_or_else(|| {
                DeviceError::Refused("original entry unsupported access width".into())
            })?;
            let result = self.peripherals.write(
                address,
                width,
                value,
                &mut Access::new(cpu, now, &mut self.interrupts),
            );
            if !matches!(result, Err(MmioError::Unmapped { .. })) {
                self.effects
                    .push(serde_json::json!({"address":address,"bytes":bytes,
                        "write":true,"result":format!("{result:?}")}));
                self.collect_irqs();
                return result.map_err(|error| DeviceError::Refused(format!("{error:?}")));
            }
            if !self
                .ram
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
        fn transfer(
            &mut self,
            cpu: usize,
            _: &mut dyn stela_contracts::dma::Memory,
            now: u64,
        ) -> Result<(), DeviceError> {
            use crate::platform::apple::sep::Sep;
            use stela_contracts::bus::Access;
            self.peripherals
                .advance(&mut Access::new(cpu, now, &mut self.interrupts))
                .map_err(|error| DeviceError::TransferRefused(format!("{error:?}")))?;
            self.collect_irqs();
            if self
                .sep
                .and_then(|device| self.peripherals.device::<Sep>(device))
                .is_some_and(Sep::pending)
            {
                return Err(DeviceError::TransferRefused(
                    "original SEP DMA requires actual DART and shared backing provider".into(),
                ));
            }
            Ok(())
        }
        fn system_register(
            &mut self,
            _: usize,
            encoding: Encoding,
            written: Option<u64>,
            _: u64,
        ) -> Option<Result<u64, &'static str>> {
            let mut entry = self.ram.borrow_mut();
            let value = if entry.redact { None } else { written };
            entry.registers.push(RegisterEvent {
                encoding,
                write: written.is_some(),
                value,
            });
            if encoding != Encoding::new(3, 3, 15, 7, 0) {
                return None;
            }
            Some(match written {
                None => entry
                    .cram
                    .read()
                    .map_err(|_| "actual canonical CRAM owner refused read"),
                Some(word) => entry
                    .cram
                    .write(word)
                    .map(|()| 0)
                    .map_err(|_| "actual canonical CRAM owner refused write"),
            })
        }
    }
    enum EntryPolicy {
        ImageOnly,
        Initialized,
        InitializedWithSep,
    }
    #[test]
    #[ignore = "oracle: STELA_TEST_PMGR_M1_ADT"]
    fn unchanged_j314s_entry_fetches_from_live_canonical_aperture_before_original_consumers() {
        live_entry(EntryPolicy::ImageOnly);
    }
    #[test]
    #[ignore = "oracle: STELA_TEST_PMGR_M1_ADT"]
    fn unchanged_j314s_entry_uses_whole_reservation_initialization_before_image_copy() {
        live_entry(EntryPolicy::Initialized);
    }
    #[test]
    #[ignore = "oracle: STELA_TEST_PMGR_M1_ADT"]
    fn unchanged_j314s_entry_exchanges_full_mailbox_frames_with_native_sep_rom() {
        live_entry(EntryPolicy::InitializedWithSep);
    }
    fn live_entry(policy: EntryPolicy) {
        let initialize_reservation = !matches!(policy, EntryPolicy::ImageOnly);
        let mount_sep = matches!(policy, EntryPolicy::InitializedWithSep);
        if mount_sep {
            assert!(
                std::env::var_os("STELA_TEST_CRAM_OUTPUT").is_none(),
                "native entropy/key runs retain coordinates only, never native-code dumps"
            );
        }
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
            redacted_stores: vec![],
            redact: false,
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
        if initialize_reservation {
            // Explicit deterministic Stela-owned RAM initialization. This
            // is an ACTUAL full-view write before image copy/fetch, not an
            // answer synthesized for a later read or Apple reset evidence.
            assert!(entry.write(APERTURE, &vec![0; CAPACITY]));
            assert!(entry.known.iter().all(|known| *known));
            let mut first = [0xff; 8];
            let mut last = [0xff; 8];
            assert!(entry.read(APERTURE, &mut first));
            assert!(entry.read(APERTURE + CAPACITY as u64 - 8, &mut last));
            assert_eq!((first, last), ([0; 8], [0; 8]));
            assert_eq!(entry.committed.len(), 1);
            assert_eq!(entry.committed[0].0, APERTURE);
            assert_eq!(entry.committed[0].1.len(), CAPACITY);
        }
        assert!(entry.write(ENTRY_BASE, &bytes));
        // Underlying allocation-pattern bytes never become readable
        // by existing. Only full-reservation initialization (where
        // declared), original loading and committed guest stores are known.
        let mut untouched = [0; 8];
        assert_eq!(entry.read(APERTURE, &mut untouched), initialize_reservation);
        if initialize_reservation {
            assert_eq!(untouched, [0; 8]);
        }
        entry.unknown.clear();
        let initialization = entry
            .committed
            .iter()
            .map(|(address, bytes)| {
                use sha2::Digest as _;
                serde_json::json!({"address":address,"bytes":bytes.len(),
                    "sha256":hex::encode(sha2::Sha256::digest(bytes))})
            })
            .collect::<Vec<_>>();
        entry.committed.clear(); // initialization is separate from guest stores
        entry.redact = mount_sep; // no runtime entropy/key bytes enter evidence logs
        drop(bytes); // no parallel original-code RAM buffer survives
        let shared = std::rc::Rc::new(std::cell::RefCell::new(entry));
        let host = NativeHost {
            original: vec![],
            entry: Some(shared.clone()),
            regime: None,
            clock: Some(std::time::Instant::now()),
            code: vec![],
            output_prefix: "j314s-live-entry".into(),
            patches: 0,
            runner: NativeRunner::new(vec![]).expect("reference fault handlers"),
        };
        let target = TargetCpu::Baseline;
        let mut fixed = stela_engine::machine::identification::derive(
            Chip::AppleM1,
            target,
            true,
            stela_engine::machine::identification::Speculation::NONE,
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
            EntryBus::new(shared.clone(), mount_sep),
            profile,
            target,
        );
        machine.set_watches(&[(APERTURE, APERTURE + GUARD_BYTES as u64 - 1)]);
        let mut watch = vec![];
        let mut exceptions = vec![];
        let stop = (1..=32768).find_map(|budget| {
                let old_pc = machine.cpu.pc;
                let old_exceptions = machine.statistics.exceptions;
                // The entry ends at the first operation answered degraded.
                let mut stop = machine.run(budget);
                if let Some(first) = machine.take_unmodeled().into_iter().next() {
                    stop = Stop::Unsupported(first);
                }
                if machine.statistics.exceptions != old_exceptions {
                    use stela_engine::machine::system::Register;
                    exceptions.push(serde_json::json!({"previous_pc":old_pc,"vector_pc":machine.cpu.pc,
                        "esr_el1":machine.cpu.read(Register::ESR_EL1),"elr_el1":machine.cpu.read(Register::ELR_EL1),
                        "far_el1":machine.cpu.read(Register::FAR_EL1),"esr_el2":machine.cpu.read(Register::ESR_EL2),
                        "elr_el2":machine.cpu.read(Register::ELR_EL2),"far_el2":machine.cpu.read(Register::FAR_EL2)}));
                }
                for hit in machine.take_watch_hits() {
                    assert_eq!(hit.dropped, 0);
                    watch.push(serde_json::json!({"pc":hit.pc,"physical":hit.physical,"bytes":hit.bytes,
                        "value":if mount_sep {None} else {Some(hit.value)},"write":hit.write,"completed":hit.completed}));
                }
                (stop != Stop::Budget || (initialize_reservation && !exceptions.is_empty()))
                    .then_some(stop)
            }).unwrap_or(Stop::Budget);
        let entry = shared.borrow();
        eprintln!(
            "original J314s live entry stop {stop:?}, pc={:#x}, blocks={}, writes={}",
            machine.cpu.pc,
            machine.statistics.blocks,
            entry.committed.len() + entry.redacted_stores.len()
        );
        assert_ne!(machine.cpu.pc, ENTRY_BASE + J314S.allocation);
        assert_eq!(entry.cram.backing().state(), before);
        assert_eq!(entry.cram.backing().commits, 0);
        assert!(view.is_current());
        assert!(entry.source_reads > 0);
        assert!(
            entry
                .registers
                .iter()
                .any(|event| event.encoding == Encoding::new(3, 3, 15, 7, 0) && !event.write)
        );
        if mount_sep {
            assert_eq!(machine.devices.entropy_calls.get(), 4);
            assert_eq!(machine.devices.effects.len(), 24);
            assert!(
                machine
                    .devices
                    .effects
                    .iter()
                    .all(|effect| effect["result"] == "Ok(())")
            );
            let Stop::Unsupported(requirement) = &stop else {
                panic!("original keyed entry did not reach its next qualified boundary: {stop:?}");
            };
            assert_eq!(requirement.pc, ENTRY_BASE + 0x2e750);
            assert!(matches!(&requirement.kind, RequirementKind::Device {
                    physical: 0x2922dc22c, write: false, detail,
                } if detail == "original entry physical input is unknown"));
            assert_eq!(entry.unknown.last(), Some(&(0x2922dc22c, 4)));
            assert!(exceptions.is_empty());
            assert_eq!(machine.statistics.exceptions, 0);
            assert!(entry.committed.is_empty(), "no runtime values logged");
            let sep = machine
                .devices
                .peripherals
                .device::<crate::platform::apple::sep::Sep>(machine.devices.sep.unwrap())
                .unwrap();
            assert!(sep.evidence().is_none());
            assert!(!sep.booted());
            assert!(!sep.pending());
        } else if initialize_reservation {
            // Continue the checked physical alias using shared
            // host time. The next input is the original SEP outbox/control
            // bank; this bounded fixture has no physical device provider.
            let Stop::Unsupported(requirement) = &stop else {
                panic!("original entry did not reach its next physical input: {stop:?}");
            };
            assert_eq!(requirement.pc, ENTRY_BASE + 0x15654);
            assert!(matches!(&requirement.kind, RequirementKind::Device {
                    physical: 0x396408114, write: false, detail,
                } if detail == "original entry physical input is unknown"));
            assert_eq!(entry.unknown.last(), Some(&(0x396408114, 4)));
            assert_eq!(machine.statistics.exceptions, 0);
            assert!(entry.registers.iter().any(|event| event.encoding
                == stela_engine::machine::registers::encodings::ACNTPCT_EL0
                && !event.write));
        } else {
            let Stop::Unsupported(requirement) = &stop else {
                panic!("original entry did not reach its unknown storage boundary: {stop:?}");
            };
            assert_eq!(requirement.pc, ENTRY_BASE + 0xcf27c);
            assert!(matches!(&requirement.kind, RequirementKind::Device {
                    physical: 0x1fc2c65e0, write: false, detail,
                } if detail == "original entry physical input is unknown"));
            assert_eq!(entry.unknown.last(), Some(&(0x1fc2c65e0, 1)));
        }
        if !initialize_reservation {
            assert_eq!(machine.statistics.exceptions, 0);
        }
        assert!(!entry.committed.is_empty() || !entry.redacted_stores.is_empty());
        if let Some(path) = std::env::var_os(if mount_sep {
            "STELA_TEST_CRAM_SEP_ENTRY_REPORT"
        } else if initialize_reservation {
            "STELA_TEST_CRAM_ZEROED_ENTRY_REPORT"
        } else {
            "STELA_TEST_CRAM_ENTRY_REPORT"
        }) {
            use std::io::Write as _;
            let report = serde_json::json!({"schema":1,"source_sha256":J314S.sha256,"entry":ENTRY_BASE,
                    "scope":"unchanged original entry; explicit emulated active canonical CRAM, not Apple initial state or completed PMGR handoff",
                    "initialization": if initialize_reservation {"actual whole canonical reservation zeroed before original image copy; declared Stela-owned policy, not Apple BootROM observation"} else {"only original immutable image bytes initially known; untouched storage unknown"},
                    "initialization_effects":initialization,
                    "aperture_base":APERTURE,"aperture_bytes":CAPACITY,"unit_exponent":16,"limit":60,"initial_units":60,
                    "initial_mapping":format!("{before:?}"),"final_mapping":format!("{:?}",entry.cram.backing().state()),
                    "backing_commits":entry.cram.backing().commits,"stop":format!("{stop:?}"),
                    "boundary":if mount_sep {"actual chip-identity physical input after native SEP mailbox transactions and canonical EL2 key writes"} else if initialize_reservation {"next original physical peripheral input; no provider mounted"} else {"unknown original storage input"},"pc":machine.cpu.pc,
                    "physical_counter":"full entry uses actual monotonic host elapsed time in the declared24MHz domain, never poll-driven ticks",
                    "blocks":machine.statistics.blocks,"exceptions":machine.statistics.exceptions,"exception_events":exceptions,
                    "registers":if mount_sep {None} else {Some(machine.cpu.state.x)},"sp":machine.cpu.state.sp,
                    "source_reads":entry.source_reads,"guest_stores":if mount_sep {serde_json::to_value(&entry.redacted_stores).unwrap()} else {serde_json::to_value(&entry.committed).unwrap()},
                    "guest_store_parts":entry.committed.len()+entry.redacted_stores.len(),"unknown_reads":entry.unknown,
                    "peripheral_effects":machine.devices.effects,"peripheral_irqs":machine.devices.irq_changes,
                    "entropy_requests":machine.devices.entropy_calls.get(),
                    "el2_key_pairs_initialized":if mount_sep {Some(machine.cpu.apple.pointer_keys.initialized())} else {None},
                    "sep_handoff":if mount_sep {"explicit Stela running ROM/enabled actual mailboxes; real host entropy; declared test ECID5354454c41544553, unknownsecurityNone, volatile state; AIC input transitions recorded, CPU delivery unmounted"} else {"no peripheral provider"},
                    "system_accesses":entry.registers.iter().map(|event|serde_json::json!({"encoding":format!("{:?}",event.encoding),"write":event.write,"value":event.value})).collect::<Vec<_>>(),"watch":watch,
                    "redaction":if mount_sep {"all runtime registers/store bytes/mailbox values/watch values omitted at collection; only coordinates, sizes, directions and counts retained"} else {"no native entropy/key provider in this scenario"},
                    "knownness":"only actual declared initialization operations, original image copy and successful guest stores initialize bytes; underlying synthetic pattern is never supplied as original input"});
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
    #[ignore = "oracle: STELA_TEST_PMGR_M1_ADT"]
    fn unchanged_original_allocation_and_release_execute_against_view_owner() {
        allocation_and_release(J473);
    }
    #[test]
    #[ignore = "oracle: STELA_TEST_PMGR_M1_ADT"]
    fn unchanged_original_capacity_and_initial_completion_branches_remain_distinct() {
        capacity_and_initial_completion(J473);
    }
    #[test]
    #[ignore = "oracle: STELA_TEST_PMGR_M1_ADT"]
    fn unchanged_j314s_allocation_and_release_execute_against_view_owner() {
        allocation_and_release(J314S);
    }
    #[test]
    #[ignore = "oracle: STELA_TEST_PMGR_M1_ADT"]
    fn unchanged_j314s_capacity_and_initial_completion_branches_remain_distinct() {
        capacity_and_initial_completion(J314S);
    }
}

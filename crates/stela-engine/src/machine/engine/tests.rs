use super::*;
use crate::machine::exception::Pstate;

#[test]
fn architectural_translation_generation_exhaustion_never_reuses_an_old_epoch() {
    let operations: [fn(&mut Machine<FakeHost, NoDevices>); 5] = [
        Machine::advance_translation_generation,
        Machine::translations_changed,
        Machine::fetch_permissions_changed,
        |machine| machine.tlb_maintained(mmu::tlbi::Reach::All, mmu::tlbi::Everywhere::All),
        Machine::table_base_changed,
    ];
    for operation in operations {
        let mut machine = board_on(stela_contracts::Chip::AppleM1, &[], NoDevices, Vec::new());
        machine.translation_generation = u64::MAX;
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| operation(&mut machine)))
                .is_err()
        );
        assert_eq!(machine.translation_generation, u64::MAX);
    }
}

pub(super) const NATIVE_CODE_STRIDE: usize = 1 << 20;

/// A synthetic boundary must name a real operand/check instruction from
/// this emitted block, never its source-map/prologue bookkeeping offset.
pub(super) fn native_fault_site<D: Devices>(
    machine: &mut Machine<FakeHost, D>,
    pc: u64,
    kind: stela_compiler::block::RecoverySiteKind,
) -> usize {
    native_fault_site_in_entry(machine, pc, pc, kind).1
}
pub(super) fn native_fault_site_in_entry<D: Devices>(
    machine: &mut Machine<FakeHost, D>,
    entry: u64,
    pc: u64,
    kind: stela_compiler::block::RecoverySiteKind,
) -> (usize, usize) {
    let Ok(Fetched::Block(index)) = machine.fetch_block(entry, false) else {
        panic!("actual compiled native block");
    };
    let rows = machine.fault_recovery[&index].test_portable_rows();
    let row = rows
        .iter()
        .find(|row| row.retirement.instruction_pc().0 == pc && row.site == kind)
        .unwrap_or_else(|| {
            panic!(
                "no {kind:?} site for {pc:#x} in entry {entry:#x}: {:?}",
                rows
            )
        });
    (index, row.start)
}

pub(super) struct FakeHost {
    pub(super) ram: Vec<u8>,
    pub(super) events: Vec<Event>,
    base: u64,
    pub(super) now: u64,
    pub(super) regimes: Vec<Regime>,
    invalidations: usize,
    /// Calls of [`Host::isolate_predictions`].
    pub(super) isolations: usize,
    /// The pages of [`Host::code_invalidated`] calls.
    pub(super) code_invalidations: Vec<Option<u64>>,
    /// The reaches and scopes of [`Host::invalidate_reach`] calls.
    pub(super) reaches: Vec<(mmu::tlbi::Reach, mmu::tlbi::Everywhere)>,
    pub(super) installed: Vec<Vec<u8>>,
    /// Executable copies of the context leaves the engine called.
    executables: Vec<crate::execution::platform::Mapping>,
    pub(super) patches: Vec<(usize, Vec<u8>)>,
    live_patch_start: usize,
    /// The chaining state the next native run leaves, as thunks would.
    pub(super) chained: Option<(*mut ChainControl, ChainControl)>,
    /// What the next native blocks return, in order: unit tests do not
    /// run native code.
    pub(super) exits: Vec<NativeExit>,
    /// A translation store, for the tests that give the host one.
    pub(super) store: Option<stored::tests::MemoryStore>,
    /// Pages whose fetch the host refuses, and its answers.
    refused: Vec<u64>,
    fetch_checks: usize,
    pub(super) counter_reads: usize,
    /// Counts the counter moves on after each read.
    pub(super) counter_step: u64,
    pub(super) execute_ticks: u64,
    pub(super) timers: Vec<Option<u64>>,
    /// What [`Host::tsc_counter`] answers.
    pub(super) tsc_counter: Option<(u64, u64)>,
    placement: mmu::placement::Placement,
    translation_helper: Option<u64>,
    /// What [`Host::memory_low`] answers.
    pub(super) memory_low: bool,
    /// Check the allocation boundary before a new compilation reads input.
    require_empty_code_on_read: bool,
    /// Installs per part of a code arena of two parts reclaimed in
    /// turn, and its parts' code addresses, oldest first; `None` for an
    /// arena of one part.
    pub(super) ring: Option<usize>,
    parts: Vec<core::ops::Range<usize>>,
}

impl Host for FakeHost {
    fn read_ram(&mut self, physical: u64, buffer: &mut [u8]) -> bool {
        if self.require_empty_code_on_read {
            assert!(
                self.installed.is_empty(),
                "resident code survived until new input allocation"
            );
        }
        let Some(offset) = physical.checked_sub(self.base) else {
            return false;
        };
        let offset = offset as usize;
        match self.ram.get(offset..offset + buffer.len()) {
            Some(bytes) => {
                buffer.copy_from_slice(bytes);
                true
            }
            None => false,
        }
    }
    fn write_ram(&mut self, physical: u64, data: &[u8]) -> bool {
        let Some(offset) = physical.checked_sub(self.base) else {
            return false;
        };
        let offset = offset as usize;
        match self.ram.get_mut(offset..offset + data.len()) {
            Some(bytes) => {
                bytes.copy_from_slice(data);
                true
            }
            None => false,
        }
    }
    fn install(&mut self, code: &[u8]) -> Result<NativeCode, InstallError> {
        if let Some(installs) = self.ring {
            let next = self.installed.len() + 1;
            let part = match self.parts.last_mut() {
                Some(part) => part,
                None => {
                    self.parts.push(next..next);
                    self.parts.last_mut().unwrap()
                }
            };
            if part.len() == installs {
                return Err(InstallError::Full);
            }
            part.end += 1;
        }
        self.installed.push(code.to_vec());
        assert!(code.len() < NATIVE_CODE_STRIDE);
        Ok(NativeCode(self.installed.len() * NATIVE_CODE_STRIDE))
    }
    fn reclaim_code(&mut self) -> Option<core::ops::Range<usize>> {
        self.ring?;
        let next = self.installed.len() + 1;
        self.parts.push(next..next);
        let range = match self.parts.len() > 2 {
            true => self.parts.remove(0),
            false => 0..0,
        };
        Some(range.start * NATIVE_CODE_STRIDE..range.end * NATIVE_CODE_STRIDE)
    }
    fn patch(&mut self, code: NativeCode, bytes: &[u8]) {
        self.patches.push((code.0, bytes.to_vec()));
    }
    fn read_native(&mut self, code: NativeCode, bytes: &mut [u8]) -> bool {
        let Some(index) = (code.0 / NATIVE_CODE_STRIDE).checked_sub(1) else {
            return false;
        };
        let offset = code.0 % NATIVE_CODE_STRIDE;
        let Some(body) = self
            .installed
            .get(index)
            .and_then(|code| code.get(offset..offset + bytes.len()))
        else {
            return false;
        };
        bytes.copy_from_slice(body);
        for (at, patch) in self.patches.iter().skip(self.live_patch_start) {
            if *at >= code.0
                && at
                    .checked_add(patch.len())
                    .is_some_and(|end| end <= code.0 + bytes.len())
            {
                bytes[*at - code.0..*at - code.0 + patch.len()].copy_from_slice(patch);
            }
        }
        true
    }
    fn discard_code(&mut self) {
        self.live_patch_start = self.patches.len();
        self.installed.clear();
        self.parts.clear();
        self.executables.clear();
    }
    fn memory_low(&self) -> bool {
        self.memory_low
    }
    #[cfg(host_memory)]
    fn context_entry(&mut self, code: NativeCode) -> Option<usize> {
        // Context leaves run: they touch only the state, the context and
        // the memory service.
        let mapping = crate::execution::platform::Mapping::new(
            &self.installed[code.0 / NATIVE_CODE_STRIDE - 1],
        )
        .expect("an executable mapping of the leaf");
        let entry = mapping.entry();
        self.executables.push(mapping);
        Some(entry)
    }
    unsafe fn execute(&mut self, _: NativeCode, _: &mut GuestState) -> NativeExit {
        assert!(!self.exits.is_empty(), "unit tests do not run native code");
        if let Some((control, chained)) = self.chained.take() {
            // SAFETY: this fixture names the owner's live control
            // outside native execution. Match native disjoint field writes;
            // the budget is always accessed atomically, even in fixtures.
            unsafe {
                AtomicU64::from_ptr(core::ptr::addr_of_mut!((*control).budget))
                    .store(chained.budget, Ordering::Relaxed);
                core::ptr::addr_of_mut!((*control).retired).write(chained.retired);
                core::ptr::addr_of_mut!((*control).block).write(chained.block);
                core::ptr::addr_of_mut!((*control).contexts).write(chained.contexts);
                core::ptr::addr_of_mut!((*control).table).write(chained.table);
                core::ptr::addr_of_mut!((*control).hits).write(chained.hits);
                core::ptr::addr_of_mut!((*control).linked).write(chained.linked);
            }
        }
        self.now = self.now.wrapping_add(self.execute_ticks);
        self.exits.remove(0)
    }
    fn set_regime(&mut self, regime: &Regime) {
        self.regimes.push(*regime);
    }
    fn isolate_predictions(&mut self) {
        self.isolations += 1;
    }
    fn code_invalidated(&mut self, page: Option<u64>) {
        self.code_invalidations.push(page);
    }
    fn fetch_permitted(&mut self, virtual_address: u64) -> bool {
        self.fetch_checks += 1;
        !self
            .refused
            .contains(&(virtual_address & !(FETCH_PAGE - 1)))
    }
    fn placement(&self) -> mmu::placement::Placement {
        self.placement
    }
    fn translation_helper(&self) -> Option<u64> {
        self.translation_helper
    }
    fn invalidate_translations(&mut self) {
        self.invalidations += 1;
    }
    fn invalidate_reach(&mut self, reach: mmu::tlbi::Reach, everywhere: mmu::tlbi::Everywhere) {
        self.reaches.push((reach, everywhere));
        if reach == mmu::tlbi::Reach::All {
            self.invalidations += 1;
        }
    }
    fn tsc_counter(&self) -> Option<(u64, u64)> {
        self.tsc_counter
    }
    fn profile_ticks(&mut self) -> u64 {
        self.counter()
    }
    fn counter(&mut self) -> u64 {
        self.counter_reads += 1;
        let now = self.now;
        self.now += self.counter_step;
        now
    }
    fn arm_timer(&mut self, until: Option<u64>) {
        self.timers.push(until);
    }
    fn wait_for_interrupt(&mut self) {
        self.now += 1000;
    }
    fn report(&mut self, event: &Event) {
        self.events.push(*event);
    }
    fn translations(&mut self) -> Option<&mut dyn Translations> {
        self.store
            .as_mut()
            .map(|store| store as &mut dyn Translations)
    }
}

pub(super) const BASE: u64 = 0x8_0000_0000;

/// A machine running `words` at BASE on PE 0 at EL1 of the chip the
/// tests run on ([`crate::machine::test_chip`]).
pub(super) fn translated_machine(words: &[u32]) -> Machine<FakeHost, NoDevices> {
    let mut machine = machine(words);
    machine.host.placement = mmu::placement::Placement::four_level(2).unwrap();
    machine.host.translation_helper = Some(0x1000);
    machine.translated_pages.insert(BASE & !(FETCH_PAGE - 1));
    machine.derived_changed();
    machine
}

pub(super) fn machine(words: &[u32]) -> Machine<FakeHost, NoDevices> {
    board(words, NoDevices, Vec::new())
}

/// The chip the tests run on, or the M2 where it has the Apple generic
/// timer's two banks (`timer::agt`): for tests of one bank's
/// architectural generic timer.
pub(super) fn one_timer_bank() -> stela_contracts::Chip {
    let chip = crate::machine::test_chip();
    if crate::machine::timer::agt::present(chip) {
        stela_contracts::Chip::AppleM2
    } else {
        chip
    }
}

/// [`machine`] on `chip`, for a test that fixes its chip.
pub(super) fn machine_on(
    chip: stela_contracts::Chip,
    words: &[u32],
) -> Machine<FakeHost, NoDevices> {
    board_on(chip, words, NoDevices, Vec::new())
}

/// Identity-map the test RAM as Normal Write-Back through stage 1 of
/// both regimes (4 KiB granule, T0SZ 25, one 1 GiB block, EL0 access
/// with `el0`, whose writable mapping EL1 cannot execute), for DC ZVA,
/// which faults on the Device memory of a disabled stage 1.
pub(super) fn normal_memory(machine: &mut Machine<FakeHost, NoDevices>, el0: bool) {
    const TABLE: usize = 0xf000;
    const TCR: u64 = 25 | 1 << 8 | 1 << 10 | 3 << 12 | 1 << 23 | 5 << 32;
    const SCTLR_M_C: u64 = 1 | 1 << 2;
    let block = BASE | 1 << 10 | 3 << 8 | if el0 { 1 << 6 } else { 0 } | 0b01;
    let entry = TABLE + (BASE >> 30) as usize * 8;
    machine.host.ram[entry..entry + 8].copy_from_slice(&block.to_le_bytes());
    let registers = &mut machine.cpu.registers;
    for (table, control, attributes, sctlr) in [
        (
            SystemRegister::TTBR0_EL1,
            SystemRegister::TCR_EL1,
            SystemRegister::MAIR_EL1,
            SystemRegister::SCTLR_EL1,
        ),
        (
            SystemRegister::TTBR0_EL2,
            SystemRegister::TCR_EL2,
            SystemRegister::MAIR_EL2,
            SystemRegister::SCTLR_EL2,
        ),
    ] {
        registers.set(table, 0, BASE + TABLE as u64);
        registers.set(control, 0, TCR);
        registers.set(attributes, 0, 0xff);
        let value = registers.get(sctlr, 0) | SCTLR_M_C;
        registers.set(sctlr, 0, value);
    }
    machine.translations_changed();
}

/// [`machine`] with `devices` and the PEs of `processors`.
pub(super) fn board<D: Devices>(
    words: &[u32],
    devices: D,
    processors: Vec<stela_contracts::identity::Identity>,
) -> Machine<FakeHost, D> {
    board_on(crate::machine::test_chip(), words, devices, processors)
}

/// [`board`] on `chip`.
pub(super) fn board_on<D: Devices>(
    chip: stela_contracts::Chip,
    words: &[u32],
    devices: D,
    processors: Vec<stela_contracts::identity::Identity>,
) -> Machine<FakeHost, D> {
    let mut ram = vec![0u8; 0x10000];
    for (index, word) in words.iter().enumerate() {
        ram[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    let host = FakeHost {
        ram,
        events: Vec::new(),
        base: BASE,
        now: 0,
        regimes: Vec::new(),
        invalidations: 0,
        isolations: 0,
        code_invalidations: Vec::new(),
        reaches: Vec::new(),
        installed: Vec::new(),
        executables: Vec::new(),
        patches: Vec::new(),
        live_patch_start: 0,
        chained: None,
        exits: Vec::new(),
        store: None,
        refused: Vec::new(),
        fetch_checks: 0,
        counter_reads: 0,
        counter_step: 0,
        execute_ticks: 0,
        timers: Vec::new(),
        tsc_counter: None,
        placement: mmu::placement::Placement::FiveLevel,
        translation_helper: None,
        memory_low: false,
        require_empty_code_on_read: false,
        ring: None,
        parts: Vec::new(),
    };
    let profile = CpuProfile {
        name: "test",
        chip,
        counter_frequency: 24_000_000,
        fixed: vec![(registers::encodings::DCZID_EL0, 4)],
        processors,
    };
    Machine::new(
        Cpu::of(chip, BASE, Pstate::reset(1)),
        host,
        devices,
        profile,
        TargetCpu::Baseline,
    )
}

/// Devices whose registers read their own PA's low 32 bits with the
/// top bit set, recording every access in order.
#[derive(Default)]
struct Recorder {
    accesses: Vec<(u64, u8, Option<u64>)>,
}

impl Devices for Recorder {
    fn read(&mut self, _: usize, physical: u64, bytes: u8, _: u64) -> Result<u64, DeviceError> {
        self.accesses.push((physical, bytes, None));
        Ok(0x8000_0000 | (physical & 0xffff))
    }
    fn write(
        &mut self,
        _: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        _: u64,
    ) -> Result<(), DeviceError> {
        self.accesses.push((physical, bytes, Some(value)));
        Ok(())
    }
    fn lines(&mut self, _: usize, _: u64) -> Lines {
        Lines::default()
    }
}

#[test]
fn unsupported_instructions_are_undefined_once_reported() {
    let mut machine = machine(&[]);
    let instruction = |machine: &Machine<_, _>| {
        machine.unsupported(RequirementKind::Instruction {
            word: 0xd500_0000,
            detail: "an instruction the engine lacks".into(),
        })
    };
    for _ in 0..2 {
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.pc = BASE;
        let stop = instruction(&machine);
        machine.undefined_instead(stop).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE);
    }
    assert_eq!(machine.take_unmodeled().len(), 1);
    assert_eq!(machine.statistics.degraded, 2);
    // A stop raised elsewhere than the PE's instruction, or an engine
    // limit with no architectural answer, still stops.
    machine.cpu.set_pstate(Pstate::reset(1));
    machine.cpu.pc = BASE;
    let elsewhere = instruction(&machine);
    machine.cpu.pc = BASE + 4;
    assert!(machine.undefined_instead(elsewhere).is_err());
    let limit = machine.unsupported(RequirementKind::Native("an engine limit"));
    assert!(machine.undefined_instead(limit).is_err());
    assert!(machine.undefined_instead(Stop::Idle).is_err());
}

#[test]
fn a_requirement_names_the_link_register_when_one_is_at_hand() {
    let mut requirement = Requirement {
        pc: 0x10,
        el: 2,
        link: 0x20,
        kind: RequirementKind::Native("absent"),
        syndrome: None,
        address: None,
        written: None,
    };
    assert!(requirement.to_string().starts_with("pc=0x10 el=2 lr=0x20 "));
    requirement.link = 0;
    assert!(!requirement.to_string().contains("lr="));
}

#[test]
fn fetches_outside_memory_take_an_external_abort() {
    const OUTSIDE: u64 = BASE - 0x1000;
    let mut machine = machine(&[]);
    machine.cpu.pc = OUTSIDE;
    let Ok(Fetched::Exception(exception)) = machine.fetch_block(OUTSIDE, false) else {
        panic!("fetches outside memory abort");
    };
    assert_eq!(
        exception.syndrome,
        super::super::exception::syndrome(Class::InstructionAbortSame, SYNCHRONOUS_EXTERNAL_ABORT)
    );
    assert_eq!(exception.fault_address, Some(OUTSIDE));
    assert_eq!(machine.take_unmodeled().len(), 1);
}

#[test]
fn refused_system_registers_act_as_storage_once_reported() {
    // MRS and MSR x0 of S3_4_C15_C13_6, an implementation-defined
    // storage register, and S3_4_C15_C12_0, a control register that
    // takes no set bit (`machine::impdef`).
    const KEY_READ: u32 = 0xd53c_fdc0;
    const CONTROL_READ: u32 = 0xd53c_fc00;
    const CONTROL_WRITE: u32 = 0xd51c_fc00;
    let mut machine = machine_on(stela_contracts::Chip::AppleM2, &[]);
    machine.cpu.set_pstate(Pstate::reset(1));
    let run = |machine: &mut Machine<_, _>, word, x0| {
        machine.cpu.pc = BASE;
        machine.cpu.state.x[0] = x0;
        let step = machine.system_instruction(word);
        (step, machine.cpu.state.x[0])
    };
    // The read before the first write, whose value is unknown, returns
    // 0, and the control holds the setting the model cannot honor
    // without its effect.
    assert_eq!(run(&mut machine, KEY_READ, 0xdead), (Ok(()), 0));
    assert_eq!(machine.cpu.pc, BASE + 4);
    for _ in 0..2 {
        assert_eq!(run(&mut machine, CONTROL_WRITE, 5), (Ok(()), 5));
        assert_eq!(run(&mut machine, CONTROL_READ, 0), (Ok(()), 5));
    }
    // A setting the model accepts returns the register to it.
    assert_eq!(run(&mut machine, CONTROL_WRITE, 0), (Ok(()), 0));
    assert_eq!(run(&mut machine, CONTROL_READ, 7), (Ok(()), 0));
    assert_eq!(machine.take_unmodeled().len(), 2);
    assert_eq!(machine.statistics.degraded, 3);
}

#[test]
fn refused_device_registers_read_zero_and_drop_writes() {
    const DEVICE: u64 = 0x2_3b3c_0a00;
    // ldr x2, [x1]; str x2, [x1]
    let (load, store) = (0xf940_0022, 0xf900_0022);
    let mut devices = pair_fault_device();
    devices.refused = Some(DEVICE);
    let mut machine = board(&[], devices, Vec::new());
    machine.write_register(Register::X(1), DEVICE);
    let esr = machine.cpu.read(SystemRegister::ESR_EL1);
    for (word, write) in [(load, false), (store, true), (load, false)] {
        machine.cpu.pc = BASE;
        machine.write_register(Register::X(2), 0x1234);
        machine.device_access(word, DEVICE, DEVICE, write).unwrap();
        assert_eq!(machine.cpu.pc, BASE + 4);
        let expected = if write { 0x1234 } else { 0 };
        assert_eq!(machine.read_register(Register::X(2)), expected);
    }
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), esr);
    assert!(machine.devices.stores.is_empty());
    // One report per register and direction.
    assert_eq!(machine.take_unmodeled().len(), 2);
}

#[test]
fn survey_substitutes_registers_but_never_dma_service_effects() {
    let mut machine = machine(&[0]);
    machine.begin_survey();
    assert!(!machine.surveyed(
        0x1000,
        4,
        Some(1),
        &DeviceError::TransferRefused("missing DMA/key service".into())
    ));
    assert!(machine.take_survey().is_empty());
    assert!(machine.surveyed(
        0x1000,
        4,
        None,
        &DeviceError::Refused("unknown register".into())
    ));
    assert_eq!(machine.take_survey().len(), 1);
}

#[test]
fn a_device_register_reports_each_refusal_once_up_to_its_first_few() {
    let mut machine = machine(&[0]);
    let mut refuse = |detail: &str| {
        let requirement = machine.requirement(RequirementKind::Device {
            physical: 0x1000,
            write: true,
            detail: detail.into(),
        });
        machine.degrade(requirement);
    };
    for detail in ["one operation", "another", "one operation"] {
        refuse(detail);
    }
    for value in 0..2 * DEVICE_REFUSALS_REPORTED {
        refuse(&format!("value {value}"));
    }
    assert_eq!(
        machine.take_unmodeled().len(),
        DEVICE_REFUSALS_REPORTED,
        "two operations and the first changing values"
    );
}

#[test]
fn unmapped_device_accesses_take_an_external_abort_once_reported() {
    const DEVICE: u64 = 0x2_3d2b_0010;
    // ldr w0, [x1]; str w0, [x1]
    let (load, store) = (0xb940_0020, 0xb900_0020);
    let mut machine = machine(&[0]);
    machine.write_register(Register::X(1), DEVICE);
    for (word, write) in [(load, false), (store, true), (load, false)] {
        machine.cpu.pc = BASE;
        machine.device_access(word, DEVICE, DEVICE, write).unwrap();
        // A data abort at EL1 from EL1: EC 0x25, IL, DFSC 0b010000, WnR.
        let wnr = if write { 1 << 6 } else { 0 };
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x9600_0010 | wnr);
        assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), DEVICE);
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE);
    }
    // One report per register and direction.
    let reports = machine.take_unmodeled();
    assert_eq!(reports.len(), 2);
    assert!(matches!(
        reports[1].kind,
        RequirementKind::Device { write: true, .. }
    ));
    assert!(machine.take_unmodeled().is_empty());
}

#[test]
fn device_pairs_are_two_ascending_accesses_in_register_order() {
    const DEVICE: u64 = 0x2_3b3c_0a00;
    let mut machine = board(&[], Recorder::default(), Vec::new());
    // ldp x2, x3, [x1, #16]!
    machine.write_register(Register::X(1), DEVICE - 16);
    machine
        .device_access(0xa9c1_0c22, DEVICE, DEVICE, false)
        .unwrap();
    assert_eq!(
        machine.devices.accesses,
        [(DEVICE, 8, None), (DEVICE + 8, 8, None)]
    );
    assert_eq!(machine.read_register(Register::X(2)), 0x8000_0a00);
    assert_eq!(machine.read_register(Register::X(3)), 0x8000_0a08);
    assert_eq!(machine.read_register(Register::X(1)), DEVICE);
    assert_eq!(machine.cpu.pc, BASE + 4);
    // ldpsw x2, x3, [x1] sign-extends each word.
    machine.devices.accesses.clear();
    machine
        .device_access(0x6940_0c22, DEVICE, DEVICE, false)
        .unwrap();
    assert_eq!(
        machine.devices.accesses,
        [(DEVICE, 4, None), (DEVICE + 4, 4, None)]
    );
    assert_eq!(machine.read_register(Register::X(3)), 0xffff_ffff_8000_0a04);
    // stp x2, x3, [x1]
    machine.devices.accesses.clear();
    machine
        .device_access(0xa900_0c22, DEVICE, DEVICE, true)
        .unwrap();
    assert_eq!(
        machine.devices.accesses,
        [
            (DEVICE, 8, Some(0xffff_ffff_8000_0a00)),
            (DEVICE + 8, 8, Some(0xffff_ffff_8000_0a04))
        ]
    );
    // A pair whose second element lies on another page is reported once.
    machine.write_register(Register::X(1), DEVICE + 0x5f8);
    machine
        .device_access(0xa940_0c22, DEVICE + 0x5f8, DEVICE + 0x5f8, false)
        .unwrap();
    assert_eq!(machine.take_unmodeled().len(), 1);
}

/// A real register store can start DMA that commits before later failure.
/// This fixture distinguishes refused register writes from failed service.
struct PairFaultDevice {
    refused: Option<u64>,
    failed_transfer: Option<usize>,
    reads: Vec<u64>,
    stores: Vec<(u64, u64)>,
    transfers: usize,
    pair: Option<Result<ConsumedPair, DeviceError>>,
    pair_reads: usize,
}

impl Devices for PairFaultDevice {
    fn read_pair(
        &mut self,
        _: usize,
        _: u64,
        _: u8,
        _: u64,
    ) -> Result<Option<ConsumedPair>, DeviceError> {
        let Some(pair) = self.pair.clone() else {
            return Ok(None);
        };
        self.pair_reads += 1;
        pair.map(Some)
    }
    fn read(&mut self, _: usize, physical: u64, _: u8, _: u64) -> Result<u64, DeviceError> {
        self.reads.push(physical);
        if self.refused == Some(physical) {
            return Err(DeviceError::Refused("injected register refusal".into()));
        }
        Ok(physical)
    }
    fn write(
        &mut self,
        _: usize,
        physical: u64,
        _: u8,
        value: u64,
        _: u64,
    ) -> Result<(), DeviceError> {
        if self.refused == Some(physical) {
            return Err(DeviceError::Refused("injected register refusal".into()));
        }
        self.stores.push((physical, value));
        Ok(())
    }
    fn transfer(&mut self, _: usize, memory: &mut dyn Memory, _: u64) -> Result<(), DeviceError> {
        let index = self.transfers;
        self.transfers += 1;
        let (_, value) = self.stores[index];
        assert!(memory.write(BASE + 0x800 + index as u64 * 8, &value.to_le_bytes()));
        if self.failed_transfer == Some(index) {
            // Use an ordinary register error: the engine
            // knows this came from service and must never survey it.
            return Err(DeviceError::Refused("injected later DMA failure".into()));
        }
        Ok(())
    }
    fn lines(&mut self, _: usize, _: u64) -> Lines {
        Lines::default()
    }
}

fn pair_fault_device() -> PairFaultDevice {
    PairFaultDevice {
        refused: None,
        failed_transfer: None,
        reads: Vec::new(),
        stores: Vec::new(),
        transfers: 0,
        pair: None,
        pair_reads: 0,
    }
}

#[test]
fn device_dma_preflights_the_memory_lock_before_any_copy() {
    let mut machine = board(&[], pair_fault_device(), Vec::new());
    let first = BASE + 0x808;
    let last = BASE + 0x80f;
    let mut memory = HostMemory {
        host: &mut machine.host,
        lock: [Some((first, last)), None, None, None],
    };
    let mut before = [0u8; 32];
    assert!(memory.read(BASE + 0x800, &mut before));
    for (at, bytes) in [(first, 1), (last, 1), (first - 4, 8), (first - 8, 32)] {
        assert!(!memory.write(at, &vec![0xa5; bytes]));
        let mut observed = [0; 32];
        assert!(memory.read(BASE + 0x800, &mut observed));
        assert_eq!(observed, before);
    }
    assert!(memory.write(first - 8, &[0x12; 8]));
    assert!(memory.write(last + 1, &[0x34; 8]));
    let mut observed = [0; 32];
    assert!(memory.read(BASE + 0x800, &mut observed));
    assert_eq!(&observed[..8], &[0x12; 8]);
    assert_eq!(&observed[8..16], &[0; 8]);
    assert_eq!(&observed[16..24], &[0x34; 8]);
    // Reads of locked RAM remain ordinary RAM reads. Address overflow
    // refuses before calling the native copy provider, even without a lock.
    memory.lock = [None; 4];
    assert!(!memory.write(u64::MAX - 1, &[0x56; 4]));
}

#[test]
fn consumed_device_pair_retires_before_reporting_later_board_failure() {
    const DEVICE: u64 = 0x2_3b3c_0a00;
    for survey in [false, true] {
        for writeback in [false, true] {
            let mut devices = pair_fault_device();
            devices.pair = Some(Ok(ConsumedPair {
                values: [0x1234, 0x5678],
                settlement: Err(DeviceError::Refused("retained wire failure".into())),
            }));
            let mut machine = board(&[], devices, Vec::new());
            if survey {
                machine.begin_survey();
            }
            machine.set_watches(&[(DEVICE, 16)]);
            machine.cpu.pstate.btype = 1;
            machine.write_register(Register::X(1), DEVICE - 16);
            machine.write_register(Register::X(8), DEVICE);
            machine.write_register(Register::X(9), 0xdead);
            let esr = machine.cpu.read(SystemRegister::ESR_EL1);
            let elr = machine.cpu.read(SystemRegister::ELR_EL1);
            // Original PTD shape: ldp x8, x9, [x8]. Also cover
            // pre-indexed ldp x2, x3, [x1, #16]! independently.
            let word = if writeback { 0xa9c1_0c22 } else { 0xa940_2508 };
            // The failure is reported once, without aborting or
            // replaying the consumed access.
            machine.device_access(word, DEVICE, DEVICE, false).unwrap();
            let mut reports = machine.take_unmodeled();
            assert_eq!(reports.len(), 1);
            let requirement = reports.remove(0);
            assert_eq!(requirement.pc, BASE);
            assert_eq!(requirement.address, Some(DEVICE));
            assert!(matches!(requirement.kind, RequirementKind::Device {
                        physical: DEVICE, write: false, ref detail
                    } if detail.contains("retained wire failure")));
            assert_eq!(machine.cpu.pc, BASE + 4);
            assert_eq!(machine.cpu.pstate.btype, 0);
            assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), esr);
            assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), elr);
            let data = if writeback { [2, 3] } else { [8, 9] };
            assert_eq!(machine.read_register(Register::X(data[0])), 0x1234);
            assert_eq!(machine.read_register(Register::X(data[1])), 0x5678);
            assert_eq!(
                machine.read_register(Register::X(1)),
                if writeback { DEVICE } else { DEVICE - 16 }
            );
            assert_eq!(machine.devices.pair_reads, 1);
            assert!(machine.devices.reads.is_empty());
            assert!(machine.devices.stores.is_empty());
            assert_eq!(machine.devices.transfers, 0);
            assert!(machine.take_survey().is_empty());
            let hits = machine.take_watch_hits();
            assert_eq!(hits.len(), 2);
            for (index, hit) in hits.iter().enumerate() {
                assert_eq!(hit.pc, BASE);
                assert_eq!(hit.physical, DEVICE + index as u64 * 8);
                assert_eq!(hit.value, [0x1234, 0x5678][index]);
                assert!(hit.completed && !hit.write);
            }
        }
    }
}

#[test]
fn whole_device_pair_refusal_precedes_consumption_and_retirement() {
    const DEVICE: u64 = 0x2_3b3c_0a00;
    let mut devices = pair_fault_device();
    devices.pair = Some(Err(DeviceError::Refused("unknown publication".into())));
    let mut machine = board(&[], devices, Vec::new());
    machine.write_register(Register::X(8), DEVICE);
    machine.write_register(Register::X(9), 0xdead);
    let esr = machine.cpu.read(SystemRegister::ESR_EL1);
    // A register the device refuses reads 0, reported once.
    machine
        .device_access(0xa940_2508, DEVICE, DEVICE, false)
        .unwrap();
    assert_eq!(machine.cpu.pc, BASE + 4);
    assert_eq!(machine.read_register(Register::X(8)), 0);
    assert_eq!(machine.read_register(Register::X(9)), 0);
    assert_eq!(machine.take_unmodeled().len(), 1);
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), esr);
    assert_eq!(machine.devices.pair_reads, 1);
    assert!(machine.devices.reads.is_empty());
}

#[test]
fn device_pair_store_faults_drop_the_refused_member_and_keep_the_rest() {
    const DEVICE: u64 = 0x2_3b3c_0a00;
    for failed_element in 0..2 {
        for service_failure in [false, true] {
            let mut devices = pair_fault_device();
            if service_failure {
                devices.failed_transfer = Some(failed_element);
            } else {
                devices.refused = Some(DEVICE + failed_element as u64 * 8);
            }
            let mut machine = board(&[], devices, Vec::new());
            machine.set_watches(&[(DEVICE, 16)]);
            machine.write_register(Register::X(1), DEVICE - 16);
            machine.write_register(Register::X(2), 0x1234);
            machine.write_register(Register::X(3), 0x5678);
            // stp x2, x3, [x1, #16]!
            machine
                .device_access(0xa981_0c22, DEVICE, DEVICE, true)
                .unwrap();
            let mut reports = machine.take_unmodeled();
            assert_eq!(reports.len(), 1);
            let requirement = reports.remove(0);
            let failed_address = DEVICE + failed_element as u64 * 8;
            assert_eq!(requirement.address, Some(failed_address));
            assert!(
                matches!(requirement.kind, RequirementKind::Device { physical, write: true, .. } if physical == failed_address)
            );
            // The pair completes with its writeback. A refused member is
            // dropped; a member whose service failed keeps its store and
            // the DMA it committed.
            assert_eq!(machine.cpu.pc, BASE + 4);
            assert_eq!(machine.read_register(Register::X(1)), DEVICE);
            let stored: Vec<_> = [(DEVICE, 0x1234u64), (DEVICE + 8, 0x5678)]
                .into_iter()
                .enumerate()
                .filter(|&(index, _)| service_failure || index != failed_element)
                .map(|(_, store)| store)
                .collect();
            assert_eq!(machine.devices.stores, stored);
            assert_eq!(machine.devices.transfers, stored.len());
            let mut ram = [0; 16];
            assert!(machine.host.read_ram(BASE + 0x800, &mut ram));
            let mut expected = [0; 16];
            for (index, &(_, value)) in stored.iter().enumerate() {
                expected[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
            }
            assert_eq!(ram, expected);
            let hits = machine.take_watch_hits();
            assert_eq!(hits.len(), 2);
            assert_eq!(
                hits.iter().filter(|hit| hit.completed).count(),
                stored.len()
            );
            assert!(hits.iter().all(|hit| hit.write));
        }
    }
}

#[test]
fn survey_never_substitutes_a_failed_service_after_an_accepted_scalar_or_pair_store() {
    const DEVICE: u64 = 0x2_3b3c_0a00;
    for (word, members) in [(0xb900_0022, 1), (0xa900_0c22, 2)] {
        // str w2 / stp x2, x3, [x1]
        let mut devices = pair_fault_device();
        devices.failed_transfer = Some(0);
        let mut machine = board(&[], devices, Vec::new());
        machine.begin_survey();
        machine.write_register(Register::X(1), DEVICE);
        machine.write_register(Register::X(2), 0x1234);
        machine.write_register(Register::X(3), 0x5678);
        // The accepted store and the DMA it started stand, and the failed
        // service is reported once.
        machine.device_access(word, DEVICE, DEVICE, true).unwrap();
        assert_eq!(machine.take_unmodeled().len(), 1);
        assert_eq!(machine.cpu.pc, BASE + 4);
        assert_eq!(
            machine.devices.stores,
            [(DEVICE, 0x1234), (DEVICE + 8, 0x5678)][..members]
        );
        assert_eq!(machine.devices.transfers, members);
        assert!(machine.take_survey().is_empty());
        let mut committed = [0; 8];
        assert!(machine.host.read_ram(BASE + 0x800, &mut committed));
        assert_eq!(u64::from_le_bytes(committed), 0x1234);
    }
}

#[test]
fn device_pair_load_refusal_preserves_both_destinations_and_reports_the_failed_member() {
    const DEVICE: u64 = 0x2_3b3c_0a00;
    for failed_element in 0..2 {
        let failed_address = DEVICE + failed_element as u64 * 8;
        let mut devices = pair_fault_device();
        devices.refused = Some(failed_address);
        let mut machine = board(&[], devices, Vec::new());
        machine.write_register(Register::X(1), DEVICE - 16);
        machine.write_register(Register::X(2), 0x1234);
        machine.write_register(Register::X(3), 0x5678);
        // ldp x2, x3, [x1, #16]!
        let result = machine.device_access(0xa9c1_0c22, DEVICE, DEVICE, false);
        // The refused member reads 0 and the pair completes.
        result.unwrap();
        let other = DEVICE + (1 - failed_element) as u64 * 8;
        let mut values = [other, other];
        values[failed_element] = 0;
        assert_eq!(machine.read_register(Register::X(1)), DEVICE);
        assert_eq!(machine.read_register(Register::X(2)), values[0]);
        assert_eq!(machine.read_register(Register::X(3)), values[1]);
        assert_eq!(machine.devices.reads.len(), 2);
        let reports = machine.take_unmodeled();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].address, Some(failed_address));
        assert!(machine.devices.stores.is_empty());
    }
}

#[test]
fn watched_device_ranges_record_each_access_and_its_value() {
    const DEVICE: u64 = 0x3_8228_c80c;
    let mut machine = board(&[], Recorder::default(), Vec::new());
    machine.set_watches(&[(0x3_8228_0000, 0x10_0000)]);
    // ldr w2, [x1]; str w2, [x1]
    machine.write_register(Register::X(1), DEVICE);
    machine
        .device_access(0xb940_0022, DEVICE, DEVICE, false)
        .unwrap();
    machine
        .device_access(0xb900_0022, DEVICE, DEVICE, true)
        .unwrap();
    // An access outside every watch is not recorded.
    machine.write_register(Register::X(1), 0x2_3b3c_0a00);
    machine
        .device_access(0xb940_0022, 0x2_3b3c_0a00, 0x2_3b3c_0a00, false)
        .unwrap();
    let hits = machine.take_watch_hits();
    assert_eq!(
        hits.iter()
            .map(|hit| (hit.physical, hit.bytes, hit.value, hit.write, hit.completed))
            .collect::<Vec<_>>(),
        [
            (DEVICE, 4, 0x8000_c80c, false, true),
            (DEVICE, 4, 0x8000_c80c, true, true)
        ]
    );
    assert!(machine.take_watch_hits().is_empty());
}

#[test]
fn host_breakpoints_end_blocks_and_stop_before_their_instruction() {
    // add x0, x0, #1 (three times); svc #0
    let add = 0x9100_0400;
    let mut machine = machine(&[add, add, add, 0xd400_0001]);
    machine.set_breakpoints(&[BASE + 8]);
    let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
        panic!("block")
    };
    assert_eq!(machine.blocks[index].source_map.len(), 2);
    machine.cpu.pc = BASE + 8;
    assert!(matches!(machine.step(), Err(Stop::Breakpoint(pc)) if pc == BASE + 8));
    assert_eq!(machine.cpu.state.x[0], 0);
}

#[test]
fn trace_points_end_blocks_and_record_each_entry_without_stopping() {
    // add x0, x0, #1 (twice); fmov d0, d0, which traps with FP access
    // disabled, so the step completes without native code.
    let add = 0x9100_0400;
    let mut machine = machine(&[add, add, 0x1e60_4000]);
    machine.set_traces(&[BASE + 8]);
    let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
        panic!("block")
    };
    assert_eq!(machine.blocks[index].source_map.len(), 2);
    machine.cpu.pc = BASE + 8;
    machine.cpu.state.x[0] = 7;
    machine.step().unwrap();
    let hits = machine.take_trace_hits();
    assert_eq!(hits.len(), 1);
    assert_eq!((hits[0].pc, hits[0].arguments[0]), (BASE + 8, 7));
    assert_ne!(machine.cpu.pc, BASE + 8, "the step went on, to the FP trap");
    assert!(machine.take_trace_hits().is_empty());
    for _ in 0..TRACE_HITS + 3 {
        machine.trace(BASE);
    }
    let hits = machine.take_trace_hits();
    assert_eq!((hits.len(), hits[TRACE_HITS - 1].dropped), (TRACE_HITS, 3));
}

#[test]
fn unavailable_extended_fault_state_cannot_partially_recover_or_retire() {
    use stela_compiler::block::{
        FaultRecoveryError, HostGprSnapshot, RecoveryBinding, RecoverySiteKind,
    };
    let mut machine = machine(&[0x9100_0400, 0xf9400043, 0xd400_0001]);
    let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
        panic!("prepared block");
    };
    machine.cpu.state.x[0] = 11;
    machine.cpu.state.x[1] = 22;
    let before = machine.cpu.state.clone();
    let pc = machine.cpu.pc;
    let retired = machine.cpu.retired;
    // Corrupt a real, minted operand row to exercise atomic capture refusal;
    // no test-only constructor invents a guest site at internal code.
    let row = machine
        .fault_recovery
        .get_mut(&index)
        .unwrap()
        .test_rows_mut()
        .iter_mut()
        .find(|row| row.site.kind() == RecoverySiteKind::GuestAccess)
        .unwrap();
    row.bindings = vec![RecoveryBinding::gpr(0, 0), RecoveryBinding::gpr(1, 16)];
    let offset = row.start;
    let stopped = machine.native_fault(
        index,
        NativeFault {
            origin: crate::machine::NativeFaultOrigin::Exception,
            trap: 14,
            error_code: 0,
            spills: stela_compiler::block::HostSpillSnapshot::new(),
            offset,
            address: 0x40,
            write: false,
            cause: FaultCause::NonCanonical,
            registers: HostGprSnapshot::legacy([99; 16]),
        },
        0,
        None,
    );
    assert!(matches!(
        stopped,
        Err(Stop::NativeFailure(ref failure)) if failure.reason == NativeFailureReason::Recovery(
            FaultRecoveryError::ExtendedStateUnavailable { register: 16 }
        )
    ));
    assert_eq!(machine.cpu.state, before);
    assert_eq!(machine.cpu.pc, pc);
    assert_eq!(machine.cpu.retired, retired);
    assert_eq!(
        machine.run(1),
        stopped.unwrap_err(),
        "terminal failure cannot resume the partial frame"
    );
    assert_eq!(machine.cpu.state, before);
    assert_eq!(machine.cpu.retired, retired);
}

#[test]
fn compiles_blocks_through_the_page_and_reports_unsupported_words() {
    // add x0, x0, #1; svc #0
    let mut machine = machine(&[0x9100_0400, 0xd400_0001]);
    let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
        panic!("block")
    };
    assert_eq!(machine.blocks[index].source_map.len(), 2);
    assert_eq!(machine.statistics.compiled, 1);
    assert!(matches!(machine.fetch_block(BASE, false), Ok(Fetched::Block(i)) if i == index));
    assert_eq!(machine.statistics.compiled, 1, "cached");
    // An SVE instruction compiles as the UDF it is on a chip without SVE
    // or SME, such as the M2.
    let mut machine = machine_on(stela_contracts::Chip::AppleM2, &[0x9100_0400, 0x04a0_0000]);
    let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
        panic!("block with UDF")
    };
    assert_eq!(machine.blocks[index].source_map.len(), 2);
    // On the M4, whose SME has it in streaming mode, the block ends
    // before it, and the engine applies its access checks on its own.
    let mut machine = machine_on(stela_contracts::Chip::AppleM4, &[0x9100_0400, 0x04a0_0000]);
    let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
        panic!("prefix block")
    };
    assert_eq!(machine.blocks[index].source_map.len(), 1);
    assert!(matches!(
        machine.fetch_block(BASE + 4, false),
        Ok(Fetched::Checked(0x04a0_0000))
    ));
}

#[test]
fn pstate_dit_selects_blocks_compiled_for_the_data_independent_timing_target() {
    const LDADD_W1_W0_X2: u32 = 0xb821_0040;
    const SVC_0: u32 = 0xd400_0001;
    const LOCK_XADD: [u8; 3] = [0xf0, 0x0f, 0xc1];
    // add r8d,ecx; mov [rdx],r8d: the plain update and store.
    const PLAIN_ADD_STORE: [u8; 6] = [0x41, 0x01, 0xc8, 0x44, 0x89, 0x02];
    let has = |machine: &Machine<FakeHost, NoDevices>, index: usize, bytes: &[u8]| {
        let code = &machine.host.installed[machine.blocks[index].code.0 / NATIVE_CODE_STRIDE - 1];
        code.windows(bytes.len()).any(|window| window == bytes)
    };
    let mut machine = machine(&[LDADD_W1_W0_X2, SVC_0]);
    // Without a host that gives the guarantee, PSTATE.DIT changes no code,
    // whose atomics lock for the PEs that run concurrently.
    machine.cpu.pstate.dit = true;
    let Ok(Fetched::Block(untimed)) = machine.fetch_block(BASE, false) else {
        panic!("block")
    };
    assert!(!machine.blocks[untimed].variant.timing);
    assert!(has(&machine, untimed, &LOCK_XADD) && !has(&machine, untimed, &PLAIN_ADD_STORE));
    machine.cpu.pstate.dit = false;
    assert!(matches!(machine.fetch_block(BASE, false), Ok(Fetched::Block(i)) if i == untimed));
    // With one, PSTATE.DIT selects a block of its own, of plain accesses
    // (LOCK has no listed timing), which load first and so report WnR as
    // Arm requires: such a host runs one PE at a time.
    machine.target = TargetCpu::DATA_INDEPENDENT_TIMING_TIERS[2].with_doit();
    machine.cpu.pstate.dit = true;
    let Ok(Fetched::Block(timed)) = machine.fetch_block(BASE, false) else {
        panic!("timed block")
    };
    assert_ne!(timed, untimed);
    assert!(machine.blocks[timed].variant.timing);
    assert!(has(&machine, timed, &PLAIN_ADD_STORE) && !has(&machine, timed, &LOCK_XADD));
    machine.cpu.pstate.dit = false;
    assert!(matches!(machine.fetch_block(BASE, false), Ok(Fetched::Block(i)) if i == untimed));
}

#[test]
fn sctlr_sa_selects_blocks_with_or_without_the_sp_alignment_check() {
    const SP_CHECK: [u8; 6] = [0xa8, 15, 0x74, 2, 0x0f, 0x0b];
    // ldr x0, [sp, #8]; svc #0
    let mut machine = machine(&[0xf940_07e0, 0xd400_0001]);
    let has_check = |machine: &Machine<FakeHost, NoDevices>, index: usize| {
        let code = &machine.host.installed[machine.blocks[index].code.0 / NATIVE_CODE_STRIDE - 1];
        code.windows(SP_CHECK.len()).any(|bytes| bytes == SP_CHECK)
    };
    let sctlr = machine.cpu.read(SystemRegister::SCTLR_EL1) | 1 << 3;
    machine
        .cpu
        .registers
        .set(SystemRegister::SCTLR_EL1, 0, sctlr);
    machine.derived_changed();
    let Ok(Fetched::Block(checked)) = machine.fetch_block(BASE, false) else {
        panic!("checked block")
    };
    assert!(machine.blocks[checked].checks.stack_alignment && has_check(&machine, checked));
    machine
        .cpu
        .registers
        .set(SystemRegister::SCTLR_EL1, 0, sctlr & !(1 << 3));
    machine.derived_changed();
    let Ok(Fetched::Block(unchecked)) = machine.fetch_block(BASE, false) else {
        panic!("unchecked block")
    };
    assert_ne!(checked, unchecked);
    assert!(!machine.blocks[unchecked].checks.stack_alignment && !has_check(&machine, unchecked));
    assert!(stack_based(0xf940_07e0) && !stack_based(0xf940_0020));
    assert!(!stack_based(0x5800_003f), "a literal load has no base");
}

#[test]
fn native_alignment_checks_take_the_alignment_fault_of_the_access() {
    const SCTLR_A: u64 = 1 << 1;
    const SCTLR_NAA: u64 = 1 << 6;
    // ldr x0, [x1]; ldp w2, w3, [x1]; ldadd x4, x5, [x1]; stlr w6, [x1];
    // ld1 {v0.8h}, [x1]
    let words = [
        0xf940_0020,
        0x2940_0c22,
        0xf824_0025,
        0x889f_fc26,
        0x4c40_7420,
    ];
    let mut machine = machine(&words);
    machine
        .cpu
        .registers
        .set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
    machine
        .cpu
        .registers
        .set(SystemRegister::CPACR_EL1, 0, 0b11 << 20);
    machine
        .cpu
        .registers
        .set(SystemRegister::CPTR_EL2, 0, 0b11 << 20);
    let sctlr = machine.cpu.read(SystemRegister::SCTLR_EL1) & !(SCTLR_A | SCTLR_NAA);
    let ud = NativeExit::Fault(NativeFault {
        origin: crate::machine::NativeFaultOrigin::Exception,
        trap: 6,
        error_code: 0,
        spills: stela_compiler::block::HostSpillSnapshot::new(),
        registers: stela_compiler::block::HostGprSnapshot::legacy([0; 16]),
        offset: 0,
        address: 0,
        write: false,
        cause: FaultCause::InvalidOpcode,
    });
    // Run the word at `index` from X1 = `address` under SCTLR_EL1 bits
    // `extra`, its native check failing; ESR_EL1 and FAR_EL1 after it.
    let mut run = |index: u64, address: u64, extra: u64| {
        machine
            .cpu
            .registers
            .set(SystemRegister::SCTLR_EL1, 0, sctlr | extra);
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.derived_changed();
        machine.cpu.pc = BASE + 4 * index;
        machine.cpu.state.x[1] = address;
        let offset = native_fault_site(
            &mut machine,
            BASE + 4 * index,
            stela_compiler::block::RecoverySiteKind::GuestCheck,
        );
        let NativeExit::Fault(mut fault) = ud else {
            unreachable!()
        };
        fault.offset = offset;
        machine.host.exits.push(NativeExit::Fault(fault));
        let outcome = machine.step();
        (
            outcome.map(|()| {
                assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE + 4 * index);
                (
                    machine.cpu.read(SystemRegister::ESR_EL1),
                    machine.cpu.read(SystemRegister::FAR_EL1),
                )
            }),
            machine.blocks.iter().last().map(|block| block.checks),
        )
    };
    // EC 0x25 with IL and DFSC 0b100001; WnR for a store.
    let load = 0x9600_0021;
    let store = load | 1 << 6;
    // Under SCTLR.A every unaligned access faults at its first element.
    let (outcome, checks) = run(0, BASE + 0x104, SCTLR_A);
    assert_eq!(outcome.unwrap(), (load, BASE + 0x104));
    assert!(checks.unwrap().alignment);
    assert_eq!(
        run(1, BASE + 0x102, SCTLR_A).0.unwrap(),
        (load, BASE + 0x102)
    );
    assert_eq!(
        run(4, BASE + 0x101, SCTLR_A).0.unwrap(),
        (load, BASE + 0x101)
    );
    // An atomic crossing its 16-byte granule faults without SCTLR.A, and
    // its fault is not a write.
    assert_eq!(run(2, BASE + 0x10c, 0).0.unwrap(), (load, BASE + 0x10c));
    // So does an ordered access with nAA clear; a store-release is a write.
    assert_eq!(run(3, BASE + 0x10e, 0).0.unwrap(), (store, BASE + 0x10e));
    // With nAA set the access completes natively; a failed check would
    // have no fault to take, and stops.
    let (outcome, checks) = run(3, BASE + 0x10e, SCTLR_NAA);
    assert!(matches!(outcome, Err(Stop::Unsupported(_))));
    assert!(!checks.unwrap().ordered_granule);
    // An address outside both ranges, such as Stela's window, takes the
    // fault of its translation: with the MMU off, an Address size fault
    // at level 0 (DFSC 0). An Alignment fault still comes first.
    const WINDOW: u64 = 0x0040_0000_0000_0000;
    for index in 0..5 {
        let write = if index == 3 { 1 << 6 } else { 0 };
        assert_eq!(
            run(index, WINDOW, 0).0.unwrap(),
            (0x9600_0000 | write, WINDOW),
            "{index}"
        );
    }
    assert_eq!(run(0, WINDOW + 4, SCTLR_A).0.unwrap(), (load, WINDOW + 4));
}

/// On a four-level host, an access to an address the guest maps below
/// the native upper range, where Stela's window is, runs its page in
/// the translated variant from the faulting instruction; the same
/// address is native under LA57, and a host without the translation
/// helper stops explicitly.
#[test]
fn a_mapped_address_outside_the_native_ranges_runs_its_page_translated() {
    // TTBR1_EL1 at 47 bits with a 4 KiB granule: L0 entry 0, then a
    // 1 GiB block of L1 entry 0, maps the upper half's first GiB to RAM.
    const LEVEL0: u64 = 0xd000;
    const LEVEL1: u64 = 0xe000;
    const TCR: u64 = 25
        | 1 << 8
        | 1 << 10
        | 3 << 12
        | 17 << 16
        | 1 << 24
        | 1 << 26
        | 3 << 28
        | 0b10 << 30
        | 5 << 32;
    const ADDRESS: u64 = mmu::placement::UPPER_HALF + 0x100;
    let setup = || {
        let mut machine = machine(&[0xf940_0020]); // ldr x0, [x1]
        normal_memory(&mut machine, false);
        let table = |machine: &mut Machine<FakeHost, NoDevices>, at: u64, entry: u64| {
            let at = at as usize;
            machine.host.ram[at..at + 8].copy_from_slice(&entry.to_le_bytes());
        };
        table(&mut machine, LEVEL0, (BASE + LEVEL1) | 0b11);
        table(&mut machine, LEVEL1, BASE | 1 << 10 | 3 << 8 | 0b01);
        machine
            .cpu
            .registers
            .set(SystemRegister::TTBR1_EL1, 0, BASE + LEVEL0);
        machine.cpu.registers.set(SystemRegister::TCR_EL1, 0, TCR);
        machine.translations_changed();
        machine
    };
    let mut machine = setup();
    let outside = |cause, offset| {
        NativeExit::Fault(NativeFault {
            origin: crate::machine::NativeFaultOrigin::Exception,
            trap: if matches!(cause, FaultCause::InvalidOpcode) {
                6
            } else {
                13
            },
            error_code: 0,
            spills: stela_compiler::block::HostSpillSnapshot::new(),
            registers: stela_compiler::block::HostGprSnapshot::legacy([0; 16]),
            offset,
            address: 0,
            write: false,
            cause,
        })
    };
    let run = |machine: &mut Machine<FakeHost, NoDevices>, cause, kind| {
        machine.cpu.pc = BASE;
        machine.cpu.state.x[1] = ADDRESS;
        let offset = native_fault_site(machine, BASE, kind);
        machine.host.exits.push(outside(cause, offset));
        machine.step()
    };
    // LA57 has no intentional range-check UD2 here. An illegal Host
    // opcode at the operand is terminal, not a graceful guest check.
    let stop = run(
        &mut machine,
        FaultCause::InvalidOpcode,
        stela_compiler::block::RecoverySiteKind::GuestAccess,
    )
    .unwrap_err();
    assert!(
        matches!(&stop, Stop::NativeFailure(failure) if failure.reason == NativeFailureReason::TrapSiteMismatch)
    );
    assert_eq!(machine.run(1), stop);
    // Continue the unchanged valid four-level cases with a fresh identical
    // frame; a terminal partial frame can never be reset into execution.
    let mut machine = setup();
    // Four-level without the helper.
    machine.host.placement = mmu::placement::Placement::four_level(2).unwrap();
    machine.derived_changed();
    let Err(Stop::Unsupported(requirement)) = run(
        &mut machine,
        FaultCause::InvalidOpcode,
        stela_compiler::block::RecoverySiteKind::GuestCheck,
    ) else {
        panic!("an explicit stop")
    };
    assert_eq!(requirement.address, Some(ADDRESS));
    assert_eq!(machine.statistics.translated_pages, 0);
    // Four-level blocks check the four-level ranges.
    let check = machine.host.placement.check();
    let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
        panic!("block")
    };
    assert_eq!(machine.blocks[index].checks.range, check);
    // With the helper, a range check's #UD and an elided access's #GP
    // alike run the page in the translated variant.
    const HELPER: u64 = 0x1000;
    machine.host.translation_helper = Some(HELPER);
    for cause in [FaultCause::InvalidOpcode, FaultCause::NonCanonical] {
        machine.translated_pages.clear();
        let kind = if matches!(cause, FaultCause::InvalidOpcode) {
            stela_compiler::block::RecoverySiteKind::GuestCheck
        } else {
            stela_compiler::block::RecoverySiteKind::GuestAccess
        };
        run(&mut machine, cause, kind).unwrap();
        assert_eq!(machine.cpu.pc, BASE, "{cause:?}");
        assert_eq!(machine.first_translated(), Some((BASE, ADDRESS)));
        let current = machine.current_variant(false, false);
        assert!(!machine.page_variant(current, BASE + FETCH_PAGE).translated);
        let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
            panic!("block")
        };
        let block = &machine.blocks[index];
        assert!(block.variant.translated, "{cause:?}");
        assert_eq!(
            block.checks,
            current.checks.with_translation(HELPER),
            "{cause:?}"
        );
        // Its failed check calls the helper through the slot.
        let mut call = vec![0x48, 0xa1]; // movabs rax, [HELPER]
        call.extend(HELPER.to_le_bytes());
        let code = &machine.host.installed[block.code.0 / NATIVE_CODE_STRIDE - 1];
        assert!(code.windows(call.len()).any(|bytes| bytes == call));
    }
    assert_eq!(machine.statistics.translated_pages, 2);
    // The translated body replaces failed range checks with helper calls;
    // no intentional UD2 exists. A Host #UD remains terminal.
    let stop = run(
        &mut machine,
        FaultCause::InvalidOpcode,
        stela_compiler::block::RecoverySiteKind::GuestAccess,
    )
    .unwrap_err();
    assert!(
        matches!(&stop, Stop::NativeFailure(failure) if failure.reason == NativeFailureReason::TrapSiteMismatch)
    );
    assert_eq!(machine.run(1), stop);
}

/// System-mode blocks check every access against the guest's ranges,
/// whatever SCTLR_ELx asks.
#[test]
fn system_mode_blocks_check_accesses_against_the_guest_ranges() {
    const CHECK: [u8; 16] = [
        0x48, 0x89, 0xc1, 0x48, 0xc1, 0xf9, 48, 0xff, 0xc1, 0x83, 0xf9, 0x01, 0x76, 0x02, 0x0f,
        0x0b,
    ];
    // ldr x0, [x1]; svc #0
    let mut machine = machine(&[0xf940_0020, 0xd400_0001]);
    let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
        panic!("block")
    };
    let code = &machine.host.installed[machine.blocks[index].code.0 / NATIVE_CODE_STRIDE - 1];
    assert!(code.windows(CHECK.len()).any(|bytes| bytes == CHECK));
}

impl Machine<FakeHost, NoDevices> {
    fn system_instruction_for_test(&mut self, word: u32) {
        self.pointer_authentication(word).unwrap();
    }
}

#[test]
fn untimed_dispatch_skips_dma_clock_but_guest_counter_reads_stay_fresh() {
    let mut machine = machine(&[]);
    machine.lines();
    machine.breakpoints.push(BASE);
    let reads = machine.host.counter_reads;
    for now in [10, 20, 30] {
        machine.host.now = now;
        assert_eq!(machine.step(), Err(Stop::Breakpoint(BASE)));
        assert_eq!(machine.host.counter_reads, reads);
    }
    machine.system_instruction(0xd53b_e041).unwrap(); // mrs x1, cntvct_el0
    assert_eq!(machine.cpu.state.x[1], 30);
    machine.host.now = 40;
    machine.system_instruction(0xd53b_e041).unwrap();
    assert_eq!(machine.cpu.state.x[1], 40);
    assert_eq!(machine.host.counter_reads, reads + 2);
}

#[test]
fn dispatch_still_reads_time_for_timer_lines_without_dma() {
    let mut machine = machine_on(one_timer_bank(), &[]);
    machine.lines();
    machine.breakpoints.push(BASE);
    machine
        .cpu
        .registers
        .set(SystemRegister::CNTV_CVAL_EL0, 0, 10);
    machine
        .cpu
        .registers
        .set(SystemRegister::CNTV_CTL_EL0, 0, 1);
    machine.timers = None;
    let reads = machine.host.counter_reads;
    machine.host.now = 9;
    assert_eq!(machine.step(), Err(Stop::Breakpoint(BASE)));
    assert_eq!(machine.host.counter_reads, reads + 1);
    assert!(!machine.lines().fiq);
    machine.host.now = 10;
    assert_eq!(machine.step(), Err(Stop::Breakpoint(BASE)));
    assert!(machine.lines().fiq); // Apple's generic timer FIQ remains masked.
}

#[test]
fn interrupt_lines_read_the_count_only_when_a_deadline_needs_it() {
    let mut machine = machine(&[]);
    assert_eq!(machine.lines(), Lines::default());
    let reads = machine.host.counter_reads;
    // No device deadline, timer or PMI: the cached answer stands.
    assert_eq!(machine.lines(), Lines::default());
    assert_eq!(machine.host.counter_reads, reads);
    // An enabled, unmasked virtual timer due at count 10.
    machine
        .cpu
        .registers
        .set(SystemRegister::CNTV_CVAL_EL0, 0, 10);
    machine
        .cpu
        .registers
        .set(SystemRegister::CNTV_CTL_EL0, 0, 1);
    machine.timers = None;
    machine.host.now = 0;
    machine.lines();
    assert_eq!(machine.host.counter_reads, reads + 1);
}

#[test]
fn a_fetch_the_host_refuses_takes_a_permission_instruction_abort() {
    // add x0, x0, #1; svc #0
    let mut machine = machine(&[0x9100_0400, 0xd400_0001]);
    assert!(matches!(
        machine.fetch_block(BASE, false),
        Ok(Fetched::Block(_))
    ));
    assert_eq!(machine.host.fetch_checks, 1);
    // The view changes: until the engine hears so, the cached
    // translation stands and the host is not asked.
    machine.host.refused.push(BASE);
    assert!(matches!(
        machine.fetch_block(BASE, false),
        Ok(Fetched::Block(_))
    ));
    assert_eq!(machine.host.fetch_checks, 1);
    machine.fetch_permissions_changed();
    let Ok(Fetched::Exception(exception)) = machine.fetch_block(BASE, false) else {
        panic!("an instruction abort")
    };
    let permission = mmu::Fault::stage1(mmu::FaultKind::Permission, HOST_REFUSED_FETCH_LEVEL);
    assert_eq!(
        exception.syndrome,
        super::super::exception::syndrome(
            Class::InstructionAbortSame,
            permission.instruction_syndrome()
        )
    );
    assert_eq!(exception.fault_address, Some(BASE));
    assert_eq!(machine.host.fetch_checks, 2);
    // Permitted again: the block runs once more.
    machine.host.refused.clear();
    machine.fetch_permissions_changed();
    assert!(matches!(
        machine.fetch_block(BASE, false),
        Ok(Fetched::Block(_))
    ));
}

#[test]
fn svc_eret_and_system_registers_follow_the_architecture() {
    let mut machine = machine(&[]);
    machine
        .cpu
        .registers
        .set(SystemRegister::VBAR_EL1, 0, 0xffff_0000_0000_0000);
    // msr vbar_el1, x1 then svc #0x42, both at EL1h.
    machine.cpu.state.x[1] = 0x1_0000;
    machine.system_instruction(0xd518_c001).unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::VBAR_EL1), 0x1_0000);
    machine.system_instruction(0xd400_0841).unwrap();
    assert_eq!(machine.cpu.pc, 0x1_0200);
    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE + 8);
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x5600_0042);
    // ERET to EL0t at ELR.
    machine.cpu.registers.set(SystemRegister::SPSR_EL1, 0, 0);
    machine.system_instruction(0xd69f_03e0).unwrap();
    assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 8, 0));
    assert_eq!(machine.host.regimes.last().unwrap().requester.el, 0);
    // EL0 cannot read TPIDR_EL1: UNDEFINED to the lower-EL group.
    machine.system_instruction(0xd538_d080).unwrap();
    assert_eq!(machine.cpu.pc, 0x1_0400);
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
    // An IMPDEF register no censused component accesses (S3_5_C15_C15_7)
    // is UNDEFINED, as an unallocated encoding.
    let unconsumed = Encoding::new(3, 5, 15, 15, 7);
    assert!(!crate::machine::impdef::consumed(
        unconsumed,
        machine.cpu.registers.chip()
    ));
    machine.system_instruction(0xd53d_ffe0).unwrap();
    assert_eq!(machine.cpu.pc, 0x1_0200);
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
    // The M2 kernel's JIT box: its range (S3_4_C15_C15_1) and mode
    // (S3_4_C15_C15_4) are held. A mode that enables the box, whose
    // enforcement is undocumented, is reported once.
    let mut machine = machine_on(stela_contracts::Chip::AppleM2, &[]);
    machine.cpu.set_pstate(Pstate::reset(1));
    machine.cpu.pc = BASE;
    machine.cpu.state.x[0] = 0x0000_0001_0200_0006;
    machine.system_instruction(0xd51c_ff20).unwrap();
    assert_eq!(machine.cpu.pc, BASE + 4);
    machine.cpu.state.x[0] = 0x061e_0c5b;
    for _ in 0..2 {
        machine.system_instruction(0xd51c_ff80).unwrap();
    }
    assert_eq!(machine.cpu.pc, BASE + 12);
    let reports = machine.take_unmodeled();
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(reports[0].syndrome, Some(0x6239_3c1e));
    assert!(machine.take_unmodeled().is_empty());
}

#[test]
fn a_guest_hypervisor_under_nv_traps_eret_sees_el2_and_reaches_vncr_memory() {
    const ERET: u32 = 0xd69f_03e0;
    const SVC: u32 = 0xd400_0001;
    const MRS_X0_HCRX_EL2: u32 = 0xd53c_1240;
    const NV: u64 = 1 << 42;
    const NV2: u64 = 1 << 45;
    let chip = stela_contracts::Chip::AppleM3;
    let mut machine = machine_on(chip, &[]);
    let registers = &mut machine.cpu.registers;
    registers.set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
    registers.set(SystemRegister::VBAR_EL2, 0, 0x2_0000);
    registers.set(SystemRegister::HCR_EL2, 0, NV | 1 << 43);
    // NV1 is RAZ/WI on the chips with FEAT_NV.
    let nested = NV | 1 << 43 | NV2;
    assert_eq!(machine.cpu.read(SystemRegister::HCR_EL2) & nested, NV);
    // ERET at EL1 traps to EL2: EC 0x1A, ISS 0.
    machine.system_instruction(ERET).unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL2), 0x6a00_0000);
    assert_eq!(machine.cpu.pstate.el, 2);
    // An SVC taken from EL1 to EL1 records EL2h in SPSR_EL1.M.
    machine.cpu.set_pstate(Pstate::reset(1));
    machine.system_instruction(SVC).unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::SPSR_EL1) & 0xf, 0b1001);
    // With NV2, MRS HCRX_EL2 at EL1 loads VNCR_EL2 + 0xA0 instead, here
    // through the flat EL2&0 regime.
    machine.cpu.set_pstate(Pstate::reset(1));
    machine
        .cpu
        .registers
        .set(SystemRegister::HCR_EL2, 0, NV | NV2);
    machine
        .cpu
        .registers
        .set(SystemRegister::VNCR_EL2, 0, BASE + 0x1000);
    assert!(
        machine
            .host
            .write_ram(BASE + 0x10a0, &0x1234_u64.to_le_bytes())
    );
    machine.system_instruction(MRS_X0_HCRX_EL2).unwrap();
    assert_eq!(machine.cpu.state.x[0], 0x1234);
    // A translation fault on it is an NV2 Data Abort to EL2: EC 0x25 with
    // ISS.VNCR, FAR_EL2 the VNCR address.
    let registers = &mut machine.cpu.registers;
    registers.set(SystemRegister::TCR_EL2, 0, 25);
    registers.set(SystemRegister::TTBR0_EL2, 0, BASE + 0x8000);
    let sctlr = registers.get(SystemRegister::SCTLR_EL2, 0);
    registers.set(SystemRegister::SCTLR_EL2, 0, sctlr | 1);
    machine.derived_changed();
    machine.system_instruction(MRS_X0_HCRX_EL2).unwrap();
    let esr = machine.cpu.read(SystemRegister::ESR_EL2);
    assert_eq!((esr >> 26, esr & 1 << 13 != 0), (0x25, true));
    assert_eq!(machine.cpu.read(SystemRegister::FAR_EL2), BASE + 0x10a0);
    assert_eq!(machine.cpu.pstate.el, 2);
    machine
        .cpu
        .registers
        .set(SystemRegister::SCTLR_EL2, 0, sctlr);
    machine.derived_changed();
    machine.cpu.set_pstate(Pstate::reset(1));
    // Outside RAM the access is reported once.
    machine
        .cpu
        .registers
        .set(SystemRegister::VNCR_EL2, 0, 0x4000_0000);
    machine.system_instruction(MRS_X0_HCRX_EL2).unwrap();
    assert_eq!(machine.take_unmodeled().len(), 1);
    // The M2 has no FEAT_NV: the bits are RES0 and ERET returns.
    let mut machine = machine_on(stela_contracts::Chip::AppleM2, &[]);
    machine
        .cpu
        .registers
        .set(SystemRegister::HCR_EL2, 0, NV | NV2);
    assert_eq!(machine.cpu.read(SystemRegister::HCR_EL2) & (NV | NV2), 0);
    machine
        .cpu
        .registers
        .set(SystemRegister::ELR_EL1, 0, BASE + 0x40);
    machine.cpu.registers.set(SystemRegister::SPSR_EL1, 0, 0x5);
    machine.system_instruction(ERET).unwrap();
    assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 0x40, 1));
}

#[test]
fn all_chip_performance_monitors_count_retirement_and_signal_their_overflow_fiq() {
    for chip in stela_contracts::Chip::ALL {
        let overflow = if chip == stela_contracts::Chip::AppleM1 {
            1u64 << 47
        } else {
            1u64 << 63
        };
        const MSR_PMCR1_X1: u32 = 0xd519_f101;
        const MSR_PMCR0_X2: u32 = 0xd519_f002;
        const MSR_PMC1_X6: u32 = 0xd51a_f106;
        const MRS_X3_PMC1: u32 = 0xd53a_f103;
        const MRS_X4_HCR_EL2: u32 = 0xd53c_1104;
        const MRS_X5_PMC1: u32 = 0xd53a_f105;
        const MRS_X7_PMCR0: u32 = 0xd539_f007;
        const MSR_PMESR1_X9: u32 = 0xd519_f609;
        const MRS_X8_PMC7: u32 = 0xd53a_f708;
        const MSR_PMC7_X6: u32 = 0xd51a_f706;
        const MRS_X8_PMSR: u32 = 0xd539_fd08;
        const ADD: u32 = 0x9100_0400;
        const B_NEXT: u32 = 0x1400_0001;
        const SVC: u32 = 0xd400_0001;
        let mut words = vec![
            MSR_PMCR1_X1,
            MSR_PMCR0_X2,
            ADD,
            ADD,
            B_NEXT,
            MRS_X3_PMC1,
            MRS_X4_HCR_EL2,
        ];
        // The EL1 vectors at BASE + 0x800: current EL, SPx, synchronous.
        words.resize(0xa00 / 4, 0);
        words.extend([MRS_X5_PMC1, SVC]);
        let identity = stela_contracts::identity::Identity {
            // No hardware identity is claimed by this synthetic PMU fixture.
            midr: 0,
            mpidr: 0x8001_0000,
            // Synthetic fixture clock: no board clock is inferred.
            clock: Some(1_000_000_000),
            caches: None,
        };
        let mut machine = board_on(chip, &words, NoDevices, vec![identity]);
        machine
            .cpu
            .registers
            .set(SystemRegister::VBAR_EL1, 0, BASE + 0x800);
        let programmable = matches!(
            chip,
            stela_contracts::Chip::AppleM1 | stela_contracts::Chip::AppleM2
        );
        if programmable {
            machine.cpu.state.x[9] = 0x8c00; // INST_ALL on PMC7 only.
            machine.system_instruction(MSR_PMESR1_X9).unwrap();
            // Configuration precedes this scripted retirement trace.
            machine.cpu.pc = BASE;
        }
        // Fixed counters on all chips; the source-checked M1/M2
        // programmable instruction event counts the same retirements.
        machine.cpu.state.x[1] = 0x30300 | if programmable { 1 << 15 | 1 << 23 } else { 0 };
        let controls = 0x3 | 0x3000 | 0x400 | if programmable { 1 << 7 | 1 << 19 } else { 0 };
        machine.cpu.state.x[2] = controls;
        let run = |machine: &mut Machine<FakeHost, NoDevices>, next_pc, kind: ExitKind| {
            machine.host.exits.push(NativeExit::Exit {
                next_pc,
                kind: kind as u64,
            });
            machine.step().unwrap();
        };
        for pc in [BASE, BASE + 4] {
            run(&mut machine, pc, ExitKind::System);
        }
        // The two ADDs and the branch, then the MRS, which counts itself.
        run(&mut machine, BASE + 20, ExitKind::Direct);
        run(&mut machine, BASE + 20, ExitKind::System);
        assert_eq!(machine.cpu.state.x[3], 4);
        // An UNDEFINED MRS does not retire; the vector's MRS does.
        run(&mut machine, BASE + 24, ExitKind::System);
        assert_eq!(machine.cpu.pc, BASE + 0xa00);
        run(&mut machine, BASE + 0xa00, ExitKind::System);
        assert_eq!(machine.cpu.state.x[5], 5);
        // SVC retires as it takes its exception.
        run(&mut machine, BASE + 0xa04, ExitKind::System);
        run(&mut machine, BASE + 0xa00, ExitKind::System);
        assert_eq!(machine.cpu.state.x[5], 7);
        if programmable {
            machine.system_instruction(MRS_X8_PMC7).unwrap();
            assert_eq!(machine.cpu.state.x[8], 7);
        }
        // Two instructions short of overflow, the PMI asserts as FIQ once
        // they retire, and PMAI reports it.
        machine.cpu.state.x[6] = overflow - 2;
        machine.system_instruction(MSR_PMC1_X6).unwrap();
        assert!(!machine.lines().fiq);
        machine.cpu.retired += 2;
        assert!(machine.lines().fiq);
        machine.system_instruction(MRS_X7_PMCR0).unwrap();
        assert_eq!(machine.cpu.state.x[7], controls | 1 << 11);
        if programmable {
            machine.cpu.state.x[6] = 0;
            machine.system_instruction(MSR_PMC1_X6).unwrap();
            machine.cpu.state.x[6] = overflow - 1;
            machine.system_instruction(MSR_PMC7_X6).unwrap();
            assert!(!machine.lines().fiq);
            machine.cpu.retired += 1;
            assert!(machine.lines().fiq);
            machine.system_instruction(MRS_X8_PMSR).unwrap();
            assert_eq!(machine.cpu.state.x[8], 1 << 7);
        }
    }
}

#[test]
fn a_full_arena_reclaims_its_oldest_part_and_forgets_those_pages() {
    const RET: u32 = 0xd65f_03c0;
    let mut machine = machine(&vec![RET; 4 * FETCH_PAGE as usize / 4]);
    machine.host.ring = Some(2);
    let base = machine.cpu.pc;
    let page = |n: u64| base + n * FETCH_PAGE;
    let pcs = [page(0), page(1), page(0) + 4, page(2), page(3), page(1) + 8];
    let mut slots = Vec::new();
    for pc in pcs {
        let Ok(Fetched::Block(slot)) = machine.fetch_block(pc, false) else {
            panic!("a block at {pc:#x}")
        };
        slots.push(slot);
    }
    // The parts held pages 0 and 1, then page 0 again and page 2; page
    // 3 needed the first part back, whose reclaim forgot pages 0 and 1
    // whole, page 0's block in the second part too, and whose slots
    // took the next blocks.
    let left: Vec<u64> = machine.index.keys().map(|&(pc, ..)| pc).collect();
    assert_eq!(left, [page(1) + 8, page(2), page(3)]);
    assert_eq!(machine.statistics.code_evictions, 1);
    assert_eq!(machine.statistics.code_discards, 0);
    assert_eq!(machine.blocks.len(), 4);
    assert_eq!(&slots[4..], [1, 0]);
}

#[test]
fn a_fetch_that_reclaims_code_looks_up_in_a_new_context() {
    const RET: u32 = 0xd65f_03c0;
    let mut machine = machine(&vec![RET; 3 * FETCH_PAGE as usize / 4]);
    machine.host.ring = Some(1);
    let base = machine.cpu.pc;
    assert!(machine.fetch_block(base, false).is_ok());
    let first = machine.chain.contexts();
    assert!(machine.fetch_block(base + FETCH_PAGE, false).is_ok());
    assert_eq!(machine.chain.contexts(), first);
    // The third part reclaims the first, whose block a lookup entry of
    // the first context names.
    let pc = base + 2 * FETCH_PAGE;
    assert!(machine.fetch_block(pc, false).is_ok());
    assert_eq!(machine.statistics.code_evictions, 1);
    assert_ne!(machine.chain.contexts(), first);
    assert_eq!(
        machine.targets[chain::lookup_slot(pc)].context,
        machine.chain.contexts()[chain::half(pc)]
    );
}

#[test]
fn pressure_reclaims_before_reading_new_compile_input() {
    const RET: u32 = 0xd65f_03c0;
    let mut machine = machine(&vec![RET; FETCH_PAGE as usize / 4 + 1]);
    let base = machine.cpu.pc;
    assert!(machine.fetch_block(base, false).is_ok());
    machine.host.memory_low = true;
    machine.host.require_empty_code_on_read = true;
    assert!(machine.fetch_block(base + FETCH_PAGE, false).is_ok());
    assert_eq!(machine.fault_recovery.len(), 1);
    assert_eq!(machine.statistics.code_discards, 1);
}

#[test]
fn pressure_reclaims_metadata_when_the_next_arena_part_is_empty() {
    const RET: u32 = 0xd65f_03c0;
    let mut machine = machine(&vec![RET; 2 * FETCH_PAGE as usize / 4 + 1]);
    machine.host.ring = Some(16);
    let base = machine.cpu.pc;
    assert!(machine.fetch_block(base, false).is_ok());
    let old_generation = machine.code_generation;
    machine.host.memory_low = true;
    assert!(machine.fetch_block(base + FETCH_PAGE, false).is_ok());
    assert_eq!(machine.fault_recovery.len(), 1);
    assert!(!machine.index.keys().any(|&(pc, ..)| pc == base));
    assert_ne!(machine.code_generation, old_generation);
    // A cached hit adds no compilation scratch and keeps its owner.
    let discarded = machine.statistics.code_discards;
    assert!(machine.fetch_block(base + FETCH_PAGE, false).is_ok());
    assert_eq!(machine.statistics.code_discards, discarded);
    // Continued foreign pressure must not permit unbounded local growth.
    assert!(machine.fetch_block(base + 2 * FETCH_PAGE, false).is_ok());
    assert_eq!(machine.fault_recovery.len(), 1);
    assert_eq!(machine.index.len(), 1);
}

#[test]
fn a_block_installed_while_memory_runs_low_discards_the_others_first() {
    const RET: u32 = 0xd65f_03c0;
    let mut machine = machine(&vec![RET; FETCH_PAGE as usize / 4 + 1]);
    let base = machine.cpu.pc;
    assert!(machine.fetch_block(base, false).is_ok());
    machine.host.memory_low = true;
    assert!(machine.fetch_block(base + FETCH_PAGE, false).is_ok());
    let left: Vec<u64> = machine.index.keys().map(|&(pc, ..)| pc).collect();
    assert_eq!(left, [base + FETCH_PAGE]);
    assert_eq!(machine.statistics.code_discards, 1);
}

#[test]
fn memory_pressure_reclaims_before_each_new_compilation() {
    const RET: u32 = 0xd65f_03c0;
    let mut machine = machine(&vec![RET; 2 * FETCH_PAGE as usize / 4 + 1]);
    let base = machine.cpu.pc;
    assert!(machine.fetch_block(base, false).is_ok());
    machine.host.memory_low = true;
    assert!(machine.fetch_block(base + FETCH_PAGE, false).is_ok());
    // Still low, as another machine's data may keep it: a new compile
    // releases this machine's old owners before allocating more.
    assert!(machine.fetch_block(base + 2 * FETCH_PAGE, false).is_ok());
    assert_eq!(machine.index.len(), 1);
    assert_eq!(machine.statistics.code_discards, 2);
}

#[test]
fn ic_ivau_forgets_its_pages_blocks_and_ic_iallu_every_block() {
    const NOP: u32 = 0xd503_201f;
    const RET: u32 = 0xd65f_03c0;
    const IC_IVAU_X0: u32 = 0xd50b_7520;
    const IC_IALLU: u32 = 0xd508_751f;
    let mut words = vec![NOP; 2 * FETCH_PAGE as usize / 4];
    words[0] = RET;
    words[FETCH_PAGE as usize / 4] = RET;
    let mut machine = machine(&words);
    let base = machine.cpu.pc;
    for pc in [base, base + FETCH_PAGE] {
        assert!(matches!(
            machine.fetch_block(pc, false),
            Ok(Fetched::Block(_))
        ));
    }
    assert_eq!(machine.index.len(), 2);
    machine.cpu.state.x[0] = base + 0x40;
    machine.system_instruction(IC_IVAU_X0).unwrap();
    let left: Vec<u64> = machine.index.keys().map(|&(pc, ..)| pc).collect();
    assert_eq!(left, [base + FETCH_PAGE]);
    assert_eq!(machine.statistics.code_invalidations, 1);
    assert_eq!(machine.statistics.code_discards, 0);
    machine.system_instruction(IC_IALLU).unwrap();
    assert!(machine.index.is_empty() && machine.code_pages.is_empty());
    assert_eq!(machine.statistics.code_discards, 1);
}

/// Two blocks that branch to each other in one page: each direct exit
/// is redirected through a thunk once its successor exists, and a run
/// that chained counts the blocks and instructions it passed through.
#[test]
fn direct_exits_chain_into_their_successors_in_the_page() {
    const ADD: u32 = 0x9100_0400; // add x0, x0, #1
    let mut machine = machine(&[ADD, 0x1400_0002, 0, ADD, 0x17ff_fffc]);
    let base = machine.cpu.pc;
    let direct = |next_pc| NativeExit::Exit {
        next_pc,
        kind: ExitKind::Direct as u64,
    };
    machine.host.exits = vec![direct(base + 12), direct(base), direct(base + 12)];
    machine.step().unwrap();
    assert!(
        machine.host.patches.is_empty(),
        "the successor is not compiled"
    );
    machine.step().unwrap();
    machine.step().unwrap();
    assert_eq!(machine.statistics.links, 2);
    let control = machine.chain.address();
    let (first, second) = (&machine.blocks[0], &machine.blocks[1]);
    // The second block's exit to the first, then the first's to it.
    for (patches, from, to, target, index) in [
        (&machine.host.patches[..2], second, first, base, 0),
        (&machine.host.patches[2..], first, second, base + 12, 1),
    ] {
        let (at, thunk) = &patches[0];
        let expected = chain::thunk(
            *at as u64,
            control,
            2,
            index,
            to.code.0 as u64,
            GuestAddress(target),
            ExitKind::Direct,
        );
        assert_eq!(Some(thunk.clone()), expected);
        // The block's one direct exit ends its code.
        let code = &machine.host.installed[from.code.0 / NATIVE_CODE_STRIDE - 1];
        let site = from.code.0 + code.len() - chain::DIRECT_EXIT_BYTES;
        let jump = chain::jump(site as u64, *at as u64).unwrap().to_vec();
        assert_eq!(patches[1], (site, jump));
        assert!(from.successors.is_empty());
    }
    // The first block chains into the second, which exits to the first.
    let (blocks, retired) = (machine.statistics.blocks, machine.cpu.retired);
    let current = machine.chain.snapshot();
    machine.host.chained = Some((
        machine.chain.address() as *mut ChainControl,
        ChainControl {
            budget: CHAIN_LIMIT - 1,
            retired: 2,
            block: 1,
            linked: 1,
            ..current
        },
    ));
    machine.host.exits = vec![direct(base)];
    machine.step().unwrap();
    assert_eq!(machine.statistics.blocks, blocks + 2);
    assert_eq!(machine.statistics.chained, 1);
    assert_eq!(machine.cpu.retired, retired + 4);
    assert_eq!(machine.cpu.pc, base);
    // A run whose last thunk found no transfer left, wrapping the
    // budget, chained the whole budget.
    let budget = machine.chain_budget();
    let (blocks, chained) = (machine.statistics.blocks, machine.statistics.chained);
    let current = machine.chain.snapshot();
    machine.host.chained = Some((
        machine.chain.address() as *mut ChainControl,
        ChainControl {
            budget: u64::MAX,
            retired: 2 * budget,
            block: 0,
            linked: budget,
            ..current
        },
    ));
    machine.host.exits = vec![direct(base + 12)];
    machine.step().unwrap();
    assert_eq!(machine.statistics.chained, chained + budget);
    assert_eq!(machine.statistics.blocks, blocks + 1 + budget);
    // This original target starts with ADD, which has no guest memory
    // operand. A synthetic Host page fault there is terminal and must not
    // invent an ARM data abort, BTYPE settlement or retired prefix.
    machine.cpu.pc = base;
    machine.cpu.pstate.btype = 0b01;
    let current = machine.chain.snapshot();
    machine.host.chained = Some((
        machine.chain.address() as *mut ChainControl,
        ChainControl {
            budget: CHAIN_LIMIT - 1,
            retired: 2,
            block: 1,
            linked: 1,
            ..current
        },
    ));
    let offset = machine.blocks[1]
        .code
        .0
        .wrapping_sub(machine.blocks[0].code.0);
    machine.host.exits = vec![NativeExit::Fault(NativeFault {
        origin: crate::machine::NativeFaultOrigin::Exception,
        trap: 14,
        error_code: 0,
        spills: stela_compiler::block::HostSpillSnapshot::new(),
        registers: stela_compiler::block::HostGprSnapshot::legacy([0; 16]),
        offset,
        address: 0x40,
        write: false,
        cause: FaultCause::Guest(mmu::Fault::stage1(mmu::FaultKind::Translation, 3)),
    })];
    let before = (
        machine.cpu.pc,
        machine.cpu.retired,
        machine.cpu.read(SystemRegister::ELR_EL1),
        machine.cpu.read(SystemRegister::SPSR_EL1),
    );
    let state = machine.cpu.state.clone();
    let stop = machine.step().unwrap_err();
    assert!(
        matches!(&stop, Stop::NativeFailure(failure) if failure.reason == NativeFailureReason::InternalSite)
    );
    assert_eq!(
        (
            machine.cpu.pc,
            machine.cpu.retired,
            machine.cpu.read(SystemRegister::ELR_EL1),
            machine.cpu.read(SystemRegister::SPSR_EL1)
        ),
        before
    );
    assert_eq!(machine.cpu.state, state);
    assert!(
        matches!(&stop, Stop::NativeFailure(failure) if failure.unsettled_chain.as_ref().is_some_and(|chain| chain.reported_retired == 2))
    );
    assert_eq!(machine.run(1), stop);
    assert_eq!(machine.cpu.state, state);
}

/// A direct exit out of its page and a RET are redirected through
/// lookup thunks at their first exits; every fetch records its block
/// under the context's number, which changes with the generations and
/// the EL and returns with neither changed.
#[test]
fn returns_and_exits_out_of_the_page_go_through_lookup_thunks() {
    const ADD: u32 = 0x9100_0400; // add x0, x0, #1
    const RET: u32 = 0xd65f_03c0;
    let mut words = vec![0; 1026];
    words[0] = 0x1400_0400; // b .+0x1000
    words[1024] = ADD;
    words[1025] = RET;
    let mut machine = machine(&words);
    let base = machine.cpu.pc;
    let far = base + 0x1000;
    let exit = |next_pc, kind: ExitKind| NativeExit::Exit {
        next_pc,
        kind: kind as u64,
    };
    machine.host.exits = vec![exit(far, ExitKind::Direct), exit(base, ExitKind::Return)];
    machine.step().unwrap();
    machine.step().unwrap();
    assert_eq!(
        (machine.statistics.lookups, machine.statistics.links),
        (2, 0)
    );
    // The engine counts the exits it completed by kind.
    let mut kinds = [0; 13];
    kinds[ExitKind::Direct as usize] = 1;
    kinds[ExitKind::Return as usize] = 1;
    assert_eq!(machine.statistics.exit_kinds, kinds);
    // Neither exit had a thunk yet.
    assert_eq!(machine.statistics.lookup_misses, [2, 0, 0, 0, 0]);
    let control = machine.chain.address();
    let (first, second) = (&machine.blocks[0], &machine.blocks[1]);
    assert!(first.successors.is_empty() && first.dynamic_site.is_none());
    assert!(second.dynamic_site.is_none());
    let code = |block: &Block| &machine.host.installed[block.code.0 / NATIVE_CODE_STRIDE - 1];
    // The branch's direct exit, then the RET's exit to RAX, ends each
    // block's code.
    let sites = [
        first.code.0 + code(first).len() - chain::DIRECT_EXIT_BYTES,
        second.code.0 + code(second).len() - chain::DYNAMIC_EXIT_BYTES,
    ];
    let thunks = [
        chain::lookup_thunk(control, 1, Some(GuestAddress(far)), ExitKind::Direct, 0),
        chain::lookup_thunk(control, 2, None, ExitKind::Return, 0),
    ];
    for (index, (site, thunk)) in sites.into_iter().zip(thunks).enumerate() {
        let at = machine
            .host
            .installed
            .iter()
            .position(|installed| Some(installed) == thunk.as_ref())
            .expect("the thunk is installed")
            + 1;
        let at = at * NATIVE_CODE_STRIDE;
        let jump = chain::jump(site as u64, at as u64).unwrap().to_vec();
        assert_eq!(machine.host.patches[index], (site, jump));
    }
    let half = chain::half(base);
    let context = machine.chain.contexts()[half];
    assert_ne!(context, 0);
    for (pc, block) in [(base, 0), (far, 1)] {
        let entry = machine.targets[chain::lookup_slot(pc)];
        let expected = chain::LookupEntry {
            pc,
            context,
            entry: machine.blocks[block].code.0 as u64,
            block: block as u32,
            targets: 0b1111,
        };
        assert_eq!(entry, expected);
    }
    // Another generation numbers the context anew; another EL too, and
    // the same EL and generation give the same number back.
    machine.translations_changed();
    machine.host.exits = vec![exit(far, ExitKind::Direct)];
    machine.step().unwrap();
    let renewed = machine.chain.contexts()[half];
    assert!(renewed > context);
    // The thunk's entry for `far` names the old context.
    assert_eq!(machine.statistics.lookup_misses, [2, 0, 1, 0, 0]);
    let variant = machine.blocks[0].variant;
    let el = machine.cpu.pstate.el;
    assert_eq!(machine.context(el, variant, half), renewed);
    assert_ne!(machine.context(el ^ 1, variant, half), renewed);
    assert_ne!(machine.context(el, variant, half ^ 1), renewed);
    assert_eq!(machine.context(el, variant, half), renewed);
}

#[test]
fn lookup_contexts_follow_translation_inputs_and_outlive_a_return_to_them() {
    const MSR_TTBR0_EL1_X0: u32 = 0xd518_2000;
    const MSR_MAIR_EL1_X0: u32 = 0xd518_a200;
    let mut machine = machine(&[]);
    let variant = machine.current_variant(false, false);
    let el = machine.cpu.pstate.el;
    let msr = |machine: &mut Machine<FakeHost, NoDevices>, word, value| {
        machine.cpu.state.x[0] = value;
        machine.system_instruction(word).unwrap();
    };
    let ttbr0 = machine.cpu.read(SystemRegister::TTBR0_EL1);
    let mair = machine.cpu.read(SystemRegister::MAIR_EL1);
    let first = machine.contexts(el, variant);
    // Another TTBR0 table under the same ASID is another lower-half
    // context alone, and the first value finds the first contexts.
    msr(&mut machine, MSR_TTBR0_EL1_X0, ttbr0 ^ 0x8000_4000);
    let other = machine.contexts(el, variant);
    assert!(other[0] != first[0] && other[1] == first[1]);
    msr(&mut machine, MSR_TTBR0_EL1_X0, ttbr0);
    assert_eq!(machine.contexts(el, variant), first);
    // Another ASID is another lower-half context alone while every
    // upper-half fetch was global.
    msr(&mut machine, MSR_TTBR0_EL1_X0, ttbr0 ^ 1 << 48);
    let asid = machine.contexts(el, variant);
    assert!(asid[0] != first[0] && asid[1] == first[1]);
    msr(&mut machine, MSR_TTBR0_EL1_X0, ttbr0);
    // Any other control, too, and back.
    msr(&mut machine, MSR_MAIR_EL1_X0, mair ^ 0xff);
    let attributes = machine.contexts(el, variant);
    assert!(attributes[0] != first[0] && attributes[1] != first[1]);
    msr(&mut machine, MSR_MAIR_EL1_X0, mair);
    assert_eq!(machine.contexts(el, variant), first);
    // So does SPRR_PERM_EL0, which a JIT's write toggle flips and XNU
    // rewrites at every thread switch, for EL0's fetches alone: the
    // kernel's fetches read SPRR_PERM_EL1.
    const MSR_SPRR_CONFIG_EL1_X0: u32 = 0xd51e_f100;
    const MSR_SPRR_PERM_EL0_X0: u32 = 0xd51e_f1a0;
    msr(&mut machine, MSR_SPRR_CONFIG_EL1_X0, 1);
    let enabled = machine.contexts(el, variant);
    let user = machine.contexts(0, variant);
    let invalidations = machine.host.invalidations;
    msr(&mut machine, MSR_SPRR_PERM_EL0_X0, 0x10);
    assert_eq!(machine.contexts(el, variant), enabled);
    let toggled = machine.contexts(0, variant);
    assert!(toggled[0] != user[0] && toggled[1] != user[1]);
    // The host's shadow learns of it from the regime alone, which
    // drops what the new permissions change.
    assert_eq!(machine.host.invalidations, invalidations);
    let regime = machine.host.regimes.last().expect("a regime");
    assert_eq!(regime.controls.sprr.el0, 0x10);
    msr(&mut machine, MSR_SPRR_PERM_EL0_X0, 0);
    assert_eq!(machine.contexts(0, variant), user);
    assert_eq!(machine.contexts(el, variant), enabled);
    msr(&mut machine, MSR_SPRR_CONFIG_EL1_X0, 0);
    assert_eq!(machine.contexts(el, variant), first);
    // An ASIDE1 forgets the lower half's contexts, while no fetch of the
    // upper half was non-global.
    let aside1 = |machine: &mut Machine<FakeHost, NoDevices>| {
        machine.tlb_maintained(mmu::tlbi::Reach::Nothing, mmu::tlbi::Everywhere::NonGlobal)
    };
    aside1(&mut machine);
    let maintained = machine.contexts(el, variant);
    assert!(maintained[0] != first[0] && maintained[1] == first[1]);
    // A global upper fetch keeps it; the first non-global one forgets
    // the upper half's contexts, whose ASID then selects among them.
    machine.fetched_through(1, 0x4000, true);
    assert_eq!(machine.contexts(el, variant), maintained);
    machine.fetched_through(1, 0x4000, false);
    let private = machine.contexts(el, variant);
    assert!(private[0] == maintained[0] && private[1] != maintained[1]);
    machine.fetched_through(1, 0x4000, false);
    assert_eq!(machine.contexts(el, variant), private);
    msr(&mut machine, MSR_TTBR0_EL1_X0, ttbr0 ^ 1 << 48);
    let asid = machine.contexts(el, variant);
    assert!(asid[0] != private[0] && asid[1] != private[1]);
    msr(&mut machine, MSR_TTBR0_EL1_X0, ttbr0);
    assert_eq!(machine.contexts(el, variant), private);
    // Then both, as do a TLBI of everything, a host permission change
    // and any other change to translation.
    for change in [
        |machine: &mut Machine<FakeHost, NoDevices>| {
            machine.private_fetches[1] = true;
            machine.tlb_maintained(mmu::tlbi::Reach::Nothing, mmu::tlbi::Everywhere::NonGlobal)
        },
        |machine: &mut Machine<FakeHost, NoDevices>| {
            machine.tlb_maintained(mmu::tlbi::Reach::All, mmu::tlbi::Everywhere::All)
        },
        Machine::fetch_permissions_changed,
        Machine::translations_changed,
    ] {
        let before = machine.contexts(el, variant);
        change(&mut machine);
        let after = machine.contexts(el, variant);
        assert!(after[0] != before[0] && after[1] != before[1]);
    }
}

#[test]
fn a_tlbi_by_va_drops_the_lookup_entries_of_its_leaf_in_every_context() {
    use mmu::tlbi::{Everywhere, Reach};
    let mut machine = machine(&[]);
    let variant = machine.current_variant(false, false);
    let contexts = machine.contexts(2, variant);
    const PAGE: u64 = 0x8000;
    machine.fetch_leaves[0] = 0x4000;
    let pcs = [PAGE - 4, PAGE, PAGE + 0x3ffc, PAGE + 0x4000];
    for (context, pc) in pcs.into_iter().enumerate() {
        machine.targets[chain::lookup_slot(pc)] = chain::LookupEntry {
            pc,
            context: context as u64 + 1,
            entry: 1,
            block: 0,
            targets: 1,
        };
    }
    let tlbi = |machine: &mut Machine<FakeHost, NoDevices>, reach| {
        machine.tlb_maintained(reach, Everywhere::Addresses(reach))
    };
    tlbi(&mut machine, Reach::Containing(PAGE + 0x10));
    let kept = pcs.map(|pc| machine.targets[chain::lookup_slot(pc)].pc == pc);
    assert_eq!(kept, [true, false, false, true]);
    assert_eq!(machine.contexts(2, variant), contexts);
    // A leaf the table could not be scanned for forgets the half's
    // contexts instead; the other half's stay.
    machine.fetch_leaves[0] = 1 << 30;
    tlbi(&mut machine, Reach::Containing(PAGE));
    let forgotten = machine.contexts(2, variant);
    assert!(forgotten[0] != contexts[0] && forgotten[1] == contexts[1]);
}

#[test]
fn dynamic_branches_name_their_exit_and_any_page_independent_btype() {
    // BR through other than X16 or X17 sets a BTYPE that depends on
    // its page.
    for (word, expected) in [
        (0xd61f_0000, Some((ExitKind::Indirect, None))), // br x0
        (0xd61f_0200, Some((ExitKind::Indirect, Some(0b01)))), // br x16
        (0xd63f_0100, Some((ExitKind::Call, Some(0b10)))), // blr x8
        (0xd65f_03c0, Some((ExitKind::Return, Some(0)))), // ret
        (0xd71f_0a31, Some((ExitKind::Indirect, Some(0b01)))), // braa x17, x17
        (0xd61f_091f, Some((ExitKind::Indirect, None))), // braaz x8
        (0xd63f_091f, Some((ExitKind::Call, Some(0b10)))), // blraaz x8
        (0xd65f_0fff, Some((ExitKind::Return, Some(0)))), // retab
        (0xd69f_03e0, None),                             // eret
        (0x1400_0000, None),                             // b .
    ] {
        assert_eq!(dynamic_branch(word), expected, "{word:#x}");
    }
}

/// BLR and BR exits are redirected through lookup thunks that set their
/// BTYPE: a BR through other than X16 or X17 sets 0b11 from a guarded
/// page, whose blocks are compiled apart, and 0b01 elsewhere. A target
/// in a guarded page accepts the BTYPEs its first instruction is
/// compatible with.
#[test]
fn indirect_branches_go_through_lookups_that_check_the_target() {
    const BLR_X8: u32 = 0xd63f_0100;
    const BR_X16: u32 = 0xd61f_0200;
    const BR_X0: u32 = 0xd61f_0000;
    const BTI_C: u32 = 0xd503_245f;
    let mut words = vec![0; 1025];
    words[0] = BLR_X8;
    words[1] = BR_X16;
    words[2] = BR_X0;
    words[1024] = BTI_C;
    let mut machine = machine(&words);
    let base = machine.cpu.pc;
    let far = base + 0x1000;
    let exit = |kind: ExitKind| NativeExit::Exit {
        next_pc: far,
        kind: kind as u64,
    };
    machine.host.exits = vec![
        exit(ExitKind::Call),
        exit(ExitKind::Indirect),
        exit(ExitKind::Indirect),
        exit(ExitKind::Indirect),
    ];
    for pc in [base, base + 4, base + 8] {
        machine.cpu.pc = pc;
        machine.cpu.pstate.btype = 0;
        machine.step().unwrap();
    }
    // The same BR X0, now in a guarded page.
    let page = (base / FETCH_PAGE) as usize % FETCH_CACHE;
    machine.fetch[page].as_mut().unwrap().guarded = true;
    machine.cpu.pc = base + 8;
    machine.cpu.pstate.btype = 0;
    machine.step().unwrap();
    assert_eq!(machine.blocks.len(), 4);
    assert!(!machine.blocks[2].variant.guarded_page && machine.blocks[3].variant.guarded_page);
    let control = machine.chain.address();
    for (index, kind, btype) in [
        (0, ExitKind::Call, 0b10),
        (1, ExitKind::Indirect, 0b01),
        (2, ExitKind::Indirect, 0b01),
        (3, ExitKind::Indirect, 0b11),
    ] {
        let thunk = chain::lookup_thunk(control, 1, None, kind, btype).unwrap();
        assert!(machine.host.installed.contains(&thunk), "{index}");
        assert_eq!(machine.blocks[index].dynamic_site, None, "{index}");
    }
    assert_eq!(machine.statistics.lookups, 4);
    machine.fetch[page].as_mut().unwrap().guarded = false;
    // The target outside a guarded page accepts every BTYPE; in one, the
    // BTYPEs BTI c is compatible with.
    machine.cpu.pc = far;
    machine.host.exits = vec![NativeExit::Exit {
        next_pc: far + 4,
        kind: ExitKind::Fallthrough as u64,
    }];
    machine.step().unwrap();
    let target = machine.blocks.len() - 1;
    assert_eq!(machine.blocks[target].pc, far);
    assert_eq!(machine.targets[chain::lookup_slot(far)].targets, 0b1111);
    let slot = (far / FETCH_PAGE) as usize % FETCH_CACHE;
    machine.fetch[slot].as_mut().unwrap().guarded = true;
    machine.remember_target(far, target);
    assert_eq!(machine.targets[chain::lookup_slot(far)].targets, 0b0111);
    // BTI C itself performs no guest memory access. Preserve this
    // original landing-pad program, but an invented Host fault at its
    // first instruction cannot be projected as an ARM data abort.
    let current = machine.chain.snapshot();
    machine.host.chained = Some((
        machine.chain.address() as *mut ChainControl,
        ChainControl {
            budget: CHAIN_LIMIT - 1,
            retired: 1,
            block: 0b10 << chain::BLOCK_BTYPE_SHIFT | target as u64,
            linked: 1,
            ..current
        },
    ));
    let offset = machine.blocks[target]
        .code
        .0
        .wrapping_sub(machine.blocks[0].code.0);
    machine.host.exits = vec![NativeExit::Fault(NativeFault {
        origin: crate::machine::NativeFaultOrigin::Exception,
        trap: 14,
        error_code: 0,
        spills: stela_compiler::block::HostSpillSnapshot::new(),
        registers: stela_compiler::block::HostGprSnapshot::legacy([0; 16]),
        offset,
        address: 0x40,
        write: false,
        cause: FaultCause::Guest(mmu::Fault::stage1(mmu::FaultKind::Translation, 3)),
    })];
    machine.cpu.pc = base;
    let before = (
        machine.cpu.pc,
        machine.cpu.retired,
        machine.cpu.read(SystemRegister::ELR_EL1),
        machine.cpu.read(SystemRegister::SPSR_EL1),
    );
    let state = machine.cpu.state.clone();
    let stop = machine.step().unwrap_err();
    assert!(
        matches!(&stop, Stop::NativeFailure(failure) if failure.reason == NativeFailureReason::InternalSite)
    );
    assert_eq!(
        (
            machine.cpu.pc,
            machine.cpu.retired,
            machine.cpu.read(SystemRegister::ELR_EL1),
            machine.cpu.read(SystemRegister::SPSR_EL1)
        ),
        before
    );
    assert_eq!(machine.cpu.state, state);
    assert!(
        matches!(&stop, Stop::NativeFailure(failure) if failure.unsettled_chain.as_ref().is_some_and(|chain| chain.reported_retired == 1))
    );
    assert_eq!(machine.run(1), stop);
    assert_eq!(machine.cpu.state, state);
}

#[test]
fn apple_sdsb_completes_as_a_barrier() {
    const SDSB_ISH: u32 = 0x0020_1462;
    let mut machine = machine(&[]);
    let pc = machine.cpu.pc;
    machine.system_instruction(SDSB_ISH).unwrap();
    assert_eq!(machine.cpu.pc, pc + 4);
}

/// A TTBR0 write reaches the host only as the regime's new controls,
/// which differ from the old in TTBR0 alone, so the host keeps the upper
/// half's shadow. Another translation control reaches it the same way,
/// and the host drops what the new controls translate differently
/// ([`Host::set_regime`]). Both make the fetch translations stale.
#[test]
fn translation_controls_reach_the_host_as_its_regime() {
    const MSR_TTBR0_EL1_X0: u32 = 0xd518_2000;
    const MSR_TCR_EL1_X0: u32 = 0xd518_2040;
    let mut machine = machine(&[]);
    let before = *machine.host.regimes.last().unwrap();
    let generation = machine.translation_generation;
    machine.cpu.state.x[0] = 0x1_0000_8000_4000;
    machine.system_instruction(MSR_TTBR0_EL1_X0).unwrap();
    assert_eq!(machine.host.invalidations, 0);
    let after = *machine.host.regimes.last().unwrap();
    assert_ne!(after.controls, before.controls);
    assert_eq!(
        mmu::Controls {
            ttbr0: after.controls.ttbr0,
            ..before.controls
        },
        after.controls
    );
    assert!(machine.translation_generation > generation);
    assert_eq!(
        (
            machine.statistics.table_base_changes,
            machine.statistics.translation_changes
        ),
        (1, 0)
    );
    machine.cpu.state.x[0] = 25 | 25 << 16;
    machine.system_instruction(MSR_TCR_EL1_X0).unwrap();
    assert_eq!(machine.host.invalidations, 0);
    assert_eq!(machine.statistics.translation_changes, 1);
    let tcr = *machine.host.regimes.last().unwrap();
    assert_eq!(tcr.controls.tcr, 25 | 25 << 16);
    assert_eq!(
        mmu::Controls {
            tcr: tcr.controls.tcr,
            ..after.controls
        },
        tcr.controls
    );
}

/// A TLBI hands the host what it reaches of the current context and
/// what it removes from every context, and makes every fetch
/// translation stale, but changes no control: the
/// regime is not sent again and what derives from System registers
/// stays.
#[test]
fn tlbis_reach_their_address_range_or_asid_without_a_regime_change() {
    use mmu::tlbi::{Everywhere, Reach};
    const TLBI_VAE1_X0: u32 = 0xd508_8720;
    const TLBI_ASIDE1_X0: u32 = 0xd508_8740;
    const TLBI_RVAE1_X0: u32 = 0xd508_8620;
    const TLBI_VMALLE1: u32 = 0xd508_871f;
    let mut machine = machine(&[]);
    let regimes = machine.host.regimes.len();
    machine.native_system();
    let generation = machine.translation_generation;
    let high = 0xffff_fe00_0123_4000_u64;
    machine.cpu.state.x[0] = 3 << 48 | (high & ((1 << 56) - 1)) >> 12;
    machine.system_instruction(TLBI_VAE1_X0).unwrap();
    // ASID 0 is the one TTBR0_EL1 names; 3 is another.
    machine.cpu.state.x[0] = 3 << 48;
    machine.system_instruction(TLBI_ASIDE1_X0).unwrap();
    machine.cpu.state.x[0] = 0;
    machine.system_instruction(TLBI_ASIDE1_X0).unwrap();
    // Four 16 KiB pages from 0x10_0000.
    machine.cpu.state.x[0] = 2 << 46 | 1 << 39 | 0x10_0000 >> 14;
    machine.system_instruction(TLBI_RVAE1_X0).unwrap();
    machine.system_instruction(TLBI_VMALLE1).unwrap();
    let range = Reach::Overlapping {
        first: 0x10_0000,
        last: 0x10_ffff,
    };
    assert_eq!(
        machine.host.reaches,
        [
            (
                Reach::Containing(high),
                Everywhere::Addresses(Reach::Containing(high))
            ),
            (Reach::Nothing, Everywhere::NonGlobal),
            (Reach::All, Everywhere::NonGlobal),
            (range, Everywhere::Addresses(range)),
            (Reach::All, Everywhere::All),
        ]
    );
    assert_eq!(machine.translation_generation, generation + 5);
    assert_eq!(machine.host.regimes.len(), regimes);
    assert!(machine.native_system.is_some());
    assert_eq!(
        (
            machine.statistics.tlb_maintenance,
            machine.statistics.scoped_maintenance,
            machine.statistics.translation_changes
        ),
        (5, 3, 0)
    );
}

#[test]
fn tlbi_invalidates_and_wfi_waits_for_the_virtual_timer() {
    let mut machine = machine_on(one_timer_bank(), &[]);
    machine.system_instruction(0xd508_871f).unwrap(); // tlbi vmalle1
    assert_eq!(machine.host.invalidations, 1);
    // Arm the virtual timer 1500 ticks ahead and wait.
    machine.cpu.state.x[0] = 1500;
    machine.system_instruction(0xd51b_e300).unwrap(); // msr cntv_tval_el0, x0
    machine.cpu.state.x[0] = 1;
    machine.system_instruction(0xd51b_e320).unwrap(); // msr cntv_ctl_el0, x0
    wait(&mut machine, 0xd503_207f).unwrap(); // wfi
    assert_eq!(machine.host.now, 2000);
    // The FIQ is masked by DAIF until it is cleared.
    assert!(!machine.deliver_interrupts());
    machine.cpu.pstate.daif = 0;
    let pc = machine.cpu.pc;
    assert!(machine.deliver_interrupts());
    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), pc);
    assert_eq!(machine.cpu.pc, 0x300);
    // With no timer armed, WFI is a terminal idle state.
    machine
        .cpu
        .registers
        .set(SystemRegister::CNTV_CTL_EL0, 0, 0);
    machine.derived_changed();
    assert_eq!(wait(&mut machine, 0xd503_207f), Err(Stop::Idle));
}

#[test]
fn timer_snapshot_tracks_guest_reads_and_wfi_when_the_clock_lags() {
    let mut machine = machine_on(one_timer_bank(), &[]);
    // Three slow slices each run ten blocks in 1000 host counts. The
    // initial observed overshoot remains monotonic, but repeated slow
    // work advances it only by ten per slice, not by host duration.
    for slice in 0..3 {
        machine.clock.start_slice(slice * 1000, slice * 10, 1);
        machine.host.now = (slice + 1) * 1000;
        machine.clock.end_slice(machine.host.now, (slice + 1) * 10);
    }
    machine.host.now = 3500;
    machine
        .cpu
        .registers
        .set(SystemRegister::CNTV_CVAL_EL0, 0, 1500);
    machine
        .cpu
        .registers
        .set(SystemRegister::CNTV_CTL_EL0, 0, timer::ENABLE);
    machine.derived_changed();
    assert_eq!(
        timer::CHANNELS[1].read_control(&machine.cpu, timer::agt::Bank::Arm, machine.host.now),
        timer::ENABLE | timer::ISTATUS,
        "the host count would incorrectly report an expired timer"
    );
    let (now, timers) = machine.timer_snapshot();
    assert_eq!((now, timers[1]), (1020, (timer::ENABLE, 1500)));
    machine.system_instruction(0xd53b_e041).unwrap(); // mrs x1, cntvct_el0
    machine.system_instruction(0xd53b_e322).unwrap(); // mrs x2, cntv_ctl_el0
    assert_eq!(
        (machine.cpu.state.x[1], machine.cpu.state.x[2]),
        (now, timers[1].0)
    );

    machine.system_instruction(0xd503_207f).unwrap(); // wfi
    assert!(machine.waiting.is_some());
    assert_eq!(machine.timer_snapshot(), (now, timers));
    machine.schedule().unwrap();
    assert_eq!(machine.host.now, 4500, "WFI waited for guest time");
    let (now, timers) = machine.timer_snapshot();
    assert_eq!(
        (now, timers[1]),
        (1530, (timer::ENABLE | timer::ISTATUS, 1500))
    );
    machine.system_instruction(0xd53b_e041).unwrap();
    machine.system_instruction(0xd53b_e322).unwrap();
    assert_eq!(
        (machine.cpu.state.x[1], machine.cpu.state.x[2]),
        (now, timers[1].0)
    );
    assert!(machine.waiting.is_none());
}

#[test]
fn pstate_masks_interrupts_to_el1_from_el0_and_to_el2_from_the_host() {
    let mut machine = machine(&[]);
    machine.cpu.pstate.daif = DAIF_F;
    let hcr = |machine: &mut Machine<FakeHost, NoDevices>, value: u64| {
        machine
            .cpu
            .registers
            .set_raw(SystemRegister::HCR_EL2, 0, value)
    };
    machine.cpu.pstate.el = 0;
    hcr(&mut machine, 0);
    assert!(!machine.taken(1, DAIF_F));
    assert!(machine.taken(2, DAIF_F));
    hcr(&mut machine, 1 << HCR_TGE);
    assert!(!machine.taken(2, DAIF_F));
    machine.cpu.pstate.el = 1;
    hcr(&mut machine, 0);
    assert!(!machine.taken(1, DAIF_F));
    assert!(machine.taken(2, DAIF_F));
    assert!(!machine.taken(0, 0));
    machine.cpu.pstate.daif = 0;
    assert!(machine.taken(1, DAIF_F));
}

#[test]
fn wfi_in_cyc_ovrds_power_down_mode_turns_the_core_off() {
    const MSR_CYC_OVRD_X0: u32 = 0xd51d_f500;
    const WFI: u32 = 0xd503_207f;
    const WFIT_X1: u32 = 0xd503_1021;
    let mut machine = machine(&[]);
    // Clock gating only: WFI waits as usual.
    machine.cpu.state.x[0] = 2 << 24;
    machine.system_instruction(MSR_CYC_OVRD_X0).unwrap();
    machine.cpu.state.x[1] = 1500;
    machine.system_instruction(0xd51b_e301).unwrap(); // msr cntv_tval_el0, x1
    machine.cpu.state.x[1] = 1;
    machine.system_instruction(0xd51b_e321).unwrap(); // msr cntv_ctl_el0, x1
    wait(&mut machine, WFI).unwrap();
    assert_eq!(machine.host.now, 2000);
    // In power-down mode the core's own timer, armed again, goes down
    // with it: nothing on this board can wake it.
    machine.cpu.state.x[0] = 3 << 24 | 1;
    machine.system_instruction(MSR_CYC_OVRD_X0).unwrap();
    machine.cpu.state.x[1] = 1_000_000;
    machine.system_instruction(0xd51b_e301).unwrap(); // msr cntv_tval_el0, x1
    assert_eq!(wait(&mut machine, WFI), Err(Stop::Idle));
    assert!(matches!(machine.peer_states()[0], PeerState::Down));
    assert_eq!(machine.host.now, 2000);
    // A WFIT's local timeout would be the core's too.
    let mut machine = machine_on(stela_contracts::Chip::AppleM4, &[]);
    machine.cpu.state.x[0] = 3 << 24;
    machine.system_instruction(MSR_CYC_OVRD_X0).unwrap();
    machine.cpu.state.x[1] = u64::MAX;
    assert!(matches!(
        machine.system_instruction(WFIT_X1),
        Err(Stop::Unsupported(_))
    ));
}

#[test]
fn wfit_and_wfet_wait_until_their_timeout_and_trap_with_the_register() {
    const WFIT_X1: u32 = 0xd503_1021;
    const WFET_X2: u32 = 0xd503_1002;
    const HCR_TWI: u64 = 1 << 13;
    let chip = stela_contracts::Chip::AppleM4;
    let mut machine = machine_on(chip, &[]);
    machine
        .cpu
        .registers
        .set(SystemRegister::VBAR_EL2, 0, 0x2_0000);
    // An expired timeout completes at once; WFET also needs no event.
    machine.cpu.state.x[2] = 0;
    machine.system_instruction(WFET_X2).unwrap();
    assert_eq!(machine.cpu.pc, BASE + 4);
    // A later one waits, and the host's next tick (FakeHost adds 1000)
    // passes it: WFIT completes without any timer or interrupt, where a
    // WFI would be idle.
    machine.cpu.state.x[1] = 500;
    wait(&mut machine, WFIT_X1).unwrap();
    assert_eq!((machine.cpu.pc, machine.statistics.waits), (BASE + 8, 1));
    // HCR_EL2.TWI traps it to EL2: ISS.TI 0b10, RV and Rt 1, CV and COND.
    machine.cpu.state.x[1] = u64::MAX;
    machine
        .cpu
        .registers
        .set(SystemRegister::HCR_EL2, 0, HCR_TWI);
    machine.system_instruction(WFIT_X1).unwrap();
    assert_eq!(
        machine.cpu.read(SystemRegister::ESR_EL2),
        0x0600_0000 | 1 << 24 | 0b1110 << 20 | 1 << 5 | 1 << 2 | 0b10
    );
    // The M2 has no FEAT_WFxT: the timeout forms are UNDEFINED.
    let mut machine = machine_on(stela_contracts::Chip::AppleM2, &[]);
    machine
        .cpu
        .registers
        .set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
    machine.system_instruction(WFIT_X1).unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
}

#[test]
fn fp8_conversions_take_fpmr_formats_behind_enfpm_and_the_fp_check() {
    const F1CVTL: u32 = 0x2e21_7820; // f1cvtl v0.8h, v1.8b
    const F2CVTL2: u32 = 0x6e61_7820; // f2cvtl2 v0.8h, v1.16b
    const BF1CVTL: u32 = 0x2ea1_7820; // bf1cvtl v0.8h, v1.8b
    const FCVTN_H: u32 = 0x0e42_f420; // fcvtn v0.8b, v1.4h, v2.4h
    const FCVTN2_S: u32 = 0x4e02_f420; // fcvtn2 v0.16b, v1.4s, v2.4s
    const FSCALE: u32 = 0x6ea2_fc20; // fscale v0.4s, v1.4s, v2.4s
    const E4M3: u64 = 1;
    const HCRX_ENFPM: u64 = 1 << 23;
    const SCTLR_ENFPM: u64 = 1 << 34;
    let code = [F1CVTL, F2CVTL2, BF1CVTL, FCVTN_H, FCVTN2_S, FSCALE];
    let mut machine = machine(&code);
    let chip = machine.profile.chip;
    let registers = &mut machine.cpu.registers;
    registers.set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
    registers.set(SystemRegister::VBAR_EL2, 0, 0x2_0000);
    registers.set(SystemRegister::CPACR_EL1, 0, 0b11 << 20);
    registers.set(SystemRegister::CPTR_EL2, 0, 0b11 << 20);
    let run = |machine: &mut Machine<FakeHost, NoDevices>, index: u64, el: u8| {
        machine.cpu.set_pstate(Pstate {
            sp: el != 0,
            ..Pstate::reset(el.max(1))
        });
        machine.cpu.pstate.el = el;
        machine.derived_changed();
        machine.cpu.pc = BASE + 4 * index;
        machine.step()
    };
    if !Feature::FEAT_FP8.on(chip) {
        // The chip lacks the forms: they compile as the UDF they are.
        for index in 0..code.len() as u64 {
            assert!(!matches!(
                machine.fetch_block(BASE + 4 * index, true),
                Ok(Fetched::Checked(_))
            ));
        }
        return;
    }
    // HCRX_EL2.EnFPM clear makes them UNDEFINED at EL1, even with FP
    // access trapped (CheckFPMREnabled comes first).
    machine.cpu.state.v[1] = [0x3c38, 0];
    run(&mut machine, 0, 1).unwrap();
    assert_eq!(
        (
            machine.cpu.pstate.el,
            machine.cpu.read(SystemRegister::ESR_EL1)
        ),
        (1, 0x0200_0000)
    );
    machine.cpu.registers.set(SystemRegister::CPACR_EL1, 0, 0);
    run(&mut machine, 0, 1).unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
    // With EnFPM set, the FP access check traps (EC 0x07).
    machine
        .cpu
        .registers
        .set(SystemRegister::HCRX_EL2, 0, HCRX_ENFPM);
    run(&mut machine, 0, 1).unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x1fe0_0000);
    machine
        .cpu
        .registers
        .set(SystemRegister::CPACR_EL1, 0, 0b11 << 20);
    // EL0 also needs SCTLR_EL1.EnFPM.
    run(&mut machine, 0, 0).unwrap();
    assert_eq!(
        (
            machine.cpu.pstate.el,
            machine.cpu.read(SystemRegister::ESR_EL1)
        ),
        (1, 0x0200_0000)
    );
    let sctlr = machine.cpu.read(SystemRegister::SCTLR_EL1);
    machine
        .cpu
        .registers
        .set(SystemRegister::SCTLR_EL1, 0, sctlr | SCTLR_ENFPM);
    // FPMR.F8S1 0 is E5M2, whose 0x3c is 1.0 and 0x38 0.5; E4M3 reads
    // 0x38 as 1.0 and 0x3c as 1.5. The widened halves fill V0.
    let fpmr = |machine: &mut Machine<FakeHost, NoDevices>, value: u64| {
        machine.cpu.scalable.as_mut().unwrap().set_fpmr(value);
    };
    fpmr(&mut machine, 0);
    run(&mut machine, 0, 0).unwrap();
    assert_eq!(machine.cpu.state.v[0], [0x3c00_3800, 0]);
    assert_eq!((machine.cpu.pstate.el, machine.cpu.pc), (0, BASE + 4));
    fpmr(&mut machine, E4M3);
    run(&mut machine, 0, 1).unwrap();
    assert_eq!(machine.cpu.state.v[0], [0x3e00_3c00, 0]);
    // F2CVTL2 takes FPMR.F8S2 and the upper half of V1.
    machine.cpu.state.v[1] = [0, 0x38];
    fpmr(&mut machine, E4M3 << 3);
    run(&mut machine, 1, 1).unwrap();
    assert_eq!(machine.cpu.state.v[0], [0x3c00, 0]);
    // BF1CVTL widens to BFloat16: E4M3 1.0 is 0x3f80.
    machine.cpu.state.v[1] = [0x38, 0];
    fpmr(&mut machine, E4M3);
    run(&mut machine, 2, 1).unwrap();
    assert_eq!(machine.cpu.state.v[0], [0x3f80, 0]);
    // FCVTN narrows the halves of V1 then V2 to FPMR.F8D's E4M3, and
    // 1.0 + 2^-10 is inexact.
    fpmr(&mut machine, E4M3 << 6);
    machine.cpu.state.v[1] = [0x3c00, 0];
    machine.cpu.state.v[2] = [0x3c01, 0];
    machine.cpu.state.fpsr = 0;
    run(&mut machine, 3, 1).unwrap();
    assert_eq!(machine.cpu.state.v[0], [0x38 << 32 | 0x38, 0]);
    assert_eq!(machine.cpu.state.fpsr, 1 << 4, "FPSR.IXC");
    // FCVTN2 from singles keeps V0's lower half.
    machine.cpu.state.v[0] = [0x1234, 0];
    machine.cpu.state.v[1] = [0x3f80_0000, 0];
    machine.cpu.state.v[2] = [0, 0];
    run(&mut machine, 4, 1).unwrap();
    assert_eq!(machine.cpu.state.v[0], [0x1234, 0x38]);
    assert_eq!(machine.cpu.pc, BASE + 20);
    // FSCALE, FEAT_FP8 without FPMR, compiles natively.
    assert!(matches!(
        machine.fetch_block(BASE + 20, true),
        Ok(Fetched::Block(_))
    ));
}

/// Execute WFI or WFE and schedule as `Machine::run` does next.
fn wait(machine: &mut Machine<FakeHost, NoDevices>, word: u32) -> Step {
    machine.system_instruction(word)?;
    machine.schedule()
}

/// Maps VA 0-1 GiB to BASE, EL1-only read/write and executable, with the
/// stage-1 GP bit when `guarded`.
fn guarded_machine(guarded: bool) -> Machine<FakeHost, NoDevices> {
    let mut machine = machine(&[]);
    let block = BASE | 1 | 1 << 10 | u64::from(guarded) << 50;
    machine.host.ram[0x4000..0x4008].copy_from_slice(&block.to_le_bytes());
    let registers = &mut machine.cpu.registers;
    registers.set(SystemRegister::TCR_EL1, 0, 25 | 1 << 23 | 5 << 32);
    registers.set(SystemRegister::TTBR0_EL1, 0, BASE + 0x4000);
    registers.set(SystemRegister::MAIR_EL1, 0, 0xff);
    registers.set(SystemRegister::SCTLR_EL1, 0, 1);
    registers.set(SystemRegister::VBAR_EL1, 0, 0x2_0000);
    machine.derived_changed();
    machine
}

#[test]
fn branch_target_compatibility_follows_bti_paciasp_brk_and_hlt() {
    const BTI: [u32; 4] = [0xd503_241f, 0xd503_245f, 0xd503_249f, 0xd503_24df];
    const PACIASP: u32 = 0xd503_233f;
    let mut machine = machine(&[]);
    // Rows BTYPE 01, 10, 11; columns BTI, BTI c, BTI j, BTI jc.
    let expected = [
        [false, true, true, true],
        [false, true, false, true],
        [false, false, true, true],
    ];
    for (btype, row) in (1..=3).zip(expected) {
        machine.cpu.pstate.btype = btype;
        for (word, compatible) in BTI.into_iter().zip(row) {
            assert_eq!(
                machine.branch_target_compatible(word),
                compatible,
                "{word:#x} {btype}"
            );
        }
        assert!(machine.branch_target_compatible(PACIASP));
        assert!(machine.branch_target_compatible(0xd420_0000)); // brk #0
        assert!(machine.branch_target_compatible(0xd440_0000)); // hlt #0
        assert!(!machine.branch_target_compatible(0xd503_201f)); // nop
    }
    // SCTLR_EL1.BT1 makes PACIASP incompatible with BTYPE 0b11 at EL1.
    machine
        .cpu
        .registers
        .set(SystemRegister::SCTLR_EL1, 0, 1 << 36);
    machine.derived_changed();
    assert!(!machine.branch_target_compatible(PACIASP));
    machine.cpu.pstate.btype = 0b01;
    assert!(machine.branch_target_compatible(PACIASP));
    // At EL0 SCTLR_EL1.BT0 decides instead.
    machine.cpu.pstate.btype = 0b11;
    machine.cpu.pstate.el = 0;
    assert!(machine.branch_target_compatible(PACIASP));
    machine
        .cpu
        .registers
        .set(SystemRegister::SCTLR_EL1, 0, 1 << 35);
    machine.derived_changed();
    assert!(!machine.branch_target_compatible(PACIASP));
}

/// SCTLR_EL2 bit 36 is BT with HCR_EL2.TGE clear and BT1 with it set
/// (E2H is RES1); either way it decides PACIASP at EL2.
#[test]
fn sctlr_el2_bt_decides_paciasp_at_el2_with_or_without_tge() {
    const PACIASP: u32 = 0xd503_233f;
    const SCTLR_BT: u64 = 1 << 36;
    const HCR_TGE: u64 = 1 << 27;
    let mut machine = machine(&[]);
    machine.cpu.pstate.el = 2;
    machine.cpu.pstate.btype = 0b11;
    for hcr in [0, HCR_TGE] {
        machine.cpu.registers.set(SystemRegister::HCR_EL2, 0, hcr);
        // SCTLR_EL1.BT1 has no say at EL2.
        machine
            .cpu
            .registers
            .set(SystemRegister::SCTLR_EL1, 0, SCTLR_BT);
        machine.cpu.registers.set(SystemRegister::SCTLR_EL2, 0, 0);
        machine.derived_changed();
        assert!(machine.branch_target_compatible(PACIASP), "{hcr:#x}");
        machine
            .cpu
            .registers
            .set(SystemRegister::SCTLR_EL2, 0, SCTLR_BT);
        machine.derived_changed();
        assert!(!machine.branch_target_compatible(PACIASP), "{hcr:#x}");
        assert!(machine.branch_target_accepts(PACIASP, 0b01));
    }
}

#[test]
fn indirect_branches_set_btype_from_their_page_and_register() {
    let mut guarded = guarded_machine(true);
    assert!(guarded.fetch_guarded(0x1000));
    assert_eq!(guarded.indirect_branch_type(0x1000, 5, false), 0b11);
    assert_eq!(guarded.indirect_branch_type(0x1000, 16, false), 0b01);
    assert_eq!(guarded.indirect_branch_type(0x1000, 17, false), 0b01);
    assert_eq!(guarded.indirect_branch_type(0x1000, 5, true), 0b10);
    let mut unguarded = guarded_machine(false);
    assert!(!unguarded.fetch_guarded(0x1000));
    assert_eq!(unguarded.indirect_branch_type(0x1000, 5, false), 0b01);
}

#[test]
fn native_branch_exits_set_btype_from_the_terminal_branch() {
    const BR_X5: u32 = 0xd61f_00a0;
    const BLR_X5: u32 = 0xd63f_00a0;
    const BL: u32 = 0x9400_0010;
    for (word, kind, btype) in [
        (BR_X5, ExitKind::Indirect, 0b11),
        (BLR_X5, ExitKind::Call, 0b10),
        (BL, ExitKind::Call, 0),
    ] {
        let mut machine = guarded_machine(true);
        machine.host.ram[0x1000..0x1004].copy_from_slice(&word.to_le_bytes());
        let Ok(Fetched::Block(index)) = machine.fetch_block(0x1000, false) else {
            panic!("{word:#x} did not compile");
        };
        machine.cpu.pstate.btype = 0b01;
        machine.exit(index, 0x3000, kind as u64).unwrap();
        assert_eq!(
            (machine.cpu.pc, machine.cpu.pstate.btype),
            (0x3000, btype),
            "{word:#x}"
        );
    }
}

#[test]
fn an_incompatible_guarded_target_takes_the_branch_target_exception() {
    let mut machine = guarded_machine(true);
    machine.host.ram[0x1000..0x1004].copy_from_slice(&0xd503_201fu32.to_le_bytes()); // nop
    machine.cpu.pstate.daif = 0;
    machine.cpu.pstate.btype = 0b11;
    machine.cpu.pc = 0x1000;
    machine.step().unwrap();
    assert_eq!(machine.cpu.pc, 0x2_0200);
    let esr = machine.cpu.read(SystemRegister::ESR_EL1);
    assert_eq!((esr >> 26, esr & 0x1ff_ffff), (0x0d, 0b11));
    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), 0x1000);
    assert_eq!((machine.cpu.read(SystemRegister::SPSR_EL1) >> 10) & 3, 0b11);
    assert_eq!(machine.cpu.pstate.btype, 0);
}

#[test]
fn wfe_wakes_on_an_event_stream_edge() {
    const WFE: u32 = 0xd503_205f;
    let mut machine = machine(&[]);
    let start = machine.host.now;
    // CNTHCTL_EL2.EVNTEN with EVNTI 9: rising edges 1024 counts apart.
    machine
        .cpu
        .registers
        .set(SystemRegister::CNTHCTL_EL2, 0, 1 << 2 | 9 << 4);
    wait(&mut machine, WFE).unwrap();
    assert!(machine.host.now > start && !machine.cpu.event);
    // An edge since the last sample sets the event register, so WFE
    // completes without waiting.
    machine.host.now += 1024;
    let now = machine.host.now;
    wait(&mut machine, WFE).unwrap();
    assert_eq!((machine.host.now, machine.cpu.event), (now, false));
    // Without a stream, timer or device, WFE is a terminal idle state.
    machine.cpu.registers.set(SystemRegister::CNTHCTL_EL2, 0, 0);
    assert_eq!(wait(&mut machine, WFE), Err(Stop::Idle));
}

#[test]
fn dc_zva_zeroes_one_profile_block_and_at_reports_par() {
    let mut machine = machine(&[]);
    normal_memory(&mut machine, false);
    machine.host.ram[0x100..0x180].fill(0xaa);
    machine.cpu.state.x[2] = BASE + 0x108;
    machine.system_instruction(0xd50b_7422).unwrap(); // dc zva, x2
    assert!(machine.host.ram[0x100..0x140].iter().all(|&b| b == 0));
    assert!(machine.host.ram[0x140..0x180].iter().all(|&b| b == 0xaa));
    machine.system_instruction(0xd508_7802).unwrap(); // at s1e1r, x2
    assert_eq!(
        machine.cpu.read(SystemRegister::PAR_EL1) & 0x0000_ffff_ffff_f000,
        BASE
    );
    assert_eq!(machine.cpu.read(SystemRegister::PAR_EL1) & 1, 0);
}

/// The DC clean operations native code completes are exactly those the
/// generated accessors complete as a plain translation check: across
/// ELs, the host, UCI, the HCR_EL2 traps and HFGITR_EL2, an operation in
/// `native_cache_clean` completes with PC + 4 or takes the Data Abort of
/// its translation, and one outside it traps.
#[test]
fn native_dc_clean_operations_are_the_untrapped_ones() {
    const WORDS: [(cache_clean::Operations, u32); 3] = [
        (cache_clean::Operations::CVAC, 0xd50b_7a22), // dc cvac, x2
        (cache_clean::Operations::CVAU, 0xd50b_7b22), // dc cvau, x2
        (cache_clean::Operations::CIVAC, 0xd50b_7e22), // dc civac, x2
    ];
    const HCR_BITS: [u32; 4] = [23, 24, 52, crate::machine::cpu::HCR_TGE];
    const HFGITR_BITS: [u32; 3] = [54, 10, 7];
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    let mut covered = [[0; 2]; 3];
    for _ in 0..192 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let el = (seed % 3) as u8;
        let bit = |index: u32| seed >> (8 + index) & 1;
        let hcr = HCR_BITS
            .iter()
            .enumerate()
            .fold(1 << 34, |hcr, (index, &field)| {
                hcr | bit(index as u32) << field
            });
        let hfgitr = HFGITR_BITS
            .iter()
            .enumerate()
            .fold(0, |value, (index, &field)| {
                value | bit(4 + index as u32) << field
            });
        let uci = (bit(7) << 26, bit(8) << 26);
        for (position, (operation, word)) in WORDS.into_iter().enumerate() {
            let mut machine = machine(&[]);
            normal_memory(&mut machine, true);
            let registers = &mut machine.cpu.registers;
            registers.set(SystemRegister::HCR_EL2, 0, hcr);
            registers.set(SystemRegister::HFGITR_EL2, 0, hfgitr);
            for (sctlr, uci) in [
                (SystemRegister::SCTLR_EL1, uci.0),
                (SystemRegister::SCTLR_EL2, uci.1),
            ] {
                let value = registers.get(sctlr, 0) | uci;
                registers.set(sctlr, 0, value);
            }
            registers.set(SystemRegister::VBAR_EL1, 0, BASE + 0x8000);
            registers.set(SystemRegister::VBAR_EL2, 0, BASE + 0x8000);
            machine.cpu.pstate.el = el;
            machine.derived_changed();
            let native = machine.native_system().cache_clean.contains(operation);
            machine.cpu.pc = BASE + 0x100;
            machine.cpu.state.x[2] = 0x2040;
            let exceptions = machine.statistics.exceptions;
            machine.system_instruction(word).unwrap();
            // A plain completion, or the Data Abort of the translation
            // check (a cache maintenance syndrome), rather than a trap.
            let target = machine.cpu.pstate.el.max(1);
            let esr = machine.cpu.read(if target == 2 {
                SystemRegister::ESR_EL2
            } else {
                SystemRegister::ESR_EL1
            });
            let checked = matches!(esr >> 26, 0x24 | 0x25) && esr & 1 << 8 != 0;
            let plain = machine.statistics.exceptions == exceptions
                && machine.cpu.pc == BASE + 0x104
                || machine.statistics.exceptions == exceptions + 1 && checked;
            assert_eq!(
                native, plain,
                "{word:#x} EL{el} HCR {hcr:#x} HFGITR {hfgitr:#x}"
            );
            covered[position][usize::from(native)] += 1;
        }
    }
    // Each operation was seen both completed natively and trapped.
    assert!(
        covered.iter().flatten().all(|&count| count > 0),
        "{covered:?}"
    );
}

/// A block ending in DC CIVAC checks Xt natively and falls through where
/// it cannot trap, and exits where HCR_EL2.TPCP traps it; a fault in the
/// native check completes DC CIVAC in the engine, which takes the Data
/// Abort with a cache maintenance syndrome.
#[test]
fn dc_clean_blocks_follow_the_traps_and_faults_complete_in_the_engine() {
    const ADD: u32 = 0x9100_0400; // add x0, x0, #1
    const DC_CIVAC: u32 = 0xd50b_7e23; // dc civac, x3
    let mut machine = machine(&[ADD, DC_CIVAC, ADD]);
    normal_memory(&mut machine, false);
    let base = machine.cpu.pc;
    let next = GuestAddress(base + 8);
    let fallthrough = NativeExit::Exit {
        next_pc: next.0,
        kind: ExitKind::Fallthrough as u64,
    };
    machine.host.exits = vec![fallthrough];
    machine.step().unwrap();
    let block = &machine.blocks[0];
    assert_eq!(
        block.variant.system.cache_clean,
        cache_clean::Operations::ALL
    );
    let code = &machine.host.installed[block.code.0 / NATIVE_CODE_STRIDE - 1];
    let tail = chain::direct_exit(next, ExitKind::Fallthrough);
    assert_eq!(code[code.len() - chain::DIRECT_EXIT_BYTES..], tail);
    assert_eq!(block.successors.len(), 1);
    // HCR_EL2.TPCP traps DC CIVAC at EL1: the PC gets a block that exits.
    let hcr = machine.cpu.read(SystemRegister::HCR_EL2);
    machine
        .cpu
        .registers
        .set(SystemRegister::HCR_EL2, 0, hcr | 1 << 23);
    machine.derived_changed();
    machine.cpu.pc = base;
    machine.host.exits = vec![fallthrough];
    machine.step().unwrap();
    let trapped = &machine.blocks[1];
    assert!(
        !trapped
            .variant
            .system
            .cache_clean
            .contains(cache_clean::Operations::CIVAC)
    );
    let code = &machine.host.installed[trapped.code.0 / NATIVE_CODE_STRIDE - 1];
    assert_eq!(
        code[code.len() - chain::DIRECT_EXIT_BYTES..],
        chain::direct_exit(GuestAddress(base + 4), ExitKind::System)
    );
    // Without TPCP, an unmapped Xt faults the native read; the engine
    // takes the level-1 translation fault as a cache maintenance one.
    machine.cpu.registers.set(SystemRegister::HCR_EL2, 0, hcr);
    machine.derived_changed();
    machine.cpu.pc = base;
    machine.cpu.state.x[3] = 0x4000_0040;
    let (entered, offset) = native_fault_site_in_entry(
        &mut machine,
        base,
        base + 4,
        stela_compiler::block::RecoverySiteKind::GuestAccess,
    );
    assert_eq!(
        &machine.fault_recovery[&entered].template.native.x86_64_code[offset..offset + 3],
        &[0x0f, 0xb6, 0x08],
        "actual MOVZX byte probe at the minted DC clean site"
    );
    machine.host.exits = vec![NativeExit::Fault(NativeFault {
        origin: crate::machine::NativeFaultOrigin::Exception,
        trap: 14,
        error_code: 0,
        spills: stela_compiler::block::HostSpillSnapshot::new(),
        registers: stela_compiler::block::HostGprSnapshot::legacy([0; 16]),
        offset,
        address: 0x4000_0040,
        write: false,
        cause: FaultCause::Device { physical: 0 },
    })];
    let exits = machine.statistics.system_exits;
    machine.step().unwrap();
    let esr = machine.cpu.read(SystemRegister::ESR_EL1);
    // EC 0x25, CM (bit 8) and WnR (bit 6), a level-1 translation fault.
    assert_eq!(esr >> 26, 0x25, "{esr:#x}");
    assert_eq!(esr & (1 << 8 | 1 << 6 | 0x3f), 1 << 8 | 1 << 6 | 0b000101);
    assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), 0x4000_0040);
    assert_eq!(machine.statistics.system_exits, exits + 1);
    assert_eq!(machine.exit_words().get(&DC_CIVAC), Some(&1));
}

#[test]
fn epan_makes_pan_cover_el0_execute_only_memory_on_the_chips_with_pan3() {
    const MSR_SCTLR_EL1_X0: u32 = 0xd518_1000;
    const AT_S1E1RP_X2: u32 = 0xd508_7902;
    const EPAN: u64 = 1 << 57;
    for (chip, pan3) in [
        (stela_contracts::Chip::AppleM2, false),
        (stela_contracts::Chip::AppleM4, true),
    ] {
        let mut machine = machine_on(chip, &[]);
        // A level-1 block maps VA 0-1 GiB at BASE, privileged
        // read/write and EL0 execute-only (AP 0b00, UXN 0).
        let block = BASE | 1 | 1 << 10;
        machine.host.ram[0x4000..0x4008].copy_from_slice(&block.to_le_bytes());
        let registers = &mut machine.cpu.registers;
        registers.set(SystemRegister::TCR_EL1, 0, 25 | 1 << 23 | 5 << 32);
        registers.set(SystemRegister::TTBR0_EL1, 0, BASE + 0x4000);
        machine.derived_changed();
        machine.cpu.state.x[0] = 1 | EPAN;
        machine.system_instruction(MSR_SCTLR_EL1_X0).unwrap();
        // EPAN holds only where FEAT_PAN3 is implemented.
        let sctlr = machine.cpu.read(SystemRegister::SCTLR_EL1);
        assert_eq!(sctlr & EPAN != 0, pan3, "{chip:?}");
        machine.cpu.pstate.pan = true;
        machine.cpu.state.x[2] = 0x1000;
        machine.system_instruction(AT_S1E1RP_X2).unwrap();
        let par = machine.cpu.read(SystemRegister::PAR_EL1);
        if pan3 {
            // A level-1 Permission fault.
            assert_eq!(par, 1 << 11 | 0b00_1101 << 1 | 1);
        } else {
            assert_eq!((par & 1, par & 0x0000_ffff_ffff_f000), (0, BASE + 0x1000));
        }
    }
}

#[test]
fn at_s1e1rp_honors_pan_where_s1e1r_ignores_it() {
    let mut machine = machine(&[]);
    // 4 KiB, 39-bit VA from level 1 at BASE + 0x4000, whose first entry
    // maps VA 0-1 GiB at BASE, EL0 read/write (AP 0b01).
    let block = BASE | 1 | 1 << 10 | 1 << 6;
    machine.host.ram[0x4000..0x4008].copy_from_slice(&block.to_le_bytes());
    let registers = &mut machine.cpu.registers;
    registers.set(SystemRegister::TCR_EL1, 0, 25 | 1 << 23 | 5 << 32);
    registers.set(SystemRegister::TTBR0_EL1, 0, BASE + 0x4000);
    registers.set(SystemRegister::SCTLR_EL1, 0, 1);
    machine.derived_changed();
    machine.cpu.pstate.pan = true;
    machine.cpu.state.x[2] = 0x1000;
    machine.system_instruction(0xd508_7802).unwrap(); // at s1e1r, x2
    let par = machine.cpu.read(SystemRegister::PAR_EL1);
    assert_eq!((par & 1, par & 0x0000_ffff_ffff_f000), (0, BASE + 0x1000));
    machine.system_instruction(0xd508_7902).unwrap(); // at s1e1rp, x2
    assert_eq!(
        machine.cpu.read(SystemRegister::PAR_EL1),
        1 << 11 | 0b00_1101 << 1 | 1
    );
    machine.cpu.pstate.pan = false;
    machine.system_instruction(0xd508_7902).unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::PAR_EL1) & 1, 0);
}

#[test]
fn instruction_and_data_aborts_report_their_origin_el() {
    let mut machine = machine(&[]);
    // 4 KiB, 39-bit VA: VA 0-1 GiB maps BASE (EL0 read/write), and the
    // next GiB is unmapped, a level-1 translation fault.
    let block = BASE | 1 | 1 << 10 | 1 << 6;
    machine.host.ram[0x4000..0x4008].copy_from_slice(&block.to_le_bytes());
    let registers = &mut machine.cpu.registers;
    registers.set(SystemRegister::TCR_EL1, 0, 25 | 1 << 23 | 5 << 32);
    registers.set(SystemRegister::TTBR0_EL1, 0, BASE + 0x4000);
    registers.set(SystemRegister::MAIR_EL1, 0, 0xff);
    registers.set(SystemRegister::SCTLR_EL1, 0, 1);
    registers.set(SystemRegister::VBAR_EL1, 0, 0x2_0000);
    machine.derived_changed();
    let unmapped = 0x4000_0000;
    let user = Pstate {
        el: 0,
        sp: false,
        daif: 0,
        ..Pstate::reset(1)
    };
    // Fetches: EC 0x20 from EL0 and 0x21 at EL1, IFSC level-1
    // translation fault, ELR and FAR the fetched address.
    for (pstate, ec, vector) in [(user, 0x20, 0x2_0400), (Pstate::reset(1), 0x21, 0x2_0200)] {
        machine.cpu.set_pstate(pstate);
        machine.cpu.pc = unmapped;
        machine.step().unwrap();
        let esr = machine.cpu.read(SystemRegister::ESR_EL1);
        assert_eq!(
            (machine.cpu.pc, esr >> 26, esr & 0x3f),
            (vector, ec, 0b00_0101)
        );
        assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), unmapped);
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), unmapped);
    }
    // A load from EL0 (LDTR, which the engine performs): EC 0x24 with
    // the faulting address in FAR and the load's address in ELR.
    machine.cpu.set_pstate(user);
    machine.cpu.pc = 0x1000;
    machine.cpu.state.x[2] = unmapped + 8;
    machine.system_instruction(0xf840_0841).unwrap(); // ldtr x1, [x2]
    let esr = machine.cpu.read(SystemRegister::ESR_EL1);
    assert_eq!(
        (machine.cpu.pc, esr >> 26, esr & 0x3f),
        (0x2_0400, 0x24, 0b00_0101)
    );
    assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), unmapped + 8);
    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), 0x1000);
    // A level-1 table outside RAM: a synchronous external abort on the
    // walk (DFSC 0b010101), taken at EL1, or at EL2 under HCR_EL2.TEA.
    machine
        .cpu
        .registers
        .set(SystemRegister::TTBR0_EL1, 0, 0x10_0000_0000);
    machine
        .cpu
        .registers
        .set(SystemRegister::VBAR_EL2, 0, 0x4_0000);
    machine.derived_changed();
    for (hcr, el, vector, esr) in [
        (0, 1, 0x2_0200, SystemRegister::ESR_EL1),
        (1 << 37, 2, 0x4_0400, SystemRegister::ESR_EL2),
    ] {
        machine.cpu.registers.set(SystemRegister::HCR_EL2, 0, hcr);
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.state.x[2] = 0x108;
        machine.system_instruction(0xf840_0841).unwrap(); // ldtr x1, [x2]
        let syndrome = machine.cpu.read(esr);
        let ec = if el == 2 { 0x24 } else { 0x25 };
        assert_eq!(
            (
                machine.cpu.pstate.el,
                machine.cpu.pc,
                syndrome >> 26,
                syndrome & 0x3f
            ),
            (el, vector, ec, 0b01_0101)
        );
    }
}

#[test]
fn stage_two_faults_go_to_el2_with_hpfar_and_at_reports_both_stages() {
    let mut machine = machine(&[]);
    // EL2 host with HCR_EL2.VM: a 40-bit IPA from two concatenated
    // level-1 tables at BASE + 0x4000, whose entry for IPA BASE maps that
    // GiB to itself, Normal Write-Back, read/write.
    let vtcr = 24 | 1 << 6 | 5 << 16 | 1 << 31;
    let tables = BASE + 0x4000;
    let block = BASE | 1 | 1 << 10 | 0b11 << 6 | 0b1111 << 2 | 0b11 << 8;
    let slot = (tables - BASE + (BASE >> 30) * 8) as usize;
    machine.host.ram[slot..slot + 8].copy_from_slice(&block.to_le_bytes());
    machine.cpu.set_pstate(Pstate::reset(2));
    let registers = &mut machine.cpu.registers;
    registers.set(SystemRegister::HCR_EL2, 0, 1 << 34 | 1);
    registers.set(SystemRegister::VTCR_EL2, 0, vtcr);
    registers.set(SystemRegister::VTTBR_EL2, 0, tables);
    registers.set(SystemRegister::VBAR_EL2, 0, 0x2_0000);
    let unmapped = 0x1_0000_0000;
    let hpfar = (unmapped >> 12) << 4;

    // AT S12E1R walks both stages (EL1&0 stage 1 is off); AT S1E1R
    // stops at the IPA; a stage-2 fault reports S=1 in PAR_EL1.
    machine.cpu.state.x[2] = BASE + 0x108;
    // AT S12E1R, S12E1W, S12E0R and S12E0W, x2.
    for word in [0xd50c_7882, 0xd50c_78a2, 0xd50c_78c2, 0xd50c_78e2] {
        machine.cpu.registers.set(SystemRegister::PAR_EL1, 0, 1);
        machine.system_instruction(word).unwrap();
        let par = machine.cpu.read(SystemRegister::PAR_EL1);
        assert_eq!(
            (par & 1, par & 0x0000_ffff_ffff_f000),
            (0, BASE),
            "{word:#x}"
        );
    }
    machine.cpu.state.x[2] = unmapped;
    machine.system_instruction(0xd50c_7882).unwrap();
    let fault = 1 << 11 | 1 << 9 | 0b00_0101 << 1 | 1;
    assert_eq!(machine.cpu.read(SystemRegister::PAR_EL1), fault);
    machine.system_instruction(0xd508_7802).unwrap(); // at s1e1r, x2
    let par = machine.cpu.read(SystemRegister::PAR_EL1);
    assert_eq!((par & 1, par & 0x0000_ffff_ffff_f000), (0, unmapped));

    // At EL1 with stage 1 off, data is Device-nGnRnE, so DC ZVA takes
    // the stage-1 Alignment fault (DFSC 0b100001, WnR) to EL1 with FAR
    // Xt, before stage 2 sees the IPA (Arm `AArch64_S1DisabledOutput`).
    machine
        .cpu
        .registers
        .set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
    machine.cpu.set_pstate(Pstate::reset(1));
    let pc = machine.cpu.pc;
    machine.system_instruction(0xd50b_7422).unwrap(); // dc zva, x2
    assert_eq!((machine.cpu.pstate.el, machine.cpu.pc), (1, 0x1_0200));
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x9600_0061);
    assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), unmapped);
    // Under HCR_EL2.DC stage 1 output is Normal: DC ZVA to an IPA stage
    // 2 does not map is a Data Abort taken to EL2 from the lower EL,
    // with FAR and HPFAR.
    machine
        .cpu
        .registers
        .set(SystemRegister::HCR_EL2, 0, 1 << 34 | 1 << 12 | 1);
    machine.cpu.set_pstate(Pstate::reset(1));
    machine.cpu.pc = pc;
    machine.system_instruction(0xd50b_7422).unwrap(); // dc zva, x2
    machine
        .cpu
        .registers
        .set(SystemRegister::HCR_EL2, 0, 1 << 34 | 1);
    assert_eq!(machine.cpu.pstate.el, 2);
    assert_eq!(machine.cpu.pc, 0x2_0400);
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL2), 0x9200_0045);
    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL2), pc);
    assert_eq!(machine.cpu.read(SystemRegister::FAR_EL2), unmapped);
    assert_eq!(machine.cpu.read(SystemRegister::HPFAR_EL2), hpfar);

    // AT S1E1R at EL1 whose stage-1 table is at an unmapped IPA: the
    // stage-2 fault on the walk is taken to EL2 with S1PTW, CM and WnR.
    machine.cpu.set_pstate(Pstate::reset(1));
    let registers = &mut machine.cpu.registers;
    registers.set(SystemRegister::HPFAR_EL2, 0, 0);
    registers.set(SystemRegister::SCTLR_EL1, 0, 1);
    registers.set(SystemRegister::TCR_EL1, 0, 25 | 1 << 23 | 5 << 32);
    registers.set(SystemRegister::TTBR0_EL1, 0, unmapped);
    machine.derived_changed();
    machine.cpu.state.x[2] = 0x1000;
    machine.system_instruction(0xd508_7802).unwrap(); // at s1e1r, x2
    assert_eq!(machine.cpu.pstate.el, 2);
    assert_eq!(
        machine.cpu.read(SystemRegister::ESR_EL2),
        0x9200_0000 | 1 << 8 | 1 << 7 | 1 << 6 | 0b00_0101
    );
    assert_eq!(machine.cpu.read(SystemRegister::FAR_EL2), 0x1000);
    assert_eq!(machine.cpu.read(SystemRegister::HPFAR_EL2), hpfar);
}

#[test]
fn debug_state_only_movt_is_undefined() {
    for word in [0xc04c_73e5, 0xc04e_03e0] {
        let mut machine = machine(&[]);
        machine.system_instruction(word).unwrap();
        assert_eq!(
            machine.cpu.read(SystemRegister::ESR_EL1),
            0x0200_0000,
            "{word:#x}"
        );
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE);
    }
}

#[test]
fn eret_at_gl_enters_gl0_whose_exceptions_return_to_gl() {
    let mut machine = machine(&[]);
    machine.cpu.state.x[0] = 1;
    machine.cpu.state.x[1] = 0x9000;
    machine.cpu.state.x[2] = 0xa000;
    machine.cpu.state.x[3] = 0x3c0;
    machine.cpu.state.x[4] = 0xb000;
    for word in [
        0xd51e_f100, // msr SPRR_CONFIG_EL1, x0
        0xd51e_f140, // msr GXF_CONFIG_EL1, x0
        0xd51e_f821, // msr GXF_ENTER_EL1, x1
        0x0020_1420, // genter
        0xd51e_fa42, // msr VBAR_GL1, x2
        0xd51e_fa63, // msr SPSR_GL1, x3 (EL0t, DAIF masked)
        0xd51e_fac4, // msr ELR_GL1, x4
        0xd69f_03e0, // eret
    ] {
        machine.system_instruction(word).unwrap();
    }
    assert_eq!(
        (machine.cpu.pstate.el, machine.cpu.pstate.guarded),
        (0, true)
    );
    assert_eq!(machine.cpu.pc, 0xb000);
    assert!(machine.host.regimes.last().unwrap().requester.guarded);
    // An SVC at GL0 is taken at VBAR_GL1's lower-EL vector.
    machine.system_instruction(0xd400_0001).unwrap();
    assert_eq!(
        (machine.cpu.pstate.el, machine.cpu.pstate.guarded),
        (1, true)
    );
    assert_eq!(machine.cpu.pc, 0xa400);
    let bank = &machine.cpu.apple.guarded[0];
    assert_eq!((bank.elr, bank.spsr, bank.aspsr), (0xb004, 0x3c0, 1));
    assert_eq!(bank.esr, 0x5600_0000);
    // GEXIT with ASPSR_GL bit 0 set resumes GL0.
    machine.system_instruction(0x0020_1400).unwrap();
    assert_eq!(
        (machine.cpu.pstate.el, machine.cpu.pstate.guarded),
        (0, true)
    );
    assert_eq!(machine.cpu.pc, 0xb004);
    // GL0 has no GEXIT.
    machine.system_instruction(0x0020_1400).unwrap();
    assert_eq!(machine.cpu.pc, 0xa400);
    assert_eq!(machine.cpu.apple.guarded[0].esr, 0x0200_0000);
}

#[test]
fn genter_gexit_and_guarded_exceptions_use_the_gl1_bank() {
    let mut machine = machine(&[]);
    let cpu = &mut machine.cpu;
    cpu.state.x[0] = 1;
    cpu.state.x[1] = 0x9000;
    cpu.state.x[2] = 0xa000;
    cpu.state.sp = 0x7000;
    // GENTER is UNDEFINED until SPRR and GXF are enabled.
    machine.system_instruction(0x0020_1420).unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
    machine.cpu.pc = BASE;
    for word in [
        0xd51e_f100, // msr SPRR_CONFIG_EL1, x0
        0xd51e_f140, // msr GXF_CONFIG_EL1, x0
        0xd51e_f821, // msr GXF_ENTER_EL1, x1
    ] {
        machine.system_instruction(word).unwrap();
    }
    // GL1 bank registers are refused outside the guarded level, reported
    // once.
    machine.system_instruction(0xd51e_fa42).unwrap();
    assert_eq!(machine.take_unmodeled().len(), 1);
    let genter_pc = machine.cpu.pc;
    machine.system_instruction(0x0020_1420).unwrap();
    assert!(machine.cpu.pstate.guarded);
    assert_eq!(machine.cpu.pc, 0x9000);
    assert_eq!(machine.cpu.apple.guarded[0].elr, genter_pc + 4);
    assert_eq!(machine.cpu.apple.guarded[0].aspsr, 0);
    assert!(machine.host.regimes.last().unwrap().requester.guarded);
    // A fresh GL1 stack; EL1's is banked.
    assert_eq!((machine.cpu.state.sp, machine.cpu.sp(1)), (0, 0x7000));
    machine.cpu.state.sp = 0x8000;
    machine.system_instruction(0xd51e_fa42).unwrap(); // msr VBAR_GL1, x2
    machine.system_instruction(0xd53e_f803).unwrap(); // mrs x3, GXF_STATUS_EL1
    assert_eq!(machine.cpu.state.x[3], 1);
    // An SVC at GL1 is taken at VBAR_GL1 and records a GL return.
    let svc_pc = machine.cpu.pc;
    let el1_elr = machine.cpu.read(SystemRegister::ELR_EL1);
    machine.system_instruction(0xd400_0001).unwrap();
    assert_eq!(machine.cpu.pc, 0xa200);
    assert_eq!(machine.cpu.apple.guarded[0].elr, svc_pc + 4);
    assert_eq!(machine.cpu.apple.guarded[0].esr, 0x5600_0000);
    assert_eq!(machine.cpu.apple.guarded[0].aspsr, 1);
    assert_eq!(
        machine.cpu.read(SystemRegister::ELR_EL1),
        el1_elr,
        "EL1's ELR is untouched"
    );
    // GEXIT returns to GL1, then (with ASPSR clear) to EL1.
    machine.system_instruction(0x0020_1400).unwrap();
    assert!(machine.cpu.pstate.guarded);
    assert_eq!(machine.cpu.pc, svc_pc + 4);
    machine.cpu.apple.guarded[0].aspsr = 0;
    machine.cpu.apple.guarded[0].elr = genter_pc + 4;
    machine.cpu.apple.guarded[0].spsr = 0x3c5;
    machine.system_instruction(0x0020_1400).unwrap();
    assert!(!machine.cpu.pstate.guarded);
    assert_eq!(
        (machine.cpu.pc, machine.cpu.state.sp),
        (genter_pc + 4, 0x7000)
    );
    assert_eq!(machine.cpu.apple.guarded[0].sp, 0x8000);
    // GEXIT outside GL is UNDEFINED; APSTS reports the master key ready.
    machine.system_instruction(0x0020_1400).unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
    machine.cpu.pstate = Pstate::reset(1);
    machine.system_instruction(0xd53e_fc85).unwrap(); // mrs x5, APSTS_EL1
    assert_eq!(machine.cpu.state.x[5], 1);
}

/// A machine at EL1h with SCTLR_EL1.EnIA and EnIB set, HCR_EL2.API set,
/// 39-bit TTBR1 addresses without TBI and both instruction keys loaded.
fn pac_machine() -> Machine<FakeHost, NoDevices> {
    pac_setup(machine(&[]))
}

/// [`pac_machine`] on `chip`, running `words` at BASE.
fn pac_machine_for(chip: stela_contracts::Chip, words: &[u32]) -> Machine<FakeHost, NoDevices> {
    pac_setup(machine_on(chip, words))
}

fn pac_setup(mut machine: Machine<FakeHost, NoDevices>) -> Machine<FakeHost, NoDevices> {
    let registers = &mut machine.cpu.registers;
    registers.set(SystemRegister::TCR_EL1, 0, 25 << 16 | 25);
    for (register, value) in [
        (SystemRegister::APIAKeyLo_EL1, 0x1111_2222_3333_4444),
        (SystemRegister::APIAKeyHi_EL1, 0x5555_6666_7777_8888),
        (SystemRegister::APIBKeyLo_EL1, 0x0123_4567_89ab_cdef),
        (SystemRegister::APIBKeyHi_EL1, 0xfedc_ba98_7654_3210),
    ] {
        registers.set(register, 0, value);
    }
    let sctlr = registers.get(SystemRegister::SCTLR_EL1, 0) | 1 << 31 | 1 << 30;
    registers.set(SystemRegister::SCTLR_EL1, 0, sctlr);
    registers.set(SystemRegister::HCR_EL2, 0, 1 << HCR_API);
    registers.set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
    registers.set(SystemRegister::VBAR_EL2, 0, 0x4_0000);
    machine.derived_changed();
    machine
}

#[test]
fn apple_el2_keys_feed_pac_without_aliasing_lower_keys_or_inventing_unknown_pairs() {
    use crate::machine::system::key;
    use stela_compiler::aarch64::system::registers::Encoding;
    const PACIASP: u32 = 0xd503_233f;
    let mut machine = pac_machine();
    machine.cpu.pstate = Pstate::reset(2);
    machine
        .cpu
        .registers
        .set(SystemRegister::TCR_EL2, 0, 25 | 25 << 16);
    machine.cpu.registers.set(SystemRegister::SCTLR_EL2, 0, 0);
    machine.derived_changed();
    machine.cpu.state.x[30] = 0x4000;
    machine.cpu.state.sp = 0x8000;
    // Disabled PAC is still a NOP with no initialized host keys.
    machine.pointer_authentication(PACIASP).unwrap();
    assert_eq!(machine.cpu.state.x[30], 0x4000);
    machine
        .cpu
        .registers
        .set(SystemRegister::SCTLR_EL2, 0, 1 << 31);
    machine.derived_changed();
    let before = machine.cpu.pc;
    assert!(matches!(
        machine.pointer_authentication(PACIASP),
        Err(Stop::Unsupported(_))
    ));
    assert_eq!((machine.cpu.pc, machine.cpu.state.x[30]), (before, 0x4000));
    // The unknown IA pair never opens; disabled IB completes unchanged.
    let ia = usize::from(x86_64_pointer::key_index(PointerAuthenticationKey::Ia));
    let ib = usize::from(x86_64_pointer::key_index(PointerAuthenticationKey::Ib));
    assert_eq!(machine.pointer.tags[ia], 0);
    assert_eq!(machine.pointer.tags[ib], x86_64_pointer::DISABLED);
    // First LLB MSR encoding; the other half must stay unknown.
    machine.cpu.state.x[1] = 11;
    machine.system_instruction(0xd51e_fd01).unwrap();
    assert_eq!(machine.pointer_keys(), [None; 5]);
    assert!(matches!(
        machine.pointer_authentication(PACIASP),
        Err(Stop::Unsupported(_))
    ));
    machine.cpu.state.x[0] = 21;
    machine.system_instruction(0xd51e_fd20).unwrap();
    assert_eq!(
        machine.pointer_keys(),
        [Some([11, 21]), None, None, None, None]
    );
    let expected = machine
        .pointer_context()
        .unwrap()
        .sign(stela_contracts::pauth::Key::Ia, 0x4000, 0x8000)
        .unwrap();
    machine.pointer_authentication(PACIASP).unwrap();
    assert_eq!(machine.cpu.state.x[30], expected);
    let first_generation = machine.pointer.generation;
    assert_ne!(machine.pointer.tags[0], 0);

    // Every source-written pair owns separate halves; a real MSR moves
    // native PAC tags off the cached inputs' generation before any
    // further code can consume them.
    for pair in 0..5 {
        for half in 0..2 {
            let index = pair * 2 + half;
            let encoding = Encoding::new(3, 6, 15, 13 + (index / 8) as u8, (index % 8) as u8);
            machine.cpu.state.x[0] = 100 + index as u64;
            machine
                .system_instruction(0xd500_0000 | u32::from(key(encoding)) << 5)
                .unwrap();
            assert!(machine.pointer.tags.iter().all(|&tag| tag == 0
                || tag == x86_64_pointer::DISABLED
                || tag >> 8 != first_generation));
        }
    }
    assert_eq!(
        machine.pointer_keys(),
        [
            Some([100, 101]),
            Some([102, 103]),
            Some([104, 105]),
            Some([106, 107]),
            Some([108, 109])
        ]
    );
    machine.cpu.state.x[30] = 0x4000;
    machine.pointer_authentication(PACIASP).unwrap();
    assert_ne!(machine.pointer.generation, first_generation);
    assert_ne!(machine.cpu.state.x[30], expected);
    assert!(
        machine
            .pointer_context()
            .unwrap()
            .generic_code(7, 9)
            .is_ok()
    );
    // Standard EL1 slots are a distinct canonical bank, not C13 storage.
    assert_eq!(
        machine.cpu.read(SystemRegister::APIAKeyLo_EL1),
        0x1111_2222_3333_4444
    );
    machine.cpu.pstate = Pstate::reset(1);
    machine.derived_changed();
    assert_eq!(
        machine.pointer_keys()[0],
        Some([0x1111_2222_3333_4444, 0x5555_6666_7777_8888])
    );
    assert_ne!(
        machine
            .pointer_context()
            .unwrap()
            .sign(stela_contracts::pauth::Key::Ia, 0x4000, 0x8000)
            .unwrap(),
        expected
    );
    // A read or a lower-EL access has no source-checked permissions:
    // each is reported once.
    machine.system_instruction(0xd51e_fd01).unwrap();
    machine.cpu.pstate = Pstate::reset(2);
    machine.system_instruction(0xd53e_fd01).unwrap();
    assert_eq!(machine.take_unmodeled().len(), 2);
}

#[test]
fn standard_el2_key_writes_feed_pacga_without_mutating_the_lower_bank() {
    use crate::machine::system::key;
    use stela_compiler::aarch64::system::registers::Encoding;
    // Original SPTM's early canary instruction, used here with authored
    // operands. Its preceding standard-name MSRs must feed EL2 PAC.
    const PACGA: u32 = 0x9ac0_33e1;
    let mut machine = pac_machine_for(stela_contracts::Chip::AppleM2, &[PACGA]);
    machine
        .cpu
        .registers
        .set(SystemRegister::APGAKeyLo_EL1, 0, 91);
    machine
        .cpu
        .registers
        .set(SystemRegister::APGAKeyHi_EL1, 0, 92);
    machine.cpu.pstate = Pstate::reset(2);
    machine.cpu.state.x[0] = 0x5354_4143_4b47_5244;
    let modifier = machine.cpu.state.x[0];
    let before = machine.cpu.pc;
    assert!(matches!(
        machine.pointer_authentication(PACGA),
        Err(Stop::Unsupported(_))
    ));
    assert_eq!(machine.cpu.pc, before);
    for (half, value) in [11, 21].into_iter().enumerate() {
        machine.cpu.state.x[2] = value;
        let encoding = Encoding::new(3, 0, 2, 3, half as u8);
        machine
            .system_instruction(0xd500_0000 | u32::from(key(encoding)) << 5 | 2)
            .unwrap();
        if half == 0 {
            assert!(!machine.pointer_context().unwrap().has_generic_key());
        }
    }
    machine.cpu.pc = BASE;
    machine.host.exits.push(NativeExit::Exit {
        next_pc: BASE,
        kind: ExitKind::PointerAuthentication as u64,
    });
    machine.step().unwrap();
    let expected = pauth::Context::new_with_version(
        0,
        pauth::Keys::from_optional_words([None; 4]).with_generic_words([11, 21]),
        machine.pointer_version().unwrap(),
    )
    .generic_code(0, modifier)
    .unwrap();
    assert_eq!(
        (machine.cpu.pc, machine.cpu.state.x[1]),
        (BASE + 4, expected)
    );
    assert_eq!(machine.cpu.read(SystemRegister::APGAKeyLo_EL1), 91);
    assert_eq!(machine.cpu.read(SystemRegister::APGAKeyHi_EL1), 92);
    machine.cpu.pstate = Pstate::reset(1);
    machine.derived_changed();
    assert_eq!(machine.pointer_keys()[4], Some([91, 92]));
}

#[test]
fn el0_in_the_host_uses_the_el2_keys() {
    use crate::machine::system::key;
    const HCR_E2H: u64 = 1 << 34;
    use stela_compiler::aarch64::system::registers::Encoding;
    let mut machine = pac_machine();
    machine.cpu.pstate = Pstate::reset(2);
    for (half, value) in [31, 32].into_iter().enumerate() {
        machine.cpu.state.x[2] = value;
        let encoding = Encoding::new(3, 0, 2, 1, 2 + half as u8);
        machine
            .system_instruction(0xd500_0000 | u32::from(key(encoding)) << 5 | 2)
            .unwrap();
    }
    let el2 = machine.pointer_keys();
    assert_eq!(el2[1], Some([31, 32]));
    machine.cpu.pstate = Pstate::reset(0);
    machine
        .cpu
        .registers
        .set(SystemRegister::HCR_EL2, 0, HCR_E2H | 1 << HCR_TGE);
    machine.derived_changed();
    assert_eq!(machine.pointer_keys(), el2);
    // A guest's EL0 keeps the lower bank.
    machine
        .cpu
        .registers
        .set(SystemRegister::HCR_EL2, 0, HCR_E2H);
    machine.derived_changed();
    assert_eq!(
        machine.pointer_keys()[1],
        Some([0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210])
    );
}

const PACM: u32 = 0xd503_24ff;
/// HCRX_EL2.SCTLR2En and PACMEn, and SCTLR2_EL1.EnPACM.
fn enable_pacm(machine: &mut Machine<FakeHost, NoDevices>) {
    let registers = &mut machine.cpu.registers;
    registers.set(SystemRegister::HCRX_EL2, 0, 1 << 24 | 1 << 15);
    registers.set(SystemRegister::SCTLR2_EL1, 0, 1 << 7);
}

#[test]
fn pacm_gives_the_next_pac_instruction_a_second_modifier_on_the_m6() {
    const PACIASP: u32 = 0xd503_233f;
    const AUTIASP: u32 = 0xd503_23bf;
    const NOP: u32 = 0xd503_201f;
    let code = [PACM, PACIASP, PACM, AUTIASP, PACM, NOP, PACIASP];
    let mut machine = pac_machine_for(stela_contracts::Chip::AppleM6, &code);
    let pointer = 0xffff_ff80_0000_4000_u64;
    let sp = 0xffff_ff80_0001_0000_u64;
    machine.cpu.state.x[30] = pointer;
    machine.cpu.state.sp = sp;
    let pac = |machine: &mut Machine<FakeHost, NoDevices>, at: u64| {
        assert_eq!(machine.cpu.pc, at);
        machine.host.exits.push(NativeExit::Exit {
            next_pc: at,
            kind: ExitKind::PointerAuthentication as u64,
        });
        machine.step().unwrap();
    };
    // HCRX_EL2.PACMEn clear makes PACM leave PSTATE.PACM clear.
    pac(&mut machine, BASE);
    assert!(!machine.cpu.pstate.pacm);
    machine.cpu.pc = BASE;
    enable_pacm(&mut machine);
    pac(&mut machine, BASE);
    assert!(machine.cpu.pstate.pacm);
    // PACIASP signs with SP and its own PC, then PACM lapses.
    pac(&mut machine, BASE + 4);
    let context = machine.pointer_context().unwrap();
    let signed = context
        .sign_two_modifiers(stela_contracts::pauth::Key::Ia, pointer, sp, BASE + 4)
        .unwrap();
    assert_eq!(machine.cpu.state.x[30], signed);
    assert!(!machine.cpu.pstate.pacm);
    // AUTIASP takes X16, the signing PACIASP's address, as the second.
    machine.cpu.state.x[16] = BASE + 4;
    pac(&mut machine, BASE + 8);
    pac(&mut machine, BASE + 12);
    assert_eq!(machine.cpu.state.x[30], pointer);
    // Any other instruction lapses PACM: the PACIASP after the NOP signs
    // with SP alone.
    pac(&mut machine, BASE + 16);
    machine.host.exits.push(NativeExit::Exit {
        next_pc: BASE + 24,
        kind: ExitKind::Fallthrough as u64,
    });
    machine.step().unwrap();
    assert!(!machine.cpu.pstate.pacm);
    pac(&mut machine, BASE + 24);
    assert_eq!(
        machine.cpu.state.x[30],
        context
            .sign(stela_contracts::pauth::Key::Ia, pointer, sp)
            .unwrap()
    );
}

#[test]
fn exceptions_save_pacm_in_spsr_and_returns_restore_it_where_enabled() {
    const PACIASP: u32 = 0xd503_233f;
    const ERET: u32 = 0xd69f_03e0;
    const SPSR_PACM: u64 = 1 << 35;
    let mut machine = pac_machine_for(stela_contracts::Chip::AppleM6, &[]);
    enable_pacm(&mut machine);
    machine.system_instruction_for_test(PACM);
    assert!(machine.cpu.pstate.pacm);
    // HCR_EL2.API clear traps the PACIASP to EL2, which saves PACM and
    // clears it.
    machine.cpu.registers.set(SystemRegister::HCR_EL2, 0, 0);
    let pc = machine.cpu.pc;
    machine.system_instruction_for_test(PACIASP);
    assert_eq!(machine.cpu.pstate.el, 2);
    assert_ne!(machine.cpu.read(SystemRegister::SPSR_EL2) & SPSR_PACM, 0);
    assert!(!machine.cpu.pstate.pacm);
    // The return restores it for the re-executed PACIASP.
    machine.system_instruction(ERET).unwrap();
    assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (pc, 1));
    assert!(machine.cpu.pstate.pacm);
    // Where IsPACMEnabled is false at the EL returned to it reads 0.
    machine.cpu.set_pstate(Pstate::reset(2));
    machine.cpu.registers.set(SystemRegister::SCTLR2_EL1, 0, 0);
    machine.system_instruction(ERET).unwrap();
    assert!(!machine.cpu.pstate.pacm);
}

#[test]
fn pauth_lr_forms_use_two_modifiers_and_fault_when_they_fail() {
    const PACIASPPC: u32 = 0xdac1_a3fe;
    const PACIA171615: u32 = 0xdac1_8bfe;
    const AUTIA171615: u32 = 0xdac1_bbfe;
    // AUTIASPPC and RETAASPPC with imm16 n: the label is PC - 4n.
    let autiasppc = |n: u32| 0xf380_001f | n << 5;
    let retaasppc = |n: u32| 0x5500_001f | n << 5;
    let pointer = 0xffff_ff80_0000_4000_u64;
    let sp = 0xffff_ff80_0001_0000_u64;
    let mut machine = pac_machine_for(stela_contracts::Chip::AppleM6, &[]);
    let context = machine.pointer_context().unwrap();
    let at = |machine: &mut Machine<FakeHost, NoDevices>, pc: u64, word: u32| {
        machine.cpu.pc = pc;
        machine.system_instruction_for_test(word);
    };
    machine.cpu.state.sp = sp;
    machine.cpu.state.x[30] = pointer;
    at(&mut machine, BASE, PACIASPPC);
    let signed = context
        .sign_two_modifiers(stela_contracts::pauth::Key::Ia, pointer, sp, BASE)
        .unwrap();
    assert_eq!(
        (machine.cpu.state.x[30], machine.cpu.pc),
        (signed, BASE + 4)
    );
    // AUTIASPPC names the PACIASPPC 8 bytes back.
    at(&mut machine, BASE + 8, autiasppc(2));
    assert_eq!(machine.cpu.state.x[30], pointer);
    // RETAASPPC authenticates and returns.
    machine.cpu.state.x[30] = signed;
    at(&mut machine, BASE + 12, retaasppc(3));
    assert_eq!(machine.cpu.pc, pointer);
    // A wrong label fails: EC 0x1C, ISS {instruction key A}. The
    // modifier takes the label's bits 36:5, so this one is 0x40 away.
    machine.cpu.state.x[30] = signed;
    at(&mut machine, BASE + 0x48, autiasppc(2));
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x7200_0000);
    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE + 0x48);
    // The *171615 forms sign X17 with X16 and X15.
    machine.cpu.set_pstate(Pstate::reset(1));
    let state = &mut machine.cpu.state;
    (state.x[17], state.x[16], state.x[15]) = (pointer, 0x1234, 0x5678);
    at(&mut machine, BASE, PACIA171615);
    assert_eq!(
        machine.cpu.state.x[17],
        context
            .sign_two_modifiers(stela_contracts::pauth::Key::Ia, pointer, 0x1234, 0x5678)
            .unwrap()
    );
    at(&mut machine, BASE + 4, AUTIA171615);
    assert_eq!(machine.cpu.state.x[17], pointer);
    // PACIASPPC is a landing pad as PACIASP is; PACNBIASPPC is not.
    machine.cpu.pstate.btype = 0b01;
    assert!(machine.branch_target_compatible(PACIASPPC));
    assert!(!machine.branch_target_compatible(0xdac1_83fe));
    // Without FEAT_PAuth_LR (the M5) they are UNDEFINED.
    let mut machine = pac_machine_for(stela_contracts::Chip::AppleM5, &[]);
    at(&mut machine, BASE, PACIASPPC);
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
}

#[test]
fn pac_uses_the_guest_keys_regime_layout_and_sctlr_enables() {
    const PACIBSP: u32 = 0xd503_237f;
    const AUTIBSP: u32 = 0xd503_23ff;
    let mut machine = pac_machine();
    let sctlr = machine.cpu.read(SystemRegister::SCTLR_EL1);
    machine
        .cpu
        .registers
        .set(SystemRegister::SCTLR_EL1, 0, sctlr & !(1 << 30));
    let pointer = 0xffff_ff80_0000_4000_u64;
    machine.cpu.state.x[30] = pointer;
    machine.cpu.state.sp = 0xffff_ff80_0001_0000;
    // EnIB clear: PACIBSP leaves LR unchanged.
    machine.system_instruction_for_test(PACIBSP);
    assert_eq!(machine.cpu.state.x[30], pointer);
    machine
        .cpu
        .registers
        .set(SystemRegister::SCTLR_EL1, 0, sctlr);
    machine.system_instruction_for_test(PACIBSP);
    let signed = machine.cpu.state.x[30];
    assert_ne!(signed, pointer);
    assert_eq!(
        signed & 0x0000_007f_ffff_ffff,
        pointer & 0x0000_007f_ffff_ffff
    );
    machine.system_instruction_for_test(AUTIBSP);
    assert_eq!(machine.cpu.state.x[30], pointer);
    // PACIA, PACIB, PACDA and PACDB x1, x2 follow EnIA, EnIB, EnDA and
    // EnDB.
    // At EL2 the EL2&0 regime's SCTLR_EL2 and TCR_EL2 govern instead.
    machine
        .cpu
        .registers
        .set(SystemRegister::TCR_EL2, 0, 25 << 16 | 25);
    // The source-checked Apple host keys have an independent owner.
    // Give this enable/layout fixture explicit inputs through real MSRs,
    // rather than borrowing the lower bank or assuming reset zeroes.
    machine.cpu.set_pstate(Pstate::reset(2));
    for word in 0..8 {
        machine.cpu.state.x[0] = 11 + word;
        machine
            .system_instruction(0xd51e_fd00 | (word as u32) << 5)
            .unwrap();
    }
    let sctlr2 = machine.cpu.read(SystemRegister::SCTLR_EL2);
    for (el, register, base) in [
        (1, SystemRegister::SCTLR_EL1, sctlr),
        (2, SystemRegister::SCTLR_EL2, sctlr2),
    ] {
        machine.cpu.set_pstate(Pstate::reset(el));
        for (key, (word, enable)) in [
            (0xdac1_0041, 31),
            (0xdac1_0441, 30),
            (0xdac1_0841, 27),
            (0xdac1_0c41, 13),
        ]
        .into_iter()
        .enumerate()
        {
            for enabled in [false, true] {
                let bit = u64::from(enabled) << enable;
                machine
                    .cpu
                    .registers
                    .set(register, 0, base & !(1 << enable) | bit);
                // As an MSR of the register does.
                machine.derived_changed();
                machine.cpu.state.x[1] = pointer;
                machine.cpu.state.x[2] = 0x55;
                machine.system_instruction_for_test(word);
                assert_eq!(
                    machine.cpu.state.x[1] != pointer,
                    enabled,
                    "EL{el} {word:#x}"
                );
                // A disabled key lets thunks complete with the pointer
                // until derived state changes.
                assert_eq!(
                    machine.pointer.tags[key] == x86_64_pointer::DISABLED,
                    !enabled,
                    "EL{el} {word:#x}"
                );
                // Unchanged state reopens the same tag words.
                let tags = machine.pointer.tags;
                machine.derived_changed();
                assert_eq!(machine.pointer.tags, tags, "EL{el} {word:#x}");
            }
        }
    }
}

#[test]
fn pac_follows_the_chips_version() {
    const PACIBSP: u32 = 0xd503_237f;
    const AUTIBSP: u32 = 0xd503_23ff;
    let pointer = 0xffff_ff80_0000_4000_u64;
    let run = |chip| {
        let mut machine = pac_machine_for(chip, &[]);
        machine.cpu.state.x[30] = pointer;
        machine.cpu.state.sp = 0xffff_ff80_0001_0000;
        machine.system_instruction_for_test(PACIBSP);
        let signed = machine.cpu.state.x[30];
        // A different modifier fails the AUT.
        machine.cpu.state.sp += 16;
        let pc = machine.cpu.pc;
        machine.system_instruction_for_test(AUTIBSP);
        (signed, machine.cpu.state.x[30], machine.cpu.pc != pc + 4)
    };
    // The M1 (no PAuth2 or FPAC) replaces the extension bits with the PAC
    // and a failed AUT writes the key B error code without an exception,
    // at bits 62:61 without TBI (Arm `Auth`); the M2 XORs the PAC in and
    // faults.
    let (classic, failed, taken) = run(stela_contracts::Chip::AppleM1);
    assert_eq!(
        classic & 0x0000_007f_ffff_ffff,
        pointer & 0x0000_007f_ffff_ffff
    );
    assert!(!taken);
    assert_eq!(failed, pointer & !(0b11 << 61) | 0b10 << 61);
    let (enhanced, _, taken) = run(stela_contracts::Chip::AppleM2);
    assert_ne!(enhanced, classic);
    assert!(taken);
}

#[test]
fn cpa_arithmetic_completes_unchecked_on_the_chips_with_feat_cpa() {
    // addpt x0, x1, x2, lsl #3; subpt sp, sp, x2; maddpt x3, x1, x2, x4;
    // msubpt x5, x1, x2, x4.
    const ADDPT: u32 = 0x9a02_2c20;
    const SUBPT_SP: u32 = 0xda02_23ff;
    const MADDPT: u32 = 0x9b62_1023;
    const MSUBPT: u32 = 0x9b62_9025;
    for (chip, cpa) in [
        (stela_contracts::Chip::AppleM5, false),
        (stela_contracts::Chip::AppleM6, true),
    ] {
        let mut machine = machine_on(chip, &[]);
        machine
            .cpu
            .registers
            .set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
        let top = 0xff00_0000_0000_0000_u64;
        machine.cpu.state.x[1] = top | 0x1000;
        machine.cpu.state.x[2] = 0x20;
        machine.cpu.state.x[4] = top | 0x8000;
        machine.cpu.state.sp = 0x9000;
        machine.system_instruction(ADDPT).unwrap();
        if !cpa {
            assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
            continue;
        }
        for word in [SUBPT_SP, MADDPT, MSUBPT] {
            machine.system_instruction(word).unwrap();
        }
        assert_eq!(machine.cpu.pc, BASE + 16);
        // Without FEAT_CPA2 nothing marks a result whose top byte changes.
        assert_eq!(machine.cpu.state.x[0], top | 0x1100);
        assert_eq!(machine.cpu.state.sp, 0x8fe0);
        let product = (top | 0x1000).wrapping_mul(0x20);
        assert_eq!(machine.cpu.state.x[3], (top | 0x8000).wrapping_add(product));
        assert_eq!(machine.cpu.state.x[5], (top | 0x8000).wrapping_sub(product));
    }
}

#[test]
fn combined_pac_instructions_fault_only_with_fpaccombine() {
    const PACIBSP: u32 = 0xd503_237f;
    const RETAB: u32 = 0xd65f_0fff;
    // ldraa x0, [x1]
    const LDRAA_X0_X1: u32 = 0xf820_0420;
    let pointer = 0xffff_ff80_0000_4000_u64;
    for (chip, faults) in [
        (stela_contracts::Chip::AppleM2, false),
        (stela_contracts::Chip::AppleM6, true),
    ] {
        let mut machine = pac_machine_for(chip, &[]);
        machine.cpu.state.x[30] = pointer;
        machine.cpu.state.sp = 0xffff_ff80_0001_0000;
        machine.system_instruction_for_test(PACIBSP);
        // A different modifier fails the RETAB's authentication.
        machine.cpu.state.sp += 16;
        let pc = machine.cpu.pc;
        machine.system_instruction_for_test(RETAB);
        if faults {
            // EC 0x1C, ISS {data=0, key B=1}, at the RETAB.
            assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x7200_0001);
            assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), pc);
            assert_eq!(machine.cpu.pc, 0x1_0200);
        } else {
            // FEAT_FPAC alone faults only standalone AUTs: RETAB branches
            // to the pointer with its error code.
            assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0);
            assert_ne!(machine.cpu.pc, pointer);
            assert_eq!(
                machine.cpu.pc & 0x0000_007f_ffff_ffff,
                pointer & 0x0000_007f_ffff_ffff
            );
        }
    }
    // LDRAA of an unsigned base faults with the data key A (ISS 0b10).
    let mut machine = pac_machine_for(stela_contracts::Chip::AppleM6, &[]);
    let registers = &mut machine.cpu.registers;
    registers.set(SystemRegister::APDAKeyLo_EL1, 0, 0x2468_ace0_1357_9bdf);
    registers.set(SystemRegister::APDAKeyHi_EL1, 0, 0x0f1e_2d3c_4b5a_6978);
    let sctlr = registers.get(SystemRegister::SCTLR_EL1, 0) | 1 << 27;
    registers.set(SystemRegister::SCTLR_EL1, 0, sctlr);
    machine.cpu.state.x[1] = 0xffff_ff80_0000_8000;
    let pc = machine.cpu.pc;
    machine.system_instruction_for_test(LDRAA_X0_X1);
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x7200_0002);
    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), pc);
    // With EnDA clear AuthDA returns the unsigned base unchanged:
    // LDRAA reads through it, here an unmapped address, whose data
    // abort (EC 0x25) reports the base itself.
    let mut machine = pac_machine_for(stela_contracts::Chip::AppleM6, &[]);
    let registers = &mut machine.cpu.registers;
    let sctlr = registers.get(SystemRegister::SCTLR_EL1, 0) & !(1 << 27);
    registers.set(SystemRegister::SCTLR_EL1, 0, sctlr);
    machine.cpu.state.x[1] = 0xffff_ff80_0000_8000;
    machine.system_instruction_for_test(LDRAA_X0_X1);
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1) >> 26, 0x25);
    assert_eq!(
        machine.cpu.read(SystemRegister::FAR_EL1),
        0xffff_ff80_0000_8000
    );
}

#[test]
fn pac_use_traps_on_hcr_el2_api_and_failed_aut_takes_ec_0x1c() {
    const PACIBSP: u32 = 0xd503_237f;
    const AUTIBSP: u32 = 0xd503_23ff;
    const XPACLRI: u32 = 0xd503_20ff;
    let mut machine = pac_machine();
    machine.cpu.state.x[30] = 0xffff_ff80_0000_4000;
    machine.cpu.state.sp = 0xffff_ff80_0001_0000;
    machine.system_instruction_for_test(PACIBSP);
    let signed = machine.cpu.state.x[30];
    // A different modifier fails a standalone AUT: under FEAT_FPAC EC
    // 0x1C, ISS {data=0, key B=1}, at the instruction, to the current EL.
    // Without it (the M1) the AUT writes the key B error code at bits
    // 62:61 and completes (Arm `Auth`).
    machine.cpu.state.sp += 16;
    let pc = machine.cpu.pc;
    machine.system_instruction_for_test(AUTIBSP);
    if Feature::FEAT_FPAC.on(machine.profile.chip) {
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x7200_0001);
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), pc);
        assert_eq!(
            (machine.cpu.pc, machine.cpu.state.x[30]),
            (0x1_0200, signed)
        );
    } else {
        let pointer = 0xffff_ff80_0000_4000_u64;
        assert_eq!(
            (machine.cpu.pc, machine.cpu.state.x[30]),
            (pc + 4, pointer & !(0b11 << 61) | 0b10 << 61)
        );
    }
    // HCR_EL2.API clear traps an enabled key's use from EL1 to EL2
    // (EC 0x09, ISS 0); XPAC uses no key and never traps.
    machine.cpu.set_pstate(Pstate::reset(1));
    machine.cpu.registers.set(SystemRegister::HCR_EL2, 0, 0);
    machine.system_instruction_for_test(XPACLRI);
    assert_eq!(machine.cpu.state.x[30], 0xffff_ff80_0000_4000);
    machine.system_instruction_for_test(PACIBSP);
    assert_eq!(machine.cpu.pstate.el, 2);
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL2), 0x2600_0000);
    assert_eq!(machine.cpu.pc, 0x4_0400);
    // A disabled key is not used, so it does not trap.
    machine.cpu.set_pstate(Pstate::reset(1));
    machine.cpu.registers.set(SystemRegister::SCTLR_EL1, 0, 0);
    machine.system_instruction_for_test(PACIBSP);
    assert_eq!(machine.cpu.pstate.el, 1);
}

#[test]
fn implicit_authentication_fault_saves_incoming_btype_before_completion() {
    let pointer = 0xffff_ff80_0000_4000u64;
    for (sign, authenticate, ret, key) in [
        (0xd503_233f, 0xd503_23bf, 0xd65f_0bff, 0),
        (0xd503_237f, 0xd503_23ff, 0xd65f_0fff, 1),
    ] {
        for chip in [
            stela_contracts::Chip::AppleM2,
            stela_contracts::Chip::AppleM6,
        ] {
            for (word, combined) in [(authenticate, false), (ret, true)] {
                for btype in 1..=3 {
                    let mut machine = pac_machine_for(chip, &[]);
                    machine.cpu.state.x[30] = pointer;
                    machine.cpu.state.sp = 0xffff_ff80_0001_0000;
                    machine.system_instruction_for_test(sign);
                    let signed = machine.cpu.state.x[30];
                    machine.cpu.state.sp += 16;
                    let sp = machine.cpu.state.sp;
                    machine.cpu.state.nzcv = 0xa000_0000;
                    machine.cpu.pstate.btype = btype;
                    let saved = machine.cpu.pstate.to_spsr(machine.cpu.state.nzcv);
                    let pc = machine.cpu.pc;
                    let retired = machine.cpu.retired;
                    // Invoke the implicit path after its source-entry
                    // boundary; this fixture does not model a guarded leaf.
                    machine.system_instruction_for_test(word);
                    let faults = !combined || chip == stela_contracts::Chip::AppleM6;
                    if faults {
                        assert_eq!(machine.cpu.read(SystemRegister::SPSR_EL1), saved);
                        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), pc);
                        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x7200_0000 | key);
                        assert_eq!(machine.cpu.state.x[30], signed);
                    } else {
                        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0);
                        assert_ne!(machine.cpu.pc, pointer);
                    }
                    assert_eq!(machine.cpu.pstate.btype, 0);
                    assert_eq!(machine.cpu.state.sp, sp);
                    assert_eq!(machine.cpu.state.nzcv, 0xa000_0000);
                    // This service entry leaves retirement to its scheduler.
                    assert_eq!(machine.cpu.retired, retired);
                }
            }
        }
    }
}

#[test]
fn implicit_pac_forms_repeat_their_results_until_the_keys_change() {
    const PACIBSP: u32 = 0xd503_237f;
    const AUTIBSP: u32 = 0xd503_23ff;
    const RETAB: u32 = 0xd65f_0fff;
    const PACIA1716: u32 = 0xd503_211f;
    let mut machine = pac_machine();
    let pointer = 0xffff_ff80_0000_4000_u64;
    machine.cpu.state.sp = 0xffff_ff80_0001_0000;
    let sign = |machine: &mut Machine<FakeHost, NoDevices>| {
        machine.cpu.state.x[30] = pointer;
        machine.system_instruction_for_test(PACIBSP);
        machine.cpu.state.x[30]
    };
    let signed = sign(&mut machine);
    let expected = machine
        .pointer_context()
        .unwrap()
        .sign(
            stela_contracts::pauth::Key::Ib,
            pointer,
            machine.cpu.state.sp,
        )
        .unwrap();
    assert_eq!(signed, expected);
    assert_eq!(sign(&mut machine), signed, "remembered");
    machine.system_instruction_for_test(AUTIBSP);
    assert_eq!(machine.cpu.state.x[30], pointer);
    // RETAB branches to the authenticated pointer and keeps X30 signed.
    machine.cpu.state.x[30] = signed;
    machine.system_instruction_for_test(RETAB);
    assert_eq!((machine.cpu.pc, machine.cpu.state.x[30]), (pointer, signed));
    // PACIA1716 signs X17 with X16 under key A.
    machine.cpu.state.x[16] = 0x55;
    machine.cpu.state.x[17] = pointer;
    machine.system_instruction_for_test(PACIA1716);
    let context = machine.pointer_context().unwrap();
    assert_eq!(
        machine.cpu.state.x[17],
        context
            .sign(stela_contracts::pauth::Key::Ia, pointer, 0x55)
            .unwrap()
    );
    // A key the guest writes changes every later result.
    machine
        .cpu
        .registers
        .set(SystemRegister::APIBKeyLo_EL1, 0, 0x0bad_cafe);
    machine.derived_changed();
    assert_ne!(sign(&mut machine), signed);
}

/// A block ending in a PAC exit has it redirected through a thunk that
/// completes the instruction from the memo, whose exit onward the block
/// may chain; a PAC exit opens the key's tag word under the current
/// memo, and a change of derived state closes it again.
#[test]
fn pac_exits_complete_natively_from_the_memo_under_open_tags() {
    const ADD: u32 = 0x9100_0400; // add x0, x0, #1
    const PACIBSP: u32 = 0xd503_237f;
    let mut machine = machine(&[ADD, PACIBSP, ADD]);
    let base = machine.cpu.pc;
    machine.host.exits = vec![NativeExit::Exit {
        next_pc: base + 8,
        kind: ExitKind::Fallthrough as u64,
    }];
    machine.step().unwrap();
    let block = &machine.blocks[0];
    let code = &machine.host.installed[block.code.0 / NATIVE_CODE_STRIDE - 1];
    let (memo, tags, service) = machine.pointer.addresses();
    let thunk = x86_64_pointer::thunk(
        x86_64_pointer::Form::of(block::PointerAuthenticationOperation::SignIbSp).unwrap(),
        GuestAddress(base + 4),
        memo,
        tags,
        service,
    );
    let installed = machine.host.installed.len() * NATIVE_CODE_STRIDE;
    assert_eq!(
        machine.host.installed[installed / NATIVE_CODE_STRIDE - 1],
        thunk.code
    );
    let site = block.code.0 + code.len() - chain::DIRECT_EXIT_BYTES;
    let jump = chain::jump(site as u64, installed as u64).unwrap().to_vec();
    assert_eq!(machine.host.patches, [(site, jump)]);
    assert_eq!(
        block.successors,
        [Successor {
            site: (installed + thunk.next.unwrap()) as u64,
            target: GuestAddress(base + 8),
            kind: ExitKind::Fallthrough,
        }]
    );
    let mut machine = pac_machine();
    assert_eq!(machine.pointer.tags, [0; 4]);
    machine
        .pointer_result(
            PointerOperation::Sign,
            stela_contracts::pauth::Key::Ib,
            0x4000,
            0x10,
        )
        .unwrap()
        .unwrap();
    let ib = x86_64_pointer::key_index(PointerAuthenticationKey::Ib);
    let open = x86_64_pointer::tag(machine.pointer.generation, ib, 0);
    assert_eq!(machine.pointer.tags[usize::from(ib)], open);
    // A derived change that keeps the inputs, enable and trap reopens
    // the tag; clearing the key's enable makes it DISABLED.
    machine.derived_changed();
    assert_eq!(machine.pointer.tags[usize::from(ib)], open);
    let sctlr = machine.cpu.regime_sctlr();
    let register = if machine.cpu.pstate.el == 2 {
        SystemRegister::SCTLR_EL2
    } else {
        SystemRegister::SCTLR_EL1
    };
    machine.cpu.registers.set(register, 0, sctlr & !(1 << 30));
    machine.derived_changed();
    assert_eq!(
        machine.pointer.tags[usize::from(ib)],
        x86_64_pointer::DISABLED
    );
}

#[test]
fn xpac_thunks_follow_regime_masks_without_key_enables_and_close_on_changes() {
    const ADD: u32 = 0x9100_0400;
    const XPACD_X17: u32 = 0xdac1_47f1;
    let mut native = machine(&[ADD, XPACD_X17, ADD]);
    let base = native.cpu.pc;
    native.host.exits = vec![NativeExit::Exit {
        next_pc: base + 8,
        kind: ExitKind::Fallthrough as u64,
    }];
    native.step().unwrap();
    let thunk = x86_64_pointer::strip::thunk(
        GuestAddress(base + 4),
        17,
        native.pointer.strip_address(true),
    )
    .unwrap();
    assert_eq!(native.host.installed.last(), Some(&thunk.code));
    let installed = native.host.installed.len() * NATIVE_CODE_STRIDE;
    assert_eq!(
        native.blocks[0].successors,
        [Successor {
            site: (installed + thunk.next.unwrap()) as u64,
            target: GuestAddress(base + 8),
            kind: ExitKind::Fallthrough,
        }]
    );
    let mut machine = pac_machine();
    machine.cpu.registers.set(SystemRegister::SCTLR_EL1, 0, 0);
    machine.cpu.registers.set(SystemRegister::HCR_EL2, 0, 0);
    for tcr in [25 | 17 << 16, 25 | 17 << 16 | 1 << 37 | 1 << 38 | 1 << 51] {
        machine.cpu.registers.set(SystemRegister::TCR_EL1, 0, tcr);
        machine.derived_changed();
        for (word, data, key) in [
            (0xdac1_43f1, false, stela_contracts::pauth::Key::Ia),
            (XPACD_X17, true, stela_contracts::pauth::Key::Da),
        ] {
            for pointer in [0xdead_1234_5678_aaaa, 0xdead_9234_5678_aaaa] {
                machine.cpu.state.x[17] = pointer;
                let expected = machine
                    .pointer_context()
                    .unwrap()
                    .strip(key, pointer)
                    .unwrap();
                let el = machine.cpu.pstate.el;
                machine.system_instruction_for_test(word);
                assert_eq!(
                    machine.cpu.pstate.el, el,
                    "XPAC neither uses nor traps a key"
                );
                assert_eq!(machine.cpu.state.x[17], expected);
                assert_eq!(machine.pointer.strips[usize::from(data)].enabled, 1);
                // XPAC opens no key's memo tag; disabled keys stay so.
                assert!(
                    machine
                        .pointer
                        .tags
                        .iter()
                        .all(|&tag| tag == 0 || tag == x86_64_pointer::DISABLED)
                );
            }
        }
        // Unchanged state reopens the same masks.
        let strips = machine.pointer.strips;
        machine.derived_changed();
        assert_eq!(machine.pointer.strips, strips);
    }
}

/// A RETAB's PAC thunk ends its completion with the exit to the target
/// in RAX, which the first return through it redirects into a lookup.
#[test]
fn pac_returns_go_through_a_lookup_thunk() {
    const RETAB: u32 = 0xd65f_0fff;
    let mut machine = machine(&[RETAB]);
    let base = machine.cpu.pc;
    machine.host.exits = vec![NativeExit::Exit {
        next_pc: base + 0x2000,
        kind: ExitKind::Return as u64,
    }];
    machine.step().unwrap();
    let (memo, tags, service) = machine.pointer.addresses();
    let thunk = x86_64_pointer::thunk(
        x86_64_pointer::Form::of(block::PointerAuthenticationOperation::ReturnIbSp).unwrap(),
        GuestAddress(base),
        memo,
        tags,
        service,
    );
    let at = machine
        .host
        .installed
        .iter()
        .position(|code| *code == thunk.code)
        .unwrap()
        + 1;
    let at = at * NATIVE_CODE_STRIDE;
    let site = (at + thunk.dynamic.unwrap()) as u64;
    let control = machine.chain.address();
    let lookup = chain::lookup_thunk(control, 1, None, ExitKind::Return, 0).unwrap();
    assert_eq!(machine.host.installed.last(), Some(&lookup));
    let jump = chain::jump(
        site,
        (machine.host.installed.len() * NATIVE_CODE_STRIDE) as u64,
    )
    .unwrap();
    assert_eq!(
        machine.host.patches.last(),
        Some(&(site as usize, jump.to_vec()))
    );
    assert_eq!(machine.statistics.lookups, 1);
    assert_eq!(machine.blocks[0].dynamic_site, None);
}

/// MRS TPIDR_EL1 ends its block in a System exit that a thunk reading
/// the engine's cell takes over, chaining on to the next instruction;
/// the cell opens on a plain read and closes on any derived change
/// other than a PSTATE mask, SPSel, TTBR0 or SPRR_PERM write.
#[test]
fn mirrored_reads_complete_natively_from_the_open_cell() {
    const ADD: u32 = 0x9100_0400; // add x0, x0, #1
    const MRS: u32 = 0xd538_d088; // mrs x8, tpidr_el1
    const MSR: u32 = 0xd518_d089; // msr tpidr_el1, x9
    const MRS_DAIF: u32 = 0xd53b_4228; // mrs x8, daif
    const DAIFCLR_I: u32 = 0xd503_42ff; // msr daifclr, #2
    const MRS_GXF_STATUS: u32 = 0xd53e_f808; // mrs x8, gxf_status_el1
    const SPSEL_1: u32 = 0xd500_41bf; // msr spsel, #1
    const DAIFCLR_D: u32 = 0xd503_48ff; // msr daifclr, #8
    let index = |encoding| MIRRORED.iter().position(|&e| e == encoding).unwrap();
    let thread = index(registers::encodings::TPIDR_EL1);
    let daif = index(registers::encodings::DAIF);
    let mut machine = machine(&[ADD, MRS, ADD]);
    let base = machine.cpu.pc;
    machine.host.exits = vec![NativeExit::Exit {
        next_pc: base + 8,
        kind: ExitKind::Fallthrough as u64,
    }];
    machine.step().unwrap();
    let block = &machine.blocks[0];
    let code = &machine.host.installed[block.code.0 / NATIVE_CODE_STRIDE - 1];
    let cell = &machine.mirrors[thread] as *const register_read::Cell as u64;
    let thunk = register_read::thunk(GuestAddress(base + 4), 8, cell);
    let installed = machine.host.installed.len() * NATIVE_CODE_STRIDE;
    assert_eq!(
        machine.host.installed[installed / NATIVE_CODE_STRIDE - 1],
        thunk.code
    );
    let site = block.code.0 + code.len() - chain::DIRECT_EXIT_BYTES;
    let jump = chain::jump(site as u64, installed as u64).unwrap().to_vec();
    assert_eq!(machine.host.patches, [(site, jump)]);
    assert_eq!(
        block.successors,
        [Successor {
            site: (installed + thunk.next.unwrap()) as u64,
            target: GuestAddress(base + 8),
            kind: ExitKind::Fallthrough,
        }]
    );
    // Other System reads keep their exit.
    let mut other = super::tests::machine(&[ADD, 0xd538_1008]); // mrs x8, sctlr_el1
    other.host.exits = machine.host.exits.clone();
    other.host.exits.push(NativeExit::Exit {
        next_pc: base + 8,
        kind: ExitKind::Fallthrough as u64,
    });
    other.step().unwrap();
    assert!(other.host.patches.is_empty() && other.blocks[0].successors.is_empty());
    machine
        .cpu
        .registers
        .set(SystemRegister::TPIDR_EL1, 0, 0x5000);
    machine.cpu.pc = base + 4;
    machine.system_instruction(MRS).unwrap();
    assert_eq!(machine.cpu.state.x[8], 0x5000);
    assert_eq!(
        machine.mirrors[thread],
        register_read::Cell {
            readable: 1,
            value: 0x5000
        }
    );
    machine.derived_changed();
    // Closed, the cell keeps no value a mispredicted read could use.
    assert_eq!(*machine.mirrors, Mirrors::default());
    // An Apple register read leaves it open.
    machine.cpu.pc = base + 4;
    machine.system_instruction(MRS).unwrap();
    let exceptions = machine.statistics.exceptions;
    machine.system_instruction(MRS_GXF_STATUS).unwrap();
    assert_eq!(machine.statistics.exceptions, exceptions);
    assert_eq!(machine.mirrors[thread].readable, 1);
    // A write of the register closes its cells in every state, and no
    // other: the thread pointer is only stored.
    machine.cpu.pc = base + 4;
    machine.system_instruction(MRS).unwrap();
    machine.system_instruction(MRS_DAIF).unwrap();
    assert_eq!(machine.mirrors[daif].readable, 1);
    machine.mirrors.banks[0][thread].readable = 1;
    machine.cpu.state.x[9] = 0x6000;
    machine.system_instruction(MSR).unwrap();
    assert_eq!(machine.mirrors[thread].readable, 0);
    assert_eq!(machine.mirrors.banks[0][thread].readable, 0);
    assert_eq!(machine.mirrors[daif].readable, 1);
    machine.derived_changed();
    machine.system_instruction(MRS_DAIF).unwrap();
    let masks = machine.cpu.state.x[8];
    // A mask write keeps the cells, the DAIF one with the new masks.
    machine.system_instruction(MRS).unwrap();
    machine.system_instruction(DAIFCLR_I).unwrap();
    assert_eq!(machine.mirrors[thread].readable, 1);
    let cell = machine.mirrors[daif];
    assert_eq!(cell.readable, 1);
    assert_ne!(cell.value, masks);
    machine.system_instruction(MRS_DAIF).unwrap();
    assert_eq!(
        (machine.mirrors[daif], machine.cpu.state.x[8]),
        (cell, cell.value)
    );
    // So does SPSel; D, like the other fields, forgets them.
    machine.system_instruction(SPSEL_1).unwrap();
    assert_eq!(machine.mirrors[daif], cell);
    assert_eq!(machine.mirrors[thread].readable, 1);
    machine.system_instruction(DAIFCLR_D).unwrap();
    assert_eq!(*machine.mirrors, Mirrors::default());
    // A read to XZR has no cell to open, nor a thunk.
    assert_eq!(mirrored_read(base, 0xd538_d09f), None); // mrs xzr, tpidr_el1
    // A TTBR0 or SPRR_PERM write changes translation alone: the host
    // takes the new controls and the cells stay.
    const MSR_TTBR0: u32 = 0xd518_2009; // msr ttbr0_el1, x9
    const MSR_SPRR_CONFIG: u32 = 0xd51e_f109; // msr sprr_config_el1, x9
    const MSR_SPRR_PERM: u32 = 0xd51e_f1c9; // msr sprr_perm_el1, x9
    machine.cpu.state.x[9] = 1;
    machine.system_instruction(MSR_SPRR_CONFIG).unwrap();
    machine.system_instruction(MRS).unwrap();
    for (msr, value) in [(MSR_TTBR0, 0x8000), (MSR_SPRR_PERM, 0x22)] {
        let (generation, regimes) = (machine.translation_generation, machine.host.regimes.len());
        let controls = machine.cpu.controls(machine.cpu.regime());
        machine.cpu.state.x[9] = value;
        machine.system_instruction(msr).unwrap();
        assert!(machine.translation_generation > generation);
        let regime = machine.host.regimes[regimes..].last().unwrap();
        assert_ne!(regime.controls, controls);
        assert_eq!(machine.mirrors[thread].readable, 1);
    }
}

/// MRS SPRR_PERM_EL0 completes from its cell, which a write of the
/// register reopens with the value it stored, so dyld's toggle and its
/// read-back take one exit; any other SPRR_PERM write closes it.
#[test]
fn sprr_perm_el0_writes_reopen_its_open_cell() {
    const MRS: u32 = 0xd53e_f1a8; // mrs x8, sprr_perm_el0
    const MSR: u32 = 0xd51e_f1a9; // msr sprr_perm_el0, x9
    const MSR_SPRR_CONFIG: u32 = 0xd51e_f109; // msr sprr_config_el1, x9
    const MSR_SPRR_PERM_EL1: u32 = 0xd51e_f1c9; // msr sprr_perm_el1, x9
    const MRS_TPIDR: u32 = 0xd538_d088; // mrs x8, tpidr_el1
    let index = |encoding| MIRRORED.iter().position(|&e| e == encoding).unwrap();
    let thread = index(registers::encodings::TPIDR_EL1);
    assert_eq!(
        mirrored_read(0, MRS),
        Some((SPRR_PERM_MIRROR, 8)),
        "the read has a thunk"
    );
    let mut machine = machine(&[MRS]);
    machine.cpu.state.x[9] = 1;
    machine.system_instruction(MSR_SPRR_CONFIG).unwrap();
    // Closed, a write leaves the cell closed.
    machine.cpu.state.x[9] = 0x10;
    machine.system_instruction(MSR).unwrap();
    assert_eq!(machine.mirrors[SPRR_PERM_MIRROR].readable, 0);
    machine.system_instruction(MRS).unwrap();
    machine.system_instruction(MRS_TPIDR).unwrap();
    assert_eq!(
        machine.mirrors[SPRR_PERM_MIRROR],
        register_read::Cell {
            readable: 1,
            value: 0x10
        }
    );
    // Open, the write reopens it with the new value, and closes the
    // other states' cells; translation changes alone.
    machine.mirrors.banks[0][SPRR_PERM_MIRROR].readable = 1;
    let generation = machine.translation_generation;
    let exits = machine.statistics.exceptions;
    machine.cpu.state.x[9] = 0x30;
    machine.system_instruction(MSR).unwrap();
    assert!(machine.translation_generation > generation);
    assert_eq!(machine.statistics.exceptions, exits);
    assert_eq!(
        machine.mirrors[SPRR_PERM_MIRROR],
        register_read::Cell {
            readable: 1,
            value: 0x30
        }
    );
    assert_eq!(machine.mirrors.banks[0][SPRR_PERM_MIRROR].readable, 0);
    machine.system_instruction(MRS).unwrap();
    assert_eq!(machine.cpu.state.x[8], 0x30);
    assert_eq!(machine.mirrors[thread].readable, 1);
    // Another SPRR_PERM register's write closes it, and only it.
    machine.cpu.state.x[9] = 0x22;
    machine.system_instruction(MSR_SPRR_PERM_EL1).unwrap();
    assert_eq!(machine.mirrors[SPRR_PERM_MIRROR].readable, 0);
    assert_eq!(machine.mirrors[thread].readable, 1);
    // Without SPRR the write is UNDEFINED and opens nothing.
    machine.system_instruction(MRS).unwrap();
    machine.cpu.state.x[9] = 0;
    machine.system_instruction(MSR_SPRR_CONFIG).unwrap();
    assert_eq!(*machine.mirrors, Mirrors::default());
    let exits = machine.statistics.exceptions;
    machine.cpu.state.x[9] = 0x40;
    machine.system_instruction(MSR).unwrap();
    assert!(machine.statistics.exceptions > exits);
    assert_eq!(machine.mirrors[SPRR_PERM_MIRROR].readable, 0);
}

/// An exception keeps the device lines; a System register write that
/// may change derived state forgets them.
#[test]
fn exceptions_keep_the_device_lines_a_register_write_forgets() {
    const SVC: u32 = 0xd400_0001; // svc #0
    let mut machine = machine(&[SVC]);
    let lines = Some((Lines::default(), u64::MAX, machine.current));
    machine.device_lines = lines;
    machine.system_instruction(SVC).unwrap();
    assert!(machine.statistics.exceptions > 0);
    assert_eq!(machine.device_lines, lines);
    machine.derived_changed();
    assert_eq!(machine.device_lines, None);
}

/// A virtual count read, of CNTVCT_EL0 or Apple's alias, opens its
/// cell with the offset it subtracts, and completes natively only on a
/// host whose counter is its TSC's, at the clock's count.
#[test]
fn count_reads_complete_natively_where_the_host_counts_its_tsc() {
    const ADD: u32 = 0x9100_0400; // add x0, x0, #1
    const READS: [(u32, usize); 2] = [
        (0xd53b_e04a, COUNT_MIRRORS[0]), // mrs x10, cntvct_el0
        (0xd53c_faca, COUNT_MIRRORS[1]), // mrs x10, cntvct_alias_el0
    ];
    for (mrs, index) in READS {
        for tsc in [None, Some((5, 7))] {
            let mut machine = machine(&[ADD, mrs, ADD]);
            machine.host.tsc_counter = tsc;
            let base = machine.cpu.pc;
            machine.host.exits = vec![NativeExit::Exit {
                next_pc: base + 8,
                kind: ExitKind::Fallthrough as u64,
            }];
            machine.step().unwrap();
            let cell = &machine.mirrors[index] as *const register_read::Cell as u64;
            let count = tsc.map_or(0, |tsc| machine.clock.native(tsc));
            let installed = machine.host.installed.last().unwrap();
            let thunk = register_read::count_thunk(GuestAddress(base + 4), 10, cell, count);
            assert_eq!(*installed == thunk.code, tsc.is_some());
            machine
                .cpu
                .registers
                .set(SystemRegister::CNTVOFF_EL2, 0, 0x30);
            machine.cpu.pc = base + 4;
            machine.system_instruction(mrs).unwrap();
            let offset = registers::count_alias_offset(&machine.cpu);
            let plain = machine.cpu.state.x[10] == machine.clock.last().wrapping_sub(offset);
            // The M2 reads both as the count less CNTVOFF_EL2.
            assert!(plain || machine.cpu.registers.chip() != stela_contracts::chip::Chip::AppleM2);
            assert_eq!(
                machine.mirrors[index],
                if plain {
                    register_read::Cell {
                        readable: 1,
                        value: offset,
                    }
                } else {
                    register_read::Cell::default()
                }
            );
        }
    }
}

/// Native accesses check and mask their own addresses at every access
/// exactly where ID_AA64PFR0_EL1.CSV3 discloses FEAT_CSV3.
#[test]
fn every_access_masks_its_address_where_csv3_is_disclosed() {
    let mut machine = machine(&[0xd503_201f]);
    for csv3 in [0, 1] {
        let pfr0 = machine.cpu.read(SystemRegister::ID_AA64PFR0_EL1);
        let pfr0 = pfr0 & !(0xf << CSV3_SHIFT) | csv3 << CSV3_SHIFT;
        machine
            .cpu
            .registers
            .set_raw(SystemRegister::ID_AA64PFR0_EL1, 0, pfr0);
        machine.derived_changed();
        assert_eq!(machine.memory_checks().every_access_masked, csv3 == 1);
    }
}

/// Where DC ZVA cannot trap, a block ending in it zeroes natively and
/// falls through; elsewhere the same PC compiles a block that exits. A
/// fault in the native zeroing completes DC ZVA in the engine.
#[test]
fn dc_zva_blocks_follow_the_permission_and_faults_complete_in_the_engine() {
    const ADD: u32 = 0x9100_0400; // add x0, x0, #1
    const DC_ZVA: u32 = 0xd50b_7423; // dc zva, x3
    let mut machine = machine(&[ADD, DC_ZVA, ADD]);
    normal_memory(&mut machine, false);
    let base = machine.cpu.pc;
    machine.cpu.state.x[3] = BASE + 0x108;
    machine.host.ram[0x100..0x180].fill(0xaa);
    let next = GuestAddress(base + 8);
    machine.host.exits = vec![NativeExit::Exit {
        next_pc: next.0,
        kind: ExitKind::Fallthrough as u64,
    }];
    machine.step().unwrap();
    let block = &machine.blocks[0];
    assert_eq!(block.variant.system.zero_block, Some(64));
    let code = &machine.host.installed[block.code.0 / NATIVE_CODE_STRIDE - 1];
    let tail = chain::direct_exit(next, ExitKind::Fallthrough);
    assert_eq!(code[code.len() - chain::DIRECT_EXIT_BYTES..], tail);
    assert_eq!(block.successors.len(), 1);
    assert_eq!(block.successors[0].target, next);
    // HCR_EL2.TDZ traps DC ZVA at EL1: the PC gets a block that exits.
    let hcr = machine.cpu.read(SystemRegister::HCR_EL2);
    machine
        .cpu
        .registers
        .set(SystemRegister::HCR_EL2, 0, hcr | 1 << 28);
    machine.derived_changed();
    machine.cpu.pc = base;
    machine.host.exits = vec![NativeExit::Exit {
        next_pc: next.0,
        kind: ExitKind::Fallthrough as u64,
    }];
    machine.step().unwrap();
    let trapped = &machine.blocks[1];
    assert_eq!(trapped.variant.system.zero_block, None);
    let code = &machine.host.installed[trapped.code.0 / NATIVE_CODE_STRIDE - 1];
    assert_eq!(
        code[code.len() - chain::DIRECT_EXIT_BYTES..],
        chain::direct_exit(GuestAddress(base + 4), ExitKind::System)
    );
    // Back without TDZ, a store fault in the zeroing hands DC ZVA to the
    // engine, which zeroes the block and continues.
    machine.cpu.registers.set(SystemRegister::HCR_EL2, 0, hcr);
    machine.derived_changed();
    machine.cpu.pc = base;
    let (entered, offset) = native_fault_site_in_entry(
        &mut machine,
        base,
        base + 4,
        stela_compiler::block::RecoverySiteKind::GuestAccess,
    );
    let expected: &[u8] = if machine.blocks[entered].variant.system.zero_block.unwrap() == 4 {
        &[0x89, 0x08]
    } else {
        &[0x48, 0x89, 0x48, 0x00]
    };
    assert_eq!(
        &machine.fault_recovery[&entered].template.native.x86_64_code
            [offset..offset + expected.len()],
        expected,
        "actual first zero store at the minted DC ZVA site"
    );
    machine.host.exits = vec![NativeExit::Fault(NativeFault {
        origin: crate::machine::NativeFaultOrigin::Exception,
        trap: 14,
        error_code: 0,
        spills: stela_compiler::block::HostSpillSnapshot::new(),
        registers: stela_compiler::block::HostGprSnapshot::legacy([0; 16]),
        offset,
        address: BASE + 0x100,
        write: true,
        cause: FaultCause::Watched,
    })];
    let exits = machine.statistics.system_exits;
    machine.step().unwrap();
    assert_eq!(machine.cpu.pc, next.0);
    assert!(machine.host.ram[0x100..0x140].iter().all(|&byte| byte == 0));
    assert!(
        machine.host.ram[0x140..0x180]
            .iter()
            .all(|&byte| byte == 0xaa)
    );
    assert_eq!(machine.statistics.system_exits, exits + 1);
    assert_eq!(machine.exit_words().get(&DC_ZVA), Some(&1));
}

/// A return to earlier keys finds their generation, and its entries,
/// again; other keys get their own, and beyond the inputs kept a
/// generation is new.
#[test]
fn memo_generations_follow_the_keys() {
    let mut machine = pac_machine();
    let (pointer, modifier) = (0xffff_ff80_0000_4000, 0x10);
    let sign = |machine: &mut Machine<FakeHost, NoDevices>, key| {
        machine
            .cpu
            .registers
            .set(SystemRegister::APIBKeyLo_EL1, 0, key);
        machine.derived_changed();
        let signed = machine
            .pointer_result(
                PointerOperation::Sign,
                stela_contracts::pauth::Key::Ib,
                pointer,
                modifier,
            )
            .unwrap()
            .unwrap();
        (signed, machine.pointer.generation)
    };
    let (first, generation) = sign(&mut machine, 1);
    let (other, other_generation) = sign(&mut machine, 2);
    assert_ne!((other, other_generation), (first, generation));
    assert_eq!(sign(&mut machine, 1), (first, generation));
    let remembered = machine.pointer.remembered(
        PointerOperation::Sign,
        stela_contracts::pauth::Key::Ib,
        pointer,
        modifier,
    );
    assert_eq!(remembered, Some(Ok(first)));
    for key in 0..pointer::POINTER_INPUTS_SEEN as u64 {
        sign(&mut machine, 0x1000 + key);
    }
    let (again, renewed) = sign(&mut machine, 1);
    assert_eq!(again, first);
    assert!(renewed > other_generation);
}

/// A signing remembers that its result authenticates back to its
/// pointer, for the plain and the combined form, unless the pointer was
/// not canonical, when authentication must be computed (and fails).
#[test]
fn signing_remembers_the_authentication_of_its_result() {
    let mut machine = pac_machine();
    let modifier = 0xffff_ff80_0001_0000;
    let sign = PointerOperation::Sign;
    let plain = PointerOperation::Authenticate { combined: false };
    let combined = PointerOperation::Authenticate { combined: true };
    let pointer = 0xffff_ff80_0000_4000;
    let (signed, _) = machine
        .pointer_result(sign, stela_contracts::pauth::Key::Ib, pointer, modifier)
        .unwrap()
        .unwrap();
    let remembered =
        machine
            .pointer
            .remembered(plain, stela_contracts::pauth::Key::Ib, signed, modifier);
    assert_eq!(remembered, Some(Ok((pointer, true))));
    let context = machine.pointer_context().unwrap();
    for operation in [plain, combined] {
        let PointerOperation::Authenticate { combined } = operation else {
            unreachable!()
        };
        let computed = context
            .authenticate_operation(stela_contracts::pauth::Key::Ib, signed, modifier, combined)
            .unwrap();
        assert_eq!(
            machine.pointer_result(operation, stela_contracts::pauth::Key::Ib, signed, modifier),
            Ok(Ok((computed.pointer, computed.authenticated)))
        );
    }
    // A pointer whose extension bits disagree does not strip back.
    let odd = 0x7fff_ff80_0000_4000;
    let (signed, _) = machine
        .pointer_result(sign, stela_contracts::pauth::Key::Ib, odd, modifier)
        .unwrap()
        .unwrap();
    assert_eq!(
        machine
            .pointer
            .remembered(plain, stela_contracts::pauth::Key::Ib, signed, modifier),
        None
    );
    let computed =
        context.authenticate_operation(stela_contracts::pauth::Key::Ib, signed, modifier, false);
    let result = machine.pointer_result(plain, stela_contracts::pauth::Key::Ib, signed, modifier);
    match computed {
        Ok(computed) => assert_eq!(result, Ok(Ok((computed.pointer, computed.authenticated)))),
        Err(pauth::AuthenticationError::Failure { code }) => assert_eq!(result, Ok(Err(code))),
        Err(error) => panic!("{error:?}"),
    }
}

#[test]
fn register_pac_forms_complete_as_the_pac_service_computes() {
    const PACIA_X0_X1: u32 = 0xdac1_0020;
    const AUTIA_X0_X1: u32 = 0xdac1_1020;
    const BLRAA_X2_X3: u32 = 0xd73f_0843;
    const BRAAZ_X2: u32 = 0xd61f_085f;
    let mut machine = pac_machine();
    let pointer = 0xffff_ff80_0000_4000_u64;
    let context = machine.pointer_context().unwrap();
    machine.cpu.state.x[0] = pointer;
    machine.cpu.state.x[1] = 0x1234;
    machine.system_instruction_for_test(PACIA_X0_X1);
    let signed = context
        .sign(stela_contracts::pauth::Key::Ia, pointer, 0x1234)
        .unwrap();
    assert_eq!(machine.cpu.state.x[0], signed);
    machine.system_instruction_for_test(AUTIA_X0_X1);
    assert_eq!(machine.cpu.state.x[0], pointer);
    // BLRAA links after authenticating the target with X3.
    machine.cpu.state.x[2] = context
        .sign(stela_contracts::pauth::Key::Ia, pointer, 0x99)
        .unwrap();
    machine.cpu.state.x[3] = 0x99;
    let pc = machine.cpu.pc;
    machine.system_instruction_for_test(BLRAA_X2_X3);
    assert_eq!((machine.cpu.pc, machine.cpu.state.x[30]), (pointer, pc + 4));
    // BRAAZ authenticates with a zero modifier; a wrong one corrupts
    // the target, as the general path's combined authentication does.
    machine.cpu.state.x[2] = context
        .sign(stela_contracts::pauth::Key::Ia, pointer, 0)
        .unwrap();
    machine.system_instruction_for_test(BRAAZ_X2);
    assert_eq!(machine.cpu.pc, pointer);
    let wrong = context
        .sign(stela_contracts::pauth::Key::Ia, pointer, 1)
        .unwrap();
    machine.cpu.state.x[2] = wrong;
    let fault_pc = machine.cpu.pc;
    machine.system_instruction_for_test(BRAAZ_X2);
    match context.authenticate_operation(stela_contracts::pauth::Key::Ia, wrong, 0, true) {
        Ok(result) => assert_eq!(machine.cpu.pc, result.pointer),
        Err(pauth::AuthenticationError::Failure { code }) => {
            // FEAT_FPACCOMBINE (M6) faults the failed branch instead of
            // returning a corrupted target. Its source stays unchanged.
            assert_eq!(
                machine.cpu.read(SystemRegister::ESR_EL1),
                0x7200_0000 | u64::from(code)
            );
            assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), fault_pc);
            assert_eq!(machine.cpu.pc, 0x1_0200);
            assert_eq!(machine.cpu.state.x[2], wrong);
        }
        Err(error) => panic!("{error:?}"),
    }
    assert_ne!(machine.cpu.pc, pointer);
}

#[test]
fn eret_traps_and_eretaa_authenticates_elr_with_sp() {
    const ERETAA: u32 = 0xd69f_0bff;
    const ERETAB: u32 = 0xd69f_0fff;
    let mut machine = pac_machine();
    let target = 0xffff_ff80_0000_8000_u64;
    machine.cpu.state.sp = 0xffff_ff80_0002_0000;
    let signed = machine
        .pointer_context()
        .unwrap()
        .sign(
            stela_contracts::pauth::Key::Ia,
            target,
            machine.cpu.state.sp,
        )
        .unwrap();
    machine
        .cpu
        .registers
        .set(SystemRegister::ELR_EL1, 0, signed);
    machine
        .cpu
        .registers
        .set(SystemRegister::SPSR_EL1, 0, 0x3c5);
    // HFGITR_EL2.ERET traps ERETAA from EL1: EC 0x1A, ISS {PAC, key B}.
    machine
        .cpu
        .registers
        .set(SystemRegister::HFGITR_EL2, 0, 1 << HFGITR_ERET);
    machine.system_instruction(ERETAB).unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL2), 0x6a00_0003);
    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL2), BASE);
    machine.cpu.set_pstate(Pstate::reset(1));
    machine.cpu.pc = BASE;
    machine.cpu.registers.set(SystemRegister::HFGITR_EL2, 0, 0);
    machine.system_instruction(ERETAA).unwrap();
    assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (target, 1));
    // With another SP the combined check corrupts the target instead of
    // faulting without FEAT_FPACCOMBINE; the M6's fault is below.
    machine.cpu.state.sp += 16;
    if !Feature::FEAT_FPACCOMBINE.on(machine.profile.chip) {
        machine.system_instruction(ERETAA).unwrap();
        assert_ne!(machine.cpu.pc, target);
        assert_eq!(machine.cpu.pc & 0x7f_ffff_ffff, target & 0x7f_ffff_ffff);
    }
    // HCR_EL2.API clear traps the enabled key's use to EL2.
    machine.cpu.registers.set(SystemRegister::HCR_EL2, 0, 0);
    machine.system_instruction(ERETAA).unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL2), 0x2600_0000);
    // With FEAT_FPACCOMBINE (M6) the failed combined check takes EC 0x1C,
    // ISS {data=0, key A=0}, at the ERETAA and the return is not made.
    let mut machine = pac_machine_for(stela_contracts::Chip::AppleM6, &[]);
    machine.cpu.state.sp = 0xffff_ff80_0002_0010;
    let registers = &mut machine.cpu.registers;
    registers.set(SystemRegister::ELR_EL1, 0, signed);
    registers.set(SystemRegister::SPSR_EL1, 0, 0x3c4);
    machine.system_instruction(ERETAA).unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x7200_0000);
    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE);
    assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (0x1_0200, 1));
}

/// An ERET or GEXIT into an EL1&0 guest while a VM register holds a
/// nonzero value enters it without the state, reported once; the host's
/// own returns are unaffected.
#[test]
fn entering_a_guest_with_unapplied_vm_state_reports_it_once() {
    const ERET: u32 = 0xd69f_03e0;
    const GEXIT: u32 = 0x0020_1400;
    const EL1H: u64 = 0x3c5;
    const EL0T: u64 = 0x3c0;
    const HCR_E2H: u64 = 1 << 34;
    let guest = super::super::impdef::TABLE
        .iter()
        .find(|entry| entry.encoding == super::super::impdef::GUEST_SPRR_C15_4)
        .unwrap();
    let mut machine = machine(&[]);
    let enter = |machine: &mut Machine<_, _>, word, spsr| {
        machine.cpu.set_pstate(Pstate::reset(2));
        machine.cpu.pc = BASE;
        machine.cpu.registers.set(SystemRegister::SPSR_EL2, 0, spsr);
        machine
            .cpu
            .registers
            .set(SystemRegister::ELR_EL2, 0, 0x8000);
        machine.system_instruction(word)
    };
    machine
        .cpu
        .registers
        .set(SystemRegister::HCR_EL2, 0, HCR_E2H);
    machine.cpu.apple.impdef.write(guest, 0x3b).unwrap();
    // The host (HCR_EL2.TGE) returning to its EL0 is no guest entry.
    machine
        .cpu
        .registers
        .set(SystemRegister::HCR_EL2, 0, HCR_E2H | 1 << HCR_TGE);
    enter(&mut machine, ERET, EL0T).unwrap();
    assert_eq!(machine.cpu.pstate.el, 0);
    assert!(machine.take_unmodeled().is_empty());
    machine
        .cpu
        .registers
        .set(SystemRegister::HCR_EL2, 0, HCR_E2H);
    for _ in 0..2 {
        enter(&mut machine, ERET, EL1H).unwrap();
        assert_eq!((machine.cpu.pstate.el, machine.cpu.pc), (1, 0x8000));
    }
    // GEXIT from GL2 into the guest enters it the same way.
    machine.cpu.set_pstate(Pstate {
        guarded: true,
        ..Pstate::reset(2)
    });
    machine.cpu.apple.guarded[1].spsr = EL1H;
    machine.cpu.apple.guarded[1].elr = 0x8000;
    machine.cpu.apple.guarded[1].aspsr = 0;
    machine.system_instruction(GEXIT).unwrap();
    assert_eq!((machine.cpu.pstate.el, machine.cpu.pc), (1, 0x8000));
    let reports = machine.take_unmodeled();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].kind, RequirementKind::VmState(guest.name));
    assert_eq!((reports[0].pc, reports[0].el), (BASE, 2));
    assert_eq!(machine.statistics.degraded, 3);
    // SPTM's zero loads leave nothing to apply.
    machine.cpu.apple.impdef.write(guest, 0).unwrap();
    enter(&mut machine, ERET, EL1H).unwrap();
    assert_eq!(machine.cpu.pstate.el, 1);
    assert_eq!(machine.statistics.degraded, 3);
}

/// HACR_EL2's SPTM VM entry value traps a guest EL1's HID read to EL2 as
/// an MRS trap, refuses an encoding no bit names and SDSB by the unnamed
/// bit, and leaves the host and a guest without set bits alone.
#[test]
fn hacr_traps_or_refuses_a_guests_apple_operations() {
    const MRS_HID4: u32 = 0xd538_f402;
    const MRS_C15_C2_5: u32 = 0xd53e_f2a2;
    const MRS_AIDR: u32 = 0xd539_00e2;
    const MRS_SPRR_PERM_EL1: u32 = 0xd53e_f1c2;
    const SDSB_ISH: u32 = 0x0020_1462;
    const HCR_E2H: u64 = 1 << 34;
    const CUSTOMER: u64 = 0x061f_0000_6100_2000;
    let mut machine = machine(&[]);
    machine
        .cpu
        .registers
        .set(SystemRegister::HCR_EL2, 0, HCR_E2H);
    machine
        .cpu
        .registers
        .set(SystemRegister::VBAR_EL2, 0, 0x4_0000);
    let run = |machine: &mut Machine<_, _>, el, hacr, word| {
        machine.cpu.set_pstate(Pstate::reset(el));
        machine.cpu.pc = BASE;
        machine.cpu.registers.set(SystemRegister::HACR_EL2, 0, hacr);
        machine.system_instruction(word)
    };
    run(&mut machine, 1, CUSTOMER, MRS_HID4).unwrap();
    assert_eq!((machine.cpu.pstate.el, machine.cpu.pc), (2, 0x4_0400));
    assert_eq!(
        machine.cpu.read(SystemRegister::ESR_EL2),
        0x18 << 26 | 1 << 25 | u64::from(registers::word_trap_iss(MRS_HID4))
    );
    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL2), BASE);
    for (word, reason) in [
        (
            MRS_C15_C2_5,
            "HACR_EL2 bit 24 on S3_6_C15_C2_5: trapped operation not recovered",
        ),
        (
            SDSB_ISH,
            "HACR_EL2 bit 24 on SDSB: trapped operation not recovered",
        ),
    ] {
        match run(&mut machine, 1, CUSTOMER, word) {
            Err(Stop::Unsupported(requirement)) => assert_eq!(
                requirement.kind,
                RequirementKind::Instruction {
                    word,
                    detail: reason.into()
                }
            ),
            other => panic!("{other:?}"),
        }
    }
    // TRAP_AIDR and TRAP_SPRR trap the guest's AIDR_EL1 and
    // SPRR_PERM_EL1 reads; without set bits the guest's SPRR access and
    // barrier run, and the host's own accesses never consult HACR_EL2.
    for (hacr, word) in [(1 << 4, MRS_AIDR), (1 << 11, MRS_SPRR_PERM_EL1)] {
        run(&mut machine, 1, hacr, word).unwrap();
        assert_eq!((machine.cpu.pstate.el, machine.cpu.pc), (2, 0x4_0400));
    }
    for (el, hacr, word) in [
        (1, 0, MRS_SPRR_PERM_EL1),
        (1, 0, SDSB_ISH),
        (2, CUSTOMER | 1 << 11, MRS_SPRR_PERM_EL1),
    ] {
        // The access completes or takes its own exception at the same
        // EL (SPRR is not enabled here), never HACR_EL2's trap.
        run(&mut machine, el, hacr, word).unwrap();
        assert_eq!(machine.cpu.pstate.el, el);
        assert_ne!(machine.cpu.pc, 0x4_0400);
    }
}

#[test]
fn illegal_returns_set_il_and_the_next_instruction_takes_ec_0x0e() {
    let mut machine = machine(&[]);
    machine
        .cpu
        .registers
        .set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
    machine
        .cpu
        .registers
        .set(SystemRegister::ELR_EL1, 0, BASE + 0x10);
    // ERET from EL1h to EL2h is illegal: EL1h stays, PC is ELR, DAIF and
    // NZCV come from SPSR and IL is set.
    machine
        .cpu
        .registers
        .set(SystemRegister::SPSR_EL1, 0, 0x4000_0000 | 0x9);
    machine.system_instruction(0xd69f_03e0).unwrap();
    let pstate = machine.cpu.pstate;
    assert_eq!((pstate.el, pstate.sp, pstate.il), (1, true, true));
    assert_eq!((pstate.daif, machine.cpu.state.nzcv), (0, 0x4000_0000));
    assert_eq!(machine.cpu.pc, BASE + 0x10);
    machine.step().unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x3a00_0000);
    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE + 0x10);
    assert_eq!(machine.cpu.read(SystemRegister::SPSR_EL1), 0x4010_0005);
    assert_eq!(machine.cpu.pc, 0x1_0200);
    assert!(!machine.cpu.pstate.il);
    // A legal return restores SPSR.IL. ELR keeps its tag only without TBI.
    machine
        .cpu
        .registers
        .set(SystemRegister::TCR_EL1, 0, 1 << 37);
    machine
        .cpu
        .registers
        .set(SystemRegister::ELR_EL1, 0, 0xab00_0000_0000_1000);
    machine
        .cpu
        .registers
        .set(SystemRegister::SPSR_EL1, 0, 1 << 20 | 0x5);
    machine.system_instruction(0xd69f_03e0).unwrap();
    assert!(machine.cpu.pstate.il);
    assert_eq!(machine.cpu.pc, 0x1000);
    // A PC with bits 1:0 set takes a PC alignment fault with FAR = PC,
    // before the Illegal Execution state.
    machine.cpu.pc = BASE + 2;
    machine.step().unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x8a00_0000);
    assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), BASE + 2);
    // EL0 ERET is UNDEFINED.
    machine.cpu.pstate = Pstate {
        el: 0,
        sp: false,
        ..Pstate::reset(1)
    };
    machine.system_instruction(0xd69f_03e0).unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
}

#[test]
fn svc_traps_esb_fp_and_debug_only_instructions_follow_the_profile() {
    let mut machine = machine(&[]);
    machine
        .cpu
        .registers
        .set(SystemRegister::VBAR_EL2, 0, 0x4_0000);
    machine
        .cpu
        .registers
        .set(SystemRegister::HFGITR_EL2, 0, 1 << HFGITR_SVC_EL1);
    // HFGITR_EL2.SVC_EL1 sends SVC to EL2 with the SVC's own address.
    machine.system_instruction(0xd400_0841).unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL2), 0x5600_0042);
    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL2), BASE);
    // ESB defers a masked virtual SError into VDISR_EL2.
    machine.cpu.set_pstate(Pstate::reset(1));
    machine
        .cpu
        .registers
        .set(SystemRegister::HCR_EL2, 0, 1 << HCR_AMO | 1 << HCR_VSE);
    machine
        .cpu
        .registers
        .set(SystemRegister::VSESR_EL2, 0, 0x0100_1234);
    machine.system_instruction(0xd503_221f).unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::VDISR_EL2), 0x8100_1234);
    assert_eq!(machine.cpu.read(SystemRegister::HCR_EL2) & 1 << HCR_VSE, 0);
    // An unmasked one is taken with EC 0x2F and IL set.
    machine
        .cpu
        .registers
        .set(SystemRegister::HCR_EL2, 0, 1 << HCR_AMO | 1 << HCR_VSE);
    machine.cpu.pstate.daif = 0;
    assert!(machine.deliver_interrupts());
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0xbf00_1234);
    // CPACR_EL1.FPEN at reset traps FP/SIMD from EL1: EC 0x07 with CV
    // and COND.
    machine.cpu.set_pstate(Pstate::reset(1));
    machine.cpu.pc = BASE;
    machine.system_instruction(0xd53b_4401).unwrap(); // mrs x1, fpcr
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x1fe0_0000);
    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE);
    // BRK is taken at itself with its immediate; HLT (no halting),
    // DCPS1/2/3 and DRPS (no Debug state) and UDF are UNDEFINED.
    machine.cpu.set_pstate(Pstate::reset(1));
    machine.cpu.pc = BASE;
    machine.system_instruction(0xd420_00a0).unwrap(); // brk #5
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0xf200_0005);
    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE);
    for word in [
        0xd440_0000,
        0xd4a0_0001,
        0xd4a0_0002,
        0xd4a0_0003,
        0xd6bf_03e0,
        0,
    ] {
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.system_instruction(word).unwrap();
        assert_eq!(
            machine.cpu.read(SystemRegister::ESR_EL1),
            0x0200_0000,
            "{word:#x}"
        );
    }
    // FPCR's trap enables and fields outside the profile are RAZ/WI.
    machine.cpu.set_pstate(Pstate::reset(1));
    for register in [SystemRegister::CPACR_EL1, SystemRegister::CPTR_EL2] {
        machine.cpu.registers.set(register, 0, 0b11 << 20);
    }
    machine.derived_changed();
    machine.cpu.state.x[0] = u64::MAX;
    machine.system_instruction(0xd51b_4400).unwrap(); // msr fpcr, x0
    machine.system_instruction(0xd53b_4401).unwrap(); // mrs x1, fpcr
    // FEAT_AFP (from the M4) adds FIZ, AH and NEP.
    let afp = if Feature::FEAT_AFP.on(machine.profile.chip) {
        0b111
    } else {
        0
    };
    assert_eq!(machine.cpu.state.x[1], 0x07c8_0000 | afp);
}

#[test]
fn sve_sme_and_streaming_checks_trap_before_the_instruction_runs() {
    const ADD_V: u32 = 0x4ea2_8420; // add v0.4s, v1.4s, v2.4s
    const ADD_Z: u32 = 0x0422_0020; // add z0.b, z1.b, z2.b
    const LDR_ZA: u32 = 0xe100_0000; // ldr za[w12, 0], [x0]
    const FADD_S: u32 = 0x1e22_2820; // fadd s0, s1, s2
    const SME_TRAP: u64 = 0x1d << 26 | 1 << 25;
    let mut machine = machine(&[ADD_V, ADD_Z, LDR_ZA, FADD_S]);
    let chip = machine.profile.chip;
    if machine.cpu.scalable.is_none() {
        // Without SME the SVE and SME forms are UNDEFINED and check
        // nothing.
        for word in [ADD_Z, LDR_ZA] {
            assert_eq!(chip.checks(chip.admit(word)), &[]);
        }
        return;
    }
    machine
        .cpu
        .registers
        .set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
    for register in [SystemRegister::CPACR_EL1, SystemRegister::CPTR_EL2] {
        machine
            .cpu
            .registers
            .set(register, 0, 0b11 << 24 | 0b11 << 20);
    }
    machine.derived_changed();
    let run = |machine: &mut Machine<FakeHost, NoDevices>, index: u64| {
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.pc = BASE + 4 * index;
        let step = machine.step();
        (step, machine.cpu.read(SystemRegister::ESR_EL1))
    };
    let trapped = |index: u64, smtc: u64| (Ok(()), SME_TRAP | smtc, BASE + 4 * index);
    let taken = |machine: &mut Machine<FakeHost, NoDevices>, index| {
        let (step, esr) = run(machine, index);
        (step, esr, machine.cpu.read(SystemRegister::ELR_EL1))
    };
    // Outside streaming mode SVE traps as not streaming and a ZA load
    // as ZA inactive, at the instruction.
    assert_eq!(taken(&mut machine, 1), trapped(1, 2));
    assert_eq!(taken(&mut machine, 2), trapped(2, 3));
    // In streaming mode AdvSIMD traps as streaming; SVE, the ZA load and
    // scalar FP pass their checks (`engine::scalable` runs them): the SVE
    // addition runs, and the ZA load from address 0, which has no RAM or
    // device, stops explicitly.
    machine.cpu.set_svcr(true, true).unwrap();
    assert_eq!(taken(&mut machine, 0), trapped(0, 1));
    assert_eq!(run(&mut machine, 1).0, Ok(()));
    assert_eq!(machine.cpu.pc, BASE + 8);
    assert!(matches!(run(&mut machine, 2).0, Err(Stop::Unsupported(_))));
    // CPACR_EL1.SMEN clear traps SVE with SMTC 0 before anything else.
    machine
        .cpu
        .registers
        .set(SystemRegister::CPACR_EL1, 0, 0b11 << 20);
    machine.derived_changed();
    assert_eq!(taken(&mut machine, 1), trapped(1, 0));
}

#[test]
fn fpcr_alternate_controls_hold_on_the_chips_with_afp() {
    const MSR_FPCR_X0: u32 = 0xd51b_4400;
    const MRS_X1_FPCR: u32 = 0xd53b_4401;
    for (chip, afp) in [
        (stela_contracts::Chip::AppleM2, false),
        (stela_contracts::Chip::AppleM4, true),
    ] {
        let mut machine = machine_on(chip, &[]);
        for register in [SystemRegister::CPACR_EL1, SystemRegister::CPTR_EL2] {
            machine.cpu.registers.set(register, 0, 0b11 << 20);
        }
        machine.derived_changed();
        // FIZ, AH and NEP hold only where FEAT_AFP is implemented; the
        // compiled FP operations take their effects from the stored FPCR.
        machine.cpu.state.x[0] = u64::MAX;
        machine.system_instruction(MSR_FPCR_X0).unwrap();
        machine.system_instruction(MRS_X1_FPCR).unwrap();
        let held = if afp { 0x07c8_0007 } else { 0x07c8_0000 };
        assert_eq!(machine.cpu.state.x[1], held, "{chip:?}");
        assert_eq!(machine.cpu.state.fpcr, held as u32, "{chip:?}");
    }
}

#[test]
fn msr_immediate_waits_and_absent_features_follow_the_profile() {
    let mut machine = machine(&[]);
    let user = Pstate {
        el: 0,
        sp: false,
        daif: 0,
        ..Pstate::reset(1)
    };
    // MSR DAIFSet, #3 at EL0 with SCTLR_EL1.UMA clear traps with the
    // instruction's own Op0/Op2/Op1/CRn/Rt/CRm (Op0 0, Rt 31).
    machine.cpu.set_pstate(user);
    machine.system_instruction(0xd503_43df).unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x620c_d3e6);
    // PAN is EL1-only and op1=3 op2=5 is unallocated: UNDEFINED.
    for (pstate, word) in [(user, 0xd500_419f), (Pstate::reset(1), 0xd503_42bf)] {
        machine.cpu.set_pstate(pstate);
        machine.system_instruction(word).unwrap();
        assert_eq!(
            machine.cpu.read(SystemRegister::ESR_EL1),
            0x0200_0000,
            "{word:#x}"
        );
    }
    // With UMA set, EL0 may mask interrupts.
    machine.cpu.set_pstate(Pstate::reset(1));
    let sctlr = machine.cpu.read(SystemRegister::SCTLR_EL1);
    machine
        .cpu
        .registers
        .set(SystemRegister::SCTLR_EL1, 0, sctlr | 1 << 9);
    machine.cpu.set_pstate(user);
    machine.cpu.pc = BASE;
    machine.system_instruction(0xd503_43df).unwrap();
    assert_eq!((machine.cpu.pstate.daif, machine.cpu.pc), (3, BASE + 4));
    // WFE with the event register set completes before the nTWE trap,
    // then traps; WFI with an interrupt pending completes before nTWI.
    machine
        .cpu
        .registers
        .set(SystemRegister::SCTLR_EL1, 0, sctlr & !(1 << 16 | 1 << 18));
    machine.cpu.set_pstate(user);
    machine.cpu.pc = BASE;
    machine.cpu.event = true;
    machine.system_instruction(0xd503_205f).unwrap();
    assert_eq!((machine.cpu.pc, machine.cpu.event), (BASE + 4, false));
    machine.system_instruction(0xd503_205f).unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x07e0_0001);
    machine.cpu.set_pstate(user);
    machine.cpu.pc = BASE;
    machine
        .cpu
        .registers
        .set(SystemRegister::HCR_EL2, 0, 1 << HCR_IMO | 1 << HCR_VI);
    machine.system_instruction(0xd503_207f).unwrap();
    assert_eq!(machine.cpu.pc, BASE + 4);
    // SEV and SEVL set the event register.
    machine.cpu.set_pstate(Pstate::reset(1));
    for word in [0xd503_209f, 0xd503_20bf] {
        machine.cpu.event = false;
        machine.system_instruction(word).unwrap();
        assert!(machine.cpu.event, "{word:#x}");
    }
    // DSB nXS is UNDEFINED without FEAT_XS (before the M4); PACM
    // completes, a NOP without FEAT_PAuth_LR.
    machine.cpu.set_pstate(Pstate::reset(1));
    machine.cpu.pc = BASE;
    machine.system_instruction(0xd503_323f).unwrap();
    if Feature::FEAT_XS.on(machine.profile.chip) {
        assert_eq!(machine.cpu.pc, BASE + 4);
    } else {
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
    }
    machine.cpu.set_pstate(Pstate::reset(1));
    machine.cpu.pc = BASE;
    machine.system_instruction_for_test(0xd503_24ff);
    assert_eq!(machine.cpu.pc, BASE + 4);
}

#[test]
fn dsb_nxs_tlbi_nxs_and_the_xs_attribute_follow_feat_xs() {
    const DSB_ISHNXS: u32 = 0xd503_3a3f;
    const AT_S1E1R_X2: u32 = 0xd508_7802;
    // SYS (op0 1) with Xt XZR from an accessor's op0:op1:CRn:CRm:op2.
    let sys =
        |accessor: &crate::machine::system::Accessor| 0xd500_001f | u32::from(accessor.value) << 5;
    for (chip, xs) in [
        (stela_contracts::Chip::AppleM2, false),
        (stela_contracts::Chip::AppleM4, true),
    ] {
        let fresh = |el| {
            let mut machine = machine_on(chip, &[]);
            machine.cpu = Cpu::of(chip, BASE, Pstate::reset(el));
            let registers = &mut machine.cpu.registers;
            registers.set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
            registers.set(SystemRegister::VBAR_EL2, 0, 0x2_0000);
            machine
        };
        // DSB nXS completes as DSB does with FEAT_XS, and is UNDEFINED
        // without it.
        let mut machine = fresh(1);
        machine.system_instruction(DSB_ISHNXS).unwrap();
        if xs {
            assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 4, 1));
        } else {
            assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
        }
        // Every TLBI nXS at EL1 and EL2 behaves as its TLBI with FEAT_XS
        // (invalidating XS 1 entries too, which a TLB may always drop),
        // and is UNDEFINED without it.
        let mut count = 0;
        for nxs in crate::machine::system::ACCESSORS
            .iter()
            .filter(|a| a.kind == "TLBI" && a.name.ends_with("NXS"))
        {
            let plain = crate::machine::system::ACCESSORS
                .iter()
                .find(|a| a.kind == "TLBI" && a.name == nxs.name.trim_end_matches("NXS"))
                .unwrap();
            for el in [1, 2] {
                let mut nxs_machine = fresh(el);
                nxs_machine.system_instruction(sys(nxs)).unwrap();
                let outcome = |machine: &Machine<FakeHost, NoDevices>| {
                    (
                        machine.cpu.pc,
                        machine.cpu.pstate.el,
                        machine.cpu.read(SystemRegister::ESR_EL1),
                        machine.cpu.read(SystemRegister::ESR_EL2),
                    )
                };
                if xs {
                    let mut plain_machine = fresh(el);
                    plain_machine.system_instruction(sys(plain)).unwrap();
                    assert_eq!(
                        outcome(&nxs_machine),
                        outcome(&plain_machine),
                        "{}",
                        nxs.name
                    );
                } else {
                    let esr = if el == 1 {
                        SystemRegister::ESR_EL1
                    } else {
                        SystemRegister::ESR_EL2
                    };
                    assert_eq!(nxs_machine.cpu.read(esr), 0x0200_0000, "{} {el}", nxs.name);
                }
            }
            count += 1;
        }
        assert!(count > 50, "{count}");
        // HCRX_EL2.FnXS makes a TLBI at EL1 behave as its nXS form,
        // which completes as the TLBI does.
        if xs {
            let mut machine = fresh(2);
            machine.cpu.state.x[0] = 1 << 3;
            machine.system_instruction(0xd51c_1240).unwrap(); // msr hcrx_el2, x0
            assert_eq!(machine.cpu.read(SystemRegister::HCRX_EL2) & 1 << 3, 1 << 3);
            machine.cpu.set_pstate(Pstate::reset(1));
            machine.cpu.pc = BASE;
            machine.system_instruction(0xd508_871f).unwrap(); // tlbi vmalle1
            assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 4, 1));
            // HFGITR_EL2.TLBIVMALLE1 traps TLBI VMALLE1NXS from EL1 to
            // EL2 unless HCRX_EL2.FGTnXS exempts the nXS forms.
            const TLBI_VMALLE1NXS: u32 = 0xd508_971f;
            for (hcrx, trapped) in [(0, true), (1 << 4, false)] {
                let mut machine = fresh(1);
                let registers = &mut machine.cpu.registers;
                registers.set(SystemRegister::HFGITR_EL2, 0, 1 << 42);
                registers.set(SystemRegister::HCRX_EL2, 0, hcrx);
                machine.system_instruction(TLBI_VMALLE1NXS).unwrap();
                if trapped {
                    assert_eq!(machine.cpu.pstate.el, 2);
                    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL2) >> 26, 0x18);
                } else {
                    assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 4, 1));
                }
            }
        }
        // MAIR index 0 Device-nGnRE with XS 0, index 1 Normal
        // Write-Back; level-1 blocks map VA 0 and 1 GiB to BASE.
        let mut machine = fresh(1);
        for (entry, index) in [(0x4000, 0u64), (0x4008, 1)] {
            let block = BASE | 1 | 1 << 10 | 1 << 6 | index << 2;
            machine.host.ram[entry..entry + 8].copy_from_slice(&block.to_le_bytes());
        }
        let registers = &mut machine.cpu.registers;
        registers.set(SystemRegister::MAIR_EL1, 0, 0xff_05);
        registers.set(SystemRegister::TCR_EL1, 0, 25 | 1 << 23 | 5 << 32);
        registers.set(SystemRegister::TTBR0_EL1, 0, BASE + 0x4000);
        registers.set(SystemRegister::SCTLR_EL1, 0, 1 | 1 << 2);
        machine.derived_changed();
        let attribute = |machine: &mut Machine<FakeHost, NoDevices>, address: u64| {
            machine.cpu.state.x[2] = address;
            machine.system_instruction(AT_S1E1R_X2).unwrap();
            machine.cpu.read(SystemRegister::PAR_EL1) >> 56
        };
        // With FEAT_XS, PAR_EL1.ATTR reports the Device memory's XS 0;
        // without it the encoding is reserved and reads as nGnRE.
        assert_eq!(
            attribute(&mut machine, 0x1000),
            if xs { 0x05 } else { 0x04 }
        );
        // SCTLR_EL1.C clear makes Write-Back memory Non-cacheable, which
        // keeps its XS 0.
        machine.cpu.registers.set(SystemRegister::SCTLR_EL1, 0, 1);
        machine.derived_changed();
        assert_eq!(
            attribute(&mut machine, 0x4000_1000),
            if xs { 0x40 } else { 0x44 }
        );
    }
}

#[test]
fn prediction_restrictions_complete_on_every_chip() {
    // CFP, DVP and CPP RCTX, X0 (SYS #3, C7, C3, #4, #5 and #7).
    const RCTX_X0: [u32; 3] = [0xd50b_7380, 0xd50b_73a0, 0xd50b_73e0];
    // MSR SCTLR_EL1, X0.
    const MSR_SCTLR_EL1_X0: u32 = 0xd518_1000;
    const SCTLR_ENRCTX: u64 = 1 << 10;
    let fresh = |el| {
        let mut machine = machine(&[]);
        machine.cpu = Cpu::of(machine.profile.chip, BASE, Pstate::reset(el));
        machine
            .cpu
            .registers
            .set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
        machine
    };
    for word in RCTX_X0 {
        let mut machine = fresh(1);
        machine.system_instruction(word).unwrap();
        assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 4, 1));
        // EnRCTX clear: EL0 traps to EL1 (EC 0x18).
        let mut machine = fresh(0);
        machine.system_instruction(word).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1) >> 26, 0x18);
    }
    // EnRCTX holds through MSR and then lets EL0 restrict predictions.
    let mut machine = fresh(1);
    let sctlr = machine.cpu.read(SystemRegister::SCTLR_EL1);
    machine.cpu.state.x[0] = sctlr | SCTLR_ENRCTX;
    machine.system_instruction(MSR_SCTLR_EL1_X0).unwrap();
    assert_eq!(
        machine.cpu.read(SystemRegister::SCTLR_EL1) & SCTLR_ENRCTX,
        SCTLR_ENRCTX
    );
    machine.cpu.pstate = Pstate::reset(0);
    machine.cpu.pc = BASE;
    machine.derived_changed();
    machine.system_instruction(RCTX_X0[0]).unwrap();
    assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 4, 0));
    // In the host (E2H and TGE) SCTLR_EL2.EnRCTX governs EL0, trapping
    // to EL2.
    const HOST: u64 = 1 << 34 | 1 << 27;
    let host = |enabled: bool| {
        let mut machine = fresh(0);
        let registers = &mut machine.cpu.registers;
        registers.set(SystemRegister::HCR_EL2, 0, HOST);
        registers.set(SystemRegister::VBAR_EL2, 0, 0x2_0000);
        let sctlr = registers.get(SystemRegister::SCTLR_EL2, 0);
        let sctlr = if enabled {
            sctlr | SCTLR_ENRCTX
        } else {
            sctlr & !SCTLR_ENRCTX
        };
        registers.set(SystemRegister::SCTLR_EL2, 0, sctlr);
        registers.set(SystemRegister::SCTLR_EL1, 0, SCTLR_ENRCTX);
        machine.derived_changed();
        machine.system_instruction(RCTX_X0[2]).unwrap();
        machine
    };
    let machine = host(false);
    assert_eq!(machine.cpu.pstate.el, 2);
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL2) >> 26, 0x18);
    let machine = host(true);
    assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 4, 0));
}

#[test]
fn cosp_rctx_restricts_nothing_on_the_chips_with_specres2() {
    // COSP RCTX, X0 (SYS #3, C7, C3, #6).
    const COSP_RCTX_X0: u32 = 0xd50b_73c0;
    const SCTLR_ENRCTX: u64 = 1 << 10;
    for (chip, specres2) in [
        (stela_contracts::Chip::AppleM4, false),
        (stela_contracts::Chip::AppleM5, true),
    ] {
        let fresh = |el| {
            let mut machine = machine_on(chip, &[]);
            machine.cpu = Cpu::of(chip, BASE, Pstate::reset(el));
            machine
                .cpu
                .registers
                .set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
            machine
        };
        // At EL1 it completes with no effect, there being no speculation
        // to restrict, or is UNDEFINED without FEAT_SPECRES2.
        let mut machine = fresh(1);
        machine.system_instruction(COSP_RCTX_X0).unwrap();
        if specres2 {
            assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 4, 1));
        } else {
            assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
            continue;
        }
        // At EL0 SCTLR_EL1.EnRCTX clear traps it to EL1 (EC 0x18).
        let mut machine = fresh(0);
        machine.system_instruction(COSP_RCTX_X0).unwrap();
        assert_eq!(machine.cpu.pstate.el, 1);
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1) >> 26, 0x18);
        let mut machine = fresh(0);
        machine
            .cpu
            .registers
            .set(SystemRegister::SCTLR_EL1, 0, SCTLR_ENRCTX);
        machine.derived_changed();
        machine.system_instruction(COSP_RCTX_X0).unwrap();
        assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 4, 0));
    }
}

#[test]
fn sysl_has_no_architectural_accessor_and_the_implementation_defined_space_is_undefined() {
    const HCR_E2H: u64 = 1 << 34;
    let mut machine = machine(&[]);
    machine
        .cpu
        .registers
        .set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
    machine
        .cpu
        .registers
        .set(SystemRegister::VBAR_EL2, 0, 0x2_0000);
    // GCSPOPM (SYSL #0, C7, C7, #1) needs FEAT_GCS, and op1 3 CRn 7 has
    // no SYSL: both are UNDEFINED at EL1 and EL0.
    for (el, word) in [(1, 0xd528_7720), (1, 0xd52b_7000), (0, 0xd528_7720)] {
        machine.cpu.set_pstate(Pstate::reset(el));
        machine.cpu.pc = BASE;
        machine.system_instruction(word).unwrap();
        assert_eq!(machine.cpu.pstate.el, 1, "{word:#x}");
        assert_eq!(
            machine.cpu.read(SystemRegister::ESR_EL1) >> 26,
            0,
            "{word:#x}"
        );
    }
    // CRn 11 and 15 are the IMPLEMENTATION DEFINED space, for SYSL and
    // SYS (sysl x0, #0, C11, C0, #0; sysl x0, #7, C15, C15, #7; sys #0,
    // C11, C0, #0, x0; sys #7, C15, C15, #7). No censused component
    // executes one, so each is UNDEFINED at EL0, EL1 and EL2.
    const SPACE: [u32; 4] = [0xd528_b000, 0xd52f_ffe0, 0xd508_b000, 0xd50f_ffff];
    machine
        .cpu
        .registers
        .set(SystemRegister::HCR_EL2, 0, HCR_E2H);
    for word in SPACE {
        for el in [0, 1, 2] {
            machine.cpu.set_pstate(Pstate::reset(el));
            machine.cpu.pc = BASE;
            machine.system_instruction(word).unwrap();
            let (target, syndrome) = if el == 2 {
                (2, SystemRegister::ESR_EL2)
            } else {
                (1, SystemRegister::ESR_EL1)
            };
            assert_eq!(machine.cpu.pstate.el, target, "{word:#x} at EL{el}");
            assert_eq!(
                machine.cpu.read(syndrome),
                0x0200_0000,
                "{word:#x} at EL{el}"
            );
        }
    }
    // HCR_EL2.TIDCP traps the space from EL1 to EL2 first (EC 0x18).
    machine
        .cpu
        .registers
        .set(SystemRegister::HCR_EL2, 0, HCR_E2H | 1 << 20);
    for word in SPACE {
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.pc = BASE;
        machine.system_instruction(word).unwrap();
        assert_eq!(machine.cpu.pstate.el, 2, "{word:#x}");
        assert_eq!(
            machine.cpu.read(SystemRegister::ESR_EL2),
            0x6200_0000 | u64::from(registers::word_trap_iss(word)),
            "{word:#x}"
        );
    }
}

#[test]
fn completion_barriers_and_unallocated_hints_only_advance_the_pc() {
    let mut machine = machine(&[]);
    for el in [0, 1, 2] {
        // DSB SY, DSB OSHLD, ISB, SSBB, PSSBB, HINT #0x54 and #0x7f.
        for word in [
            0xd503_3f9f,
            0xd503_319f,
            0xd503_3fdf,
            0xd503_309f,
            0xd503_349f,
            0xd503_2a9f,
            0xd503_2fff,
        ] {
            machine.cpu.set_pstate(Pstate::reset(el));
            machine.cpu.pc = BASE;
            let before = machine.cpu.state.clone();
            machine.system_instruction(word).unwrap();
            assert_eq!(machine.cpu.pc, BASE + 4, "{word:#x} at EL{el}");
            assert_eq!(machine.cpu.pstate.el, el);
            assert_eq!(machine.cpu.state, before, "{word:#x} at EL{el}");
        }
    }
}

/// A machine with the OS lock clear and MDSCR_EL1 `mdscr`.
fn debug_machine(mdscr: u64) -> Machine<FakeHost, NoDevices> {
    let mut machine = machine(&[0xd503_201f, 0xd503_201f, 0xd503_201f]);
    let registers = &mut machine.cpu.registers;
    registers.set(SystemRegister::OSLSR_EL1, 0, 0b1000);
    registers.set(SystemRegister::MDSCR_EL1, 0, mdscr);
    registers.set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
    registers.set(SystemRegister::VBAR_EL2, 0, 0x4_0000);
    machine.derived_changed();
    machine
}

#[test]
fn breakpoints_and_brk_follow_kde_pstate_d_and_tde() {
    const MDE: u64 = 1 << 15;
    const KDE: u64 = 1 << 13;
    let mut machine = debug_machine(MDE | KDE);
    // Breakpoint 0 at BASE + 4 for EL1 (PMC 0b01).
    machine
        .cpu
        .registers
        .set(SystemRegister::DBGBVR_EL1, 0, BASE + 4);
    machine
        .cpu
        .registers
        .set(SystemRegister::DBGBCR_EL1, 0, 0b1111 << 5 | 0b01 << 1 | 1);
    machine.cpu.set_pstate(Pstate {
        daif: 0,
        ..Pstate::reset(1)
    });
    machine.derived_changed();
    // The instruction at BASE runs as a single-instruction block.
    machine.host.exits.push(NativeExit::Exit {
        next_pc: BASE + 4,
        kind: ExitKind::Fallthrough as u64,
    });
    machine.step().unwrap();
    assert_eq!(machine.cpu.pc, BASE + 4);
    // The breakpoint is taken before BASE + 4 executes: EC 0x31, IFSC
    // 0b100010, FAR not written.
    machine
        .cpu
        .registers
        .set(SystemRegister::FAR_EL1, 0, 0x1234);
    machine.step().unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0xc600_0022);
    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE + 4);
    assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), 0x1234);
    assert_eq!(machine.cpu.pc, 0x1_0200);
    // With PSTATE.D set (as on exception entry) the breakpoint is masked.
    machine.cpu.pc = BASE + 4;
    machine.host.exits.push(NativeExit::Exit {
        next_pc: BASE + 8,
        kind: ExitKind::Fallthrough as u64,
    });
    machine.step().unwrap();
    assert_eq!(machine.cpu.pc, BASE + 8);
    // MDCR_EL2.TDCC (bit 27) traps only DCC accesses: BRK stays at EL1.
    machine
        .cpu
        .registers
        .set(SystemRegister::MDCR_EL2, 0, 1 << 27);
    machine.cpu.set_pstate(Pstate::reset(1));
    machine.derived_changed();
    machine.cpu.pc = BASE;
    machine.system_instruction(0xd420_0020).unwrap(); // brk #1
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0xf200_0001);
    assert_eq!(machine.cpu.pstate.el, 1);
    // MDCR_EL2.TDE (bit 8) routes debug exceptions, BRK included, to EL2.
    machine
        .cpu
        .registers
        .set(SystemRegister::MDCR_EL2, 0, 1 << 8);
    machine.cpu.set_pstate(Pstate::reset(1));
    machine.derived_changed();
    machine.cpu.pc = BASE;
    machine.system_instruction(0xd420_0020).unwrap(); // brk #1
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL2), 0xf200_0001);
    assert_eq!(machine.cpu.pstate.el, 2);
}

#[test]
fn software_step_runs_one_instruction_then_takes_ec_0x32() {
    const SS: u64 = 1;
    let mut machine = debug_machine(SS);
    // ERET from EL1 (debug disabled there: no KDE) to EL0 with SPSR.SS
    // set makes the step active-not-pending at EL0.
    machine.cpu.registers.set(SystemRegister::ELR_EL1, 0, BASE);
    machine
        .cpu
        .registers
        .set(SystemRegister::SPSR_EL1, 0, 1 << 21);
    machine.system_instruction(0xd69f_03e0).unwrap();
    assert!(machine.cpu.pstate.ss && machine.cpu.pstate.el == 0);
    machine.host.exits.push(NativeExit::Exit {
        next_pc: BASE + 4,
        kind: ExitKind::Fallthrough as u64,
    });
    machine.step().unwrap();
    assert_eq!((machine.cpu.pc, machine.cpu.pstate.ss), (BASE + 4, false));
    // Active-pending: the next instruction takes the step exception to
    // EL1 (EC 0x32, ISS 0x22) with SPSR.SS clear.
    machine.step().unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0xca00_0022);
    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE + 4);
    assert_eq!(machine.cpu.read(SystemRegister::SPSR_EL1) & 1 << 21, 0);
    assert_eq!(machine.cpu.pc, 0x1_0400);
    // An SVC stepped from EL0 completes the step: SPSR.SS is 0.
    machine
        .cpu
        .registers
        .set(SystemRegister::SPSR_EL1, 0, 1 << 21);
    machine.cpu.registers.set(SystemRegister::ELR_EL1, 0, BASE);
    machine.system_instruction(0xd69f_03e0).unwrap();
    machine.cpu.step_advance = true;
    machine.system_instruction(0xd400_0001).unwrap(); // svc #0
    assert_eq!(machine.cpu.read(SystemRegister::SPSR_EL1) & 1 << 21, 0);
}

#[test]
fn watched_pages_exit_and_matching_accesses_take_ec_0x35() {
    const MDE: u64 = 1 << 15;
    const KDE: u64 = 1 << 13;
    // str x1, [x0]; ldr x2, [x0, #8]
    let mut machine = machine(&[0xf900_0001, 0xf940_0402]);
    let registers = &mut machine.cpu.registers;
    registers.set(SystemRegister::OSLSR_EL1, 0, 0b1000);
    registers.set(SystemRegister::MDSCR_EL1, 0, MDE | KDE);
    registers.set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
    // Watchpoint 0: bytes 4..=7 of the doubleword at BASE + 0x100,
    // stores, EL1.
    registers.set(SystemRegister::DBGWVR_EL1, 0, BASE + 0x100);
    registers.set(
        SystemRegister::DBGWCR_EL1,
        0,
        0xf0 << 5 | 0b10 << 3 | 0b01 << 1 | 1,
    );
    machine.cpu.set_pstate(Pstate {
        daif: 0,
        ..Pstate::reset(1)
    });
    machine.sync_regime();
    let watch = machine.host.regimes.last().unwrap().watch;
    assert!(watch.blocks(BASE) && !watch.blocks(BASE + 0x1000));
    machine.cpu.state.x[0] = BASE + 0x100;
    let watched = |address, write, offset| {
        NativeExit::Fault(NativeFault {
            origin: crate::machine::NativeFaultOrigin::Exception,
            trap: 14,
            error_code: 0,
            spills: stela_compiler::block::HostSpillSnapshot::new(),
            registers: stela_compiler::block::HostGprSnapshot::legacy([0; 16]),
            offset,
            address,
            write,
            cause: FaultCause::Watched,
        })
    };
    // The store covers bytes 0..=7: a match at byte 4, EC 0x35 (same
    // EL), WnR, DFSC 0b100010, FAR the first matching byte.
    let offset = native_fault_site(
        &mut machine,
        BASE,
        stela_compiler::block::RecoverySiteKind::GuestAccess,
    );
    machine.host.exits.push(watched(BASE + 0x100, true, offset));
    machine.step().unwrap();
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0xd600_0062);
    assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), BASE + 0x104);
    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE);
    // The load at BASE + 4 does not match: it runs once with its page
    // passed, which then leaves the shadow again.
    machine.cpu.set_pstate(Pstate {
        daif: 0,
        ..Pstate::reset(1)
    });
    machine.sync_regime();
    machine.cpu.pc = BASE + 4;
    let offset = native_fault_site(
        &mut machine,
        BASE + 4,
        stela_compiler::block::RecoverySiteKind::GuestAccess,
    );
    machine
        .host
        .exits
        .push(watched(BASE + 0x108, false, offset));
    machine.host.exits.push(NativeExit::Exit {
        next_pc: BASE + 8,
        kind: ExitKind::Fallthrough as u64,
    });
    let invalidations = machine.host.invalidations;
    machine.step().unwrap();
    assert_eq!(machine.cpu.pc, BASE + 8);
    assert!(machine.host.invalidations > invalidations);
    assert!(
        machine
            .host
            .regimes
            .iter()
            .any(|regime| regime.watch.pass[0] == Some(BASE))
    );
    assert_eq!(machine.host.regimes.last().unwrap().watch.pass, [None; 2]);
    // DC ZVA writes its whole block: the same watchpoint matches.
    normal_memory(&mut machine, false);
    machine.cpu.pc = BASE;
    machine.cpu.state.x[3] = BASE + 0x120;
    machine.system_instruction(0xd50b_7423).unwrap(); // dc zva, x3
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0xd600_0062);
    assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), BASE + 0x104);
}

#[test]
fn exclusives_use_the_monitor_granule_and_lse2_alignment() {
    let mut machine = machine(&[]);
    let data = 0x200;
    machine.host.ram[data..data + 16]
        .copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    machine.cpu.state.x[2] = BASE + data as u64;
    // ldxr x1, [x2]; stxr w3, x4, [x2]: passes once.
    machine.system_instruction(0xc85f_7c41).unwrap();
    assert_eq!(machine.cpu.state.x[1], 0x0807_0605_0403_0201);
    assert_eq!(
        machine.cpu.monitor.map(|reservation| reservation.granule),
        Some((BASE + 0x200) & !63)
    );
    machine.cpu.state.x[4] = 0x1111_2222_3333_4444;
    machine.system_instruction(0xc803_7c44).unwrap();
    assert_eq!(machine.cpu.state.x[3], 0);
    assert_eq!(
        &machine.host.ram[data..data + 8],
        &0x1111_2222_3333_4444u64.to_le_bytes()
    );
    machine.cpu.state.x[4] = 0;
    machine.system_instruction(0xc803_7c44).unwrap();
    assert_eq!(machine.cpu.state.x[3], 1, "the monitor was cleared");
    // CLREX clears the monitor between the pair.
    machine.system_instruction(0xc85f_7c41).unwrap();
    machine.system_instruction(0xd503_305f).unwrap();
    machine.system_instruction(0xc803_7c44).unwrap();
    assert_eq!(machine.cpu.state.x[3], 1);
    // ldxp x1, x5, [x2]; stxp w3, x4, x6, [x2].
    machine.system_instruction(0xc87f_1441).unwrap();
    assert_eq!(machine.cpu.state.x[5], 0x100f_0e0d_0c0b_0a09);
    machine.cpu.state.x[6] = 7;
    machine.system_instruction(0xc823_1844).unwrap();
    assert_eq!(machine.cpu.state.x[3], 0);
    assert_eq!(&machine.host.ram[data + 8..data + 16], &7u64.to_le_bytes());
    // With the MMU off data is Device memory, where an unaligned exclusive
    // is an Alignment fault (EC 0x25, DFSC 0b100001) even inside its
    // 16-byte granule.
    machine.cpu.state.x[2] = BASE + data as u64 + 2;
    machine.cpu.pc = BASE;
    machine.system_instruction(0x885f_7c41).unwrap(); // ldxr w1, [x2]
    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x9600_0021);
    assert_eq!(
        machine.cpu.read(SystemRegister::FAR_EL1),
        BASE + data as u64 + 2
    );
}

#[test]
fn os_lock_and_the_debug_communications_channel() {
    let mut machine = machine(&[]);
    // The OS lock is set at Cold reset; MSR OSLAR_EL1 clears it.
    assert_eq!(machine.cpu.read(SystemRegister::OSLSR_EL1) & 0b10, 0b10);
    // While it is set, OSECCR_EL1 saves and restores EDECCR (bits 31:0;
    // bits 63:32 are RES0). No external debugger reads it.
    machine.cpu.state.x[0] = 0xffff_ffff_1234_5678;
    machine.system_instruction(0xd510_0640).unwrap(); // msr oseccr_el1, x0
    machine.system_instruction(0xd530_0645).unwrap(); // mrs x5, oseccr_el1
    assert_eq!(machine.cpu.state.x[5], 0x1234_5678);
    machine.cpu.state.x[0] = 0;
    machine.system_instruction(0xd510_1080).unwrap(); // msr oslar_el1, x0
    assert_eq!(machine.cpu.read(SystemRegister::OSLSR_EL1) & 0b10, 0);
    // Unlocked, writes are ignored and reads are UNKNOWN (0 here).
    machine.cpu.state.x[0] = 0x9;
    machine.system_instruction(0xd510_0640).unwrap(); // msr oseccr_el1, x0
    machine.system_instruction(0xd530_0645).unwrap(); // mrs x5, oseccr_el1
    assert_eq!(machine.cpu.state.x[5], 0);
    assert_eq!(machine.cpu.read(SystemRegister::OSECCR_EL1), 0x1234_5678);
    machine.cpu.state.x[0] = 0;
    // A DBGDTRTX_EL0 write latches TXfull; nothing fills DTRRX.
    machine.cpu.state.x[0] = 0x1234_5678;
    machine.system_instruction(0xd513_0500).unwrap(); // msr dbgdtrtx_el0, x0
    machine.system_instruction(0xd533_0101).unwrap(); // mrs x1, mdccsr_el0
    assert_eq!(machine.cpu.state.x[1], 1 << 29);
    machine.cpu.state.x[2] = 7;
    machine.system_instruction(0xd533_0502).unwrap(); // mrs x2, dbgdtrrx_el0
    assert_eq!(machine.cpu.state.x[2], 0);
    assert_eq!(machine.cpu.dcc.tx, 0x1234_5678);
    // Claim tags: SET reads every implemented tag, CLR the claim.
    machine.cpu.state.x[0] = 0b101;
    machine.system_instruction(0xd510_78c0).unwrap(); // msr dbgclaimset_el1, x0
    machine.cpu.state.x[0] = 0b1;
    machine.system_instruction(0xd510_79c0).unwrap(); // msr dbgclaimclr_el1, x0
    machine.system_instruction(0xd530_79c3).unwrap(); // mrs x3, dbgclaimclr_el1
    machine.system_instruction(0xd530_78c4).unwrap(); // mrs x4, dbgclaimset_el1
    assert_eq!(
        (machine.cpu.state.x[3], machine.cpu.state.x[4]),
        (0b100, 0xff)
    );
}

#[test]
fn floating_point_detection_matches_encoding_classes() {
    for word in [
        0x1e60_2820_u32,
        0x4ea1_1c20,
        0x3dc0_0020,
        0xad40_0420,
        0xbd40_0020,
    ] {
        assert!(is_floating_point(word), "{word:#x}");
    }
    for word in [0x9100_0400_u32, 0xf940_0020, 0xa900_0be1, 0xd503_201f] {
        assert!(!is_floating_point(word), "{word:#x}");
    }
}

/// 26A434 XNU's TTBR1 layout: a 16 KiB granule with T1SZ 17, so 2048
/// level-1 entries of 64 GiB from 0xffff_8000_0000_0000.
#[test]
fn upper_occupancy_lists_the_mapped_level_one_ranges_and_outermost_blocks() {
    const ROOT: u64 = BASE + 0x8000;
    const NEXT: u64 = BASE + 0xc000;
    let mut machine = machine(&[]);
    let mut put = |address: u64, value: u64| {
        let offset = (address - BASE) as usize;
        machine.host.ram[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    };
    put(ROOT + 2016 * 8, NEXT | 0b11);
    put(ROOT + 2017 * 8, 0b01);
    put(ROOT + 2047 * 8, 0b01);
    put(NEXT + 3 * 8, 0b11);
    let registers = &mut machine.cpu.registers;
    registers.set(SystemRegister::TCR_EL1, 0, 17 << 16 | 0b01 << 30);
    registers.set(SystemRegister::TTBR1_EL1, 0, ROOT);
    assert_eq!(machine.upper_occupancy(), None, "the MMU is off");
    machine.cpu.registers.set(SystemRegister::SCTLR_EL1, 0, 1);
    assert_eq!(
        machine.upper_occupancy(),
        Some(Occupancy {
            root: ROOT,
            ranges: vec![
                (0xffff_fe00_0000_0000, 0xffff_fe1f_ffff_ffff),
                (0xffff_fff0_0000_0000, u64::MAX),
            ],
            lowest: Some(0xffff_fe00_0600_0000),
            highest: Some(u64::MAX),
        })
    );
    // Another granule is not reported.
    machine
        .cpu
        .registers
        .set(SystemRegister::TCR_EL1, 0, 17 << 16 | 0b10 << 30);
    assert_eq!(machine.upper_occupancy(), None);
}

mod recovery;

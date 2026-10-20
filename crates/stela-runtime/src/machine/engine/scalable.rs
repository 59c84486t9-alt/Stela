//! SVE and SME instructions that passed their access checks
//! (`machine::streaming`), run one at a time as context leaves of the shared
//! compiler (`stela_compiler::extended::prepare_leaf`) on the PE's scalable
//! state (`crate::scalable`) at the streaming vector length. The leaf's
//! profile is the PE's mode (PSTATE.SM and ZA) and the chip's scalable
//! features the engine implements; leaves are cached by PC, word and profile
//! and discarded with the blocks. A leaf's memory accesses come back to the
//! engine one element at a time through the context's memory service
//! ([`serve`]), which translates and checks each as a plain data access and
//! raises its exception after the leaf returns. What a leaf cannot run stops
//! explicitly: numerical floating point, tag-checked accesses with tag checks
//! enabled, and PSTATE.DIT set, whose timing the leaves do not keep.
use super::{
    DeviceError, Devices, FETCH_PAGE, Host, InstallError, Machine, NativeCode, RamTables,
    RequirementKind, Step, Stop, Translated,
};
use crate::machine::{
    Chip,
    cpu::{Exception, STREAMING_VECTOR_BYTES},
    debug,
    exception::Class,
    mmu::{self, Access, MemoryType, alignment},
    system::Feature,
};
use alloc::{format, string::String, vec::Vec};
use stela_compiler::{
    GuestAddress, GuestState,
    aarch64::scalable::{
        VectorLength,
        features::{ScalableFeature, ScalableFeatures},
        profile::ScalableControls,
    },
    context::{
        ExecutionContext,
        memory::{
            MEMORY_CONTEXT_BYTES, MEMORY_CONTEXT_VERSION, MemoryContextView, MemoryRequest,
            MemoryRequirements, MemoryStatus, SpAlignmentRequirement, flags, profile_requirements,
        },
    },
    extended::{self, ScalableProfile},
};

/// RET X30, which ends a context leaf.
const RET_X30: u32 = 0xd65f_03c0;
/// SCTLR_ELx.TCF and TCF0: tag check faults at EL1 or EL2, and at EL0.
const SCTLR_TCF: u32 = 40;
const SCTLR_TCF0: u32 = 38;

/// The chip features the compiler's scalable profiles name.
const FEATURES: [(Feature, ScalableFeature); 17] = [
    (Feature::FEAT_SME, ScalableFeature::Sme),
    (Feature::FEAT_SME2, ScalableFeature::Sme2),
    (Feature::FEAT_SME2p1, ScalableFeature::Sme2p1),
    (Feature::FEAT_SME_F64F64, ScalableFeature::SmeF64F64),
    (Feature::FEAT_SME_I16I64, ScalableFeature::SmeI16I64),
    (Feature::FEAT_SME_B16B16, ScalableFeature::SmeB16B16),
    (Feature::FEAT_SME_F16F16, ScalableFeature::SmeF16F16),
    (Feature::FEAT_SME_F8F16, ScalableFeature::SmeF8F16),
    (Feature::FEAT_SME_F8F32, ScalableFeature::SmeF8F32),
    (Feature::FEAT_SME_LUTv2, ScalableFeature::SmeLutV2),
    (Feature::FEAT_SVE_B16B16, ScalableFeature::SveB16B16),
    (Feature::FEAT_BF16, ScalableFeature::Bf16),
    (Feature::FEAT_I8MM, ScalableFeature::I8mm),
    (Feature::FEAT_FAMINMAX, ScalableFeature::FaMinMax),
    (Feature::FEAT_LUT, ScalableFeature::Lut),
    (Feature::FEAT_FP8, ScalableFeature::Fp8),
    (Feature::FEAT_FPMR, ScalableFeature::Fpmr),
];

/// The scalable features of `chip` that the engine implements: an
/// instruction of a feature it has but the engine lacks fails to compile,
/// and stops.
pub(crate) fn features(chip: Chip) -> ScalableFeatures {
    FEATURES
        .iter()
        .filter(|(feature, _)| chip.implemented(*feature) == Ok(true))
        .fold(ScalableFeatures::empty(), |features, (_, scalable)| {
            features.with(*scalable)
        })
}

/// A context leaf's entry: `extended::prepare_leaf`'s two-argument ABI.
type Entry = unsafe extern "sysv64" fn(*mut GuestState, *mut ExecutionContext);

/// An installed leaf and what its memory accesses require of the PE.
#[derive(Debug, Clone, Copy)]
pub(super) struct Leaf {
    code: NativeCode,
    memory: MemoryRequirements,
}

/// Why a memory request failed: the exception its element takes, or why the
/// engine stops. Either is reported to the leaf as `status`.
enum Failure {
    Exception(MemoryStatus, Exception),
    Stop(MemoryStatus, Stop),
}

/// The memory service of one leaf call: its requests reach `machine`, whose
/// GuestState and scalable state are lent to the leaf meanwhile.
struct Service<H: Host, D: Devices> {
    machine: *mut Machine<H, D>,
    word: u32,
    failure: Option<Failure>,
}

/// The `MemoryCallback` of [`Service`]: one architectural element, in
/// order, which the engine translates, checks and transfers.
unsafe extern "sysv64" fn serve<H: Host, D: Devices>(
    view: *mut MemoryContextView,
    request: *const MemoryRequest,
) -> u32 {
    if view.is_null() || request.is_null() {
        return MemoryStatus::InvalidRequest as u32;
    }
    // SAFETY: the leaf passes the view the engine built and a request in its
    // own frame, for this call.
    let (view, request) = unsafe { (&mut *view, &*request) };
    // SAFETY: `opaque` is the Service of this call, and its machine is not
    // otherwise borrowed while the leaf runs.
    let service = unsafe { &mut *view.opaque.cast::<Service<H, D>>() };
    let machine = unsafe { &mut *service.machine };
    let word = service.word;
    let result = crate::platform::unwind::invoke(core::panic::AssertUnwindSafe(|| {
        machine.scalable_access(word, request)
    }));
    let failure = match result {
        Ok(Ok(())) => {
            view.completed_bytes += u64::from(request.bytes);
            return MemoryStatus::Success as u32;
        }
        Ok(Err(failure)) => failure,
        #[allow(unreachable_patterns)]
        Err(_) => Failure::Stop(
            MemoryStatus::Domain,
            machine.unsupported(RequirementKind::Instruction {
                word,
                detail: "the SVE and SME memory service panicked".into(),
            }),
        ),
    };
    let status = match &failure {
        Failure::Exception(status, _) | Failure::Stop(status, _) => *status,
    };
    service.failure = Some(failure);
    view.record(status, request.address, request.pc, view.completed_bytes);
    status as u32
}

impl<H: Host, D: Devices> Machine<H, D> {
    /// Run the SVE or SME instruction `word` at `pc`, whose access checks
    /// passed.
    pub(super) fn scalable_instruction(&mut self, pc: u64, word: u32) -> Step {
        let refuse = |machine: &Self, detail: &str| {
            Err(machine.unsupported(RequirementKind::Instruction {
                word,
                detail: detail.into(),
            }))
        };
        // Version 2 profiles require PSTATE.DIT clear: the leaves are not
        // compiled for data-independent timing.
        if self.cpu.pstate.dit {
            return refuse(
                self,
                "SVE and SME instructions with PSTATE.DIT set are not run by the system engine",
            );
        }
        let profile = match self.scalable_profile() {
            Ok(profile) => profile,
            Err(detail) => return refuse(self, &detail),
        };
        let leaf = match self.scalable_leaf(pc, word, profile) {
            Ok(leaf) => leaf,
            Err(detail) => return refuse(self, &detail),
        };
        if let Err(detail) = self.admit_memory(leaf.memory) {
            return refuse(self, detail);
        }
        let Some(entry) = self.host.context_entry(leaf.code) else {
            return refuse(
                self,
                "this host does not run the context leaves of SVE and SME instructions",
            );
        };
        // SAFETY: the host gives the address of the installed leaf, compiled
        // for the two-argument context ABI.
        let entry: Entry = unsafe { core::mem::transmute::<usize, Entry>(entry) };
        self.completing(pc, |machine| machine.call_leaf(entry, profile, word))
    }

    /// Call `entry` on the PE's state, lent with its scalable registers, and
    /// complete the instruction or take the exception its memory access
    /// raised.
    fn call_leaf(&mut self, entry: Entry, profile: ScalableProfile, word: u32) -> Step {
        let mut state = core::mem::take(&mut self.cpu.state);
        let Some(mut scalable) = self.cpu.scalable.take() else {
            self.cpu.state = state;
            return Err(self.unsupported(RequirementKind::Instruction {
                word,
                detail: "a PE without SME state".into(),
            }));
        };
        let mut service = Service {
            machine: self as *mut Self,
            word,
            failure: None,
        };
        let mut memory = MemoryContextView {
            version: MEMORY_CONTEXT_VERSION,
            bytes: MEMORY_CONTEXT_BYTES,
            callback: serve::<H, D>,
            opaque: (&raw mut service).cast(),
            fault_kind: MemoryStatus::Success as u32,
            reserved: 0,
            fault_address: 0,
            fault_pc: 0,
            completed_bytes: 0,
            reserved_tail: 0,
        };
        // SAFETY: the view lends the PE's register buffers for this one
        // call, which the leaf compiled for `profile` reaches only through
        // it, and keeps no pointer to. Its memory service reaches the machine
        // through `service`, while `state` and `scalable` are out of it.
        let called = unsafe {
            scalable.with_view(|view| {
                let mut context = ExecutionContext {
                    memory: (&raw mut memory).cast(),
                    scalable: view,
                    ..ExecutionContext::default()
                };
                profile.validate_view(&context, view)?;
                entry(&mut state, &mut context);
                Ok::<_, stela_compiler::CompileError>(())
            })
        };
        self.cpu.state = state;
        self.cpu.scalable = Some(scalable);
        if let Err(error) = called {
            return Err(self.unsupported(RequirementKind::Instruction {
                word,
                detail: error.0,
            }));
        }
        match (MemoryStatus::from_code(memory.fault_kind), service.failure) {
            (Some(MemoryStatus::Success), None) => {}
            (_, Some(Failure::Exception(_, exception))) => {
                self.take(exception);
                return Ok(());
            }
            (_, Some(Failure::Stop(_, stop))) => return Err(stop),
            // The leaf checks SP alignment itself, where the access needs it
            // checked (`admit_memory`).
            (Some(MemoryStatus::StackAlignment), None) => {
                self.take(Exception::synchronous(Class::SpAlignment, 0, self.cpu.pc));
                return Ok(());
            }
            (status, None) => {
                return Err(self.unsupported(RequirementKind::Instruction {
                    word,
                    detail: format!("the leaf reported memory status {status:?} by itself"),
                }));
            }
        }
        self.statistics.blocks += 1;
        self.next()?;
        match self.devices.take_reset() {
            Some(reason) => Err(Stop::Reset(reason)),
            None => Ok(()),
        }
    }

    /// Whether the PE's controls are those the leaf's memory accesses were
    /// compiled for: SP alignment checked as the access requires, and
    /// nothing the engine's memory service does not provide.
    fn admit_memory(&mut self, memory: MemoryRequirements) -> Result<(), &'static str> {
        let known = profile_requirements::NATIVE_ACCESS
            | profile_requirements::TAG_GRANULES
            | profile_requirements::SCALABLE_TAG_CHECKS;
        if memory.required_profile & !known != 0
            || memory.required_flags & (flags::ATOMIC | flags::ORDERED | flags::EXCLUSIVE) != 0
            || !memory.required_address_checks.is_empty()
            || memory.required_pointer_arithmetic.is_some()
        {
            return Err("an SVE or SME memory access the engine's memory service does not provide");
        }
        match (memory.required_sp_alignment, self.stack_alignment_checked()) {
            (SpAlignmentRequirement::Enabled, false) => Err(
                "an SP-based SVE or SME access with SCTLR_ELx.SA clear, whose leaf checks SP alignment",
            ),
            (SpAlignmentRequirement::Disabled, true) => Err(
                "an SP-based SVE or SME access with SCTLR_ELx.SA set, whose leaf does not check SP alignment",
            ),
            _ => Ok(()),
        }
    }

    /// One element of an SVE or SME access: translated and checked in
    /// Arm's order (alignment, each page's translation and permission, the
    /// memory type's alignment, watchpoints), then read or written whole.
    fn scalable_access(&mut self, word: u32, request: &MemoryRequest) -> Result<(), Failure> {
        let stop = |machine: &Self, detail: &str| {
            Failure::Stop(
                MemoryStatus::Unsupported,
                machine.unsupported(RequirementKind::Instruction {
                    word,
                    detail: detail.into(),
                }),
            )
        };
        let bytes = request.bytes as usize;
        if !request.has_supported_ordinary_shape()
            || request.flags & (flags::ASIMD | flags::PAIR) != 0
            || request.data.is_null()
            || request.pc != self.cpu.pc
        {
            return Err(stop(self, "a malformed SVE or SME memory request"));
        }
        let write = request.flags & flags::WRITE != 0;
        if request.flags & flags::TAG_CHECKED != 0 && self.tag_checks_enabled() {
            return Err(stop(
                self,
                "tag-checked SVE and SME accesses are not run by the system engine",
            ));
        }
        let address = request.address;
        let shape = alignment::Shape {
            kind: alignment::Kind::Plain,
            bytes: bytes as u64,
            pair: false,
        };
        let aligned = shape.aligned(address);
        let access = if write { Access::Write } else { Access::Read };
        let controls = self.cpu.controls(self.cpu.regime());
        let requester = self.cpu.requester();
        let mut pieces: Vec<(u64, usize, MemoryType)> = Vec::with_capacity(2);
        let mut done = 0;
        while done < bytes {
            let virtual_address = address.wrapping_add(done as u64);
            let length =
                ((FETCH_PAGE - (virtual_address & (FETCH_PAGE - 1))) as usize).min(bytes - done);
            match mmu::translate_checked(
                &controls,
                virtual_address,
                access,
                requester,
                shape,
                &mut RamTables(&mut self.host),
            ) {
                // An unaligned element crossing into Device memory faults
                // there too.
                Translated::Mapped(translation)
                    if done > 0 && !aligned && translation.memory == MemoryType::Device =>
                {
                    let fault = mmu::Fault {
                        kind: mmu::FaultKind::Alignment,
                        level: 0,
                        second_stage: None,
                    };
                    let exception = self.data_abort_exception(address, fault, write, false);
                    return Err(Failure::Exception(MemoryStatus::Alignment, exception));
                }
                Translated::Mapped(translation) => {
                    pieces.push((translation.physical, length, translation.memory));
                }
                Translated::Fault(fault) => {
                    let status = match fault.kind {
                        mmu::FaultKind::Alignment => MemoryStatus::Alignment,
                        mmu::FaultKind::Permission => MemoryStatus::Permission,
                        _ => MemoryStatus::Translation,
                    };
                    let exception = self.data_abort_exception(virtual_address, fault, write, false);
                    return Err(Failure::Exception(status, exception));
                }
                Translated::Unsupported(unsupported) => {
                    return Err(Failure::Stop(
                        MemoryStatus::Unsupported,
                        self.unsupported(RequirementKind::Translation(unsupported)),
                    ));
                }
            }
            done += length;
        }
        let watched = debug::Access {
            address,
            size: bytes as u64,
            read: !write,
            write,
            maintenance: false,
            el: self.cpu.pstate.el,
        };
        if let Some(exception) = self.watchpoint_exception(&watched, self.cpu.pc) {
            return Err(Failure::Exception(MemoryStatus::Permission, exception));
        }
        // SAFETY: the leaf's request names `bytes` of private staging.
        let data = unsafe { core::slice::from_raw_parts_mut(request.data, bytes) };
        let ram = pieces.iter().all(|&(physical, length, _)| {
            let mut probe = [0u8; 1];
            self.host.read_ram(physical, &mut probe)
                && self.host.read_ram(physical + length as u64 - 1, &mut probe)
        });
        if ram {
            let mut offset = 0;
            for (physical, length, _) in pieces {
                let part = &mut data[offset..offset + length];
                if write {
                    self.host.write_ram(physical, part);
                } else {
                    self.host.read_ram(physical, part);
                }
                offset += length;
            }
            return Ok(());
        }
        let [(physical, _, _)] = pieces[..] else {
            return Err(stop(self, "an SVE or SME element crossing out of RAM"));
        };
        if bytes > size_of::<u64>() {
            return Err(stop(self, "a 16-byte SVE or SME element of a device"));
        }
        let now = self.now();
        let mut value = [0u8; size_of::<u64>()];
        let result = if write {
            value[..bytes].copy_from_slice(data);
            self.device_write(physical, bytes as u8, u64::from_le_bytes(value), now)
                .map(|()| 0)
        } else {
            self.device_read(physical, bytes as u8, now)
        };
        match result {
            Ok(read) => {
                if !write {
                    data.copy_from_slice(&read.to_le_bytes()[..bytes]);
                }
                Ok(())
            }
            Err(DeviceError::NoDevice) => Err(Failure::Stop(
                MemoryStatus::Unsupported,
                self.scalable_device(address, physical, write, "no device model".into()),
            )),
            Err(DeviceError::Refused(detail) | DeviceError::TransferRefused(detail)) => {
                Err(Failure::Stop(
                    MemoryStatus::Unsupported,
                    self.scalable_device(address, physical, write, detail),
                ))
            }
        }
    }

    fn scalable_device(&self, address: u64, physical: u64, write: bool, detail: String) -> Stop {
        let mut requirement = self.requirement(RequirementKind::Device {
            physical,
            write,
            detail,
        });
        requirement.address = Some(address);
        Stop::Unsupported(requirement)
    }

    /// Whether a tag-checked access would be checked (FEAT_MTE2 with
    /// SCTLR_ELx.TCF, or TCF0 at EL0, of the regime not 0), which the engine
    /// does not implement.
    fn tag_checks_enabled(&self) -> bool {
        if !Feature::FEAT_MTE2.on(self.profile.chip) {
            return false;
        }
        let shift = if self.cpu.pstate.el == 0 {
            SCTLR_TCF0
        } else {
            SCTLR_TCF
        };
        (self.cpu.regime_sctlr() >> shift) & 0b11 != 0
    }

    /// The profile of the PE's current scalable state.
    fn scalable_profile(&self) -> Result<ScalableProfile, String> {
        let scalable = self
            .cpu
            .scalable
            .as_ref()
            .ok_or_else(|| String::from("a PE without SME state"))?;
        let features = features(self.profile.chip);
        let length = VectorLength::from_bytes(STREAMING_VECTOR_BYTES)
            .ok_or_else(|| String::from("the streaming vector length"))?;
        let controls = ScalableControls::new(length, features.contains(ScalableFeature::Sme2));
        ScalableProfile::new_with_features(length, scalable.mode(), features, controls)
            .map_err(|error| error.0)
    }

    /// The installed leaf of `word` at `pc` for `profile`, compiling it on
    /// first use.
    fn scalable_leaf(
        &mut self,
        pc: u64,
        word: u32,
        profile: ScalableProfile,
    ) -> Result<Leaf, String> {
        if let Some(leaf) = self.scalable_leaves.get(&(pc, word, profile)) {
            return Ok(*leaf);
        }
        let source: Vec<u8> = [word, RET_X30]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        let prepared = extended::prepare_leaf(&source, GuestAddress(pc), profile, self.target)
            .map_err(|error| error.0)?;
        let native = &prepared.native.x86_64_code;
        let code = match self.host.install(native) {
            Ok(code) => code,
            Err(InstallError::Full) => {
                self.discard_code();
                self.host
                    .install(native)
                    .map_err(|_| String::from("the leaf exceeds the code arena"))?
            }
        };
        self.statistics.compiled += 1;
        let leaf = Leaf {
            code,
            memory: prepared.memory_requirements,
        };
        self.scalable_leaves.insert((pc, word, profile), leaf);
        Ok(leaf)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        NoDevices, Stop,
        tests::{BASE, FakeHost, machine, normal_memory},
    };
    use super::*;
    use crate::machine::{exception::Pstate, system::Register};

    type TestMachine = Machine<FakeHost, NoDevices>;

    const PTRUE_P0_B: u32 = 0x2518_e3e0; // ptrue p0.b
    const INDEX_Z1_0_1: u32 = 0x0421_4001; // index z1.b, #0, #1
    const INDEX_Z2_3_0: u32 = 0x0420_4062; // index z2.b, #3, #0
    const ADD_Z0_Z1_Z2: u32 = 0x0422_0020; // add z0.b, z1.b, z2.b
    const MOVA_ZA0H_Z0: u32 = 0xc000_0000; // mova za0h.b[w12, 0], p0/m, z0.b
    const MOVA_Z3_ZA0H: u32 = 0xc002_0003; // mova z3.b, p0/m, za0h.b[w12, 0]
    const RDSVL_X5: u32 = 0x04bf_5825; // rdsvl x5, #1
    const ZERO_ZA: u32 = 0xc008_00ff; // zero {za}

    /// A PE of the test chip at EL1 with FP, SVE and SME enabled, in
    /// streaming mode with ZA, running `words` from BASE; `None` on a chip
    /// without SME.
    fn streaming(words: &[u32]) -> Option<TestMachine> {
        let mut machine = machine(words);
        machine.cpu.scalable.as_ref()?;
        machine.cpu.registers.set(Register::VBAR_EL1, 0, 0x1_0000);
        for register in [Register::CPACR_EL1, Register::CPTR_EL2] {
            machine
                .cpu
                .registers
                .set(register, 0, 0b11 << 24 | 0b11 << 20 | 0b11 << 16);
        }
        machine.derived_changed();
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.set_svcr(true, true).unwrap();
        machine.cpu.pc = BASE;
        Some(machine)
    }

    fn z(machine: &TestMachine, register: u8) -> Vec<u8> {
        let mut bytes = alloc::vec![0; STREAMING_VECTOR_BYTES];
        let scalable = machine.cpu.scalable.as_ref().unwrap();
        scalable
            .read_z(&machine.cpu.state, register, &mut bytes)
            .unwrap();
        bytes
    }

    #[test]
    fn streaming_sve_and_sme_instructions_run_on_the_512_bit_state() {
        let words = [
            PTRUE_P0_B,
            INDEX_Z1_0_1,
            INDEX_Z2_3_0,
            ADD_Z0_Z1_Z2,
            MOVA_ZA0H_Z0,
            MOVA_Z3_ZA0H,
            RDSVL_X5,
            ZERO_ZA,
        ];
        // The scalar lowering, and the host's AVX2 and AVX-512 where it has
        // them.
        for target in [
            stela_compiler::TargetCpu::Baseline,
            stela_compiler::TargetCpu::detect(),
        ] {
            run_on(target, &words);
        }
    }

    fn run_on(target: stela_compiler::TargetCpu, words: &[u32]) {
        let Some(mut machine) = streaming(words) else {
            return;
        };
        machine.target = target;
        let compiled = machine.statistics.compiled;
        for index in 0..words.len() as u64 {
            assert_eq!(machine.step(), Ok(()), "{index}");
            assert_eq!(machine.cpu.pc, BASE + 4 * (index + 1));
        }
        assert_eq!(machine.statistics.compiled - compiled, words.len() as u64);
        // Every element of the 512-bit vectors: Z1 counts up, Z2 is 3.
        let expected: Vec<u8> = (3..3 + STREAMING_VECTOR_BYTES as u8).collect();
        assert_eq!(z(&machine, 0), expected);
        // Through ZA0H.B row 0 and back; then ZERO {ZA} clears the row.
        assert_eq!(z(&machine, 3), expected);
        let mut row = [0xffu8; STREAMING_VECTOR_BYTES];
        let scalable = machine.cpu.scalable.as_ref().unwrap();
        scalable.read_za(0, &mut row).unwrap();
        assert_eq!(row, [0; STREAMING_VECTOR_BYTES]);
        assert_eq!(machine.cpu.state.x[5], STREAMING_VECTOR_BYTES as u64);
        // Running an instruction again reuses its leaf.
        machine.cpu.pc = BASE + 4 * 3;
        let compiled = machine.statistics.compiled;
        machine.step().unwrap();
        assert_eq!(machine.statistics.compiled, compiled);
    }

    #[test]
    fn dit_stops_explicitly() {
        let Some(mut machine) = streaming(&[ADD_Z0_Z1_Z2]) else {
            return;
        };
        machine.cpu.pstate.dit = true;
        assert!(stop(&mut machine).contains("PSTATE.DIT"));
        assert_eq!(machine.cpu.pc, BASE);
    }

    fn stop(machine: &mut TestMachine) -> alloc::string::String {
        match machine.step() {
            Err(Stop::Unsupported(requirement)) => alloc::format!("{:?}", requirement.kind),
            other => panic!("{other:?}"),
        }
    }

    /// RAM at `address`, `bytes` long.
    fn ram(machine: &TestMachine, address: u64, bytes: usize) -> Vec<u8> {
        let offset = (address - BASE) as usize;
        machine.host.ram[offset..offset + bytes].to_vec()
    }

    #[test]
    fn scalable_loads_and_stores_reach_translated_memory_element_by_element() {
        const ST1B_Z1_X5: u32 = 0xe400_e0a1; // st1b {z1.b}, p0, [x5]
        const LD1B_Z2_X5: u32 = 0xa400_a0a2; // ld1b {z2.b}, p0/z, [x5]
        const LDR_ZA_X5: u32 = 0xe100_00a0; // ldr za[w12, 0], [x5]
        const STR_ZA_X6: u32 = 0xe120_00c0; // str za[w12, 0], [x6]
        let words = [
            PTRUE_P0_B,
            INDEX_Z1_0_1,
            ST1B_Z1_X5,
            LD1B_Z2_X5,
            LDR_ZA_X5,
            STR_ZA_X6,
        ];
        let Some(mut machine) = streaming(&words) else {
            return;
        };
        normal_memory(&mut machine, false);
        // The ZA store crosses a page.
        let (source, destination) = (BASE + 0x8000, BASE + 0x9000 - 24);
        machine.cpu.state.x[5] = source;
        machine.cpu.state.x[6] = destination;
        for index in 0..words.len() as u64 {
            assert_eq!(machine.step(), Ok(()), "{index}");
            assert_eq!(machine.cpu.pc, BASE + 4 * (index + 1));
        }
        let counted: Vec<u8> = (0..STREAMING_VECTOR_BYTES as u8).collect();
        assert_eq!(ram(&machine, source, STREAMING_VECTOR_BYTES), counted);
        assert_eq!(z(&machine, 2), counted);
        assert_eq!(ram(&machine, destination, STREAMING_VECTOR_BYTES), counted);
    }

    #[test]
    fn scalable_accesses_take_their_data_aborts_alignment_and_sp_faults() {
        const LD1B_Z2_X5: u32 = 0xa400_a0a2; // ld1b {z2.b}, p0/z, [x5]
        const ST1B_Z1_X5: u32 = 0xe400_e0a1; // st1b {z1.b}, p0, [x5]
        const LD1W_Z0_X5: u32 = 0xa540_a0a0; // ld1w {z0.s}, p0/z, [x5]
        const LD1B_Z2_SP: u32 = 0xa400_a3e2; // ld1b {z2.b}, p0/z, [sp]
        const SCTLR_A: u64 = 1 << 1;
        const SCTLR_SA: u64 = 1 << 3;
        let words = [PTRUE_P0_B, LD1B_Z2_X5, ST1B_Z1_X5, LD1W_Z0_X5, LD1B_Z2_SP];
        let Some(mut machine) = streaming(&words) else {
            return;
        };
        normal_memory(&mut machine, false);
        machine.step().unwrap();
        let run = |machine: &mut TestMachine, index: u64| {
            machine.cpu.set_pstate(Pstate::reset(1));
            machine.cpu.pc = BASE + 4 * index;
            machine.step()
        };
        let syndrome = |machine: &TestMachine| {
            (
                machine.cpu.read(Register::ESR_EL1),
                machine.cpu.read(Register::FAR_EL1),
                machine.cpu.read(Register::ELR_EL1),
            )
        };
        // Outside the mapped gigabyte: a level-1 translation fault, a write
        // for the store, at the instruction and its first element.
        let unmapped = BASE + 0x4000_0000;
        machine.cpu.state.x[5] = unmapped;
        for (index, write) in [(1, 0), (2, 1 << 6)] {
            assert_eq!(run(&mut machine, index), Ok(()));
            assert_eq!(
                syndrome(&machine),
                (
                    0x25 << 26 | 1 << 25 | write | 0b00_0101,
                    unmapped,
                    BASE + 4 * index
                )
            );
        }
        // A store that reaches past RAM stops there, and keeps the elements
        // before it (Z1 is zero).
        let edge = BASE + 0x1_0000 - 16;
        let offset = (edge - BASE) as usize;
        machine.host.ram[offset..].fill(0xff);
        machine.cpu.state.x[5] = edge;
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.pc = BASE + 8;
        assert!(stop(&mut machine).contains("no device model"));
        assert_eq!(ram(&machine, edge, 16), [0; 16]);
        // With SCTLR_EL1.A an unaligned word element faults (DFSC 0x21).
        let sctlr = machine.cpu.read(Register::SCTLR_EL1);
        machine
            .cpu
            .registers
            .set(Register::SCTLR_EL1, 0, sctlr | SCTLR_A);
        machine.derived_changed();
        machine.cpu.state.x[5] = BASE + 0x8002;
        assert_eq!(run(&mut machine, 3), Ok(()));
        assert_eq!(
            syndrome(&machine),
            (0x25 << 26 | 1 << 25 | 0x21, BASE + 0x8002, BASE + 12)
        );
        // An unaligned SP faults with EC 0x26 under SCTLR_EL1.SA, before
        // any element; without SA the leaf, which checks it, stops.
        machine.cpu.state.sp = BASE + 0x8001;
        machine
            .cpu
            .registers
            .set(Register::SCTLR_EL1, 0, sctlr | SCTLR_SA);
        machine.derived_changed();
        assert_eq!(run(&mut machine, 4), Ok(()));
        assert_eq!(machine.cpu.read(Register::ESR_EL1), 0x26 << 26 | 1 << 25);
        machine
            .cpu
            .registers
            .set(Register::SCTLR_EL1, 0, sctlr & !SCTLR_SA);
        machine.derived_changed();
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.pc = BASE + 16;
        assert!(stop(&mut machine).contains("SCTLR_ELx.SA clear"));
    }
}

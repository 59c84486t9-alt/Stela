//! SVE and SME instructions that passed their access checks
//! (`machine::streaming`), run one at a time as context leaves of the shared
//! compiler (a `Features::LEAF | Features::CONTEXT` plan) on the PE's scalable
//! state (`crate::scalable`) at the streaming vector length. The leaf's
//! profile is the PE's mode (PSTATE.SM and ZA) and the chip's scalable
//! features the engine implements; leaves are cached by PC, word and profile
//! and discarded with the blocks. A leaf's memory accesses come back to the
//! engine one element at a time through the context's memory service
//! ([`serve`]), which translates and checks each as a plain data access,
//! with its watchpoints and, for a tag-checked form, its Tag Check
//! (`engine::tags`), and raises its exception after the leaf returns. A word that Arm's decode
//! makes UNDEFINED on the chip takes that, before its access checks
//! ([`Machine::scalable_undefined`]). What a leaf cannot run stops
//! explicitly: PSTATE.DIT set, whose timing the leaves do not keep. Numerical floating point, which
//! needs Arm's FP semantics, is completed in software
//! ([`Machine::scalable_numerical`]).
use super::{
    DeviceError, Devices, FETCH_PAGE, Fetched, Host, InstallError, Machine, NativeCode, RamTables,
    RequirementKind, Step, Stop, Translated, Variant, tags::TagCheck,
};
use crate::scalable::ScalableState;
use alloc::string::ToString;
use alloc::{format, string::String, vec::Vec};
use stela_compiler::{
    GuestAddress, GuestState, Options, TargetCpu,
    aarch64::{
        floating::features::NumericalFeatures,
        scalable::{
            ScalableMode, VectorLength,
            features::{ScalableFeature, ScalableFeatures},
            profile::ScalableControls,
        },
        sme::movement,
    },
    block::{
        BlockProfile, CompilationPlan, Features,
        scalable::{
            AdmittedScalableNumericalInstruction, admit_scalable_numerical_instruction,
            decode_scalable_numerical_instruction,
        },
    },
    context::{
        ExecutionContext,
        memory::{
            MEMORY_CONTEXT_BYTES, MEMORY_CONTEXT_VERSION, MemoryContextView, MemoryRequest,
            MemoryRequirements, MemoryStatus, SpAlignmentRequirement, flags, profile_requirements,
        },
    },
    scalable_context::ScalableProfile,
};
use {
    crate::machine::cpu::Exception, crate::machine::cpu::STREAMING_VECTOR_BYTES,
    crate::machine::debug, crate::machine::exception::Class, crate::machine::mmu,
    crate::machine::mmu::Access, crate::machine::mmu::MemoryType, crate::machine::mmu::alignment,
    crate::machine::streaming, crate::machine::streaming::VectorDestinations,
    crate::machine::system::File, stela_contracts::Feature,
};

/// The numerical features of every Apple chip's identification: no
/// FEAT_SME_FA64 (FullA64 off), FEAT_EBF16 or FEAT_RPRES.
const NUMERICAL_FEATURES: NumericalFeatures = NumericalFeatures::new(false, false, false);
/// RET X30, which ends a context leaf.
const RET_X30: u32 = 0xd65f_03c0;

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

/// The scalable features of the PE whose register file is `registers`
/// that the engine implements: an instruction of a feature it has but the
/// engine lacks fails to compile, and stops.
pub(crate) fn features(registers: &File) -> ScalableFeatures {
    features_where(|feature| registers.implemented(feature) == Ok(true))
}

/// The scalable features `keep` selects of [`FEATURES`].
fn features_where(keep: impl Fn(Feature) -> bool) -> ScalableFeatures {
    FEATURES
        .iter()
        .filter(|(feature, _)| keep(*feature))
        .fold(ScalableFeatures::empty(), |features, (_, scalable)| {
            features.with(*scalable)
        })
}

/// A scalable leaf cannot be prepared or installed for this PE.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PreparationError {
    MissingState,
    InvalidVectorLength,
    Compile(stela_compiler::CompileError),
    MissingMemoryRequirements,
    CodeArenaFull,
}
impl From<stela_compiler::CompileError> for PreparationError {
    fn from(error: stela_compiler::CompileError) -> Self {
        Self::Compile(error)
    }
}
impl core::fmt::Display for PreparationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingState => f.write_str("a PE without SME state"),
            Self::InvalidVectorLength => f.write_str("the streaming vector length"),
            Self::Compile(error) => error.fmt(f),
            Self::MissingMemoryRequirements => {
                f.write_str("a context leaf without memory requirements")
            }
            Self::CodeArenaFull => f.write_str("the leaf exceeds the code arena"),
        }
    }
}
impl core::error::Error for PreparationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Compile(error) => Some(error),
            _ => None,
        }
    }
}

/// What the engine runs an SVE or SME word as.
enum Prepared {
    Movprfx(Movprfx),
    Numerical(AdmittedScalableNumericalInstruction),
    Leaf(Leaf),
    /// UNDEFINED: the word needs a feature the chip lacks, or Debug state.
    Undefined,
}

/// MOVPRFX (unpredicated, and predicated with merging or zeroing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Movprfx {
    destination: u8,
    source: u8,
    /// The governing predicate, element bytes and merging.
    predicated: Option<(u8, usize, bool)>,
}

impl Movprfx {
    const UNPREDICATED_MASK: u32 = 0xffff_fc00;
    const UNPREDICATED: u32 = 0x0420_bc00;
    const PREDICATED_MASK: u32 = 0xff3e_e000;
    const PREDICATED: u32 = 0x0410_2000;

    fn decode(word: u32) -> Option<Self> {
        let (destination, source) = ((word & 0x1f) as u8, ((word >> 5) & 0x1f) as u8);
        let predicated = if word & Self::UNPREDICATED_MASK == Self::UNPREDICATED {
            None
        } else if word & Self::PREDICATED_MASK == Self::PREDICATED {
            let predicate = ((word >> 10) & 0b111) as u8;
            Some((predicate, 1 << ((word >> 22) & 0b11), word & 1 << 16 != 0))
        } else {
            return None;
        };
        Some(Self {
            destination,
            source,
            predicated,
        })
    }

    /// Arm's MOVPRFX: Zd = Zn, or for each element its active value,
    /// keeping (merging) or zeroing the inactive ones.
    fn apply(self, scalable: &mut ScalableState, state: &mut GuestState) -> anyhow::Result<()> {
        let mut result = [0u8; STREAMING_VECTOR_BYTES];
        scalable.read_z(state, self.source, &mut result)?;
        if let Some((predicate, element, merging)) = self.predicated {
            let mut mask = [0u8; STREAMING_VECTOR_BYTES / 8];
            scalable.read_predicate(predicate, &mut mask)?;
            let mut old = [0u8; STREAMING_VECTOR_BYTES];
            scalable.read_z(state, self.destination, &mut old)?;
            for (index, (new, old)) in result
                .chunks_mut(element)
                .zip(old.chunks(element))
                .enumerate()
            {
                let bit = index * element;
                if mask[bit / 8] & 1 << (bit % 8) == 0 {
                    if merging {
                        new.copy_from_slice(old);
                    } else {
                        new.fill(0);
                    }
                }
            }
        }
        scalable.write_z(state, self.destination, &result)
    }
}

/// What a PE's context leaf of `profile` compiles for.
fn leaf_options(profile: ScalableProfile, target: TargetCpu) -> Options {
    Options::new(
        BlockProfile::new(Features::LEAF | Features::CONTEXT),
        target,
    )
    .with_scalable(profile)
}

/// A context leaf's entry: the two-argument context ABI.
type Entry = unsafe extern "sysv64" fn(*mut GuestState, *mut ExecutionContext);

/// An installed leaf and what its memory accesses require of the PE.
#[derive(Debug, Clone, Copy)]
pub(super) struct Leaf {
    pub(super) code: NativeCode,
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
    // SAFETY: `machine` belongs to this call's service and is not otherwise borrowed while the leaf
    // runs.
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
            Err(error) => return refuse(self, &error.to_string()),
        };
        let leaf = match self.prepare_scalable(pc, word, profile) {
            Ok(Prepared::Movprfx(prefix)) => return self.movprfx(pc, word, prefix),
            Ok(Prepared::Numerical(admitted)) => return self.scalable_numerical(admitted),
            Ok(Prepared::Undefined) => {
                self.cpu.step_advance = false;
                return self.undefined();
            }
            Ok(Prepared::Leaf(leaf)) => leaf,
            Err(error) => return refuse(self, &error.to_string()),
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

    /// MOVPRFX on its own, as Arm permits it to run: the move it is,
    /// whatever follows (the follower then runs as the next instruction).
    fn movprfx(&mut self, pc: u64, word: u32, prefix: Movprfx) -> Step {
        self.completing(pc, |machine| {
            let Some(scalable) = machine.cpu.scalable.as_mut() else {
                return Err(machine.unsupported(RequirementKind::Instruction {
                    word,
                    detail: "a PE without SME state".into(),
                }));
            };
            if prefix.apply(scalable, &mut machine.cpu.state).is_err() {
                return Err(machine.unsupported(RequirementKind::Instruction {
                    word,
                    detail: "the streaming Z and P registers".into(),
                }));
            }
            machine.statistics.blocks += 1;
            machine.next()
        })
    }

    /// Run the scalar FP or SIMD&FP load or store `word` at `pc` in
    /// streaming mode: as a one-instruction block of the system-mode
    /// compiler, compiled apart from the blocks that end before it, after
    /// which the Z bits above 128 of each register it wrote are zero, as
    /// Arm's `V[]` makes them. An instruction that took an exception wrote
    /// none.
    pub(super) fn streaming_scalar(&mut self, pc: u64, word: u32) -> Step {
        let Some(VectorDestinations(destinations)) = streaming::vector_destinations(word) else {
            return Err(self.unsupported(RequirementKind::Instruction {
                word,
                detail: "scalar FP in streaming mode whose vector destinations are not known"
                    .into(),
            }));
        };
        let physical = match self.fetch_physical(pc) {
            Ok(physical) => physical,
            Err(Ok(exception)) => {
                self.cpu.step_advance = false;
                self.take(exception);
                return Ok(());
            }
            Err(Err(stop)) => return Err(stop),
        };
        let variant = Variant {
            fp: self.floating_point_enabled(),
            checks: self.memory_checks(),
            single: true,
            scalable: None,
            system: self.native_system(),
            guarded_page: self.fetch_guarded(pc),
            timing: self.cpu.pstate.dit && self.timing_target().is_some(),
            translated: false,
        };
        let variant = self.page_variant(variant, physical);
        let index = match self.index.get(&(pc, physical, variant)) {
            Some(&index) => index,
            None => match self.compile(pc, physical, variant)? {
                Fetched::Block(index) => index,
                Fetched::Exception(exception) => {
                    self.cpu.step_advance = false;
                    self.take(exception);
                    return Ok(());
                }
                Fetched::Checked(_) => {
                    return Err(self.unsupported(RequirementKind::Instruction {
                        word,
                        detail: "a streaming scalar FP block that ends before itself".into(),
                    }));
                }
            },
        };
        let exceptions = self.statistics.exceptions;
        self.execute(index, 0)?;
        if self.statistics.exceptions != exceptions {
            return Ok(());
        }
        let Some(scalable) = self.cpu.scalable.as_mut() else {
            return Ok(());
        };
        let zeroed = destinations.into_iter().flatten().try_for_each(|register| {
            let value = self.cpu.state.v[usize::from(register)];
            scalable.write_v(&mut self.cpu.state, register, value)
        });
        if zeroed.is_err() {
            return Err(self.unsupported(RequirementKind::Instruction {
                word,
                detail: "the streaming Z registers".into(),
            }));
        }
        Ok(())
    }

    /// Complete the numerical floating-point instruction `instruction` in
    /// software (`floating::scalable`), with FPCR's controls and FPSR's
    /// cumulative flags; in streaming mode without FEAT_SME_FA64 Arm's
    /// `FPProcessException` takes no FP trap, so none is.
    fn scalable_numerical(&mut self, admitted: AdmittedScalableNumericalInstruction) -> Step {
        let (pc, word) = (admitted.instruction_pc().0, admitted.word());
        let refuse = |machine: &Self, detail: String| {
            Err(machine.unsupported(RequirementKind::Instruction { word, detail }))
        };
        self.completing(pc, |machine| {
            let Some(scalable) = machine.cpu.scalable.as_mut() else {
                return refuse(machine, "a PE without SME state".into());
            };
            if let Err(error) =
                crate::floating::scalable::complete(&mut machine.cpu.state, scalable, &admitted)
            {
                return refuse(machine, format!("{error}"));
            }
            machine.statistics.blocks += 1;
            machine.next()
        })
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
            fault_access: 0,
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
                detail: error.to_string(),
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
        if request.flags & flags::TAG_CHECKED != 0 {
            match self.tag_check(&watched, requester, None) {
                Ok(TagCheck::Failed(exception)) => {
                    return Err(Failure::Exception(MemoryStatus::TagCheck, exception));
                }
                Ok(TagCheck::Passed | TagCheck::Untranslated) => {}
                Err(stop) => return Err(Failure::Stop(MemoryStatus::Unsupported, stop)),
            }
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

    /// What `word` at `pc` runs as under `profile`, compiling its leaf.
    fn prepare_scalable(
        &mut self,
        pc: u64,
        word: u32,
        profile: ScalableProfile,
    ) -> Result<Prepared, PreparationError> {
        if let Some(prefix) = Movprfx::decode(word) {
            return Ok(Prepared::Movprfx(prefix));
        }
        let result = match decode_scalable_numerical_instruction(GuestAddress(pc), word)
            .map_err(PreparationError::from)?
        {
            Some(instruction) => {
                admit_scalable_numerical_instruction(instruction, profile, NUMERICAL_FEATURES)
                    .map(Prepared::Numerical)
                    .map_err(PreparationError::from)
            }
            None => self.scalable_leaf(pc, word, profile).map(Prepared::Leaf),
        };
        match result {
            Err(_) if self.scalable_undefined(pc, word) => Ok(Prepared::Undefined),
            result => result,
        }
    }

    /// Whether the SVE or SME word `word` at `pc` decodes as UNDEFINED on
    /// this chip, which Arm's decode raises before any access check, in any
    /// mode: MOVT between ZT0 and a general-purpose register, defined only
    /// in Debug state, which this engine never enters (as the System
    /// instructions of Debug state), and a word that compiles with every
    /// scalable feature but not with those the chip has, engine-implemented
    /// or not, so that `IsFeatureImplemented` fails, such as BFADD inside
    /// the M4's FADD encoding.
    pub(super) fn scalable_undefined(&self, pc: u64, word: u32) -> bool {
        if movement::decode(word).is_some_and(|operand| operand.requirements.halted) {
            return true;
        }
        let Some(length) = VectorLength::from_bytes(STREAMING_VECTOR_BYTES) else {
            return false;
        };
        let chip = self.profile.chip;
        let compiles = |features: ScalableFeatures| {
            let controls = ScalableControls::new(length, features.contains(ScalableFeature::Sme2));
            let Ok(profile) = ScalableProfile::new_with_features(
                length,
                ScalableMode::new(true, true),
                features,
                controls,
            ) else {
                return false;
            };
            match decode_scalable_numerical_instruction(GuestAddress(pc), word) {
                Ok(Some(instruction)) => {
                    admit_scalable_numerical_instruction(instruction, profile, NUMERICAL_FEATURES)
                        .is_ok()
                }
                Ok(None) => {
                    let source: Vec<u8> = [word, RET_X30]
                        .iter()
                        .flat_map(|word| word.to_le_bytes())
                        .collect();
                    let options = leaf_options(profile, self.target);
                    stela_compiler::compile(&source, GuestAddress(pc), &options).is_ok()
                }
                Err(_) => false,
            }
        };
        compiles(features_where(|_| true)) && !compiles(features_where(|f| f.on(chip)))
    }

    /// The profile of the PE's current scalable state.
    fn scalable_profile(&self) -> Result<ScalableProfile, PreparationError> {
        let scalable = self
            .cpu
            .scalable
            .as_ref()
            .ok_or(PreparationError::MissingState)?;
        let features = features(&self.cpu.registers);
        let length = VectorLength::from_bytes(STREAMING_VECTOR_BYTES)
            .ok_or(PreparationError::InvalidVectorLength)?;
        // The FP8 forms read FPMR, which the PE reaches once their
        // CheckFPMREnabled passes.
        let controls = ScalableControls::new(length, features.contains(ScalableFeature::Sme2))
            .with_fpmr_enabled(streaming::fpmr_enabled(&self.cpu));
        ScalableProfile::new_with_features(length, scalable.mode(), features, controls)
            .map_err(PreparationError::from)
    }

    /// The installed leaf of `word` at `pc` for `profile`, compiling it on
    /// first use.
    fn scalable_leaf(
        &mut self,
        pc: u64,
        word: u32,
        profile: ScalableProfile,
    ) -> Result<Leaf, PreparationError> {
        if let Some(leaf) = self.scalable_leaves.get(&(pc, word, profile)) {
            return Ok(*leaf);
        }
        let source: Vec<u8> = [word, RET_X30]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        let plan = CompilationPlan::new(
            &source,
            GuestAddress(pc),
            &leaf_options(profile, self.target),
        )
        .map_err(PreparationError::from)?;
        let memory = plan
            .memory_requirements()
            .ok_or(PreparationError::MissingMemoryRequirements)?;
        let compiled = plan.compile().map_err(PreparationError::from)?;
        let native = &compiled.native.x86_64_code;
        let code = match self.host.install(native) {
            Ok(code) => code,
            Err(InstallError::Full) => {
                self.reclaim_code();
                self.host
                    .install(native)
                    .map_err(|_| PreparationError::CodeArenaFull)?
            }
        };
        self.statistics.compiled += 1;
        let leaf = Leaf { code, memory };
        self.scalable_leaves.insert((pc, word, profile), leaf);
        Ok(leaf)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        NativeExit, NoDevices, Stop,
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
    /// HCRX_EL2.EnFPM: FPMR at EL0 and EL1 outside the host.
    const HCRX_ENFPM: u64 = 1 << 23;

    /// A PE of the test chip at EL1 with FP, SVE and SME enabled, in
    /// streaming mode with ZA, running `words` from BASE; `None` on a chip
    /// without SME.
    fn streaming(words: &[u32]) -> Option<TestMachine> {
        let mut machine = machine(words);
        machine.cpu.scalable.as_ref()?;
        enable_streaming(&mut machine);
        Some(machine)
    }

    /// Enable FP, SVE and SME at EL1 (vectors at 0x1_0000), and enter
    /// streaming mode with ZA at BASE.
    fn enable_streaming(machine: &mut TestMachine) {
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
    fn scalable_floating_point_follows_fpcr_and_sets_fpsr_without_trapping() {
        const PTRUE_P0_S: u32 = 0x2598_e3e0; // ptrue p0.s
        const FDUP_Z0_1: u32 = 0x25b9_ce00; // fdup z0.s, #1.0
        const FDUP_Z1_2: u32 = 0x25b9_c001; // fdup z1.s, #2.0
        const FADD_Z0_Z1: u32 = 0x6580_8020; // fadd z0.s, p0/m, z0.s, z1.s
        const DUP_Z1_0: u32 = 0x25b8_c001; // dup z1.s, #0
        const FDIV_Z0_Z1: u32 = 0x658d_8020; // fdiv z0.s, p0/m, z0.s, z1.s
        const FPCR_DZE: u32 = 1 << 9;
        const FPSR_DZC: u32 = 1 << 1;
        const FMOPA_ZA0_Z0_Z1: u32 = 0x8081_0000; // fmopa za0.s, p0/m, p0/m, z0.s, z1.s
        let words = [
            PTRUE_P0_S,
            FDUP_Z0_1,
            FDUP_Z1_2,
            FADD_Z0_Z1,
            DUP_Z1_0,
            FDIV_Z0_Z1,
            FDUP_Z0_1,
            FDUP_Z1_2,
            FMOPA_ZA0_Z0_Z1,
        ];
        let Some(mut machine) = streaming(&words) else {
            return;
        };
        // Divide-by-zero trapping enabled: streaming mode without FA64
        // ignores it and only accumulates DZC.
        machine.cpu.state.fpcr = FPCR_DZE;
        machine.cpu.state.fpsr = 0;
        for index in 0..4 {
            assert_eq!(machine.step(), Ok(()), "{index}");
        }
        let lanes = |machine: &TestMachine| -> Vec<u32> {
            z(machine, 0)
                .chunks(4)
                .map(|lane| u32::from_le_bytes(lane.try_into().unwrap()))
                .collect()
        };
        assert_eq!(lanes(&machine), [3.0f32.to_bits(); 16]);
        assert_eq!(machine.cpu.state.fpsr, 0);
        for index in 4..6 {
            assert_eq!(machine.step(), Ok(()), "{index}");
        }
        assert_eq!(lanes(&machine), [f32::INFINITY.to_bits(); 16]);
        assert_eq!(machine.cpu.state.fpsr, FPSR_DZC);
        // The outer product of ones and twos: row 0 of ZA0.S is ZA's first
        // array vector.
        for index in 6..9 {
            assert_eq!(machine.step(), Ok(()), "{index}");
        }
        let mut row = [0u8; STREAMING_VECTOR_BYTES];
        let scalable = machine.cpu.scalable.as_ref().unwrap();
        scalable.read_za(0, &mut row).unwrap();
        assert!(
            row.chunks(4)
                .all(|lane| lane == 2.0f32.to_bits().to_le_bytes())
        );
        assert_eq!(machine.cpu.pc, BASE + 36);
    }

    #[test]
    fn streaming_scalar_fp_runs_as_a_block_and_zeroes_the_upper_z_bits_it_writes() {
        const FADD_S7: u32 = 0x1e22_2827; // fadd s7, s1, s2
        const FCMP_S1_S2: u32 = 0x1e22_2020; // fcmp s1, s2
        let Some(mut machine) = streaming(&[FADD_S7, FCMP_S1_S2]) else {
            return;
        };
        // Z0 to Z7 all ones.
        let ones = alloc::vec![0xff; STREAMING_VECTOR_BYTES];
        for register in 0..8 {
            let scalable = machine.cpu.scalable.as_mut().unwrap();
            scalable
                .write_z(&mut machine.cpu.state, register, &ones)
                .unwrap();
        }
        // The unit-test host runs no native block: it reports the
        // fallthrough the FADD's block takes.
        let fallthrough = |pc: u64| NativeExit::Exit {
            next_pc: pc,
            kind: stela_compiler::block::ExitKind::Fallthrough as u64,
        };
        machine.host.exits.push(fallthrough(BASE + 4));
        assert_eq!(machine.step(), Ok(()));
        assert_eq!(machine.cpu.pc, BASE + 4);
        // S7's Z bits above 128 are zero; the other registers keep theirs.
        let mut upper_zero = ones.clone();
        upper_zero[16..].fill(0);
        assert_eq!(z(&machine, 7), upper_zero);
        assert_eq!(z(&machine, 1), ones);
        // FCMP writes no vector register.
        machine.host.exits.push(fallthrough(BASE + 8));
        assert_eq!(machine.step(), Ok(()));
        assert_eq!((z(&machine, 1), z(&machine, 2)), (ones.clone(), ones));
        // Outside streaming mode the FADD is part of an ordinary block.
        machine.cpu.set_svcr(false, false).unwrap();
        machine.cpu.pc = BASE;
        let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
            panic!("an ordinary block")
        };
        let map = &machine.blocks[index].source_map;
        assert_eq!((map[0].0, map[1].0), (BASE, BASE + 4));
    }

    #[test]
    fn movprfx_runs_as_its_move_and_its_follower_after_it() {
        const PTRUE_P1_S_VL2: u32 = 0x2598_e041; // ptrue p1.s, vl2
        const MOVPRFX_Z3_Z1: u32 = 0x0420_bc23; // movprfx z3, z1
        const MOVPRFX_Z4_P1Z_Z1: u32 = 0x0490_2424; // movprfx z4.s, p1/z, z1.s
        const MOVPRFX_Z5_P1M_Z1: u32 = 0x0491_2425; // movprfx z5.s, p1/m, z1.s
        const MOVPRFX_Z6_Z1: u32 = 0x0420_bc26; // movprfx z6, z1
        const ADD_Z6_P0M_Z2: u32 = 0x0400_0046; // add z6.b, p0/m, z6.b, z2.b
        let words = [
            PTRUE_P0_B,
            PTRUE_P1_S_VL2,
            INDEX_Z1_0_1,
            INDEX_Z2_3_0,
            MOVPRFX_Z3_Z1,
            MOVPRFX_Z4_P1Z_Z1,
            MOVPRFX_Z5_P1M_Z1,
            MOVPRFX_Z6_Z1,
            ADD_Z6_P0M_Z2,
        ];
        let Some(mut machine) = streaming(&words) else {
            return;
        };
        let ones = alloc::vec![0xff; STREAMING_VECTOR_BYTES];
        let scalable = machine.cpu.scalable.as_mut().unwrap();
        for register in [4, 5] {
            scalable
                .write_z(&mut machine.cpu.state, register, &ones)
                .unwrap();
        }
        for index in 0..words.len() as u64 {
            assert_eq!(machine.step(), Ok(()), "{index}");
            assert_eq!(machine.cpu.pc, BASE + 4 * (index + 1));
        }
        let counted: Vec<u8> = (0..STREAMING_VECTOR_BYTES as u8).collect();
        assert_eq!(z(&machine, 3), counted);
        // VL2 makes the first two words active.
        let mut zeroed = counted.clone();
        zeroed[8..].fill(0);
        assert_eq!(z(&machine, 4), zeroed);
        let mut merged = ones.clone();
        merged[..8].copy_from_slice(&counted[..8]);
        assert_eq!(z(&machine, 5), merged);
        let added: Vec<u8> = (3..3 + STREAMING_VECTOR_BYTES as u8).collect();
        assert_eq!(z(&machine, 6), added);
    }

    /// Every SVE and SME form of the M4, M5 and M6 that runs through
    /// [`Machine::prepare_scalable`], its operand fields filled in 24 ways,
    /// in each mode its access checks allow: each form has a filling that
    /// runs or decodes as UNDEFINED, and no filling stops for a feature, the
    /// M6's FPMR-checked FP8 forms included. Scalar FP, Advanced SIMD and
    /// non-streaming SVE forms take other paths. The other fillings decline
    /// the reserved encodings they hit.
    #[test]
    fn every_sve_and_sme_form_of_the_sme_chips_runs_or_is_undefined() {
        use {stela_contracts::Chip, stela_contracts::chip::Check};
        // BFSCALE, of FEAT_SVE_BFSCALE, which no Apple chip has, lies inside
        // FSCALE's encodings, and the compiler declines it as unknown: the
        // SVE form, and the multi-vector forms, FSCALE's with size 0.
        const FSCALE: [u32; 4] = [0xc120_a180, 0xc120_a980, 0xc120_b180, 0xc120_b980];
        const SIZE: u32 = 0b11 << 22;
        const BFSCALE: (u32, u32) = (0xffff_e000, 0x6509_8000);
        let mut runs = 0;
        let mut undefined = 0;
        for chip in [Chip::AppleM4, Chip::AppleM5, Chip::AppleM6] {
            let mut machine = super::super::tests::machine_on(chip, &[]);
            machine.target = stela_compiler::TargetCpu::detect();
            // HCRX_EL2.EnFPM gives EL1 FPMR, for the M6's FP8 forms.
            machine.cpu.registers.set(Register::HCRX_EL2, 0, HCRX_ENFPM);
            for (mask, value, checks) in chip.check_forms() {
                if checks.iter().any(|check| {
                    matches!(check, Check::Fp | Check::FpAdvSimd | Check::NonStreamingSve)
                }) {
                    continue;
                }
                let known = (mask, value) == BFSCALE
                    || FSCALE.contains(&value) && mask & SIZE == SIZE && value & SIZE == 0;
                let streaming_only = checks.iter().any(|check| {
                    matches!(
                        check,
                        Check::Sve | Check::StreamingSve | Check::StreamingSveAndZa
                    )
                });
                for streaming in [true, false] {
                    if !streaming && streaming_only {
                        continue;
                    }
                    machine.cpu.set_svcr(streaming, true).unwrap();
                    let profile = machine.scalable_profile().unwrap();
                    let (mut tried, mut handled) = (false, false);
                    let mut declined = alloc::string::String::new();
                    let mut seed = value ^ 0x9e37_79b9;
                    for _ in 0..24 {
                        seed ^= seed << 13;
                        seed ^= seed >> 17;
                        seed ^= seed << 5;
                        let word = value | (seed & !mask);
                        if chip.admit(word) != word || chip.checks(word) != checks {
                            continue;
                        }
                        tried = true;
                        match machine.prepare_scalable(BASE, word, profile) {
                            Ok(Prepared::Undefined) => {
                                handled = true;
                                undefined += 1;
                            }
                            Ok(_) => {
                                handled = true;
                                runs += 1;
                            }
                            Err(error) => {
                                assert!(
                                    known || !matches!(&error, PreparationError::Compile(stela_compiler::CompileError {
                                        kind: stela_compiler::CompileErrorKind::GuestFeaturesUnavailable { .. },
                                        ..
                                    })),
                                    "{chip:?} {word:#010x}: {error}"
                                );
                                declined = error.to_string();
                            }
                        }
                    }
                    assert!(
                        !tried || handled || known,
                        "{chip:?} streaming {streaming}: {value:#010x} under {mask:#010x}: {declined}"
                    );
                }
            }
        }
        assert!(runs > 25_000 && undefined > 1_000, "{runs} {undefined}");
    }

    #[test]
    fn features_the_chip_lacks_and_debug_state_movt_are_undefined_before_their_checks() {
        use stela_contracts::Chip;
        const BFADD_Z0_Z1: u32 = 0x6500_8020; // bfadd z0.h, p0/m, z0.h, z1.h
        const MOVT_X0_ZT0: u32 = 0xc04c_03e0; // movt x0, zt0[0]
        const UNDEFINED: u64 = 1 << 25;
        let on = |chip, word| {
            let mut machine = super::super::tests::machine_on(chip, &[PTRUE_P0_B, word]);
            enable_streaming(&mut machine);
            machine.step().unwrap();
            machine
        };
        // The M4 lacks FEAT_SVE_B16B16: BFADD is UNDEFINED, also with SME
        // disabled, where it would otherwise trap; the M5 runs it.
        let mut m4 = on(Chip::AppleM4, BFADD_Z0_Z1);
        assert_eq!(m4.step(), Ok(()));
        assert_eq!(m4.cpu.read(Register::ESR_EL1), UNDEFINED);
        assert_eq!(m4.cpu.read(Register::ELR_EL1), BASE + 4);
        let mut m5 = on(Chip::AppleM5, BFADD_Z0_Z1);
        assert_eq!(m5.step(), Ok(()));
        assert_eq!(m5.cpu.pc, BASE + 8);
        for (chip, word) in [(Chip::AppleM4, BFADD_Z0_Z1), (Chip::AppleM5, MOVT_X0_ZT0)] {
            let mut machine = on(chip, word);
            for register in [Register::CPACR_EL1, Register::CPTR_EL2] {
                machine.cpu.registers.set(register, 0, 0);
            }
            machine.derived_changed();
            assert_eq!(machine.step(), Ok(()), "{chip:?}");
            assert_eq!(machine.cpu.read(Register::ESR_EL1), UNDEFINED, "{chip:?}");
        }
        // MOVT between ZT0 and an X register exists only in Debug state.
        let mut m6 = on(Chip::AppleM6, MOVT_X0_ZT0);
        assert_eq!(m6.step(), Ok(()));
        assert_eq!(m6.cpu.read(Register::ESR_EL1), UNDEFINED);
        assert_eq!(m6.cpu.read(Register::ELR_EL1), BASE + 4);
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

    /// The M6's FP8 SME forms run under FPMR's formats once
    /// CheckFPMREnabled passes: the FP8 to FP16 (FEAT_SME_F8F16) and FP32
    /// (FEAT_SME_F8F32) outer products, FSCALE (multiple vectors) and the
    /// multi-vector FP8 conversions.
    #[test]
    fn the_m6_fp8_sme_forms_run_under_fpmr() {
        const PTRUE_P1_B: u32 = 0x2518_e3e1; // ptrue p1.b
        const DUP_Z0: u32 = 0x2538_c700; // mov z0.b, #0x38
        const DUP_Z1: u32 = 0x2538_c701; // mov z1.b, #0x38
        const FMOPA_ZA0_H: u32 = 0x80a1_2008; // fmopa za0.h, p0/m, p1/m, z0.b, z1.b
        const FMOPA_ZA1_S: u32 = 0x80a1_2001; // fmopa za1.s, p0/m, p1/m, z0.b, z1.b
        const MOVA_Z3_ZA0H_H: u32 = 0xc042_0003; // mov z3.h, p0/m, za0h.h[w12, 0]
        const MOVA_Z4_ZA1H_S: u32 = 0xc082_0084; // mov z4.s, p0/m, za1h.s[w12, 0]
        const DUP_Z6_3: u32 = 0x25b8_c066; // mov z6.s, #3
        const FSCALE: u32 = 0xc1a6_a184; // fscale {z4.s, z5.s}, {z4.s, z5.s}, z6.s
        const F1CVT: u32 = 0xc126_e006; // f1cvt {z6.h, z7.h}, z0.b
        // F8S1 and F8S2 E4M3, whose 0x38 is 1.0.
        const E4M3: u64 = 1 | 1 << 3;
        let words = [
            PTRUE_P0_B,
            PTRUE_P1_B,
            DUP_Z0,
            DUP_Z1,
            ZERO_ZA,
            FMOPA_ZA0_H,
            FMOPA_ZA1_S,
            MOVA_Z3_ZA0H_H,
            MOVA_Z4_ZA1H_S,
            DUP_Z6_3,
            FSCALE,
            F1CVT,
        ];
        let mut machine = super::super::tests::machine_on(stela_contracts::Chip::AppleM6, &words);
        enable_streaming(&mut machine);
        for _ in 0..5 {
            machine.step().unwrap();
        }
        // HCRX_EL2.EnFPM clear makes them UNDEFINED at EL1.
        assert_eq!(machine.step(), Ok(()));
        assert_eq!(
            (
                machine.cpu.read(Register::ESR_EL1),
                machine.cpu.read(Register::ELR_EL1)
            ),
            (1 << 25, BASE + 20)
        );
        machine.cpu.registers.set(Register::HCRX_EL2, 0, HCRX_ENFPM);
        machine.derived_changed();
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.scalable.as_mut().unwrap().set_fpmr(E4M3);
        machine.cpu.pc = BASE + 20;
        for index in 5..words.len() as u64 {
            assert_eq!(machine.step(), Ok(()), "{index}");
            assert_eq!(machine.cpu.pc, BASE + 4 * (index + 1), "{index}");
        }
        let repeat = |bytes: &[u8]| -> Vec<u8> {
            bytes
                .iter()
                .copied()
                .cycle()
                .take(STREAMING_VECTOR_BYTES)
                .collect()
        };
        // Two products of 1.0 make each half 2.0, and four each single 4.0,
        // which FSCALE takes to 32.0 (Z5, zero, stays zero); F1CVT widens
        // E4M3 1.0 to half 1.0.
        assert_eq!(z(&machine, 3), repeat(&0x4000u16.to_le_bytes()));
        assert_eq!(z(&machine, 4), repeat(&32.0f32.to_le_bytes()));
        assert_eq!(z(&machine, 5), repeat(&[0]));
        assert_eq!(z(&machine, 6), repeat(&0x3c00u16.to_le_bytes()));
        assert_eq!(z(&machine, 7), repeat(&0x3c00u16.to_le_bytes()));
    }

    /// On the M5 and M6, with tag checks on, each element of a tag-checked
    /// SVE access is checked against its granule's Allocation Tag.
    #[test]
    fn tag_checked_scalable_accesses_take_tag_check_faults_by_element() {
        const LD1B_Z2_X5: u32 = 0xa400_a0a2; // ld1b {z2.b}, p0/z, [x5]
        const TAGGED: u64 = 0xf0;
        const HCR_ATA: u64 = 1 << 56;
        const SCTLR_ATA_TCF_SYNC: u64 = 1 << 43 | 1 << 40;
        const TCR_TBI0: u64 = 1 << 37;
        for chip in [
            stela_contracts::Chip::AppleM5,
            stela_contracts::Chip::AppleM6,
        ] {
            let mut machine = super::super::tests::machine_on(chip, &[PTRUE_P0_B, LD1B_Z2_X5]);
            enable_streaming(&mut machine);
            normal_memory(&mut machine, false);
            machine.cpu.registers.set(Register::MAIR_EL1, 0, TAGGED);
            for (register, set) in [
                (Register::HCR_EL2, HCR_ATA),
                (Register::SCTLR_EL1, SCTLR_ATA_TCF_SYNC),
                (Register::TCR_EL1, TCR_TBI0),
            ] {
                let value = machine.cpu.read(register) | set;
                machine.cpu.registers.set(register, 0, value);
            }
            machine.translations_changed();
            let data = BASE + 0x8000;
            for offset in (0..STREAMING_VECTOR_BYTES as u64).step_by(16) {
                machine
                    .tags
                    .set(data + offset, if offset == 16 { 0xb } else { 0xa });
            }
            machine.step().unwrap();
            // The second granule's first element mismatches.
            let pointer = 0xa << 56 | data;
            machine.cpu.state.x[5] = pointer;
            machine.cpu.pc = BASE + 4;
            assert_eq!(machine.step(), Ok(()));
            assert_eq!(
                (
                    machine.cpu.read(Register::ESR_EL1),
                    machine.cpu.read(Register::FAR_EL1),
                    machine.cpu.read(Register::ELR_EL1),
                ),
                (0x25 << 26 | 1 << 25 | 0b01_0001, pointer + 16, BASE + 4)
            );
            // With every tag matching the load completes.
            machine.tags.set(data + 16, 0xa);
            machine.cpu.set_pstate(Pstate::reset(1));
            machine.cpu.set_svcr(true, true).unwrap();
            machine.cpu.pc = BASE + 4;
            assert_eq!(machine.step(), Ok(()));
            assert_eq!(machine.cpu.pc, BASE + 8);
        }
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

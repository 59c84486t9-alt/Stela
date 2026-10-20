//! SVE and SME instructions that passed their access checks
//! (`machine::streaming`), run one at a time as context leaves of the shared
//! compiler (`stela_compiler::extended::prepare_leaf`) on the PE's scalable
//! state (`crate::scalable`) at the streaming vector length. The leaf's
//! profile is the PE's mode (PSTATE.SM and ZA) and the chip's scalable
//! features the engine implements; leaves are cached by PC, word and profile
//! and discarded with the blocks. What a leaf cannot run stops explicitly:
//! memory accesses, numerical floating point, and PSTATE.DIT set, whose
//! timing the leaves do not keep.
use super::{Devices, Host, InstallError, Machine, NativeCode, RequirementKind, Step};
use crate::machine::{Chip, cpu::STREAMING_VECTOR_BYTES, system::Feature};
use alloc::{string::String, vec::Vec};
use stela_compiler::{
    GuestAddress,
    aarch64::scalable::{
        VectorLength,
        execution::GuestMemoryQuantity,
        features::{ScalableFeature, ScalableFeatures},
        profile::ScalableControls,
    },
    context::ExecutionContext,
    extended::{self, ScalableProfile},
};

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

impl<H: Host, D: Devices> Machine<H, D> {
    /// Run the SVE or SME instruction `word` at `pc`, whose access checks
    /// passed.
    pub(super) fn scalable_instruction(&mut self, pc: u64, word: u32) -> Step {
        let refuse = |machine: &Self, detail: String| {
            Err(machine.unsupported(RequirementKind::Instruction { word, detail }))
        };
        // Version 2 profiles require PSTATE.DIT clear: the leaves are not
        // compiled for data-independent timing.
        if self.cpu.pstate.dit {
            return refuse(
                self,
                "SVE and SME instructions with PSTATE.DIT set are not run by the system engine"
                    .into(),
            );
        }
        let profile = match self.scalable_profile() {
            Ok(profile) => profile,
            Err(detail) => return refuse(self, detail),
        };
        let code = match self.scalable_leaf(pc, word, profile) {
            Ok(code) => code,
            Err(detail) => return refuse(self, detail),
        };
        self.completing(pc, |machine| {
            let Some(scalable) = machine.cpu.scalable.as_mut() else {
                return refuse(machine, "a PE without SME state".into());
            };
            let (host, state) = (&mut machine.host, &mut machine.cpu.state);
            // SAFETY: the view lends the PE's own register buffers for this
            // one call, which the leaf compiled for `profile` reaches only
            // through it; the leaf has no memory access and keeps no pointer.
            let called = unsafe {
                scalable.with_view(|view| {
                    let mut context = ExecutionContext {
                        scalable: view,
                        ..ExecutionContext::default()
                    };
                    profile
                        .validate_view(&context, view)
                        .map_err(|error| error.0)?;
                    Ok::<_, String>(host.call_context(code, state, &mut context))
                })
            };
            match called {
                Ok(true) => {}
                Ok(false) => {
                    return refuse(
                        machine,
                        "this host does not run the context leaves of SVE and SME instructions"
                            .into(),
                    );
                }
                Err(detail) => return refuse(machine, detail),
            }
            machine.statistics.blocks += 1;
            machine.next()
        })
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
    ) -> Result<NativeCode, String> {
        if let Some(code) = self.scalable_leaves.get(&(pc, word, profile)) {
            return Ok(*code);
        }
        let source: Vec<u8> = [word, RET_X30]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        let prepared = extended::prepare_leaf(&source, GuestAddress(pc), profile, self.target)
            .map_err(|error| error.0)?;
        // The engine applied the access checks AARCHMRS gives the word
        // (`Chip::checks`) before compiling it.
        let instruction = &prepared.execution_requirements.instructions()[0];
        if matches!(
            instruction.guest_memory_quantity(),
            GuestMemoryQuantity::Maximum(_)
        ) || prepared.memory_requirements != Default::default()
        {
            return Err("SVE and SME memory accesses are not run by the system engine".into());
        }
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
        self.scalable_leaves.insert((pc, word, profile), code);
        Ok(code)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        NoDevices, Stop,
        tests::{BASE, FakeHost, machine},
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
    const LD1B_Z1_X5: u32 = 0xa400_a0a1; // ld1b {z1.b}, p0/z, [x5]

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
    fn scalable_memory_accesses_and_dit_stop_explicitly() {
        let Some(mut machine) = streaming(&[LD1B_Z1_X5, ADD_Z0_Z1_Z2]) else {
            return;
        };
        let stop = |machine: &mut TestMachine| match machine.step() {
            Err(Stop::Unsupported(requirement)) => alloc::format!("{:?}", requirement.kind),
            other => panic!("{other:?}"),
        };
        assert!(stop(&mut machine).contains("memory accesses"));
        assert_eq!(machine.cpu.pc, BASE);
        machine.cpu.pc = BASE + 4;
        machine.cpu.pstate.dit = true;
        assert!(stop(&mut machine).contains("PSTATE.DIT"));
        assert_eq!(machine.cpu.pc, BASE + 4);
    }
}

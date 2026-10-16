//! Retained original register/PSTATE successes; component effects, not PE entry.
use super::*;
use crate::system::{
    access::{ExceptionLevel, Profile, SecurityState},
    pstate::{Controls, Features, MteFeature, SsbsFeature, ThreadIdTrapBits},
    state::{El1Registers, StackBank},
};
use anyhow::{Context as _, Result, ensure};
use serde_json::Value;
use std::path::{Path, PathBuf};
use stela_compiler::{
    GuestAddress, TargetCpu,
    block::{BlockProfile, CompilationPlan, ExitKind},
};

const ORIGINAL_RECEIPT_SHA256: &str =
    "ddb40c944296b03f925118a42004885b4cb367ec8b31111bd30ed68044ea37e0";
const POSITIVE_CASES: [u64; 19] = [
    0, 1, 2, 3, 4, 5, 6, 7, 22, 23, 26, 27, 28, 29, 33, 34, 35, 37, 38,
];
const STATE_BYTES: usize = std::mem::size_of::<GuestState>();
const REGISTER_LIMIT: u8 = 31;
// Literal positions in the immutable original observer's model-input protocol.
const SOURCE_EL_INDEX: usize = 8;
const SOURCE_UMA_INDEX: usize = 9;
const PFR0_INDEX: usize = 16;
const PFR1_INDEX: usize = 17;
const MMFR0_INDEX: usize = 18;
const MMFR1_INDEX: usize = 19;
const MMFR2_INDEX: usize = 20;

fn state(bytes: &[u8]) -> Result<GuestState> {
    ensure!(bytes.len() == STATE_BYTES);
    let mut value = GuestState::default();
    // SAFETY: The complete repr(C) storage consists only of integer fields;
    // exactly STATE_BYTES initialized bytes replace its fully initialized value.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (&mut value as *mut GuestState).cast(),
            STATE_BYTES,
        )
    };
    Ok(value)
}
fn frame(value: &GuestState) -> &[u8] {
    // SAFETY: GuestState has the checked784-byte initialized repr(C) layout.
    unsafe { std::slice::from_raw_parts((value as *const GuestState).cast(), STATE_BYTES) }
}
fn unhex(value: &str) -> Result<Vec<u8>> {
    ensure!(
        value.is_ascii() && value.len().is_multiple_of(2),
        "invalid original hex bytes"
    );
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).map_err(Into::into))
        .collect()
}
fn raw(observation: &Value, name: &str) -> Result<u64> {
    let value = unhex(
        observation["raw_register_hex"][name]
            .as_str()
            .context("raw register")?,
    )?;
    Ok(u64::from_le_bytes(
        value
            .try_into()
            .map_err(|_| anyhow::anyhow!("register width"))?,
    ))
}
fn context(values: &[Value]) -> Result<Context> {
    let value = |n: usize| values[n].as_u64().context("original model control");
    let pfr0 = value(PFR0_INDEX)?;
    let pfr1 = value(PFR1_INDEX)?;
    let mmfr0 = value(MMFR0_INDEX)?;
    let mmfr1 = value(MMFR1_INDEX)?;
    let mmfr2 = value(MMFR2_INDEX)?;
    let no_traps = ThreadIdTrapBits {
        el0: false,
        read_only_el0: false,
        el1: false,
    };
    Ok(Context {
        profile: Profile {
            current_el: if value(SOURCE_EL_INDEX)? == 0 {
                ExceptionLevel::El0
            } else {
                ExceptionLevel::El1
            },
            security: SecurityState::NonSecure,
            el2_enabled: false,
            el3_present: false,
        },
        features: Features {
            aa64: matches!(pfr0 & 15, 1 | 2) && matches!((pfr0 >> 4) & 15, 1 | 2),
            pan: matches!((mmfr1 >> 20) & 15, 1..=3),
            uao: (mmfr2 >> 4) & 15 == 1,
            dit: (pfr0 >> 48) & 15 == 1,
            ssbs: match (pfr1 >> 4) & 15 {
                0 => SsbsFeature::Absent,
                1 => SsbsFeature::ImmediateOnly,
                2 => SsbsFeature::ReadWrite,
                _ => anyhow::bail!("reserved SSBS"),
            },
            mte: match (pfr1 >> 8) & 15 {
                0 => MteFeature::Absent,
                1 => MteFeature::One {
                    register_raz_wi: true,
                    immediate_ignored: true,
                },
                2 | 3 => MteFeature::TwoOrLater,
                _ => anyhow::bail!("reserved MTE"),
            },
            fine_grained_traps: matches!((mmfr0 >> 56) & 15, 1 | 2),
        },
        controls: Controls {
            el0_in_host: false,
            sctlr_el1_uma: value(SOURCE_UMA_INDEX)? != 0,
            hcr_el2_tge: false,
            effective_hcr_el2_nvx: 0,
            scr_el3_fgt_enable: false,
            thread_id_read_traps: no_traps,
            thread_id_write_traps: no_traps,
        },
    })
}

#[test]
#[ignore = "requires retained exact original register corpus and explicit native component invocation"]
fn retained_original_register_pstate_effects_match_current_native_boundaries() -> Result<()> {
    let input = PathBuf::from(
        std::env::var_os("STELA_REGISTER_ORIGINAL_RECEIPT").context("retained original receipt")?,
    );
    let bytes = std::fs::read(&input)?;
    ensure!(stela_core::sha256(&bytes) == ORIGINAL_RECEIPT_SHA256);
    let cohort: Value = serde_json::from_slice(&bytes)?;
    ensure!(cohort["cases"] == 40);
    let output = PathBuf::from(
        std::env::var_os("STELA_REGISTER_NATIVE_OUTPUT").context("fresh native output")?,
    );
    ensure!(output.is_absolute() && !output.exists());
    std::fs::create_dir_all(&output)?;
    let mut records = Vec::new();
    for index in POSITIVE_CASES {
        let row = &cohort["records"][usize::try_from(index)?];
        ensure!(row["case"] == index && row["passed"] == true);
        let path = Path::new(row["receipt"]["path"].as_str().context("original path")?);
        let data = std::fs::read(path)?;
        ensure!(stela_core::sha256(&data) == row["receipt"]["sha256"]);
        let original: Value = serde_json::from_slice(&data)?;
        ensure!(original["passed"] == true);
        let before = &original["observation"]["before"];
        let after = &original["observation"]["after"];
        let initial = unhex(before["state_hex"].as_str().context("before State")?)?;
        let expected = unhex(after["state_hex"].as_str().context("after State")?)?;
        let mut registers = state(&initial)?;
        let pstate = before["pstate_low32"].as_u64().context("original PSTATE")?;
        let inactive = raw(
            before,
            if before["active_sp_bank"].as_u64() == Some(1) {
                "SP_EL0"
            } else {
                "SP_EL1"
            },
        )?;
        let mut system = SystemState::new(
            pstate & !NZCV_MASK,
            inactive,
            El1Registers::new(
                raw(before, "ELR_EL1")?,
                raw(before, "SPSR_EL1")?,
                raw(before, "ESR_EL1")?,
                raw(before, "FAR_EL1")?,
                raw(before, "VBAR_EL1")?,
            ),
        )
        .map_err(|error| anyhow::anyhow!("original SystemState {error:?}"))?;
        let word = u32::try_from(original["case"]["word"].as_u64().context("source word")?)?;
        let pc = GuestAddress(
            original["subject"]["instruction_pc"]
                .as_u64()
                .context("original PC")?,
        );
        let source = word.to_le_bytes();
        let plan = CompilationPlan::new(
            &source,
            pc,
            BlockProfile::SystemRegistersV1,
            TargetCpu::Baseline,
        )?;
        ensure!(plan.source_bytes() == source.len());
        let compiled = plan.compile()?;
        let checked = CompilationPlan::new(
            &source,
            pc,
            BlockProfile::SystemRegistersV1,
            TargetCpu::detect(),
        )?
        .compile()?;
        ensure!(
            compiled.native.x86_64_code == checked.native.x86_64_code
                && compiled.native.source_map == checked.native.source_map
        );
        let mapping = crate::execution::platform::Mapping::new(&compiled.native.x86_64_code)?;
        // SAFETY: Exact baseline System boundary contains only immediate carrier
        // stores into RAX/RDX and RET; no guest RAM access, loop or callback.
        let exit = unsafe { mapping.call_block(&mut registers)? };
        ensure!(exit.next_pc == pc.0 && exit.kind == ExitKind::System as u64);
        ensure!(frame(&registers) == initial);
        let instruction = stela_compiler::block::system::decode_system_instruction(pc, word)?
            .context("typed source")?;
        let request = match instruction.operation {
            stela_compiler::block::system::SystemOperation::Register(operand) => {
                match operand.direction() {
                    stela_compiler::aarch64::system::registers::Direction::Read => {
                        Request::read(operand.encoding(), operand.rt())
                    }
                    stela_compiler::aarch64::system::registers::Direction::Write => Request::write(
                        operand.encoding(),
                        operand.rt(),
                        if operand.rt() == REGISTER_LIMIT {
                            0
                        } else {
                            registers.x[usize::from(operand.rt())]
                        },
                    ),
                }
            }
            stela_compiler::block::system::SystemOperation::PstateImmediate(encoding) => {
                Request::write(encoding, REGISTER_LIMIT, 0)
            }
            _ => anyhow::bail!("unexpected source family"),
        };
        let context = context(
            original["frozen_model"]["input_values"]
                .as_array()
                .context("original controls")?,
        )?;
        match resolve(request, &context, &system, &registers) {
            Resolution::Read(value) => {
                if request.rt != REGISTER_LIMIT {
                    registers.x[usize::from(request.rt)] = value;
                }
            }
            Resolution::BackendRequired(effect) => commit(effect, &mut system, &mut registers)
                .map_err(|e| anyhow::anyhow!("component commit {e:?}"))?,
            decision => anyhow::bail!("uncompleted positive source {decision:?}"),
        };
        ensure!(frame(&registers) == expected, "State mismatch case{index}");
        ensure!(
            system.pstate(&registers) == after["pstate_low32"].as_u64().context("after PSTATE")?
        );
        ensure!(
            system.el1_registers().elr() == raw(after, "ELR_EL1")?
                && system.el1_registers().spsr() == raw(after, "SPSR_EL1")?
                && system.el1_registers().esr() == raw(after, "ESR_EL1")?
                && system.el1_registers().far() == raw(after, "FAR_EL1")?
                && system.el1_registers().vbar() == raw(after, "VBAR_EL1")?
        );
        ensure!(system.stack_pointer(StackBank::El0, &registers) == raw(after, "SP_EL0")?);
        ensure!(system.stack_pointer(StackBank::El1, &registers) == raw(after, "SP_EL1")?);
        ensure!(original["before"]["ram_canary_hex"] == after["ram_canary_hex"]);
        let folder = output.join(format!("case-{index:03}"));
        std::fs::create_dir(&folder)?;
        std::fs::write(folder.join("native.bin"), &compiled.native.x86_64_code)?;
        std::fs::write(folder.join("native-state.bin"), frame(&registers))?;
        records.push(serde_json::json!({"case":index,"word":word,"pc":pc.0,"native_sha256":stela_core::sha256(&compiled.native.x86_64_code),"native_bytes":compiled.native.x86_64_code.len(),"source_map":compiled.native.source_map,"original_receipt_sha256":stela_core::sha256(&data),"native_state_sha256":stela_core::sha256(frame(&registers)),"pstate":system.pstate(&registers)}));
    }
    ensure!(records.len() == POSITIVE_CASES.len());
    std::fs::write(
        output.join("receipt.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({"passed":true,"kind":"register_pstate_original_native_component","compiler_source_sha256":crate::compiler_source_sha256(),"original_receipt_sha256":ORIGINAL_RECEIPT_SHA256,"cases":records.len(),"state_bytes":STATE_BYTES,"records":records,"limits":["Component native System carrier plus Rust effect, not actual PE entry/retirement permission","Original failed40-case whole cohort and12 exceptions remain uncredited; selected19 nonexception effects only","No actual DAIF async lease/source-plan integration or full original CPU adoption/OS/boot claim","No VBAR original or performance measurement"]}),
        )?,
    )?;
    Ok(())
}

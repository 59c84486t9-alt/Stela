//! Original-only transport/provenance, never imports producers or models.
use crate::blocks::ThreadState;
use crate::system::{
    pstate::NZCV_MASK,
    state::{El1Registers, PSTATE_SS_MASK, StackBank, SystemState},
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::path::Path;
use stela_compiler::GuestState;
use stela_core::sha256;

pub(super) const STATE_BYTES: usize = 784;
const GPR_BYTES: usize = size_of::<u64>();
const VECTOR_BYTES: usize = size_of::<[u64; 2]>();
const FP_CONTROL_BYTES: usize = size_of::<u32>();
const GPR_OFFSET: usize = std::mem::offset_of!(GuestState, x);
const SP_OFFSET: usize = std::mem::offset_of!(GuestState, sp);
const NZCV_OFFSET: usize = std::mem::offset_of!(GuestState, nzcv);
const VECTOR_OFFSET: usize = std::mem::offset_of!(GuestState, v);
const FPCR_OFFSET: usize = std::mem::offset_of!(GuestState, fpcr);
const FPSR_OFFSET: usize = std::mem::offset_of!(GuestState, fpsr);
pub(super) const ORIGINAL_SHA: &str =
    "2293f2b9b1be319113d08e3bfecbdabe067bd659c6203377df46eaa8754d2774";
const RAW_AUDIT_SHA: &str = "3f21b012ac8bb62874a1b14677bb8b9d19c421f6b324ba27f24d508fd496b6e3";
const INDEPENDENT_SHA: &str = "52be11ebebd207a5e5e951d56acacc7ba66a8b9ad350c5a85cc20045370b1e47";
const HISTORICAL_NATIVE_SHA: &str =
    "c47993ff4dc97e1e3fbc8d69c67f5ab0a216c08cc0eae079c07ddfab278479d7";
const PREFIX: &str = ".stela/research/coverage-race/nonstreaming/system-control/";

pub(super) fn read_bound(path: &Path, digest: &str) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    ensure!(
        sha256(&bytes) == digest,
        "original evidence changed: {}",
        path.display()
    );
    Ok(bytes)
}
pub(super) fn number(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("missing unsigned {key}"))
}
pub(super) fn unhex(s: &str) -> Result<Vec<u8>> {
    ensure!(
        s.len().is_multiple_of(2) && s.is_ascii(),
        "invalid original hex"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Into::into))
        .collect()
}
pub(super) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub(super) fn state_bytes(s: &GuestState) -> &[u8] {
    assert_eq!(size_of::<GuestState>(), STATE_BYTES);
    // SAFETY: canonical repr(C) GuestState is initialized integer fields, no padding.
    unsafe { std::slice::from_raw_parts(std::ptr::from_ref(s).cast(), STATE_BYTES) }
}
pub(super) fn state_from(frame: &Value) -> Result<GuestState> {
    let bytes = unhex(
        frame["state_hex"]
            .as_str()
            .context("missing original State")?,
    )?;
    ensure!(bytes.len() == STATE_BYTES, "original State size");
    ensure!(
        sha256(&bytes)
            == frame["state_sha256"]
                .as_str()
                .context("missing State identity")?,
        "original State identity"
    );
    let raw = frame["raw_register_hex"]
        .as_object()
        .context("missing raw original registers")?;
    let mut state = GuestState::default();
    for i in 0..state.x.len() {
        ensure!(
            unhex(raw[&format!("x{i}")].as_str().context("raw x")?)?
                == bytes[GPR_OFFSET + i * GPR_BYTES..GPR_OFFSET + (i + 1) * GPR_BYTES],
            "raw GPR differs"
        );
    }
    for i in 0..state.v.len() {
        ensure!(
            unhex(raw[&format!("v{i}")].as_str().context("raw v")?)?
                == bytes[VECTOR_OFFSET + i * VECTOR_BYTES..VECTOR_OFFSET + (i + 1) * VECTOR_BYTES],
            "raw vector differs"
        );
    }
    for (name, offset, length) in [
        ("sp", SP_OFFSET, GPR_BYTES),
        ("fpcr", FPCR_OFFSET, FP_CONTROL_BYTES),
        ("fpsr", FPSR_OFFSET, FP_CONTROL_BYTES),
    ] {
        ensure!(
            unhex(raw[name].as_str().context("raw scalar")?)? == bytes[offset..offset + length],
            "raw scalar differs"
        );
    }
    let cpsr = unhex(raw["cpsr"].as_str().context("raw cpsr")?)?;
    let raw_pc = unhex(raw["pc"].as_str().context("raw pc")?)?;
    ensure!(
        raw_pc == number(frame, "pc")?.to_le_bytes(),
        "raw PC differs"
    );
    let pstate = u32::from_le_bytes(
        cpsr.try_into()
            .map_err(|_| anyhow::anyhow!("raw cpsr size"))?,
    ) as u64;
    ensure!(
        pstate == number(frame, "pstate_low32")?,
        "raw PSTATE differs"
    );
    ensure!(
        pstate & NZCV_MASK
            == u32::from_le_bytes(
                bytes[NZCV_OFFSET..NZCV_OFFSET + FP_CONTROL_BYTES]
                    .try_into()
                    .unwrap()
            ) as u64,
        "original NZCV differs"
    );
    ensure!(
        frame["pstate_high32_observed"] == false
            && number(frame, "handler_instructions_executed")? == 0,
        "observer boundary differs"
    );
    assert_eq!(size_of::<GuestState>(), STATE_BYTES);
    // SAFETY: actual GuestState has plain integer fields; all bits valid, disjoint copy.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            std::ptr::from_mut(&mut state).cast(),
            STATE_BYTES,
        );
    }
    Ok(state)
}
pub(super) fn system_from(frame: &Value) -> Result<SystemState> {
    ensure!(
        number(frame, "pstate_low32")? & PSTATE_SS_MASK == 0,
        "original event corpus requires captured PSTATE.SS=0"
    );
    let raw = &frame["raw_register_hex"];
    let scalar = |name: &str| -> Result<u64> {
        let bytes = unhex(raw[name].as_str().context("missing raw system register")?)?;
        Ok(u64::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("system register size"))?,
        ))
    };
    ensure!(
        number(frame, "current_el")? == 0 && number(frame, "active_sp_bank")? == 0,
        "original must be EL0t"
    );
    for name in ["SP_EL0", "SP_EL1"] {
        ensure!(
            scalar(name)? == number(&frame["canonical_sp_banks"], name)?,
            "raw SP bank differs"
        );
    }
    SystemState::new(
        number(frame, "pstate_low32")? & !NZCV_MASK,
        number(&frame["canonical_sp_banks"], "SP_EL1")?,
        El1Registers::new(
            scalar("ELR_EL1")?,
            scalar("SPSR_EL1")?,
            scalar("ESR_EL1")?,
            scalar("FAR_EL1")?,
            scalar("VBAR_EL1")?,
        ),
    )
    .map_err(|e| anyhow::anyhow!("original system state: {e:?}"))
}
pub(super) fn snapshot(thread: &ThreadState, system: &SystemState, event: bool) -> Value {
    let saved = system.el1_registers();
    json!({"state_hex":hex(state_bytes(&thread.registers)), "state_sha256":sha256(state_bytes(&thread.registers)),
        "pstate":system.pstate(&thread.registers), "pstate_low32":system.pstate(&thread.registers), "pc":thread.pc.0,
        "canonical_sp_banks":{"SP_EL0":system.stack_pointer(StackBank::El0, &thread.registers),
            "SP_EL1":system.stack_pointer(StackBank::El1, &thread.registers)},
        "el1_registers":{"ELR_EL1":saved.elr(),"SPSR_EL1":saved.spsr(),"ESR_EL1":saved.esr(),"FAR_EL1":saved.far(),"VBAR_EL1":saved.vbar()}, "event":event})
}
pub(super) fn compare(thread: &ThreadState, system: &SystemState, frame: &Value) -> Result<()> {
    ensure!(
        state_bytes(&thread.registers) == state_bytes(&state_from(frame)?),
        "full original State differs"
    );
    ensure!(
        system.pstate(&thread.registers) == number(frame, "pstate_low32")?,
        "original PSTATE differs"
    );
    for (bank, name) in [(StackBank::El0, "SP_EL0"), (StackBank::El1, "SP_EL1")] {
        ensure!(
            system.stack_pointer(bank, &thread.registers)
                == number(&frame["canonical_sp_banks"], name)?,
            "original SP bank differs"
        );
    }
    ensure!(thread.pc.0 == number(frame, "pc")?, "original PC differs");
    ensure!(
        system.el1_registers() == system_from(frame)?.el1_registers(),
        "original EL1 saved registers differ"
    );
    Ok(())
}
pub(super) fn verify_original_dependencies(repo: &Path, original: &Path) -> Result<Value> {
    let aggregate: Value = serde_json::from_slice(&read_bound(original, ORIGINAL_SHA)?)?;
    ensure!(
        aggregate["passed"] == true && aggregate["cases"].as_array().context("cases")?.len() == 6,
        "original six-case corpus"
    );
    let audit_path = repo.join(format!(
        "{PREFIX}events/send-original-1/source-and-evidence-audit-1/receipt.json"
    ));
    let audit: Value = serde_json::from_slice(&read_bound(&audit_path, RAW_AUDIT_SHA)?)?;
    ensure!(audit["passed"] == true, "original raw audit failed");
    for item in audit["all_capture_files"]
        .as_array()
        .context("raw original file inventory")?
    {
        let relative = Path::new(item["path"].as_str().context("raw file path")?);
        ensure!(
            !relative.is_absolute()
                && relative
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_))),
            "invalid original locator"
        );
        let bytes = read_bound(
            &repo.join(relative),
            item["sha256"].as_str().context("raw file SHA")?,
        )?;
        ensure!(
            bytes.len() as u64 == number(item, "bytes")?,
            "raw original file size differs"
        );
    }
    read_bound(
        &repo.join(format!(
            "{PREFIX}integration/sev-sevl-1/independent-events-review-1/receipt.json"
        )),
        INDEPENDENT_SHA,
    )?;
    read_bound(
        &repo.join(format!(
            "{PREFIX}integration/sev-sevl-1/original-native-report.json"
        )),
        HISTORICAL_NATIVE_SHA,
    )?;
    Ok(aggregate)
}

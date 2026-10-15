//! Saved proof observations for the existing ignored family corpus only.
//! No record can grant entry or replace source, state, controls, queue or owner.
use crate::{
    scalable::ScalableState,
    system::{debug::halted::DebugMachine, state::SystemState},
};
use serde_json::{Value, json};
use std::{
    io::Write,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};
use stela_compiler::{GuestState, extended::debug_movement::PreparedDebugMovement};
static ROWS: OnceLock<Mutex<Vec<Value>>> = OnceLock::new();
fn enabled() -> Option<PathBuf> {
    std::env::var_os("STELA_PRIVILEGED_CORPUS_REPORT").map(PathBuf::from)
}
fn blob(bytes: &[u8]) -> Value {
    let hash = stela_core::sha256(bytes);
    let report = enabled().expect("artifact output requires exact corpus report path");
    let directory = report
        .parent()
        .expect("report parent")
        .join("privileged-artifacts");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(format!("{hash}.bin"));
    if path.exists() {
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    } else {
        std::fs::write(&path, bytes).unwrap();
    }
    json!({"sha256":hash,"bytes":bytes.len(),"path":path})
}
fn push(row: Value) {
    // Each actual row reaches the per-run journal before its semantic assertions.
    // A panic leaves both complete raw blobs and the exact descriptive row.
    let mut rows = ROWS.get_or_init(|| Mutex::new(Vec::new())).lock().unwrap();
    let journal = enabled()
        .expect("exact report path")
        .with_extension("observations.jsonl");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(journal)
        .unwrap();
    serde_json::to_writer(&mut file, &row).unwrap();
    file.write_all(b"\n").unwrap();
    file.flush().unwrap();
    rows.push(row);
}
pub(crate) fn reset() {
    let report = enabled().expect("exact report path required before execution");
    std::fs::create_dir_all(report.parent().expect("report parent")).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(report.with_extension("observations.jsonl"))
        .expect("fresh immutable observation journal");
    ROWS.get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap()
        .clear();
}
pub(crate) fn rows() -> Vec<Value> {
    ROWS.get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap()
        .clone()
}
/// Reads this exact owned RX mapping under its original retained lifetime.
pub(crate) fn capsule(
    prepared: &PreparedDebugMovement,
    mapping: &crate::execution::platform::Mapping,
) {
    if enabled().is_none() {
        return;
    }
    // SAFETY: Mapping::new owns exactly these initialized code bytes and remains
    // borrowed and RX here. No writable alias, unmap or native call can coexist.
    let mapped = unsafe {
        std::slice::from_raw_parts(mapping.address() as *const u8, prepared.code().len())
    };
    push(
        json!({"kind":"actual_rx_capsule","word":prepared.word(),"source_kind":prepared.source_kind(),
        "external_word_to_native":prepared.word_to_native(),"recipe":format!("{:?}",prepared.recipe()),
        "profile":format!("{:?}",prepared.profile()),"requirements":format!("{:?}",prepared.execution_requirements()),
        "code":blob(mapped),"compiler_source_sha256":crate::compiler_source_sha256()}),
    );
    assert_eq!(mapped, prepared.code());
}
fn registers(state: &GuestState) -> Vec<u8> {
    let mut out = Vec::with_capacity(784);
    for x in state.x {
        out.extend(x.to_le_bytes());
    }
    out.extend(state.sp.to_le_bytes());
    out.extend(state.nzcv.to_le_bytes());
    out.extend(state.reserved.to_le_bytes());
    for v in state.v {
        for limb in v {
            out.extend(limb.to_le_bytes());
        }
    }
    out.extend(state.fpcr.to_le_bytes());
    out.extend(state.fpsr.to_le_bytes());
    assert_eq!(out.len(), 784);
    out
}
pub(crate) fn snapshot(
    registers_before: &GuestState,
    scalable: &ScalableState,
    system: &SystemState,
) -> Value {
    if enabled().is_none() {
        return Value::Null;
    }
    let length = scalable.vector_length();
    let mode = scalable.mode();
    let mut allocated = Vec::new();
    let mut layout = Vec::new();
    let mut append = |name: String, bytes: &[u8]| {
        layout.push(json!({"bank":name,"offset":allocated.len(),"bytes":bytes.len()}));
        allocated.extend(bytes);
    };
    if mode.za_enabled() {
        let mut za = vec![0; length.bytes().pow(2)];
        scalable.read_za(0, &mut za).unwrap();
        append("ZA".into(), &za);
        let mut zt0 = [0; 64];
        scalable.read_zt0(0, &mut zt0).unwrap();
        append("ZT0".into(), &zt0);
    }
    if mode.streaming() {
        for r in 0..32 {
            let mut z = vec![0; length.bytes()];
            scalable.read_z(registers_before, r, &mut z).unwrap();
            append(format!("Z{r}"), &z);
        }
        for r in 0..16 {
            let mut p = vec![0; length.predicate_bytes()];
            scalable.read_predicate(r, &mut p).unwrap();
            append(format!("P{r}"), &p);
        }
        let mut ffr = vec![0; length.predicate_bytes()];
        scalable.read_ffr(&mut ffr).unwrap();
        append("FFR".into(), &ffr);
    }
    append("TPIDR2_EL0".into(), &scalable.tpidr2_el0().to_le_bytes());
    append("FPMR".into(), &scalable.fpmr().to_le_bytes());
    json!({"guest_state":blob(&registers(registers_before)),"guest_state_layout":"x31,SP,NZCV,reserved,V32(low/high64),FPCR,FPSR;LE;784bytes",
        "allocated_scalable":blob(&allocated),"layout":layout,"svl_bytes":length.bytes(),"svcr":mode.svcr(),
        "z_p_ffr":"full allocated SM1 only; SM0 has no enabled Z/P/FFR access; low128 V in GuestState",
        "system":format!("{system:?}"),"pstate":system.pstate(registers_before)})
}
pub(crate) fn actual_lifecycle(
    debug: Option<&DebugMachine>,
    system: &SystemState,
    pc: stela_compiler::GuestAddress,
) -> Value {
    json!({"debug":format!("{debug:?}"),"system":format!("{system:?}"),"actual_pc":pc.0})
}
pub(crate) fn movement_case(
    word: u32,
    before: Value,
    after: Value,
    lifecycle: Value,
    record: String,
    context: Value,
) {
    if enabled().is_none() {
        return;
    }
    push(
        json!({"kind":"actual_movt_case","word":word,"before":before,"after":after,"lifecycle":lifecycle,"record":record,"context":context}),
    );
}

pub(crate) fn system_native(
    bound: &super::super::super::source::BoundSource<'_>,
    system: &SystemState,
    registers_actual: &GuestState,
    phase: &str,
) {
    if enabled().is_none() {
        return;
    }
    let manifest = &bound.block.prepared.manifest;
    // SAFETY: same owned borrowed RX mapping; its validated manifest bounds the
    // initialized bytes. This observation neither calls code nor escapes a pointer.
    let mapped = unsafe {
        std::slice::from_raw_parts(
            bound.block.mapping.address() as *const u8,
            manifest.native_bytes,
        )
    };
    push(
        json!({"kind":"actual_system_rx_and_state","phase":phase,"identity":manifest.identity,
        "source_map":manifest.source_map,"code":blob(mapped),"requirements":manifest.memory_requirements,
        "guest_state":blob(&registers(registers_actual)),"system":format!("{system:?}")}),
    );
    assert_eq!(stela_core::sha256(mapped), manifest.native_sha256);
}

pub(crate) fn context(context: &stela_compiler::context::ExecutionContext) -> Value {
    json!({"version":context.version,"bytes":context.bytes,"memory":context.memory as usize,
        "scalable":context.scalable as usize,"system":context.system as usize})
}

pub(crate) fn factory_state(
    thread: &crate::blocks::ThreadState,
    system: &SystemState,
    scalable: Option<&ScalableState>,
    lifecycle: String,
    phase: &str,
) {
    if enabled().is_none() {
        return;
    }
    push(
        json!({"kind":"actual_factory_state","phase":phase,"guest_state":blob(&registers(&thread.registers)),
        "actual_pc":thread.pc.0,"system":format!("{system:?}"),"lifecycle":lifecycle,
        "scalable":scalable.map(|state| snapshot(&thread.registers,state,system))}),
    );
}
pub(crate) fn factory_report(
    report: &super::super::super::software_privileged::DeclaredPrivilegedReport,
) {
    if enabled().is_none() {
        return;
    }
    factory_state(
        &report.thread,
        &report.system,
        report.scalable.as_ref(),
        report.asynchronous.clone(),
        "after-lifetime",
    );
    push(
        json!({"kind":"actual_factory_receipts","receipts":report.receipts.iter().map(|receipt| json!({
        "operation":receipt.operation,"stop":receipt.stop,"actual_pc":receipt.actual_pc.0,
        "source_receipts":receipt.source_receipts,"native_observation":receipt.native_observation,
        "debug_record":receipt.debug_record,"editr_source":receipt.editr_source,"editr_disposition":receipt.editr_disposition,"lifecycle":receipt.lifecycle,
    })).collect::<Vec<_>>(),"compiler_source_sha256":report.compiler_source_sha256}),
    );
}

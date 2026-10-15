//! Ignored original SEV/SEVL family adapter over production runtime owners.
//! No WFx, exception, guest-data, capture producer or result model is executed.
#[path = "event_corpus/backend.rs"]
mod backend;
#[path = "event_corpus/provenance.rs"]
mod provenance;
#[path = "event_corpus/source_inventory.rs"]
mod source_inventory;

use crate::{
    blocks::{BlockRuntime, StopReason, ThreadState},
    system::{
        events::EventDomain,
        execution::{Execution, Failure},
    },
};
use anyhow::{Context, Result, ensure};
use backend::{ADD_X0, EventBackend, NOP, SEV, SEVL};
use provenance::{
    compare, hex, number, read_bound, snapshot, state_from, system_from,
    verify_original_dependencies,
};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use stela_compiler::{
    GuestAddress, TargetCpu,
    block::{BlockProfile, ExitKind},
};
use stela_core::sha256;

const ADDRESS_SPACE: u64 = 7;
const INSTRUCTION_BYTES: u64 = size_of::<u32>() as u64;
const TEST_PREFIX_PC: GuestAddress = GuestAddress(0x1000);
const KIND: &str = "system_events_runtime_corpus_v1";
const X86_NOP: u8 = 0x90;
const X86_MOV_RAX_IMMEDIATE: [u8; 2] = [0x48, 0xb8];
const X86_MOV_EDX_IMMEDIATE: u8 = 0xba;
const X86_RET: u8 = 0xc3;

fn backends() -> Result<[EventBackend; 2]> {
    let domain = Arc::new(EventDomain::new());
    let first = domain
        .register(false, None)
        .map_err(|e| anyhow::anyhow!("event register: {e:?}"))?;
    let second = domain
        .register(false, None)
        .map_err(|e| anyhow::anyhow!("event register: {e:?}"))?;
    Ok([
        EventBackend::new(Arc::clone(&domain), first),
        EventBackend::new(domain, second),
    ])
}

fn actual_body(
    runtime: &mut BlockRuntime,
    entry: GuestAddress,
    word: u32,
    original_source: &[u8],
) -> Result<Value> {
    let prepared = runtime.prepare(entry)?;
    let native = std::fs::read(prepared.prepared.directory.join("native.bin"))?;
    let manifest = &prepared.prepared.manifest;
    let consumed_source = original_source
        .get(..prepared.analysis.source_bytes)
        .context("actual consumed original source")?;
    ensure!(
        manifest.identity.source_sha256 == sha256(consumed_source)
            && manifest.identity.guest_base == entry.0
            && manifest.identity.target_cpu == TargetCpu::Baseline.id(),
        "actual source/target identity differs"
    );
    ensure!(
        manifest.identity.compiler_source_sha256
            == sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
        "actual prepared compiler source identity differs"
    );
    ensure!(
        sha256(&native) == manifest.native_sha256,
        "actual native hash differs"
    );
    ensure!(
        native.len() == manifest.native_bytes,
        "actual native size differs"
    );
    ensure!(
        !manifest.source_map.is_empty() && manifest.source_map[0].0 == entry,
        "actual first source map"
    );
    let (terminal_pc, offset) = *manifest.source_map.last().context("terminal map")?;
    ensure!(
        manifest.source_map.len() * INSTRUCTION_BYTES as usize == prepared.analysis.source_bytes,
        "actual map extent differs"
    );
    for (index, (pc, _)) in manifest.source_map.iter().enumerate() {
        ensure!(
            pc.0 == entry.0 + index as u64 * INSTRUCTION_BYTES,
            "actual map source PC differs"
        );
    }
    let mut expected = Vec::new();
    if word == NOP {
        expected.push(X86_NOP);
    }
    expected.extend(X86_MOV_RAX_IMMEDIATE);
    expected
        .extend((terminal_pc.0 + if word == NOP { INSTRUCTION_BYTES } else { 0 }).to_le_bytes());
    expected.push(X86_MOV_EDX_IMMEDIATE);
    expected.extend(
        (if word == NOP {
            ExitKind::Fallthrough
        } else {
            ExitKind::System
        } as u32)
            .to_le_bytes(),
    );
    expected.push(X86_RET);
    ensure!(
        native.get(offset..) == Some(expected.as_slice()),
        "actual terminal body differs from baseline exit recipe"
    );
    Ok(
        json!({"pc":entry.0,"word":word,"original_source_hex":hex(consumed_source),
        "native_hex":hex(&native),"native_sha256":sha256(&native),"manifest":manifest,
        "source_map":manifest.source_map,"terminal_pc":terminal_pc.0,
        "terminal_native_offset":offset,"actual_body_verified":true}),
    )
}

fn original_case(aggregate_path: &Path, binding: &Value) -> Result<Value> {
    let recorded = Path::new(binding["path"].as_str().context("original case locator")?);
    ensure!(
        recorded.file_name().context("original case file")? == "receipt.json",
        "original case filename"
    );
    let directory = recorded
        .parent()
        .and_then(Path::file_name)
        .context("original case directory")?;
    let p = aggregate_path
        .parent()
        .context("aggregate parent")?
        .join(directory)
        .join("receipt.json");
    let bytes = read_bound(
        &p,
        binding["sha256"]
            .as_str()
            .context("original case identity")?,
    )?;
    ensure!(
        bytes.len() as u64 == number(binding, "bytes")?,
        "original case size"
    );
    let case: Value = serde_json::from_slice(&bytes)?;
    ensure!(case["passed"] == true, "original case failed");
    ensure!(
        case["input_ram_before_send_hex"] == case["input_ram_after_send_hex"],
        "original input RAM changed"
    );
    ensure!(
        case["control_header_ram_before_send_hex"] == case["control_header_ram_after_send_hex"],
        "original control RAM changed"
    );
    Ok(case)
}

fn failure_prefix_checks(frame0: &Value, frame1: &Value) -> Result<Vec<Value>> {
    let mut checks = Vec::new();
    let word = SEVL;
    let cache = tempfile::tempdir()?;
    let mut runtime = BlockRuntime::new_for_target(
        ADDRESS_SPACE,
        cache.path().into(),
        BlockProfile::SystemV1,
        TargetCpu::Baseline,
    );
    let original_source: Vec<u8> = [ADD_X0, word]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    runtime.register_code(TEST_PREFIX_PC, original_source.clone())?;
    let mut owners = backends()?;
    owners[0].expect(GuestAddress(TEST_PREFIX_PC.0 + INSTRUCTION_BYTES), word);
    owners[0].service_available = false;
    let mut thread = ThreadState {
        registers: state_from(frame0)?,
        pc: TEST_PREFIX_PC,
    };
    let peer = ThreadState {
        registers: state_from(frame1)?,
        pc: GuestAddress(number(frame1, "pc")?),
    };
    let mut system = system_from(frame0)?;
    let peer_system = system_from(frame1)?;
    let original_system = system.clone();
    let before = snapshot(&thread, &system, owners[0].endpoint.is_set());
    let peer_before = snapshot(&peer, &peer_system, owners[1].endpoint.is_set());
    let body = actual_body(&mut runtime, TEST_PREFIX_PC, word, &original_source)?;
    let mut expected = thread.registers.clone();
    expected.x[0] = expected.x[0].wrapping_add(1);
    // SAFETY: admitted source is exact baseline ADD plus SEV/SEVL. All
    // publication services are explicitly unavailable; no guest RAM occurs.
    let outcome = unsafe {
        runtime.run_with_system(
            &mut thread,
            None,
            1,
            &mut Execution::new(ADDRESS_SPACE, &mut system, &mut owners[0]),
        )?
    };
    let StopReason::SystemFailure {
        instruction,
        failure,
    } = &outcome.reason
    else {
        anyhow::bail!("expected source-bound send service failure after prefix");
    };
    ensure!(
        instruction.word == word
            && instruction.instruction_pc.0 == TEST_PREFIX_PC.0 + INSTRUCTION_BYTES,
        "failure terminal identity"
    );
    ensure!(
        matches!(failure, Failure::Backend(_)),
        "actual unavailable service failure class"
    );
    ensure!(
        outcome.blocks_executed == 1 && thread.pc == instruction.instruction_pc,
        "failure source PC/prefix boundary"
    );
    ensure!(
        thread.registers == expected && system == original_system,
        "only completed ADD prefix may commit"
    );
    ensure!(
        !owners[0].endpoint.is_set() && !owners[1].endpoint.is_set(),
        "failed send published an event"
    );
    let peer_after = snapshot(&peer, &peer_system, owners[1].endpoint.is_set());
    ensure!(peer_before == peer_after, "failed send changed peer");
    checks.push(
        json!({"word":word,"terminal_pc":instruction.instruction_pc.0,
        "original_source_hex":hex(&original_source),"body":body,"source_map":body["source_map"],
        "before":before,"after":snapshot(&thread,&system,owners[0].endpoint.is_set()),
        "peer_before":peer_before,"peer_after":peer_after,
        "native_outcome":outcome,"actual_system_failure":true,"passed":true}),
    );
    Ok(checks)
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn fixture_single_step_refusal_precedes_native_prefix_and_publication() -> Result<()> {
    use crate::system::state::{El1Registers, PSTATE_EL0T, PSTATE_SS_MASK, SystemState};
    use stela_compiler::GuestState;

    let cache = tempfile::tempdir()?;
    let mut runtime = BlockRuntime::new_for_target(
        ADDRESS_SPACE,
        cache.path().into(),
        BlockProfile::SystemV1,
        TargetCpu::Baseline,
    );
    runtime.register_code(
        TEST_PREFIX_PC,
        [ADD_X0, SEVL]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
    )?;
    let mut owners = backends()?;
    owners[0].expect(GuestAddress(TEST_PREFIX_PC.0 + INSTRUCTION_BYTES), SEVL);
    let mut thread = ThreadState {
        registers: GuestState {
            x: std::array::from_fn(|index| 0x1000 + index as u64),
            sp: 0x4000,
            nzcv: 0xa000_0000,
            reserved: 0x1234_5678,
            v: std::array::from_fn(|index| [index as u64, !(index as u64)]),
            fpcr: 0,
            fpsr: 0x0800_0001,
        },
        pc: TEST_PREFIX_PC,
    };
    let mut system = SystemState::new(
        PSTATE_EL0T | PSTATE_SS_MASK,
        0x5000,
        El1Registers::new(0x2000, PSTATE_EL0T, 0, 0, 0x8000),
    )
    .map_err(|error| anyhow::anyhow!("single-step fixture state: {error:?}"))?;
    assert_ne!(system.pstate(&thread.registers) & PSTATE_SS_MASK, 0);
    assert!(owners[0].service_available);
    let original_registers = thread.registers.clone();
    let original_system = system.clone();
    let original_pc = thread.pc;
    let original_events = [owners[0].endpoint.is_set(), owners[1].endpoint.is_set()];
    // SAFETY: the fixture's actual SS check rejects before this admitted
    // register/send source enters native code. No guest RAM access is possible.
    let outcome = unsafe {
        runtime.run_with_system(
            &mut thread,
            None,
            1,
            &mut Execution::new(ADDRESS_SPACE, &mut system, &mut owners[0]),
        )?
    };
    assert!(matches!(
        outcome.reason,
        StopReason::SystemEntryFailure {
            instruction_pc: TEST_PREFIX_PC,
            word: ADD_X0,
            failure: Failure::Backend(_),
        }
    ));
    assert_eq!(outcome.blocks_executed, 0);
    assert_eq!(thread.registers, original_registers);
    assert_eq!(system, original_system);
    assert_eq!(thread.pc, original_pc);
    assert_eq!(
        [owners[0].endpoint.is_set(), owners[1].endpoint.is_set()],
        original_events
    );
    assert_eq!(original_events, [false, false]);
    Ok(())
}

#[test]
#[ignore = "requires explicitly supplied unchanged original event corpus and fresh output"]
fn original_sends_match_runtime() -> Result<()> {
    let repo = PathBuf::from(std::env::var("STELA_SYSTEM_EVENTS_REPO")?);
    let original = PathBuf::from(std::env::var("STELA_SYSTEM_EVENTS_ORIGINAL")?);
    let report_path = PathBuf::from(std::env::var("STELA_SYSTEM_EVENTS_REPORT")?);
    ensure!(
        !report_path.exists(),
        "refuse to replace an existing report"
    );
    let aggregate = verify_original_dependencies(&repo, &original)?;
    let mut reports = Vec::new();
    let mut sender_steps = 0;
    let mut nop_steps = 0;
    let mut first_frames = None;
    for binding in aggregate["cases"].as_array().context("cases")? {
        let case = original_case(&original, binding)?;
        let sender = usize::try_from(number(&case, "sender")?)?;
        let repeats = usize::try_from(number(&case, "repeats")?)?;
        let word = u32::try_from(number(&case, "subject_word")?)?;
        ensure!(
            sender < 2 && matches!(repeats, 1 | 2) && matches!(word, NOP | SEV | SEVL),
            "bounded original case scope"
        );
        let first_pc = GuestAddress(number(&case["symbols"], "sender_subject")?);
        let stop_pc = GuestAddress(number(&case["symbols"], "sender_probe")?);
        ensure!(
            stop_pc.0 == first_pc.0 + repeats as u64 * INSTRUCTION_BYTES,
            "original sender extent"
        );
        ensure!(
            case["observations"]
                .as_array()
                .context("sender observations")?
                .len()
                == repeats,
            "original step count"
        );
        let mut owners = backends()?;
        let frames = [
            &case["both_before_send"]["0"],
            &case["both_before_send"]["1"],
        ];
        if first_frames.is_none() {
            first_frames = Some([(*frames[0]).clone(), (*frames[1]).clone()]);
        }
        let mut threads = [
            ThreadState {
                registers: state_from(frames[0])?,
                pc: GuestAddress(number(frames[0], "pc")?),
            },
            ThreadState {
                registers: state_from(frames[1])?,
                pc: GuestAddress(number(frames[1], "pc")?),
            },
        ];
        let mut systems = [system_from(frames[0])?, system_from(frames[1])?];
        let original_systems = systems.clone();
        ensure!(threads[sender].pc == first_pc, "original sender PC");
        for pe in 0..2 {
            compare(&threads[pe], &systems[pe], frames[pe])?;
        }
        let cache = tempfile::tempdir()?;
        let mut runtime = BlockRuntime::new_for_target(
            ADDRESS_SPACE,
            cache.path().into(),
            BlockProfile::SystemV1,
            TargetCpu::Baseline,
        );
        let source: Vec<u8> = std::iter::repeat_n(word, repeats)
            .flat_map(u32::to_le_bytes)
            .collect();
        runtime.register_code(first_pc, source.clone())?;
        let mut bodies = Vec::new();
        let mut outcomes = Vec::new();
        let mut step_pes = Vec::new();
        for index in 0..repeats {
            let pc = GuestAddress(first_pc.0 + index as u64 * INSTRUCTION_BYTES);
            let observation = &case["observations"][index];
            let observed_source = provenance::unhex(
                observation["source_hex"]
                    .as_str()
                    .context("original observed source bytes")?,
            )?;
            ensure!(
                number(observation, "source_pc")? == pc.0
                    && observed_source == word.to_le_bytes()
                    && sha256(&observed_source)
                        == observation["source_sha256"]
                            .as_str()
                            .context("original observed source identity")?,
                "original executed subject differs"
            );
            compare(
                &threads[sender],
                &systems[sender],
                &case["observations"][index]["before"],
            )?;
            owners[sender].expect(pc, word);
            bodies.push(actual_body(
                &mut runtime,
                pc,
                word,
                &source[index * INSTRUCTION_BYTES as usize..],
            )?);
            let before = threads[sender].registers.clone();
            // SAFETY: exact unchanged original NOP/SEV/SEVL source. The fixture
            // admits no guest-memory instruction or unrelated system service.
            let outcome = unsafe {
                runtime.run_with_system(
                    &mut threads[sender],
                    Some(GuestAddress(pc.0 + INSTRUCTION_BYTES)),
                    1,
                    &mut Execution::new(ADDRESS_SPACE, &mut systems[sender], &mut owners[sender]),
                )?
            };
            ensure!(
                outcome.reason == StopReason::StopAddress,
                "native sender did not stop after exact subject"
            );
            ensure!(
                outcome.blocks_executed == 1,
                "exact subject must execute one native block"
            );
            ensure!(
                threads[sender].registers == before && systems == original_systems,
                "send changed State or system banks"
            );
            compare(
                &threads[sender],
                &systems[sender],
                &case["observations"][index]["after"],
            )?;
            compare(
                &threads[1 - sender],
                &systems[1 - sender],
                frames[1 - sender],
            )?;
            for (pe, owner) in owners.iter().enumerate() {
                ensure!(
                    owner.endpoint.is_set() == (word != NOP && (word == SEV || pe == sender)),
                    "actual event/coalescing result"
                );
            }
            step_pes.push(json!([
                snapshot(&threads[0], &systems[0], owners[0].endpoint.is_set()),
                snapshot(&threads[1], &systems[1], owners[1].endpoint.is_set())
            ]));
            outcomes.push(serde_json::to_value(outcome)?);
            sender_steps += 1;
            nop_steps += usize::from(word == NOP);
        }
        let mut pes = Vec::new();
        for pe in 0..2 {
            compare(
                &threads[pe],
                &systems[pe],
                &case["both_after_send"][pe.to_string()],
            )?;
            let event = owners[pe].endpoint.is_set();
            let expected = case["probes"][pe]["event_expected"]
                .as_bool()
                .context("original event probe")?;
            ensure!(
                event == expected,
                "event differs from actual original WFE observation"
            );
            let mut report = snapshot(&threads[pe], &systems[pe], event);
            report["pe"] = json!(pe);
            report["original_probe_expected"] = json!(expected);
            pes.push(report);
        }
        reports.push(json!({"original":binding,"mnemonic":case["mnemonic"],"sender":sender,"repeats":repeats,
            "bodies":bodies,"native_outcomes":outcomes,"step_pes":step_pes,"pes":pes,"passed":true}));
    }
    ensure!(
        reports.len() == 6 && sender_steps == 8 && nop_steps == 2,
        "original cohort census differs"
    );
    let frames = first_frames.context("missing original initialization frames")?;
    let failures = failure_prefix_checks(&frames[0], &frames[1])?;
    ensure!(
        failures.len() == 1,
        "one bounded native failure-prefix check required"
    );
    // Recheck exact original/raw/proof dependencies after all native work.
    ensure!(
        verify_original_dependencies(&repo, &original)? == aggregate,
        "original dependencies changed"
    );
    let compiler_source = reports[0]["bodies"][0]["manifest"]["identity"]["compiler_source_sha256"]
        .as_str()
        .context("actual prepared compiler identity")?;
    ensure!(
        compiler_source == sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
        "cohort compiler identity differs"
    );
    let report = json!({"kind":KIND,"family":"system_events_send_v1","passed":true,
        "compiled_sources_sha256":source_inventory::compiled_sources(),"original_receipt":original,
        "original_receipt_sha256":provenance::ORIGINAL_SHA,"cases":reports,"failure_prefix_checks":failures,
        "compiler_source_sha256":compiler_source,"fresh_original_state_comparisons":sender_steps + reports.len() * 2,
        "fresh_native_blocks_executed":sender_steps,"original_cases":reports.len(),"both_pe_checks":reports.len() * 2,
        "send_steps":sender_steps - nop_steps,"nop_steps":nop_steps,"failure_prefix_check_count":failures.len(),
        "sender_steps":sender_steps,"nop_control_steps":nop_steps,"both_pe_final_comparisons":12,
        "wfx_admission":false,"exception_admission":false,"new_original_captures":0,
        "target":"x86_64-baseline","limits":["Original event result is an indirect WFE observer; native reads the actual authoritative event endpoint bit",
            "Original PSTATE high32 was not observed; equality is low32 only",
            "No guest RAM instructions, device/cache/TLBI or SMP memory-order claim",
            "Historical c479 proof remains historical; this report requires a freshly compiled source-bound executable"]});
    use std::io::Write;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(report_path)?;
    output.write_all(&serde_json::to_vec_pretty(&report)?)?;
    output.write_all(b"\n")?;
    Ok(())
}

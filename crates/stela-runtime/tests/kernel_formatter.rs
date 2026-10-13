//! Native replay of unchanged, bounded interior windows from a pinned kernel.
//! This does not execute a kernel syscall, exception entry, PAC or epilogue.
#![cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use stela_compiler::{GuestAddress, GuestState, SOURCE_FINGERPRINT_MATERIAL};
use stela_core::sha256;
use stela_runtime::{
    blocks::{BlockRuntime, StopReason, ThreadState},
    memory::{MemoryRegionSpec, OwnedMemory},
};
use std::{collections::BTreeSet, io::Write, path::Path};

const KERNEL: &str = "ca55ea8c4c86170e870380ae5501b8b43adb2d2d3db28be4531b3040653be203";
const CODE_PAGE: &str = "65bd00f9e8fb459f36b6a5aeb53e087c661169e977afaaa76bc997b30814630e";
const PAGE_PC: u64 = 0xfffffe000a633000;
const PAGE_OFFSET: usize = 0x362f000;
const ENTRY_START: u64 = 0xfffffe000a633688;
const ENTRY_END: u64 = 0xfffffe000a633694;
const RETURN_START: u64 = 0xfffffe000a63386c;
const RETURN_END: u64 = 0xfffffe000a633980;
const TAIL_START: u64 = 0xfffffe000a633990;
const FUNCTION_START: u64 = 0xfffffe000a633828;
const FUNCTION_END: u64 = 0xfffffe000a6339fc;
const SYSENT: u64 = 0x220000000000;
const SAVED: u64 = 0x220000010000;
const UTHREAD: u64 = 0x220000020000;
const PAGE_BYTES: usize = 4096;
const SAVED_BYTES: usize = 0x140;
const RESERVED: u32 = 0xa5c39e71;
const BLOCK_BUDGET: usize = 128;
const RETURN_TYPES: [&str; 8] = [
    "none",
    "int",
    "unsigned_int",
    "offset",
    "address",
    "size",
    "signed_size",
    "unsigned64",
];
const VALUES: [[u32; 2]; 9] = [
    [0, 0],
    [1, 0],
    [0x7fffffff, 0x80000000],
    [0x80000000, 0x7fffffff],
    [0xffffffff, 0xffffffff],
    [0xffffffff, 1],
    [0, 0xffffffff],
    [0x89abcdef, 0x01234567],
    [0x01234567, 0x89abcdef],
];
const ERRNOS: [u32; 6] = [1, 4, 9, 22, 78, 0x7fffffff];

fn number(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .context("expected unsigned reference integer")
}

fn hex_number(value: &Value) -> Result<u64> {
    let text = value.as_str().context("expected reference hex address")?;
    Ok(u64::from_str_radix(
        text.strip_prefix("0x").context("hex address prefix")?,
        16,
    )?)
}

fn decode_hex(value: &Value, length: usize) -> Result<Vec<u8>> {
    let text = value.as_str().context("expected reference hex bytes")?;
    ensure!(
        text.len() == length * 2 && text.is_ascii(),
        "reference byte length"
    );
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

fn cpu(value: &Value) -> Result<ThreadState> {
    let registers = &value["registers"];
    let xs = registers["x"]
        .as_array()
        .context("reference CPU registers")?;
    ensure!(xs.len() == 31, "reference CPU register count");
    let mut x = [0; 31];
    for (destination, source) in x.iter_mut().zip(xs) {
        *destination = number(source)?;
    }
    let mut state = ThreadState {
        pc: GuestAddress(number(&value["pc"])?),
        registers: GuestState {
            x,
            sp: number(&registers["sp"])?,
            nzcv: u32::try_from(number(&registers["nzcv"])?)?,
            reserved: u32::try_from(number(&registers["reserved"])?)?,
            // This original integer-window reference predates SIMD/FP snapshots.
            ..GuestState::default()
        },
    };
    if let Some(vectors) = registers.get("v") {
        let vectors = vectors.as_array().context("reference SIMD registers")?;
        ensure!(vectors.len() == 32, "reference SIMD register count");
        for (destination, source) in state.registers.v.iter_mut().zip(vectors) {
            let limbs = source.as_array().context("reference SIMD limbs")?;
            ensure!(limbs.len() == 2, "reference SIMD limb count");
            *destination = [number(&limbs[0])?, number(&limbs[1])?];
        }
    }
    if let Some(fpcr) = registers.get("fpcr") {
        state.registers.fpcr = u32::try_from(number(fpcr)?)?;
    }
    if let Some(fpsr) = registers.get("fpsr") {
        state.registers.fpsr = u32::try_from(number(fpsr)?)?;
    }
    Ok(state)
}

fn cpu_json(state: &ThreadState) -> Value {
    json!({"pc":state.pc.0,"registers":{
        "x":state.registers.x,"sp":state.registers.sp,
        "nzcv":state.registers.nzcv,"reserved":state.registers.reserved,
        "v":state.registers.v,"fpcr":state.registers.fpcr,"fpsr":state.registers.fpsr}})
}

fn compare_cpu(actual: &ThreadState, expected: &Value) -> Result<()> {
    let expected = cpu(expected)?;
    ensure!(
        actual.pc == expected.pc,
        "CPU PC mismatch: {:#x} != {:#x}",
        actual.pc.0,
        expected.pc.0
    );
    ensure!(
        actual.registers == expected.registers,
        "CPU X0..X30/SP/NZCV/reserved/V0..V31/FPCR/FPSR mismatch"
    );
    Ok(())
}

fn initial_cpu() -> ThreadState {
    let mut x = std::array::from_fn(|index| 0x456789ab00000000 + index as u64 * 0x10101);
    x[19] = SAVED;
    ThreadState {
        registers: GuestState {
            x,
            sp: 0x40400000,
            nzcv: 0,
            reserved: RESERVED,
            v: std::array::from_fn(|index| {
                [
                    0x0123456789abcdefu64.rotate_left(index as u32),
                    0xfedcba9876543210u64.rotate_right(index as u32),
                ]
            }),
            fpcr: 0x03c00000,
            fpsr: 0x0800001f,
        },
        pc: GuestAddress(ENTRY_START),
    }
}

#[test]
fn reference_cpu_accepts_legacy_state_and_validates_supplied_vector_fp_fields() -> Result<()> {
    let mut value = cpu_json(&initial_cpu());
    for field in ["v", "fpcr", "fpsr"] {
        value["registers"].as_object_mut().unwrap().remove(field);
    }
    let legacy = cpu(&value)?;
    assert_eq!(legacy.registers.v, [[0; 2]; 32]);
    assert_eq!((legacy.registers.fpcr, legacy.registers.fpsr), (0, 0));
    let mut full = cpu_json(&legacy);
    full["registers"]["v"][31][1] = json!(u64::MAX);
    full["registers"]["fpcr"] = json!(u32::MAX);
    full["registers"]["fpsr"] = json!(0x8000009fu32);
    let parsed = cpu(&full)?;
    assert_eq!(parsed.registers.v[31][1], u64::MAX);
    assert_eq!(parsed.registers.fpcr, u32::MAX);
    assert_eq!(parsed.registers.fpsr, 0x8000009f);
    for change in 0..5 {
        let mut invalid = full.clone();
        match change {
            0 => invalid["registers"]["v"] = json!([]),
            1 => invalid["registers"]["v"][0] = json!([0]),
            2 => invalid["registers"]["v"][0][0] = json!(-1),
            3 => invalid["registers"]["fpcr"] = json!(u64::MAX),
            _ => invalid["registers"]["fpsr"] = Value::Null,
        }
        assert!(cpu(&invalid).is_err());
    }
    Ok(())
}

fn saved_page(flags: u32, return_type: u32) -> Vec<u8> {
    let mut page = vec![0; PAGE_BYTES];
    for (index, byte) in page[..SAVED_BYTES].iter_mut().enumerate() {
        *byte = (index * 73 + flags as usize * 11 + return_type as usize * 7) as u8;
    }
    page[..4].copy_from_slice(&0x15u32.to_le_bytes());
    page[4..8].copy_from_slice(&74u32.to_le_bytes());
    for index in 0..31 {
        let value = 0xdeadbeef12340000u64
            + index as u64 * 0x102030405
            + u64::from(flags) * 0x10001
            + u64::from(return_type);
        page[8 + index * 8..16 + index * 8].copy_from_slice(&value.to_le_bytes());
    }
    page[8 + 16 * 8..16 + 16 * 8].copy_from_slice(&4u64.to_le_bytes());
    page[0x100..0x108].copy_from_slice(&0x40010000u64.to_le_bytes());
    page[0x108..0x110].copy_from_slice(&0x10000cu64.to_le_bytes());
    page[0x110..0x114].copy_from_slice(&(flags << 28).to_le_bytes());
    page[0x114..0x118].copy_from_slice(&RESERVED.to_le_bytes());
    page
}

fn code_range(page: &[u8], start: u64, end: u64) -> &[u8] {
    &page[(start - PAGE_PC) as usize..(end - PAGE_PC) as usize]
}

fn validate_path(case: &Value, reference: &Value, page: &[u8]) -> Result<()> {
    let path_id = usize::try_from(number(&case["path_id"])?)?;
    let path = reference["paths"]
        .as_array()
        .context("reference paths")?
        .get(path_id)
        .context("reference path index")?;
    ensure!(
        number(&path["id"])? == path_id as u64,
        "reference path identity"
    );
    let pcs = path["pcs"].as_array().context("reference path PCs")?;
    let words = path["instruction_bytes"]
        .as_array()
        .context("reference path bytes")?;
    ensure!(
        !pcs.is_empty() && pcs.len() <= 128 && pcs.len() == words.len(),
        "bounded reference path"
    );
    ensure!(hex_number(&pcs[0])? == RETURN_START, "reference path entry");
    for (pc, bytes) in pcs.iter().zip(words) {
        let pc = hex_number(pc)?;
        ensure!(
            pc.is_multiple_of(4)
                && ((RETURN_START..RETURN_END).contains(&pc)
                    || (TAIL_START..FUNCTION_END).contains(&pc)),
            "reference path leaves registered interior extents"
        );
        let word = decode_hex(bytes, 4)?;
        ensure!(
            word == code_range(page, pc, pc + 4),
            "reference instruction identity"
        );
        ensure!(
            u32::from_le_bytes(word.try_into().unwrap()) & 0xfc000000 != 0x94000000,
            "helper BL is outside replay profile"
        );
    }
    Ok(())
}

fn compare_memory(
    memory: &OwnedMemory,
    saved: &[u8],
    sysent: &[u8],
    uthread: &[u8],
) -> Result<Vec<String>> {
    let mut hashes = Vec::with_capacity(3);
    for (address, expected) in [(SAVED, saved), (SYSENT, sysent), (UTHREAD, uthread)] {
        let actual = memory.read_snapshot(address, PAGE_BYTES)?;
        ensure!(actual == expected, "full buffer mismatch at {address:#x}");
        hashes.push(sha256(&actual));
    }
    Ok(hashes)
}

#[test]
#[ignore = "requires STELA_DARWIN_REFERENCE with actual-CPU pinned kernel oracle"]
fn unchanged_kernel_formatter_windows_match_original_cpu_and_full_memory() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap();
    let reference_path = std::path::PathBuf::from(std::env::var("STELA_DARWIN_REFERENCE")?);
    let reference_path = if reference_path.is_absolute() {
        reference_path
    } else {
        root.join(reference_path)
    };
    ensure!(
        // Full V/FP snapshots increase the pinned 1,920-case JSON beyond64MiB.
        std::fs::metadata(&reference_path)?.len() <= 128 * 1024 * 1024,
        "reference size limit"
    );
    let bytes = std::fs::read(&reference_path)?;
    let reference_hash = sha256(&bytes);
    let reference: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        reference["status"] == "passed"
            && reference["schema_version"] == 1
            && reference["native_replay_schema_version"] == 1,
        "reference schema/status"
    );
    ensure!(
        reference["native_memory_layout"]
            == json!({"sysent":SYSENT,
        "saved_state":SAVED,"uthread":UTHREAD,"bytes_each":PAGE_BYTES}),
        "reference memory layout identity"
    );
    ensure!(
        reference["kernel_sha256"] == KERNEL && reference["kernel_snapshot_sha256"] == KERNEL,
        "kernel reference identity"
    );
    let generator_hash = sha256(include_bytes!("../../../dev/kernel-syscall-reference.py"));
    ensure!(
        reference["harness_sha256"] == generator_hash
            && sha256(&std::fs::read(
                root.join("dev/kernel-syscall-reference.py")
            )?) == generator_hash,
        "compiled/current/reference generator identity mismatch"
    );
    for field in ["harness_start_sha256", "harness_end_sha256"] {
        ensure!(
            reference["source_integrity"][field] == generator_hash,
            "reference generator changed during run"
        );
    }
    for field in ["kernel_start_sha256", "kernel_end_sha256"] {
        ensure!(
            reference["source_integrity"][field] == KERNEL,
            "reference kernel changed during run"
        );
    }
    let kernel_path = Path::new(reference["kernel_path"].as_str().context("kernel path")?);
    ensure!(
        std::fs::metadata(kernel_path)?.len() <= 1024 * 1024 * 1024,
        "kernel size limit"
    );
    let kernel = std::fs::read(kernel_path)?;
    ensure!(sha256(&kernel) == KERNEL, "pinned kernel content changed");
    let page = kernel
        .get(PAGE_OFFSET..PAGE_OFFSET + PAGE_BYTES)
        .context("kernel source page bounds")?;
    ensure!(
        sha256(page) == CODE_PAGE && reference["code_page"]["sha256"] == CODE_PAGE,
        "pinned source-page identity"
    );
    ensure!(
        hex_number(&reference["code_page"]["va"])? == PAGE_PC
            && hex_number(&reference["code_page"]["file_offset"])? == PAGE_OFFSET as u64
            && number(&reference["code_page"]["bytes"])? == PAGE_BYTES as u64,
        "source-page placement identity"
    );
    ensure!(
        hex_number(&reference["entry_window"]["start"])? == ENTRY_START
            && hex_number(&reference["entry_window"]["end_exclusive"])? == ENTRY_END
            && reference["entry_window"]["sha256"]
                == sha256(code_range(page, ENTRY_START, ENTRY_END)),
        "entry-window identity"
    );
    ensure!(
        hex_number(&reference["return_window"]["start"])? == RETURN_START
            && hex_number(&reference["return_window"]["stop_before_epilogue"])? == RETURN_END
            && reference["return_window"]["function_sha256"]
                == sha256(code_range(page, FUNCTION_START, FUNCTION_END)),
        "return-window identity"
    );

    // No MAP_FIXED: occupied addresses cause an explicit mapping failure. These
    // synthetic addresses match the original oracle without host guard changes.
    let mut memory = OwnedMemory::map(
        [SYSENT, SAVED, UTHREAD]
            .into_iter()
            .map(|guest_address| MemoryRegionSpec {
                guest_address,
                virtual_bytes: PAGE_BYTES as u64,
                initial_bytes: Vec::new(),
                readable: true,
                writable: true,
                executable: false,
            })
            .collect(),
    )?;
    let cache = tempfile::tempdir()?;
    let mut runtime = BlockRuntime::new(0x4b45524e464d5401, cache.path().to_path_buf());
    let extents = [
        (ENTRY_START, ENTRY_END),
        (RETURN_START, RETURN_END),
        (TAIL_START, FUNCTION_END),
    ];
    for (start, end) in extents {
        runtime.register_code(GuestAddress(start), code_range(page, start, end).to_vec())?;
    }
    let cases = reference["cases"].as_array().context("reference cases")?;
    let mut coverage = BTreeSet::new();
    let mut records = Vec::new();
    let mut total_blocks = 0usize;
    for case in cases {
        if case["adapter_comparable"] != true {
            continue;
        }
        let input = &case["native_replay"]["memory_inputs"];
        let return_type = u32::try_from(number(&input["sysent_return_type"])?)?;
        ensure!(
            return_type < 8
                && number(&case["prototype"]["argument_count"])? == 8
                && case["prototype"]["return_type"] == RETURN_TYPES[return_type as usize],
            "return prototype identity"
        );
        ensure!(
            number(&input["saved_bytes"])? == SAVED_BYTES as u64
                && number(&input["page_bytes"])? == PAGE_BYTES as u64
                && number(&input["saved_page_padding_byte"])? == 0,
            "buffer initialization profile"
        );
        let retval = input["uthread_retval32"]
            .as_array()
            .context("retval32 inputs")?;
        ensure!(retval.len() == 2, "retval32 pair size");
        let values = [
            u32::try_from(number(&retval[0])?)?,
            u32::try_from(number(&retval[1])?)?,
        ];
        let error = u32::try_from(number(&input["completion_w3"])?)?;
        match case["kind"].as_str() {
            Some("success") => ensure!(
                error == 0
                    && VALUES.contains(&values)
                    && case["completion"] == json!({"kind":"success","values":values}),
                "success input profile"
            ),
            Some("error") => ensure!(
                ERRNOS.contains(&error)
                    && values == [0x89abcdef, 0x01234567]
                    && case["completion"] == json!({"kind":"error","errno":error}),
                "error input profile"
            ),
            _ => anyhow::bail!("comparable case must be ordinary success/error"),
        }
        let before = decode_hex(&case["saved_buffer_before_hex"], SAVED_BYTES)?;
        let flags = u32::from_le_bytes(before[0x110..0x114].try_into().unwrap()) >> 28;
        let mut expected_saved = saved_page(flags, return_type);
        ensure!(
            expected_saved[..SAVED_BYTES] == before,
            "deterministic saved-state inputs"
        );
        ensure!(
            coverage.insert((flags, return_type, error, values)),
            "duplicate reference case"
        );
        validate_path(case, &reference, page)?;
        let mut sysent = vec![0; PAGE_BYTES];
        sysent[0x10..0x14].copy_from_slice(&return_type.to_le_bytes());
        let mut uthread = vec![0; PAGE_BYTES];
        uthread[0x40..0x44].copy_from_slice(&values[0].to_le_bytes());
        uthread[0x44..0x48].copy_from_slice(&values[1].to_le_bytes());
        memory.write(SAVED, &expected_saved)?;
        memory.write(SYSENT, &sysent)?;
        memory.write(UTHREAD, &uthread)?;
        let replay = &case["native_replay"];
        ensure!(
            replay["page_hash_order"] == json!(["saved_state", "sysent", "uthread"]),
            "original full-page hash order"
        );
        let mut state = initial_cpu();
        compare_cpu(&state, &replay["cpu_before_entry"])?;
        // SAFETY: exact pinned original interior instructions, deterministic
        // CPU inputs and private live mappings. The clipped entry source
        // ends before unrelated code; no buffer aliases Rust/runtime storage.
        let entry =
            unsafe { runtime.run(&mut state, Some(GuestAddress(ENTRY_END)), BLOCK_BUDGET) }?;
        ensure!(
            entry.reason == StopReason::StopAddress && entry.blocks_executed == 1,
            "entry-window stop"
        );
        compare_cpu(&state, &replay["cpu_after_entry"])?;
        let entry_cpu_hash = sha256(&serde_json::to_vec(&cpu_json(&state))?);
        let after_entry = decode_hex(&case["saved_buffer_after_entry_hex"], SAVED_BYTES)?;
        expected_saved[..SAVED_BYTES].copy_from_slice(&after_entry);
        let entry_hashes = compare_memory(&memory, &expected_saved, &sysent, &uthread)?;
        ensure!(
            replay["page_sha256_after_entry"] == json!(entry_hashes),
            "original/native full entry-page hashes"
        );

        // The reference supplies these same four formatter arguments between
        // the windows; the unmodeled intervening handler is never executed.
        state.registers.x[..4].copy_from_slice(&[SYSENT, SAVED, UTHREAD, u64::from(error)]);
        state.pc = GuestAddress(RETURN_START);
        compare_cpu(&state, &replay["cpu_before_return"])?;
        // SAFETY: pinned formatter bytes with reviewed ordinary completion and
        // return-type domain. Paths touch only the three owned pages. Helper,
        // PAC/prologue/epilogue are not executed; omitted epilogue stops native
        // source scanning at RETURN_END while branch tails retain original PCs.
        let returned =
            unsafe { runtime.run(&mut state, Some(GuestAddress(RETURN_END)), BLOCK_BUDGET) }?;
        ensure!(
            returned.reason == StopReason::StopAddress && returned.blocks_executed > 0,
            "return-window stop: {:?}",
            returned.reason
        );
        compare_cpu(&state, &replay["cpu_after_return"])?;
        let after = decode_hex(&case["saved_buffer_after_hex"], SAVED_BYTES)?;
        expected_saved[..SAVED_BYTES].copy_from_slice(&after);
        let return_hashes = compare_memory(&memory, &expected_saved, &sysent, &uthread)?;
        ensure!(
            replay["page_sha256_after_return"] == json!(return_hashes),
            "original/native full return-page hashes"
        );
        total_blocks += entry.blocks_executed + returned.blocks_executed;
        records.push(json!({"case_id":case["id"],"path_id":case["path_id"],
            "entry_cpu_sha256":entry_cpu_hash,
            "return_cpu_sha256":sha256(&serde_json::to_vec(&cpu_json(&state))?),
            "entry_buffer_sha256":entry_hashes,"return_buffer_sha256":return_hashes,
            "entry_blocks":entry.blocks_executed,"return_blocks":returned.blocks_executed}));
    }
    ensure!(
        coverage.len() == 1920,
        "incomplete flags/type/value/error coverage"
    );
    ensure!(
        std::fs::read(&reference_path)? == bytes,
        "reference changed during replay"
    );
    ensure!(
        sha256(&std::fs::read(
            root.join("dev/kernel-syscall-reference.py")
        )?) == generator_hash,
        "generator changed during replay"
    );
    let report = json!({
        "kind":"unchanged_kernel_formatter_native_vs_original_arm", "passed":true,
        "reference_sha256":reference_hash,"kernel_sha256":KERNEL,"source_page_sha256":CODE_PAGE,
        "generator_sha256":generator_hash,"unicorn_version":reference["unicorn_version"],
        "compiler_source_sha256":sha256(SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
        "test_source_sha256":sha256(include_bytes!("kernel_formatter.rs")),
        "runtime_blocks_source_sha256":sha256(include_bytes!("../src/blocks.rs")),
        "runtime_memory_source_sha256":sha256(include_bytes!("../src/memory.rs")),
        "test_executable_sha256":sha256(&std::fs::read(std::env::current_exe()?)?),
        "registered_source_extents":extents.map(|(start,end)|json!({"start":start,"end_exclusive":end,
            "sha256":sha256(code_range(page,start,end))})),
        "stop_pcs":[ENTRY_END,RETURN_END],"block_budget_per_window":BLOCK_BUDGET,
        "omitted_epilogue":{"start":RETURN_END,"end_exclusive":TAIL_START},
        "guest_buffers":{"sysent":SYSENT,"saved_state":SAVED,"uthread":UTHREAD,"bytes_each":PAGE_BYTES},
        "ordinary_cases":coverage.len(),"full_cpu_output_comparisons":coverage.len()*2,
        "full_page_output_comparisons":coverage.len()*6,"native_blocks_executed":total_blocks,
        "cases":records,
        "limits":"Unchanged pinned kernel interior instructions with synthetic owned buffers. No complete kernel function/syscall, service, exception entry/return, EL/PSTATE delivery, PAC/prologue/epilogue, restart helper or JustReturn context restoration."
    });
    let mut output = serde_json::to_vec_pretty(&report)?;
    output.push(b'\n');
    let directory = root.join(".stela/evidence/kernel-formatter-native");
    std::fs::create_dir_all(&directory)?;
    let archive = directory.join(format!("{}.json", sha256(&output)));
    let mut pending = tempfile::NamedTempFile::new_in(&directory)?;
    pending.write_all(&output)?;
    pending.as_file().sync_all()?;
    match pending.persist_noclobber(&archive) {
        Ok(_) => {}
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure!(
                std::fs::read(&archive)? == output,
                "native evidence archive identity mismatch"
            );
        }
        Err(error) => return Err(error.error.into()),
    }
    println!(
        "{}",
        json!({"passed":true,"ordinary_cases":coverage.len(),
        "full_cpu_output_comparisons":coverage.len()*2,"report":archive})
    );
    Ok(())
}

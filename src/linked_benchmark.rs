//! In-process release benchmark of the project's real chained-bound entry fixture.
//! The comparator is optimizing Rust with the same modeled state/RAM effects;
//! it is not an x86 Mach-O implementation, dyld benchmark or whole-app estimate.
use crate::macho::{
    linked_images::{ImageInput, LinkedImages},
    mapped_image::StackSpec,
};
use anyhow::{Context, Result, ensure};
use object::{Object, ObjectSection, ObjectSymbol};
use serde::Serialize;
use serde_json::{Value, json};
use stela_compiler::{GuestAddress, GuestState, SOURCE_FINGERPRINT_MATERIAL};
use stela_core::{sha256, write_json};
use stela_runtime::blocks::{RunOutcome, StopReason, ThreadState};
use std::{
    collections::BTreeMap,
    hint::black_box,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const BASES: [u64; 2] = [0x40000000000, 0x50000000000];
const STACK: u64 = 0x80000000000;
const STACK_BYTES: u64 = 65536;
const STOP: u64 = 0xffff0000;
const SEED: u64 = 0x9e3779b97f4a7c15;
const TRIALS: usize = 7;
const MAX_ITERATIONS: usize = 1 << 20;

struct Input {
    data: Vec<u8>,
    container_hash: String,
    slice_offset: u64,
    symbols: BTreeMap<String, u64>,
    preferred: u64,
    text_hash: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct Addresses {
    imports: u64,
    main_output: u64,
    library_pointers: u64,
    library_output: u64,
    function: u64,
    seed: u64,
    stack_top: u64,
}

#[derive(Clone)]
struct ExpectedMemory {
    address: u64,
    bytes: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct Batch {
    iterations: usize,
    wall_ns: u128,
    ns_per_entry: f64,
    checksum: u64,
}

fn adrp(pc: u64, target: u64, register: u32) -> Result<u32> {
    let pages = (i128::from(target / 4096)) - i128::from(pc / 4096);
    ensure!(
        (-1048576..1048576).contains(&pages),
        "fixture ADRP target exceeds signed21 range"
    );
    let value = (pages as u32) & 0x1fffff;
    Ok(0x90000000 | ((value & 3) << 29) | ((value >> 2) << 5) | register)
}

fn add_page(target: u64, register: u32) -> u32 {
    0x91000000 | (((target & 4095) as u32) << 10) | (register << 5) | register
}

fn input(path: &Path, main: bool) -> Result<Input> {
    let container = std::fs::read(path)?;
    let (slice_offset, data) = crate::apple_slice(&container, path, Some("arm64"))?;
    let file = object::File::parse(data)?;
    let names: &[&str] = if main {
        &["_bound_entry", "_bound_imports", "_bound_output"]
    } else {
        &[
            "_bound_function",
            "_bound_seed",
            "_library_pointers",
            "_library_output",
        ]
    };
    let mut symbols = BTreeMap::new();
    for symbol in file.symbols() {
        if let Ok(name) = symbol.name()
            && names.contains(&name)
            && symbol.is_definition()
        {
            ensure!(
                symbols.insert(name.to_owned(), symbol.address()).is_none(),
                "duplicate fixture symbol {name}"
            );
        }
    }
    ensure!(
        symbols.len() == names.len(),
        "benchmark accepts only the project's complete bound fixture symbol set"
    );
    let text: Vec<_> = file
        .sections()
        .filter(|section| matches!(section.name(), Ok("__text")))
        .collect();
    ensure!(
        text.len() == 1,
        "benchmark fixture requires one __text section"
    );
    let section = &text[0];
    let code = section.data()?;
    let pc = section.address();
    let get = |name: &str| symbols[name];
    let words = if main {
        ensure!(
            get("_bound_entry") == pc,
            "fixture entry no longer starts its complete text"
        );
        vec![
            0xa9bf7bfd,
            0x910003fd,
            adrp(pc + 8, get("_bound_imports"), 9)?,
            add_page(get("_bound_imports"), 9),
            0xa940352c,
            0xf94001a1,
            0x8b010000,
            0xd63f0180,
            adrp(pc + 32, get("_bound_output"), 14)?,
            add_page(get("_bound_output"), 14),
            0xf90001c0,
            0xa8c17bfd,
            0xd65f03c0,
        ]
    } else {
        ensure!(
            get("_bound_function") == pc,
            "fixture provider no longer starts its complete text"
        );
        vec![
            adrp(pc, get("_library_pointers"), 9)?,
            add_page(get("_library_pointers"), 9),
            0xf940012a,
            0xf9400144,
            0xf9000140,
            0x91002c00,
            0xf9000540,
            0xd65f03c0,
        ]
    };
    let expected: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    ensure!(
        code == expected,
        "fixture instructions changed; review the independent benchmark oracle before execution"
    );
    let plan = if main {
        crate::macho::load_plan::plan(data)?
    } else {
        crate::macho::load_plan::plan_library(data)?
    };
    let preferred = crate::macho::mapped_image::preferred_base(&plan)?;
    Ok(Input {
        data: data.to_vec(),
        container_hash: sha256(&container),
        slice_offset,
        symbols,
        preferred,
        text_hash: sha256(code),
    })
}

fn load(inputs: &[Input; 2], cache: &Path) -> Result<LinkedImages> {
    LinkedImages::load(
        inputs
            .iter()
            .enumerate()
            .map(|(index, input)| ImageInput {
                data: input.data.clone(),
                container_sha256: input.container_hash.clone(),
                slice_offset: input.slice_offset,
                load_base: Some(BASES[index]),
            })
            .collect(),
        cache.to_path_buf(),
        StackSpec {
            base: STACK,
            bytes: STACK_BYTES,
        },
    )
}

fn relocated(input: &Input, index: usize, name: &str) -> Result<u64> {
    let offset = input.symbols[name]
        .checked_sub(input.preferred)
        .context("fixture symbol is below preferred address")?;
    BASES[index]
        .checked_add(offset)
        .context("fixture relocated symbol overflow")
}

fn writeable(images: &LinkedImages, address: u64, length: u64) -> Result<()> {
    ensure!(
        address.is_multiple_of(8)
            && images.regions().iter().any(|region| region.writable
                && address >= region.guest_address
                && address
                    .checked_add(length)
                    .is_some_and(|end| end <= region.guest_address + region.virtual_bytes)),
        "benchmark write target is outside aligned owned writable RAM"
    );
    Ok(())
}

fn addresses(images: &LinkedImages, inputs: &[Input; 2]) -> Result<Addresses> {
    ensure!(
        images.images().len() == 2 && images.entry() == relocated(&inputs[0], 0, "_bound_entry")?,
        "unexpected linked benchmark image set"
    );
    let rows = images.images();
    ensure!(
        rows[0].applied_binds == 2
            && rows[0].applied_rebases == 0
            && rows[1].applied_binds == 0
            && rows[1].applied_rebases == 1,
        "benchmark requires two genuine binds and one provider rebase"
    );
    ensure!(
        rows.iter().all(|row| row.fixups.pointer_formats == [6]),
        "benchmark pointer format changed"
    );
    let result = Addresses {
        imports: relocated(&inputs[0], 0, "_bound_imports")?,
        main_output: relocated(&inputs[0], 0, "_bound_output")?,
        library_pointers: relocated(&inputs[1], 1, "_library_pointers")?,
        library_output: relocated(&inputs[1], 1, "_library_output")?,
        function: relocated(&inputs[1], 1, "_bound_function")?,
        seed: relocated(&inputs[1], 1, "_bound_seed")?,
        stack_top: images.stack().initial_sp,
    };
    ensure!(
        result.stack_top == STACK + STACK_BYTES,
        "benchmark stack top changed"
    );
    for (name, address, slot) in [
        ("_bound_function", result.function, result.imports),
        ("_bound_seed", result.seed, result.imports + 8),
    ] {
        ensure!(
            rows[0]
                .bindings
                .iter()
                .filter(|row| row.name == name
                    && row.provider_image == 1
                    && row.address == address
                    && row.value == address
                    && row.guest_address == slot
                    && row.addend == 0)
                .count()
                == 1,
            "unexpected fixture binding {name}"
        );
    }
    ensure!(
        rows[1].fixups.rebases[0].guest_address == result.library_pointers
            && rows[1].fixups.rebases[0].value == result.library_output,
        "unexpected provider BSS rebase"
    );
    ensure!(
        images.read_snapshot(result.imports, 16)?
            == [result.function.to_le_bytes(), result.seed.to_le_bytes()].concat(),
        "bound import memory differs from symbol oracle"
    );
    ensure!(
        images.read_snapshot(result.library_pointers, 8)? == result.library_output.to_le_bytes()
            && images.read_snapshot(result.seed, 8)? == SEED.to_le_bytes(),
        "provider pointer/seed differs from oracle"
    );
    writeable(images, result.main_output, 8)?;
    writeable(images, result.library_output, 16)?;
    writeable(images, result.stack_top - 16, 16)?;
    Ok(result)
}

fn memory_oracle(
    images: &LinkedImages,
    inputs: &[Input; 2],
    addresses: Addresses,
) -> Result<Vec<ExpectedMemory>> {
    let mut rows = vec![];
    for (index, image) in images.images().iter().enumerate() {
        for segment in image
            .plan
            .segments
            .iter()
            .filter(|segment| matches!(segment.name.as_str(), "__DATA_CONST" | "__DATA"))
        {
            let address = BASES[index] + segment.guest.address - inputs[index].preferred;
            let mut bytes = vec![0u8; usize::try_from(segment.guest.bytes)?];
            let start = usize::try_from(segment.file.offset)?;
            let length = usize::try_from(segment.file.bytes)?;
            bytes[..length].copy_from_slice(&inputs[index].data[start..start + length]);
            rows.push(ExpectedMemory { address, bytes });
        }
    }
    ensure!(
        rows.len() == 4 && rows.iter().map(|row| row.bytes.len()).sum::<usize>() == 131072,
        "benchmark DATA_CONST/DATA layout changed"
    );
    patch(&mut rows, addresses.imports, addresses.function)?;
    patch(&mut rows, addresses.imports + 8, addresses.seed)?;
    patch(
        &mut rows,
        addresses.library_pointers,
        addresses.library_output,
    )?;
    for row in &rows {
        ensure!(
            images.read_snapshot(row.address, row.bytes.len())? == row.bytes,
            "initial linked data/BSS differs from independent file/zero-fill oracle"
        );
    }
    Ok(rows)
}

fn patch(rows: &mut [ExpectedMemory], address: u64, value: u64) -> Result<()> {
    let row = rows
        .iter_mut()
        .find(|row| {
            address >= row.address
                && address - row.address <= row.bytes.len().saturating_sub(8) as u64
        })
        .context("oracle write exceeds expected memory")?;
    let offset = usize::try_from(address - row.address)?;
    row.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn states(addresses: Addresses) -> Vec<GuestState> {
    (0..16)
        .map(|flags| {
            let mut state = GuestState {
                sp: addresses.stack_top,
                nzcv: flags << 28,
                reserved: 0xa5c39e71,
                fpcr: (flags & 3) << 22,
                fpsr: flags & 0x1f,
                ..GuestState::default()
            };
            for index in 0..31 {
                state.x[index] = 0xdeadbeef12345678u64
                    .wrapping_mul(index as u64 + 1)
                    .rotate_left(flags * 3);
            }
            for (index, vector) in state.v.iter_mut().enumerate() {
                *vector = [
                    0x0123456789abcdefu64.rotate_left(flags + index as u32),
                    0xfedcba9876543210u64.rotate_right(flags + index as u32),
                ];
            }
            state.x[0] = [
                0,
                1,
                u64::MAX,
                u64::MAX - SEED,
                0x8000000000000000,
                0x7fffffffffffffff,
                0xffffffff,
                0x100000000,
            ][flags as usize % 8];
            state.x[30] = STOP;
            state
        })
        .collect()
}

fn expected(initial: &GuestState, old_output: u64, addresses: Addresses) -> GuestState {
    let mut state = initial.clone();
    state.x[0] = initial.x[0].wrapping_add(SEED).wrapping_add(11);
    state.x[1] = SEED;
    state.x[4] = old_output;
    state.x[9] = addresses.library_pointers;
    state.x[10] = addresses.library_output;
    state.x[12] = addresses.function;
    state.x[13] = addresses.seed;
    state.x[14] = addresses.main_output;
    state
}

fn validate(
    images: &LinkedImages,
    initial: &GuestState,
    actual: &ThreadState,
    old_output: u64,
    addresses: Addresses,
    baseline: &[ExpectedMemory],
) -> Result<()> {
    ensure!(
        actual.pc == GuestAddress(STOP)
            && actual.registers == expected(initial, old_output, addresses),
        "linked benchmark full-state/return-PC mismatch"
    );
    let mut memory = baseline.to_vec();
    let first = initial.x[0].wrapping_add(SEED);
    let final_value = first.wrapping_add(11);
    patch(&mut memory, addresses.main_output, final_value)?;
    patch(&mut memory, addresses.library_output, first)?;
    patch(&mut memory, addresses.library_output + 8, final_value)?;
    for row in memory {
        ensure!(
            images.read_snapshot(row.address, row.bytes.len())? == row.bytes,
            "linked benchmark complete DATA_CONST/DATA/BSS mismatch"
        );
    }
    ensure!(
        images.read_snapshot(addresses.stack_top - 16, 16)?
            == [initial.x[29].to_le_bytes(), initial.x[30].to_le_bytes()].concat(),
        "linked benchmark FP/LR stack frame mismatch"
    );
    Ok(())
}

fn outcome(outcome: &RunOutcome, compiled: usize, disk: usize, hot: usize) -> Result<()> {
    ensure!(
        outcome.reason == StopReason::StopAddress
            && outcome.blocks_executed == 3
            && outcome.last_exit == Some((STOP, 4))
            && outcome.compiled_blocks == compiled
            && outcome.disk_cache_hits == disk
            && outcome.memory_cache_hits == hot,
        "linked benchmark dispatch/cache outcome changed"
    );
    Ok(())
}

fn reset(images: &mut LinkedImages, addresses: Addresses) {
    // SAFETY: addresses() proved all five aligned words lie in writable owned
    // mappings, and this exclusive owner remains alive for the complete call.
    unsafe {
        for address in [
            addresses.main_output,
            addresses.library_output,
            addresses.library_output + 8,
            addresses.stack_top - 16,
            addresses.stack_top - 8,
        ] {
            (address as *mut u64).write(0);
        }
    }
    black_box(images);
}

/// Independent optimizing native implementation of the reviewed fixture's
/// observable GuestState and RAM semantics, using its actual bound pointers.
#[inline(never)]
unsafe extern "C" fn native_fixture(state: *mut GuestState, addresses: *const Addresses) {
    // SAFETY: caller holds exclusive live owned mappings and distinct valid state;
    // fixture validation proves every loaded pointer and its full target extent.
    unsafe {
        let state = &mut *state;
        let addresses = &*addresses;
        let imports = addresses.imports as *const u64;
        let function = imports.read();
        let seed_pointer = imports.add(1).read();
        let seed = (seed_pointer as *const u64).read();
        let output = (addresses.library_pointers as *const u64).read() as *mut u64;
        let old = output.read();
        let first = state.x[0].wrapping_add(seed);
        let final_value = first.wrapping_add(11);
        (state.sp as *mut u64).sub(2).write(state.x[29]);
        (state.sp as *mut u64).sub(1).write(state.x[30]);
        output.write(first);
        output.add(1).write(final_value);
        (addresses.main_output as *mut u64).write(final_value);
        state.x[0] = final_value;
        state.x[1] = seed;
        state.x[4] = old;
        state.x[9] = addresses.library_pointers;
        state.x[10] = output as u64;
        state.x[12] = function;
        state.x[13] = seed_pointer;
        state.x[14] = addresses.main_output;
    }
}

#[inline(never)]
unsafe extern "C" fn empty_fixture(state: *mut GuestState, addresses: *const Addresses) {
    black_box((state, addresses));
}

fn checksum(hash: u64, state: &GuestState, index: usize) -> u64 {
    // Multiplication and an explicit iteration salt prevent the rotate-XOR
    // cancellation of repeated state schedules at power-of-two batch lengths.
    // This is a work-integrity check, not a cryptographic state attestation.
    let sample = state.x[0].rotate_left(17)
        ^ state.x[4].rotate_right(11)
        ^ state.x[29]
        ^ u64::from(state.nzcv)
        ^ (index as u64).wrapping_mul(0x9e3779b97f4a7c15);
    (hash ^ sample)
        .rotate_left(23)
        .wrapping_mul(0xbf58476d1ce4e5b9)
        .wrapping_add(0x94d049bb133111eb)
}

fn expected_checksum(
    states: &[GuestState],
    iterations: usize,
    addresses: Addresses,
    empty: bool,
) -> u64 {
    let mut hash = 0u64;
    let mut previous = 0;
    for index in 0..iterations {
        let initial = &states[index % states.len()];
        let final_state = if empty {
            initial.clone()
        } else {
            expected(initial, previous, addresses)
        };
        hash = checksum(hash, &final_state, index);
        previous = initial.x[0].wrapping_add(SEED);
    }
    hash
}

fn batch(
    images: &mut LinkedImages,
    addresses: Addresses,
    states: &[GuestState],
    iterations: usize,
    translated: bool,
    empty: bool,
    baseline: &[ExpectedMemory],
) -> Result<Batch> {
    reset(images, addresses);
    let entry = images.entry();
    let function = black_box(if empty { empty_fixture } else { native_fixture }
        as unsafe extern "C" fn(*mut GuestState, *const Addresses));
    let mut hash = 0;
    let mut last = ThreadState {
        pc: GuestAddress(entry),
        registers: states[0].clone(),
    };
    let mut last_outcome = None;
    let started = Instant::now();
    for index in 0..iterations {
        let mut thread = ThreadState {
            pc: GuestAddress(entry),
            registers: states[index % states.len()].clone(),
        };
        if translated {
            // SAFETY: exact reviewed fixture, verified entry/bind addresses and
            // live exclusive owner; no instructions access other host memory.
            last_outcome = Some(unsafe { images.run(&mut thread, Some(GuestAddress(STOP)), 8)? });
        } else {
            // SAFETY: same verified live GuestState/RAM profile as translated path.
            unsafe {
                function(&mut thread.registers, &addresses);
            }
            thread.pc = GuestAddress(STOP);
        }
        hash = checksum(hash, &thread.registers, index);
        black_box(&mut thread);
        last = thread;
    }
    let wall_ns = started.elapsed().as_nanos();
    ensure!(
        hash == expected_checksum(states, iterations, addresses, empty),
        "timed linked benchmark checksum mismatch"
    );
    if translated {
        outcome(last_outcome.as_ref().context("empty timed batch")?, 0, 0, 3)?;
    }
    if !empty {
        let old = if iterations == 1 {
            0
        } else {
            states[(iterations - 2) % states.len()].x[0].wrapping_add(SEED)
        };
        validate(
            images,
            &states[(iterations - 1) % states.len()],
            &last,
            old,
            addresses,
            baseline,
        )?;
    }
    Ok(Batch {
        iterations,
        wall_ns,
        ns_per_entry: wall_ns as f64 / iterations as f64,
        checksum: hash,
    })
}

fn command(program: &Path, arguments: &[&str]) -> Option<String> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let started = Instant::now();
    while child.try_wait().ok()?.is_none() {
        if started.elapsed() >= Duration::from_secs(2) {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn summary(values: &[f64]) -> Value {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    json!({"min":sorted[0],"median":sorted[sorted.len()/2],"max":sorted[sorted.len()-1],"trials":values})
}

fn source_hashes() -> BTreeMap<&'static str, String> {
    [
        (
            "src/linked_benchmark.rs",
            include_bytes!("linked_benchmark.rs").as_slice(),
        ),
        (
            "src/macho/linked_images.rs",
            include_bytes!("macho/linked_images.rs").as_slice(),
        ),
        (
            "src/macho/chained_fixups.rs",
            include_bytes!("macho/chained_fixups.rs").as_slice(),
        ),
        (
            "src/macho/exports.rs",
            include_bytes!("macho/exports.rs").as_slice(),
        ),
        (
            "src/macho/load_plan.rs",
            include_bytes!("macho/load_plan.rs").as_slice(),
        ),
        (
            "src/macho/mapped_image.rs",
            include_bytes!("macho/mapped_image.rs").as_slice(),
        ),
        (
            "crates/stela-runtime/src/lib.rs",
            include_bytes!("../crates/stela-runtime/src/lib.rs").as_slice(),
        ),
        (
            "crates/stela-runtime/src/execution.rs",
            include_bytes!("../crates/stela-runtime/src/execution.rs").as_slice(),
        ),
        (
            "crates/stela-runtime/src/blocks.rs",
            include_bytes!("../crates/stela-runtime/src/blocks.rs").as_slice(),
        ),
        (
            "crates/stela-runtime/src/memory.rs",
            include_bytes!("../crates/stela-runtime/src/memory.rs").as_slice(),
        ),
        (
            "tests/fixtures/bound-image-arm64.S",
            include_bytes!("../tests/fixtures/bound-image-arm64.S").as_slice(),
        ),
        (
            "tests/fixtures/bound-library-arm64.S",
            include_bytes!("../tests/fixtures/bound-library-arm64.S").as_slice(),
        ),
        ("Cargo.toml", include_bytes!("../Cargo.toml").as_slice()),
        ("Cargo.lock", include_bytes!("../Cargo.lock").as_slice()),
    ]
    .into_iter()
    .map(|(name, bytes)| (name, sha256(bytes)))
    .collect()
}

fn original_reference_snapshot(root: &Path, data: &[u8]) -> Result<PathBuf> {
    let directory = root.join(".stela/evidence/bound-image-differential");
    std::fs::create_dir_all(&directory)?;
    let snapshot = directory.join(format!("{}.json", sha256(data)));
    if !snapshot.exists() {
        // Publish a complete immutable snapshot without overwriting another
        // writer's archive. A failed write leaves no partially published file.
        let mut pending = tempfile::NamedTempFile::new_in(&directory)?;
        pending.write_all(data)?;
        pending.as_file().sync_all()?;
        match pending.persist_noclobber(&snapshot) {
            Ok(_) => {}
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.error).context("cannot archive original-ARM evidence"),
        }
    }
    ensure!(
        std::fs::read(&snapshot)? == data,
        "original-ARM evidence archive identity mismatch"
    );
    Ok(snapshot)
}

fn original_reference(root: &Path, inputs: &[Input; 2], compiler: &str) -> Result<Value> {
    let path = root.join(".stela/bound-image-differential.json");
    let data = std::fs::read(&path).context(
        "run the genuine bound-image original-ARM differential harness before benchmarking",
    )?;
    let report: Value = serde_json::from_slice(&data)?;
    let expected = json!(
        inputs
            .iter()
            .map(|input| sha256(&input.data))
            .collect::<Vec<_>>()
    );
    ensure!(
        report["kind"] == "own_bound_macho_cross_image_differential"
            && report["passed"] == true
            && report["compiler_source_sha256"] == compiler
            && report["fixture"]["image_sha256"] == expected
            && report["full_state_comparisons"]
                .as_u64()
                .is_some_and(|count| count >= 32),
        "original-ARM report does not match these exact linked images/compiler"
    );
    ensure!(
        report["harness_source_sha256"]
            == sha256(include_bytes!("../dev/bound-image-differential.py")),
        "original-ARM evidence harness identity changed"
    );
    let snapshot = original_reference_snapshot(root, &data)?;
    Ok(
        json!({"report":snapshot,"latest_report":path,"sha256":sha256(&data),"full_state_comparisons":report["full_state_comparisons"],"reference":"previous exact-image Unicorn ARM64 and independent mathematical/symbol oracle; neither is timed"}),
    )
}

fn cache_receipts(cache: &Path) -> Result<Vec<Value>> {
    let mut rows = vec![];
    for entry in std::fs::read_dir(cache)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let manifest_bytes = std::fs::read(entry.path().join("manifest.json"))?;
        let manifest: Value = serde_json::from_slice(&manifest_bytes)?;
        let native = std::fs::read(entry.path().join("native.bin"))?;
        ensure!(
            manifest["native_sha256"] == sha256(&native),
            "benchmark cache payload identity mismatch"
        );
        rows.push(json!({"key":entry.file_name().to_string_lossy(), "manifest_sha256":sha256(&manifest_bytes),"manifest":manifest}));
    }
    rows.sort_by_key(|row| row["key"].as_str().unwrap_or_default().to_owned());
    ensure!(
        rows.len() == 3,
        "benchmark translation-cache entry count changed"
    );
    Ok(rows)
}

fn archive(output: &Path, report: &Value, root: &Path) -> Result<PathBuf> {
    let mut data = serde_json::to_vec_pretty(report)?;
    data.push(b'\n');
    let directory = root.join(".stela/evidence/linked-benchmark");
    std::fs::create_dir_all(&directory)?;
    if output.exists() {
        let previous = std::fs::read(output)?;
        let old = directory.join(format!("{}.json", sha256(&previous)));
        if !old.exists() {
            std::fs::write(old, previous)?;
        }
    }
    let snapshot = directory.join(format!("{}.json", sha256(&data)));
    if snapshot.exists() {
        ensure!(
            std::fs::read(&snapshot)? == data,
            "benchmark archive identity mismatch"
        );
    } else {
        std::fs::write(&snapshot, &data)?;
    }
    write_json(output, report)?;
    Ok(snapshot)
}

/// Benchmark only the byte-validated project fixture under its supplied entry ABI.
pub fn run(main: &Path, library: &Path, output: &Path) -> Result<()> {
    ensure!(
        !cfg!(debug_assertions),
        "linked benchmark requires an optimized release build"
    );
    ensure!(
        std::env::consts::ARCH == "x86_64",
        "linked benchmark requires native x86-64"
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let inputs = [input(main, true)?, input(library, false)?];
    let compiler = sha256(SOURCE_FINGERPRINT_MATERIAL.as_bytes());
    let reference = original_reference(root, &inputs, &compiler)?;
    let executable = std::env::current_exe()?;
    let executable_hash = sha256(&std::fs::read(&executable)?);
    let cache = tempfile::tempdir()?;
    let started = Instant::now();
    let mut cold = load(&inputs, cache.path())?;
    let cold_load_ns = started.elapsed().as_nanos();
    let addresses = addresses(&cold, &inputs)?;
    let expected_memory = memory_oracle(&cold, &inputs, addresses)?;
    let states = states(addresses);
    let mut thread = ThreadState {
        pc: GuestAddress(cold.entry()),
        registers: states[0].clone(),
    };
    let started = Instant::now();
    // SAFETY: exact instruction bytes, symbols, live data and supplied ABI verified above.
    let first = unsafe { cold.run(&mut thread, Some(GuestAddress(STOP)), 8)? };
    let cold_first_run_ns = started.elapsed().as_nanos();
    outcome(&first, 3, 0, 0)?;
    validate(&cold, &states[0], &thread, 0, addresses, &expected_memory)?;
    let receipts = serde_json::to_value(cold.images())?;
    drop(cold);
    let started = Instant::now();
    let mut images = load(&inputs, cache.path())?;
    let disk_load_ns = started.elapsed().as_nanos();
    ensure!(
        self::addresses(&images, &inputs)?.stack_top == addresses.stack_top,
        "disk-loader context changed"
    );
    memory_oracle(&images, &inputs, addresses)?;
    let mut thread = ThreadState {
        pc: GuestAddress(images.entry()),
        registers: states[0].clone(),
    };
    let started = Instant::now();
    // SAFETY: identical verified fixture/addresses in a new exclusive owned mapping set.
    let disk = unsafe { images.run(&mut thread, Some(GuestAddress(STOP)), 8)? };
    let disk_first_run_ns = started.elapsed().as_nanos();
    outcome(&disk, 0, 3, 0)?;
    validate(&images, &states[0], &thread, 0, addresses, &expected_memory)?;
    for initial in &states {
        reset(&mut images, addresses);
        let mut thread = ThreadState {
            pc: GuestAddress(images.entry()),
            registers: initial.clone(),
        };
        // SAFETY: same verified fixture and live owner; preflight remains outside timing.
        let observed = unsafe { images.run(&mut thread, Some(GuestAddress(STOP)), 8)? };
        outcome(&observed, 0, 0, 3)?;
        validate(&images, initial, &thread, 0, addresses, &expected_memory)?;
        reset(&mut images, addresses);
        let mut native = ThreadState {
            pc: GuestAddress(images.entry()),
            registers: initial.clone(),
        };
        // SAFETY: same aligned, validated live RAM and distinct state as translated path.
        unsafe {
            native_fixture(&mut native.registers, &addresses);
        }
        native.pc = GuestAddress(STOP);
        validate(&images, initial, &native, 0, addresses, &expected_memory)?;
    }
    let mut iterations = 256;
    let mut calibration = vec![];
    loop {
        let measured = batch(
            &mut images,
            addresses,
            &states,
            iterations,
            false,
            false,
            &expected_memory,
        )?;
        let enough = measured.wall_ns >= 2_000_000;
        calibration.push(measured);
        if enough || iterations == MAX_ITERATIONS {
            break;
        }
        iterations = (iterations * 2).min(MAX_ITERATIONS);
    }
    ensure!(
        calibration.last().unwrap().wall_ns >= 2_000_000,
        "baseline batches did not reach 2 ms timing floor"
    );
    let mut trials = vec![];
    let mut native_times = vec![];
    let mut translated_times = vec![];
    let mut ratios = vec![];
    let mut floor_times = vec![];
    for index in 0..TRIALS {
        let (translated, native) = if index % 2 == 0 {
            let native = batch(
                &mut images,
                addresses,
                &states,
                iterations,
                false,
                false,
                &expected_memory,
            )?;
            let translated = batch(
                &mut images,
                addresses,
                &states,
                iterations,
                true,
                false,
                &expected_memory,
            )?;
            (translated, native)
        } else {
            let translated = batch(
                &mut images,
                addresses,
                &states,
                iterations,
                true,
                false,
                &expected_memory,
            )?;
            let native = batch(
                &mut images,
                addresses,
                &states,
                iterations,
                false,
                false,
                &expected_memory,
            )?;
            (translated, native)
        };
        let floor = batch(
            &mut images,
            addresses,
            &states,
            iterations,
            false,
            true,
            &expected_memory,
        )?;
        ratios.push(translated.ns_per_entry / native.ns_per_entry);
        native_times.push(native.ns_per_entry);
        translated_times.push(translated.ns_per_entry);
        floor_times.push(floor.ns_per_entry);
        trials.push(json!({"order":if index % 2 == 0 {"native_then_stela"} else {"stela_then_native"},"native_rust":native,"stela":translated,"empty_wrapper":floor}));
    }
    ensure!(
        executable_hash == sha256(&std::fs::read(&executable)?),
        "benchmark executable changed during measurement"
    );
    for (path, input) in [(main, &inputs[0]), (library, &inputs[1])] {
        ensure!(
            sha256(&std::fs::read(path)?) == input.container_hash,
            "benchmark input changed on disk"
        );
    }
    let cpu = if std::env::consts::OS == "macos" {
        command(
            Path::new("/usr/sbin/sysctl"),
            &["-n", "machdep.cpu.brand_string"],
        )
    } else {
        let mut output = String::new();
        std::fs::File::open("/proc/cpuinfo")
            .ok()
            .and_then(|file| file.take(65536).read_to_string(&mut output).ok())
            .and_then(|_| {
                output
                    .lines()
                    .find(|line| line.starts_with("model name"))
                    .map(str::to_owned)
            })
    };
    let rustc = root.join(".tools/rust/rustup/toolchains/stable-x86_64-apple-darwin/bin/rustc");
    let report = json!({"schema_version":1,"kind":"bound_fixture_release_runtime_benchmark","passed":true,"complete_binary_verified":false,
        "unix_time_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "compiler_source_sha256":compiler,"compiler_executable_sha256":executable_hash,"source_sha256":source_hashes(),"original_arm_reference":reference,
        "inputs":[{"path":main,"container_sha256":inputs[0].container_hash,"slice_sha256":sha256(&inputs[0].data),"text_sha256":inputs[0].text_hash},
                  {"path":library,"container_sha256":inputs[1].container_hash,"slice_sha256":sha256(&inputs[1].data),"text_sha256":inputs[1].text_hash}],
        "placements":BASES,"addresses":addresses,"image_receipts":receipts,"translation_cache_receipts":cache_receipts(cache.path())?,
        "verification":{"preflight_full_state_memory_comparisons":34,"modeled_state":"all 31 GPRs, SP, NZCV, reserved, 32 V registers, FPCR, FPSR and actual return PC", "data_bytes_per_comparison":131072,"stack_frame_bytes_per_comparison":16,
                        "instruction_count_per_entry":21,"native_blocks_per_entry":3,"batch_checksum_and_final_full_state_memory_verified":true,
                        "checksum":"iteration index salt, rotated state samples and wrapping multiply/add"},
        "cold":{"fresh_load_plan_bind_map_ns":cold_load_ns,"first_compile_dispatch_ns":cold_first_run_ns,"combined_ns":cold_load_ns+cold_first_run_ns,"outcome":first},
        "fresh_loader_disk_reuse":{"plan_bind_map_ns":disk_load_ns,"first_disk_dispatch_ns":disk_first_run_ns,"combined_ns":disk_load_ns+disk_first_run_ns,"outcome":disk},
        "timing":{"iterations_per_batch":iterations,"paired_trials":TRIALS,"stela_ns_per_entry":summary(&translated_times),"native_rust_ns_per_entry":summary(&native_times),
                  "paired_stela_over_native_ratio":summary(&ratios),"empty_wrapper_ns_per_entry":summary(&floor_times),"calibration":calibration,"trials":trials,
                  "scope":"In-process hot three-block LinkedImages::run versus independent optimizing Rust extern-C semantic function. Equal reset-state/checksum/black_box wrappers; RAM reset once per batch outside timer; both paths execute all final state and RAM effects. No Python/Unicorn, CLI startup, loader work, full snapshots or mathematical verification inside hot timers. Runtime API checks/counters remain part of Stela execution."},
        "host":{"architecture":std::env::consts::ARCH,"os":std::env::consts::OS,"logical_processors":std::thread::available_parallelism().ok().map(usize::from),"cpu":cpu,
                "uname":command(Path::new("/usr/bin/uname"), &["-a"]),"available_local_rustc_version":command(&rustc, &["--version"]),"release_debug_assertions":cfg!(debug_assertions),"cpu_affinity_pinned":false},
        "limits":"Own 21-instruction bound fixture under supplied direct-RAM entry ABI. Native Rust is a semantic optimization baseline, not an x86 Mach-O/C build. Ratios include wrapper and runtime dispatch overhead; empty-wrapper values are reported without subtraction. CPU affinity/frequency are uncontrolled. No full application, dyld, PAC, kernel or macOS boot performance claim."});
    let snapshot = archive(output, &report, root)?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"passed":true,"report":output,"snapshot":snapshot,"iterations_per_trial":iterations,
        "median_stela_ns":summary(&translated_times)["median"],"median_native_rust_ns":summary(&native_times)["median"],"median_paired_ratio":summary(&ratios)["median"]})
        )?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_distinguishes_periodic_batch_counts_and_state_order() {
        let states: Vec<_> = (0..16)
            .map(|index| {
                let mut state = GuestState {
                    nzcv: index << 28,
                    ..GuestState::default()
                };
                state.x[0] = SEED.wrapping_mul(u64::from(index) + 1);
                state.x[4] = state.x[0].rotate_left(9);
                state.x[29] = 0x12345678;
                state
            })
            .collect();
        let fold = |iterations: usize, reverse: bool| {
            (0..iterations).fold(0, |hash, index| {
                let slot = index % states.len();
                let slot = if reverse {
                    states.len() - 1 - slot
                } else {
                    slot
                };
                checksum(hash, &states[slot], index)
            })
        };
        assert_ne!(fold(256, false), fold(512, false));
        assert_ne!(fold(256, false), fold(1024, false));
        assert_ne!(fold(256, false), fold(256, true));
        assert_ne!(checksum(0, &states[0], 0), checksum(0, &states[0], 1));
    }

    #[test]
    fn original_reference_archive_is_created_reused_and_verified() {
        let root = tempfile::tempdir().unwrap();
        let evidence = b"{\"passed\":true}\n";
        let snapshot = original_reference_snapshot(root.path(), evidence).unwrap();
        assert_eq!(
            snapshot.file_name().unwrap(),
            format!("{}.json", sha256(evidence)).as_str()
        );
        assert_eq!(std::fs::read(&snapshot).unwrap(), evidence);
        assert_eq!(
            original_reference_snapshot(root.path(), evidence).unwrap(),
            snapshot
        );
        std::fs::write(&snapshot, b"changed archive").unwrap();
        assert!(original_reference_snapshot(root.path(), evidence).is_err());
        assert_eq!(std::fs::read(snapshot).unwrap(), b"changed archive");
    }

    #[test]
    fn independent_native_semantics_preserve_complete_state_and_visible_ram() {
        #[repr(align(16))]
        struct Frame([u64; 2]);
        let seed = Box::new(SEED);
        let mut frame = Box::new(Frame([0; 2]));
        let mut main_output = Box::new(0u64);
        let mut library_output = Box::new([0u64; 2]);
        let imports = Box::new([0x123456780u64, (&*seed as *const u64) as u64]);
        let pointer = Box::new(library_output.as_mut_ptr() as u64);
        let addresses = Addresses {
            imports: imports.as_ptr() as u64,
            main_output: (&mut *main_output as *mut u64) as u64,
            library_pointers: (&*pointer as *const u64) as u64,
            library_output: library_output.as_mut_ptr() as u64,
            function: imports[0],
            seed: imports[1],
            stack_top: frame.0.as_mut_ptr() as u64 + 16,
        };
        for initial in states(addresses) {
            library_output[0] = 0xa5a55a5adeadbeef;
            let previous = library_output[0];
            let mut actual = initial.clone();
            // SAFETY: all pointers refer to distinct live aligned owned buffers;
            // stack_top is one-past the two-word, 16-byte-aligned frame.
            unsafe {
                native_fixture(&mut actual, &addresses);
            }
            assert_eq!(actual, expected(&initial, previous, addresses));
            assert_eq!(
                *main_output,
                initial.x[0].wrapping_add(SEED).wrapping_add(11)
            );
            assert_eq!(
                *library_output,
                [initial.x[0].wrapping_add(SEED), actual.x[0]]
            );
            assert_eq!(frame.0, [initial.x[29], initial.x[30]]);
            assert_eq!(*imports, [addresses.function, addresses.seed]);
            assert_eq!(*pointer, addresses.library_output);
            assert_eq!(*seed, SEED);
        }
    }

    #[test]
    fn fixture_address_encodings_enforce_architectural_4k_pages_and_bounds() {
        assert_eq!(adrp(0x100000478, 0x100004000, 9).unwrap(), 0x90000029);
        assert_eq!(adrp(0x1ffc, 0x2000, 0).unwrap(), 0xb0000000);
        assert_eq!(adrp(0x2000, 0x1000, 0).unwrap(), 0xf0ffffe0);
        assert!(adrp(0, 0x100000000, 0).is_err());
        assert!(adrp(0x100000000, 0, 0).is_ok());
        assert_eq!(add_page(0x10000c008, 14), 0x910021ce);
    }
}

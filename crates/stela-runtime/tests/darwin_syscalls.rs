//! Owned-code integration of native SVC boundaries and explicit BSD completion.
//! The pipe service below is a test backend, not a Darwin syscall implementation.
#![cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]

use anyhow::{Result, bail, ensure};
use stela_compiler::{
    GuestAddress, GuestState,
    block::{SynchronousTrap, TrapKind},
};
use stela_runtime::{
    blocks::{BlockRuntime, StopReason, ThreadState},
    darwin::{AbiError, BsdCompletion, BsdPrototype, BsdRequest, BsdReturnType, PendingBsdCall},
    memory::{MemoryRegionSpec, OwnedMemory},
};
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicU64, Ordering},
};

const BASE: u64 = 0x10000;
const STOP: u64 = 0xdead0000;
const CARRY: u32 = 1 << 29;
const GUEST_PIPE: u64 = 0x70000000;
const PAYLOAD: &[u8] = b"Stela native guest write\n";
const DARWIN_EBADF: u32 = 9;
const DARWIN_EFAULT: u32 = 14;
// Assembled from tests/fixtures/darwin-syscall-arm64.S. B.CC jumps from +8 to +20.
const WRITE_STUB: [u32; 7] = [
    0xd2800090, // MOV X16, #4
    0xd4001001, // SVC #0x80
    0x54000063, // B.CC +12
    0xd28175a9, // MOV X9, #0xbad
    0xd65f03c0, // RET X30
    0xd28c01a9, // MOV X9, #0x600d
    0xd65f03c0, // RET X30
];
static NEXT_BUFFER: AtomicU64 = AtomicU64::new(0x210000000000);

fn prototype() -> BsdPrototype {
    BsdPrototype {
        argument_count: 3,
        return_type: BsdReturnType::SignedSize,
    }
}
fn thread(flags: u32, address: u64) -> ThreadState {
    let mut registers = GuestState {
        x: std::array::from_fn(|index| {
            0x9e3779b97f4a7c15u64.wrapping_mul(index as u64 + 1) ^ 0xa5c39e7100ff55aa
        }),
        sp: 0x1234000056780000,
        nzcv: flags << 28,
        reserved: 0xa5c39e71,
        v: std::array::from_fn(|index| {
            [
                0x0123456789abcdefu64.rotate_left(index as u32),
                0xfedcba9876543210u64.rotate_right(index as u32),
            ]
        }),
        fpcr: 0xa5c39e71 ^ flags,
        fpsr: 0x5a3c618e ^ flags,
    };
    registers.x[0] = GUEST_PIPE;
    registers.x[1] = address;
    registers.x[2] = PAYLOAD.len() as u64;
    registers.x[30] = STOP;
    ThreadState {
        registers,
        pc: GuestAddress(BASE),
    }
}
fn assert_state(actual: &ThreadState, expected: &ThreadState) {
    assert_eq!(actual.pc, expected.pc);
    assert_eq!(actual.registers, expected.registers);
}
fn private_buffer() -> Result<(OwnedMemory, u64)> {
    let address = NEXT_BUFFER.fetch_add(0x10000, Ordering::Relaxed);
    let memory = OwnedMemory::map(vec![MemoryRegionSpec {
        guest_address: address,
        virtual_bytes: PAYLOAD.len() as u64,
        initial_bytes: PAYLOAD.to_vec(),
        readable: true,
        writable: false,
        executable: false,
    }])?;
    Ok((memory, address))
}
fn pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut descriptors = [-1; 2];
    // SAFETY: descriptors points to two valid writable ints; successful pipe
    // transfers each new descriptor exactly once into an OwnedFd below.
    ensure!(
        unsafe { libc::pipe(descriptors.as_mut_ptr()) } == 0,
        "pipe creation failed"
    );
    // SAFETY: successful pipe returned two distinct, newly owned descriptors.
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    })
}
fn enter(runtime: &mut BlockRuntime, state: &mut ThreadState) -> Result<SynchronousTrap> {
    let mut expected = state.clone();
    expected.registers.x[16] = 4;
    expected.pc = GuestAddress(BASE + 4);
    // SAFETY: immutable own MOV/SVC code accesses no guest data and stops at SVC.
    let outcome = unsafe { runtime.run(state, Some(GuestAddress(STOP)), 8)? };
    assert_eq!(outcome.blocks_executed, 1);
    assert_state(state, &expected);
    match outcome.reason {
        StopReason::SynchronousTrap { trap } => Ok(trap),
        other => bail!("expected genuine SVC boundary, got {other:?}"),
    }
}
fn resume(runtime: &mut BlockRuntime, state: &mut ThreadState, success: bool) -> Result<()> {
    let mut expected = state.clone();
    expected.registers.x[9] = if success { 0x600d } else { 0xbad };
    expected.pc = GuestAddress(STOP);
    // SAFETY: own B.CC/MOV/RET paths are finite and memory-free; X30 is STOP.
    let outcome = unsafe { runtime.run(state, Some(GuestAddress(STOP)), 4)? };
    assert_eq!(outcome.reason, StopReason::StopAddress);
    assert_eq!(outcome.blocks_executed, 2);
    assert_state(state, &expected);
    Ok(())
}
fn runtime(cache: &std::path::Path) -> Result<BlockRuntime> {
    let mut runtime = BlockRuntime::new(0x44415257494e, cache.into());
    runtime.register_code(
        GuestAddress(BASE),
        WRITE_STUB
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect(),
    )?;
    Ok(runtime)
}

#[derive(Default)]
struct PipeBackend {
    descriptors: BTreeMap<u64, OwnedFd>,
    host_writes: usize,
}
impl PipeBackend {
    fn service(&mut self, request: &BsdRequest, memory: &OwnedMemory) -> Result<BsdCompletion> {
        ensure!(request.number == 4, "BSD service is not implemented");
        ensure!(
            !request.indirect && request.arguments().len() == 3,
            "unexpected write prototype"
        );
        let Some(descriptor) = self.descriptors.get(&request.arguments()[0]) else {
            return Ok(BsdCompletion::Error {
                errno: DARWIN_EBADF,
            });
        };
        let Ok(length) = usize::try_from(request.arguments()[2]) else {
            return Ok(BsdCompletion::Error {
                errno: DARWIN_EFAULT,
            });
        };
        let Ok(bytes) = memory.read_snapshot(request.arguments()[1], length) else {
            return Ok(BsdCompletion::Error {
                errno: DARWIN_EFAULT,
            });
        };
        self.host_writes += 1;
        // SAFETY: only an owned descriptor capability reaches libc. bytes is a
        // live private Rust copy; no unvalidated guest pointer crosses this call.
        let written =
            unsafe { libc::write(descriptor.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            let errno = match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EBADF) => DARWIN_EBADF,
                Some(libc::EFAULT) => DARWIN_EFAULT,
                other => bail!("host write errno has no explicit Darwin translation: {other:?}"),
            };
            return Ok(BsdCompletion::Error { errno });
        }
        let written = written as u64;
        Ok(BsdCompletion::Success {
            values: [written as u32, (written >> 32) as u32],
        })
    }
}

#[test]
fn translated_write_success_copies_private_bytes_and_resumes_carry_clear_path() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = runtime(cache.path())?;
    let (memory, address) = private_buffer()?;
    let (read, write) = pipe()?;
    let mut reader = File::from(read);
    let mut backend = PipeBackend::default();
    backend.descriptors.insert(GUEST_PIPE, write);
    for flags in 0..16 {
        let mut state = thread(flags, address);
        let trap = enter(&mut runtime, &mut state)?;
        let pending = PendingBsdCall::from_trap(&state, &trap, prototype())?;
        assert_eq!(pending.request().number, 4);
        assert_eq!(
            pending.request().arguments(),
            &[GUEST_PIPE, address, PAYLOAD.len() as u64]
        );
        let mut expected = state.clone();
        expected.pc = GuestAddress(BASE + 8);
        expected.registers.x[0] = PAYLOAD.len() as u64;
        expected.registers.x[1] = 0;
        expected.registers.nzcv &= !CARRY;
        let completion = backend.service(pending.request(), &memory)?;
        pending.complete(&mut state, completion)?;
        assert_state(&state, &expected);
        let mut actual = vec![0; PAYLOAD.len()];
        reader.read_exact(&mut actual)?;
        assert_eq!(actual, PAYLOAD);
        assert_eq!(memory.read_snapshot(address, PAYLOAD.len())?, PAYLOAD);
        resume(&mut runtime, &mut state, true)?;
    }
    assert_eq!(backend.host_writes, 16);
    Ok(())
}

#[test]
fn invalid_guest_capability_and_buffer_bounds_resume_darwin_errno_path() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = runtime(cache.path())?;
    let (memory, address) = private_buffer()?;
    let (_read, write) = pipe()?;
    let real_host_descriptor = write.as_raw_fd() as u64;
    let mut backend = PipeBackend::default();
    backend.descriptors.insert(GUEST_PIPE, write);
    for flags in 0..16 {
        for (descriptor, pointer, length, errno) in [
            (
                real_host_descriptor,
                address,
                PAYLOAD.len() as u64,
                DARWIN_EBADF,
            ),
            (
                GUEST_PIPE,
                address + PAYLOAD.len() as u64 - 1,
                2,
                DARWIN_EFAULT,
            ),
            (GUEST_PIPE, u64::MAX - 1, 8, DARWIN_EFAULT),
        ] {
            let mut state = thread(flags, address);
            state.registers.x[0] = descriptor;
            state.registers.x[1] = pointer;
            state.registers.x[2] = length;
            let trap = enter(&mut runtime, &mut state)?;
            let pending = PendingBsdCall::from_trap(&state, &trap, prototype())?;
            let mut expected = state.clone();
            expected.pc = GuestAddress(BASE + 8);
            expected.registers.x[0] = u64::from(errno);
            expected.registers.x[1] = 0;
            expected.registers.nzcv |= CARRY;
            let completion = backend.service(pending.request(), &memory)?;
            pending.complete(&mut state, completion)?;
            assert_state(&state, &expected);
            resume(&mut runtime, &mut state, false)?;
        }
    }
    assert_eq!(backend.host_writes, 0);
    Ok(())
}

#[test]
fn known_host_errno_is_explicitly_translated_without_host_descriptor_passthrough() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = runtime(cache.path())?;
    let (memory, address) = private_buffer()?;
    let (read, _write) = pipe()?;
    let mut backend = PipeBackend::default();
    // Deliberately give the test backend the pipe's read endpoint. libc::write
    // returns host EBADF; the service must translate it to Darwin errno9.
    backend.descriptors.insert(GUEST_PIPE, read);
    let mut state = thread(0xf, address);
    let trap = enter(&mut runtime, &mut state)?;
    let pending = PendingBsdCall::from_trap(&state, &trap, prototype())?;
    let mut expected = state.clone();
    expected.pc = GuestAddress(BASE + 8);
    expected.registers.x[0] = u64::from(DARWIN_EBADF);
    expected.registers.x[1] = 0;
    expected.registers.nzcv |= CARRY;
    let completion = backend.service(pending.request(), &memory)?;
    pending.complete(&mut state, completion)?;
    assert_state(&state, &expected);
    assert_eq!(backend.host_writes, 1);
    resume(&mut runtime, &mut state, false)?;
    Ok(())
}

#[test]
fn restart_preserves_argument_registers_clears_entry_carry_and_reexecutes_svc() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = runtime(cache.path())?;
    for flags in 0..16 {
        let mut state = thread(flags, 0x123456780000);
        let trap = enter(&mut runtime, &mut state)?;
        let pending = PendingBsdCall::from_trap(&state, &trap, prototype())?;
        let mut expected = state.clone();
        expected.registers.nzcv &= !CARRY;
        pending.complete(&mut state, BsdCompletion::Restart)?;
        assert_state(&state, &expected);
        // SAFETY: resume at exactly the registered SVC; no service or data access.
        let again = unsafe { runtime.run(&mut state, None, 1)? };
        assert_eq!(again.reason, StopReason::SynchronousTrap { trap });
        assert_state(&state, &expected);
    }
    Ok(())
}

#[test]
fn just_return_is_an_explicit_decline_with_exact_state_preserved() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = runtime(cache.path())?;
    let mut state = thread(0xf, 0x123456780000);
    let trap = enter(&mut runtime, &mut state)?;
    let pending = PendingBsdCall::from_trap(&state, &trap, prototype())?;
    let before = state.clone();
    assert!(matches!(
        pending.complete(&mut state, BsdCompletion::JustReturn),
        Err(AbiError::UnsupportedJustReturn)
    ));
    assert_state(&state, &before);
    let pending = PendingBsdCall::from_trap(&state, &trap, prototype())?;
    state.registers.x[7] ^= 0x123456789abcdef0;
    state.registers.reserved ^= 1;
    let changed = state.clone();
    assert!(matches!(
        pending.complete(&mut state, BsdCompletion::JustReturn),
        Err(AbiError::StateChanged)
    ));
    assert_state(&state, &changed);
    Ok(())
}

#[test]
fn unknown_bsd_service_declines_without_completing_or_mutating_guest_state() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime = runtime(cache.path())?;
    let unknown = [0xd28ffff0u32, 0xd4001001, 0xd65f03c0]; // Own second fixture.
    runtime.register_code(
        GuestAddress(BASE),
        unknown.iter().flat_map(|word| word.to_le_bytes()).collect(),
    )?;
    let (memory, address) = private_buffer()?;
    let mut state = thread(0xf, address);
    // SAFETY: finite own MOV/SVC code stops before executing RET.
    let outcome = unsafe { runtime.run(&mut state, None, 1)? };
    let StopReason::SynchronousTrap { trap } = outcome.reason else {
        bail!("unsupported-service fixture did not reach SVC");
    };
    let pending = PendingBsdCall::from_trap(&state, &trap, prototype())?;
    let before = state.clone();
    assert_eq!(pending.request().number, 0x7fff);
    let mut backend = PipeBackend::default();
    assert!(backend.service(pending.request(), &memory).is_err());
    assert_eq!(backend.host_writes, 0);
    assert_state(&state, &before);
    Ok(())
}

/// Optional exact-build oracle: Apple bytes and Unicorn outputs remain ignored.
/// The two original interior windows exclude PAC, exception entry and helpers.
#[test]
#[ignore = "requires STELA_DARWIN_REFERENCE with the pinned kernel formatter receipt"]
fn adapter_matches_original_macos27_formatter_windows() -> Result<()> {
    use serde_json::{Value, json};
    use stela_core::sha256;
    use std::path::Path;

    const KERNEL: &str = "ca55ea8c4c86170e870380ae5501b8b43adb2d2d3db28be4531b3040653be203";
    const CODE_PAGE: &str = "65bd00f9e8fb459f36b6a5aeb53e087c661169e977afaaa76bc997b30814630e";
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap();
    let reference_path = Path::new(&std::env::var("STELA_DARWIN_REFERENCE")?).to_path_buf();
    let reference_path = if reference_path.is_absolute() {
        reference_path
    } else {
        root.join(reference_path)
    };
    let bytes = std::fs::read(&reference_path)?;
    let reference_hash = sha256(&bytes);
    let reference: Value = serde_json::from_slice(&bytes)?;
    ensure!(reference["status"] == "passed" && reference["kernel_sha256"] == KERNEL);
    let kernel = std::fs::read(reference["kernel_path"].as_str().unwrap())?;
    ensure!(
        sha256(&kernel) == KERNEL,
        "original kernel identity changed"
    );
    ensure!(
        reference["harness_sha256"]
            == sha256(&std::fs::read(
                root.join("dev/kernel-syscall-reference.py")
            )?),
        "original reference generator identity changed"
    );
    let page = &kernel[0x362f000..0x3630000];
    ensure!(sha256(page) == CODE_PAGE && reference["code_page"]["sha256"] == CODE_PAGE);

    fn parse_state(value: &Value) -> ThreadState {
        assert_eq!(value["registers"]["x"].as_array().unwrap().len(), 31);
        let mut state = ThreadState {
            pc: GuestAddress(value["pc"].as_u64().unwrap()),
            registers: GuestState {
                x: std::array::from_fn(|index| value["registers"]["x"][index].as_u64().unwrap()),
                sp: value["registers"]["sp"].as_u64().unwrap(),
                nzcv: u32::try_from(value["registers"]["nzcv"].as_u64().unwrap()).unwrap(),
                reserved: u32::try_from(value["registers"]["reserved"].as_u64().unwrap()).unwrap(),
                // The historical integer-only reference omits SIMD/FP state.
                ..GuestState::default()
            },
        };
        if let Some(vectors) = value["registers"].get("v") {
            let vectors = vectors.as_array().unwrap();
            assert_eq!(vectors.len(), 32);
            for (destination, source) in state.registers.v.iter_mut().zip(vectors) {
                let limbs = source.as_array().unwrap();
                assert_eq!(limbs.len(), 2);
                *destination = [limbs[0].as_u64().unwrap(), limbs[1].as_u64().unwrap()];
            }
        }
        if let Some(fpcr) = value["registers"].get("fpcr") {
            state.registers.fpcr = u32::try_from(fpcr.as_u64().unwrap()).unwrap();
        }
        if let Some(fpsr) = value["registers"].get("fpsr") {
            state.registers.fpsr = u32::try_from(fpsr.as_u64().unwrap()).unwrap();
        }
        state
    }
    let mut comparisons = 0;
    for case in reference["cases"].as_array().unwrap() {
        if case["adapter_comparable"] != true {
            continue;
        }
        let return_type = match case["prototype"]["return_type"].as_str().unwrap() {
            "int" => BsdReturnType::Int,
            "unsigned_int" => BsdReturnType::UnsignedInt,
            "offset" => BsdReturnType::Offset,
            "address" => BsdReturnType::Address,
            "size" => BsdReturnType::Size,
            "signed_size" => BsdReturnType::SignedSize,
            "unsigned64" => BsdReturnType::Unsigned64,
            "none" => BsdReturnType::None,
            other => bail!("unknown original return type: {other}"),
        };
        let completion = match case["completion"]["kind"].as_str().unwrap() {
            "success" => BsdCompletion::Success {
                values: std::array::from_fn(|index| {
                    u32::try_from(case["completion"]["values"][index].as_u64().unwrap()).unwrap()
                }),
            },
            "error" => BsdCompletion::Error {
                errno: u32::try_from(case["completion"]["errno"].as_u64().unwrap())?,
            },
            other => bail!("noncomparable original completion: {other}"),
        };
        let mut state = parse_state(&case["initial_adapter_state"]);
        let trap = SynchronousTrap {
            kind: TrapKind::SupervisorCall,
            immediate: 0x80,
            instruction_pc: state.pc,
            exception_return_pc: GuestAddress(
                case["kernel_saved_pc_precondition"].as_u64().unwrap(),
            ),
        };
        let pending = PendingBsdCall::from_trap(
            &state,
            &trap,
            BsdPrototype {
                argument_count: usize::try_from(
                    case["prototype"]["argument_count"].as_u64().unwrap(),
                )?,
                return_type,
            },
        )?;
        pending.complete(&mut state, completion)?;
        assert_state(&state, &parse_state(&case["original_observed_state"]));
        comparisons += 1;
    }
    assert_eq!(comparisons, 1920);
    let report = json!({
        "kind":"darwin_bsd_adapter_vs_original_kernel_formatter", "passed":true,
        "reference_sha256":reference_hash, "kernel_sha256":KERNEL,
        "full_state_comparisons":comparisons,
        "source_sha256": {
            "crates/stela-runtime/src/darwin.rs":sha256(&std::fs::read(root.join("crates/stela-runtime/src/darwin.rs"))?),
            "crates/stela-runtime/tests/darwin_syscalls.rs":sha256(include_bytes!("darwin_syscalls.rs"))
        },
        "test_executable_sha256":sha256(&std::fs::read(std::env::current_exe()?)?),
        "limits":"Two unchanged bounded kernel code windows in Unicorn versus ABI completion. No complete kernel syscall, PAC, exception entry, context restoration or restart-helper execution."
    });
    let mut output = serde_json::to_vec_pretty(&report)?;
    output.push(b'\n');
    let directory = root.join(".stela/evidence/darwin-formatter");
    std::fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{}.json", sha256(&output)));
    if path.exists() {
        ensure!(
            std::fs::read(&path)? == output,
            "formatter evidence archive identity mismatch"
        );
    } else {
        std::fs::write(&path, output)?;
    }
    println!(
        "{}",
        json!({"passed":true,"full_state_comparisons":comparisons,"report":path})
    );
    Ok(())
}

fn vm_buffer(writable: bool) -> Result<(OwnedMemory, u64)> {
    let address = NEXT_BUFFER.fetch_add(0x10000, Ordering::Relaxed);
    let memory = OwnedMemory::map(vec![MemoryRegionSpec {
        guest_address: address,
        virtual_bytes: 32768,
        initial_bytes: vec![7, 8, 9],
        readable: true,
        writable,
        executable: false,
    }])?;
    Ok((memory, address))
}
fn vm_runtime(cache: &std::path::Path, base: u64, words: &[u32]) -> Result<BlockRuntime> {
    let mut runtime = BlockRuntime::new(0x44415257494e, cache.into());
    runtime.register_code(
        GuestAddress(base),
        words.iter().flat_map(|w| w.to_le_bytes()).collect(),
    )?;
    Ok(runtime)
}
#[test]
fn data_vm_service_preserves_full_state_and_guest_page_rounding_on_success_and_errors() -> Result<()>
{
    use stela_runtime::darwin::{ExecutionServices, run_data_vm};
    let cache = tempfile::tempdir()?;
    for flags in 0..16 {
        for indirect in [false, true] {
            for case in 0..7 {
                let (mut memory, address) = vm_buffer(case != 2)?;
                let mut state = thread(flags, address);
                state.registers.x[30] = STOP;
                let (target, length, prot, errno) = match case {
                    0 => (address, 1, 1, 0), // One byte protects a complete guest16KiB page.
                    1 => (address, 1, 2, 0), // Darwin write implies read.
                    2 => (address, 1, 3, 13),
                    3 => (address + 1, 1, 1, 22),
                    4 => (address + 0x8000, 1, 1, 12),
                    5 => (address, 0, 1, 0),
                    _ => (address, u64::MAX, 1, 22),
                };
                state.registers.x[16] = if indirect { 0 } else { 74 };
                if indirect {
                    state.registers.x[0] = 74;
                    state.registers.x[1] = target;
                    state.registers.x[2] = length;
                    state.registers.x[3] = prot;
                } else {
                    state.registers.x[0] = target;
                    state.registers.x[1] = length;
                    state.registers.x[2] = prot;
                }
                let initial = state.clone();
                let mut expected = initial.clone();
                expected.pc = GuestAddress(STOP);
                expected.registers.x[0] = errno;
                expected.registers.x[1] = 0;
                expected.registers.nzcv =
                    (expected.registers.nzcv & !CARRY) | if errno == 0 { 0 } else { CARRY };
                let mut runtime = vm_runtime(cache.path(), BASE, &[0xd4001001, 0xd65f03c0])?;
                // SAFETY: original-style SVC/RET fixture never accesses guest RAM
                // directly; the explicit service validates the exclusively owned pages.
                let result = unsafe {
                    run_data_vm(
                        &mut runtime,
                        &mut state,
                        Some(GuestAddress(STOP)),
                        2,
                        &mut memory,
                        ExecutionServices::default(),
                    )?
                };
                assert_state(&state, &expected);
                assert_eq!(result.execution.reason, StopReason::StopAddress);
                assert_eq!(result.execution.blocks_executed, 2);
                assert_eq!(result.services.len(), 1);
                assert!(
                    result.services[0].completion.is_some()
                        && result.services[0].declined.is_none()
                );
                assert_eq!(memory.read_snapshot(address, 3)?, [7, 8, 9]);
                if case == 0 {
                    assert!(!memory.regions()[0].writable);
                    assert_eq!(memory.regions()[0].virtual_bytes, 16384);
                    assert!(memory.regions()[1].writable);
                } else {
                    assert_eq!(memory.regions()[0].writable, case != 2);
                }
            }
        }
    }
    Ok(())
}
#[test]
fn data_vm_driver_reuses_aot_and_resumes_services_under_one_native_budget() -> Result<()> {
    use stela_runtime::darwin::{ExecutionServices, run_data_vm};
    let cache = tempfile::tempdir()?;
    let (mut memory, address) = vm_buffer(true)?;
    let words = [
        0xaa1403e0, 0xaa1503e1, 0x52800022, 0xd2800950, 0xd4001001, 0xaa1403e0, 0xaa1503e1,
        0x52800062, 0xd2800950, 0xd4001001, 0xd65f03c0,
    ];
    let mut runtime = vm_runtime(cache.path(), BASE, &words)?;
    for pc in [BASE, BASE + 20, BASE + 40] {
        runtime.prepare(GuestAddress(pc))?;
    }
    let mut state = thread(15, address);
    state.registers.x[20] = address;
    state.registers.x[21] = 1;
    // SAFETY: these native instructions only select call arguments and return;
    // protection services own/validate all data, with no concurrent execution.
    let first = unsafe {
        run_data_vm(
            &mut runtime,
            &mut state,
            Some(GuestAddress(STOP)),
            1,
            &mut memory,
            ExecutionServices::default(),
        )?
    };
    assert_eq!(first.execution.reason, StopReason::BudgetExhausted);
    assert_eq!(state.pc, GuestAddress(BASE + 20));
    assert_eq!(first.services.len(), 1);
    assert!(!memory.regions()[0].writable);
    let second = unsafe {
        run_data_vm(
            &mut runtime,
            &mut state,
            Some(GuestAddress(STOP)),
            2,
            &mut memory,
            ExecutionServices::default(),
        )?
    };
    assert_eq!(second.execution.reason, StopReason::StopAddress);
    assert_eq!(second.execution.blocks_executed, 2);
    assert_eq!(second.services.len(), 1);
    assert!(memory.regions()[0].writable);
    assert_eq!(
        first.execution.compiled_blocks + second.execution.compiled_blocks,
        0
    );
    assert_eq!(
        first.execution.disk_cache_hits + second.execution.disk_cache_hits,
        3
    );
    state.pc = GuestAddress(BASE);
    let warm = unsafe {
        run_data_vm(
            &mut runtime,
            &mut state,
            Some(GuestAddress(STOP)),
            3,
            &mut memory,
            ExecutionServices::default(),
        )?
    };
    assert_eq!(warm.services.len(), 2);
    assert_eq!(warm.execution.blocks_executed, 3);
    assert_eq!(warm.execution.memory_cache_hits, 3);
    Ok(())
}
#[test]
fn unsupported_vm_services_and_registered_code_aliases_preserve_pending_state() -> Result<()> {
    use stela_runtime::darwin::{ExecutionServices, run_data_vm};
    let cache = tempfile::tempdir()?;
    for case in 0..4 {
        let (mut memory, address) = vm_buffer(true)?;
        let base = if case == 3 { address } else { BASE };
        let mut runtime = vm_runtime(cache.path(), base, &[0xd4001001, 0xd65f03c0])?;
        let mut state = thread(15, address);
        state.pc = GuestAddress(base);
        state.registers.x[16] = if case == 0 { 20 } else { 74 };
        state.registers.x[0] = address;
        state.registers.x[1] = 16384;
        state.registers.x[2] = match case {
            1 => 4,
            2 => 0x10,
            _ => 1,
        };
        let initial = state.clone();
        let old = memory.regions().to_vec();
        // SAFETY: SVC/RET accesses no data; all requested transitions are declined.
        let result = unsafe {
            run_data_vm(
                &mut runtime,
                &mut state,
                Some(GuestAddress(STOP)),
                8,
                &mut memory,
                ExecutionServices::default(),
            )?
        };
        assert_state(&state, &initial);
        assert!(matches!(
            result.execution.reason,
            StopReason::SynchronousTrap { .. }
        ));
        assert_eq!(result.execution.blocks_executed, 1);
        assert_eq!(result.services.len(), 1);
        assert!(result.services[0].completion.is_none() && result.services[0].declined.is_some());
        assert_eq!(memory.regions(), old);
        assert_eq!(memory.read_snapshot(address, 3)?, [7, 8, 9]);
    }
    Ok(())
}

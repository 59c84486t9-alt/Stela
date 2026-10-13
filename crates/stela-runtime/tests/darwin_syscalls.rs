//! Owned-code integration of native SVC boundaries and explicit BSD completion.
//! The pipe service below is a test backend, not a Darwin syscall implementation.
#![cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]

use anyhow::{Result, bail, ensure};
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicU64, Ordering},
};
use stela_compiler::{
    GuestAddress, GuestState,
    block::{SynchronousTrap, TrapKind},
};
use stela_runtime::{
    blocks::{BlockRuntime, StopReason, ThreadState},
    darwin::{AbiError, BsdCompletion, BsdPrototype, BsdRequest, BsdReturnType, PendingBsdCall},
    memory::{MemoryRegionSpec, OwnedMemory},
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
    use std::path::Path;
    use stela_core::sha256;

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

#[cfg(target_os = "macos")]
mod native_thread_services {
    use super::*;
    use stela_compiler::block::BlockProfile;
    use stela_runtime::{
        clock,
        darwin::{ExecutionServices, ServiceRunOutcome, platform, run_services},
        mach::{self, HostPorts},
        memory::DIRECT_RAM_USER_END,
        pauth,
        thread::{self as guest_thread, Context, VmMaximum},
    };

    const SVC_DARWIN: u32 = 0xd4001001;
    const RET_X30: u32 = 0xd65f03c0;
    const INSTRUCTION_BYTES: u64 = 4;
    const SELECTOR_REGISTER: usize = 16;
    const SUBCODE_REGISTER: usize = 3;
    const NZCV_COMBINATIONS: u32 = 16;
    const UNALIGNED_VM_MAXIMUM: u64 = 0x12345;
    const CURRENT_HOST_THREAD: libc::pthread_t = 0;
    const TLS_SENTINEL_VALUE: u64 = 0x123456789abcdef0;
    const ADDRESS_SPACE_ID: u64 = 0x44415257494e;
    const MRS_TPIDRRO_EL0: u32 = 0xd53bd060;
    const MRS_TPIDR_EL0: u32 = 0xd53bd040;
    const MSR_TPIDRRO_EL0: u32 = 0xd51bd060;
    const ZERO_REGISTER: u32 = 31;
    const LINK_REGISTER: u32 = 30;
    const READBACK_REGISTER: u32 = 8;
    const MOV_X7_42: u32 = 0xd2800547;
    const PREFIX_REGISTER: usize = 7;
    const PREFIX_VALUE: u64 = 42;
    const MRS_CNTVCT_EL0_X9: u32 = 0xd53be049;

    struct HostTlsSentinel {
        key: libc::pthread_key_t,
        value: Box<u64>,
    }
    impl HostTlsSentinel {
        fn new() -> Result<Self> {
            let mut key = 0;
            // SAFETY: key is a valid out-pointer; no destructor is needed for
            // the separately owned Box, released after this private key.
            ensure!(unsafe { libc::pthread_key_create(&mut key, None) } == 0);
            let sentinel = Self {
                key,
                value: Box::new(TLS_SENTINEL_VALUE),
            };
            // SAFETY: the Box pointer is stable throughout the private key's
            // lifetime; the host never owns or frees the pointed-to value.
            ensure!(
                unsafe {
                    libc::pthread_setspecific(
                        key,
                        std::ptr::from_ref(sentinel.value.as_ref()).cast(),
                    )
                } == 0
            );
            Ok(sentinel)
        }
        fn assert_unchanged(&self) {
            // SAFETY: this test owns a live key on the same host thread.
            let actual = unsafe { libc::pthread_getspecific(self.key) };
            assert_eq!(
                actual.cast_const(),
                std::ptr::from_ref(self.value.as_ref()).cast()
            );
            assert_eq!(*self.value, TLS_SENTINEL_VALUE);
        }
    }
    impl Drop for HostTlsSentinel {
        fn drop(&mut self) {
            // SAFETY: this test uniquely owns the key, deleted before Box drop.
            assert_eq!(unsafe { libc::pthread_key_delete(self.key) }, 0);
        }
    }

    fn host_identity() -> Result<(libc::pthread_t, u64)> {
        let mut identifier = 0;
        // SAFETY: the zero thread selects the current host thread, and identifier
        // is a valid writable u64. pthread_self neither transfers nor mutates TLS.
        let (handle, status) = unsafe {
            (
                libc::pthread_self(),
                libc::pthread_threadid_np(CURRENT_HOST_THREAD, &mut identifier),
            )
        };
        ensure!(
            status == 0 && identifier != 0,
            "host pthread identity failed"
        );
        Ok((handle, identifier))
    }

    fn run(
        runtime: &mut BlockRuntime,
        state: &mut ThreadState,
        context: &mut Context,
        budget: usize,
    ) -> Result<ServiceRunOutcome> {
        let mut memory = OwnedMemory::map(Vec::new())?;
        // SAFETY: fixtures are immutable owned SVC/MRS/RET code without loads or
        // stores. Services store numeric guest TSD values without dereferencing.
        unsafe {
            run_services(
                runtime,
                state,
                Some(GuestAddress(STOP)),
                budget,
                &mut memory,
                ExecutionServices {
                    thread: Some(context),
                    ..ExecutionServices::default()
                },
            )
        }
    }

    fn thread_register_runtime(cache: &std::path::Path, words: &[u32]) -> Result<BlockRuntime> {
        let mut runtime = BlockRuntime::new_with_profile(
            ADDRESS_SPACE_ID,
            cache.into(),
            BlockProfile::DarwinArm64ThreadV1,
        );
        runtime.register_code(
            GuestAddress(BASE),
            words.iter().flat_map(|word| word.to_le_bytes()).collect(),
        )?;
        Ok(runtime)
    }

    fn platform_set_state(flags: u32, address: u64) -> ThreadState {
        let mut state = thread(flags, address);
        state.registers.x[0] = address;
        state.registers.x[SELECTOR_REGISTER] = u64::from(platform::PLATFORM_CALL_SELECTOR as u32);
        state.registers.x[SUBCODE_REGISTER] = u64::from(platform::SET_THREAD_SPECIFIC_DATA);
        state
    }

    #[test]
    fn platform_set_then_thread_register_read_preserves_full_state_and_host_tls() -> Result<()> {
        let cache = tempfile::tempdir()?;
        let identity = host_identity()?;
        let tls = HostTlsSentinel::new()?;
        for destination in 0..=ZERO_REGISTER {
            let mut runtime = thread_register_runtime(
                cache.path(),
                &[SVC_DARWIN, MRS_TPIDRRO_EL0 | destination, RET_X30],
            )?;
            for maximum in [UNALIGNED_VM_MAXIMUM, DIRECT_RAM_USER_END] {
                let mut context =
                    Context::native(runtime.address_space(), VmMaximum::new(maximum)?)?;
                for flags in 0..NZCV_COMBINATIONS {
                    for address in [0, 1, maximum - 1, maximum, maximum + 1, u64::MAX] {
                        let value = if address > maximum { 0 } else { address };
                        let mut state = platform_set_state(flags, address);
                        let mut expected = state.clone();
                        expected.pc = GuestAddress(BASE + 2 * INSTRUCTION_BYTES);
                        if destination != ZERO_REGISTER {
                            expected.registers.x[destination as usize] = value;
                        }
                        let outcome = run(&mut runtime, &mut state, &mut context, 2)?;
                        assert_state(&state, &expected);
                        assert_eq!(outcome.execution.reason, StopReason::BudgetExhausted);
                        assert_eq!(outcome.execution.blocks_executed, 2);
                        assert_eq!(outcome.thread_services.len(), 1);
                        assert!(outcome.thread_services[0].completed());
                        assert_eq!(outcome.execution.thread_register_events.len(), 1);
                        let event = &outcome.execution.thread_register_events[0];
                        assert_eq!(event.instruction.destination, destination as u8);
                        assert_eq!(
                            event.instruction.instruction_pc,
                            GuestAddress(BASE + INSTRUCTION_BYTES)
                        );
                        assert_eq!(event.instruction.next_pc, expected.pc);
                        assert_eq!(event.next_pc, expected.pc);
                        assert_eq!(event.value, value);
                        assert_eq!(context.thread_specific_data(), value);
                        if destination != LINK_REGISTER {
                            expected.pc = GuestAddress(STOP);
                            let returned = run(&mut runtime, &mut state, &mut context, 1)?;
                            assert_state(&state, &expected);
                            assert_eq!(returned.execution.reason, StopReason::StopAddress);
                            assert!(returned.execution.thread_register_events.is_empty());
                        }
                        tls.assert_unchanged();
                    }
                }
            }
        }
        assert_eq!(host_identity()?, identity);
        Ok(())
    }

    #[test]
    fn thread_register_reads_live_context_across_budget_resume_and_disk_cache() -> Result<()> {
        let cache = tempfile::tempdir()?;
        let words = [SVC_DARWIN, MRS_TPIDRRO_EL0 | READBACK_REGISTER, RET_X30];
        let mut runtime = thread_register_runtime(cache.path(), &words)?;
        for offset in [0, INSTRUCTION_BYTES, 2 * INSTRUCTION_BYTES] {
            runtime.prepare(GuestAddress(BASE + offset))?;
        }
        let mut context = Context::native(
            runtime.address_space(),
            VmMaximum::new(DIRECT_RAM_USER_END)?,
        )?;
        let mut state = platform_set_state(15, DIRECT_RAM_USER_END);
        let initial = state.clone();
        let zero = run(&mut runtime, &mut state, &mut context, 0)?;
        assert_eq!(zero.execution.reason, StopReason::BudgetExhausted);
        assert_eq!(zero.execution.blocks_executed, 0);
        assert!(
            zero.thread_services.is_empty() && zero.execution.thread_register_events.is_empty()
        );
        assert_eq!(context.thread_specific_data(), 0);
        assert_state(&state, &initial);
        let set = run(&mut runtime, &mut state, &mut context, 1)?;
        assert_eq!(set.execution.reason, StopReason::BudgetExhausted);
        assert_eq!(set.thread_services.len(), 1);
        assert!(set.execution.thread_register_events.is_empty());
        let mut expected = initial.clone();
        expected.pc = GuestAddress(BASE + INSTRUCTION_BYTES);
        assert_state(&state, &expected);
        let read = run(&mut runtime, &mut state, &mut context, 1)?;
        assert_eq!(read.execution.reason, StopReason::BudgetExhausted);
        assert_eq!(read.execution.thread_register_events.len(), 1);
        expected.pc = GuestAddress(BASE + 2 * INSTRUCTION_BYTES);
        expected.registers.x[READBACK_REGISTER as usize] = DIRECT_RAM_USER_END;
        assert_state(&state, &expected);
        let returned = run(&mut runtime, &mut state, &mut context, 1)?;
        expected.pc = GuestAddress(STOP);
        assert_state(&state, &expected);
        assert_eq!(returned.execution.reason, StopReason::StopAddress);
        assert_eq!(
            set.execution.disk_cache_hits
                + read.execution.disk_cache_hits
                + returned.execution.disk_cache_hits,
            3
        );
        for value in [1, DIRECT_RAM_USER_END - 1] {
            state = platform_set_state(15, value);
            expected = state.clone();
            expected.pc = GuestAddress(STOP);
            expected.registers.x[READBACK_REGISTER as usize] = value;
            let warm = run(&mut runtime, &mut state, &mut context, 3)?;
            assert_state(&state, &expected);
            assert_eq!(warm.execution.memory_cache_hits, 3);
            assert_eq!(warm.execution.thread_register_events[0].value, value);
        }
        drop(runtime);
        let mut fresh = thread_register_runtime(cache.path(), &words)?;
        state = platform_set_state(15, UNALIGNED_VM_MAXIMUM);
        expected = state.clone();
        expected.pc = GuestAddress(STOP);
        expected.registers.x[READBACK_REGISTER as usize] = UNALIGNED_VM_MAXIMUM;
        let cached = run(&mut fresh, &mut state, &mut context, 3)?;
        assert_state(&state, &expected);
        assert_eq!(cached.execution.disk_cache_hits, 3);
        assert_eq!(cached.execution.compiled_blocks, 0);
        assert_eq!(
            cached.execution.thread_register_events[0].value,
            UNALIGNED_VM_MAXIMUM
        );
        Ok(())
    }

    #[test]
    fn thread_register_missing_or_foreign_context_stops_before_register_effects() -> Result<()> {
        let cache = tempfile::tempdir()?;
        for destination in [READBACK_REGISTER, ZERO_REGISTER] {
            let mut runtime = thread_register_runtime(
                cache.path(),
                &[MOV_X7_42, MRS_TPIDRRO_EL0 | destination, RET_X30],
            )?;
            let mut state = thread(15, 1);
            let before = state.clone();
            let foreign = Context::native(
                runtime.address_space() + 1,
                VmMaximum::new(DIRECT_RAM_USER_END)?,
            )?;
            // SAFETY: foreign ownership must fail before the prefix executes.
            let result = unsafe {
                runtime.run_with_thread(
                    &mut state,
                    Some(GuestAddress(STOP)),
                    1,
                    &foreign,
                    None,
                    None,
                )
            };
            assert!(result.is_err());
            assert_state(&state, &before);
            // SAFETY: owned MOV/MRS/RET accesses no RAM. Missing context must
            // preserve the executed prefix and leave even an XZR read pending.
            let missing = unsafe { runtime.run(&mut state, Some(GuestAddress(STOP)), 1)? };
            let StopReason::ThreadRegisterRequired { instruction } = missing.reason else {
                bail!("thread register read did not request its owning context");
            };
            let mut expected = before;
            expected.pc = GuestAddress(BASE + INSTRUCTION_BYTES);
            expected.registers.x[PREFIX_REGISTER] = PREFIX_VALUE;
            assert_eq!(instruction.destination, destination as u8);
            assert_eq!(instruction.instruction_pc, expected.pc);
            assert_eq!(
                instruction.next_pc,
                GuestAddress(BASE + 2 * INSTRUCTION_BYTES)
            );
            assert_eq!(missing.blocks_executed, 1);
            assert!(missing.thread_register_events.is_empty());
            assert_state(&state, &expected);
            let context = Context::native(
                runtime.address_space(),
                VmMaximum::new(DIRECT_RAM_USER_END)?,
            )?;
            // SAFETY: read-only context and immutable MRS/RET access no RAM.
            let resumed = unsafe {
                runtime.run_with_thread(
                    &mut state,
                    Some(GuestAddress(STOP)),
                    2,
                    &context,
                    None,
                    None,
                )?
            };
            expected.pc = GuestAddress(STOP);
            if destination != ZERO_REGISTER {
                expected.registers.x[destination as usize] = 0;
            }
            assert_state(&state, &expected);
            assert_eq!(resumed.reason, StopReason::StopAddress);
            assert_eq!(resumed.thread_register_events.len(), 1);
        }
        Ok(())
    }

    #[test]
    fn thread_register_optional_services_validate_before_prefix_effects() -> Result<()> {
        let cache = tempfile::tempdir()?;
        let foreign = ADDRESS_SPACE_ID + 1;
        for (profile, pauth_owner, clock_owner) in [
            (BlockProfile::Ordinary, None, None),
            (
                BlockProfile::DarwinArm64ThreadV1,
                Some(ADDRESS_SPACE_ID),
                None,
            ),
            (
                BlockProfile::AppleArm64eSoftwarePauthThreadV1,
                Some(foreign),
                None,
            ),
            (
                BlockProfile::AppleArm64eSoftwarePauthClockThreadV1,
                Some(ADDRESS_SPACE_ID),
                Some(foreign),
            ),
            (
                BlockProfile::AppleArm64eSoftwarePauthClockThreadV1,
                None,
                Some(ADDRESS_SPACE_ID),
            ),
            (
                BlockProfile::AppleArm64eSoftwarePauthThreadV1,
                Some(ADDRESS_SPACE_ID),
                Some(ADDRESS_SPACE_ID),
            ),
        ] {
            let mut runtime =
                BlockRuntime::new_with_profile(ADDRESS_SPACE_ID, cache.path().into(), profile);
            runtime.register_code(
                GuestAddress(BASE),
                [MOV_X7_42, MRS_TPIDRRO_EL0 | READBACK_REGISTER, RET_X30]
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect(),
            )?;
            let context = Context::native(ADDRESS_SPACE_ID, VmMaximum::new(DIRECT_RAM_USER_END)?)?;
            let keys = pauth_owner
                .map(|owner| pauth::Context::new(owner, pauth::Keys::from_ib_words(1, 2)));
            let mut clock = clock_owner
                .map(|owner| {
                    clock::Context::new(
                        owner,
                        Box::new(clock::ReplaySource::new(vec![clock::Snapshot {
                            counter: 100,
                            sleep_ticks: 10,
                        }])?),
                    )
                })
                .transpose()?;
            let page = clock
                .as_ref()
                .map(|clock| clock.snapshot_bytes(0, clock::GUEST_BYTES))
                .transpose()?;
            let mut state = thread(15, 1);
            let before = state.clone();
            // SAFETY: optional profile/ownership validation must reject every
            // listed combination before immutable memory-free code executes.
            let result = unsafe {
                runtime.run_with_thread(
                    &mut state,
                    Some(GuestAddress(STOP)),
                    3,
                    &context,
                    keys.as_ref(),
                    clock.as_mut(),
                )
            };
            assert!(result.is_err());
            assert_state(&state, &before);
            if let Some(clock) = clock {
                assert_eq!(clock.events().len(), 1);
                assert_eq!(Some(clock.snapshot_bytes(0, clock::GUEST_BYTES)?), page);
            }
        }
        let mut runtime = BlockRuntime::new_with_profile(
            ADDRESS_SPACE_ID,
            cache.path().into(),
            BlockProfile::AppleArm64eSoftwarePauthClockThreadV1,
        );
        runtime.register_code(
            GuestAddress(BASE),
            [MOV_X7_42, MRS_CNTVCT_EL0_X9, RET_X30]
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect(),
        )?;
        let context = Context::native(ADDRESS_SPACE_ID, VmMaximum::new(DIRECT_RAM_USER_END)?)?;
        let keys = pauth::Context::new(ADDRESS_SPACE_ID, pauth::Keys::from_ib_words(1, 2));
        let mut state = thread(15, 1);
        let mut expected = state.clone();
        expected.registers.x[PREFIX_REGISTER] = PREFIX_VALUE;
        expected.pc = GuestAddress(BASE + INSTRUCTION_BYTES);
        // SAFETY: a missing optional clock leaves the genuine counter helper
        // pending after the memory-free prefix, preserving all other state.
        let result = unsafe {
            runtime.run_with_thread(
                &mut state,
                Some(GuestAddress(STOP)),
                1,
                &context,
                Some(&keys),
                None,
            )?
        };
        assert!(matches!(result.reason, StopReason::ClockRequired { .. }));
        assert_state(&state, &expected);
        assert!(result.clock_events.is_empty() && result.thread_register_events.is_empty());
        Ok(())
    }

    #[test]
    fn unsupported_thread_register_and_read_only_write_remain_explicit() -> Result<()> {
        let cache = tempfile::tempdir()?;
        for instruction in [MRS_TPIDR_EL0, MSR_TPIDRRO_EL0] {
            let mut runtime =
                thread_register_runtime(cache.path(), &[instruction | READBACK_REGISTER, RET_X30])?;
            let mut context = Context::native(
                runtime.address_space(),
                VmMaximum::new(DIRECT_RAM_USER_END)?,
            )?;
            let mut state = thread(15, 1);
            let before = state.clone();
            let snapshot = context.snapshot();
            let outcome = run(&mut runtime, &mut state, &mut context, 2)?;
            assert!(matches!(
                outcome.execution.reason,
                StopReason::Unsupported { .. }
            ));
            assert_eq!(outcome.execution.blocks_executed, 0);
            assert!(
                outcome.thread_services.is_empty()
                    && outcome.execution.thread_register_events.is_empty()
            );
            assert_eq!(context.snapshot(), snapshot);
            assert_state(&state, &before);
        }
        Ok(())
    }

    #[test]
    fn native_identity_matches_owned_thread_right_and_preserves_host_tls() -> Result<()> {
        let cache = tempfile::tempdir()?;
        let mut runtime = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, RET_X30])?;
        let before = host_identity()?;
        let mut context = Context::native(
            runtime.address_space(),
            VmMaximum::new(DIRECT_RAM_USER_END)?,
        )?;
        assert_eq!(context.snapshot().thread_id, before.1);
        assert_eq!(context.snapshot().thread_specific_data, 0);
        assert!(context.ports().rights().is_empty());
        let request = mach::Request {
            number: mach::THREAD_SELF_TRAP,
            arguments: Vec::new(),
        };
        let first = context.ports_mut().request(&request)? as u32;
        let repeated = context.ports_mut().request(&request)? as u32;
        assert_eq!(first, repeated);
        assert_eq!(context.ports().thread_identifier(first)?, before.1);
        assert_eq!(context.ports().rights()[0].references, 2);
        let task = context.ports_mut().request(&mach::Request {
            number: mach::TASK_SELF_TRAP,
            arguments: Vec::new(),
        })? as u32;
        assert!(context.ports().thread_identifier(task).is_err());
        assert!(context.ports().thread_identifier(u32::MAX).is_err());
        for flags in 0..NZCV_COMBINATIONS {
            for selector in [
                u64::from(guest_thread::THREAD_SELFID_SYSCALL),
                0xfeedface00000000 | u64::from(guest_thread::THREAD_SELFID_SYSCALL),
                0,
            ] {
                let mut state = thread(flags, 1);
                state.registers.x[SELECTOR_REGISTER] = selector;
                if selector == 0 {
                    state.registers.x[0] = u64::from(guest_thread::THREAD_SELFID_SYSCALL);
                }
                let mut expected = state.clone();
                expected.pc = GuestAddress(STOP);
                expected.registers.x[0] = before.1;
                expected.registers.x[1] = 0;
                expected.registers.nzcv &= !CARRY;
                let outcome = run(&mut runtime, &mut state, &mut context, 2)?;
                assert_state(&state, &expected);
                assert_eq!(outcome.execution.reason, StopReason::StopAddress);
                assert_eq!(outcome.thread_services.len(), 1);
                let guest_thread::Event::Identity(event) = &outcome.thread_services[0] else {
                    bail!("identity call was routed to another service");
                };
                assert!(event.completion.is_some() && event.declined.is_none());
                assert!(event.request.unwrap().arguments().is_empty());
                assert_eq!(context.snapshot().thread_id, before.1);
            }
        }
        assert_eq!(host_identity()?, before);
        Ok(())
    }

    #[test]
    fn platform_set_get_preserves_complete_state_without_guest_mapping_or_alignment() -> Result<()>
    {
        let cache = tempfile::tempdir()?;
        let mut runtime = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, RET_X30])?;
        let before = host_identity()?;
        let tls = HostTlsSentinel::new()?;
        for maximum in [UNALIGNED_VM_MAXIMUM, DIRECT_RAM_USER_END] {
            let mut context = Context::native(runtime.address_space(), VmMaximum::new(maximum)?)?;
            for flags in 0..NZCV_COMBINATIONS {
                for upper in [0, u32::MAX] {
                    for address in [0, 1, maximum - 1, maximum, maximum + 1, u64::MAX] {
                        let sanitized = if address > maximum { 0 } else { address };
                        for subcode in [
                            platform::SET_THREAD_SPECIFIC_DATA,
                            platform::GET_THREAD_SPECIFIC_DATA,
                        ] {
                            let mut state = thread(flags, 1);
                            state.registers.x[0] = address;
                            state.registers.x[SELECTOR_REGISTER] = (u64::from(upper) << 32)
                                | u64::from(platform::PLATFORM_CALL_SELECTOR as u32);
                            state.registers.x[SUBCODE_REGISTER] =
                                (u64::from(upper) << 32) | u64::from(subcode);
                            let mut expected = state.clone();
                            expected.pc = GuestAddress(STOP);
                            if subcode == platform::GET_THREAD_SPECIFIC_DATA {
                                expected.registers.x[0] = sanitized;
                            }
                            let outcome = run(&mut runtime, &mut state, &mut context, 2)?;
                            assert_state(&state, &expected);
                            assert_eq!(outcome.execution.reason, StopReason::StopAddress);
                            assert_eq!(outcome.thread_services.len(), 1);
                            assert!(outcome.thread_services[0].completed());
                            assert!(
                                outcome.services.is_empty() && outcome.mach_services.is_empty()
                            );
                            assert_eq!(context.snapshot().thread_specific_data, sanitized);
                            tls.assert_unchanged();
                        }
                    }
                }
            }
        }
        assert_eq!(host_identity()?, before);
        Ok(())
    }

    #[test]
    fn unsupported_calls_and_context_mismatches_leave_precise_pending_state() -> Result<()> {
        let cache = tempfile::tempdir()?;
        let mut runtime = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, RET_X30])?;
        let mut context = Context::native(
            runtime.address_space(),
            VmMaximum::new(DIRECT_RAM_USER_END)?,
        )?;
        for (selector, subcode) in [
            (20, 0),
            (u64::from(platform::PLATFORM_CALL_SELECTOR as u32), 0),
            (u64::from(platform::PLATFORM_CALL_SELECTOR as u32), 1),
            (u64::from(platform::PLATFORM_CALL_SELECTOR as u32), u64::MAX),
        ] {
            let mut state = thread(15, 1);
            state.registers.x[SELECTOR_REGISTER] = selector;
            state.registers.x[SUBCODE_REGISTER] = subcode;
            let before = state.clone();
            let snapshot = context.snapshot();
            let outcome = run(&mut runtime, &mut state, &mut context, 8)?;
            assert_state(&state, &before);
            assert!(matches!(
                outcome.execution.reason,
                StopReason::SynchronousTrap { .. }
            ));
            assert_eq!(outcome.execution.blocks_executed, 1);
            assert_eq!(context.snapshot(), snapshot);
            assert_eq!(outcome.thread_services.len(), usize::from(selector != 20));
            assert!(
                outcome
                    .thread_services
                    .iter()
                    .all(|event| !event.completed())
            );
        }
        for foreign in [false, true] {
            let owner = runtime.address_space() + u64::from(foreign);
            let mut context = Context::native(owner, VmMaximum::new(DIRECT_RAM_USER_END)?)?;
            let mut ports = HostPorts::new(runtime.address_space())?;
            let mut memory = OwnedMemory::map(Vec::new())?;
            let mut state = thread(15, 1);
            let before = state.clone();
            // SAFETY: validation must reject either foreign ownership or two
            // independent port owners before any immutable fixture executes.
            let outcome = unsafe {
                run_services(
                    &mut runtime,
                    &mut state,
                    Some(GuestAddress(STOP)),
                    8,
                    &mut memory,
                    ExecutionServices {
                        thread: Some(&mut context),
                        mach_ports: if foreign { None } else { Some(&mut ports) },
                        ..ExecutionServices::default()
                    },
                )
            };
            assert!(outcome.is_err());
            assert_state(&state, &before);
            assert!(context.ports().rights().is_empty() && ports.rights().is_empty());
        }
        Ok(())
    }

    #[test]
    fn budget_resume_and_fresh_disk_cache_preserve_thread_context() -> Result<()> {
        let cache = tempfile::tempdir()?;
        let mut runtime = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, SVC_DARWIN, RET_X30])?;
        for offset in [0, INSTRUCTION_BYTES, 2 * INSTRUCTION_BYTES] {
            runtime.prepare(GuestAddress(BASE + offset))?;
        }
        let mut context = Context::native(
            runtime.address_space(),
            VmMaximum::new(DIRECT_RAM_USER_END)?,
        )?;
        let mut state = thread(15, 1);
        state.registers.x[SELECTOR_REGISTER] = u64::from(guest_thread::THREAD_SELFID_SYSCALL);
        let first = run(&mut runtime, &mut state, &mut context, 1)?;
        assert_eq!(first.execution.reason, StopReason::BudgetExhausted);
        assert_eq!(first.thread_services.len(), 1);
        assert_eq!(state.pc, GuestAddress(BASE + INSTRUCTION_BYTES));
        let second = run(&mut runtime, &mut state, &mut context, 2)?;
        assert_eq!(second.execution.reason, StopReason::StopAddress);
        assert_eq!(second.execution.blocks_executed, 2);
        assert_eq!(second.thread_services.len(), 1);
        assert_eq!(
            first.execution.compiled_blocks + second.execution.compiled_blocks,
            0
        );
        assert_eq!(
            first.execution.disk_cache_hits + second.execution.disk_cache_hits,
            3
        );
        let warm_state = state.registers.clone();
        state.pc = GuestAddress(BASE);
        let warm = run(&mut runtime, &mut state, &mut context, 3)?;
        assert_eq!(warm.execution.memory_cache_hits, 3);
        assert_eq!(warm.thread_services.len(), 2);
        assert_eq!(state.registers, warm_state);
        drop(runtime);
        let mut fresh = vm_runtime(cache.path(), BASE, &[SVC_DARWIN, SVC_DARWIN, RET_X30])?;
        state.pc = GuestAddress(BASE);
        let cached = run(&mut fresh, &mut state, &mut context, 3)?;
        assert_eq!(cached.execution.disk_cache_hits, 3);
        assert_eq!(cached.execution.compiled_blocks, 0);
        assert_eq!(state.registers, warm_state);
        Ok(())
    }
}

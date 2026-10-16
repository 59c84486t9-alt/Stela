//! `getentropy` from host entropy (XNU `bsd/dev/random/randomdev.c`).
//! Oversized requests return EINVAL; a host failure returns EIO.

use super::{
    BsdCompletion, BsdPrototype, BsdReturnType, BsdServiceEvent, PendingBsdCall, classify_bsd_call,
    copyout,
};
use crate::{blocks::ThreadState, memory::OwnedMemory};
#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, string::ToString};
use anyhow::{Result, ensure};
use std::io;
use stela_compiler::block::SynchronousTrap;

pub const PROFILE_ID: &str = "darwin-host-owned-getentropy-v1";
pub const SYSCALL_NUMBER: u16 = 500;
pub const MAX_BYTES: usize = 256;

const DARWIN_EIO: u32 = 5;
const DARWIN_EFAULT: u32 = 14;
const DARWIN_EINVAL: u32 = 22;
const PROTOTYPE: BsdPrototype = BsdPrototype {
    argument_count: 2,
    return_type: BsdReturnType::Int,
};

pub fn handles(state: &ThreadState, trap: &SynchronousTrap) -> bool {
    classify_bsd_call(state, trap).is_ok_and(|selector| selector.number == SYSCALL_NUMBER)
}

/// Get fresh kernel entropy, then validate and write the whole destination.
/// Store prefixes survive supported copyout faults; ambiguous pair faults
/// decline before writing. Requires non-shared OwnedMemory.
pub fn service(
    state: &mut ThreadState,
    trap: &SynchronousTrap,
    memory: &mut OwnedMemory,
) -> BsdServiceEvent {
    service_with_source(state, trap, memory, host_entropy)
}

fn service_with_source(
    state: &mut ThreadState,
    trap: &SynchronousTrap,
    memory: &mut OwnedMemory,
    source: impl FnOnce(&mut [u8]) -> io::Result<()>,
) -> BsdServiceEvent {
    let mut event = BsdServiceEvent {
        trap: *trap,
        request: None,
        completion: None,
        declined: None,
    };
    let result = (|| -> Result<BsdCompletion> {
        ensure!(memory.is_usable(), "guest address space is unusable");
        let pending = PendingBsdCall::from_trap(state, trap, PROTOTYPE)?;
        let request = *pending.request();
        event.request = Some(request);
        ensure!(
            request.number == SYSCALL_NUMBER,
            "BSD service {} is not implemented by the entropy profile",
            request.number
        );
        let [address, size] = request.arguments() else {
            unreachable!("the validated entropy prototype contains two arguments")
        };
        let errno = if *size > MAX_BYTES as u64 {
            Some(DARWIN_EINVAL)
        } else {
            let mut buffer = [0; MAX_BYTES];
            let bytes = &mut buffer[..*size as usize];
            if source(bytes).is_err() {
                Some(DARWIN_EIO)
            } else {
                match copyout::copyout(memory, *address, bytes)? {
                    copyout::Completion::Copied => None,
                    copyout::Completion::Fault { .. } => Some(DARWIN_EFAULT),
                }
            }
        };
        let completion = errno.map_or(BsdCompletion::Success { values: [0, 0] }, |errno| {
            BsdCompletion::Error { errno }
        });
        pending.complete(state, completion)?;
        Ok(completion)
    })();
    match result {
        Ok(completion) => event.completion = Some(completion),
        Err(error) => event.declined = Some(error.to_string()),
    }
    event
}

fn host_entropy(bytes: &mut [u8]) -> io::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        // SAFETY: the buffer is local, writable and at most MAX_BYTES; no guest
        // pointer reaches the host call.
        let result = unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "host getentropy provider is unavailable",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemoryRegionSpec, host_page_size};
    use stela_compiler::{GuestAddress, GuestState, block::TrapKind};

    const NZCV_SHIFT: u32 = 28;
    const NZCV_COMBINATIONS: u32 = 16;
    const CARRY: u32 = 0x20000000;
    const SVC_IMMEDIATE: u16 = 0x80;
    const TEST_PC: u64 = 0x1000;
    const TEST_BASE: u64 = 0x6a000000000;
    const ADDRESS_ATTEMPTS: u64 = 32;
    const CANARY: u8 = 0xa5;
    const GENERATED: u8 = 0x3c;

    fn trap() -> SynchronousTrap {
        SynchronousTrap {
            kind: TrapKind::SupervisorCall,
            immediate: SVC_IMMEDIATE,
            instruction_pc: GuestAddress(TEST_PC),
            exception_return_pc: GuestAddress(TEST_PC + 4),
        }
    }

    fn memory(second_page: Option<bool>) -> OwnedMemory {
        let page = host_page_size().unwrap() as u64;
        for attempt in 0..ADDRESS_ATTEMPTS {
            let base = TEST_BASE + attempt * page * 4;
            let region = |address, writable| MemoryRegionSpec {
                guest_address: address,
                virtual_bytes: page,
                initial_bytes: vec![CANARY; page as usize],
                readable: true,
                writable,
                executable: false,
            };
            let mut regions = vec![region(base, true)];
            if let Some(writable) = second_page {
                regions.push(region(base + page, writable));
            }
            if let Ok(memory) = OwnedMemory::map(regions) {
                return memory;
            }
        }
        panic!("cannot allocate entropy fixture mapping");
    }

    fn state(indirect: bool, arguments: [u64; 2], flags: u32) -> ThreadState {
        let mut registers = GuestState {
            x: std::array::from_fn(|index| 0xdeadc0de12340000 + index as u64),
            sp: 0xfeed0000,
            nzcv: flags << NZCV_SHIFT,
            reserved: 0xa5a5,
            v: std::array::from_fn(|index| [index as u64, !(index as u64)]),
            fpcr: 17,
            fpsr: 29,
        };
        registers.x[super::super::SYSCALL_SELECTOR_REGISTER] = if indirect {
            0
        } else {
            u64::from(SYSCALL_NUMBER)
        };
        if indirect {
            registers.x[0] = u64::from(SYSCALL_NUMBER);
        }
        let start = usize::from(indirect);
        registers.x[start..start + arguments.len()].copy_from_slice(&arguments);
        ThreadState {
            registers,
            pc: trap().instruction_pc,
        }
    }

    fn assert_completion(
        memory: &mut OwnedMemory,
        indirect: bool,
        arguments: [u64; 2],
        flags: u32,
        errno: Option<u32>,
        source: impl FnOnce(&mut [u8]) -> io::Result<()>,
    ) {
        let mut state = state(indirect, arguments, flags);
        let mut expected = state.clone();
        expected.pc = trap().exception_return_pc;
        expected.registers.x[0] = u64::from(errno.unwrap_or(0));
        expected.registers.x[1] = 0;
        expected.registers.nzcv =
            (expected.registers.nzcv & !CARRY) | if errno.is_some() { CARRY } else { 0 };
        assert!(handles(&state, &trap()));
        let event = service_with_source(&mut state, &trap(), memory, source);
        assert!(event.declined.is_none());
        assert_eq!(event.request.unwrap().arguments(), arguments);
        assert_eq!(
            event.completion,
            Some(
                errno.map_or(BsdCompletion::Success { values: [0, 0] }, |errno| {
                    BsdCompletion::Error { errno }
                })
            )
        );
        assert_eq!(state.pc, expected.pc);
        assert_eq!(state.registers, expected.registers);
    }

    fn fill(bytes: &mut [u8]) -> io::Result<()> {
        bytes.fill(GENERATED);
        Ok(())
    }

    #[test]
    fn direct_and_indirect_calls_preserve_full_state_and_buffer_canaries() {
        let mut memory = memory(None);
        let base = memory.regions()[0].guest_address;
        for indirect in [false, true] {
            for flags in 0..NZCV_COMBINATIONS {
                for size in [0, 1, 128, MAX_BYTES] {
                    memory.write(base, &[CANARY; MAX_BYTES + 2]).unwrap();
                    assert_completion(
                        &mut memory,
                        indirect,
                        [base + 1, size as u64],
                        flags,
                        None,
                        fill,
                    );
                    let mut expected = vec![CANARY; MAX_BYTES + 2];
                    expected[1..1 + size].fill(GENERATED);
                    assert_eq!(
                        memory.read_snapshot(base, expected.len()).unwrap(),
                        expected
                    );
                }
            }
        }
    }

    #[test]
    fn errors_preserve_full_state_for_direct_indirect_and_all_flags() {
        let mut memory = memory(None);
        let base = memory.regions()[0].guest_address;
        for indirect in [false, true] {
            for flags in 0..NZCV_COMBINATIONS {
                assert_completion(
                    &mut memory,
                    indirect,
                    [0, 1],
                    flags,
                    Some(DARWIN_EFAULT),
                    fill,
                );
                assert_completion(
                    &mut memory,
                    indirect,
                    [base, MAX_BYTES as u64 + 1],
                    flags,
                    Some(DARWIN_EINVAL),
                    |_| panic!("oversized request reached provider"),
                );
                assert_completion(
                    &mut memory,
                    indirect,
                    [base, 1],
                    flags,
                    Some(DARWIN_EIO),
                    |bytes| {
                        bytes.fill(GENERATED);
                        Err(io::Error::from_raw_os_error(libc::EFAULT))
                    },
                );
                assert_eq!(
                    memory.read_snapshot(base, MAX_BYTES).unwrap(),
                    [CANARY; MAX_BYTES]
                );
            }
        }
    }

    #[test]
    fn oversized_requests_precede_source_and_destination_validation() {
        let mut memory = memory(None);
        let base = memory.regions()[0].guest_address;
        for indirect in [false, true] {
            for size in [MAX_BYTES as u64 + 1, 1 << 32, u64::MAX] {
                assert_completion(
                    &mut memory,
                    indirect,
                    [u64::MAX, size],
                    15,
                    Some(DARWIN_EINVAL),
                    |_| panic!("oversized entropy request reached provider"),
                );
                assert_eq!(
                    memory.read_snapshot(base, MAX_BYTES).unwrap(),
                    [CANARY; MAX_BYTES]
                );
            }
        }
    }

    #[test]
    fn zero_length_accepts_invalid_addresses_without_pointer_access() {
        let mut memory = memory(None);
        for address in [0, u64::MAX] {
            assert_completion(&mut memory, false, [address, 0], 15, None, |bytes| {
                assert!(bytes.is_empty());
                Ok(())
            });
        }
    }

    #[test]
    fn copyout_faults_preserve_source_defined_byte_prefixes() {
        for second_page in [None, Some(false), Some(true)] {
            let mut memory = memory(second_page);
            let page = memory.regions()[0].virtual_bytes as usize;
            let base = memory.regions()[0].guest_address;
            for (address, size) in [(base + page as u64 - 1, 2), (0, 1), (u64::MAX, 2)] {
                let before = memory.read_snapshot(base, page).unwrap();
                let valid = second_page == Some(true) && address == base + page as u64 - 1;
                assert_completion(
                    &mut memory,
                    false,
                    [address, size],
                    0,
                    (!valid).then_some(DARWIN_EFAULT),
                    |bytes| {
                        assert_eq!(bytes.len(), size as usize);
                        fill(bytes)
                    },
                );
                let mut expected = before;
                if address == base + page as u64 - 1 {
                    expected[page - 1] = GENERATED;
                }
                if valid {
                    assert_eq!(
                        memory.read_snapshot(base + page as u64, 2).unwrap(),
                        [GENERATED, CANARY]
                    );
                }
                assert_eq!(memory.read_snapshot(base, page).unwrap(), expected);
            }
            memory.protect_data(base, page as u64, true, false).unwrap();
            let before = memory.read_snapshot(base, page).unwrap();
            assert_completion(
                &mut memory,
                false,
                [base, MAX_BYTES as u64],
                15,
                Some(DARWIN_EFAULT),
                fill,
            );
            assert_eq!(memory.read_snapshot(base, page).unwrap(), before);
        }
    }

    #[test]
    fn ambiguous_pair_fault_declines_before_all_guest_memory_effects() {
        let mut memory = memory(Some(false));
        let base = memory.regions()[0].guest_address;
        let page = memory.regions()[0].virtual_bytes as usize;
        let address = base + page as u64 - 24;
        let mut state = state(false, [address, 32], 15);
        let before_state = state.clone();
        let before_memory = memory.read_snapshot(base, 2 * page).unwrap();
        let event = service_with_source(&mut state, &trap(), &mut memory, fill);
        assert!(event.completion.is_none() && event.declined.is_some());
        assert_eq!(state.pc, before_state.pc);
        assert_eq!(state.registers, before_state.registers);
        assert_eq!(memory.read_snapshot(base, 2 * page).unwrap(), before_memory);
    }

    #[test]
    fn partial_provider_failure_never_publishes_bytes_or_host_errno() {
        let mut memory = memory(None);
        let base = memory.regions()[0].guest_address;
        for address in [base, 0] {
            assert_completion(
                &mut memory,
                false,
                [address, MAX_BYTES as u64],
                15,
                Some(DARWIN_EIO),
                |bytes| {
                    bytes[..MAX_BYTES / 2].fill(GENERATED);
                    Err(io::Error::from_raw_os_error(libc::EPERM))
                },
            );
            assert_eq!(
                memory.read_snapshot(base, MAX_BYTES).unwrap(),
                [CANARY; MAX_BYTES]
            );
        }
    }

    #[test]
    fn unknown_services_and_invalid_traps_leave_state_and_memory_pending() {
        let mut memory = memory(None);
        let base = memory.regions()[0].guest_address;
        for number in [SYSCALL_NUMBER - 1, SYSCALL_NUMBER + 1] {
            let mut state = state(false, [base, 1], 15);
            state.registers.x[super::super::SYSCALL_SELECTOR_REGISTER] = u64::from(number);
            let before = state.clone();
            assert!(!handles(&state, &trap()));
            let event = service_with_source(&mut state, &trap(), &mut memory, |_| {
                panic!("unknown service reached provider")
            });
            assert!(event.completion.is_none() && event.declined.is_some());
            assert_eq!(state.pc, before.pc);
            assert_eq!(state.registers, before.registers);
        }
        let mut state = state(false, [base, 1], 15);
        let before = state.clone();
        let mut wrong = trap();
        wrong.exception_return_pc.0 += 4;
        let event = service_with_source(&mut state, &wrong, &mut memory, |_| {
            panic!("invalid trap reached provider")
        });
        assert!(event.completion.is_none() && event.declined.is_some());
        assert_eq!(state.pc, before.pc);
        assert_eq!(state.registers, before.registers);
        assert_eq!(
            memory.read_snapshot(base, MAX_BYTES).unwrap(),
            [CANARY; MAX_BYTES]
        );
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn genuine_host_provider_completes_owned_copyout() {
        let mut memory = memory(None);
        let base = memory.regions()[0].guest_address;
        let mut state = state(false, [base + 1, MAX_BYTES as u64], 15);
        let mut expected = state.clone();
        expected.pc = trap().exception_return_pc;
        expected.registers.x[0] = 0;
        expected.registers.x[1] = 0;
        expected.registers.nzcv &= !CARRY;
        let event = service(&mut state, &trap(), &mut memory);
        assert_eq!(
            event.completion,
            Some(BsdCompletion::Success { values: [0, 0] })
        );
        assert!(event.declined.is_none());
        assert_eq!(state.pc, expected.pc);
        assert_eq!(state.registers, expected.registers);
        assert_eq!(memory.read_snapshot(base, 1).unwrap(), [CANARY]);
        assert_eq!(
            memory
                .read_snapshot(base + MAX_BYTES as u64 + 1, 1)
                .unwrap(),
            [CANARY]
        );
        assert_eq!(
            memory.read_snapshot(base + 1, MAX_BYTES).unwrap().len(),
            MAX_BYTES
        );
        // Random values have no deterministic oracle or statistical assertion.
    }
    #[test]
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    fn native_original_request_resumes_only_when_entropy_is_enabled() -> Result<()> {
        use super::super::{ExecutionServices, run_services};
        use crate::blocks::{BlockRuntime, StopReason};
        use stela_compiler::{TargetCpu, block::BlockProfile};

        // Unchanged 26A434 dyld request at offsets 0x683c..0x6844. The
        // separately recorded continuation owns its full slice/source identity.
        // Only this request window executes here; complete process execution
        // and the subsequent shared-cache boundary remain unverified.
        const MOV_X16_GETENTROPY: u32 = 0xd2803e90;
        const SVC_DARWIN: u32 = 0xd4001001;
        const ORIGINAL_REQUEST: [u32; 2] = [MOV_X16_GETENTROPY, SVC_DARWIN];
        const INSTRUCTION_BYTES: u64 = 4;
        const REQUEST_BYTES: u64 = 2 * INSTRUCTION_BYTES;
        const ADDRESS_SPACE: u64 = 0x454e54524f5059;

        let cache = tempfile::tempdir()?;
        let mut runtime = BlockRuntime::new_for_target(
            ADDRESS_SPACE,
            cache.path().to_owned(),
            BlockProfile::Ordinary,
            TargetCpu::Baseline,
        );
        runtime.register_code(
            GuestAddress(TEST_PC),
            ORIGINAL_REQUEST
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect(),
        )?;
        let mut memory = memory(None);
        let base = memory.regions()[0].guest_address;
        for enabled in [false, true] {
            for indirect in [false, true] {
                for flags in 0..NZCV_COMBINATIONS {
                    for (address, size, errno) in [
                        (base + 1, 0, None),
                        (base + 1, 128, None),
                        (0, 1, Some(DARWIN_EFAULT)),
                        (u64::MAX, MAX_BYTES as u64 + 1, Some(DARWIN_EINVAL)),
                    ] {
                        memory.write(base, &[CANARY; MAX_BYTES + 2])?;
                        let before = memory.read_snapshot(base, MAX_BYTES + 2)?;
                        let mut state = state(indirect, [address, size], flags);
                        if indirect {
                            state.pc.0 += INSTRUCTION_BYTES;
                        }
                        let mut expected = state.clone();
                        if !indirect {
                            expected.registers.x[super::super::SYSCALL_SELECTOR_REGISTER] =
                                u64::from(SYSCALL_NUMBER);
                        }
                        expected.pc = GuestAddress(
                            TEST_PC
                                + if enabled {
                                    REQUEST_BYTES
                                } else {
                                    INSTRUCTION_BYTES
                                },
                        );
                        if enabled {
                            expected.registers.x[0] = u64::from(errno.unwrap_or(0));
                            expected.registers.x[1] = 0;
                            expected.registers.nzcv = (expected.registers.nzcv & !CARRY)
                                | if errno.is_some() { CARRY } else { 0 };
                        }
                        // SAFETY: MOV and SVC access no RAM; the copyout owns all
                        // affected data, and no exclusive monitor or concurrent
                        // execution exists.
                        let outcome = unsafe {
                            run_services(
                                &mut runtime,
                                &mut state,
                                Some(GuestAddress(TEST_PC + REQUEST_BYTES)),
                                1,
                                &mut memory,
                                ExecutionServices {
                                    entropy: enabled,
                                    ..ExecutionServices::default()
                                },
                            )?
                        };
                        if enabled {
                            assert_eq!(outcome.execution.reason, StopReason::StopAddress);
                            assert_eq!(outcome.entropy_services.len(), 1);
                            assert!(outcome.entropy_services[0].declined.is_none());
                            assert_eq!(
                                outcome.entropy_services[0].completion,
                                Some(
                                    errno.map_or(
                                        BsdCompletion::Success { values: [0, 0] },
                                        |errno| { BsdCompletion::Error { errno } }
                                    )
                                )
                            );
                        } else {
                            assert!(matches!(
                                outcome.execution.reason,
                                StopReason::SynchronousTrap { .. }
                            ));
                            assert!(outcome.entropy_services.is_empty());
                        }
                        assert_eq!(state.pc, expected.pc);
                        assert_eq!(state.registers, expected.registers);
                        let after = memory.read_snapshot(base, MAX_BYTES + 2)?;
                        if enabled && errno.is_none() && size != 0 {
                            assert_eq!(after[0], CANARY);
                            assert_eq!(&after[1 + size as usize..], &before[1 + size as usize..]);
                        } else {
                            assert_eq!(after, before);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

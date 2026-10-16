//! System-integrity (CSR) policy queries against a fixed guest policy
//! (XNU `bsd/kern/kern_csr.c`). The host's policy is never consulted.

use super::{
    BsdCompletion, BsdPrototype, BsdReturnType, BsdServiceEvent, PendingBsdCall, classify_bsd_call,
};
use crate::{
    blocks::ThreadState,
    memory::{DIRECT_RAM_USER_END, OwnedMemory},
};
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use anyhow::{Result, ensure};
use serde::Serialize;
use stela_compiler::block::SynchronousTrap;

pub const PROFILE_ID: &str = "darwin-arm64-immutable-csr-policy-v1";
pub const SYSCALL_NUMBER: u16 = 483;
pub const CHECK: u32 = 0;
pub const GET_ACTIVE_CONFIG: u32 = 1;

const ALLOW_UNTRUSTED_KEXTS: u32 = 1 << 0;
const ALLOW_UNRESTRICTED_FS: u32 = 1 << 1;
const ALLOW_TASK_FOR_PID: u32 = 1 << 2;
const ALLOW_KERNEL_DEBUGGER: u32 = 1 << 3;
const ALLOW_APPLE_INTERNAL: u32 = 1 << 4;
const ALLOW_UNRESTRICTED_DTRACE: u32 = 1 << 5;
const ALLOW_UNRESTRICTED_NVRAM: u32 = 1 << 6;
const ALLOW_DEVICE_CONFIGURATION: u32 = 1 << 7;
const ALLOW_ANY_RECOVERY_OS: u32 = 1 << 8;
const ALLOW_UNAPPROVED_KEXTS: u32 = 1 << 9;
const ALLOW_EXECUTABLE_POLICY_OVERRIDE: u32 = 1 << 10;
const ALLOW_UNAUTHENTICATED_ROOT: u32 = 1 << 11;
const ALLOW_RESEARCH_GUESTS: u32 = 1 << 12;
const VALID_FLAGS: u32 = ALLOW_UNTRUSTED_KEXTS
    | ALLOW_UNRESTRICTED_FS
    | ALLOW_TASK_FOR_PID
    | ALLOW_KERNEL_DEBUGGER
    | ALLOW_APPLE_INTERNAL
    | ALLOW_UNRESTRICTED_DTRACE
    | ALLOW_UNRESTRICTED_NVRAM
    | ALLOW_DEVICE_CONFIGURATION
    | ALLOW_ANY_RECOVERY_OS
    | ALLOW_UNAPPROVED_KEXTS
    | ALLOW_EXECUTABLE_POLICY_OVERRIDE
    | ALLOW_UNAUTHENTICATED_ROOT
    | ALLOW_RESEARCH_GUESTS;
const CONFIG_BYTES: usize = size_of::<u32>();
const DARWIN_EPERM: u32 = 1;
const DARWIN_EFAULT: u32 = 14;
const DARWIN_EINVAL: u32 = 22;
const DARWIN_ENOSYS: u32 = 78;
const PROTOTYPE: BsdPrototype = BsdPrototype {
    argument_count: 3,
    return_type: BsdReturnType::Int,
};

/// A guest configuration supplied by the caller. The active configuration and
/// the effective CHECK mask differ on purpose: ARM XNU allows kernel debugging
/// when untrusted kexts or AppleInternal is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ArmSecurityPolicy {
    active_configuration: u32,
}

impl ArmSecurityPolicy {
    pub fn new(active_configuration: u32) -> Result<Self> {
        ensure!(
            active_configuration & !VALID_FLAGS == 0,
            "CSR policy contains flags outside the pinned ARM contract"
        );
        Ok(Self {
            active_configuration,
        })
    }

    pub fn active_configuration(&self) -> u32 {
        self.active_configuration
    }

    pub fn permits(&self, requested: u32) -> bool {
        let mut effective = self.active_configuration;
        if effective & (ALLOW_UNTRUSTED_KEXTS | ALLOW_APPLE_INTERNAL) != 0 {
            effective |= ALLOW_KERNEL_DEBUGGER;
        }
        effective & requested == requested
    }
}

pub fn handles(state: &ThreadState, trap: &SynchronousTrap) -> bool {
    classify_bsd_call(state, trap).is_ok_and(|selector| selector.number == SYSCALL_NUMBER)
}

/// Service a query against owned guest memory. Unknown operations return the
/// syscall's ENOSYS; calls for other services stay pending. Copyout checks the
/// user range first, then keeps the completed prefix if a later byte is
/// unmapped or read-only.
pub fn service(
    state: &mut ThreadState,
    trap: &SynchronousTrap,
    memory: &mut OwnedMemory,
    policy: &ArmSecurityPolicy,
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
            "BSD service {} is not implemented by the CSR profile",
            request.number
        );
        let [operation, address, size] = request.arguments() else {
            unreachable!("the validated CSR prototype contains three arguments")
        };
        let errno = match *operation as u32 {
            CHECK | GET_ACTIVE_CONFIG if *address == 0 || *size != CONFIG_BYTES as u64 => {
                Some(DARWIN_EINVAL)
            }
            CHECK => match memory.read_snapshot(*address, CONFIG_BYTES) {
                Ok(bytes) => {
                    let requested =
                        u32::from_le_bytes(bytes.try_into().expect("four-byte CSR mask"));
                    (!policy.permits(requested)).then_some(DARWIN_EPERM)
                }
                Err(_) => Some(DARWIN_EFAULT),
            },
            GET_ACTIVE_CONFIG => copy_active_configuration(memory, *address, policy),
            _ => Some(DARWIN_ENOSYS),
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

fn copy_active_configuration(
    memory: &mut OwnedMemory,
    address: u64,
    policy: &ArmSecurityPolicy,
) -> Option<u32> {
    // Pinned ARM copyio.c validates the complete numeric user range before
    // BCOPY_IMPL performs a forward byte copy for lengths below sixteen.
    // OwnedMemory supplies this serialized profile's lower-VA47 user bound;
    // forbidden top-byte tags are outside it and therefore fail the range check.
    if address
        .checked_add(CONFIG_BYTES as u64)
        .is_none_or(|end| end > DIRECT_RAM_USER_END)
    {
        return Some(DARWIN_EFAULT);
    }
    for (offset, byte) in policy.active_configuration.to_le_bytes().iter().enumerate() {
        if memory
            .write(address + offset as u64, core::slice::from_ref(byte))
            .is_err()
        {
            return Some(DARWIN_EFAULT);
        }
    }
    None
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
    const TEST_BASE: u64 = 0x69000000000;
    const ADDRESS_ATTEMPTS: u64 = 32;

    fn trap() -> SynchronousTrap {
        SynchronousTrap {
            kind: TrapKind::SupervisorCall,
            immediate: SVC_IMMEDIATE,
            instruction_pc: GuestAddress(TEST_PC),
            exception_return_pc: GuestAddress(TEST_PC + 4),
        }
    }

    fn memory() -> OwnedMemory {
        memory_pages(1)
    }

    fn memory_pages(pages: u64) -> OwnedMemory {
        let page = host_page_size().unwrap() as u64;
        for attempt in 0..ADDRESS_ATTEMPTS {
            if let Ok(memory) = OwnedMemory::map(vec![MemoryRegionSpec {
                guest_address: TEST_BASE + attempt * page * pages,
                virtual_bytes: page * pages,
                initial_bytes: vec![0xa5; (page * pages) as usize],
                readable: true,
                writable: true,
                executable: false,
            }]) {
                return memory;
            }
        }
        panic!("cannot allocate CSR fixture mapping");
    }

    fn state(indirect: bool, arguments: [u64; 3], flags: u32) -> ThreadState {
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
        policy: &ArmSecurityPolicy,
        indirect: bool,
        arguments: [u64; 3],
        flags: u32,
        errno: Option<u32>,
    ) {
        let mut state = state(indirect, arguments, flags);
        let mut expected = state.clone();
        expected.pc = trap().exception_return_pc;
        expected.registers.x[0] = u64::from(errno.unwrap_or(0));
        expected.registers.x[1] = 0;
        expected.registers.nzcv =
            (expected.registers.nzcv & !CARRY) | if errno.is_some() { CARRY } else { 0 };
        assert!(handles(&state, &trap()));
        let event = service(&mut state, &trap(), memory, policy);
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

    #[test]
    fn arm_policy_preserves_active_flags_and_derives_debugger_permission_only_for_check() {
        for configuration in 0..=VALID_FLAGS {
            let policy = ArmSecurityPolicy::new(configuration).unwrap();
            assert_eq!(policy.active_configuration(), configuration);
            assert!(policy.permits(0));
            assert!(policy.permits(configuration));
            assert!(!policy.permits(!VALID_FLAGS));
            let debugger = configuration
                & (ALLOW_UNTRUSTED_KEXTS | ALLOW_APPLE_INTERNAL | ALLOW_KERNEL_DEBUGGER)
                != 0;
            assert_eq!(policy.permits(ALLOW_KERNEL_DEBUGGER), debugger);
        }
        for bit in 13..u32::BITS {
            assert!(ArmSecurityPolicy::new(1 << bit).is_err());
        }
    }

    #[test]
    fn direct_and_indirect_queries_preserve_full_state_and_unrelated_memory() {
        let mut memory = memory();
        let base = memory.regions()[0].guest_address;
        for indirect in [false, true] {
            for flags in 0..NZCV_COMBINATIONS {
                for configuration in [0, ALLOW_APPLE_INTERNAL, VALID_FLAGS] {
                    let policy = ArmSecurityPolicy::new(configuration).unwrap();
                    for requested in [0, ALLOW_APPLE_INTERNAL, ALLOW_KERNEL_DEBUGGER, !VALID_FLAGS]
                    {
                        memory.write(base + 1, &requested.to_le_bytes()).unwrap();
                        let before = memory.read_snapshot(base, 16).unwrap();
                        assert_completion(
                            &mut memory,
                            &policy,
                            indirect,
                            [u64::from(CHECK), base + 1, CONFIG_BYTES as u64],
                            flags,
                            (!policy.permits(requested)).then_some(DARWIN_EPERM),
                        );
                        assert_eq!(memory.read_snapshot(base, 16).unwrap(), before);
                    }
                    let mut expected = memory.read_snapshot(base, 16).unwrap();
                    expected[1..1 + CONFIG_BYTES].copy_from_slice(&configuration.to_le_bytes());
                    assert_completion(
                        &mut memory,
                        &policy,
                        indirect,
                        [u64::from(GET_ACTIVE_CONFIG), base + 1, CONFIG_BYTES as u64],
                        flags,
                        None,
                    );
                    assert_eq!(memory.read_snapshot(base, 16).unwrap(), expected);
                }
            }
        }
    }

    #[test]
    fn operation_truncates_to_uint32_and_unknown_operations_precede_pointer_validation() {
        let mut memory = memory();
        let base = memory.regions()[0].guest_address;
        let policy = ArmSecurityPolicy::new(0).unwrap();
        memory.write(base, &0_u32.to_le_bytes()).unwrap();
        for indirect in [false, true] {
            for upper in [1, u32::MAX] {
                assert_completion(
                    &mut memory,
                    &policy,
                    indirect,
                    [u64::from(upper) << 32, base, CONFIG_BYTES as u64],
                    15,
                    None,
                );
                for operation in [2, u32::MAX] {
                    assert_completion(
                        &mut memory,
                        &policy,
                        indirect,
                        [(u64::from(upper) << 32) | u64::from(operation), 0, u64::MAX],
                        15,
                        Some(DARWIN_ENOSYS),
                    );
                }
            }
        }
    }

    #[test]
    fn invalid_arguments_and_memory_faults_preserve_the_exact_copy_prefix() {
        let mut memory = memory();
        let region = memory.regions()[0].clone();
        let base = region.guest_address;
        let end = base + region.virtual_bytes;
        let policy = ArmSecurityPolicy::new(ALLOW_APPLE_INTERNAL).unwrap();
        for operation in [CHECK, GET_ACTIVE_CONFIG] {
            for (address, size, error) in [
                (0, CONFIG_BYTES as u64, DARWIN_EINVAL),
                (base, 0, DARWIN_EINVAL),
                (base, CONFIG_BYTES as u64 + 1, DARWIN_EINVAL),
                (base, (1 << 32) + CONFIG_BYTES as u64, DARWIN_EINVAL),
                (end - 1, CONFIG_BYTES as u64, DARWIN_EFAULT),
                (end - 2, CONFIG_BYTES as u64, DARWIN_EFAULT),
                (end - 3, CONFIG_BYTES as u64, DARWIN_EFAULT),
                (u64::MAX - 1, CONFIG_BYTES as u64, DARWIN_EFAULT),
            ] {
                let mut expected = memory
                    .read_snapshot(base, region.virtual_bytes as usize)
                    .unwrap();
                if operation == GET_ACTIVE_CONFIG
                    && address < end
                    && address > end - CONFIG_BYTES as u64
                {
                    let prefix = (end - address) as usize;
                    let offset = (address - base) as usize;
                    expected[offset..]
                        .copy_from_slice(&policy.active_configuration().to_le_bytes()[..prefix]);
                }
                assert_completion(
                    &mut memory,
                    &policy,
                    false,
                    [u64::from(operation), address, size],
                    15,
                    Some(error),
                );
                assert_eq!(
                    memory
                        .read_snapshot(base, region.virtual_bytes as usize)
                        .unwrap(),
                    expected
                );
            }
        }
        memory
            .protect_data(base, region.mapped_bytes, true, false)
            .unwrap();
        let before = memory
            .read_snapshot(base, region.virtual_bytes as usize)
            .unwrap();
        assert_completion(
            &mut memory,
            &policy,
            false,
            [u64::from(GET_ACTIVE_CONFIG), base, CONFIG_BYTES as u64],
            0,
            Some(DARWIN_EFAULT),
        );
        assert_eq!(
            memory
                .read_snapshot(base, region.virtual_bytes as usize)
                .unwrap(),
            before
        );
    }

    #[test]
    fn copyout_retains_the_written_prefix_before_a_readonly_page() {
        let mut memory = memory_pages(2);
        let base = memory.regions()[0].guest_address;
        let page = host_page_size().unwrap() as u64;
        memory.protect_data(base + page, page, true, false).unwrap();
        let policy = ArmSecurityPolicy::new(VALID_FLAGS).unwrap();
        for prefix in 1..CONFIG_BYTES {
            let address = base + page - prefix as u64;
            let mut expected = memory.read_snapshot(base, (2 * page) as usize).unwrap();
            expected[page as usize - prefix..page as usize]
                .copy_from_slice(&policy.active_configuration().to_le_bytes()[..prefix]);
            assert_completion(
                &mut memory,
                &policy,
                false,
                [u64::from(GET_ACTIVE_CONFIG), address, CONFIG_BYTES as u64],
                15,
                Some(DARWIN_EFAULT),
            );
            assert_eq!(
                memory.read_snapshot(base, (2 * page) as usize).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn unknown_services_and_invalid_traps_preserve_pending_state_and_memory() {
        let mut memory = memory();
        let base = memory.regions()[0].guest_address;
        let policy = ArmSecurityPolicy::new(0).unwrap();
        for number in [1, SYSCALL_NUMBER - 1, SYSCALL_NUMBER + 1] {
            let mut state = state(
                false,
                [u64::from(GET_ACTIVE_CONFIG), base, CONFIG_BYTES as u64],
                0,
            );
            state.registers.x[super::super::SYSCALL_SELECTOR_REGISTER] = u64::from(number);
            let before = state.clone();
            let bytes = memory.read_snapshot(base, 16).unwrap();
            assert!(!handles(&state, &trap()));
            let event = service(&mut state, &trap(), &mut memory, &policy);
            assert!(event.completion.is_none() && event.declined.is_some());
            assert_eq!(state.pc, before.pc);
            assert_eq!(state.registers, before.registers);
            assert_eq!(memory.read_snapshot(base, 16).unwrap(), bytes);
        }
        let mut state = state(
            false,
            [u64::from(GET_ACTIVE_CONFIG), base, CONFIG_BYTES as u64],
            0,
        );
        let before = state.clone();
        let mut wrong = trap();
        wrong.exception_return_pc.0 += 4;
        let event = service(&mut state, &wrong, &mut memory, &policy);
        assert!(event.completion.is_none() && event.declined.is_some());
        assert_eq!(state.pc, before.pc);
        assert_eq!(state.registers, before.registers);
        assert_eq!(memory.read_snapshot(base, 4).unwrap(), vec![0xa5; 4]);
    }

    #[test]
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    fn native_original_request_window_resumes_through_explicit_policy() -> Result<()> {
        use super::super::{ExecutionServices, run_services};
        use crate::blocks::{BlockRuntime, StopReason};
        use stela_compiler::{TargetCpu, block::BlockProfile};

        // Instructions at offsets 0x504c-0x5054 of the 26A434 dyld slice. Only this
        // request window runs.
        const MOV_X16_CSRCTL: u32 = 0xd2803c70;
        const SVC_DARWIN: u32 = 0xd4001001;
        const ORIGINAL_REQUEST: [u32; 2] = [MOV_X16_CSRCTL, SVC_DARWIN];
        const REQUEST_BYTES: u64 = 8;
        const ADDRESS_SPACE: u64 = 0x435352;

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
        let mut memory = memory();
        let base = memory.regions()[0].guest_address;
        let ram_bytes = memory.regions()[0].virtual_bytes as usize;
        let policy = ArmSecurityPolicy::new(ALLOW_APPLE_INTERNAL)?;
        for flags in 0..NZCV_COMBINATIONS {
            for (operation, requested, error, prefix) in [
                (CHECK, ALLOW_APPLE_INTERNAL, None, 0),
                (CHECK, ALLOW_UNRESTRICTED_FS, Some(DARWIN_EPERM), 0),
                (GET_ACTIVE_CONFIG, 0, None, 0),
                (GET_ACTIVE_CONFIG, 0, Some(DARWIN_EFAULT), 0),
                (GET_ACTIVE_CONFIG, 0, Some(DARWIN_EFAULT), 2),
            ] {
                let address = if prefix != 0 {
                    base + (ram_bytes - prefix) as u64
                } else if error == Some(DARWIN_EFAULT) {
                    u64::MAX
                } else {
                    base + 1
                };
                memory.write(base + 1, &requested.to_le_bytes())?;
                let mut expected_ram = memory.read_snapshot(base, ram_bytes)?;
                if operation == GET_ACTIVE_CONFIG && error.is_none() {
                    expected_ram[1..1 + CONFIG_BYTES]
                        .copy_from_slice(&policy.active_configuration().to_le_bytes());
                } else if prefix != 0 {
                    expected_ram[ram_bytes - prefix..]
                        .copy_from_slice(&policy.active_configuration().to_le_bytes()[..prefix]);
                }
                let mut state = state(
                    false,
                    [u64::from(operation), address, CONFIG_BYTES as u64],
                    flags,
                );
                let mut expected = state.clone();
                expected.pc = GuestAddress(TEST_PC + REQUEST_BYTES);
                expected.registers.x[super::super::SYSCALL_SELECTOR_REGISTER] =
                    u64::from(SYSCALL_NUMBER);
                expected.registers.x[0] = u64::from(error.unwrap_or(0));
                expected.registers.x[1] = 0;
                expected.registers.nzcv =
                    (expected.registers.nzcv & !CARRY) | if error.is_some() { CARRY } else { 0 };
                // SAFETY: MOV and SVC only produce a request. CSR writes owned
                // data, and no exclusive monitor is live.
                let outcome = unsafe {
                    run_services(
                        &mut runtime,
                        &mut state,
                        Some(expected.pc),
                        1,
                        &mut memory,
                        ExecutionServices {
                            csr: Some(&policy),
                            ..ExecutionServices::default()
                        },
                    )?
                };
                assert_eq!(outcome.execution.reason, StopReason::StopAddress);
                assert_eq!(outcome.csr_services.len(), 1);
                assert!(outcome.csr_services[0].declined.is_none());
                assert_eq!(state.pc, expected.pc);
                assert_eq!(state.registers, expected.registers);
                assert_eq!(memory.read_snapshot(base, ram_bytes)?, expected_ram);
            }
        }
        Ok(())
    }
}

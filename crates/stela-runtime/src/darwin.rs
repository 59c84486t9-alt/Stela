//! Explicit LP64 Darwin BSD-call ABI adaptation for a stopped SVC #0x80.
//!
//! Reference: public XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea,
//! bsd/dev/arm/systemcalls.c, bsd/sys/user.h and osfmk/arm64/sleh.c.
//! This profile does not establish the private macOS 27 kernel contract.
//! The #0x80 restriction is an initial Stela profile, not an XNU check of
//! the SVC immediate. No service, host syscall, memory access or exception-level
//! transition occurs in the ABI adapter itself. The opt-in data VM service below
//! changes owned data protections; all other backends remain caller supplied.
//! Declining a request means leaving its pending state unchanged.
use crate::blocks::ThreadState;
use serde::{Serialize, ser::SerializeStruct};
use stela_compiler::block::{SynchronousTrap, TrapKind};
use std::{error::Error, fmt};

pub const MAX_BSD_ARGUMENTS: usize = 8;
const CARRY: u32 = 0x20000000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BsdReturnType {
    Int,
    UnsignedInt,
    Offset,
    Address,
    Size,
    SignedSize,
    Unsigned64,
    None,
}

/// Caller-declared sysent metadata; the adapter never guesses a syscall table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BsdPrototype {
    pub argument_count: usize,
    pub return_type: BsdReturnType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BsdSelector {
    pub number: u16,
    pub indirect: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BsdRequest {
    pub number: u16,
    pub indirect: bool,
    arguments: [u64; MAX_BSD_ARGUMENTS],
    prototype: BsdPrototype,
}

impl BsdRequest {
    /// Exactly the argument slots declared by the validated call prototype.
    pub fn arguments(&self) -> &[u64] {
        &self.arguments[..self.prototype.argument_count]
    }

    pub fn prototype(&self) -> BsdPrototype {
        self.prototype
    }
}

impl Serialize for BsdRequest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut request = serializer.serialize_struct("BsdRequest", 4)?;
        request.serialize_field("number", &self.number)?;
        request.serialize_field("indirect", &self.indirect)?;
        request.serialize_field("arguments", self.arguments())?;
        request.serialize_field("prototype", &self.prototype)?;
        request.end()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BsdCompletion {
    /// The two original 32-bit uthread retval slots, before ABI normalization.
    Success {
        values: [u32; 2],
    },
    /// A positive Darwin errno supplied by the service; never a host errno cast.
    Error {
        errno: u32,
    },
    Restart,
    /// Requires external context restoration and is deliberately declined.
    JustReturn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AbiError {
    UnsupportedTrap { trap_kind: TrapKind, immediate: u16 },
    InvalidTrapState { detail: &'static str },
    PlatformCall { raw_x16: u64 },
    MachCall { number: i32, raw_x16: u64 },
    InvalidPrototype { argument_count: usize },
    StateChanged,
    InvalidErrno { errno: u32 },
    UnsupportedJustReturn,
}

impl fmt::Display for AbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedTrap { trap_kind, immediate } => write!(f, "Darwin BSD profile requires SVC #0x80, received {trap_kind:?} #{immediate:#x}"),
            Self::InvalidTrapState { detail } => write!(f, "incoherent stopped Darwin call: {detail}"),
            Self::PlatformCall { raw_x16 } => write!(f, "Darwin platform call selector {raw_x16:#x} is unsupported"),
            Self::MachCall { number, .. } => write!(f, "Darwin Mach call selector {number} is unsupported"),
            Self::InvalidPrototype { argument_count } => write!(f, "Darwin LP64 prototype has {argument_count} arguments, maximum is {MAX_BSD_ARGUMENTS}"),
            Self::StateChanged => f.write_str("stopped thread changed after Darwin call capture"),
            Self::InvalidErrno { errno } => write!(f, "Darwin completion requires a positive signed32 errno, received {errno}"),
            Self::UnsupportedJustReturn => f.write_str("EJUSTRETURN requires externally restored thread context; adapter context restoration is unsupported"),
        }
    }
}

impl Error for AbiError {}

pub(crate) fn validate_trap(state: &ThreadState, trap: &SynchronousTrap) -> Result<(), AbiError> {
    if trap.kind != TrapKind::SupervisorCall || trap.immediate != 0x80 {
        return Err(AbiError::UnsupportedTrap {
            trap_kind: trap.kind,
            immediate: trap.immediate,
        });
    }
    if state.pc != trap.instruction_pc || !trap.instruction_pc.0.is_multiple_of(4) {
        return Err(AbiError::InvalidTrapState {
            detail: "thread PC must identify the aligned SVC instruction",
        });
    }
    if trap.instruction_pc.0.checked_add(4) != Some(trap.exception_return_pc.0) {
        return Err(AbiError::InvalidTrapState {
            detail: "SVC preferred return PC must be instruction PC plus four",
        });
    }
    if state.registers.nzcv & !0xf0000000 != 0 {
        return Err(AbiError::InvalidTrapState {
            detail: "state contains unsupported NZCV bits",
        });
    }
    Ok(())
}

/// Classify without mutating state, allowing the caller to select its prototype.
/// XNU first converts X16 to signed32 for dispatch. BSD number/argument selection
/// separately tests the full saved X16 for zero and truncates the number to u16.
pub fn classify_bsd_call(
    state: &ThreadState,
    trap: &SynchronousTrap,
) -> Result<BsdSelector, AbiError> {
    validate_trap(state, trap)?;
    let raw_x16 = state.registers.x[16];
    let dispatch = raw_x16 as u32 as i32;
    if dispatch == i32::MIN {
        return Err(AbiError::PlatformCall { raw_x16 });
    }
    if dispatch < 0 {
        return Err(AbiError::MachCall {
            number: dispatch,
            raw_x16,
        });
    }
    let indirect = raw_x16 == 0;
    Ok(BsdSelector {
        number: if indirect {
            state.registers.x[0] as u16
        } else {
            raw_x16 as u16
        },
        indirect,
    })
}

/// Owns an immutable request and complete pre-service thread snapshot.
/// This is a pending ABI event, not evidence that its service has executed.
#[derive(Debug)]
pub struct PendingBsdCall {
    request: BsdRequest,
    issued: ThreadState,
    trap: SynchronousTrap,
}

impl PendingBsdCall {
    pub fn from_trap(
        state: &ThreadState,
        trap: &SynchronousTrap,
        prototype: BsdPrototype,
    ) -> Result<Self, AbiError> {
        let selector = classify_bsd_call(state, trap)?;
        if prototype.argument_count > MAX_BSD_ARGUMENTS {
            return Err(AbiError::InvalidPrototype {
                argument_count: prototype.argument_count,
            });
        }
        // The pinned LP64 C implementation copies up to eight u64 values from
        // x[0] for direct calls or x[1] for indirect calls: no guest-stack read.
        let start = usize::from(selector.indirect);
        let mut arguments = [0; MAX_BSD_ARGUMENTS];
        arguments[..prototype.argument_count]
            .copy_from_slice(&state.registers.x[start..start + prototype.argument_count]);
        Ok(Self {
            request: BsdRequest {
                number: selector.number,
                indirect: selector.indirect,
                arguments,
                prototype,
            },
            issued: state.clone(),
            trap: *trap,
        })
    }

    pub fn request(&self) -> &BsdRequest {
        &self.request
    }

    /// Apply one actual backend result after proving the stopped state unchanged.
    /// A declined service must not call this method. Invalid replies and declined
    /// context restoration leave all state unchanged. BSD completion touches only
    /// the declared return registers, carry and PC; no EL/PSTATE entry is modeled.
    pub fn complete(
        self,
        state: &mut ThreadState,
        completion: BsdCompletion,
    ) -> Result<(), AbiError> {
        if state.pc != self.issued.pc || state.registers != self.issued.registers {
            return Err(AbiError::StateChanged);
        }
        if completion == BsdCompletion::JustReturn {
            return Err(AbiError::UnsupportedJustReturn);
        }
        let mut next = self.issued;
        next.registers.nzcv &= !CARRY;
        next.pc = self.trap.exception_return_pc;
        match completion {
            BsdCompletion::Success { values } => match self.request.prototype.return_type {
                BsdReturnType::Int => {
                    next.registers.x[0] = values[0] as i32 as i64 as u64;
                    next.registers.x[1] = values[1] as i32 as i64 as u64;
                }
                BsdReturnType::UnsignedInt => {
                    next.registers.x[0] = u64::from(values[0]);
                    next.registers.x[1] = u64::from(values[1]);
                }
                BsdReturnType::Offset
                | BsdReturnType::Address
                | BsdReturnType::Size
                | BsdReturnType::SignedSize
                | BsdReturnType::Unsigned64 => {
                    next.registers.x[0] = u64::from(values[0]) | (u64::from(values[1]) << 32);
                    next.registers.x[1] = 0;
                }
                BsdReturnType::None => {}
            },
            BsdCompletion::Error { errno } => {
                if errno == 0 || errno > i32::MAX as u32 {
                    return Err(AbiError::InvalidErrno { errno });
                }
                next.registers.x[0] = u64::from(errno);
                next.registers.x[1] = 0;
                next.registers.nzcv |= CARRY;
            }
            BsdCompletion::Restart => next.pc = self.trap.instruction_pc,
            BsdCompletion::JustReturn => {
                unreachable!("context restoration was declined before mutation")
            }
        }
        *state = next;
        Ok(())
    }
}

/// Explicit ARM process VM profile; ordinary data protections only. Executable
/// transitions, trusted/TPRO flags and MAC/code-sign policy remain unsupported.
pub const DATA_VM_PROFILE: &str = "darwin-arm64-va47-page16k-data-mprotect-v1";
pub const GUEST_PAGE_BYTES: u64 = 16 * 1024;
#[derive(Debug, Serialize)]
pub struct DataVmEvent {
    pub trap: SynchronousTrap,
    pub request: Option<BsdRequest>,
    pub completion: Option<BsdCompletion>,
    pub declined: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct ServiceRunOutcome {
    pub execution: crate::blocks::RunOutcome,
    pub services: Vec<DataVmEvent>,
    pub mach_services: Vec<crate::mach::Event>,
}
#[derive(Default)]
pub struct ExecutionServices<'a> {
    pub mach_ports: Option<&'a mut crate::mach::HostPorts>,
    pub data_vm: bool,
    pub pauth: Option<&'a crate::pauth::Context>,
    pub clock: Option<&'a mut crate::clock::Context>,
}

/// Service the reviewed BSD74 ABI using owned guest pages, never host pointers
/// supplied unchecked by the guest. Unsupported requests preserve pending state.
/// Reference: pinned XNU bsd/kern/kern_mman.c mprotect/mprotect_sanitize and
/// syscalls.master. W implies R in that source; guest pages are16KiB regardless
/// of the host's page size. This is not the complete Darwin security/VM policy.
pub fn service_data_mprotect(
    state: &mut ThreadState,
    trap: &SynchronousTrap,
    memory: &mut crate::memory::OwnedMemory,
    runtime: &crate::blocks::BlockRuntime,
) -> DataVmEvent {
    let mut event = DataVmEvent {
        trap: *trap,
        request: None,
        completion: None,
        declined: None,
    };
    let result = (|| -> anyhow::Result<BsdCompletion> {
        anyhow::ensure!(memory.is_usable(), "guest address space is unusable");
        let selector = classify_bsd_call(state, trap)?;
        anyhow::ensure!(
            selector.number == 74,
            "BSD service {} is not implemented by the data VM profile",
            selector.number
        );
        let pending = PendingBsdCall::from_trap(
            state,
            trap,
            BsdPrototype {
                argument_count: 3,
                return_type: BsdReturnType::Int,
            },
        )?;
        let request = *pending.request();
        event.request = Some(request);
        let [address, length, raw_prot]: [u64; 3] = request.arguments().try_into()?;
        let prot = raw_prot as u32;
        anyhow::ensure!(
            prot & !7 == 0,
            "special/unknown mprotect flags require a reviewed platform policy"
        );
        anyhow::ensure!(
            prot & 4 == 0,
            "executable protection requires source publication/invalidation"
        );
        let completion = if !address.is_multiple_of(GUEST_PAGE_BYTES) {
            BsdCompletion::Error { errno: 22 }
        } else if let Some(end) = address
            .checked_add(length)
            .and_then(|e| e.checked_add(GUEST_PAGE_BYTES - 1))
            .map(|e| e & !(GUEST_PAGE_BYTES - 1))
        {
            if address >= (1 << 47) || end > (1 << 47) {
                BsdCompletion::Error { errno: 12 }
            } else if length == 0 {
                BsdCompletion::Success { values: [0, 0] }
            } else {
                anyhow::ensure!(
                    !runtime.source_overlaps(address, end - address),
                    "data protection overlaps a registered code snapshot"
                );
                let writable = prot & 2 != 0;
                let readable = prot & 3 != 0;
                match memory.protect_data(address, end - address, readable, writable) {
                    Ok(()) => BsdCompletion::Success { values: [0, 0] },
                    Err(crate::memory::ProtectionError::MaximumProtection) => {
                        BsdCompletion::Error { errno: 13 }
                    }
                    Err(crate::memory::ProtectionError::UnmappedRange) => {
                        BsdCompletion::Error { errno: 12 }
                    }
                    Err(crate::memory::ProtectionError::InvalidRange) => {
                        BsdCompletion::Error { errno: 22 }
                    }
                    Err(crate::memory::ProtectionError::HostFailure {
                        errno: Some(e),
                        rollback_succeeded: true,
                    }) if e == libc::ENOMEM => BsdCompletion::Error { errno: 12 },
                    Err(crate::memory::ProtectionError::HostFailure {
                        errno: Some(e),
                        rollback_succeeded: true,
                    }) if e == libc::EACCES => BsdCompletion::Error { errno: 13 },
                    Err(error) => return Err(error.into()),
                }
            }
        } else {
            BsdCompletion::Error { errno: 22 }
        };
        // Exclusive thread/owner borrows exclude mutation between capture and
        // completion; service code does not otherwise touch architectural state.
        pending.complete(state, completion)?;
        Ok(completion)
    })();
    match result {
        Ok(completion) => event.completion = Some(completion),
        Err(error) => event.declined = Some(error.to_string()),
    }
    event
}

/// Run the shared native dispatcher with explicitly selected data-VM/Mach services.
/// Unknown services remain precise trap stops, and a single aggregate budget
/// counts every native block across resumptions.
///
/// # Safety
/// All BlockRuntime direct-RAM requirements apply; this owner must cover data
/// used by trusted code. No concurrent guest execution or code/data mutation is
/// allowed. Executable transitions are declined rather than invalidated here.
pub unsafe fn run_services(
    runtime: &mut crate::blocks::BlockRuntime,
    state: &mut ThreadState,
    stop: Option<stela_compiler::GuestAddress>,
    budget: usize,
    memory: &mut crate::memory::OwnedMemory,
    mut services: ExecutionServices<'_>,
) -> anyhow::Result<ServiceRunOutcome> {
    use crate::blocks::{RunOutcome, StopReason};
    let mut aggregate: Option<RunOutcome> = None;
    let mut events = Vec::new();
    let mut mach_events = Vec::new();
    if let Some(ports) = services.mach_ports.as_ref() {
        anyhow::ensure!(
            ports.address_space() == runtime.address_space(),
            "Mach ports belong to another guest address space"
        );
    }
    let mut executed = 0;
    loop {
        anyhow::ensure!(
            memory.is_usable(),
            "refusing execution in an unusable guest address space"
        );
        let mut part = unsafe {
            match (services.pauth, services.clock.as_deref_mut()) {
                (Some(pauth), Some(clock)) => {
                    runtime.run_with_clock(state, stop, budget - executed, pauth, clock)?
                }
                (Some(pauth), None) => {
                    runtime.run_with_pauth(state, stop, budget - executed, pauth)?
                }
                (None, None) => runtime.run(state, stop, budget - executed)?,
                (None, Some(_)) => anyhow::bail!("clock execution requires a PAC context"),
            }
        };
        executed += part.blocks_executed;
        let trap = match &part.reason {
            StopReason::SynchronousTrap { trap } => Some(*trap),
            _ => None,
        };
        if let Some(total) = &mut aggregate {
            total.reason = part.reason;
            total.blocks_executed = executed;
            total.compiled_blocks += part.compiled_blocks;
            total.disk_cache_hits += part.disk_cache_hits;
            total.memory_cache_hits += part.memory_cache_hits;
            total.last_exit = part.last_exit.or(total.last_exit);
            total
                .pointer_authentication_events
                .append(&mut part.pointer_authentication_events);
            total.clock_events.append(&mut part.clock_events);
        } else {
            aggregate = Some(part);
        }
        let Some(trap) = trap else {
            break;
        };
        let serviced = if (state.registers.x[16] as u32 as i32) < 0 {
            if let Some(ports) = services.mach_ports.as_deref_mut() {
                let event = crate::mach::service(state, &trap, ports);
                let serviced = event.result.is_some();
                mach_events.push(event);
                serviced
            } else {
                false
            }
        } else if services.data_vm {
            let event = service_data_mprotect(state, &trap, memory, runtime);
            let serviced = event.completion.is_some();
            events.push(event);
            serviced
        } else {
            false
        };
        if !serviced {
            break;
        }
        let total = aggregate.as_mut().expect("one native dispatch outcome");
        if stop == Some(state.pc) {
            total.reason = StopReason::StopAddress;
            break;
        }
        if executed == budget {
            total.reason = StopReason::BudgetExhausted;
            break;
        }
    }
    Ok(ServiceRunOutcome {
        execution: aggregate.expect("one native dispatch outcome"),
        services: events,
        mach_services: mach_events,
    })
}

/// Data-only compatibility entry; Mach services remain absent unless supplied.
///
/// # Safety
/// The same direct-RAM requirements as `run_services` apply.
pub unsafe fn run_data_vm(
    runtime: &mut crate::blocks::BlockRuntime,
    state: &mut ThreadState,
    stop: Option<stela_compiler::GuestAddress>,
    budget: usize,
    memory: &mut crate::memory::OwnedMemory,
    mut services: ExecutionServices<'_>,
) -> anyhow::Result<ServiceRunOutcome> {
    services.data_vm = true;
    unsafe { run_services(runtime, state, stop, budget, memory, services) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::{GuestAddress, GuestState};

    fn state(selector: u64, flags: u32) -> ThreadState {
        let mut registers = GuestState {
            sp: 0x12340000,
            nzcv: flags << 28,
            reserved: 0xa5c39e71,
            ..GuestState::default()
        };
        for index in 0..31 {
            registers.x[index] = 0xdeadbeef12340000 + index as u64;
        }
        registers.v = std::array::from_fn(|index| {
            [
                0x0123456789abcdefu64.rotate_left(index as u32),
                0xfedcba9876543210u64.rotate_right(index as u32),
            ]
        });
        registers.fpcr = 0xa5c39e71 ^ flags;
        registers.fpsr = 0x5a3c618e ^ flags;
        registers.x[16] = selector;
        ThreadState {
            registers,
            pc: GuestAddress(0x1000),
        }
    }
    fn trap() -> SynchronousTrap {
        SynchronousTrap {
            kind: TrapKind::SupervisorCall,
            immediate: 0x80,
            instruction_pc: GuestAddress(0x1000),
            exception_return_pc: GuestAddress(0x1004),
        }
    }
    fn prototype(return_type: BsdReturnType, argument_count: usize) -> BsdPrototype {
        BsdPrototype {
            argument_count,
            return_type,
        }
    }
    fn same(actual: &ThreadState, expected: &ThreadState) {
        assert_eq!(actual.pc, expected.pc);
        assert_eq!(actual.registers, expected.registers);
    }

    #[test]
    fn dispatch_truncation_and_full_width_indirect_selection_match_pinned_c() {
        for (x16, number, indirect) in [
            (4, 4, false),
            (0x12340004, 4, false),
            (0, 20, true),
            (0x1_0000_0000, 0, false),
            (0xffff_ffff_0000_0004, 4, false),
        ] {
            let mut input = state(x16, 15);
            input.registers.x[0] = 0xabcd_0014;
            let before = input.clone();
            let selected = classify_bsd_call(&input, &trap()).unwrap();
            assert_eq!(selected, BsdSelector { number, indirect });
            let pending =
                PendingBsdCall::from_trap(&input, &trap(), prototype(BsdReturnType::Int, 8))
                    .unwrap();
            let start = usize::from(indirect);
            assert_eq!(
                pending.request().arguments(),
                &input.registers.x[start..start + 8]
            );
            assert_eq!(pending.request().number, number);
            same(&input, &before);
        }
    }

    #[test]
    fn request_exposes_and_serializes_only_declared_argument_slots() {
        for argument_count in 0..=MAX_BSD_ARGUMENTS {
            for selector in [0, 4] {
                let input = state(selector, 0);
                let declared = prototype(BsdReturnType::SignedSize, argument_count);
                let pending = PendingBsdCall::from_trap(&input, &trap(), declared).unwrap();
                let request = pending.request();
                let start = usize::from(selector == 0);
                let expected = &input.registers.x[start..start + argument_count];
                assert_eq!(request.arguments(), expected);
                assert_eq!(request.prototype(), declared);
                assert!(
                    request.arguments[argument_count..]
                        .iter()
                        .all(|slot| *slot == 0)
                );
                let encoded = serde_json::to_value(request).unwrap();
                assert_eq!(encoded["arguments"], serde_json::json!(expected));
                assert_eq!(
                    encoded["prototype"],
                    serde_json::to_value(declared).unwrap()
                );
            }
        }
    }

    #[test]
    fn mach_platform_and_invalid_prototypes_are_typed_declines_without_state_changes() {
        for x16 in [0x80000000, 0xffff_ffff_8000_0000] {
            let input = state(x16, 15);
            assert_eq!(
                classify_bsd_call(&input, &trap()).unwrap_err(),
                AbiError::PlatformCall { raw_x16: x16 }
            );
        }
        for x16 in [0xffffffe1, u64::MAX] {
            let input = state(x16, 15);
            assert_eq!(
                classify_bsd_call(&input, &trap()).unwrap_err(),
                AbiError::MachCall {
                    number: x16 as u32 as i32,
                    raw_x16: x16
                }
            );
        }
        let input = state(4, 15);
        assert_eq!(
            PendingBsdCall::from_trap(&input, &trap(), prototype(BsdReturnType::SignedSize, 9))
                .unwrap_err(),
            AbiError::InvalidPrototype { argument_count: 9 }
        );
    }

    #[test]
    fn trap_kind_immediate_pc_and_return_pc_must_be_coherent() {
        let input = state(4, 15);
        for invalid in [
            SynchronousTrap {
                kind: TrapKind::SoftwareBreakpoint,
                ..trap()
            },
            SynchronousTrap {
                immediate: 0,
                ..trap()
            },
            SynchronousTrap {
                instruction_pc: GuestAddress(0x1002),
                ..trap()
            },
            SynchronousTrap {
                instruction_pc: GuestAddress(0x1004),
                ..trap()
            },
            SynchronousTrap {
                exception_return_pc: GuestAddress(0x1008),
                ..trap()
            },
        ] {
            assert!(classify_bsd_call(&input, &invalid).is_err());
        }
        let mut invalid = input.clone();
        invalid.registers.nzcv |= 1;
        assert!(classify_bsd_call(&invalid, &trap()).is_err());
    }

    #[test]
    fn all_success_return_types_normalize_slots_and_preserve_other_state() {
        for flags in 0..16 {
            for (return_type, expected_words) in [
                (
                    BsdReturnType::Int,
                    Some([0xffff_ffff_8765_4321, 0x12345678]),
                ),
                (BsdReturnType::UnsignedInt, Some([0x87654321, 0x12345678])),
                (BsdReturnType::Offset, Some([0x1234567887654321, 0])),
                (BsdReturnType::Address, Some([0x1234567887654321, 0])),
                (BsdReturnType::Size, Some([0x1234567887654321, 0])),
                (BsdReturnType::SignedSize, Some([0x1234567887654321, 0])),
                (BsdReturnType::Unsigned64, Some([0x1234567887654321, 0])),
                (BsdReturnType::None, None),
            ] {
                let mut input = state(4, flags);
                let mut expected = input.clone();
                expected.pc = trap().exception_return_pc;
                expected.registers.nzcv &= !CARRY;
                if let Some(values) = expected_words {
                    expected.registers.x[..2].copy_from_slice(&values);
                }
                PendingBsdCall::from_trap(&input, &trap(), prototype(return_type, 3))
                    .unwrap()
                    .complete(
                        &mut input,
                        BsdCompletion::Success {
                            values: [0x87654321, 0x12345678],
                        },
                    )
                    .unwrap();
                same(&input, &expected);
            }
        }
        let mut input = state(4, 15);
        PendingBsdCall::from_trap(&input, &trap(), prototype(BsdReturnType::Int, 0))
            .unwrap()
            .complete(
                &mut input,
                BsdCompletion::Success {
                    values: [u32::MAX, 0x80000000],
                },
            )
            .unwrap();
        assert_eq!(input.registers.x[..2], [u64::MAX, 0xffffffff80000000]);
    }

    #[test]
    fn errno_sets_only_return_registers_carry_and_continuation_pc() {
        for flags in 0..16 {
            let mut input = state(4, flags);
            let mut expected = input.clone();
            expected.pc = trap().exception_return_pc;
            expected.registers.x[0] = 14;
            expected.registers.x[1] = 0;
            expected.registers.nzcv |= CARRY;
            PendingBsdCall::from_trap(&input, &trap(), prototype(BsdReturnType::SignedSize, 3))
                .unwrap()
                .complete(&mut input, BsdCompletion::Error { errno: 14 })
                .unwrap();
            same(&input, &expected);
        }
    }

    #[test]
    fn restart_preserves_indirect_number_arguments_and_clears_only_carry() {
        for selector in [0, 4, 0x1_0000_0000] {
            for flags in 0..16 {
                let mut input = state(selector, flags);
                input.registers.x[0] = 20;
                let original_selector = classify_bsd_call(&input, &trap()).unwrap();
                let mut expected = input.clone();
                expected.registers.nzcv &= !CARRY;
                PendingBsdCall::from_trap(&input, &trap(), prototype(BsdReturnType::Int, 8))
                    .unwrap()
                    .complete(&mut input, BsdCompletion::Restart)
                    .unwrap();
                same(&input, &expected);
                assert_eq!(
                    classify_bsd_call(&input, &trap()).unwrap(),
                    original_selector
                );
            }
        }
    }

    #[test]
    fn state_drift_invalid_errno_and_just_return_fail_atomically() {
        for change in 0..9 {
            let mut input = state(4, 15);
            let pending =
                PendingBsdCall::from_trap(&input, &trap(), prototype(BsdReturnType::SignedSize, 3))
                    .unwrap();
            match change {
                0 => input.pc.0 += 4,
                1 => input.registers.x[30] ^= 1,
                2 => input.registers.x[16] ^= 1,
                3 => input.registers.sp += 16,
                4 => input.registers.nzcv ^= CARRY,
                5 => input.registers.reserved ^= 1,
                6 => input.registers.v[31][1] ^= 1,
                7 => input.registers.fpcr ^= 1,
                _ => input.registers.fpsr ^= 1,
            }
            let changed = input.clone();
            assert_eq!(
                pending
                    .complete(&mut input, BsdCompletion::Success { values: [10, 0] })
                    .unwrap_err(),
                AbiError::StateChanged
            );
            same(&input, &changed);
        }
        for completion in [
            BsdCompletion::Error { errno: 0 },
            BsdCompletion::Error { errno: 0x80000000 },
            BsdCompletion::JustReturn,
        ] {
            let mut input = state(4, 15);
            let before = input.clone();
            let pending =
                PendingBsdCall::from_trap(&input, &trap(), prototype(BsdReturnType::SignedSize, 3))
                    .unwrap();
            let error = pending.complete(&mut input, completion).unwrap_err();
            assert_eq!(
                error,
                match completion {
                    BsdCompletion::Error { errno } => AbiError::InvalidErrno { errno },
                    _ => AbiError::UnsupportedJustReturn,
                }
            );
            same(&input, &before);
        }
    }
}

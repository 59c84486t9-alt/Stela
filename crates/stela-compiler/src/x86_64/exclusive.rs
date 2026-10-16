//! Exclusive loads and stores through the per-thread reservation in the memory
//! service, which owns the access, ordering, faults and monitor state.

use super::{load, memory_context as memory, store};
use crate::{
    CompileError,
    aarch64::{
        AddressMode, Register,
        exclusive::{Data, Kind, Operand},
    },
    block::CheckedMemoryProfile,
    context::memory::{
        MEMORY_REQUEST_BYTES, MemoryOrder, MemoryRequirements, SpAlignmentRequirement,
        exclusive::{
            EXCLUSIVE_DATA_BYTES, EXCLUSIVE_OPERATION_OFFSET, EXCLUSIVE_ORDER_OFFSET,
            EXCLUSIVE_SHAPE_OFFSET, EXCLUSIVE_STATUS_OFFSET, EXCLUSIVE_VALUE_OFFSET,
            ExclusiveOperation, ExclusiveShape,
        },
        flags, host_caps, profile_requirements,
    },
};
use alloc::vec::Vec;

const BYTE_BYTES: u8 = 1;
const HALFWORD_BYTES: u8 = 2;
const WORD_BYTES: u8 = 4;
const DOUBLEWORD_BYTES: u8 = 8;
const PAIR_MEMBERS: u8 = 2;
const DOUBLEWORD_PAIR_BYTES: u8 = PAIR_MEMBERS * DOUBLEWORD_BYTES;
const GPR_COUNT: u8 = 31;
const VECTOR_BYTES: u32 = 16;
const STACK_ALIGNMENT_BYTES: u32 = 16;
const REQUEST_OFFSET: u32 = 0;
const DATA_OFFSET: u32 = MEMORY_REQUEST_BYTES as u32;
const SCRATCH_BYTES: u32 = (DATA_OFFSET + EXCLUSIVE_DATA_BYTES as u32)
    .div_ceil(STACK_ALIGNMENT_BYTES)
    * STACK_ALIGNMENT_BYTES;
const _: () = assert!(SCRATCH_BYTES <= i8::MAX as u32);
const SUB_RSP_IMM8: &[u8] = &[0x48, 0x83, 0xec];
const ADD_RSP_IMM8: &[u8] = &[0x48, 0x83, 0xc4];
const PXOR_XMM0_XMM0: &[u8] = &[0x66, 0x0f, 0xef, 0xc0];
const MOVDQU_RSP_DISP8_XMM0: &[u8] = &[0xf3, 0x0f, 0x7f, 0x44, 0x24];
const MOV_RSP_DISP8_IMM32: &[u8] = &[0xc7, 0x44, 0x24];
const MOV_RSP_DISP8_AL: &[u8] = &[0x88, 0x44, 0x24];
const MOV_RSP_DISP8_AX: &[u8] = &[0x66, 0x89, 0x44, 0x24];
const MOV_RSP_DISP8_EAX: &[u8] = &[0x89, 0x44, 0x24];
const MOV_RSP_DISP8_RAX: &[u8] = &[0x48, 0x89, 0x44, 0x24];
const MOVZX_EAX_BYTE_RSP_DISP8: &[u8] = &[0x0f, 0xb6, 0x44, 0x24];
const MOVZX_EAX_WORD_RSP_DISP8: &[u8] = &[0x0f, 0xb7, 0x44, 0x24];
const MOV_EAX_RSP_DISP8: &[u8] = &[0x8b, 0x44, 0x24];
const MOV_RAX_RSP_DISP8: &[u8] = &[0x48, 0x8b, 0x44, 0x24];
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];

/// One control specialization drives both the body's metadata and its emission.
/// The checked entry selects it from the live controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CheckedOperand {
    operand: Operand,
    profile: CheckedMemoryProfile,
}

impl CheckedOperand {
    pub(crate) fn new(
        operand: Operand,
        profile: CheckedMemoryProfile,
    ) -> Result<Self, CompileError> {
        validate(&operand)?;
        Ok(Self { operand, profile })
    }
}

fn data_register(register: Register) -> bool {
    matches!(register, Register::X(index) if index < GPR_COUNT) || register == Register::Zero
}

/// Constructed operands must obey the same register-role and constrained-UNDEF
/// boundary as the existing decoder. Decode errors require a source-bound
/// generic undefined-instruction exit; they never become successful transfers.
fn validate(operand: &Operand) -> Result<(), CompileError> {
    let Operand::Transfer {
        element_bytes,
        base,
        data,
        kind,
    } = *operand
    else {
        return Ok(());
    };
    let base_valid =
        matches!(base, Register::X(index) if index < GPR_COUNT) || base == Register::Sp;
    let data_valid = match data {
        Data::Scalar(register) => {
            matches!(
                element_bytes,
                BYTE_BYTES | HALFWORD_BYTES | WORD_BYTES | DOUBLEWORD_BYTES
            ) && data_register(register)
        }
        Data::Pair(registers) => {
            matches!(element_bytes, WORD_BYTES | DOUBLEWORD_BYTES)
                && registers.into_iter().all(data_register)
        }
    };
    let constrained = match (data, kind) {
        (Data::Pair([first, second]), Kind::Load { .. }) => first == second,
        (data, Kind::Store { status, .. }) => {
            if !data_register(status) {
                return Err(CompileError("invalid exclusive status register".into()));
            }
            let data_overlap = match data {
                Data::Scalar(register) => status == register,
                Data::Pair(registers) => registers.contains(&status),
            };
            data_overlap || base != Register::Sp && status == base
        }
        _ => false,
    };
    if !base_valid || !data_valid {
        return Err(CompileError("invalid exclusive transfer operands".into()));
    }
    if constrained {
        return Err(CompileError(
            "constrained exclusive operands require a generic undefined-instruction boundary"
                .into(),
        ));
    }
    Ok(())
}

fn descriptor(operand: &Operand) -> u32 {
    flags::EXCLUSIVE
        | match *operand {
            Operand::Clear => 0,
            Operand::Transfer { base, kind, .. } => {
                (if matches!(kind, Kind::Store { .. }) {
                    flags::WRITE
                } else {
                    0
                }) | if base != Register::Sp {
                    flags::TAG_CHECKED
                } else {
                    0
                }
            }
        }
}

fn total_bytes(element_bytes: u8, data: Data) -> u32 {
    u32::from(element_bytes)
        * if matches!(data, Data::Pair(_)) {
            u32::from(PAIR_MEMBERS)
        } else {
            1
        }
}

pub(crate) fn requirements(checked: &CheckedOperand) -> MemoryRequirements {
    let operand = &checked.operand;
    let Operand::Transfer {
        element_bytes,
        base,
        data,
        kind,
    } = *operand
    else {
        return MemoryRequirements {
            required_flags: flags::EXCLUSIVE,
            ..MemoryRequirements::default()
        };
    };
    let bytes = total_bytes(element_bytes, data);
    let required_host_caps = match kind {
        Kind::Load { .. }
            if bytes == u32::from(DOUBLEWORD_PAIR_BYTES)
                || bytes > u32::from(BYTE_BYTES)
                    && (base != Register::Sp
                        || checked.profile.sp_requirement()
                            == SpAlignmentRequirement::Disabled) =>
        {
            host_caps::ATOMIC_LOAD16
        }
        Kind::Store { .. } if bytes == u32::from(DOUBLEWORD_PAIR_BYTES) => host_caps::CX16,
        _ => 0,
    };
    MemoryRequirements {
        required_pointer_arithmetic: None,
        required_address_checks: checked.profile.direct_address_requirements(),
        required_flags: descriptor(operand),
        required_host_caps,
        required_profile: profile_requirements::NATIVE_ACCESS
            | if base != Register::Sp {
                profile_requirements::TAG_GRANULES
            } else {
                0
            },
        required_sp_alignment: if base == Register::Sp {
            checked.profile.sp_requirement()
        } else {
            SpAlignmentRequirement::Any
        },
    }
}

fn initialize(code: &mut Vec<u8>) {
    code.extend(PXOR_XMM0_XMM0);
    for offset in (0..EXCLUSIVE_DATA_BYTES as u32).step_by(VECTOR_BYTES as usize) {
        code.extend(MOVDQU_RSP_DISP8_XMM0);
        code.push((DATA_OFFSET + offset) as u8);
    }
}

fn set_field(code: &mut Vec<u8>, offset: u32, value: u32) {
    // The complete payload was initialized. Zero-valued fields need no rewrite.
    if value != 0 {
        code.extend(MOV_RSP_DISP8_IMM32);
        code.push((DATA_OFFSET + offset) as u8);
        code.extend(value.to_le_bytes());
    }
}

fn stage(code: &mut Vec<u8>, register: Register, bytes: u8, offset: u32) {
    if register == Register::Zero {
        return;
    }
    load(code, register);
    code.extend(match bytes {
        BYTE_BYTES => MOV_RSP_DISP8_AL,
        HALFWORD_BYTES => MOV_RSP_DISP8_AX,
        WORD_BYTES => MOV_RSP_DISP8_EAX,
        DOUBLEWORD_BYTES => MOV_RSP_DISP8_RAX,
        _ => unreachable!("validated exclusive element width"),
    });
    code.push((DATA_OFFSET + offset) as u8);
}

fn commit(code: &mut Vec<u8>, register: Register, bytes: u8, offset: u32) {
    if register == Register::Zero {
        return;
    }
    code.extend(match bytes {
        BYTE_BYTES => MOVZX_EAX_BYTE_RSP_DISP8,
        HALFWORD_BYTES => MOVZX_EAX_WORD_RSP_DISP8,
        WORD_BYTES => MOV_EAX_RSP_DISP8,
        DOUBLEWORD_BYTES => MOV_RAX_RSP_DISP8,
        _ => unreachable!("validated exclusive result width"),
    });
    code.push((DATA_OFFSET + offset) as u8);
    store(code, register);
}

fn transfer_data(code: &mut Vec<u8>, data: Data, element_bytes: u8, loading: bool) {
    let emit = if loading { commit } else { stage };
    match data {
        Data::Scalar(register) => emit(code, register, element_bytes, EXCLUSIVE_VALUE_OFFSET),
        Data::Pair(registers) => {
            for (index, register) in registers.into_iter().enumerate() {
                emit(
                    code,
                    register,
                    element_bytes,
                    EXCLUSIVE_VALUE_OFFSET + index as u32 * u32::from(element_bytes),
                );
            }
        }
    }
}

/// The checked entry binds the body's requirements and the thread's memory
/// owner before execution. Each callback handles one exclusive access or CLREX;
/// on failure scratch space is released first.
pub(crate) fn emit_context(
    code: &mut Vec<u8>,
    checked: &CheckedOperand,
    pc: u64,
) -> Result<(), CompileError> {
    let operand = &checked.operand;
    validate(operand)?;
    code.extend(SUB_RSP_IMM8);
    code.push(SCRATCH_BYTES as u8);
    memory::begin(code);
    let (base, bytes, operation, order, shape) = match *operand {
        Operand::Clear => (
            None,
            0,
            ExclusiveOperation::Clear,
            MemoryOrder::Relaxed,
            ExclusiveShape::Scalar,
        ),
        Operand::Transfer {
            element_bytes,
            base,
            data,
            kind,
        } => {
            let (operation, order) = match kind {
                Kind::Load { acquire } => (
                    ExclusiveOperation::Load,
                    if acquire {
                        MemoryOrder::AcquireRcsc
                    } else {
                        MemoryOrder::Relaxed
                    },
                ),
                Kind::Store { release, .. } => (
                    ExclusiveOperation::Store,
                    if release {
                        MemoryOrder::Release
                    } else {
                        MemoryOrder::Relaxed
                    },
                ),
            };
            (
                Some(base),
                total_bytes(element_bytes, data),
                operation,
                order,
                if matches!(data, Data::Pair(_)) {
                    ExclusiveShape::Pair
                } else {
                    ExclusiveShape::Scalar
                },
            )
        }
    };
    let sp_failure = if checked.profile.sp_requirement() == SpAlignmentRequirement::Enabled {
        base.and_then(|base| memory::address::check_sp(code, base, pc))
    } else {
        None
    };
    if let Some(base) = base {
        memory::address::immediate(code, base, 0, AddressMode::Offset);
    } else {
        code.extend(XOR_EAX_EAX);
    }
    memory::request(
        code,
        REQUEST_OFFSET,
        DATA_OFFSET,
        bytes,
        descriptor(operand),
        pc,
    );
    initialize(code);
    set_field(code, EXCLUSIVE_OPERATION_OFFSET, operation as u32);
    set_field(code, EXCLUSIVE_ORDER_OFFSET, order as u32);
    set_field(code, EXCLUSIVE_SHAPE_OFFSET, shape as u32);
    if let Operand::Transfer {
        element_bytes,
        data,
        kind: Kind::Store { .. },
        ..
    } = *operand
    {
        transfer_data(code, data, element_bytes, false);
    }
    memory::call(code, REQUEST_OFFSET);
    let callback_failure = memory::branch_failed(code);
    match *operand {
        Operand::Transfer {
            element_bytes,
            data,
            kind: Kind::Load { .. },
            ..
        } => transfer_data(code, data, element_bytes, true),
        Operand::Transfer {
            kind: Kind::Store { status, .. },
            ..
        } => commit(code, status, WORD_BYTES, EXCLUSIVE_STATUS_OFFSET),
        Operand::Clear => {}
    }
    code.extend(XOR_EAX_EAX);
    let cleanup = code.len();
    memory::patch_branch(code, callback_failure, cleanup);
    if let Some(failure) = sp_failure {
        memory::patch_branch(code, failure, cleanup);
    }
    code.extend(ADD_RSP_IMM8);
    code.push(SCRATCH_BYTES as u8);
    memory::address::return_if_failed(code);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::exclusive::{ConstrainedUndefined, decode};
    use alloc::format;
    use alloc::vec;
    use alloc::vec::Vec;

    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    mod native_component {
        //! Emitted exclusive-access code run against a test memory-service callback.
        use super::*;
        use crate::{
            GuestState,
            context::{
                ExecutionContext,
                memory::{
                    MEMORY_CONTEXT_BYTES, MEMORY_CONTEXT_VERSION, MemoryContextView, MemoryRequest,
                    MemoryStatus,
                    exclusive::{
                        EXCLUSIVE_DATA_ALIGNMENT, EXCLUSIVE_FAILED, EXCLUSIVE_STORED, ExclusiveData,
                    },
                },
            },
        };
        use core::ffi::c_void;

        unsafe extern "C" {
            fn mmap(
                address: *mut c_void,
                bytes: usize,
                protection: i32,
                flags: i32,
                fd: i32,
                offset: i64,
            ) -> *mut c_void;
            fn mprotect(address: *mut c_void, bytes: usize, protection: i32) -> i32;
            fn munmap(address: *mut c_void, bytes: usize) -> i32;
        }
        const CODE_ALLOCATION_BYTES: usize = 4096;
        const PROT_READ_WRITE: i32 = 3;
        const PROT_READ_EXECUTE: i32 = 5;
        const MAP_PRIVATE: i32 = 2;
        #[cfg(target_os = "macos")]
        const MAP_ANONYMOUS: i32 = 0x1000;
        #[cfg(target_os = "linux")]
        const MAP_ANONYMOUS: i32 = 0x20;
        const TEST_PC: u64 = 0x4100_0000;
        const TEST_ADDRESS: u64 = 0x5200_0000;
        const ENTRY: &[u8] = &[
            0x41, 0x57, 0x49, 0x89, 0xf7, 0xe8, 3, 0, 0, 0, 0x41, 0x5f, 0xc3,
        ];
        const RET: u8 = 0xc3;

        struct Executable {
            pointer: *mut c_void,
            bytes: Vec<u8>,
        }
        impl Executable {
            fn new(operand: &Operand) -> Self {
                let mut bytes = ENTRY.to_vec();
                emit_context(&mut bytes, operand, TEST_PC).unwrap();
                bytes.push(RET);
                assert!(bytes.len() <= CODE_ALLOCATION_BYTES);
                // SAFETY: private anonymous memory becomes RX after exact bytes copy.
                let pointer = unsafe {
                    mmap(
                        core::ptr::null_mut(),
                        CODE_ALLOCATION_BYTES,
                        PROT_READ_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                assert_ne!(pointer as usize, usize::MAX);
                unsafe {
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer.cast(), bytes.len())
                };
                assert_eq!(
                    unsafe { mprotect(pointer, CODE_ALLOCATION_BYTES, PROT_READ_EXECUTE) },
                    0
                );
                Self { pointer, bytes }
            }
            fn run(&self, state: &mut GuestState, view: &mut MemoryContextView) -> u32 {
                let context = ExecutionContext {
                    memory: core::ptr::from_mut(view).cast(),
                    ..ExecutionContext::default()
                };
                let entry: unsafe extern "sysv64" fn(
                    *mut GuestState,
                    *const ExecutionContext,
                ) -> u32 = unsafe { core::mem::transmute(self.pointer) };
                unsafe { entry(state, &context) }
            }
        }
        impl Drop for Executable {
            fn drop(&mut self) {
                assert_eq!(unsafe { munmap(self.pointer, CODE_ALLOCATION_BYTES) }, 0);
            }
        }

        struct Observation {
            expected: ExclusiveData,
            output: ExclusiveData,
            bytes: u32,
            flags: u32,
            address: u64,
            status: MemoryStatus,
            calls: usize,
        }

        unsafe extern "sysv64" fn callback(
            view: *mut MemoryContextView,
            request: *const MemoryRequest,
        ) -> u32 {
            let view = unsafe { &mut *view };
            let request = unsafe { &*request };
            let observation = unsafe { &mut *view.opaque.cast::<Observation>() };
            assert_eq!(request.pc, TEST_PC);
            assert_eq!(request.address, observation.address);
            assert_eq!(request.bytes, observation.bytes);
            assert_eq!(request.flags, observation.flags);
            assert!((request.data as usize).is_multiple_of(EXCLUSIVE_DATA_ALIGNMENT));
            let payload = unsafe { &mut *request.data.cast::<ExclusiveData>() };
            assert_eq!(*payload, observation.expected);
            assert!(payload.validate(request.bytes).is_some());
            observation.calls += 1;
            // A fault deliberately dirties private staging to prove no destination is
            // committed. This adversarial test double is not the runtime service.
            *payload = observation.output;
            view.record(observation.status, request.address, request.pc, 0);
            observation.status as u32
        }

        fn initial_state() -> GuestState {
            let mut state = GuestState::default();
            for (index, value) in state.x.iter_mut().enumerate() {
                *value = 0x1020_3040_5060_7080_u64.wrapping_mul(index as u64 + 1);
            }
            state.sp = TEST_ADDRESS;
            state.nzcv = 0xf000_0000;
            state.fpcr = 0x03c0_0000;
            state.fpsr = 0x0800_001f;
            state.reserved = 0x1234_5678;
            for (register, vector) in state.v.iter_mut().enumerate() {
                *vector = [register as u64 * 17 + 3, register as u64 * 23 + 5];
            }
            state
        }

        fn view(observation: &mut Observation) -> MemoryContextView {
            MemoryContextView {
                version: MEMORY_CONTEXT_VERSION,
                bytes: MEMORY_CONTEXT_BYTES,
                callback,
                opaque: core::ptr::from_mut(observation).cast(),
                fault_kind: 7,
                reserved: 0,
                fault_address: 0x1234,
                fault_pc: 0x5678,
                completed_bytes: 999,
                reserved_tail: 0,
            }
        }

        fn source(state: &GuestState, register: Register) -> u64 {
            match register {
                Register::X(index) => state.x[usize::from(index)],
                Register::Zero => 0,
                Register::Sp => state.sp,
            }
        }

        fn expected_payload(operand: &Operand, before: &GuestState) -> (ExclusiveData, u32, u64) {
            let mut payload = ExclusiveData::default();
            let Operand::Transfer {
                element_bytes,
                base,
                data,
                kind,
            } = *operand
            else {
                payload.operation = ExclusiveOperation::Clear as u32;
                return (payload, 0, 0);
            };
            payload.shape = if matches!(data, Data::Pair(_)) {
                ExclusiveShape::Pair as u32
            } else {
                ExclusiveShape::Scalar as u32
            };
            payload.order = match kind {
                Kind::Load { acquire: false } | Kind::Store { release: false, .. } => {
                    MemoryOrder::Relaxed
                }
                Kind::Load { acquire: true } => MemoryOrder::AcquireRcsc,
                Kind::Store { release: true, .. } => MemoryOrder::Release,
            } as u32;
            if matches!(kind, Kind::Store { .. }) {
                payload.operation = ExclusiveOperation::Store as u32;
                let mut value = [0_u8; 16];
                let registers = match data {
                    Data::Scalar(register) => vec![register],
                    Data::Pair(registers) => registers.to_vec(),
                };
                for (index, register) in registers.into_iter().enumerate() {
                    let start = index * usize::from(element_bytes);
                    value[start..start + usize::from(element_bytes)].copy_from_slice(
                        &source(before, register).to_le_bytes()[..usize::from(element_bytes)],
                    );
                }
                payload.value = [
                    u64::from_le_bytes(value[..8].try_into().unwrap()),
                    u64::from_le_bytes(value[8..].try_into().unwrap()),
                ];
            }
            (
                payload,
                total_bytes(element_bytes, data),
                source(before, base),
            )
        }

        fn commit_expected(expected: &mut GuestState, operand: &Operand, output: ExclusiveData) {
            let Operand::Transfer {
                element_bytes,
                data,
                kind,
                ..
            } = *operand
            else {
                return;
            };
            match kind {
                Kind::Load { .. } => {
                    let mut raw = [0_u8; 16];
                    raw[..8].copy_from_slice(&output.value[0].to_le_bytes());
                    raw[8..].copy_from_slice(&output.value[1].to_le_bytes());
                    let registers = match data {
                        Data::Scalar(register) => vec![register],
                        Data::Pair(registers) => registers.to_vec(),
                    };
                    for (index, register) in registers.into_iter().enumerate() {
                        if let Register::X(register) = register {
                            let start = index * usize::from(element_bytes);
                            let mut value = [0_u8; 8];
                            value[..usize::from(element_bytes)]
                                .copy_from_slice(&raw[start..start + usize::from(element_bytes)]);
                            expected.x[usize::from(register)] = u64::from_le_bytes(value);
                        }
                    }
                }
                Kind::Store {
                    status: Register::X(register),
                    ..
                } => {
                    expected.x[usize::from(register)] = u64::from(output.status);
                }
                Kind::Store { .. } => {}
            }
        }

        #[test]
        fn emitted_exclusive_payloads_results_and_faults_match_private_abi() {
            assert_eq!(size_of::<GuestState>(), 784);
            assert_eq!(size_of::<ExclusiveData>(), EXCLUSIVE_DATA_BYTES);
            assert_eq!(align_of::<ExclusiveData>(), EXCLUSIVE_DATA_ALIGNMENT);
            let dump =
                std::env::var_os("STELA_EXCLUSIVE_COMPONENT_OUTPUT").map(std::path::PathBuf::from);
            if let Some(path) = &dump {
                std::fs::create_dir_all(path).unwrap();
            }
            let mut bodies = 0;
            let mut executions = 0;
            let mut operands = vec![Operand::Clear];
            for base in [Register::X(3), Register::Sp] {
                for element_bytes in [BYTE_BYTES, HALFWORD_BYTES, WORD_BYTES, DOUBLEWORD_BYTES] {
                    for data in [
                        Data::Scalar(Register::X(1)),
                        Data::Scalar(Register::Zero),
                        Data::Scalar(Register::X(3)),
                    ] {
                        for ordered in [false, true] {
                            operands.push(Operand::Transfer {
                                element_bytes,
                                base,
                                data,
                                kind: Kind::Load { acquire: ordered },
                            });
                            operands.push(Operand::Transfer {
                                element_bytes,
                                base,
                                data,
                                kind: Kind::Store {
                                    release: ordered,
                                    status: Register::X(0),
                                },
                            });
                        }
                    }
                }
                for element_bytes in [WORD_BYTES, DOUBLEWORD_BYTES] {
                    for data in [
                        Data::Pair([Register::X(1), Register::X(2)]),
                        Data::Pair([Register::Zero, Register::X(3)]),
                        Data::Pair([Register::X(3), Register::Zero]),
                    ] {
                        for ordered in [false, true] {
                            operands.push(Operand::Transfer {
                                element_bytes,
                                base,
                                data,
                                kind: Kind::Load { acquire: ordered },
                            });
                            operands.push(Operand::Transfer {
                                element_bytes,
                                base,
                                data,
                                kind: Kind::Store {
                                    release: ordered,
                                    status: Register::X(0),
                                },
                            });
                        }
                    }
                }
            }
            for operand in operands {
                let executable = Executable::new(&operand);
                if let Some(path) = &dump {
                    std::fs::write(path.join(format!("body-{bodies}.bin")), &executable.bytes)
                        .unwrap();
                }
                bodies += 1;
                for callback_status in [MemoryStatus::Success, MemoryStatus::Permission] {
                    for store_status in [EXCLUSIVE_STORED, EXCLUSIVE_FAILED] {
                        let mut before = initial_state();
                        before.x[3] = TEST_ADDRESS;
                        let (payload, bytes, address) = expected_payload(&operand, &before);
                        let output = ExclusiveData {
                            status: store_status,
                            value: [0xfedc_ba98_7654_3210, 0x1020_3040_5060_7080],
                            ..payload
                        };
                        let mut observation = Observation {
                            expected: payload,
                            output,
                            bytes,
                            flags: descriptor(&operand),
                            address,
                            status: callback_status,
                            calls: 0,
                        };
                        let mut expected = before.clone();
                        if callback_status == MemoryStatus::Success {
                            commit_expected(&mut expected, &operand, output);
                        }
                        let mut actual = before.clone();
                        let mut view = view(&mut observation);
                        assert_eq!(
                            executable.run(&mut actual, &mut view),
                            callback_status as u32
                        );
                        assert_eq!(observation.calls, 1);
                        assert_eq!(actual, expected);
                        executions += 1;
                    }
                }
            }
            std::println!("exclusive_component_bodies={bodies} executions={executions}");
        }

        #[test]
        fn emitted_original_sp_faults_precede_the_callback_and_all_results() {
            for kind in [
                Kind::Load { acquire: true },
                Kind::Store {
                    release: true,
                    status: Register::X(0),
                },
            ] {
                let operand = Operand::Transfer {
                    element_bytes: WORD_BYTES,
                    base: Register::Sp,
                    data: Data::Scalar(Register::X(1)),
                    kind,
                };
                let executable = Executable::new(&operand);
                for residue in 1..STACK_ALIGNMENT_BYTES {
                    let mut before = initial_state();
                    before.sp += u64::from(residue);
                    let (payload, bytes, address) = expected_payload(&operand, &before);
                    let mut observation = Observation {
                        expected: payload,
                        output: payload,
                        bytes,
                        flags: descriptor(&operand),
                        address,
                        status: MemoryStatus::Success,
                        calls: 0,
                    };
                    let mut actual = before.clone();
                    let mut view = view(&mut observation);
                    assert_eq!(
                        executable.run(&mut actual, &mut view),
                        MemoryStatus::StackAlignment as u32
                    );
                    assert_eq!(observation.calls, 0);
                    assert_eq!(actual, before);
                    assert_eq!(view.fault_address, before.sp);
                    assert_eq!(view.fault_pc, TEST_PC);
                    assert_eq!(view.completed_bytes, 0);
                }
            }
        }

        #[test]
        fn exclusive_wire_layout_and_negative_payloads_are_explicit() {
            use core::mem::offset_of;
            assert_eq!(size_of::<ExclusiveData>(), EXCLUSIVE_DATA_BYTES);
            assert_eq!(align_of::<ExclusiveData>(), EXCLUSIVE_DATA_ALIGNMENT);
            assert_eq!(
                offset_of!(ExclusiveData, operation),
                EXCLUSIVE_OPERATION_OFFSET as usize
            );
            assert_eq!(
                offset_of!(ExclusiveData, order),
                EXCLUSIVE_ORDER_OFFSET as usize
            );
            assert_eq!(
                offset_of!(ExclusiveData, shape),
                EXCLUSIVE_SHAPE_OFFSET as usize
            );
            assert_eq!(
                offset_of!(ExclusiveData, status),
                EXCLUSIVE_STATUS_OFFSET as usize
            );
            assert_eq!(
                offset_of!(ExclusiveData, value),
                EXCLUSIVE_VALUE_OFFSET as usize
            );
            for (shape, widths) in [
                (ExclusiveShape::Scalar, &[1, 2, 4, 8][..]),
                (ExclusiveShape::Pair, &[8, 16][..]),
            ] {
                for &bytes in widths {
                    for operation in [ExclusiveOperation::Load, ExclusiveOperation::Store] {
                        let mut valid = ExclusiveData {
                            operation: operation as u32,
                            shape: shape as u32,
                            ..ExclusiveData::default()
                        };
                        assert!(valid.validate(bytes).is_some());
                        valid.order = match operation {
                            ExclusiveOperation::Load => MemoryOrder::AcquireRcsc,
                            ExclusiveOperation::Store => MemoryOrder::Release,
                            ExclusiveOperation::Clear => unreachable!(),
                        } as u32;
                        assert!(valid.validate(bytes).is_some());
                        for invalid in [
                            ExclusiveData {
                                operation: u32::MAX,
                                ..valid
                            },
                            ExclusiveData {
                                order: u32::MAX,
                                ..valid
                            },
                            ExclusiveData {
                                shape: u32::MAX,
                                ..valid
                            },
                            ExclusiveData {
                                status: EXCLUSIVE_FAILED,
                                ..valid
                            },
                            ExclusiveData {
                                order: MemoryOrder::AcquireRcpc as u32,
                                ..valid
                            },
                            ExclusiveData {
                                order: MemoryOrder::AcquireRelease as u32,
                                ..valid
                            },
                        ] {
                            assert!(invalid.validate(bytes).is_none());
                        }
                        for invalid_width in [0, 3, 5, 7, 9, 15, 17, 32] {
                            assert!(valid.validate(invalid_width).is_none());
                        }
                        if operation == ExclusiveOperation::Load {
                            valid.value[0] = 1;
                            assert!(valid.validate(bytes).is_none());
                        } else if bytes < 16 {
                            valid.value[1] = 1;
                            assert!(valid.validate(bytes).is_none());
                            valid.value[1] = 0;
                            if bytes < 8 {
                                valid.value[0] = 1 << (bytes * 8);
                                assert!(valid.validate(bytes).is_none());
                            }
                        }
                    }
                }
            }
            let clear = ExclusiveData {
                operation: ExclusiveOperation::Clear as u32,
                ..ExclusiveData::default()
            };
            assert!(clear.validate(0).is_some());
            assert!(clear.validate(1).is_none());
            for invalid in [
                ExclusiveData {
                    order: MemoryOrder::Release as u32,
                    ..clear
                },
                ExclusiveData {
                    shape: ExclusiveShape::Pair as u32,
                    ..clear
                },
                ExclusiveData {
                    status: EXCLUSIVE_FAILED,
                    ..clear
                },
                ExclusiveData {
                    value: [1, 0],
                    ..clear
                },
                ExclusiveData {
                    value: [0, 1],
                    ..clear
                },
            ] {
                assert!(invalid.validate(0).is_none());
            }
        }
    }

    // Tests use the SP-alignment-enabled specialization.
    fn requirements(operand: &Operand) -> Result<MemoryRequirements, CompileError> {
        Ok(super::requirements(&CheckedOperand::new(
            *operand,
            CheckedMemoryProfile::SpAlignmentEnabled,
        )?))
    }
    fn emit_context(code: &mut Vec<u8>, operand: &Operand, pc: u64) -> Result<(), CompileError> {
        super::emit_context(
            code,
            &CheckedOperand::new(*operand, CheckedMemoryProfile::SpAlignmentEnabled)?,
            pc,
        )
    }

    const SCALAR_CLASS: u32 = 0x0800_0000;
    const PAIR_CLASS: u32 = 0x8820_0000;
    const CLEAR_CLASS: u32 = 0xd503_305f;
    const SIZE_SHIFT: u32 = 30;
    const LOAD_BIT: u32 = 1 << 22;
    const ACQUIRE_RELEASE_BIT: u32 = 1 << 15;
    const STATUS_SHIFT: u32 = 16;
    const SECOND_SHIFT: u32 = 10;
    const BASE_SHIFT: u32 = 5;
    const REGISTER_MASK: u32 = 31;
    const SBO_STATUS: u32 = REGISTER_MASK << STATUS_SHIFT;
    const SBO_SECOND: u32 = REGISTER_MASK << SECOND_SHIFT;
    const OBSERVED_LOAD_WORD: u32 = 0x885f_7d2a;

    #[test]
    fn existing_decoder_covers_all_twenty_five_forms_without_reinterpretation() {
        let mut forms = 0;
        for size in 0..4 {
            for load in [false, true] {
                for ordered in [false, true] {
                    let word = SCALAR_CLASS
                        | (size << SIZE_SHIFT)
                        | if load { LOAD_BIT | SBO_STATUS } else { 0 }
                        | if ordered { ACQUIRE_RELEASE_BIT } else { 0 }
                        | SBO_SECOND
                        | (2 << BASE_SHIFT)
                        | 1;
                    let operand = decode(word).unwrap().unwrap();
                    assert!(validate(&operand).is_ok());
                    let required = requirements(&operand).unwrap();
                    assert_eq!(required.required_flags & flags::EXCLUSIVE, flags::EXCLUSIVE);
                    assert_eq!(required.required_flags & flags::WRITE != 0, !load);
                    assert_eq!(
                        required.required_flags & flags::TAG_CHECKED,
                        flags::TAG_CHECKED
                    );
                    assert_eq!(required.required_flags & flags::PAIR, 0);
                    assert_eq!(required.required_sp_alignment, SpAlignmentRequirement::Any);
                    forms += 1;
                }
            }
        }
        for size in 0..2 {
            for load in [false, true] {
                for ordered in [false, true] {
                    let word = PAIR_CLASS
                        | (size << SIZE_SHIFT)
                        | if load { LOAD_BIT | SBO_STATUS } else { 0 }
                        | if ordered { ACQUIRE_RELEASE_BIT } else { 0 }
                        | (2 << SECOND_SHIFT)
                        | (3 << BASE_SHIFT)
                        | 1;
                    let operand = decode(word).unwrap().unwrap();
                    assert!(validate(&operand).is_ok());
                    assert_eq!(
                        requirements(&operand).unwrap().required_flags & flags::PAIR,
                        0
                    );
                    forms += 1;
                }
            }
        }
        assert_eq!(decode(CLEAR_CLASS), Some(Ok(Operand::Clear)));
        assert!(validate(&Operand::Clear).is_ok());
        forms += 1;
        assert_eq!(forms, 25);
        assert_eq!(
            decode(OBSERVED_LOAD_WORD),
            Some(Ok(Operand::Transfer {
                element_bytes: WORD_BYTES,
                base: Register::X(9),
                data: Data::Scalar(Register::X(10)),
                kind: Kind::Load { acquire: false }
            }))
        );
    }

    #[test]
    fn source_register_aliases_zr_and_acquire_intent_remain_explicit() {
        for element_bytes in [BYTE_BYTES, HALFWORD_BYTES, WORD_BYTES, DOUBLEWORD_BYTES] {
            for base in [Register::X(1), Register::Sp] {
                for data in [Register::X(1), Register::Zero] {
                    let operand = Operand::Transfer {
                        element_bytes,
                        base,
                        data: Data::Scalar(data),
                        kind: Kind::Load { acquire: true },
                    };
                    assert!(validate(&operand).is_ok());
                    assert!(matches!(
                        operand,
                        Operand::Transfer {
                            kind: Kind::Load { acquire: true },
                            ..
                        }
                    ));
                    assert_eq!(
                        requirements(&operand).unwrap().required_sp_alignment,
                        if base == Register::Sp {
                            SpAlignmentRequirement::Enabled
                        } else {
                            SpAlignmentRequirement::Any
                        }
                    );
                    let store = Operand::Transfer {
                        element_bytes,
                        base,
                        data: Data::Scalar(data),
                        kind: Kind::Store {
                            release: true,
                            status: Register::X(2),
                        },
                    };
                    assert!(validate(&store).is_ok());
                }
            }
        }
        let duplicate_sources = Operand::Transfer {
            element_bytes: DOUBLEWORD_BYTES,
            base: Register::X(1),
            data: Data::Pair([Register::X(1); 2]),
            kind: Kind::Store {
                release: false,
                status: Register::Zero,
            },
        };
        assert!(validate(&duplicate_sources).is_ok());
    }

    #[test]
    fn malformed_and_constrained_operands_fail_before_any_emission() {
        let valid = Operand::Transfer {
            element_bytes: WORD_BYTES,
            base: Register::X(3),
            data: Data::Scalar(Register::X(1)),
            kind: Kind::Store {
                release: false,
                status: Register::X(0),
            },
        };
        assert!(validate(&valid).is_ok());
        let invalid = [
            Operand::Transfer {
                element_bytes: 0,
                base: Register::X(3),
                data: Data::Scalar(Register::X(1)),
                kind: Kind::Load { acquire: false },
            },
            Operand::Transfer {
                element_bytes: HALFWORD_BYTES,
                base: Register::X(3),
                data: Data::Pair([Register::X(1), Register::X(2)]),
                kind: Kind::Load { acquire: false },
            },
            Operand::Transfer {
                element_bytes: WORD_BYTES,
                base: Register::Zero,
                data: Data::Scalar(Register::X(1)),
                kind: Kind::Load { acquire: false },
            },
            Operand::Transfer {
                element_bytes: WORD_BYTES,
                base: Register::X(GPR_COUNT),
                data: Data::Scalar(Register::X(1)),
                kind: Kind::Load { acquire: false },
            },
            Operand::Transfer {
                element_bytes: WORD_BYTES,
                base: Register::X(3),
                data: Data::Scalar(Register::Sp),
                kind: Kind::Load { acquire: false },
            },
            Operand::Transfer {
                element_bytes: WORD_BYTES,
                base: Register::X(3),
                data: Data::Scalar(Register::X(GPR_COUNT)),
                kind: Kind::Load { acquire: false },
            },
            Operand::Transfer {
                element_bytes: WORD_BYTES,
                base: Register::Sp,
                data: Data::Pair([Register::Zero; 2]),
                kind: Kind::Load { acquire: false },
            },
            Operand::Transfer {
                element_bytes: WORD_BYTES,
                base: Register::X(3),
                data: Data::Scalar(Register::X(1)),
                kind: Kind::Store {
                    release: false,
                    status: Register::X(1),
                },
            },
            Operand::Transfer {
                element_bytes: WORD_BYTES,
                base: Register::X(3),
                data: Data::Scalar(Register::X(1)),
                kind: Kind::Store {
                    release: false,
                    status: Register::X(3),
                },
            },
            Operand::Transfer {
                element_bytes: WORD_BYTES,
                base: Register::X(3),
                data: Data::Scalar(Register::Zero),
                kind: Kind::Store {
                    release: false,
                    status: Register::Zero,
                },
            },
        ];
        for operand in invalid {
            assert!(requirements(&operand).is_err());
            let mut code = vec![0x90];
            assert!(emit_context(&mut code, &operand, 0x1000).is_err());
            assert_eq!(code, [0x90]);
        }
        assert_eq!(
            decode(PAIR_CLASS | LOAD_BIT | SBO_STATUS | (2 << BASE_SHIFT)),
            Some(Err(ConstrainedUndefined::PairLoadOutputs))
        );
        assert_eq!(
            decode(SCALAR_CLASS | SBO_SECOND | (1 << BASE_SHIFT)),
            Some(Err(ConstrainedUndefined::StoreStatusData))
        );
    }

    #[test]
    fn exact_atomic_quantities_derive_read_and_write_host_requirements() {
        for base in [Register::X(3), Register::Sp] {
            for element_bytes in [BYTE_BYTES, HALFWORD_BYTES, WORD_BYTES, DOUBLEWORD_BYTES] {
                let load = Operand::Transfer {
                    element_bytes,
                    base,
                    data: Data::Scalar(Register::Zero),
                    kind: Kind::Load { acquire: true },
                };
                let required = requirements(&load).unwrap();
                assert_eq!(
                    required.required_host_caps,
                    if base != Register::Sp && element_bytes > BYTE_BYTES {
                        host_caps::ATOMIC_LOAD16
                    } else {
                        0
                    }
                );
                let store = Operand::Transfer {
                    element_bytes,
                    base,
                    data: Data::Scalar(Register::X(1)),
                    kind: Kind::Store {
                        release: true,
                        status: Register::X(0),
                    },
                };
                assert_eq!(requirements(&store).unwrap().required_host_caps, 0);
            }
            for element_bytes in [WORD_BYTES, DOUBLEWORD_BYTES] {
                let data = Data::Pair([Register::X(1), Register::X(2)]);
                let load = Operand::Transfer {
                    element_bytes,
                    base,
                    data,
                    kind: Kind::Load { acquire: true },
                };
                assert_eq!(
                    requirements(&load).unwrap().required_host_caps,
                    if base != Register::Sp || element_bytes == DOUBLEWORD_BYTES {
                        host_caps::ATOMIC_LOAD16
                    } else {
                        0
                    }
                );
                let store = Operand::Transfer {
                    element_bytes,
                    base,
                    data,
                    kind: Kind::Store {
                        release: true,
                        status: Register::X(0),
                    },
                };
                assert_eq!(
                    requirements(&store).unwrap().required_host_caps,
                    if element_bytes == DOUBLEWORD_BYTES {
                        host_caps::CX16
                    } else {
                        0
                    }
                );
            }
        }
        let clear = requirements(&Operand::Clear).unwrap();
        assert_eq!(
            clear,
            MemoryRequirements {
                required_flags: flags::EXCLUSIVE,
                ..MemoryRequirements::default()
            }
        );
    }

    #[test]
    fn immutable_profile_binds_sp_checks_and_conservative_read_capabilities() {
        for profile in [
            CheckedMemoryProfile::SpAlignmentEnabled,
            CheckedMemoryProfile::SpAlignmentDisabled,
        ] {
            for base in [Register::X(3), Register::Sp] {
                for (element_bytes, data) in [
                    (BYTE_BYTES, Data::Scalar(Register::X(1))),
                    (HALFWORD_BYTES, Data::Scalar(Register::X(1))),
                    (WORD_BYTES, Data::Scalar(Register::X(1))),
                    (DOUBLEWORD_BYTES, Data::Scalar(Register::X(1))),
                    (WORD_BYTES, Data::Pair([Register::X(1), Register::X(2)])),
                    (
                        DOUBLEWORD_BYTES,
                        Data::Pair([Register::X(1), Register::X(2)]),
                    ),
                ] {
                    for kind in [
                        Kind::Load { acquire: true },
                        Kind::Store {
                            release: true,
                            status: Register::X(0),
                        },
                    ] {
                        let operand = Operand::Transfer {
                            element_bytes,
                            base,
                            data,
                            kind,
                        };
                        let checked = CheckedOperand::new(operand, profile).unwrap();
                        let required = super::requirements(&checked);
                        assert_eq!(
                            required.required_sp_alignment,
                            if base == Register::Sp {
                                profile.sp_requirement()
                            } else {
                                SpAlignmentRequirement::Any
                            }
                        );
                        let quantity = total_bytes(element_bytes, data);
                        let expected_caps = match kind {
                            Kind::Load { .. }
                                if quantity == u32::from(DOUBLEWORD_PAIR_BYTES)
                                    || quantity > u32::from(BYTE_BYTES)
                                        && (base != Register::Sp
                                            || profile
                                                == CheckedMemoryProfile::SpAlignmentDisabled) =>
                            {
                                host_caps::ATOMIC_LOAD16
                            }
                            Kind::Store { .. } if quantity == u32::from(DOUBLEWORD_PAIR_BYTES) => {
                                host_caps::CX16
                            }
                            _ => 0,
                        };
                        assert_eq!(required.required_host_caps, expected_caps);
                        assert_eq!(required.required_flags, descriptor(&operand));
                    }
                }
            }
            let clear = CheckedOperand::new(Operand::Clear, profile).unwrap();
            assert_eq!(
                super::requirements(&clear),
                MemoryRequirements {
                    required_flags: flags::EXCLUSIVE,
                    ..MemoryRequirements::default()
                }
            );
        }
    }

    #[test]
    fn profile_specialization_preserves_gpr_clear_bytes() {
        const SOURCE_PC: u64 = 0x4100_0000;
        const ENTRY: &[u8] = &[
            0x41, 0x57, 0x49, 0x89, 0xf7, 0xe8, 3, 0, 0, 0, 0x41, 0x5f, 0xc3,
        ];
        const RET: u8 = 0xc3;
        const HISTORICAL_CLEAR_BODY: usize = 0;
        const HISTORICAL_GPR_WORD_LOAD_BODY: usize = 25;
        const HISTORICAL_SP_WORD_LOAD_BODY: usize = 97;
        let mut cases = vec![(Operand::Clear, HISTORICAL_CLEAR_BODY)];
        for (base, historical_body) in [
            (Register::X(3), HISTORICAL_GPR_WORD_LOAD_BODY),
            (Register::Sp, HISTORICAL_SP_WORD_LOAD_BODY),
        ] {
            cases.push((
                Operand::Transfer {
                    element_bytes: WORD_BYTES,
                    base,
                    data: Data::Scalar(Register::X(1)),
                    kind: Kind::Load { acquire: false },
                },
                historical_body,
            ));
        }
        let historical =
            std::env::var_os("STELA_EXCLUSIVE_HISTORICAL_BODIES").map(std::path::PathBuf::from);
        for (operand, historical_body) in cases {
            let mut enabled = ENTRY.to_vec();
            let mut disabled = ENTRY.to_vec();
            super::emit_context(
                &mut enabled,
                &CheckedOperand::new(operand, CheckedMemoryProfile::SpAlignmentEnabled).unwrap(),
                SOURCE_PC,
            )
            .unwrap();
            super::emit_context(
                &mut disabled,
                &CheckedOperand::new(operand, CheckedMemoryProfile::SpAlignmentDisabled).unwrap(),
                SOURCE_PC,
            )
            .unwrap();
            enabled.push(RET);
            disabled.push(RET);
            if let Some(path) = &historical {
                assert_eq!(
                    enabled,
                    std::fs::read(path.join(format!("body-{historical_body}.bin"))).unwrap()
                );
            }
            if matches!(
                operand,
                Operand::Transfer {
                    base: Register::Sp,
                    ..
                }
            ) {
                assert!(disabled.len() < enabled.len());
            } else {
                assert_eq!(enabled, disabled);
            }
        }
    }
}

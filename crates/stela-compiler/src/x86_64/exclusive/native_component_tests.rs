//! Private emitted adapter ABI tests with an explicit callback test double.
//! These tests make no MemoryThread, original ARM or checked-entry claim.
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
use std::ffi::c_void;

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
                std::ptr::null_mut(),
                CODE_ALLOCATION_BYTES,
                PROT_READ_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(pointer as usize, usize::MAX);
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer.cast(), bytes.len()) };
        assert_eq!(
            unsafe { mprotect(pointer, CODE_ALLOCATION_BYTES, PROT_READ_EXECUTE) },
            0
        );
        Self { pointer, bytes }
    }
    fn run(&self, state: &mut GuestState, view: &mut MemoryContextView) -> u32 {
        let context = ExecutionContext {
            memory: std::ptr::from_mut(view).cast(),
            ..ExecutionContext::default()
        };
        let entry: unsafe extern "C" fn(*mut GuestState, *const ExecutionContext) -> u32 =
            unsafe { std::mem::transmute(self.pointer) };
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

unsafe extern "C" fn callback(view: *mut MemoryContextView, request: *const MemoryRequest) -> u32 {
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
        opaque: std::ptr::from_mut(observation).cast(),
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
        Kind::Load { acquire: false } | Kind::Store { release: false, .. } => MemoryOrder::Relaxed,
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
    let dump = std::env::var_os("STELA_EXCLUSIVE_COMPONENT_OUTPUT").map(std::path::PathBuf::from);
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
            std::fs::write(path.join(format!("body-{bodies}.bin")), &executable.bytes).unwrap();
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
    println!("exclusive_component_bodies={bodies} executions={executions}");
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
    use std::mem::offset_of;
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

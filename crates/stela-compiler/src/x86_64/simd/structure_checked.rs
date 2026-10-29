//! Fixed-width AdvSIMD structures through exact element memory-service requests.
//! The typed schedule owns access order and partial load commits. Guest addresses
//! are never host pointers; only private State and stack staging are dereferenced.
use crate::x86_64::asm::{Alu, Code, Gpr, Mem, Size};
use crate::x86_64::simd::encode::guest;

use super::{commit, vector_offset};
use crate::{
    TargetCpu,
    aarch64::{
        AddressMode, Operation, Register,
        register_offset::IndexExtend,
        simd::{
            Operand as SimdOperand,
            structure_memory::{Direction, Layout, LoadCommit, Operand, PostIndex},
        },
    },
    block::CheckedMemoryProfile,
    context::memory::{
        MEMORY_REQUEST_BYTES, MemoryRequirements, SpAlignmentRequirement, address::IncrementChoice,
        flags, host_caps, profile_requirements,
    },
    x86_64::{isa::SimdOpcode as Host, memory_context as service, store},
};
use alloc::vec::Vec;

const BYTE_BYTES: u8 = 1;
const HALFWORD_BYTES: u8 = 2;
const DWORD_BYTES: u8 = 4;
const QWORD_BYTES: u8 = 8;
const VECTOR_BYTES: u8 = 16;
const VECTOR_COUNT: u8 = 32;
const GPR_COUNT: u8 = 31;
const MAX_REGISTERS: u8 = 4;
const DATA_OFFSET: u8 = 0;
const BASE_OFFSET: u8 = QWORD_BYTES;
const WRITEBACK_OFFSET: u8 = BASE_OFFSET + QWORD_BYTES;
const REQUEST_OFFSET: u32 = 2 * VECTOR_BYTES as u32;
const SCRATCH_BYTES: u8 = REQUEST_OFFSET as u8 + MEMORY_REQUEST_BYTES as u8;

#[derive(Clone, Copy)]
pub(crate) struct CheckedOperand {
    operand: Operand,
    profile: CheckedMemoryProfile,
}

impl CheckedOperand {
    pub(crate) fn from_operation(
        operation: &Operation,
        profile: CheckedMemoryProfile,
    ) -> Option<Self> {
        let Operation::Simd(SimdOperand::StructureMemory(operand)) = operation else {
            return None;
        };
        let valid_base = matches!(operand.base, Register::X(index) if index < GPR_COUNT)
            || operand.base == Register::Sp;
        let valid_layout = match operand.layout {
            Layout::Multiple {
                repetitions,
                structures,
                vector_bytes,
            } => {
                (1..=MAX_REGISTERS).contains(&repetitions)
                    && (1..=MAX_REGISTERS).contains(&structures)
                    && (repetitions == 1 || structures == 1)
                    && matches!(vector_bytes, QWORD_BYTES | VECTOR_BYTES)
                    && operand.element_bytes <= vector_bytes
                    && !(structures > 1
                        && vector_bytes == QWORD_BYTES
                        && operand.element_bytes == QWORD_BYTES)
            }
            Layout::Lane { structures, index } => {
                (1..=MAX_REGISTERS).contains(&structures)
                    && u16::from(index) * u16::from(operand.element_bytes) < u16::from(VECTOR_BYTES)
            }
            Layout::Replicate {
                structures,
                vector_bytes,
            } => {
                operand.direction == Direction::Load
                    && (1..=MAX_REGISTERS).contains(&structures)
                    && matches!(vector_bytes, QWORD_BYTES | VECTOR_BYTES)
            }
        };
        if !valid_base
            || !valid_layout
            || operand.first_vector >= VECTOR_COUNT
            || !matches!(
                operand.element_bytes,
                BYTE_BYTES | HALFWORD_BYTES | DWORD_BYTES | QWORD_BYTES
            )
            || matches!(operand.post_index, PostIndex::Register(index) if index >= GPR_COUNT)
        {
            return None;
        }
        Some(Self {
            operand: *operand,
            profile,
        })
    }

    fn descriptor(self) -> u32 {
        flags::ASIMD
            | if self.operand.direction == Direction::Store {
                flags::WRITE
            } else {
                0
            }
            | if self.operand.base != Register::Sp || self.operand.post_index != PostIndex::None {
                flags::TAG_CHECKED
            } else {
                0
            }
    }

    pub(crate) fn requirements(self) -> MemoryRequirements {
        let required_flags = self.descriptor();
        MemoryRequirements {
            required_flags,
            required_host_caps: if self.operand.direction == Direction::Load
                && self.operand.element_bytes > BYTE_BYTES
                && (self.operand.base != Register::Sp
                    || self.profile.sp_requirement() != SpAlignmentRequirement::Enabled)
            {
                host_caps::ATOMIC_LOAD16
            } else {
                0
            },
            required_profile: profile_requirements::NATIVE_ACCESS
                | if required_flags & flags::TAG_CHECKED != 0 {
                    profile_requirements::TAG_GRANULES
                } else {
                    0
                },
            required_sp_alignment: if self.operand.base == Register::Sp {
                self.profile.sp_requirement()
            } else {
                SpAlignmentRequirement::Any
            },
            required_address_checks: if self.operand.post_index == PostIndex::None {
                self.profile.direct_address_requirements()
            } else {
                self.profile.address_requirements(false)
            }
            .with_increment_choice(IncrementChoice::Unchecked),
            ..MemoryRequirements::default()
        }
    }

    pub(crate) fn emit_context(self, code: &mut Code, pc: u64, target: TargetCpu) {
        let operand = self.operand;
        code.asm()
            .alu_imm8(Alu::Sub, Size::Qword, Gpr::Rsp, SCRATCH_BYTES as i8);
        service::begin(code);
        let mut failures = Vec::new();
        if self.profile.sp_requirement() == SpAlignmentRequirement::Enabled
            && let Some(failure) = service::address::check_sp(code, operand.base, pc)
        {
            failures.push(failure);
        }
        crate::x86_64::load(code, operand.base);
        save(code, Gpr::Rax, BASE_OFFSET);
        // Save original Rn and Xm-derived writeback before any callback. CPA2
        // result marking has no fault or guest effect and can be computed early.
        match operand.post_index {
            PostIndex::None => {}
            PostIndex::TransferredBytes => {
                service::address::immediate_with_checks(
                    code,
                    operand.base,
                    i32::from(operand.transferred_bytes()),
                    AddressMode::PostIndex,
                    self.profile.address_checks(false),
                );
                save(code, Gpr::Rdx, WRITEBACK_OFFSET);
            }
            PostIndex::Register(index) => {
                service::address::register_offset_with_checks(
                    code,
                    operand.base,
                    Register::X(index),
                    IndexExtend::Lsl,
                    0,
                    self.profile.address_checks(false),
                );
                save(code, Gpr::Rax, WRITEBACK_OFFSET);
            }
        }
        for access in operand.accesses() {
            if operand.direction == Direction::Store {
                let LoadCommit::Lane { index, .. } = access.commit else {
                    unreachable!("validated stores have lane sources")
                };
                scalar(
                    code,
                    false,
                    operand.element_bytes,
                    guest(vector_offset(access.vector) + u32::from(index * operand.element_bytes)),
                );
                // A full private staging store is safe; the request retains the
                // exact element width and does not expose unused staging bytes.
                save(code, Gpr::Rcx, DATA_OFFSET);
            }
            restore(code, BASE_OFFSET);
            if access.byte_offset != 0 {
                code.asm().lea(
                    Size::Qword,
                    Gpr::Rax,
                    Mem::base_disp8(Gpr::Rax, access.byte_offset as i8),
                );
            }
            service::request(
                code,
                REQUEST_OFFSET,
                u32::from(DATA_OFFSET),
                u32::from(operand.element_bytes),
                self.descriptor(),
                pc,
            );
            service::call(code, REQUEST_OFFSET);
            failures.push(service::branch_failed(code));
            if operand.direction == Direction::Load {
                scalar(code, false, operand.element_bytes, slot(DATA_OFFSET));
                match access.commit {
                    LoadCommit::Lane { index, clear_upper } => {
                        scalar(
                            code,
                            true,
                            operand.element_bytes,
                            guest(
                                vector_offset(access.vector)
                                    + u32::from(index * operand.element_bytes),
                            ),
                        );
                        if clear_upper {
                            clear_upper_half(code, access.vector);
                        }
                    }
                    LoadCommit::Replicate { vector_bytes } => {
                        replicate(code, operand.element_bytes, vector_bytes, target);
                        commit(code, access.vector, 0);
                    }
                }
            }
        }
        if operand.post_index != PostIndex::None {
            restore(code, WRITEBACK_OFFSET);
            store(code, operand.base);
        }
        code.asm().alu(Alu::Xor, Size::Dword, Gpr::Rax, Gpr::Rax);
        let cleanup = code.len();
        for failure in failures {
            crate::x86_64::asm::resolve(code, failure, cleanup);
        }
        code.asm()
            .alu_imm8(Alu::Add, Size::Qword, Gpr::Rsp, SCRATCH_BYTES as i8);
        service::address::return_if_failed(code);
    }
}

/// `[rsp + offset]` in the scratch frame, with an 8-bit displacement.
fn slot(offset: u8) -> Mem {
    Mem::base_disp8(Gpr::Rsp, offset as i8)
}

/// Save `register` in the scratch slot at `offset`.
fn save(code: &mut Code, register: Gpr, offset: u8) {
    code.asm().mov_store(Size::Qword, slot(offset), register);
}

/// Reload RAX from the scratch slot at `offset`.
fn restore(code: &mut Code, offset: u8) {
    code.asm().mov_load(Size::Qword, Gpr::Rax, slot(offset));
}

/// Exact-width state/staging reads zero-extend narrow elements into RCX;
/// writes store RCX's low `bytes`.
fn scalar(code: &mut Code, write: bool, bytes: u8, memory: Mem) {
    let size = match bytes {
        BYTE_BYTES => Size::Byte,
        HALFWORD_BYTES => Size::Word,
        DWORD_BYTES => Size::Dword,
        QWORD_BYTES => Size::Qword,
        _ => unreachable!("validated structure element width"),
    };
    let mut asm = code.asm();
    if write {
        asm.mov_store(size, memory, Gpr::Rcx);
    } else if bytes <= HALFWORD_BYTES {
        asm.movzx(Size::Dword, Gpr::Rcx, size, memory);
    } else {
        asm.mov_load(size, Gpr::Rcx, memory);
    }
}

fn clear_upper_half(code: &mut Code, vector: u8) {
    code.asm().mov_rm_imm32(
        Size::Qword,
        guest(vector_offset(vector) + u32::from(QWORD_BYTES)),
        0,
    );
}

/// RCX contains one zero-extended, successfully read element. Rebuild an
/// optional shuffle mask after each callback; no host vector survives it.
fn replicate(code: &mut Code, bytes: u8, vector_bytes: u8, target: TargetCpu) {
    Host::MoveGprQword.register(code, 0, 1, TargetCpu::Baseline); // XMM0 <- RCX
    if bytes == BYTE_BYTES && vector_bytes == VECTOR_BYTES && target.supports(TargetCpu::Ssse3) {
        Host::Xor.register(code, 1, 1, TargetCpu::Baseline);
        Host::ByteShuffle.register(code, 0, 1, target);
        return;
    }
    if bytes == BYTE_BYTES {
        Host::UnpackLowByte.register(code, 0, 0, TargetCpu::Baseline);
    }
    match bytes {
        BYTE_BYTES | HALFWORD_BYTES if vector_bytes == QWORD_BYTES => {
            Host::ShuffleLowWord.register_imm(code, 0, 0, 0, TargetCpu::Baseline); // repeat low word, retaining the zero upper64
        }
        BYTE_BYTES | HALFWORD_BYTES => {
            Host::UnpackLowWord.register(code, 0, 0, TargetCpu::Baseline);
            Host::ShuffleDword.register_imm(code, 0, 0, 0, TargetCpu::Baseline); // repeat low dword
        }
        DWORD_BYTES if vector_bytes == VECTOR_BYTES => {
            Host::ShuffleDword.register_imm(code, 0, 0, 0, TargetCpu::Baseline);
        }
        DWORD_BYTES => Host::UnpackLowDword.register(code, 0, 0, TargetCpu::Baseline),
        QWORD_BYTES if vector_bytes == VECTOR_BYTES => {
            Host::UnpackLowQword.register(code, 0, 0, TargetCpu::Baseline);
        }
        QWORD_BYTES => {}
        _ => unreachable!("validated structure element width"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::simd::structure_memory;
    use crate::context::memory::address::{AccessEl, AddressAddChecks, EffectiveAddressChecks};

    const BASE_SHIFT: u32 = 5;

    /// Enumerate encoding fields, including every lane index, without relying
    /// on the adapter's validation or its emitted access iterator.
    fn words() -> Vec<u32> {
        let mut words = Vec::new();
        for class in [0x0c00_0000, 0x0d00_0000] {
            for q in 0..2 {
                for load in 0..2 {
                    for fields in 0..128 {
                        let word = class
                            | (q << 30)
                            | (load << 22)
                            | if class == 0x0c00_0000 {
                                // Includes reserved opcodes, bit11:10 sizes,
                                // and zero/one in the reserved bit21.
                                ((fields & 15) << 12)
                                    | (((fields >> 4) & 3) << 10)
                                    | (((fields >> 6) & 1) << 21)
                            } else {
                                ((fields & 7) << 13)
                                    | (((fields >> 3) & 1) << 12)
                                    | (((fields >> 4) & 3) << 10)
                                    | (((fields >> 6) & 1) << 21)
                            }
                            | (2 << BASE_SHIFT)
                            | 31;
                        if matches!(structure_memory::decode(word), Some(Ok(_))) {
                            words.push(word);
                        }
                    }
                }
            }
        }
        words
    }

    fn checked(operand: Operand, profile: CheckedMemoryProfile) -> CheckedOperand {
        CheckedOperand::from_operation(
            &Operation::Simd(SimdOperand::StructureMemory(operand)),
            profile,
        )
        .expect("allocated structured operand")
    }

    #[test]
    fn all_shapes_bind_exact_descriptors_quantities_and_address_choices() {
        let words = words();
        assert!(words.contains(&0x4c40_005f)); // LD4 .16B, wrapping V31 list
        for word in words {
            for base in [Register::X(0), Register::X(30), Register::Sp] {
                for post_index in [
                    PostIndex::None,
                    PostIndex::TransferredBytes,
                    PostIndex::Register(30),
                ] {
                    let mut operand = structure_memory::decode(word).unwrap().unwrap();
                    operand.base = base;
                    operand.post_index = post_index;
                    for checks in [AddressAddChecks::Disabled, AddressAddChecks::Enabled] {
                        let effects =
                            EffectiveAddressChecks::new(AddressAddChecks::Disabled, checks);
                        for sp in [
                            CheckedMemoryProfile::SpAlignmentEnabled,
                            CheckedMemoryProfile::SpAlignmentDisabled,
                        ] {
                            let profile =
                                sp.with_address_checks(AccessEl::El1, AccessEl::El0, effects);
                            let required = checked(operand, profile).requirements();
                            let tag = base != Register::Sp || post_index != PostIndex::None;
                            let write = operand.direction == Direction::Store;
                            assert_eq!(
                                required.required_flags,
                                flags::ASIMD
                                    | if write { flags::WRITE } else { 0 }
                                    | if tag { flags::TAG_CHECKED } else { 0 }
                            );
                            assert_eq!(
                                required.required_host_caps,
                                if !write
                                    && operand.element_bytes > 1
                                    && (base != Register::Sp
                                        || sp == CheckedMemoryProfile::SpAlignmentDisabled)
                                {
                                    host_caps::ATOMIC_LOAD16
                                } else {
                                    0
                                }
                            );
                            assert_eq!(
                                required.required_profile,
                                profile_requirements::NATIVE_ACCESS
                                    | if tag {
                                        profile_requirements::TAG_GRANULES
                                    } else {
                                        0
                                    }
                            );
                            assert_eq!(
                                required.required_sp_alignment,
                                if base == Register::Sp {
                                    sp.sp_requirement()
                                } else {
                                    SpAlignmentRequirement::Any
                                }
                            );
                            assert!(
                                required
                                    .required_address_checks
                                    .matches(effects, IncrementChoice::Unchecked)
                            );
                            assert!(
                                !required
                                    .required_address_checks
                                    .matches(effects, IncrementChoice::Checked)
                            );
                            if post_index != PostIndex::None {
                                let opposite = match checks {
                                    AddressAddChecks::Disabled => AddressAddChecks::Enabled,
                                    AddressAddChecks::Enabled => AddressAddChecks::Disabled,
                                };
                                assert!(!required.required_address_checks.matches(
                                    EffectiveAddressChecks::new(checks, opposite),
                                    IncrementChoice::Unchecked
                                ));
                            }
                            assert!(operand.transferred_bytes() <= 64);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn malformed_typed_shapes_and_staged_m0_profile_decline() {
        let valid = structure_memory::decode(0x4c40_0044).unwrap().unwrap();
        let profile = CheckedMemoryProfile::SpAlignmentEnabled;
        for operand in [
            Operand {
                first_vector: 32,
                ..valid
            },
            Operand {
                base: Register::Zero,
                ..valid
            },
            Operand {
                base: Register::X(31),
                ..valid
            },
            Operand {
                element_bytes: 0,
                ..valid
            },
            Operand {
                element_bytes: 3,
                ..valid
            },
            Operand {
                post_index: PostIndex::Register(31),
                ..valid
            },
            Operand {
                layout: Layout::Lane {
                    structures: 4,
                    index: 16,
                },
                ..valid
            },
            Operand {
                layout: Layout::Multiple {
                    repetitions: 4,
                    structures: 4,
                    vector_bytes: 16,
                },
                ..valid
            },
            Operand {
                layout: Layout::Multiple {
                    repetitions: 1,
                    structures: 0,
                    vector_bytes: 16,
                },
                ..valid
            },
            Operand {
                element_bytes: 8,
                layout: Layout::Multiple {
                    repetitions: 1,
                    structures: 4,
                    vector_bytes: 8,
                },
                ..valid
            },
            Operand {
                direction: Direction::Store,
                layout: Layout::Replicate {
                    structures: 4,
                    vector_bytes: 16,
                },
                ..valid
            },
        ] {
            assert!(
                CheckedOperand::from_operation(
                    &Operation::Simd(SimdOperand::StructureMemory(operand)),
                    profile
                )
                .is_none()
            );
        }
    }

    #[cfg(all(target_arch = "x86_64", unix))]
    mod native {
        use super::*;
        use crate::{
            GuestAddress, GuestState,
            context::{
                ExecutionContext,
                memory::{
                    MEMORY_CONTEXT_BYTES, MEMORY_CONTEXT_VERSION, MemoryContextView, MemoryRequest,
                    MemoryStatus,
                },
            },
        };
        use alloc::format;
        use core::ffi::c_void;

        const GUEST_PC: u64 = 0x4000;
        const RAM_BYTES: usize = 128;
        const RET: u32 = 0xd65f_03c0;

        /// Independent source-loop oracle: (vector, lane byte, replicate width).
        /// Do not use Operand::accesses or LoadCommit here.
        fn source_accesses(operand: Operand) -> Vec<(usize, usize, usize)> {
            let mut accesses = Vec::new();
            let first = usize::from(operand.first_vector);
            let width = usize::from(operand.element_bytes);
            match operand.layout {
                Layout::Multiple {
                    repetitions,
                    structures,
                    vector_bytes,
                } => {
                    for repetition in 0..usize::from(repetitions) {
                        for lane in 0..usize::from(vector_bytes) / width {
                            for structure in 0..usize::from(structures) {
                                accesses.push((
                                    (first + repetition + structure) % 32,
                                    lane * width,
                                    0,
                                ));
                            }
                        }
                    }
                }
                Layout::Lane { structures, index } => {
                    for structure in 0..usize::from(structures) {
                        accesses.push(((first + structure) % 32, usize::from(index) * width, 0));
                    }
                }
                Layout::Replicate {
                    structures,
                    vector_bytes,
                } => {
                    for structure in 0..usize::from(structures) {
                        accesses.push(((first + structure) % 32, 0, usize::from(vector_bytes)));
                    }
                }
            }
            accesses
        }

        fn vector_bytes(vector: [u64; 2]) -> [u8; 16] {
            let mut bytes = [0; 16];
            bytes[..8].copy_from_slice(&vector[0].to_le_bytes());
            bytes[8..].copy_from_slice(&vector[1].to_le_bytes());
            bytes
        }

        fn reference(
            operand: Operand,
            original: &GuestState,
            ram: [u8; RAM_BYTES],
            completed: usize,
            success: bool,
            checks: AddressAddChecks,
        ) -> (GuestState, [u8; RAM_BYTES]) {
            let mut state = original.clone();
            let mut memory = ram;
            let width = usize::from(operand.element_bytes);
            for (ordinal, (vector, lane_byte, replicate_bytes)) in
                source_accesses(operand).into_iter().enumerate()
            {
                let start = ordinal * width;
                let mut bytes = vector_bytes(state.v[vector]);
                if operand.direction == Direction::Store {
                    for (byte, value) in bytes[lane_byte..lane_byte + width].iter().enumerate() {
                        if start + byte < completed {
                            memory[start + byte] = *value;
                        }
                    }
                } else if start + width <= completed {
                    if replicate_bytes != 0 {
                        for (byte, value) in bytes[..replicate_bytes].iter_mut().enumerate() {
                            *value = ram[start + byte % width];
                        }
                        bytes[replicate_bytes..].fill(0);
                    } else {
                        bytes[lane_byte..lane_byte + width]
                            .copy_from_slice(&ram[start..start + width]);
                        if matches!(
                            operand.layout,
                            Layout::Multiple {
                                vector_bytes: 8,
                                ..
                            }
                        ) {
                            bytes[8..].fill(0);
                        }
                    }
                    state.v[vector] = [
                        u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                        u64::from_le_bytes(bytes[8..].try_into().unwrap()),
                    ];
                }
            }
            if success && operand.post_index != PostIndex::None {
                let base = match operand.base {
                    Register::Sp => original.sp,
                    Register::X(n) => original.x[usize::from(n)],
                    _ => unreachable!(),
                };
                let increment = match operand.post_index {
                    PostIndex::TransferredBytes => operand.transferred_bytes().into(),
                    PostIndex::Register(n) => original.x[usize::from(n)],
                    PostIndex::None => unreachable!(),
                };
                let value = checks.apply(base.wrapping_add(increment), base);
                match operand.base {
                    Register::Sp => state.sp = value,
                    Register::X(n) => state.x[usize::from(n)] = value,
                    _ => unreachable!(),
                }
            }
            (state, memory)
        }

        struct Harness {
            ram: [u8; RAM_BYTES],
            base: u64,
            fail_after: usize,
            state: *const GuestState,
            requests: Vec<(u64, u32, u32, u64)>,
            observed: Vec<GuestState>,
        }

        /// Exact-width test transport with byte-level faults inside a request.
        /// Failed loads deliberately leave poisoned/partial staging; destinations
        /// must still retain the preceding successful architectural assignments.
        unsafe extern "sysv64" fn callback(
            view: *mut MemoryContextView,
            request: *const MemoryRequest,
        ) -> u32 {
            // SAFETY: run retains disjoint State, view, harness and private stack
            // staging until native return. No reference spans this callback.
            let (view, request) = unsafe { (&mut *view, &*request) };
            // SAFETY: NativeCode::run stores its unique Harness borrow in opaque until return.
            let harness = unsafe { &mut *view.opaque.cast::<Harness>() };
            harness
                .requests
                .push((request.address, request.bytes, request.flags, request.pc));
            // SAFETY: run stores the live state pointer; callbacks occur synchronously between native writes.
            harness.observed.push(unsafe { (&*harness.state).clone() });
            let start = request.address.wrapping_sub(harness.base) as usize;
            // SAFETY: the emitted request names its private staging for exactly request.bytes bytes.
            let data =
                unsafe { core::slice::from_raw_parts_mut(request.data, request.bytes as usize) };
            if request.flags & flags::WRITE == 0 {
                data.fill(0xcc);
            }
            let mut status = MemoryStatus::Success;
            for (byte, value) in data.iter_mut().enumerate() {
                if start + byte == harness.fail_after {
                    status = MemoryStatus::Permission;
                    view.record(
                        status,
                        request.address.wrapping_add(byte as u64),
                        request.pc,
                        view.completed_bytes,
                    );
                    break;
                }
                if request.flags & flags::WRITE != 0 {
                    harness.ram[start + byte] = *value;
                } else {
                    *value = harness.ram[start + byte];
                }
                view.completed_bytes += 1;
            }
            let poison_mxcsr = 0x3f81_u32;
            // SAFETY: all listed registers are caller-saved in this SystemV ABI.
            // The callback wrapper must preserve State/context pointers and MXCSR.
            unsafe {
                core::arch::asm!(
                    "pxor xmm0, xmm0", "pxor xmm1, xmm1", "pxor xmm2, xmm2", "pxor xmm3, xmm3",
                    "pxor xmm4, xmm4", "pxor xmm5, xmm5", "pxor xmm6, xmm6", "pxor xmm7, xmm7",
                    "pxor xmm8, xmm8", "pxor xmm9, xmm9", "pxor xmm10, xmm10", "pxor xmm11, xmm11",
                    "pxor xmm12, xmm12", "pxor xmm13, xmm13", "pxor xmm14, xmm14", "pxor xmm15, xmm15",
                    "ldmxcsr [{control}]", control = in(reg) &poison_mxcsr,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                    out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                    out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
                    out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
                    options(nostack)
                );
                core::arch::asm!(
                    "mov rax, -1", "mov rcx, -1", "mov rdx, -1", "mov rsi, -1",
                    "mov r8, -1", "mov r9, -1", "mov r10, -1", "mov r11, -1",
                    out("rax") _, out("rcx") _, out("rdx") _, out("rsi") _,
                    out("r8") _, out("r9") _, out("r10") _, out("r11") _, options(nostack)
                );
            }
            status as u32
        }

        unsafe extern "C" {
            fn mmap(
                address: *mut c_void,
                bytes: usize,
                protection: i32,
                flags: i32,
                fd: i32,
                offset: i64,
            ) -> *mut c_void;
            fn munmap(address: *mut c_void, bytes: usize) -> i32;
        }

        struct NativeCode(*mut c_void, usize);

        impl NativeCode {
            fn new(code: &[u8]) -> Self {
                const PROT_READ_WRITE_EXECUTE: i32 = 7;
                const MAP_PRIVATE: i32 = 2;
                #[cfg(target_os = "macos")]
                const MAP_ANONYMOUS: i32 = 0x1000;
                #[cfg(not(target_os = "macos"))]
                const MAP_ANONYMOUS: i32 = 0x20;
                if let Ok(directory) = std::env::var("STELA_STRUCTURE_CHECKED_OUTPUT") {
                    use core::sync::atomic::{AtomicUsize, Ordering};
                    static NEXT: AtomicUsize = AtomicUsize::new(0);
                    std::fs::create_dir_all(&directory).unwrap();
                    std::fs::write(
                        std::path::Path::new(&directory)
                            .join(format!("body-{}.bin", NEXT.fetch_add(1, Ordering::Relaxed))),
                        code,
                    )
                    .unwrap();
                }
                // SAFETY: mapping is private, copied once, invoked while owned,
                // and unmapped only when no native call is active.
                let pointer = unsafe {
                    mmap(
                        core::ptr::null_mut(),
                        code.len(),
                        PROT_READ_WRITE_EXECUTE,
                        MAP_PRIVATE | MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                assert_ne!(pointer as usize, usize::MAX);
                // SAFETY: the live mapping covers code.len() bytes and is disjoint from the source Vec.
                unsafe {
                    core::ptr::copy_nonoverlapping(code.as_ptr(), pointer.cast(), code.len());
                }
                Self(pointer, code.len())
            }

            fn body(operand: Operand, profile: CheckedMemoryProfile) -> Self {
                Self::body_for_target(operand, profile, TargetCpu::Baseline)
            }

            fn body_for_target(
                operand: Operand,
                profile: CheckedMemoryProfile,
                target: TargetCpu,
            ) -> Self {
                let mut code = crate::scalable_context::context_wrapper();
                checked(operand, profile).emit_context(&mut code, GUEST_PC, target);
                code.asm().ret();
                Self::new(&code)
            }

            fn run(
                &self,
                state: &mut GuestState,
                harness: &mut Harness,
            ) -> (u32, MemoryContextView) {
                harness.state = state;
                let mut view = MemoryContextView {
                    version: MEMORY_CONTEXT_VERSION,
                    bytes: MEMORY_CONTEXT_BYTES,
                    callback,
                    opaque: (harness as *mut Harness).cast(),
                    fault_kind: u32::MAX,
                    fault_access: 2,
                    fault_address: 0,
                    fault_pc: 0,
                    completed_bytes: u64::MAX,
                    reserved_tail: 0,
                };
                let mut context = ExecutionContext {
                    memory: (&mut view as *mut MemoryContextView).cast(),
                    ..ExecutionContext::default()
                };
                // SAFETY: the exact generated wrapper implements this borrowed ABI.
                let entry: unsafe extern "sysv64" fn(
                    *mut GuestState,
                    *mut ExecutionContext,
                ) -> u32 = unsafe { core::mem::transmute(self.0) };
                let before = mxcsr();
                // SAFETY: state, context, view and Harness outlive this call through the generated ABI.
                let status = unsafe { entry(state, &mut context) };
                assert_eq!(
                    mxcsr(),
                    before,
                    "full host MXCSR must survive every callback"
                );
                (status, view)
            }
        }

        impl Drop for NativeCode {
            fn drop(&mut self) {
                // SAFETY: this object exclusively owns the inactive native mapping.
                assert_eq!(unsafe { munmap(self.0, self.1) }, 0);
            }
        }

        fn mxcsr() -> u32 {
            let mut value = 0_u32;
            // SAFETY: STMXCSR writes the independently live four-byte destination.
            unsafe {
                core::arch::asm!("stmxcsr [{p}]", p = in(reg) &mut value, options(nostack));
            }
            value
        }

        fn state(operand: Operand, base: u64) -> GuestState {
            let mut state = GuestState {
                sp: base,
                nzcv: 0xa000_0000,
                fpcr: 0x0040_0000,
                fpsr: 0x0800_009f,
                reserved: 0x1357_9bdf,
                ..GuestState::default()
            };
            for (index, register) in state.x.iter_mut().enumerate() {
                *register = (index as u64 + 1).wrapping_mul(0x0101_0101_0101_0101);
            }
            if let Register::X(index) = operand.base {
                state.x[usize::from(index)] = base;
            }
            for (index, vector) in state.v.iter_mut().enumerate() {
                *vector = [
                    0x0123_4567_89ab_cdef ^ (index as u64 * 0x0101_0101_0101_0101),
                    0xfedc_ba98_7654_3210 ^ (index as u64 * 0x0101_0101_0101_0101),
                ];
            }
            state
        }

        fn harness(base: u64, fail_after: usize) -> Harness {
            Harness {
                ram: core::array::from_fn(|index| (index as u8).wrapping_mul(37).wrapping_add(13)),
                base,
                fail_after,
                state: core::ptr::null(),
                requests: Vec::new(),
                observed: Vec::new(),
            }
        }

        fn check_prefix(
            code: &NativeCode,
            operand: Operand,
            original: &GuestState,
            base: u64,
            stop: usize,
            checks: AddressAddChecks,
        ) {
            let mut actual = original.clone();
            let mut harness = harness(base, stop);
            let initial_ram = harness.ram;
            let (status, view) = code.run(&mut actual, &mut harness);
            let success = stop == usize::from(operand.transferred_bytes());
            assert_eq!(
                status,
                if success {
                    MemoryStatus::Success
                } else {
                    MemoryStatus::Permission
                } as u32
            );
            let (expected, expected_ram) =
                reference(operand, original, initial_ram, stop, success, checks);
            assert_eq!(actual, expected, "operand={operand:?}, prefix={stop}");
            assert_eq!(
                harness.ram, expected_ram,
                "operand={operand:?}, prefix={stop}"
            );
            assert_eq!(view.completed_bytes, stop as u64);
            assert_eq!(view.fault_kind, status);
            assert_eq!(view.fault_access, 0);
            if !success {
                assert_eq!(view.fault_address, base.wrapping_add(stop as u64));
                assert_eq!(view.fault_pc, GUEST_PC);
            }
            let width = usize::from(operand.element_bytes);
            let requests = if success {
                stop / width
            } else {
                stop / width + 1
            };
            assert_eq!(harness.requests.len(), requests);
            let descriptor = flags::ASIMD
                | if operand.direction == Direction::Store {
                    flags::WRITE
                } else {
                    0
                }
                | if operand.base != Register::Sp || operand.post_index != PostIndex::None {
                    flags::TAG_CHECKED
                } else {
                    0
                };
            for (ordinal, request) in harness.requests.iter().enumerate() {
                assert_eq!(
                    *request,
                    (
                        base.wrapping_add((ordinal * width) as u64),
                        width as u32,
                        descriptor,
                        GUEST_PC
                    )
                );
                // A prior element must already be committed when the next
                // service observes State, including Q0 upper-half clearing.
                let (expected, _) = reference(
                    operand,
                    original,
                    initial_ram,
                    ordinal * width,
                    false,
                    checks,
                );
                assert_eq!(harness.observed[ordinal], expected);
            }
        }

        #[test]
        fn every_allocated_variant_executes_all_byte_fault_prefixes_and_original_post_inputs() {
            for word in words() {
                for post_index in [
                    PostIndex::None,
                    PostIndex::TransferredBytes,
                    PostIndex::Register(2),
                ] {
                    let mut operand = structure_memory::decode(word).unwrap().unwrap();
                    operand.post_index = post_index;
                    let code = NativeCode::body(operand, CheckedMemoryProfile::SpAlignmentDisabled);
                    // Unaligned and crossing 4KiB: no packed-footprint shortcut.
                    let base = 0x1ffd;
                    let original = state(operand, base);
                    for stop in 0..=usize::from(operand.transferred_bytes()) {
                        check_prefix(
                            &code,
                            operand,
                            &original,
                            base,
                            stop,
                            AddressAddChecks::Disabled,
                        );
                    }
                }
            }
        }

        #[test]
        fn sp_policies_tag_intent_and_original_alignment_fault_precede_callbacks() {
            for word in words() {
                for post_index in [
                    PostIndex::None,
                    PostIndex::TransferredBytes,
                    PostIndex::Register(30),
                ] {
                    let mut operand = structure_memory::decode(word).unwrap().unwrap();
                    operand.base = Register::Sp;
                    operand.post_index = post_index;
                    for profile in [
                        CheckedMemoryProfile::SpAlignmentEnabled,
                        CheckedMemoryProfile::SpAlignmentDisabled,
                    ] {
                        let code = NativeCode::body(operand, profile);
                        for base in [0x2000, 0x2003] {
                            let original = state(operand, base);
                            if profile == CheckedMemoryProfile::SpAlignmentEnabled && base & 15 != 0
                            {
                                let mut actual = original.clone();
                                let mut harness = harness(base, usize::MAX);
                                let (status, view) = code.run(&mut actual, &mut harness);
                                assert_eq!(status, MemoryStatus::StackAlignment as u32);
                                assert_eq!(actual, original);
                                assert!(harness.requests.is_empty());
                                assert_eq!(view.completed_bytes, 0);
                                assert_eq!(view.fault_address, base);
                                assert_eq!(view.fault_pc, GUEST_PC);
                            } else {
                                let total = usize::from(operand.transferred_bytes());
                                for stop in [0, total / 2, total] {
                                    check_prefix(
                                        &code,
                                        operand,
                                        &original,
                                        base,
                                        stop,
                                        AddressAddChecks::Disabled,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        #[test]
        fn element_increment_wraps_unchecked_and_only_post_index_uses_cpa2_address_add() {
            for word in [
                0x4c40_0044,
                0x4c40_0444,
                0x4c40_0844,
                0x4c40_0c44,
                0x4c00_0044,
                0x4d60_e05f,
                0x4d60_205f,
            ] {
                for post_index in [
                    PostIndex::None,
                    PostIndex::TransferredBytes,
                    PostIndex::Register(2),
                    PostIndex::Register(30),
                ] {
                    for base in [u64::MAX - 7, 0x00ff_ffff_ffff_fff8, 0x0080_0000_0000_0000] {
                        let mut operand = structure_memory::decode(word).unwrap().unwrap();
                        operand.post_index = post_index;
                        let checks = AddressAddChecks::Enabled;
                        let profile = CheckedMemoryProfile::SpAlignmentDisabled
                            .with_address_checks(
                                AccessEl::El1,
                                AccessEl::El0,
                                EffectiveAddressChecks::new(AddressAddChecks::Disabled, checks),
                            );
                        let code = NativeCode::body(operand, profile);
                        let mut original = state(operand, base);
                        if post_index == PostIndex::Register(30) {
                            original.x[30] = 0x0100_0000_0000_0010;
                        }
                        for stop in [
                            0,
                            usize::from(operand.element_bytes),
                            usize::from(operand.transferred_bytes()),
                        ] {
                            check_prefix(&code, operand, &original, base, stop, checks);
                        }
                    }
                }
            }
        }

        #[test]
        fn checked_ssse3_replication_matches_baseline_for_every_byte_and_fault_prefix() {
            if !std::is_x86_feature_detected!("ssse3") {
                return;
            }
            for word in [0x4d40_c05f, 0x4d60_c05f, 0x4d40_e05f, 0x4d60_e05f] {
                let operand = structure_memory::decode(word).unwrap().unwrap();
                let profile = CheckedMemoryProfile::SpAlignmentDisabled;
                for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
                    let code = NativeCode::body_for_target(operand, profile, target);
                    for value in 0..=u8::MAX {
                        for stop in 0..=usize::from(operand.transferred_bytes()) {
                            let original = state(operand, 0x2001);
                            let mut actual = original.clone();
                            let mut harness = harness(0x2001, stop);
                            harness.ram.fill(value);
                            let success = stop == usize::from(operand.transferred_bytes());
                            let expected = reference(
                                operand,
                                &original,
                                harness.ram,
                                stop,
                                success,
                                AddressAddChecks::Disabled,
                            );
                            let (status, view) = code.run(&mut actual, &mut harness);
                            assert_eq!((actual, harness.ram), expected);
                            assert_eq!(view.completed_bytes, stop as u64);
                            assert_eq!(
                                status,
                                if success {
                                    MemoryStatus::Success as u32
                                } else {
                                    MemoryStatus::Permission as u32
                                }
                            );
                        }
                    }
                }
            }
        }

        #[test]
        fn original_ld4_word_uses_checked_block_routing_and_real_source_intervals() {
            use crate::block::{BlockProfile, CompilationPlan, Features};
            let source: Vec<_> = [0x4c40_0044, RET]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            for profile in [
                BlockProfile::ORDINARY
                    .with_checked_memory(CheckedMemoryProfile::SpAlignmentDisabled),
                BlockProfile::new(Features::SYSTEM_MODE)
                    .with_checked_memory(CheckedMemoryProfile::SpAlignmentDisabled),
            ] {
                let plan = CompilationPlan::new(
                    &source,
                    GuestAddress(GUEST_PC),
                    &crate::Options::new(profile, TargetCpu::X86_64_V2),
                )
                .unwrap();
                let required = plan.memory_requirements().unwrap();
                assert_eq!(required.required_flags, flags::ASIMD | flags::TAG_CHECKED);
                assert_eq!(required.required_host_caps, 0); // LD4 .16B has byte Mem accesses
                let compiled = plan.compile().unwrap();
                assert_eq!(compiled.source_bytes, source.len());
                assert_eq!(compiled.native.source_map.len(), 2);
                assert_eq!(compiled.native.source_map[0].0, GuestAddress(GUEST_PC));
                assert_eq!(compiled.native.source_map[1].0, GuestAddress(GUEST_PC + 4));
                let operand = structure_memory::decode(0x4c40_0044).unwrap().unwrap();
                let code = NativeCode::new(&compiled.native.x86_64_code);
                let original = state(operand, 0x1ffd);
                check_prefix(
                    &code,
                    operand,
                    &original,
                    0x1ffd,
                    31,
                    AddressAddChecks::Disabled,
                );
                let mut actual = original.clone();
                let mut harness = harness(0x1ffd, usize::MAX);
                let expected = reference(
                    operand,
                    &original,
                    harness.ram,
                    64,
                    true,
                    AddressAddChecks::Disabled,
                );
                // Success reaches the real RET terminator, returning a block
                // exit rather than a MemoryStatus. The retained view is decisive.
                let (_, view) = code.run(&mut actual, &mut harness);
                assert_eq!((actual, harness.ram), expected);
                assert_eq!(view.fault_kind, MemoryStatus::Success as u32);
                assert_eq!(view.completed_bytes, 64);
                assert_eq!(harness.requests.len(), 64);
            }
        }
    }
}

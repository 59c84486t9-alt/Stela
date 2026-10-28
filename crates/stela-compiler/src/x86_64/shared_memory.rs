//! Typed checked LSE, acquire/release and DMB requests. No guest RAM pointer
//! is embedded in native code; the shared writer/monitor owner performs effects.
use super::{load, memory_context as memory, store};
use crate::x86_64::asm::Code;
use crate::{
    CompileError,
    aarch64::{AddressMode, Operation, Register, Width, atomic, ordered},
    block::CheckedMemoryProfile,
    context::memory::{
        InstructionRequirements, MEMORY_REQUEST_BYTES, MemoryOrder, MemoryRequirements,
        SpAlignmentRequirement, atomic as wire_atomic, flags, host_caps, ordered as wire_ordered,
        profile_requirements,
    },
};

const DATA_OFFSET: u32 = MEMORY_REQUEST_BYTES as u32;
const STACK_ALIGNMENT: u32 = 16;
const SUB_RSP: &[u8] = &[0x48, 0x83, 0xec];
const ADD_RSP: &[u8] = &[0x48, 0x83, 0xc4];
const ZERO_EAX: &[u8] = &[0x31, 0xc0];
const ZERO_XMM0: &[u8] = &[0x66, 0x0f, 0xef, 0xc0];
const STORE_VECTOR: &[u8] = &[0xf3, 0x0f, 0x7f, 0x44, 0x24];
const STORE_FIELD: &[u8] = &[0xc7, 0x44, 0x24];

const STORE_BYTE: &[u8] = &[0x88, 0x44, 0x24];
const STORE_HALF: &[u8] = &[0x66, 0x89, 0x44, 0x24];
const STORE_WORD: &[u8] = &[0x89, 0x44, 0x24];
const STORE_DOUBLE: &[u8] = &[0x48, 0x89, 0x44, 0x24];
const LOAD_BYTE: &[u8] = &[0x0f, 0xb6, 0x44, 0x24];
const LOAD_HALF: &[u8] = &[0x0f, 0xb7, 0x44, 0x24];
const LOAD_WORD: &[u8] = &[0x8b, 0x44, 0x24];
const LOAD_DOUBLE: &[u8] = &[0x48, 0x8b, 0x44, 0x24];
const SIGN_BYTE_TO_X: &[u8] = &[0x48, 0x0f, 0xbe, 0x44, 0x24];
const SIGN_HALF_TO_X: &[u8] = &[0x48, 0x0f, 0xbf, 0x44, 0x24];
const SIGN_WORD_TO_X: &[u8] = &[0x48, 0x63, 0x44, 0x24];
const SIGN_BYTE_TO_W: &[u8] = &[0x0f, 0xbe, 0x44, 0x24];
const SIGN_HALF_TO_W: &[u8] = &[0x0f, 0xbf, 0x44, 0x24];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operand {
    Atomic(atomic::Operand),
    Ordered(ordered::Operand),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CheckedOperand {
    operand: Operand,
    profile: CheckedMemoryProfile,
}

fn data_register(register: Register) -> bool {
    matches!(register, Register::X(index) if index < 31) || register == Register::Zero
}
fn base_register(register: Register) -> bool {
    matches!(register, Register::X(index) if index < 31) || register == Register::Sp
}
fn valid_pair(pair: [Register; 2]) -> bool {
    matches!(pair, [Register::X(first), second] if first < 31 && first % 2 == 0
        && second == if first == 30 { Register::Zero } else { Register::X(first + 1) })
}
impl CheckedOperand {
    pub(crate) fn from_operation(
        operation: &Operation,
        profile: CheckedMemoryProfile,
    ) -> Result<Option<Self>, CompileError> {
        let operand = match *operation {
            Operation::Atomic(operand) => {
                let valid = base_register(operand.base)
                    && match operand.kind {
                        atomic::Kind::CompareExchange { compare, source } => {
                            matches!(operand.bytes, 1 | 2 | 4 | 8)
                                && data_register(compare)
                                && data_register(source)
                        }
                        atomic::Kind::CompareExchangePair { compare, source } => {
                            matches!(operand.bytes, 8 | 16)
                                && valid_pair(compare)
                                && valid_pair(source)
                        }
                        atomic::Kind::ReadModifyWrite {
                            source,
                            destination,
                            ..
                        } => {
                            matches!(operand.bytes, 1 | 2 | 4 | 8)
                                && data_register(source)
                                && data_register(destination)
                        }
                    };
                if !valid {
                    return Err(CompileError("invalid checked LSE operand".into()));
                }
                Operand::Atomic(operand)
            }
            Operation::Ordered(operand) => {
                match operand {
                    ordered::Operand::Barrier {
                        option,
                        requirement,
                    } => {
                        let expected = match option & 3 {
                            1 => ordered::Barrier::Reads,
                            2 => ordered::Barrier::Writes,
                            _ => ordered::Barrier::All,
                        };
                        if option > 15 || requirement != expected {
                            return Err(CompileError("invalid checked DMB operand".into()));
                        }
                    }
                    ordered::Operand::Transfer {
                        feature,
                        kind,
                        bytes,
                        data,
                        base,
                        displacement,
                        extension,
                    } => {
                        let source_form = match feature {
                            ordered::Feature::Base | ordered::Feature::Lor => {
                                displacement == 0
                                    && matches!(
                                        kind,
                                        ordered::Kind::Acquire | ordered::Kind::Release
                                    )
                                    && extension == ordered::LoadExtension::Zero
                            }
                            ordered::Feature::Rcpc => {
                                displacement == 0
                                    && kind == ordered::Kind::AcquirePc
                                    && extension == ordered::LoadExtension::Zero
                            }
                            ordered::Feature::Rcpc2 => {
                                (-256..=255).contains(&displacement)
                                    && matches!(
                                        kind,
                                        ordered::Kind::AcquirePc | ordered::Kind::Release
                                    )
                                    && match extension {
                                        ordered::LoadExtension::Zero => true,
                                        ordered::LoadExtension::Sign(Width::W32) => {
                                            kind != ordered::Kind::Release && bytes < 4
                                        }
                                        ordered::LoadExtension::Sign(Width::X64) => {
                                            kind != ordered::Kind::Release && bytes < 8
                                        }
                                    }
                            }
                        };
                        if !source_form
                            || !matches!(bytes, 1 | 2 | 4 | 8)
                            || !data_register(data)
                            || !base_register(base)
                        {
                            return Err(CompileError("invalid checked ordered operand".into()));
                        }
                    }
                }
                Operand::Ordered(operand)
            }
            _ => return Ok(None),
        };
        if !matches!(
            profile,
            CheckedMemoryProfile::SpAlignmentEnabled | CheckedMemoryProfile::SpAlignmentDisabled
        ) {
            return Err(CompileError(
                "checked shared operations require the fixed address contract".into(),
            ));
        }
        Ok(Some(Self { operand, profile }))
    }

    fn base(&self) -> Option<Register> {
        match self.operand {
            Operand::Atomic(operand) => Some(operand.base),
            Operand::Ordered(ordered::Operand::Transfer { base, .. }) => Some(base),
            Operand::Ordered(ordered::Operand::Barrier { .. }) => None,
        }
    }
    fn bytes(&self) -> u32 {
        match self.operand {
            Operand::Atomic(operand) => u32::from(operand.bytes),
            Operand::Ordered(ordered::Operand::Transfer { bytes, .. }) => u32::from(bytes),
            Operand::Ordered(ordered::Operand::Barrier { .. }) => 0,
        }
    }
    fn descriptor(&self) -> u32 {
        let class = match self.operand {
            Operand::Atomic(_) => flags::ATOMIC | flags::WRITE,
            Operand::Ordered(ordered::Operand::Transfer {
                kind: ordered::Kind::Release,
                ..
            }) => flags::ORDERED | flags::WRITE,
            Operand::Ordered(_) => flags::ORDERED,
        };
        class
            | if self.base().is_some_and(|base| base != Register::Sp) {
                flags::TAG_CHECKED
            } else {
                0
            }
    }
    pub(crate) fn requirements(&self) -> MemoryRequirements {
        let required_instructions = match self.operand {
            Operand::Atomic(_) => InstructionRequirements::LSE,
            Operand::Ordered(ordered::Operand::Transfer { feature, .. }) => {
                wire_feature(feature).requirements()
            }
            Operand::Ordered(_) => InstructionRequirements::NONE,
        };
        let required_host_caps = match self.operand {
            Operand::Atomic(atomic::Operand { bytes: 16, .. }) => host_caps::CX16,
            Operand::Ordered(ordered::Operand::Transfer {
                kind: ordered::Kind::Acquire | ordered::Kind::AcquirePc,
                bytes,
                base,
                displacement,
                ..
            }) if bytes > 1
                && (base != Register::Sp
                    || self.profile.sp_requirement() != SpAlignmentRequirement::Enabled
                    || displacement.rem_euclid(8) > 8 - i32::from(bytes)) =>
            {
                host_caps::ATOMIC_LOAD16
            }
            _ => 0,
        };
        MemoryRequirements {
            required_flags: self.descriptor(),
            required_host_caps,
            required_instructions,
            required_address_checks: self.profile.direct_address_requirements(),
            required_sp_alignment: if self.base() == Some(Register::Sp) {
                self.profile.sp_requirement()
            } else {
                SpAlignmentRequirement::Any
            },
            required_profile: if self.base().is_some() {
                profile_requirements::NATIVE_ACCESS
                    | if self.base() != Some(Register::Sp) {
                        profile_requirements::TAG_GRANULES
                    } else {
                        0
                    }
            } else {
                0
            },
            ..MemoryRequirements::default()
        }
    }
    pub(crate) fn emit(&self, code: &mut Code, pc: u64) {
        let data_bytes = match self.operand {
            Operand::Atomic(_) => wire_atomic::DATA_BYTES,
            Operand::Ordered(_) => wire_ordered::DATA_BYTES,
        } as u32;
        let scratch = (DATA_OFFSET + data_bytes).div_ceil(STACK_ALIGNMENT) * STACK_ALIGNMENT;
        assert!(scratch <= i8::MAX as u32);
        code.extend(SUB_RSP);
        code.push(scratch as u8);
        memory::begin(code);
        let sp_failure = if self.profile.sp_requirement() == SpAlignmentRequirement::Enabled {
            self.base()
                .and_then(|base| memory::address::check_sp(code, base, pc))
        } else {
            None
        };
        if let Some(base) = self.base() {
            let displacement = match self.operand {
                Operand::Ordered(ordered::Operand::Transfer { displacement, .. }) => displacement,
                _ => 0,
            };
            memory::address::immediate(code, base, displacement, AddressMode::Offset);
        } else {
            code.extend(ZERO_EAX);
        }
        memory::request(code, 0, DATA_OFFSET, self.bytes(), self.descriptor(), pc);
        code.extend(ZERO_XMM0);
        for offset in (0..data_bytes).step_by(STACK_ALIGNMENT as usize) {
            code.extend(STORE_VECTOR);
            code.push((DATA_OFFSET + offset) as u8);
        }
        match self.operand {
            Operand::Atomic(operand) => stage_atomic(code, operand),
            Operand::Ordered(operand) => stage_ordered(code, operand),
        }
        memory::call(code, 0);
        let failure = memory::branch_failed(code);
        match self.operand {
            Operand::Atomic(operand) => commit_atomic(code, operand),
            Operand::Ordered(ordered::Operand::Transfer {
                kind: ordered::Kind::Acquire | ordered::Kind::AcquirePc,
                data,
                bytes,
                extension,
                ..
            }) => {
                commit(code, data, bytes, wire_ordered::VALUE_OFFSET, extension);
            }
            Operand::Ordered(_) => {}
        }
        code.extend(ZERO_EAX);
        let cleanup = code.len();
        memory::patch_branch(code, failure, cleanup);
        if let Some(failure) = sp_failure {
            memory::patch_branch(code, failure, cleanup);
        }
        code.extend(ADD_RSP);
        code.push(scratch as u8);
        memory::address::return_if_failed(code);
    }
}
fn field(code: &mut Code, offset: u32, value: u32) {
    if value != 0 {
        code.extend(STORE_FIELD);
        code.push((DATA_OFFSET + offset) as u8);
        code.extend(value.to_le_bytes());
    }
}
fn stage(code: &mut Code, register: Register, bytes: u8, offset: u32) {
    if register == Register::Zero {
        return;
    }
    load(code, register);
    code.extend(match bytes {
        1 => STORE_BYTE,
        2 => STORE_HALF,
        4 => STORE_WORD,
        8 => STORE_DOUBLE,
        _ => unreachable!("validated width"),
    });
    code.push((DATA_OFFSET + offset) as u8);
}
fn commit(
    code: &mut Code,
    register: Register,
    bytes: u8,
    offset: u32,
    extension: ordered::LoadExtension,
) {
    if register == Register::Zero {
        return;
    }
    let prefix: &[u8] = match (bytes, extension) {
        (1, ordered::LoadExtension::Sign(Width::X64)) => SIGN_BYTE_TO_X,
        (2, ordered::LoadExtension::Sign(Width::X64)) => SIGN_HALF_TO_X,
        (4, ordered::LoadExtension::Sign(Width::X64)) => SIGN_WORD_TO_X,
        (1, ordered::LoadExtension::Sign(Width::W32)) => SIGN_BYTE_TO_W,
        (2, ordered::LoadExtension::Sign(Width::W32)) => SIGN_HALF_TO_W,
        (1, _) => LOAD_BYTE,
        (2, _) => LOAD_HALF,
        (4, _) => LOAD_WORD,
        (8, _) => LOAD_DOUBLE,
        _ => unreachable!("validated result width"),
    };
    code.extend(prefix);
    code.push((DATA_OFFSET + offset) as u8);
    store(code, register);
}
fn atomic_operation(kind: atomic::Kind) -> wire_atomic::AtomicOperation {
    use atomic::{Kind, Rmw};
    use wire_atomic::AtomicOperation as W;
    match kind {
        Kind::CompareExchange { .. } => W::CompareExchange,
        Kind::CompareExchangePair { .. } => W::CompareExchangePair,
        Kind::ReadModifyWrite { operation, .. } => match operation {
            Rmw::Add => W::Add,
            Rmw::Clear => W::Clear,
            Rmw::Xor => W::Xor,
            Rmw::Set => W::Set,
            Rmw::SignedMax => W::SignedMax,
            Rmw::SignedMin => W::SignedMin,
            Rmw::UnsignedMax => W::UnsignedMax,
            Rmw::UnsignedMin => W::UnsignedMin,
            Rmw::Swap => W::Swap,
        },
    }
}
fn stage_atomic(code: &mut Code, operand: atomic::Operand) {
    use atomic::{Kind, Order};
    let acquire = match operand.kind {
        Kind::CompareExchange { compare, .. } => operand.order.acquires(compare),
        Kind::ReadModifyWrite { destination, .. } => operand.order.acquires(destination),
        Kind::CompareExchangePair { .. } => {
            matches!(operand.order, Order::Acquire | Order::AcquireRelease)
        }
    };
    let release = matches!(operand.order, Order::Release | Order::AcquireRelease);
    let order = match (acquire, release) {
        (false, false) => MemoryOrder::Relaxed,
        (true, false) => MemoryOrder::AcquireRcsc,
        (false, true) => MemoryOrder::Release,
        (true, true) => MemoryOrder::AcquireRelease,
    };
    field(
        code,
        wire_atomic::OPERATION_OFFSET,
        atomic_operation(operand.kind) as u32,
    );
    field(code, wire_atomic::ORDER_OFFSET, order as u32);
    match operand.kind {
        Kind::CompareExchange { compare, source } => {
            stage(code, compare, operand.bytes, wire_atomic::COMPARE_OFFSET);
            stage(code, source, operand.bytes, wire_atomic::OPERAND_OFFSET);
        }
        Kind::CompareExchangePair { compare, source } => {
            for index in 0..2 {
                let bytes = operand.bytes / 2;
                stage(
                    code,
                    compare[index],
                    bytes,
                    wire_atomic::COMPARE_OFFSET + index as u32 * u32::from(bytes),
                );
                stage(
                    code,
                    source[index],
                    bytes,
                    wire_atomic::OPERAND_OFFSET + index as u32 * u32::from(bytes),
                );
            }
        }
        Kind::ReadModifyWrite { source, .. } => {
            stage(code, source, operand.bytes, wire_atomic::OPERAND_OFFSET)
        }
    }
}
fn commit_atomic(code: &mut Code, operand: atomic::Operand) {
    use atomic::Kind;
    let extension = ordered::LoadExtension::Zero;
    match operand.kind {
        Kind::CompareExchange { compare, .. } => commit(
            code,
            compare,
            operand.bytes,
            wire_atomic::RESULT_OFFSET,
            extension,
        ),
        Kind::ReadModifyWrite { destination, .. } => commit(
            code,
            destination,
            operand.bytes,
            wire_atomic::RESULT_OFFSET,
            extension,
        ),
        Kind::CompareExchangePair { compare, .. } => {
            for (index, register) in compare.into_iter().enumerate() {
                let bytes = operand.bytes / 2;
                commit(
                    code,
                    register,
                    bytes,
                    wire_atomic::RESULT_OFFSET + index as u32 * u32::from(bytes),
                    extension,
                );
            }
        }
    }
}
fn wire_feature(feature: ordered::Feature) -> wire_ordered::OrderedFeature {
    match feature {
        ordered::Feature::Base => wire_ordered::OrderedFeature::Base,
        ordered::Feature::Rcpc => wire_ordered::OrderedFeature::Rcpc,
        ordered::Feature::Rcpc2 => wire_ordered::OrderedFeature::Rcpc2,
        ordered::Feature::Lor => wire_ordered::OrderedFeature::Lor,
    }
}
fn stage_ordered(code: &mut Code, operand: ordered::Operand) {
    use wire_ordered::{
        BARRIER_OFFSET, FEATURE_OFFSET, OPERATION_OFFSET, ORDER_OFFSET, OrderedOperation,
        VALUE_OFFSET,
    };
    match operand {
        ordered::Operand::Barrier { option, .. } => {
            field(code, OPERATION_OFFSET, OrderedOperation::Barrier as u32);
            field(code, BARRIER_OFFSET, u32::from(option));
        }
        ordered::Operand::Transfer {
            feature,
            kind,
            data,
            bytes,
            ..
        } => {
            field(code, FEATURE_OFFSET, wire_feature(feature) as u32);
            field(
                code,
                ORDER_OFFSET,
                match kind {
                    ordered::Kind::Acquire => MemoryOrder::AcquireRcsc,
                    ordered::Kind::AcquirePc => MemoryOrder::AcquireRcpc,
                    ordered::Kind::Release => MemoryOrder::Release,
                } as u32,
            );
            if kind == ordered::Kind::Release {
                field(code, OPERATION_OFFSET, OrderedOperation::Store as u32);
                stage(code, data, bytes, VALUE_OFFSET);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PROFILE: CheckedMemoryProfile = CheckedMemoryProfile::SpAlignmentEnabled;
    #[test]
    fn checked_requirements_keep_publication_and_reader_capabilities_distinct() {
        let pair = Operation::Atomic(atomic::Operand {
            bytes: 16,
            base: Register::X(0),
            order: atomic::Order::AcquireRelease,
            kind: atomic::Kind::CompareExchangePair {
                compare: [Register::X(2), Register::X(3)],
                source: [Register::X(30), Register::Zero],
            },
        });
        let required = CheckedOperand::from_operation(&pair, PROFILE)
            .unwrap()
            .unwrap()
            .requirements();
        assert_eq!(required.required_host_caps, host_caps::CX16);
        assert_eq!(required.required_instructions, InstructionRequirements::LSE);
        for (base, expected) in [
            (Register::Sp, 0),
            (Register::X(0), host_caps::ATOMIC_LOAD16),
        ] {
            let source = Operation::Ordered(ordered::Operand::Transfer {
                feature: ordered::Feature::Rcpc2,
                kind: ordered::Kind::AcquirePc,
                bytes: 8,
                data: Register::Zero,
                base,
                displacement: 0,
                extension: ordered::LoadExtension::Zero,
            });
            let required = CheckedOperand::from_operation(&source, PROFILE)
                .unwrap()
                .unwrap()
                .requirements();
            assert_eq!(
                required.required_instructions,
                InstructionRequirements::RCPC2
            );
            assert_eq!(required.required_host_caps, expected);
        }
        let barrier = Operation::Ordered(ordered::Operand::Barrier {
            option: 0,
            requirement: ordered::Barrier::All,
        });
        let required = CheckedOperand::from_operation(&barrier, PROFILE)
            .unwrap()
            .unwrap()
            .requirements();
        assert_eq!(required.required_profile, 0);
        assert_eq!(required.required_host_caps, 0);
        assert_eq!(required.required_flags, flags::ORDERED);
    }
    #[test]
    fn constructed_invalid_roles_widths_and_feature_forms_decline_before_emission() {
        for operation in [
            Operation::Atomic(atomic::Operand {
                bytes: 3,
                base: Register::X(0),
                order: atomic::Order::Relaxed,
                kind: atomic::Kind::CompareExchange {
                    compare: Register::X(1),
                    source: Register::Zero,
                },
            }),
            Operation::Atomic(atomic::Operand {
                bytes: 16,
                base: Register::X(0),
                order: atomic::Order::Relaxed,
                kind: atomic::Kind::CompareExchangePair {
                    compare: [Register::X(1), Register::X(2)],
                    source: [Register::X(2), Register::X(3)],
                },
            }),
            Operation::Ordered(ordered::Operand::Transfer {
                feature: ordered::Feature::Rcpc,
                kind: ordered::Kind::Acquire,
                bytes: 8,
                data: Register::X(1),
                base: Register::X(0),
                displacement: 0,
                extension: ordered::LoadExtension::Zero,
            }),
            Operation::Ordered(ordered::Operand::Transfer {
                feature: ordered::Feature::Base,
                kind: ordered::Kind::Release,
                bytes: 8,
                data: Register::Sp,
                base: Register::X(0),
                displacement: 0,
                extension: ordered::LoadExtension::Zero,
            }),
            Operation::Ordered(ordered::Operand::Barrier {
                option: 16,
                requirement: ordered::Barrier::All,
            }),
        ] {
            assert!(CheckedOperand::from_operation(&operation, PROFILE).is_err());
        }
    }
}

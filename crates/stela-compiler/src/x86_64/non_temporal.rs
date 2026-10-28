//! LDNP/STNP as ordinary accesses with the same footprint (no streaming opcodes,
//! which would add alignment requirements).
use super::{AddressMode, MemoryTransfer, Width, memory_pair, simd};
use crate::aarch64::{
    non_temporal::{Data, Operand},
    simd::Operand as SimdOperand,
};
use crate::x86_64::asm::Code;

const DWORD_BYTES: u8 = 4;
const QWORD_BYTES: u8 = 8;

pub(super) fn emit(code: &mut Code, operand: &Operand, checks: super::MemoryChecks) {
    match operand.data {
        Data::Integer(data) => {
            let transfer = if operand.load {
                MemoryTransfer::Load {
                    signed: false,
                    width: match operand.bytes {
                        DWORD_BYTES => Width::W32,
                        QWORD_BYTES => Width::X64,
                        _ => unreachable!("decoder validates integer non-temporal width"),
                    },
                }
            } else {
                MemoryTransfer::Store
            };
            memory_pair(
                code,
                checks,
                transfer,
                operand.bytes,
                data,
                operand.base,
                operand.displacement,
                AddressMode::Offset,
            );
        }
        Data::Vector(vectors) => {
            simd::emit_for_target(
                code,
                &SimdOperand::MemoryPair {
                    load: operand.load,
                    bytes: operand.bytes,
                    vectors,
                    base: operand.base,
                    displacement: operand.displacement,
                    mode: AddressMode::Offset,
                },
                crate::TargetCpu::Baseline,
                checks,
            );
        }
    }
    // The shared pair recipes stage both loads before destination commits,
    // retain completed store prefixes on faults, and never write back at Offset.
}

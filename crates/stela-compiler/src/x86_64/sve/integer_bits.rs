//! SVE predicated bit operations with SSE2 or SSSE3.
use crate::x86_64::asm::Gpr::Rax;
use crate::x86_64::asm::{Code, Rm, vector_extensions};
use crate::{
    TargetCpu,
    aarch64::{
        scalable::{ElementSize, Predication, VectorLength},
        sve::integer_bits::{Kind, Operand},
    },
    x86_64::{
        isa::{ShiftOpcode as Shift, SimdOpcode as Host},
        scalable::{load_z_chunk, read_predicate_mask, store_z_chunk},
    },
};

mod scalar;

const ALTERNATING_BIT_MASK: u8 = 0x55;
const TWO_BIT_GROUP_MASK: u8 = 0x33;
const SCALAR_WORD_VECTOR_BYTES: usize = 256;
const SOURCE_XMM: u8 = 0;
const OLD_DESTINATION_XMM: u8 = 7;
const PREDICATE_XMM: u8 = 6;
const PREDICATE_SCRATCH_XMM: u8 = 5;
const BYTE_BITS: u8 = u8::BITS as u8;
const NIBBLE_BITS: u8 = BYTE_BITS / 2;
const DWORD_SIGN_SHIFT: u8 = u32::BITS as u8 - 1;
const QWORD_BYTES: usize = core::mem::size_of::<u64>();
const LOW_NIBBLE: u8 = 0x0f;
const SWAP_ADJACENT: u8 = 0xb1;
const REVERSE_FOUR: u8 = 0x1b;
const DUPLICATE_HIGH_DWORDS: u8 = 0xf5;

fn packed(code: &mut Code, opcode: Host, destination: u8, source: u8) {
    opcode.register(code, destination, source, TargetCpu::Baseline);
}

fn constant_qword(code: &mut Code, destination: u8, value: u64) {
    code.asm().mov_imm64(Rax, value);
    packed(code, Host::MoveGprQword, destination, 0);
}

fn repeated_constant(code: &mut Code, destination: u8, element: ElementSize, value: u64) {
    let source = value.to_le_bytes();
    let repeated = core::array::from_fn(|i| source[i % element.bytes()]);
    constant_qword(code, destination, u64::from_le_bytes(repeated));
    packed(code, Host::UnpackLowQword, destination, destination);
}

fn table_constant(code: &mut Code, destination: u8, scratch: u8, values: [u8; 16]) {
    constant_qword(
        code,
        destination,
        u64::from_le_bytes(values[..QWORD_BYTES].try_into().unwrap()),
    );
    constant_qword(
        code,
        scratch,
        u64::from_le_bytes(values[QWORD_BYTES..].try_into().unwrap()),
    );
    packed(code, Host::UnpackLowQword, destination, scratch);
}

fn shuffle(code: &mut Code, opcode: Host, destination: u8, source: u8, control: u8) {
    code.asm().simd_imm(
        opcode,
        destination,
        Rm::Xmm(source),
        control,
        TargetCpu::Baseline,
    );
}

fn add(element: ElementSize) -> Host {
    match element {
        ElementSize::Byte => Host::AddByte,
        ElementSize::Halfword => Host::AddWord,
        ElementSize::Word => Host::AddDword,
        ElementSize::Doubleword => Host::AddQword,
        ElementSize::Quadword => unreachable!("bit-operation decoder excludes 128-bit elements"),
    }
}

fn subtract(element: ElementSize) -> Host {
    match element {
        ElementSize::Byte => Host::SubByte,
        ElementSize::Halfword => Host::SubWord,
        ElementSize::Word => Host::SubDword,
        ElementSize::Doubleword => Host::SubQword,
        ElementSize::Quadword => unreachable!("bit-operation decoder excludes 128-bit elements"),
    }
}

/// Immediate logical element shifts. SSE2 byte shifts need a post-shift mask.
fn logical_shift(code: &mut Code, xmm: u8, element: ElementSize, amount: u8, left: bool) {
    let opcode = match (element, left) {
        (ElementSize::Byte | ElementSize::Halfword, false) => Shift::RightWord,
        (ElementSize::Byte | ElementSize::Halfword, true) => Shift::LeftWord,
        (ElementSize::Word, false) => Shift::RightDword,
        (ElementSize::Word, true) => Shift::LeftDword,
        (ElementSize::Doubleword, false) => Shift::RightQword,
        (ElementSize::Doubleword, true) => Shift::LeftQword,
        (ElementSize::Quadword, _) => unreachable!("bit-operation decoder element"),
    };
    opcode.emit(code, xmm, amount);
    if element == ElementSize::Byte {
        let mask = if left {
            u8::MAX << amount
        } else {
            u8::MAX >> amount
        };
        repeated_constant(code, 6, ElementSize::Byte, u64::from(mask));
        packed(code, Host::And, xmm, 6);
    }
}

/// Compare against zero in XMM3. Qword equality requires both dwords to match.
fn equal_zero(code: &mut Code, xmm: u8, element: ElementSize, target: TargetCpu) {
    if element == ElementSize::Doubleword && target.supports(TargetCpu::Sse41) {
        Host::EqualQword.register(code, xmm, 3, target);
        return;
    }
    let opcode = match element {
        ElementSize::Byte => Host::EqualByte,
        ElementSize::Halfword => Host::EqualWord,
        ElementSize::Word | ElementSize::Doubleword => Host::EqualDword,
        ElementSize::Quadword => unreachable!("bit-operation decoder element"),
    };
    packed(code, opcode, xmm, 3);
    if element == ElementSize::Doubleword {
        shuffle(code, Host::ShuffleDword, 4, xmm, SWAP_ADJACENT);
        packed(code, Host::And, xmm, 4);
    }
}

fn leading_count(code: &mut Code, element: ElementSize, sign: bool, target: TargetCpu) {
    if sign {
        if element == ElementSize::Doubleword {
            packed(code, Host::MoveAligned, 1, SOURCE_XMM);
            Shift::ArithmeticDword.emit(code, 1, DWORD_SIGN_SHIFT);
            shuffle(code, Host::ShuffleDword, 1, 1, DUPLICATE_HIGH_DWORDS);
        } else {
            packed(code, Host::Xor, 1, 1);
            let compare = match element {
                ElementSize::Byte => Host::GreaterByte,
                ElementSize::Halfword => Host::GreaterWord,
                ElementSize::Word => Host::GreaterDword,
                _ => unreachable!("non-qword bit-operation element"),
            };
            packed(code, compare, 1, SOURCE_XMM);
        }
        packed(code, Host::Xor, SOURCE_XMM, 1);
    }
    if vector_extensions::leading_zeros(code, element.bytes() as u8, SOURCE_XMM, target) {
        if sign {
            repeated_constant(code, 1, element, 1);
            packed(code, subtract(element), SOURCE_XMM, 1);
        }
        return;
    }
    packed(code, Host::Xor, 2, 2);
    packed(code, Host::Xor, 3, 3);
    let bits = element.bits() as u8;
    let mut step = bits / 2;
    while step != 0 {
        packed(code, Host::MoveAligned, 1, SOURCE_XMM);
        logical_shift(code, 1, element, bits - step, false);
        equal_zero(code, 1, element, target);
        repeated_constant(code, 4, element, u64::from(step));
        packed(code, Host::And, 4, 1);
        packed(code, add(element), 2, 4);
        packed(code, Host::MoveAligned, 4, SOURCE_XMM);
        logical_shift(code, 4, element, step, true);
        packed(code, Host::Xor, 4, SOURCE_XMM);
        packed(code, Host::And, 4, 1);
        packed(code, Host::Xor, SOURCE_XMM, 4);
        step /= 2;
    }
    equal_zero(code, SOURCE_XMM, element, target);
    repeated_constant(code, 1, element, 1);
    packed(code, Host::And, SOURCE_XMM, 1);
    packed(code, add(element), 2, SOURCE_XMM);
    if sign {
        packed(code, subtract(element), 2, 1);
    }
    packed(code, Host::MoveAligned, SOURCE_XMM, 2);
}

fn nibble_lookup(code: &mut Code, reverse: bool, target: TargetCpu) {
    let values = core::array::from_fn(|i| {
        if reverse {
            (i as u8).reverse_bits() >> NIBBLE_BITS
        } else {
            (i as u8).count_ones() as u8
        }
    });
    table_constant(code, 2, 5, values);
    packed(code, Host::MoveAligned, 4, 2);
    packed(code, Host::MoveAligned, 1, SOURCE_XMM);
    repeated_constant(code, 3, ElementSize::Byte, u64::from(LOW_NIBBLE));
    packed(code, Host::And, SOURCE_XMM, 3);
    Shift::RightWord.emit(code, 1, NIBBLE_BITS);
    packed(code, Host::And, 1, 3);
    Host::ByteShuffle.register(code, 2, SOURCE_XMM, target);
    Host::ByteShuffle.register(code, 4, 1, target);
    if reverse {
        Shift::LeftWord.emit(code, 2, NIBBLE_BITS);
        packed(code, Host::Or, 2, 4);
    } else {
        packed(code, Host::AddByte, 2, 4);
    }
    packed(code, Host::MoveAligned, SOURCE_XMM, 2);
}

fn population_bytes(code: &mut Code, target: TargetCpu) {
    if vector_extensions::population_count(code, 1, SOURCE_XMM, target) {
        return;
    }
    if target.supports(TargetCpu::Ssse3) {
        nibble_lookup(code, false, target);
        return;
    }
    packed(code, Host::MoveAligned, 1, SOURCE_XMM);
    Shift::RightWord.emit(code, 1, 1);
    repeated_constant(code, 2, ElementSize::Byte, u64::from(ALTERNATING_BIT_MASK));
    packed(code, Host::And, 1, 2);
    packed(code, Host::SubByte, SOURCE_XMM, 1);
    packed(code, Host::MoveAligned, 1, SOURCE_XMM);
    Shift::RightWord.emit(code, 1, 2);
    repeated_constant(code, 2, ElementSize::Byte, u64::from(TWO_BIT_GROUP_MASK));
    packed(code, Host::And, SOURCE_XMM, 2);
    packed(code, Host::And, 1, 2);
    packed(code, Host::AddByte, SOURCE_XMM, 1);
    packed(code, Host::MoveAligned, 1, SOURCE_XMM);
    Shift::RightWord.emit(code, 1, NIBBLE_BITS);
    packed(code, Host::AddByte, SOURCE_XMM, 1);
    repeated_constant(code, 2, ElementSize::Byte, u64::from(LOW_NIBBLE));
    packed(code, Host::And, SOURCE_XMM, 2);
}

fn population(code: &mut Code, element: ElementSize, target: TargetCpu) {
    if vector_extensions::population_count(code, element.bytes() as u8, SOURCE_XMM, target) {
        return;
    }
    population_bytes(code, target);
    if element == ElementSize::Doubleword {
        packed(code, Host::Xor, 1, 1);
        code.asm().psadbw(SOURCE_XMM, Rm::Xmm(1));
        return;
    }
    for (width, shift, mask) in [
        (ElementSize::Halfword, BYTE_BITS, u64::from(u8::MAX)),
        (ElementSize::Word, 2 * BYTE_BITS, u64::from(u16::MAX)),
    ] {
        if element < width {
            break;
        }
        packed(code, Host::MoveAligned, 1, SOURCE_XMM);
        logical_shift(code, 1, width, shift, false);
        repeated_constant(code, 2, width, mask);
        packed(code, Host::And, SOURCE_XMM, 2);
        packed(code, add(width), SOURCE_XMM, 1);
    }
}

fn reverse_groups(code: &mut Code, element: ElementSize, group: ElementSize) {
    if group == ElementSize::Byte {
        packed(code, Host::MoveAligned, 1, SOURCE_XMM);
        Shift::RightWord.emit(code, 1, BYTE_BITS);
        Shift::LeftWord.emit(code, SOURCE_XMM, BYTE_BITS);
        packed(code, Host::Or, SOURCE_XMM, 1);
    }
    if group <= ElementSize::Halfword && element >= ElementSize::Word {
        let control = if element == ElementSize::Word {
            SWAP_ADJACENT
        } else {
            REVERSE_FOUR
        };
        shuffle(code, Host::ShuffleLowWord, SOURCE_XMM, SOURCE_XMM, control);
        shuffle(code, Host::ShuffleHighWord, SOURCE_XMM, SOURCE_XMM, control);
    } else if group == ElementSize::Word {
        shuffle(
            code,
            Host::ShuffleDword,
            SOURCE_XMM,
            SOURCE_XMM,
            SWAP_ADJACENT,
        );
    }
}

fn reverse_bits(code: &mut Code, element: ElementSize, target: TargetCpu) {
    if vector_extensions::reverse_bytes(code, SOURCE_XMM, 2, target) {
        // Wider elements also reverse their bytes below.
    } else if target.supports(TargetCpu::Ssse3) {
        nibble_lookup(code, true, target);
    } else {
        const BIT_SWAP_STAGES: [(u8, u8); 3] = [
            (1, ALTERNATING_BIT_MASK),
            (2, TWO_BIT_GROUP_MASK),
            (NIBBLE_BITS, LOW_NIBBLE),
        ];
        for (amount, mask) in BIT_SWAP_STAGES {
            packed(code, Host::MoveAligned, 1, SOURCE_XMM);
            Shift::RightWord.emit(code, 1, amount);
            repeated_constant(code, 2, ElementSize::Byte, u64::from(mask));
            packed(code, Host::And, 1, 2);
            packed(code, Host::And, SOURCE_XMM, 2);
            Shift::LeftWord.emit(code, SOURCE_XMM, amount);
            packed(code, Host::Or, SOURCE_XMM, 1);
        }
    }
    if element != ElementSize::Byte {
        reverse_groups(code, element, ElementSize::Byte);
    }
}

/// The BSR leading-count recipe requires a profile declaring DIT clear; the
/// fixed-work packed recipes do not.
pub(crate) fn requires_declared_dit_zero(operand: Operand, length: VectorLength) -> bool {
    matches!(operand.kind, Kind::LeadingSignBits | Kind::LeadingZeros)
        && (operand.element_size == ElementSize::Doubleword
            || (operand.element_size == ElementSize::Word
                && length.bytes() == SCALAR_WORD_VECTOR_BYTES))
}

pub fn emit(code: &mut Code, operand: Operand, length: VectorLength, target: TargetCpu) {
    let Predication::Merging(predicate) = operand.predication else {
        unreachable!("bit-operation decoder owns only merging forms");
    };
    if (operand.kind == Kind::PopulationCount
        && (vector_extensions::population_supported(operand.element_size.bytes() as u8, target)
            || vector_extensions::population_supported(1, target)))
        || (matches!(operand.kind, Kind::LeadingZeros | Kind::LeadingSignBits)
            && vector_extensions::leading_supported(operand.element_size.bytes() as u8, target))
    {
        code.asm().vzeroupper();
    }
    for chunk in 0..length.chunks() {
        load_z_chunk(code, operand.source, chunk, SOURCE_XMM, length, target);
        match operand.kind {
            Kind::LeadingSignBits | Kind::LeadingZeros => {
                let sign = operand.kind == Kind::LeadingSignBits;
                if requires_declared_dit_zero(operand, length)
                    && !vector_extensions::leading_supported(
                        operand.element_size.bytes() as u8,
                        target,
                    )
                {
                    scalar::chunk(code, operand.element_size, sign);
                } else {
                    leading_count(code, operand.element_size, sign, target);
                }
            }
            Kind::PopulationCount => population(code, operand.element_size, target),
            Kind::ReverseBits => reverse_bits(code, operand.element_size, target),
            Kind::ReverseGroups { group_size } => {
                reverse_groups(code, operand.element_size, group_size)
            }
        }
        load_z_chunk(
            code,
            operand.destination,
            chunk,
            OLD_DESTINATION_XMM,
            length,
            target,
        );
        read_predicate_mask(
            code,
            predicate,
            chunk,
            operand.element_size,
            crate::x86_64::scalable::MaskRegisters::new(PREDICATE_XMM, PREDICATE_SCRATCH_XMM),
            length,
            target,
        );
        // old XOR ((new XOR old) AND active-mask), preserving inactive bytes.
        packed(code, Host::Xor, SOURCE_XMM, OLD_DESTINATION_XMM);
        packed(code, Host::And, SOURCE_XMM, PREDICATE_XMM);
        packed(code, Host::Xor, SOURCE_XMM, OLD_DESTINATION_XMM);
        store_z_chunk(code, operand.destination, chunk, SOURCE_XMM, length, target);
    }
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests {
    use super::*;
    use crate::x86_64::asm::vector_extensions::execution::Native;
    use crate::{
        GuestState,
        context::{ExecutionContext, ScalableStateView},
    };
    use alloc::{vec, vec::Vec};

    #[test]
    fn packed_bit_extensions_preserve_predication_and_aliases() {
        let host = TargetCpu::detect();
        for target in [
            TargetCpu::Baseline,
            TargetCpu::Gfni,
            TargetCpu::Avx512f.with_avx512vl().with_avx512bitalg(),
            TargetCpu::Avx512f.with_avx512vl().with_avx512vpopcntdq(),
            TargetCpu::Avx512f.with_avx512vl().with_avx512cd(),
        ] {
            if !host.supports(target) {
                continue;
            }
            for bytes in [16usize, 64, 256] {
                let length = VectorLength::from_bytes(bytes).unwrap();
                let upper_bytes = bytes - 16;
                for element_size in [
                    ElementSize::Byte,
                    ElementSize::Halfword,
                    ElementSize::Word,
                    ElementSize::Doubleword,
                ] {
                    for kind in [
                        Kind::ReverseBits,
                        Kind::PopulationCount,
                        Kind::LeadingZeros,
                        Kind::LeadingSignBits,
                    ] {
                        for destination in [1u8, 2] {
                            let operand = Operand {
                                kind,
                                destination,
                                source: 1,
                                element_size,
                                predication: Predication::Merging(0),
                            };
                            let mut code = crate::scalable_context::context_wrapper();
                            emit(&mut code, operand, length, target);
                            code.asm().ret();
                            let native = Native::new(&code);
                            for mask in [0u16, u16::MAX, 0xa5c3] {
                                let input: Vec<u8> = (0..bytes)
                                    .map(|i| ((i * 37 + 91) ^ (i >> 2)) as u8)
                                    .collect();
                                let old = if destination == 1 {
                                    input.clone()
                                } else {
                                    vec![0xa5; bytes]
                                };
                                let mut expected = old.clone();
                                let lane = element_size.bytes();
                                for at in (0..bytes).step_by(lane) {
                                    if mask & (1 << (at % 16)) == 0 {
                                        continue;
                                    }
                                    let mut x = [0u8; 8];
                                    x[..lane].copy_from_slice(&input[at..at + lane]);
                                    let x = u64::from_le_bytes(x);
                                    let bits = element_size.bits();
                                    let result = match kind {
                                        Kind::ReverseBits => x.reverse_bits() >> (64 - bits),
                                        Kind::PopulationCount => u64::from(x.count_ones()),
                                        Kind::LeadingZeros => {
                                            u64::from(x.leading_zeros()) - (64 - bits) as u64
                                        }
                                        Kind::LeadingSignBits => {
                                            let shifted = (x << (64 - bits)) as i64;
                                            let unsigned = if shifted < 0 {
                                                !shifted as u64
                                            } else {
                                                shifted as u64
                                            };
                                            u64::from(unsigned.leading_zeros().min(bits as u32)) - 1
                                        }
                                        _ => unreachable!(),
                                    };
                                    expected[at..at + lane]
                                        .copy_from_slice(&result.to_le_bytes()[..lane]);
                                }
                                let words = |x: &[u8]| {
                                    [
                                        u64::from_le_bytes(x[..8].try_into().unwrap()),
                                        u64::from_le_bytes(x[8..16].try_into().unwrap()),
                                    ]
                                };
                                let mut state = GuestState {
                                    fpsr: 0x0800_001f,
                                    nzcv: 0xa000_0000,
                                    ..GuestState::default()
                                };
                                state.v[1] = words(&input);
                                state.v[usize::from(destination)] = words(&old);
                                let mut upper = vec![0u8; 32 * upper_bytes];
                                upper[upper_bytes..2 * upper_bytes].copy_from_slice(&input[16..]);
                                upper[usize::from(destination) * upper_bytes
                                    ..(usize::from(destination) + 1) * upper_bytes]
                                    .copy_from_slice(&old[16..]);
                                let mut predicates = vec![0u8; 16 * length.predicate_bytes()];
                                for b in predicates[..length.predicate_bytes()]
                                    .as_chunks_mut::<2>()
                                    .0
                                {
                                    b.copy_from_slice(&mask.to_le_bytes());
                                }
                                let original_predicates = predicates.clone();
                                let mut scalable = ScalableStateView {
                                    svl_bytes: bytes as u16,
                                    reserved: [0; 6],
                                    svcr: 0,
                                    tpidr2_el0: 0,
                                    fpmr: 0,
                                    z_upper: upper.as_mut_ptr(),
                                    predicates: predicates.as_mut_ptr(),
                                    ffr: core::ptr::null_mut(),
                                    za: core::ptr::null_mut(),
                                    zt0: core::ptr::null_mut(),
                                };
                                let mut context = ExecutionContext {
                                    scalable: &mut scalable,
                                    ..ExecutionContext::default()
                                };
                                native.run(&mut state, &mut context);
                                let mut result = state.v[usize::from(destination)]
                                    .iter()
                                    .flat_map(|w| w.to_le_bytes())
                                    .collect::<Vec<_>>();
                                result.extend_from_slice(
                                    &upper[usize::from(destination) * upper_bytes
                                        ..(usize::from(destination) + 1) * upper_bytes],
                                );
                                assert_eq!(
                                    result, expected,
                                    "{target:?} {bytes} {element_size:?} {kind:?} {destination} {mask:#x}"
                                );
                                assert_eq!(state.fpsr, 0x0800_001f);
                                assert_eq!(state.nzcv, 0xa000_0000);
                                assert_eq!(predicates, original_predicates);
                            }
                        }
                    }
                }
            }
        }
    }
}

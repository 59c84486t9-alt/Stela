//! Bitsliced AES S-box circuit over 16-byte planes on the stack.
//!
//! The SysV entry has RSP%16 == 8, so the frame is padded by eight bytes to align
//! each plane for PAND/PXOR memory operands. The frame is restored before the
//! destination is written.
use super::{BYTE_BITS, Host, LEFT, MASK, RESULT, Shift, TargetCpu, byte_constant, packed};
use alloc::vec::Vec;

const VECTOR_BYTES: u32 = 16;
const INPUT_PLANES: usize = 8;
const SYSV_ENTRY_STACK_MISALIGNMENT: u32 = 8;
const STACK_MODRM_DISP32: u8 = 0x84;
const STACK_SIB: u8 = 0x24;
const SUB_RSP_IMMEDIATE: [u8; 3] = [0x48, 0x81, 0xec];
const ADD_RSP_IMMEDIATE: [u8; 3] = [0x48, 0x81, 0xc4];

// Peralta/Calik's 113-gate forward and 121-gate inverse mathematical circuits:
// https://www.cs.yale.edu/homes/peralta/CircuitStuff/{SLP_AES_113.txt,Sinv.txt}.
// Hash-pinned research receipts retain source identity and exhaustive checks
// against Arm's independent S-box tables. U0/S0 are the most significant bits.
// Every gate is evaluated on sixteen independent 0/1 byte planes. Fixed stack
// locations keep lowering simple; no secret-indexed access or allocation policy.
#[derive(Clone, Copy)]
enum Gate {
    And(u8, u8),
    Xor(u8, u8),
    Xnor(u8, u8),
}

const FORWARD_GATES: [Gate; 113] = [
    Gate::Xor(3, 5),
    Gate::Xor(0, 6),
    Gate::Xor(0, 3),
    Gate::Xor(0, 5),
    Gate::Xor(1, 2),
    Gate::Xor(12, 7),
    Gate::Xor(13, 3),
    Gate::Xor(9, 8),
    Gate::Xor(13, 0),
    Gate::Xor(13, 6),
    Gate::Xor(17, 11),
    Gate::Xor(4, 15),
    Gate::Xor(19, 5),
    Gate::Xor(19, 1),
    Gate::Xor(20, 7),
    Gate::Xor(20, 12),
    Gate::Xor(21, 10),
    Gate::Xor(7, 24),
    Gate::Xor(23, 24),
    Gate::Xor(23, 11),
    Gate::Xor(12, 24),
    Gate::Xor(9, 28),
    Gate::Xor(0, 28),
    Gate::And(15, 20),
    Gate::And(18, 22),
    Gate::Xor(32, 31),
    Gate::And(14, 7),
    Gate::Xor(34, 31),
    Gate::And(9, 28),
    Gate::And(17, 13),
    Gate::Xor(37, 36),
    Gate::And(16, 25),
    Gate::Xor(39, 36),
    Gate::And(10, 24),
    Gate::And(8, 26),
    Gate::Xor(42, 41),
    Gate::And(11, 23),
    Gate::Xor(44, 41),
    Gate::Xor(33, 21),
    Gate::Xor(35, 45),
    Gate::Xor(38, 43),
    Gate::Xor(40, 45),
    Gate::Xor(46, 43),
    Gate::Xor(47, 27),
    Gate::Xor(48, 29),
    Gate::Xor(49, 30),
    Gate::Xor(50, 51),
    Gate::And(50, 52),
    Gate::Xor(53, 55),
    Gate::And(54, 56),
    Gate::Xor(57, 51),
    Gate::Xor(52, 53),
    Gate::Xor(51, 55),
    Gate::And(60, 59),
    Gate::Xor(61, 53),
    Gate::Xor(52, 62),
    Gate::Xor(56, 62),
    Gate::And(53, 64),
    Gate::Xor(65, 63),
    Gate::Xor(56, 65),
    Gate::And(58, 67),
    Gate::Xor(54, 68),
    Gate::Xor(69, 66),
    Gate::Xor(58, 62),
    Gate::Xor(58, 69),
    Gate::Xor(62, 66),
    Gate::Xor(71, 70),
    Gate::And(73, 20),
    Gate::And(66, 22),
    Gate::And(62, 7),
    Gate::And(72, 28),
    Gate::And(69, 13),
    Gate::And(58, 25),
    Gate::And(71, 24),
    Gate::And(74, 26),
    Gate::And(70, 23),
    Gate::And(73, 15),
    Gate::And(66, 18),
    Gate::And(62, 14),
    Gate::And(72, 9),
    Gate::And(69, 17),
    Gate::And(58, 16),
    Gate::And(71, 10),
    Gate::And(74, 8),
    Gate::And(70, 11),
    Gate::Xor(90, 91),
    Gate::Xor(85, 93),
    Gate::Xor(84, 94),
    Gate::Xor(75, 77),
    Gate::Xor(76, 75),
    Gate::Xor(78, 79),
    Gate::Xor(87, 96),
    Gate::Xor(82, 98),
    Gate::Xor(83, 99),
    Gate::Xor(100, 101),
    Gate::Xor(98, 97),
    Gate::Xor(78, 80),
    Gate::Xor(88, 93),
    Gate::Xor(96, 104),
    Gate::Xor(95, 103),
    Gate::Xor(81, 100),
    Gate::Xor(89, 102),
    Gate::Xor(105, 106),
    Gate::Xnor(87, 110),
    Gate::Xor(90, 108),
    Gate::Xor(94, 86),
    Gate::Xor(95, 108),
    Gate::Xnor(102, 110),
    Gate::Xor(106, 107),
    Gate::Xnor(107, 108),
    Gate::Xor(109, 112),
    Gate::Xnor(118, 92),
    Gate::Xor(113, 109),
];
const FORWARD_OUTPUTS: [u8; 8] = [114, 117, 119, 107, 116, 120, 115, 111];

const INVERSE_GATES: [Gate; 121] = [
    Gate::Xor(0, 3),
    Gate::Xnor(1, 3),
    Gate::Xor(0, 9),
    Gate::Xor(6, 7),
    Gate::Xor(9, 11),
    Gate::Xnor(2, 12),
    Gate::Xor(3, 4),
    Gate::Xnor(7, 14),
    Gate::Xor(12, 14),
    Gate::Xnor(0, 2),
    Gate::Xor(5, 17),
    Gate::Xor(8, 9),
    Gate::Xor(12, 16),
    Gate::Xor(10, 15),
    Gate::Xor(18, 13),
    Gate::Xor(8, 12),
    Gate::Xor(9, 16),
    Gate::Xor(20, 19),
    Gate::Xor(10, 18),
    Gate::Xor(15, 13),
    Gate::Xor(22, 21),
    Gate::Xor(20, 22),
    Gate::Xor(24, 27),
    Gate::Xor(16, 13),
    Gate::Xor(19, 21),
    Gate::And(23, 26),
    Gate::And(8, 10),
    Gate::Xor(29, 33),
    Gate::And(12, 18),
    Gate::Xor(36, 33),
    Gate::And(24, 27),
    Gate::And(9, 15),
    Gate::Xor(30, 38),
    Gate::And(16, 13),
    Gate::Xor(41, 38),
    Gate::And(20, 22),
    Gate::And(25, 28),
    Gate::Xor(44, 43),
    Gate::And(19, 21),
    Gate::Xor(46, 43),
    Gate::Xor(35, 34),
    Gate::Xor(37, 32),
    Gate::Xor(40, 39),
    Gate::Xor(42, 47),
    Gate::Xor(48, 45),
    Gate::Xor(49, 47),
    Gate::Xor(50, 45),
    Gate::Xor(51, 31),
    Gate::Xor(54, 55),
    Gate::And(54, 52),
    Gate::Xor(53, 57),
    Gate::Xor(52, 53),
    Gate::Xor(55, 57),
    Gate::And(60, 59),
    Gate::And(58, 56),
    Gate::Xor(55, 62),
    Gate::Xor(53, 61),
    Gate::And(52, 55),
    Gate::And(59, 65),
    Gate::Xor(59, 57),
    Gate::Xor(66, 67),
    Gate::And(53, 54),
    Gate::And(56, 69),
    Gate::Xor(56, 57),
    Gate::Xor(70, 71),
    Gate::Xor(68, 72),
    Gate::Xor(64, 63),
    Gate::Xor(64, 68),
    Gate::Xor(63, 72),
    Gate::Xor(74, 73),
    Gate::And(76, 26),
    Gate::And(72, 10),
    Gate::And(63, 18),
    Gate::And(75, 27),
    Gate::And(68, 15),
    Gate::And(64, 13),
    Gate::And(74, 22),
    Gate::And(77, 28),
    Gate::And(73, 21),
    Gate::And(76, 23),
    Gate::And(72, 8),
    Gate::And(63, 12),
    Gate::And(75, 24),
    Gate::And(68, 9),
    Gate::And(64, 16),
    Gate::And(74, 20),
    Gate::And(77, 25),
    Gate::And(73, 19),
    Gate::Xor(79, 78),
    Gate::Xor(80, 78),
    Gate::Xor(82, 81),
    Gate::Xor(83, 81),
    Gate::Xor(85, 84),
    Gate::Xor(86, 84),
    Gate::Xor(96, 100),
    Gate::Xor(97, 101),
    Gate::Xor(98, 100),
    Gate::Xor(99, 101),
    Gate::Xor(88, 87),
    Gate::Xor(89, 87),
    Gate::Xor(91, 90),
    Gate::Xor(92, 90),
    Gate::Xor(94, 93),
    Gate::Xor(95, 93),
    Gate::Xor(106, 110),
    Gate::Xor(107, 111),
    Gate::Xor(108, 110),
    Gate::Xor(109, 111),
    Gate::Xor(103, 114),
    Gate::Xor(104, 114),
    Gate::Xor(105, 114),
    Gate::Xor(102, 104),
    Gate::Xor(118, 119),
    Gate::Xor(112, 115),
    Gate::Xor(119, 121),
    Gate::Xor(116, 122),
    Gate::Xor(103, 113),
    Gate::Xor(122, 124),
    Gate::Xor(102, 112),
    Gate::Xor(120, 124),
    Gate::Xor(126, 127),
];
const INVERSE_OUTPUTS: [u8; 8] = [118, 123, 125, 116, 128, 120, 117, 113];

fn stack_plane(code: &mut Vec<u8>, register: u8, plane: usize, opcode: Host) {
    opcode.append(code, TargetCpu::Baseline);
    code.extend([STACK_MODRM_DISP32 | (register << 3), STACK_SIB]);
    code.extend((plane as u32 * VECTOR_BYTES).to_le_bytes());
}

pub(super) fn emit(code: &mut Vec<u8>, inverse: bool) {
    let (gates, outputs): (&[Gate], [u8; 8]) = if inverse {
        (&INVERSE_GATES, INVERSE_OUTPUTS)
    } else {
        (&FORWARD_GATES, FORWARD_OUTPUTS)
    };
    let frame = (INPUT_PLANES + gates.len()) as u32 * VECTOR_BYTES + SYSV_ENTRY_STACK_MISALIGNMENT;
    code.extend(SUB_RSP_IMMEDIATE);
    code.extend(frame.to_le_bytes());
    byte_constant(code, MASK, 1);
    for input in 0..INPUT_PLANES {
        packed(code, Host::MoveAligned, LEFT, RESULT);
        let bit = BYTE_BITS - 1 - input as u8;
        if bit != 0 {
            Shift::RightWord.emit(code, LEFT, bit);
        }
        packed(code, Host::And, LEFT, MASK);
        stack_plane(code, LEFT, input, Host::StoreUnaligned);
    }
    for (index, gate) in gates.iter().enumerate() {
        let (left, right, opcode, invert) = match *gate {
            Gate::And(left, right) => (left, right, Host::And, false),
            Gate::Xor(left, right) => (left, right, Host::Xor, false),
            Gate::Xnor(left, right) => (left, right, Host::Xor, true),
        };
        stack_plane(code, LEFT, usize::from(left), Host::LoadUnaligned);
        stack_plane(code, LEFT, usize::from(right), opcode);
        if invert {
            packed(code, Host::Xor, LEFT, MASK);
        }
        stack_plane(code, LEFT, INPUT_PLANES + index, Host::StoreUnaligned);
    }
    packed(code, Host::Xor, RESULT, RESULT);
    for (output, plane) in outputs.into_iter().enumerate() {
        stack_plane(code, LEFT, usize::from(plane), Host::LoadUnaligned);
        let bit = BYTE_BITS - 1 - output as u8;
        if bit != 0 {
            Shift::LeftWord.emit(code, LEFT, bit);
        }
        packed(code, Host::Or, RESULT, LEFT);
    }
    code.extend(ADD_RSP_IMMEDIATE);
    code.extend(frame.to_le_bytes());
}

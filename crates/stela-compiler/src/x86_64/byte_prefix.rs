//! A sum and sum of prefixes over a contiguous, read-only 16-byte span.
use super::asm::{Alu, Code, Cond, Gpr, Mem, Patch, Rm, ShiftOp, Size};
use super::isa::SimdOpcode as Host;
use crate::{
    TargetCpu,
    aarch64::{AddressMode, Instruction, MemoryTransfer, Operation, Register, Width},
    block::Terminator,
};

const BYTES: usize = 16;
const PAGE_BYTES: i32 = super::memory_store::PROTECTION_GRANULE_BYTES as i32;

/// The sum and sum-of-prefixes recurrence, plus architectural writebacks.
pub(super) struct Plan<'a> {
    base: Register,
    sum: Register,
    prefix: Register,
    scratch: [Register; 2],
    counter: [Option<&'a Operation>; 2],
}

impl<'a> Plan<'a> {
    pub(super) fn new(
        body: &'a [Instruction],
        terminal: Option<&(crate::GuestAddress, Terminator)>,
    ) -> Option<Self> {
        // Three operations per byte, one base advance, and one or two
        // independent counter operations.
        if !(3 * BYTES + 2..=3 * BYTES + 3).contains(&body.len()) {
            return None;
        }
        let (branch, Terminator::Branch(Operation::BranchCondition { target, condition })) =
            terminal?
        else {
            return None;
        };
        let first = body.first()?;
        if *target != first.pc
            || *condition >= 14
            || first.pc.0.checked_add(4 * body.len() as u64) != Some(branch.0)
        {
            return None;
        }
        let Operation::Memory {
            base: base @ Register::X(_),
            ..
        } = first.operation
        else {
            return None;
        };

        let mut scratch = [Register::Zero; 2];
        let mut byte_in_scratch = [None; 2];
        let (mut loads, mut sums, mut prefixes) = (0, 0, 0);
        let (mut sum, mut prefix) = (None, None);
        let mut advanced = false;
        let mut counter = [None; 2];
        let mut counter_len = 0;
        let mut counter_register = None;
        let mut writes_flags = false;
        for (index, row) in body.iter().enumerate() {
            if first.pc.0.checked_add(4 * index as u64) != Some(row.pc.0) {
                return None;
            }
            match row.operation {
                Operation::Memory {
                    transfer:
                        MemoryTransfer::Load {
                            signed: false,
                            width: Width::W32,
                        },
                    bytes: 1,
                    data: data @ Register::X(_),
                    base: address,
                    displacement,
                    mode: AddressMode::Offset,
                } if address == base
                    && !advanced
                    && loads < BYTES
                    && displacement == loads as i32 =>
                {
                    let lane = loads % 2;
                    if scratch[lane] == Register::Zero {
                        scratch[lane] = data;
                    }
                    if scratch[lane] != data || byte_in_scratch[lane].is_some_and(|i| i >= sums) {
                        return None;
                    }
                    byte_in_scratch[lane] = Some(loads);
                    loads += 1;
                }
                Operation::AddSubRegister {
                    width: Width::X64,
                    subtract: false,
                    flags: false,
                    destination: destination @ Register::X(_),
                    left,
                    right,
                    amount: 0,
                    ..
                } => {
                    let other = if left == destination {
                        right
                    } else if right == destination {
                        left
                    } else {
                        return None;
                    };
                    if Some(other) == sum {
                        if sums != prefixes + 1 || *prefix.get_or_insert(destination) != destination
                        {
                            return None;
                        }
                        prefixes += 1;
                    } else {
                        let lane = scratch.iter().position(|&register| register == other)?;
                        if sums == BYTES
                            || sums != prefixes
                            || byte_in_scratch[lane] != Some(sums)
                            || *sum.get_or_insert(destination) != destination
                        {
                            return None;
                        }
                        sums += 1;
                    }
                }
                Operation::AddSub {
                    width: Width::X64,
                    subtract: false,
                    flags: false,
                    destination,
                    source,
                    immediate,
                } if destination == base && source == base && immediate == BYTES as u32 => {
                    if advanced || loads != BYTES {
                        return None;
                    }
                    advanced = true;
                }
                Operation::AddSub {
                    source: source @ Register::X(_),
                    destination,
                    flags,
                    ..
                } if destination == source || (flags && destination == Register::Zero) => {
                    if *counter_register.get_or_insert(source) != source || (flags && writes_flags)
                    {
                        return None;
                    }
                    writes_flags |= flags;
                    *counter.get_mut(counter_len)? = Some(&row.operation);
                    counter_len += 1;
                }
                _ => return None,
            }
        }
        let (sum, prefix) = (sum?, prefix?);
        let registers = [base, sum, prefix, scratch[0], scratch[1], counter_register?];
        if !advanced
            || !writes_flags
            || sums != BYTES
            || prefixes != BYTES
            || byte_in_scratch != [Some(BYTES - 2), Some(BYTES - 1)]
            || registers
                .iter()
                .enumerate()
                .any(|(i, register)| registers[..i].contains(register))
        {
            return None;
        }
        Some(Self {
            base,
            sum,
            prefix,
            scratch,
            counter,
        })
    }

    /// An exact 16-byte read fits one protection page. If it faults, the
    /// first original byte would fault before any guest state write. Split
    /// pages take the scalar body with its original individual accesses.
    /// The caller binds the fast path to the common branch after that body.
    pub(super) fn emit(self, code: &mut Code, target: TargetCpu) -> Patch {
        use Gpr::{R8, R9, Rax, Rcx, Rdx};
        use Size::{Byte, Dword, Qword};
        const DATA: u8 = 0;
        const ZERO: u8 = 1;
        const WORK: u8 = 2;
        const DOT: u8 = 3;
        const WEIGHT: u8 = 4;

        debug_assert!(!code.is_pinned() && !code.constant_time());
        code.set_instruction(0);
        super::load(code, self.base);
        let mut asm = code.asm();
        asm.mov(Dword, Rcx, Rax);
        asm.alu_imm32(Alu::And, Dword, Rcx, PAGE_BYTES - 1);
        asm.alu_imm32(Alu::Cmp, Dword, Rcx, PAGE_BYTES - BYTES as i32);
        let split_page = asm.jcc(Cond::A);
        asm.guest_access(|asm| asm.movdqu_load(DATA, Mem::base(Rax, 0)));

        Host::Xor.register(code, ZERO, ZERO, target);
        Host::MoveAligned.register(code, WORK, DATA, target);
        code.asm().psadbw(WORK, Rm::Xmm(ZERO));
        code.asm().movhlps(DOT, Rm::Xmm(WORK));
        Host::AddQword.register(code, WORK, DOT, target);
        code.asm().movd_from_xmm(R8, WORK);

        Host::MoveAligned.register(code, DOT, DATA, target);
        let (fields, weights) = if target.supports(TargetCpu::Ssse3) {
            let first = load_constant(code, WEIGHT);
            Host::MultiplyAddUnsignedBytes.register(code, DOT, WEIGHT, target);
            let second = load_constant(code, WEIGHT);
            Host::MultiplyAddWords.register(code, DOT, WEIGHT, target);
            Host::HorizontalAddDword.register(code, DOT, DOT, target);
            Host::HorizontalAddDword.register(code, DOT, DOT, target);
            (
                [first, second],
                [
                    [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
                    [1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0],
                ],
            )
        } else {
            Host::UnpackLowByte.register(code, DOT, ZERO, target);
            Host::MoveAligned.register(code, WORK, DATA, target);
            Host::UnpackHighByte.register(code, WORK, ZERO, target);
            let first = load_constant(code, WEIGHT);
            Host::MultiplyAddWords.register(code, DOT, WEIGHT, target);
            let second = load_constant(code, WEIGHT);
            Host::MultiplyAddWords.register(code, WORK, WEIGHT, target);
            Host::AddDword.register(code, DOT, WORK, target);
            for shuffle in [0x4e, 0xb1] {
                Host::ShuffleDword.register_imm(code, WORK, DOT, shuffle, target);
                Host::AddDword.register(code, DOT, WORK, target);
            }
            (
                [first, second],
                [
                    [16, 0, 15, 0, 14, 0, 13, 0, 12, 0, 11, 0, 10, 0, 9, 0],
                    [8, 0, 7, 0, 6, 0, 5, 0, 4, 0, 3, 0, 2, 0, 1, 0],
                ],
            )
        };

        let mut asm = code.asm();
        asm.movd_from_xmm(R9, DOT);
        asm.pextrw(Rdx, DATA, 7);
        asm.movzx(Dword, Rcx, Byte, Rdx);
        asm.shift_imm(ShiftOp::Shr, Dword, Rdx, 8);
        store(&mut asm, self.scratch[0], Rcx);
        store(&mut asm, self.scratch[1], Rdx);

        let sum = asm.guest(self.sum).expect("prefix sum input");
        let prefix = asm.guest(self.prefix).expect("prefix sum accumulator");
        asm.mov_load(Qword, Rcx, sum);
        asm.lea(Qword, Rdx, Mem::indexed(Rcx, R8, 1, 0));
        asm.mov_store(Qword, sum, Rdx);
        asm.shift_imm(ShiftOp::Shl, Qword, Rcx, 4);
        asm.alu_load(Alu::Add, Qword, Rcx, prefix);
        asm.alu(Alu::Add, Qword, Rcx, R9);
        asm.mov_store(Qword, prefix, Rcx);
        asm.alu_imm8(Alu::Add, Qword, Rax, BYTES as i8);
        store(&mut asm, self.base, Rax);
        for operation in self.counter.into_iter().flatten() {
            assert!(super::pinned::emit_direct(code, operation, target));
        }

        let done = code.asm().jmp();
        for (field, weight) in fields.into_iter().zip(weights) {
            let displacement = i32::try_from(code.len() - field - size_of::<i32>())
                .expect("bounded prefix sum table displacement");
            code.patch(field, displacement.to_le_bytes());
            code.asm().data(&weight);
        }
        code.asm().bind(split_page);
        done
    }
}

fn load_constant(code: &mut Code, xmm: u8) -> usize {
    code.asm().movdqu_load(xmm, Mem::rip(0));
    code.len() - size_of::<i32>()
}

fn store(asm: &mut super::asm::Asm<'_>, register: Register, value: Gpr) {
    let destination = asm.guest(register).expect("prefix sum frame output");
    asm.mov_store(Size::Qword, destination, value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        GuestAddress, Options,
        block::{BlockProfile, CompilationPlan, Features},
    };
    use alloc::{vec, vec::Vec};

    const ENTRY: GuestAddress = GuestAddress(0x1000);
    const VECTOR_READ: [u8; 4] = [0xf3, 0x0f, 0x6f, 0x00];

    fn source() -> Vec<u32> {
        // Read through X0 into alternating W2/W3, accumulate in X5/X6.
        // The independent W4 counter supplies the backedge predicate.
        let load = |byte: u32| 0x3940_0002 | (byte << 10) | (byte & 1);
        let mut words = vec![load(0), load(1), 0x3100_0484];
        for byte in 0..BYTES as u32 {
            words.push(0x8b02_00a5 | ((byte & 1) << 16)); // ADD X5,X5,X2/X3
            if byte + 2 < BYTES as u32 {
                words.push(load(byte + 2));
            }
            words.push(0x8b05_00c6); // ADD X6,X6,X5
        }
        words.push(0x9100_4000); // ADD X0,X0,#16
        let backedge = (-(words.len() as i32) as u32) & 0x7_ffff;
        words.push(0x5400_0003 | (backedge << 5)); // B.LO entry
        words
    }

    fn compile(
        words: &[u32],
        pc: GuestAddress,
        target: TargetCpu,
        resident: bool,
    ) -> crate::block::CompiledBlock {
        let source: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let options = Options::new(BlockProfile::ORDINARY, target);
        let plan = CompilationPlan::new(&source, pc, &options).unwrap();
        let plan = if resident {
            let plan = plan.with_resident_loops();
            assert!(plan.profile().has(Features::RESIDENT_LOOPS));
            plan
        } else {
            plan
        };
        plan.compile().unwrap()
    }

    fn vector_reads(block: &crate::block::CompiledBlock) -> usize {
        block
            .native
            .x86_64_code
            .windows(VECTOR_READ.len())
            .filter(|bytes| *bytes == VECTOR_READ)
            .count()
    }

    #[test]
    fn guarded_prefix_sums_keep_scalar_rows_and_decline_unsafe_shapes() {
        let words = source();
        let baseline = TargetCpu::Baseline;
        for target in [baseline, TargetCpu::Ssse3] {
            for resident in [false, true] {
                let block = compile(&words, ENTRY, target, resident);
                assert_eq!(vector_reads(&block), 1);
                let map = &block.native.source_map;
                assert_eq!(map.len(), words.len());
                assert_eq!(map[0], (ENTRY, 0));
                assert!(
                    map.windows(2)
                        .all(|pair| { pair[1].0.0 == pair[0].0.0 + 4 && pair[1].1 > pair[0].1 })
                );
                let vector = block
                    .native
                    .x86_64_code
                    .windows(VECTOR_READ.len())
                    .position(|bytes| bytes == VECTOR_READ)
                    .unwrap();
                assert!(vector < map[1].1);
            }
        }

        let mut duplicate = words.clone();
        duplicate[1] &= !(1 << 10); // Repeat offset zero.
        let mut alias = words.clone();
        alias[2] = 0x3100_0400; // ADDS W0,W0,#1 also changes the load base.
        let mut wide = words.clone();
        wide[0] |= 1 << 30; // LDRH has a larger fault footprint.
        for fallback in [duplicate, alias, wide] {
            assert_eq!(vector_reads(&compile(&fallback, ENTRY, baseline, false)), 0);
        }
        assert_eq!(
            vector_reads(&compile(
                &words,
                ENTRY,
                baseline.with_data_independent_timing(),
                false
            )),
            0
        );
        assert_eq!(
            vector_reads(&compile(
                &words[1..],
                GuestAddress(ENTRY.0 + 4),
                baseline,
                false
            )),
            0
        );
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn emitted_prefix_sums_settle_ordinary_and_resident_exits() {
        use crate::{GuestState, block::loop_budget::LoopBudget, x86_64::native};

        #[repr(align(4096))]
        struct Pages([u8; 8192]);

        let input = Pages(core::array::from_fn(|i| (i * 43 + (i >> 7)) as u8));
        let mut words = source();
        for counter_last in [false, true] {
            if counter_last {
                let counter = words.remove(2);
                words.insert(words.len() - 1, counter);
            }
            let fallthrough = ENTRY.0 + words.len() as u64 * 4;
            for target in [
                TargetCpu::Baseline,
                TargetCpu::Ssse3,
                TargetCpu::X86_64_V2.with_bmi2().with_fast_pdep(),
            ] {
                if !TargetCpu::detect().supports(target) {
                    continue;
                }
                let ordinary = compile(&words, ENTRY, target, false);
                let resident = compile(&words, ENTRY, target, true);
                for offset in [4080, 4081] {
                    let data = &input.0[offset..offset + 2 * BYTES];
                    for (budget, counter) in [
                        (0, 0),
                        (1, 0),
                        (2, 0),
                        (1, i32::MAX as u32),
                        (2, u32::MAX - 1),
                        (2, u32::MAX),
                    ] {
                        for resident in [None, Some(&resident)] {
                            let mut state = GuestState::default();
                            state.x[0] = data.as_ptr() as u64;
                            state.x[2] = u64::MAX;
                            state.x[3] = u64::MAX;
                            state.x[4] = u64::from(counter) | (u64::MAX << 32);
                            state.x[5] = u64::MAX - 101;
                            state.x[6] = u64::MAX - 37;
                            state.nzcv = 0xf000_0000;
                            state.v[0] = [0x1357, 0x2468];
                            let mut expected = state.clone();
                            let limit = if resident.is_some() { budget } else { 1 };
                            let mut pc = ENTRY.0;
                            let mut consumed = 0;
                            for bytes in data.as_chunks::<BYTES>().0.iter().take(limit) {
                                for &byte in bytes {
                                    expected.x[5] = expected.x[5].wrapping_add(u64::from(byte));
                                    expected.x[6] = expected.x[6].wrapping_add(expected.x[5]);
                                }
                                expected.x[0] += BYTES as u64;
                                expected.x[2] = u64::from(bytes[BYTES - 2]);
                                expected.x[3] = u64::from(bytes[BYTES - 1]);
                                let old = expected.x[4] as u32;
                                let (next, carry) = old.overflowing_add(1);
                                expected.x[4] = u64::from(next);
                                expected.nzcv = (next & 0x8000_0000)
                                    | (u32::from(next == 0) << 30)
                                    | (u32::from(carry) << 29)
                                    | (u32::from(old == i32::MAX as u32) << 28);
                                consumed += 1;
                                if carry {
                                    pc = fallthrough;
                                    break;
                                }
                            }
                            let returned = if let Some(block) = resident {
                                let mut remaining = LoopBudget::new(budget);
                                let returned = native::run_with_budget(
                                    &block.native.x86_64_code,
                                    &mut state,
                                    &mut remaining,
                                );
                                assert_eq!(remaining.consumed(budget), Some(consumed));
                                returned
                            } else {
                                native::run(&ordinary.native.x86_64_code, &mut state)
                            };
                            assert_eq!(returned, pc, "{target:?} {offset} {budget} {counter}");
                            assert_eq!(state, expected, "{target:?} {offset} {budget} {counter}");
                        }
                    }
                }
            }
        }
    }
}

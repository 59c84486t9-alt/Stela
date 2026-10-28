//! Predicate generation, using BMI1 when available.
use super::predicate;
use crate::x86_64::asm::Gpr::{R8, R9, R10, R11, Rax, Rcx, Rdi, Rdx};
use crate::x86_64::asm::{Alu, Code, Cond, Mem, ShiftOp, Size, Unary};
use crate::{
    GuestState, TargetCpu,
    aarch64::{
        Register, Shift, Width,
        scalable::{ElementSize, MAX_VECTOR_BYTES, VectorLength},
        sve::predicate_generation::{BasicOperand, Destination, Operand},
    },
    x86_64::{
        load, right_operand,
        scalable::{read_predicate_chunk, write_predicate_chunk, zero_predicate},
    },
};

const CHUNK_BITS: usize = u64::BITS as usize;
const CHUNK_BYTES: usize = core::mem::size_of::<u64>();
const NZCV_OFFSET: u32 = core::mem::offset_of!(GuestState, nzcv) as u32;
const N_FLAG: u32 = 1 << 31;
const Z_FLAG: u32 = 1 << 30;
const C_FLAG: u32 = 1 << 29;
const V_FLAG: u32 = 1 << 28;
const COUNTER_INVERT_BIT: u64 = 1 << 15;
const PATTERN_POW2: u8 = 0;
const PATTERN_MUL4: u8 = 29;
const PATTERN_MUL3: u8 = 30;
const PATTERN_ALL: u8 = 31;

pub(crate) fn emit(code: &mut Code, operand: &Operand, length: VectorLength, target: TargetCpu) {
    match operand {
        Operand::Basic(basic) => emit_basic(code, basic, length, target),
        Operand::Break(operand) => breaks::emit_break(code, *operand, length, target),
        Operand::While(operand) => whiles::emit_while(code, operand, length, write_counted),
    }
}

fn chunks(length: VectorLength) -> usize {
    length.predicate_bytes().div_ceil(CHUNK_BYTES)
}
fn constant(code: &mut Code, value: u64) {
    if value == 0 {
        code.asm().alu(Alu::Xor, Size::Dword, Rax, Rax);
    } else if let Ok(value) = u32::try_from(value) {
        code.asm().mov_imm32(Rax, value);
    } else if let Ok(value) = i32::try_from(value as i64) {
        code.asm().mov_rm_imm32(Size::Qword, Rax, value);
    } else {
        code.asm().mov_imm64(Rax, value);
    }
}
fn marker_mask(element: ElementSize) -> u64 {
    predicate::leading_bits(element)
}
fn stage(code: &mut Code, xmm: u8) {
    assert!(xmm < 8);
    code.asm().movq_to_xmm(xmm, Rax);
}
fn restore(code: &mut Code, xmm: u8) {
    assert!(xmm < 8);
    code.asm().movq_from_xmm(Rax, xmm);
}
fn restore_guard(code: &mut Code, xmm: u8) {
    restore(code, xmm);
    code.asm().mov(Size::Qword, R11, Rax);
}
fn commit_staged(code: &mut Code, destination: u8, length: VectorLength) {
    for chunk in 0..chunks(length) {
        restore(code, chunk as u8);
        write_predicate_chunk(code, destination, chunk, length);
    }
}
fn test_staged(code: &mut Code, element: ElementSize, length: VectorLength) {
    predicate::begin_predtest(code);
    for chunk in 0..chunks(length) {
        restore_guard(code, 4 + chunk as u8);
        restore(code, chunk as u8);
        predicate::accumulate_predtest(code, element);
    }
    predicate::finish_predtest(code);
}
fn immediate_flags(code: &mut Code, flags: u32) {
    code.asm().mov_rm_imm32(
        Size::Dword,
        Mem::base_disp32(Rdi, NZCV_OFFSET as i32),
        flags as i32,
    );
}
fn pattern_count(pattern: u8, elements: usize) -> usize {
    let count = match pattern {
        PATTERN_POW2 => 1 << elements.ilog2(),
        1..=8 => usize::from(pattern),
        9..=13 => 1 << (pattern - 5),
        PATTERN_MUL4 => elements / 4 * 4,
        PATTERN_MUL3 => elements / 3 * 3,
        PATTERN_ALL => elements,
        _ => 0,
    };
    if count <= elements { count } else { 0 }
}
fn emit_basic(code: &mut Code, operand: &BasicOperand, length: VectorLength, target: TargetCpu) {
    match *operand {
        BasicOperand::False { destination } => zero_predicate(code, destination, length),
        BasicOperand::True {
            destination,
            element,
            pattern,
            set_flags,
        } => {
            let count = pattern_count(pattern, length.lanes(element));
            for chunk in 0..chunks(length) {
                let value = (0..count)
                    .map(|lane| lane * element.bytes())
                    .filter(|bit| bit / CHUNK_BITS == chunk)
                    .fold(0, |mask, bit| mask | (1u64 << (bit % CHUNK_BITS)));
                constant(code, value);
                write_predicate_chunk(code, destination, chunk, length);
            }
            if set_flags {
                immediate_flags(code, if count == 0 { Z_FLAG | C_FLAG } else { N_FLAG });
            }
        }
        BasicOperand::TrueCounter {
            destination,
            element,
        } => {
            if chunks(length) > 1 {
                zero_predicate(code, destination, length);
            }
            constant(code, COUNTER_INVERT_BIT | element.bytes() as u64);
            write_predicate_chunk(code, destination, 0, length);
        }
        BasicOperand::Test { governing, source } => {
            predicate::begin_predtest(code);
            for chunk in 0..chunks(length) {
                read_predicate_chunk(code, governing, chunk, length);
                code.asm().mov(Size::Qword, R11, Rax);
                read_predicate_chunk(code, source, chunk, length);
                predicate::accumulate_predtest(code, ElementSize::Byte);
            }
            predicate::finish_predtest(code);
        }
        BasicOperand::First {
            destination,
            governing,
        } => emit_first(code, destination, governing, length, target),
        BasicOperand::Next {
            destination,
            governing,
            element,
        } => emit_next(code, destination, governing, element, length),
        BasicOperand::ConditionalTerminate {
            first,
            second,
            width,
            equal,
        } => emit_terminate(code, first, second, width, equal),
    }
}
fn emit_first(
    code: &mut Code,
    destination: u8,
    governing: u8,
    length: VectorLength,
    target: TargetCpu,
) {
    code.asm().mov_rm_imm32(Size::Qword, R10, -1);
    for chunk in 0..chunks(length) {
        read_predicate_chunk(code, governing, chunk, length);
        stage(code, 4 + chunk as u8);
        code.asm().mov(Size::Qword, R11, Rax);
        // Shorter profiles retain the baseline recipe: some measured short
        // cohorts regressed with BMI1, while the maximum profile improved.
        if target.supports(TargetCpu::Bmi1) && length.bytes() == MAX_VECTOR_BYTES {
            code.asm().blsi(Size::Qword, R9, R11);
        } else {
            let mut asm = code.asm();
            asm.mov(Size::Qword, R9, R11);
            asm.unary(Unary::Neg, Size::Qword, R9);
            asm.alu(Alu::And, Size::Qword, R9, R11);
        }
        let mut asm = code.asm();
        asm.alu(Alu::And, Size::Qword, R9, R10);
        asm.alu_imm8(Alu::Cmp, Size::Qword, R11, 1);
        asm.alu(Alu::Sbb, Size::Qword, Rcx, Rcx);
        asm.alu(Alu::And, Size::Qword, R10, Rcx);
        read_predicate_chunk(code, destination, chunk, length);
        code.asm().alu(Alu::Or, Size::Qword, Rax, R9);
        stage(code, chunk as u8);
    }
    commit_staged(code, destination, length);
    test_staged(code, ElementSize::Byte, length);
}
fn emit_next(
    code: &mut Code,
    destination: u8,
    governing: u8,
    element: ElementSize,
    length: VectorLength,
) {
    code.asm().alu(Alu::Xor, Size::Dword, R10, R10);
    for chunk in 0..chunks(length) {
        read_predicate_chunk(code, governing, chunk, length);
        stage(code, 4 + chunk as u8);
        read_predicate_chunk(code, destination, chunk, length);
        let mut asm = code.asm();
        asm.mov_imm64(R11, marker_mask(element));
        asm.alu(Alu::And, Size::Qword, Rax, R11);
        asm.test(Size::Qword, Rax, Rax);
        let empty = asm.jcc(Cond::E);
        asm.bsr(Size::Qword, Rcx, Rax);
        asm.lea(
            Size::Dword,
            R10,
            Mem::base_disp32(Rcx, (chunk * CHUNK_BITS + element.bytes()) as i32),
        );
        asm.bind(empty);
    }
    code.asm().mov_rm_imm32(Size::Qword, R9, -1);
    for chunk in 0..chunks(length) {
        restore(code, 4 + chunk as u8);
        let mut asm = code.asm();
        asm.mov_imm64(R11, marker_mask(element));
        asm.alu(Alu::And, Size::Qword, Rax, R11);
        asm.alu_imm32(Alu::Cmp, Size::Dword, R10, (chunk * CHUNK_BITS) as i32);
        let keep = asm.jcc(Cond::Be);
        asm.alu_imm32(
            Alu::Cmp,
            Size::Dword,
            R10,
            ((chunk + 1) * CHUNK_BITS) as i32,
        );
        let empty = asm.jcc(Cond::Ae);
        asm.mov(Size::Dword, Rcx, R10);
        asm.alu_imm32(Alu::Sub, Size::Dword, Rcx, (chunk * CHUNK_BITS) as i32);
        asm.mov_imm64(R11, u64::MAX);
        asm.shift_cl(ShiftOp::Shl, Size::Qword, R11);
        asm.alu(Alu::And, Size::Qword, Rax, R11);
        asm.bind(keep);
        asm.mov(Size::Qword, R11, Rax);
        asm.unary(Unary::Neg, Size::Qword, R11);
        asm.alu(Alu::And, Size::Qword, Rax, R11);
        asm.alu(Alu::And, Size::Qword, Rax, R9);
        asm.alu_imm8(Alu::Cmp, Size::Qword, Rax, 1);
        asm.alu(Alu::Sbb, Size::Qword, Rcx, Rcx);
        asm.alu(Alu::And, Size::Qword, R9, Rcx);
        let ready = asm.jmp();
        asm.bind(empty);
        asm.alu(Alu::Xor, Size::Dword, Rax, Rax);
        asm.bind(ready);
        stage(code, chunk as u8);
    }
    commit_staged(code, destination, length);
    test_staged(code, element, length);
}
fn emit_terminate(code: &mut Code, first: Register, second: Register, width: Width, equal: bool) {
    load(code, first);
    right_operand(code, second, width, Shift::Lsl, 0);
    let mut asm = code.asm();
    asm.alu(Alu::Cmp, Size::of(width == Width::X64), Rax, Rcx);
    asm.setcc(if equal { Cond::E } else { Cond::Ne }, Rax);
    asm.movzx(Size::Dword, Rax, Size::Byte, Rax);
    asm.mov(Size::Dword, Rcx, Rax);
    asm.alu_imm8(Alu::Xor, Size::Dword, Rcx, 1);
    asm.shift_imm(
        ShiftOp::Shl,
        Size::Dword,
        Rax,
        N_FLAG.trailing_zeros() as u8,
    );
    asm.mov_load(Size::Dword, Rdx, Mem::base_disp32(Rdi, NZCV_OFFSET as i32));
    asm.alu_imm32(Alu::And, Size::Dword, Rdx, (Z_FLAG | C_FLAG) as i32);
    asm.alu(Alu::Or, Size::Dword, Rax, Rdx);
    asm.mov(Size::Dword, R11, Rdx);
    asm.shift_imm(
        ShiftOp::Shr,
        Size::Dword,
        R11,
        C_FLAG.trailing_zeros() as u8,
    );
    // Z survives independently; isolate C before forming !C.
    asm.alu_imm8(Alu::And, Size::Dword, R11, 1);
    asm.alu_imm8(Alu::Xor, Size::Dword, R11, 1);
    asm.alu(Alu::And, Size::Dword, Rcx, R11);
    asm.shift_imm(
        ShiftOp::Shl,
        Size::Dword,
        Rcx,
        V_FLAG.trailing_zeros() as u8,
    );
    asm.alu(Alu::Or, Size::Dword, Rax, Rcx);
    asm.mov_store(Size::Dword, Mem::base_disp32(Rdi, NZCV_OFFSET as i32), Rax);
}

/// Emit a complete P/PP prefix or suffix from the clamped R8D element count.
/// R8 survives; packed physical chunks need not align to a pair's global64 bits.
fn write_counted(
    code: &mut Code,
    destination: Destination,
    element: ElementSize,
    length: VectorLength,
    suffix: bool,
    capacity: u32,
) {
    let (first, vectors) = match destination {
        Destination::Predicate(register) => (register, 1),
        Destination::Pair(register) => (register, 2),
        Destination::Counter { .. } => unreachable!("counter uses architectural encoding"),
    };
    if suffix {
        let mut asm = code.asm();
        asm.mov_imm32(R9, capacity);
        asm.alu(Alu::Sub, Size::Dword, R9, R8);
    } else {
        code.asm().mov(Size::Dword, R9, R8);
    }
    let shift = element.bytes().trailing_zeros() as u8;
    if shift != 0 {
        code.asm().shift_imm(ShiftOp::Shl, Size::Dword, R9, shift);
    }
    for vector in 0..vectors {
        for chunk in 0..chunks(length) {
            let start = vector * length.bytes() + chunk * CHUNK_BITS;
            let width = (length.bytes() - chunk * CHUNK_BITS).min(CHUNK_BITS);
            let mut asm = code.asm();
            asm.alu_imm32(Alu::Cmp, Size::Dword, R9, start as i32);
            let low = asm.jcc(Cond::Be);
            asm.alu_imm32(Alu::Cmp, Size::Dword, R9, (start + width) as i32);
            let high = asm.jcc(Cond::Ae);
            asm.mov(Size::Dword, Rcx, R9);
            asm.alu_imm32(Alu::Sub, Size::Dword, Rcx, start as i32);
            constant(code, 1);
            let mut asm = code.asm();
            asm.shift_cl(ShiftOp::Shl, Size::Qword, Rax);
            asm.dec(Size::Qword, Rax);
            if suffix {
                asm.unary(Unary::Not, Size::Qword, Rax);
            }
            let partial = asm.jmp();
            asm.bind(low);
            constant(code, if suffix { u64::MAX } else { 0 });
            let low_ready = code.asm().jmp();
            code.asm().bind(high);
            constant(code, if suffix { 0 } else { u64::MAX });
            let mut asm = code.asm();
            asm.bind(partial);
            asm.bind(low_ready);
            asm.mov_imm64(R11, marker_mask(element));
            asm.alu(Alu::And, Size::Qword, Rax, R11);
            write_predicate_chunk(code, first + vector as u8, chunk, length);
        }
    }
}

mod breaks {
    //! Predicate BRK* forms with alias-safe SSE2 staging and BMI1 cores.
    //!
    //! Only packed P storage is accessed. RDI/R15 and the host stack survive.
    //! Results use XMM0-3; flag-setting forms other than BRKN keep Pg in
    //! XMM4-7.
    use crate::x86_64::asm::Gpr::{R8, R9, R10, R11, Rax, Rcx};
    use crate::x86_64::asm::{Alu, Code, Cond, Mem, Size, Unary};

    use crate::aarch64::scalable::{ElementSize, VectorLength};
    use crate::aarch64::sve::predicate_generation::{Boundary, BreakKind, BreakOperand};
    use crate::x86_64::scalable::{read_predicate_chunk, write_predicate_chunk};
    use crate::x86_64::sve::predicate;
    use alloc::vec::Vec;

    use crate::TargetCpu;

    const QWORD_BYTES: usize = core::mem::size_of::<u64>();
    const BITS_PER_BYTE: usize = u8::BITS as usize;
    const ORIGINAL_GUARD_XMM_BASE: usize = 4;
    const ALL_BITS: i32 = -1;

    fn stage(code: &mut Code, xmm: usize) {
        code.asm().movq_to_xmm(xmm as u8, Rax);
    }

    fn restore(code: &mut Code, xmm: usize) {
        code.asm().movq_from_xmm(Rax, xmm as u8);
    }

    /// R10=-1 iff Pn at the last active Pg bit is one; otherwise R10=0.
    /// Read all selection inputs before any result is committed. BSR is never
    /// consumed on zero. Scalable storage reads preserve RCX and R10.
    fn last_active(code: &mut Code, guard: u8, source: u8, length: VectorLength) {
        let chunks = length.predicate_bytes().div_ceil(QWORD_BYTES);
        code.asm().alu(Alu::Xor, Size::Dword, R10, R10);
        let mut completed = Vec::with_capacity(chunks);
        for chunk in (0..chunks).rev() {
            read_predicate_chunk(code, guard, chunk, length);
            let mut asm = code.asm();
            asm.test(Size::Qword, Rax, Rax);
            let absent = asm.jcc(Cond::E);
            asm.bsr(Size::Qword, Rcx, Rax);
            read_predicate_chunk(code, source, chunk, length);
            let mut asm = code.asm();
            asm.bt(Size::Qword, Rax, Rcx);
            asm.alu(Alu::Sbb, Size::Qword, R10, R10);
            completed.push(asm.jmp());
            asm.bind(absent);
        }
        let mut asm = code.asm();
        for done in completed {
            asm.bind(done);
        }
    }

    fn all_chunk_bits(code: &mut Code, chunk: usize, length: VectorLength) {
        let bytes = (length.predicate_bytes() - chunk * QWORD_BYTES).min(QWORD_BYTES);
        if bytes == QWORD_BYTES {
            code.asm().mov_rm_imm32(Size::Qword, R11, ALL_BITS);
        } else {
            // Full physical tail width matters to BRKNS's C flag.
            let bits = bytes * BITS_PER_BYTE;
            code.asm().mov_imm64(R11, (1_u64 << bits) - 1);
        }
    }

    pub(crate) fn emit_break(
        code: &mut Code,
        operand: BreakOperand,
        length: VectorLength,
        target: TargetCpu,
    ) {
        let chunks = length.predicate_bytes().div_ceil(QWORD_BYTES);
        debug_assert!(chunks <= ORIGINAL_GUARD_XMM_BASE);
        let (boundary, merging, breaking) = match operand.kind {
            BreakKind::Break { boundary, merging } => {
                code.asm().mov_rm_imm32(Size::Qword, R10, ALL_BITS);
                (Some(boundary), merging, operand.source)
            }
            BreakKind::Previous { boundary, source } => {
                last_active(code, operand.guard, operand.source, length);
                (Some(boundary), false, source)
            }
            BreakKind::Next => {
                last_active(code, operand.guard, operand.source, length);
                (None, false, operand.destination)
            }
        };
        for chunk in 0..chunks {
            if let Some(boundary) = boundary {
                read_predicate_chunk(code, operand.guard, chunk, length);
                if operand.set_flags {
                    stage(code, ORIGINAL_GUARD_XMM_BASE + chunk);
                }
                code.asm().mov(Size::Qword, R8, Rax);
                read_predicate_chunk(code, breaking, chunk, length);
                let mut asm = code.asm();
                asm.alu(Alu::And, Size::Qword, Rax, R8);
                asm.mov(Size::Qword, R9, Rax);
                match boundary {
                    Boundary::After if target.supports(TargetCpu::Bmi1) => {
                        asm.blsmsk(Size::Qword, Rax, R9);
                    }
                    Boundary::Before if target.supports(TargetCpu::Bmi1) => {
                        asm.blsi(Size::Qword, Rax, R9);
                        asm.dec(Size::Qword, Rax);
                    }
                    Boundary::After => {
                        asm.lea(Size::Qword, Rax, Mem::base_disp8(R9, -1));
                        asm.alu(Alu::Xor, Size::Qword, Rax, R9);
                    }
                    Boundary::Before => {
                        asm.lea(Size::Qword, Rax, Mem::base_disp8(R9, -1));
                        asm.mov(Size::Qword, R11, R9);
                        asm.unary(Unary::Not, Size::Qword, R11);
                        asm.alu(Alu::And, Size::Qword, Rax, R11);
                    }
                }
                asm.alu(Alu::And, Size::Qword, Rax, R8);
                asm.alu(Alu::And, Size::Qword, Rax, R10);
                if merging {
                    code.asm().mov(Size::Qword, R11, Rax);
                    read_predicate_chunk(code, operand.destination, chunk, length);
                    let mut asm = code.asm();
                    asm.unary(Unary::Not, Size::Qword, R8);
                    asm.alu(Alu::And, Size::Qword, Rax, R8);
                    asm.alu(Alu::Or, Size::Qword, Rax, R11);
                }
                stage(code, chunk);
                let mut asm = code.asm();
                asm.alu_imm8(Alu::Cmp, Size::Qword, R9, 1);
                asm.alu(Alu::Sbb, Size::Qword, R11, R11);
                asm.alu(Alu::And, Size::Qword, R10, R11);
            } else {
                read_predicate_chunk(code, operand.destination, chunk, length);
                code.asm().alu(Alu::And, Size::Qword, Rax, R10);
                stage(code, chunk);
            }
        }
        // Every input and alias has been consumed before the first write.
        for chunk in 0..chunks {
            restore(code, chunk);
            write_predicate_chunk(code, operand.destination, chunk, length);
        }
        if operand.set_flags {
            predicate::begin_predtest(code);
            for chunk in 0..chunks {
                if boundary.is_some() {
                    restore(code, ORIGINAL_GUARD_XMM_BASE + chunk);
                    code.asm().mov(Size::Qword, R11, Rax);
                } else {
                    all_chunk_bits(code, chunk, length);
                }
                restore(code, chunk);
                predicate::accumulate_predtest(code, ElementSize::Byte);
            }
            predicate::finish_predtest(code);
        }
    }
}

mod whiles {
    //! Baseline WHILE count and PN emission. Parent owns the P/PP chunk writer.
    //!
    //! Count is retained in R8D across state helpers; RAX/RCX/RDX are scratch.
    //! No callee-saved register is used. Scalar inputs are read before guest writes.
    use crate::x86_64::asm::Gpr::{R8, Rax, Rcx, Rdi, Rdx};
    use crate::x86_64::asm::{Alu, Code, Cond, Mem, ShiftOp, Size, Unary};

    use crate::{
        GuestState,
        aarch64::{
            Register, Width,
            scalable::{ElementSize, VectorLength},
            sve::predicate_generation::{Comparison, Destination, WhileOperand},
        },
        x86_64::{
            offset,
            scalable::{write_predicate_chunk, zero_predicate},
        },
    };

    const GPR_BYTES: usize = core::mem::size_of::<u64>();
    const NZCV_OFFSET: u32 = core::mem::offset_of!(GuestState, nzcv) as u32;
    const NZCV_STATE_SHIFT: u8 = 28;
    const N_NIBBLE: u32 = 8;
    const C_NIBBLE: u32 = 2;
    const ASCENDING_PARTIAL_FLAGS: u32 = N_NIBBLE | C_NIBBLE;
    const N_NIBBLE_SHIFT: u8 = 3;
    const Z_NIBBLE_SHIFT: u8 = 2;
    const PN_INVERT_BIT: u32 = 1 << 15;
    const PN_COUNT_SCALE_SHIFT: u32 = 1;

    fn scalar(code: &mut Code, source: Register, width: Width, signed: bool, first: bool) {
        let destination = if first { Rax } else { Rcx };
        let mut asm = code.asm();
        if source == Register::Zero {
            asm.alu(Alu::Xor, Size::Dword, destination, destination);
            return;
        }
        debug_assert!(matches!(source, Register::X(_)));
        let state = Mem::base_disp32(
            Rdi,
            offset(source).expect("WHILE scalar source is GPR") as i32,
        );
        match (width, signed) {
            (Width::X64, _) => asm.mov_load(Size::Qword, destination, state),
            (Width::W32, false) => asm.mov_load(Size::Dword, destination, state),
            (Width::W32, true) => asm.movsxd(destination, state),
        }
    }

    fn descending(comparison: Comparison) -> bool {
        matches!(
            comparison,
            Comparison::SignedGe
                | Comparison::SignedGt
                | Comparison::UnsignedGe
                | Comparison::UnsignedGt
        )
    }

    fn signed(comparison: Comparison) -> bool {
        matches!(
            comparison,
            Comparison::SignedLt
                | Comparison::SignedLe
                | Comparison::SignedGe
                | Comparison::SignedGt
        )
    }

    fn inclusive(comparison: Comparison) -> bool {
        matches!(
            comparison,
            Comparison::SignedLe
                | Comparison::SignedGe
                | Comparison::UnsignedLe
                | Comparison::UnsignedGe
        )
    }

    fn failed_condition(comparison: Comparison) -> Cond {
        match comparison {
            Comparison::SignedLt => Cond::Ge,
            Comparison::SignedLe => Cond::G,
            Comparison::SignedGe => Cond::L,
            Comparison::SignedGt => Cond::Le,
            Comparison::UnsignedLt => Cond::Ae,
            Comparison::UnsignedLe => Cond::A,
            Comparison::UnsignedGe => Cond::B,
            Comparison::UnsignedGt => Cond::Be,
            _ => unreachable!("address distance has its own count mapping"),
        }
    }

    /// Compare RCX to the inclusive bound covering the entire modular domain.
    fn endpoint_compare(code: &mut Code, comparison: Comparison, width: Width) {
        if comparison == Comparison::UnsignedGe {
            code.asm().test(Size::Qword, Rcx, Rcx);
        } else if comparison == Comparison::UnsignedLe && width == Width::X64 {
            code.asm().alu_imm8(Alu::Cmp, Size::Qword, Rcx, -1);
        } else if width == Width::W32 {
            let endpoint = match comparison {
                Comparison::SignedLe => i32::MAX as u32,
                Comparison::SignedGe => i32::MIN as u32,
                Comparison::UnsignedLe => u32::MAX,
                _ => unreachable!("inclusive comparison"),
            };
            code.asm()
                .alu_imm32(Alu::Cmp, Size::Dword, Rcx, endpoint as i32);
        } else {
            let endpoint = if comparison == Comparison::SignedLe {
                i64::MAX as u64
            } else {
                i64::MIN as u64
            };
            let mut asm = code.asm();
            asm.mov_imm64(Rdx, endpoint);
            asm.alu(Alu::Cmp, Size::Qword, Rcx, Rdx);
        }
    }

    fn clamped_distance(code: &mut Code, capacity: u32, add_one: bool) {
        // The unsigned distance can be UINT64_MAX even for signed64 operands.
        // Clamp BEFORE increment, so inclusive full-domain distance cannot overflow.
        let mut asm = code.asm();
        asm.mov_imm32(Rdx, capacity - u32::from(add_one));
        asm.alu(Alu::Cmp, Size::Qword, Rax, Rdx);
        asm.cmov(Cond::A, Size::Qword, Rax, Rdx);
        if add_one {
            asm.lea(Size::Dword, R8, Mem::base_disp8(Rax, 1));
        } else {
            asm.mov(Size::Dword, R8, Rax);
        }
    }

    fn comparison_count(code: &mut Code, operand: &WhileOperand, capacity: u32) {
        let add_one = inclusive(operand.comparison);
        if operand.first == operand.limit {
            if !add_one {
                code.asm().alu(Alu::Xor, Size::Dword, R8, R8);
            } else {
                // Equal inputs produce one active element except at the inclusive
                // domain endpoint, where comparison remains true across scalar wrap.
                scalar(
                    code,
                    operand.limit,
                    operand.width,
                    signed(operand.comparison),
                    false,
                );
                code.asm().mov_imm32(R8, 1);
                endpoint_compare(code, operand.comparison, operand.width);
                let mut asm = code.asm();
                asm.mov_imm32(Rdx, capacity);
                asm.cmov(Cond::E, Size::Dword, R8, Rdx);
            }
            return;
        }
        scalar(
            code,
            operand.first,
            operand.width,
            signed(operand.comparison),
            true,
        );
        scalar(
            code,
            operand.limit,
            operand.width,
            signed(operand.comparison),
            false,
        );
        let endpoint = if add_one {
            code.asm().mov_imm32(R8, capacity);
            endpoint_compare(code, operand.comparison, operand.width);
            Some(code.asm().jcc(Cond::E))
        } else {
            None
        };
        let mut asm = code.asm();
        asm.alu(Alu::Xor, Size::Dword, R8, R8);
        asm.alu(Alu::Cmp, Size::Qword, Rax, Rcx);
        let failed = asm.jcc(failed_condition(operand.comparison));
        if descending(operand.comparison) {
            asm.alu(Alu::Sub, Size::Qword, Rax, Rcx);
        } else {
            asm.alu(Alu::Sub, Size::Qword, Rcx, Rax);
            asm.mov(Size::Qword, Rax, Rcx);
        }
        clamped_distance(code, capacity, add_one);
        let mut asm = code.asm();
        asm.bind(failed);
        if let Some(endpoint) = endpoint {
            asm.bind(endpoint);
        }
    }

    fn address_count(code: &mut Code, operand: &WhileOperand, capacity: u32) {
        code.asm().mov_imm32(R8, capacity);
        if operand.first == operand.limit {
            return;
        }
        scalar(code, operand.first, Width::X64, false, true);
        scalar(code, operand.limit, Width::X64, false, false);
        let mut asm = code.asm();
        let backward = if operand.comparison == Comparison::WriteReadDistance {
            asm.alu(Alu::Cmp, Size::Qword, Rcx, Rax);
            let backward = asm.jcc(Cond::Be);
            asm.alu(Alu::Sub, Size::Qword, Rcx, Rax);
            asm.mov(Size::Qword, Rax, Rcx);
            Some(backward)
        } else {
            // A borrowed unsigned subtraction followed by NEG recovers abs(a-b),
            // including differences above INT64_MAX; signed ABS would be incorrect.
            asm.alu(Alu::Sub, Size::Qword, Rax, Rcx);
            let borrowed = asm.jcc8(Cond::Ae);
            asm.unary(Unary::Neg, Size::Qword, Rax);
            asm.bind(borrowed);
            None
        };
        let divisor_shift = operand.element.bytes().trailing_zeros() as u8;
        if divisor_shift != 0 {
            asm.shift_imm(ShiftOp::Shr, Size::Qword, Rax, divisor_shift);
        }
        asm.test(Size::Qword, Rax, Rax);
        let unrestricted = asm.jcc(Cond::E);
        clamped_distance(code, capacity, false);
        let mut asm = code.asm();
        asm.bind(unrestricted);
        if let Some(backward) = backward {
            asm.bind(backward);
        }
    }

    fn count_flags(code: &mut Code, capacity: u32, suffix: bool) {
        let mut asm = code.asm();
        asm.alu_imm32(Alu::Cmp, Size::Dword, R8, capacity as i32);
        asm.setcc(Cond::E, Rcx);
        asm.test(Size::Dword, R8, R8);
        asm.setcc(Cond::E, Rdx);
        asm.movzx(Size::Dword, Rcx, Size::Byte, Rcx);
        asm.movzx(Size::Dword, Rdx, Size::Byte, Rdx);
        if suffix {
            // nibble = 8*full + 6*none; partial suffix has nibble0.
            asm.lea(Size::Dword, Rax, Mem::indexed(Rdx, Rdx, 2, 0));
            asm.alu(Alu::Add, Size::Dword, Rax, Rax);
            asm.shift_imm(ShiftOp::Shl, Size::Dword, Rcx, N_NIBBLE_SHIFT);
            asm.alu(Alu::Or, Size::Dword, Rax, Rcx);
        } else {
            // nibble = 10 - 4*none - 2*full.
            asm.mov_imm32(Rax, ASCENDING_PARTIAL_FLAGS);
            asm.shift_imm(ShiftOp::Shl, Size::Dword, Rdx, Z_NIBBLE_SHIFT);
            asm.alu(Alu::Sub, Size::Dword, Rax, Rdx);
            asm.alu(Alu::Add, Size::Dword, Rcx, Rcx);
            asm.alu(Alu::Sub, Size::Dword, Rax, Rcx);
        }
        asm.shift_imm(ShiftOp::Shl, Size::Dword, Rax, NZCV_STATE_SHIFT);
        asm.mov_store(Size::Dword, Mem::base_disp32(Rdi, NZCV_OFFSET as i32), Rax);
    }

    fn counter(
        code: &mut Code,
        destination: u8,
        element: ElementSize,
        length: VectorLength,
        capacity: u32,
        suffix: bool,
    ) {
        let single_chunk = length.predicate_bytes() <= GPR_BYTES;
        if single_chunk {
            code.asm().alu(Alu::Xor, Size::Dword, Rax, Rax);
        } else {
            zero_predicate(code, destination, length);
        }
        let mut asm = code.asm();
        asm.test(Size::Dword, R8, R8);
        let empty = asm.jcc(Cond::E);
        let tag = element.bytes() as u32;
        let shift = (element.bytes().trailing_zeros() + PN_COUNT_SCALE_SHIFT) as u8;
        if suffix {
            asm.mov_imm32(Rax, capacity);
            asm.alu(Alu::Sub, Size::Dword, Rax, R8);
            asm.shift_imm(ShiftOp::Shl, Size::Dword, Rax, shift);
            asm.alu_accumulator_imm32(Alu::Or, Size::Dword, (PN_INVERT_BIT | tag) as i32);
        } else {
            asm.alu_imm32(Alu::Cmp, Size::Dword, R8, capacity as i32);
            let full = asm.jcc(Cond::E);
            asm.mov(Size::Dword, Rax, R8);
            asm.shift_imm(ShiftOp::Shl, Size::Dword, Rax, shift);
            asm.alu_accumulator_imm32(Alu::Or, Size::Dword, tag as i32);
            let encoded = asm.jmp();
            asm.bind(full);
            asm.mov_imm32(Rax, PN_INVERT_BIT | tag);
            asm.bind(encoded);
        }
        if single_chunk {
            asm.bind(empty);
            write_predicate_chunk(code, destination, 0, length);
        } else {
            write_predicate_chunk(code, destination, 0, length);
            code.asm().bind(empty);
        }
    }

    /// Parent callback emits the complete prefix/suffix P or PP write from R8D.
    /// It must preserve R8D. `capacity` spans both destinations for a pair.
    pub(super) fn emit_while(
        code: &mut Code,
        operand: &WhileOperand,
        length: VectorLength,
        write_counted: impl FnOnce(&mut Code, Destination, ElementSize, VectorLength, bool, u32),
    ) {
        debug_assert!(operand.element.bytes() <= GPR_BYTES);
        let vectors = match operand.destination {
            Destination::Predicate(_) => 1,
            Destination::Pair(_) => 2,
            Destination::Counter { vectors, .. } => usize::from(vectors),
        };
        let capacity = (length.lanes(operand.element) * vectors) as u32;
        let suffix = descending(operand.comparison);
        if matches!(
            operand.comparison,
            Comparison::ReadWriteDistance | Comparison::WriteReadDistance
        ) {
            address_count(code, operand, capacity);
        } else {
            comparison_count(code, operand, capacity);
        }
        count_flags(code, capacity, suffix);
        if let Destination::Counter { register, .. } = operand.destination {
            counter(code, register, operand.element, length, capacity, suffix);
        } else {
            write_counted(
                code,
                operand.destination,
                operand.element,
                length,
                suffix,
                capacity,
            );
        }
    }
}

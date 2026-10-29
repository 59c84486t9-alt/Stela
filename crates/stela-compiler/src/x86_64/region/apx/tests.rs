//! APX residency, admission boundaries and differential native execution.
use super::*;
use crate::GuestAddress;
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
use alloc::vec;

fn prefix(instructions: &[Instruction]) -> Result<Option<OptimizedRegion>, RegionError> {
    super::prefix(instructions, crate::TargetCpu::Apx)
}

fn inputs(operations: impl IntoIterator<Item = Operation>) -> Vec<Instruction> {
    operations
        .into_iter()
        .enumerate()
        .map(|(i, operation)| Instruction {
            pc: GuestAddress(0x1000 + i as u64 * 4),
            operation,
        })
        .collect()
}
fn add(destination: Register, source: Register, flags: bool) -> Operation {
    Operation::AddSub {
        width: Width::X64,
        subtract: false,
        flags,
        destination,
        source,
        immediate: 3,
    }
}

#[test]
fn full_guest_bank_uses_every_integer_register_except_the_stack_pointer() {
    let registers: Vec<_> = (0..31).map(resident).collect();
    for number in 0..32 {
        assert_eq!(registers.contains(&Gpr::from_encoding(number)), number != 4);
    }
}

#[test]
fn memory_flags_and_sp_end_the_span_without_claiming_fault_recovery() {
    let ordinary = add(Register::X(0), Register::X(0), false);
    let memory = Operation::Memory {
        transfer: crate::aarch64::MemoryTransfer::Load {
            signed: false,
            width: Width::X64,
        },
        bytes: 8,
        data: Register::X(0),
        base: Register::X(1),
        displacement: 0,
        mode: crate::aarch64::AddressMode::Offset,
    };
    for boundary in [
        memory,
        add(Register::X(0), Register::X(0), true),
        add(Register::Sp, Register::Sp, false),
    ] {
        let region = prefix(&inputs([ordinary.clone(), ordinary.clone(), boundary]))
            .unwrap()
            .unwrap();
        assert_eq!(region.consumed_instructions, 2);
        assert_eq!(region.stats.peak_resident, 31);
        assert!(region.fault_recovery.is_empty());
    }
    assert_eq!(
        prefix(&[Instruction {
            pc: GuestAddress(1),
            operation: ordinary.clone()
        }]),
        Err(RegionError::Misaligned)
    );
    let mut input = inputs([ordinary.clone(), ordinary]);
    input[1].pc.0 += 4;
    assert_eq!(prefix(&input), Err(RegionError::NonContiguous));
}

#[test]
fn production_keeps_apx_disabled_pending_interrupt_preservation() {
    let input = inputs((0..128).map(|i| add(Register::X(i % 31), Register::X(i % 31), false)));
    let plain = crate::x86_64::block::emit_ordinary_for_target(
        &input,
        None,
        GuestAddress(0x1200),
        crate::TargetCpu::Baseline,
    );
    let apx = crate::x86_64::block::emit_ordinary_for_target(
        &input,
        None,
        GuestAddress(0x1200),
        crate::TargetCpu::Apx,
    );
    assert_eq!(plain.x86_64_code, apx.x86_64_code);
    let timed = crate::x86_64::block::emit_ordinary_for_target(
        &input,
        None,
        GuestAddress(0x1200),
        crate::TargetCpu::Baseline.with_data_independent_timing(),
    );
    let timed_apx = crate::x86_64::block::emit_ordinary_for_target(
        &input,
        None,
        GuestAddress(0x1200),
        crate::TargetCpu::Apx.with_data_independent_timing(),
    );
    assert_eq!(timed.x86_64_code, timed_apx.x86_64_code);
    assert_eq!(
        plain
            .source_map
            .iter()
            .map(|(pc, _)| pc)
            .collect::<Vec<_>>(),
        apx.source_map.iter().map(|(pc, _)| pc).collect::<Vec<_>>()
    );
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[test]
fn emitted_apx_bank_matches_baseline_for_aliases_zero_widths_and_scratch_borrows() {
    if !crate::TargetCpu::detect().supports(crate::TargetCpu::Apx) {
        std::eprintln!("APX execution unavailable on this host");
        return;
    }
    let mut cases = 0;
    for width in [Width::W32, Width::X64] {
        for guest in 0..31 {
            let destination = Register::X(guest);
            for (left, right) in [
                (destination, destination),
                (Register::X((guest + 1) % 31), destination),
                (destination, Register::X((guest + 1) % 31)),
                (Register::X((guest + 1) % 31), Register::X((guest + 2) % 31)),
                (Register::Zero, destination),
                (destination, Register::Zero),
            ] {
                let operations = [
                    Operation::AddSubRegister {
                        width,
                        subtract: false,
                        flags: false,
                        destination,
                        left,
                        right,
                        shift: Shift::Lsl,
                        amount: 0,
                    },
                    Operation::AddSubRegister {
                        width,
                        subtract: true,
                        flags: false,
                        destination,
                        left,
                        right,
                        shift: Shift::Asr,
                        amount: if width == Width::W32 { 31 } else { 63 },
                    },
                    Operation::LogicalRegister {
                        width,
                        kind: Logical::Xor,
                        invert: true,
                        flags: false,
                        destination,
                        left,
                        right,
                        shift: Shift::Ror,
                        amount: 7,
                    },
                    Operation::LogicalImmediate {
                        width,
                        kind: Logical::And,
                        flags: false,
                        destination,
                        source: left,
                        immediate: 0x80ff_1122_3344_aa55,
                    },
                    Operation::MoveWide {
                        width,
                        kind: WideMove::Keep,
                        destination,
                        immediate: 0x1234,
                        shift: if width == Width::W32 { 16 } else { 48 },
                    },
                ];
                for operation in operations {
                    let input = inputs([operation, Operation::Nop]);
                    let region = prefix(&input).unwrap().unwrap();
                    let mut baseline = Code::new();
                    let mut fixups = vec![];
                    for instruction in &input {
                        crate::x86_64::emit_instruction(
                            &mut baseline,
                            instruction,
                            &mut fixups,
                            crate::TargetCpu::Baseline,
                            crate::x86_64::MemoryChecks::DEFAULT,
                        );
                    }
                    assert!(fixups.is_empty());
                    let mut expected = crate::GuestState {
                        x: core::array::from_fn(|i| {
                            0x80ff_ff11_7788_2233_u64.wrapping_mul(i as u64 + 1)
                        }),
                        sp: 0xdead_beef,
                        nzcv: 0xa0000000,
                        fpcr: 0x1234,
                        fpsr: 0x5678,
                        ..crate::GuestState::default()
                    };
                    let mut actual = expected.clone();
                    crate::x86_64::native::run(&baseline, &mut expected);
                    crate::x86_64::native::run(&region.code, &mut actual);
                    assert_eq!(
                        actual, expected,
                        "{width:?} guest{guest} left{left:?} right{right:?}"
                    );
                    cases += 1;
                }
            }
        }
    }
    std::eprintln!("APX differential execution completed for {cases} cases");
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[test]
fn apx_span_restores_callee_registers_context_and_stack() {
    if !crate::TargetCpu::detect().supports(crate::TargetCpu::Apx) {
        std::eprintln!("APX execution unavailable on this host");
        return;
    }
    let input = inputs([
        add(Register::X(0), Register::X(0), false),
        add(Register::X(0), Register::X(0), false),
    ]);
    let region = prefix(&input).unwrap().unwrap();
    let mut code = Code::new();
    {
        let mut a = code.asm();
        for saved in SAVED {
            a.push(saved);
        }
        a.reserve_stack(16);
        a.mov_store(Size::Qword, stack(0), Gpr::Rsi);
        a.mov_store(Size::Qword, stack(8), Gpr::Rsp);
        for (i, saved) in SAVED.into_iter().enumerate() {
            a.mov_imm64(saved, 0xaabb_ccdd_eeff_0000 + i as u64);
        }
    }
    code.append(region.code);
    {
        let mut a = code.asm();
        let vectors = core::mem::offset_of!(crate::GuestState, v) as i32;
        for (i, saved) in SAVED.into_iter().enumerate() {
            a.mov_store(
                Size::Qword,
                Mem::base(Gpr::Rdi, vectors + i as i32 * 8),
                saved,
            );
        }
        a.mov_load(Size::Qword, Gpr::Rax, stack(8));
        a.mov(Size::Qword, Gpr::Rdx, Gpr::Rsp);
        a.alu(Alu::Sub, Size::Qword, Gpr::Rdx, Gpr::Rax);
        a.mov_store(Size::Qword, Mem::base(Gpr::Rdi, vectors + 64), Gpr::Rdx);
        a.mov_load(Size::Qword, Gpr::Rax, stack(0));
        a.mov(Size::Qword, Gpr::Rdx, Gpr::Rsi);
        a.alu(Alu::Sub, Size::Qword, Gpr::Rdx, Gpr::Rax);
        a.mov_store(Size::Qword, Mem::base(Gpr::Rdi, vectors + 72), Gpr::Rdx);
        a.release_stack(16);
        for saved in SAVED.into_iter().rev() {
            a.pop(saved);
        }
        a.ret();
    }
    let mut state = crate::GuestState::default();
    let mut context = crate::context::ExecutionContext::default();
    crate::x86_64::asm::vector_extensions::execution::Native::new(&code)
        .run(&mut state, &mut context);
    assert_eq!(state.x[0], 6);
    for i in 0..8 {
        assert_eq!(state.v[i / 2][i % 2], 0xaabb_ccdd_eeff_0000 + i as u64);
    }
    assert_eq!(
        state.v[4],
        [0, 0],
        "private stack and invocation pointer restored"
    );
    std::eprintln!("APX callee, frame, context and stack restoration executed");
}

#[test]
fn ndd_candidate_requires_its_separate_capability_and_declines_dit() {
    let input = inputs([
        Operation::AddSubRegister {
            width: Width::X64,
            subtract: false,
            flags: false,
            destination: Register::X(1),
            left: Register::X(2),
            right: Register::X(3),
            shift: Shift::Lsl,
            amount: 0,
        },
        Operation::Nop,
    ]);
    for target in [
        crate::TargetCpu::Baseline,
        crate::TargetCpu::ApxNdd,
        crate::TargetCpu::Apx
            .with_apx_ndd()
            .with_data_independent_timing(),
    ] {
        assert!(super::prefix(&input, target).unwrap().is_none());
    }
    let foundation = prefix(&input).unwrap().unwrap();
    let ndd = super::prefix(&input, crate::TargetCpu::Apx.with_apx_ndd())
        .unwrap()
        .unwrap();
    assert_eq!(foundation.code.instructions(), ndd.code.instructions() + 1);
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[test]
fn ndd_candidate_matches_foundation_for_every_guest_destination_and_alias() {
    let target = crate::TargetCpu::Apx.with_apx_ndd();
    if !crate::TargetCpu::detect().supports(target) {
        std::eprintln!("APX NDD/NF execution unavailable on this host");
        return;
    }
    let mut cases = 0;
    for width in [Width::W32, Width::X64] {
        for guest in 0..31 {
            let destination = Register::X(guest);
            for (left, right) in [
                (destination, destination),
                (Register::X((guest + 1) % 31), destination),
                (destination, Register::X((guest + 1) % 31)),
                (Register::X((guest + 1) % 31), Register::X((guest + 2) % 31)),
                (Register::Zero, destination),
                (destination, Register::Zero),
            ] {
                for kind in 0..5 {
                    let operation = if kind < 2 {
                        Operation::AddSubRegister {
                            width,
                            subtract: kind != 0,
                            flags: false,
                            destination,
                            left,
                            right,
                            shift: Shift::Lsl,
                            amount: 0,
                        }
                    } else {
                        Operation::LogicalRegister {
                            width,
                            kind: [Logical::And, Logical::Or, Logical::Xor][kind - 2],
                            invert: false,
                            flags: false,
                            destination,
                            left,
                            right,
                            shift: Shift::Lsl,
                            amount: 0,
                        }
                    };
                    let input = inputs([operation, Operation::Nop]);
                    let foundation = prefix(&input).unwrap().unwrap();
                    let ndd = super::prefix(&input, target).unwrap().unwrap();
                    let mut expected = crate::GuestState {
                        x: core::array::from_fn(|i| {
                            0x80ff_1199_aabb_ccdd_u64.wrapping_mul(i as u64 + 1)
                        }),
                        nzcv: 0xf0000000,
                        sp: 0xfeed_1234,
                        ..crate::GuestState::default()
                    };
                    let mut actual = expected.clone();
                    crate::x86_64::native::run(&foundation.code, &mut expected);
                    crate::x86_64::native::run(&ndd.code, &mut actual);
                    assert_eq!(
                        actual, expected,
                        "{width:?} guest{guest} kind{kind} left{left:?} right{right:?}"
                    );
                    cases += 1;
                }
            }
        }
    }
    std::eprintln!("APX NDD/NF differential execution completed for {cases} cases");
}

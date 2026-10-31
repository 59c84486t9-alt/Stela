#[cfg(target_arch = "x86_64")]
use super::services::complete_pauth;
use super::*;
use anyhow::Result;
use stela_compiler::{
    GuestState,
    block::{
        PointerAuthentication, PointerAuthenticationKey, PointerAuthenticationModifier,
        decode_clock_instruction, decode_pointer_authentication, decode_trap,
    },
};

#[cfg(target_arch = "x86_64")]
mod basic_pauth {
    use super::*;

    const BASE: GuestAddress = GuestAddress(0x4000);
    const STOP: GuestAddress = GuestAddress(0x5000);

    fn full_context() -> pauth::Context {
        pauth::Context::new(9, pauth::Keys::from_words([1, 2], [3, 4], [5, 6], [7, 8]))
    }

    fn initial(flags: u32) -> ThreadState {
        ThreadState {
            pc: BASE,
            registers: GuestState {
                x: core::array::from_fn(|i| 0x123456789abcdef0u64.rotate_left(i as u32)),
                sp: 0x70000010000,
                nzcv: flags << 28,
                exclusive_bytes: 0xc31a7e29,
                exclusive_address: 0,
                exclusive_value: 0,
                daif: 0,
                pending: 0,
                v: core::array::from_fn(|i| {
                    [
                        0x0123456789abcdefu64.rotate_left(i as u32),
                        0xfedcba9876543210u64.rotate_right(i as u32),
                    ]
                }),
                fpcr: 0x03c00000,
                fpsr: 0x0800001f,
            },
        }
    }

    fn runtime(cache: &std::path::Path, words: &[u32]) -> Result<BlockRuntime> {
        let mut vm = BlockRuntime::new_with_profile(
            9,
            cache.into(),
            BlockProfile::new(Features::POINTER_AUTHENTICATION),
        );
        vm.register_code(
            BASE,
            words.iter().flat_map(|word| word.to_le_bytes()).collect(),
        )?;
        Ok(vm)
    }

    #[test]
    fn all_basic_forms_preserve_full_state_across_native_helper_boundaries() -> Result<()> {
        let context = full_context();
        let cache = tempfile::tempdir()?;
        let fixed = [
            0xd503211f, 0xd503215f, 0xd503219f, 0xd50321df, 0xd503231f, 0xd503233f, 0xd503235f,
            0xd503237f, 0xd503239f, 0xd50323bf, 0xd50323df, 0xd50323ff, 0xd50320ff, 0xd65f0bff,
            0xd65f0fff, 0xdac143f1, 0xdac147f1,
        ];
        let integer = (0..8).flat_map(|op| {
            [
                0xdac10000 | (op << 10) | (16 << 5) | 17,
                0xdac123e0 | (op << 10) | 17,
            ]
        });
        let words: Vec<_> = fixed.into_iter().chain(integer).collect();
        assert_eq!(words.len(), 33);
        for word in words {
            let mut vm = runtime(cache.path(), &[0xd2800547, word, 0])?; // MOV X7,#42; helper; bad code
            let instruction =
                decode_pointer_authentication(GuestAddress(BASE.0 + 4), word)?.unwrap();
            for flags in 0..16 {
                let mut state = initial(flags);
                if instruction.operation.is_return() {
                    let key = runtime_pauth_key(instruction.operation.required_key().unwrap());
                    state.registers.x[30] = context.sign(key, STOP.0, state.registers.sp)?;
                }
                let mut expected = state.registers.clone();
                expected.x[7] = 42;
                let (next_pc, authenticated) =
                    complete_pauth(&context, &instruction, &mut expected)?;
                // SAFETY: only register operations and a typed helper, no guest RAM accesses.
                let outcome = unsafe { vm.run_with_pauth(&mut state, None, 1, &context)? };
                assert_eq!(state.registers, expected, "word {word:08x}, flags {flags}");
                assert_eq!(state.pc, next_pc);
                assert_eq!(outcome.reason, StopReason::BudgetExhausted);
                assert_eq!(outcome.pointer_authentication_events.len(), 1);
                assert_eq!(
                    outcome.pointer_authentication_events[0].instruction,
                    instruction
                );
                assert_eq!(
                    outcome.pointer_authentication_events[0].authenticated,
                    authenticated
                );
            }
        }
        Ok(())
    }

    #[test]
    fn register_modifiers_aliases_sp_zero_and_xzr_have_precise_effects() -> Result<()> {
        let context = full_context();
        for key in [
            PointerAuthenticationKey::Ia,
            PointerAuthenticationKey::Ib,
            PointerAuthenticationKey::Da,
            PointerAuthenticationKey::Db,
        ] {
            for destination in 0..32u8 {
                for modifier in [
                    PointerAuthenticationModifier::Register(0),
                    PointerAuthenticationModifier::Register(destination.min(30)),
                    PointerAuthenticationModifier::StackPointer,
                    PointerAuthenticationModifier::Zero,
                ] {
                    let input = initial(15).registers;
                    let original = if destination == 31 {
                        0
                    } else {
                        input.x[usize::from(destination)]
                    };
                    let modifier_value = match modifier {
                        PointerAuthenticationModifier::Register(index) => {
                            input.x[usize::from(index)]
                        }
                        PointerAuthenticationModifier::StackPointer => input.sp,
                        PointerAuthenticationModifier::Zero => 0,
                    };
                    for authenticate in [false, true] {
                        let operation = if authenticate {
                            PointerAuthenticationOperation::Authenticate {
                                key,
                                destination,
                                modifier,
                            }
                        } else {
                            PointerAuthenticationOperation::Sign {
                                key,
                                destination,
                                modifier,
                            }
                        };
                        let instruction = PointerAuthentication {
                            operation,
                            instruction_pc: BASE,
                            next_pc: GuestAddress(BASE.0 + 4),
                        };
                        let mut actual = input.clone();
                        let mut expected = input.clone();
                        let value = if authenticate {
                            context
                                .authenticate(runtime_pauth_key(key), original, modifier_value)?
                                .pointer
                        } else {
                            context.sign(runtime_pauth_key(key), original, modifier_value)?
                        };
                        if destination != 31 {
                            expected.x[usize::from(destination)] = value;
                        }
                        let (pc, _) = complete_pauth(&context, &instruction, &mut actual)?;
                        assert_eq!(actual, expected);
                        assert_eq!(pc, instruction.next_pc);
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn native_integer_pac_handles_alias_sp_and_zero_register_corners() -> Result<()> {
        let context = full_context();
        let cache = tempfile::tempdir()?;
        for opcode in 0..8u32 {
            for destination in [0, 16, 17, 30, 31] {
                for (rn, zero) in [(destination.min(30), false), (31, false), (31, true)] {
                    let word = 0xdac10000
                        | (opcode << 10)
                        | ((zero as u32) << 13)
                        | (rn << 5)
                        | destination;
                    let mut vm = runtime(cache.path(), &[word, 0])?;
                    let instruction = decode_pointer_authentication(BASE, word)?.unwrap();
                    let mut state = initial(15);
                    let mut expected = state.registers.clone();
                    let (next, authenticated) =
                        complete_pauth(&context, &instruction, &mut expected)?;
                    // SAFETY: exact register-only PAC/AUT helper, immutable code and no memory operand.
                    let outcome = unsafe { vm.run_with_pauth(&mut state, None, 1, &context)? };
                    assert_eq!(outcome.reason, StopReason::BudgetExhausted);
                    assert_eq!(state.registers, expected);
                    assert_eq!(state.pc, next);
                    assert_eq!(
                        outcome.pointer_authentication_events[0].authenticated,
                        authenticated
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn authenticated_calls_snapshot_aliases_link_before_poison_and_never_fetch_failure()
    -> Result<()> {
        let context = full_context();
        let cache = tempfile::tempdir()?;
        for key in [
            stela_contracts::pauth::Key::Ia,
            stela_contracts::pauth::Key::Ib,
        ] {
            for link in [false, true] {
                for (target, rm, zero) in [
                    (0, 1, false),
                    (30, 1, false),
                    (0, 30, false),
                    (30, 31, false),
                    (31, 31, true),
                ] {
                    let word = 0xd61f0800
                        | (u32::from(!zero) << 24)
                        | (u32::from(link) << 21)
                        | (u32::from(key == stela_contracts::pauth::Key::Ib) << 10)
                        | (target << 5)
                        | rm;
                    let mut vm = runtime(cache.path(), &[0x910004e7, word])?;
                    for flags in 0..16 {
                        for corrupt in [false, true] {
                            let mut state = initial(flags);
                            let modifier = if zero {
                                0
                            } else if rm == 31 {
                                state.registers.sp
                            } else {
                                state.registers.x[rm as usize]
                            };
                            if target != 31 {
                                state.registers.x[target as usize] = context
                                    .sign(key, STOP.0, modifier)?
                                    ^ if corrupt { 1 << 47 } else { 0 };
                            }
                            let pointer = if target == 31 {
                                0
                            } else {
                                state.registers.x[target as usize]
                            };
                            let result = context.authenticate(key, pointer, modifier)?;
                            let mut expected = state.registers.clone();
                            expected.x[7] = expected.x[7].wrapping_add(1);
                            if link {
                                expected.x[30] = BASE.0 + 8;
                            }
                            // SAFETY: register prefix and authenticated transfer only; the target is a stop sentinel.
                            let outcome = unsafe {
                                vm.run_with_pauth(
                                    &mut state,
                                    Some(GuestAddress(result.pointer)),
                                    1,
                                    &context,
                                )?
                            };
                            assert_eq!(state.registers, expected);
                            assert_eq!(state.pc, GuestAddress(result.pointer));
                            assert_eq!(outcome.blocks_executed, 1);
                            assert_eq!(
                                outcome.pointer_authentication_events[0].authenticated,
                                Some(result.authenticated)
                            );
                            if result.authenticated {
                                assert_eq!(outcome.reason, StopReason::StopAddress);
                            } else {
                                assert!(matches!(
                                    outcome.reason,
                                    StopReason::PointerAuthenticationPoisonedBranch { .. }
                                ));
                                let before = state.registers.clone();
                                let poisoned_pc = state.pc;
                                // SAFETY: noncanonical poisoned target is rejected before fetch or a matching stop sentinel.
                                let resumed = unsafe {
                                    vm.run_with_pauth(&mut state, Some(poisoned_pc), 1, &context)?
                                };
                                assert!(matches!(
                                    resumed.reason,
                                    StopReason::NoncanonicalInstructionTarget { .. }
                                ));
                                assert_eq!(resumed.blocks_executed, 0);
                                assert_eq!(state.registers, before);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn missing_key_stops_atomically_and_resumes_without_repeating_native_prefix() -> Result<()> {
        let ib_only = pauth::Context::new(9, pauth::Keys::from_ib_words(3, 4));
        let full = full_context();
        let cache = tempfile::tempdir()?;
        for (word, key) in [
            (0xdac10011, PointerAuthenticationKey::Ia),
            (0xdac10811, PointerAuthenticationKey::Da),
            (0xdac10c11, PointerAuthenticationKey::Db),
            (0xdac11011, PointerAuthenticationKey::Ia),
            (0xd65f0bff, PointerAuthenticationKey::Ia),
            (0xd73f0bdf, PointerAuthenticationKey::Ia), // BLRAA X30,SP
        ] {
            let mut vm = runtime(cache.path(), &[0x910004e7, word, 0])?; // ADD X7,X7,#1
            let mut state = initial(11);
            state.registers.x[30] =
                full.sign(stela_contracts::pauth::Key::Ia, STOP.0, state.registers.sp)?;
            let mut expected = state.registers.clone();
            expected.x[7] = expected.x[7].wrapping_add(1);
            // SAFETY: register prefix/helper only; missing key cannot touch guest RAM.
            let outcome = unsafe { vm.run_with_pauth(&mut state, None, 1, &ib_only)? };
            let instruction =
                decode_pointer_authentication(GuestAddress(BASE.0 + 4), word)?.unwrap();
            assert_eq!(
                outcome.reason,
                StopReason::PointerAuthenticationKeyUnavailable { instruction, key }
            );
            assert_eq!(state.registers, expected);
            assert_eq!(state.pc, instruction.instruction_pc);
            assert!(outcome.pointer_authentication_events.is_empty());
            let (next, _) = complete_pauth(&full, &instruction, &mut expected)?;
            // SAFETY: same immutable register-only helper with all requested keys.
            let resumed = unsafe { vm.run_with_pauth(&mut state, None, 1, &full)? };
            assert_eq!(resumed.reason, StopReason::BudgetExhausted);
            assert_eq!(state.registers, expected);
            assert_eq!(state.pc, next);
        }
        // XPAC needs no key, even for the IA/DA domain absent in an IB-only context.
        for word in [0xdac143f1, 0xdac147f1, 0xd50320ff, 0xdac143ff, 0xdac147ff] {
            let mut vm = runtime(cache.path(), &[word])?;
            let mut state = initial(7);
            let instruction = decode_pointer_authentication(BASE, word)?.unwrap();
            let mut expected = state.registers.clone();
            complete_pauth(&ib_only, &instruction, &mut expected)?;
            // SAFETY: keyless XPAC only, no guest memory accesses.
            let outcome = unsafe { vm.run_with_pauth(&mut state, None, 1, &ib_only)? };
            assert_eq!(outcome.reason, StopReason::BudgetExhausted);
            assert_eq!(state.registers, expected);
            assert_eq!(state.pc, instruction.next_pc);
        }
        Ok(())
    }

    #[test]
    fn retaa_failure_keeps_signed_lr_and_stops_before_poisoned_fetch() -> Result<()> {
        let context = full_context();
        let cache = tempfile::tempdir()?;
        let mut vm = runtime(cache.path(), &[0xd65f0bff])?;
        let mut state = initial(8);
        let signed = context.sign(stela_contracts::pauth::Key::Ia, STOP.0, state.registers.sp)?;
        state.registers.x[30] = signed ^ (1 << 47);
        let expected = state.registers.clone();
        let target = context.authenticate(
            stela_contracts::pauth::Key::Ia,
            state.registers.x[30],
            state.registers.sp,
        )?;
        assert!(!target.authenticated);
        // SAFETY: helper-only RETAA, no target is fetched by failed completion.
        let outcome = unsafe { vm.run_with_pauth(&mut state, None, 1, &context)? };
        assert_eq!(state.registers, expected);
        assert_eq!(state.pc, GuestAddress(target.pointer));
        assert!(
            matches!(outcome.reason, StopReason::PointerAuthenticationPoisonedReturn { poisoned_target, .. } if poisoned_target == state.pc)
        );
        Ok(())
    }
}
mod numerical_validation {
    use super::*;

    const BASE: u64 = 0x1000;
    const NOP: u32 = 0xd503201f;
    const FADD_S: u32 = 0x1e222820;
    const RET: u32 = 0xd65f03c0;

    fn source(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn interior_numerical_exit_keeps_terminal_helpers_strict() {
        let bytes = source(&[NOP, FADD_S, RET]);
        let (operand, continuation) = validate_numerical_exit(
            GuestAddress(BASE),
            GuestAddress(BASE + 4),
            bytes.len(),
            BASE,
            &bytes,
        )
        .unwrap();
        let stela_compiler::aarch64::FloatingPointOperation::Binary(operand) = operand else {
            panic!("binary instruction decoded as another numerical family");
        };
        assert_eq!(operand.destination, 0);
        assert_eq!(
            operand.inputs,
            stela_compiler::aarch64::simd::arithmetic::Inputs::Elementwise { left: 1, right: 2 }
        );
        assert_eq!(continuation, GuestAddress(BASE + 8));
        assert!(
            validate_terminal_word(
                GuestAddress(BASE),
                GuestAddress(BASE + 4),
                bytes.len(),
                BASE,
                &bytes
            )
            .is_err()
        );
    }

    #[test]
    fn metadata_cannot_authorize_outside_reserved_or_nonnumerical_words() {
        let bytes = source(&[NOP, FADD_S, RET]);
        for (entry, exit, count, region) in [
            (BASE, BASE - 4, 12, BASE),
            (BASE, BASE + 12, 12, BASE),
            (BASE, BASE + 5, 12, BASE),
            (BASE + 1, BASE + 4, 12, BASE),
            (BASE, BASE + 4, 0, BASE),
            (BASE, BASE + 4, 10, BASE),
            (BASE, BASE + 4, 16, BASE),
            (BASE, BASE + 4, 12, BASE + 4),
            (BASE, BASE, 12, BASE),
            (BASE, BASE + 8, 12, BASE),
        ] {
            assert!(
                validate_numerical_exit(
                    GuestAddress(entry),
                    GuestAddress(exit),
                    count,
                    region,
                    &bytes
                )
                .is_err()
            );
        }
        let reserved = source(&[FADD_S | (2 << 22)]);
        assert!(
            validate_numerical_exit(GuestAddress(BASE), GuestAddress(BASE), 4, BASE, &reserved)
                .is_err()
        );
        assert!(
            validate_numerical_exit(
                GuestAddress(u64::MAX - 3),
                GuestAddress(u64::MAX - 3),
                4,
                u64::MAX - 3,
                &source(&[FADD_S])
            )
            .is_err()
        );
    }
}
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
mod resident {
    //! Resident loops: block accounting, final state and cache ownership.
    use super::*;

    const BASE: GuestAddress = GuestAddress(0x1000);
    const FALLTHROUGH: GuestAddress = GuestAddress(BASE.0 + 8);
    const STOP: GuestAddress = GuestAddress(0x2000);
    const SUBS_X0_ONE: u32 = 0xf100_0400;
    const SUBS_W0_ONE: u32 = 0x7100_0400;
    const B_NE_SELF: u32 = 0x54ff_ffe1;
    const MOV_X0_99: u32 = 0xd280_0c60;
    const RET_X30: u32 = 0xd65f_03c0;
    const ARM_CARRY: u32 = 1 << 29;
    const ARM_ZERO: u32 = 1 << 30;

    fn thread(count: u64) -> ThreadState {
        let mut registers = GuestState {
            x: std::array::from_fn(|index| 0x1234_5678_9abc_def0u64.rotate_left(index as u32)),
            sp: 0x3000,
            nzcv: 0xf000_0000,
            exclusive_bytes: 0xa5c3_9e71,
            exclusive_address: 0,
            exclusive_value: 0,
            daif: 0,
            pending: 0,
            v: std::array::from_fn(|index| [index as u64, !(index as u64)]),
            fpcr: 0x03c0_0000,
            fpsr: 0x0800_001f,
        };
        registers.x[0] = count;
        registers.x[30] = STOP.0;
        ThreadState {
            registers,
            pc: BASE,
        }
    }

    fn runtime(path: &std::path::Path, words: &[u32]) -> Result<BlockRuntime> {
        let mut runtime = BlockRuntime::new_with_profile(
            1,
            path.to_path_buf(),
            BlockProfile::new(Features::RESIDENT_LOOPS),
        );
        runtime.register_code(
            BASE,
            words.iter().flat_map(|word| word.to_le_bytes()).collect(),
        )?;
        Ok(runtime)
    }

    #[test]
    fn resident_budget_counts_original_blocks_and_prioritizes_edge() -> Result<()> {
        for (subtract, upper) in [(SUBS_X0_ONE, 0), (SUBS_W0_ONE, 0x1234_5678_0000_0000)] {
            for count in 1..=5 {
                for budget in 0..=7 {
                    let cache = tempfile::tempdir()?;
                    let mut runtime = runtime(cache.path(), &[subtract, B_NE_SELF])?;
                    let mut state = thread(upper | count);
                    let mut expected = state.registers.clone();
                    let consumed = (count as usize).min(budget);
                    if consumed != 0 {
                        expected.x[0] = count - consumed as u64;
                        expected.nzcv = ARM_CARRY | if expected.x[0] == 0 { ARM_ZERO } else { 0 };
                    }
                    // SAFETY: a non-faulting SUBS/branch loop bounded by the block
                    // counter, with no data access or host calls.
                    let outcome = unsafe { runtime.run(&mut state, Some(FALLTHROUGH), budget)? };
                    assert_eq!(state.registers, expected);
                    assert_eq!(outcome.blocks_executed, consumed);
                    if consumed == count as usize {
                        assert_eq!(state.pc, FALLTHROUGH);
                        assert_eq!(outcome.reason, StopReason::StopAddress);
                    } else {
                        assert_eq!(state.pc, BASE);
                        assert_eq!(outcome.reason, StopReason::BudgetExhausted);
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn zero_budget_does_not_prepare_or_execute_a_resident_artifact() -> Result<()> {
        let cache = tempfile::tempdir()?;
        let mut runtime = runtime(cache.path(), &[SUBS_X0_ONE, B_NE_SELF])?;
        let mut state = thread(5);
        let expected = state.registers.clone();
        // SAFETY: zero budget performs no native invocation or instruction fetch.
        let outcome = unsafe { runtime.run(&mut state, None, 0)? };
        assert_eq!(state.registers, expected);
        assert_eq!(state.pc, BASE);
        assert_eq!(outcome.blocks_executed, 0);
        assert_eq!(outcome.compiled_blocks, 0);
        assert!(runtime.loaded_manifest(BASE).is_none());
        Ok(())
    }

    #[test]
    fn ordinary_fallback_preserves_flags_and_consumes_one_block() -> Result<()> {
        let cache = tempfile::tempdir()?;
        let mut runtime = runtime(cache.path(), &[MOV_X0_99, RET_X30])?;
        let mut state = thread(5);
        let mut expected = state.registers.clone();
        expected.x[0] = 99;
        // SAFETY: MOV/RET with no data access.
        let outcome = unsafe { runtime.run(&mut state, Some(STOP), 1)? };
        assert_eq!(state.registers, expected);
        assert_eq!(state.pc, STOP);
        assert_eq!(outcome.blocks_executed, 1);
        assert_eq!(outcome.reason, StopReason::StopAddress);
        assert_eq!(
            runtime.loaded_manifest(BASE).unwrap().identity.abi,
            BlockProfile::new(Features::RESIDENT_LOOPS).abi()
        );
        Ok(())
    }

    #[test]
    fn source_replacement_discards_the_loaded_resident_loop() -> Result<()> {
        let cache = tempfile::tempdir()?;
        let mut runtime = runtime(cache.path(), &[SUBS_X0_ONE, B_NE_SELF])?;
        let mut state = thread(5);
        // SAFETY: the same loop and budget as above.
        unsafe { runtime.run(&mut state, None, 2)? };
        assert_eq!(state.registers.x[0], 3);
        runtime.register_code(
            BASE,
            [MOV_X0_99, RET_X30]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        )?;
        assert!(runtime.loaded_manifest(BASE).is_none());
        let mut expected = state.registers.clone();
        expected.x[0] = 99;
        // SAFETY: the replacement is MOV/RET with no data access.
        let outcome = unsafe { runtime.run(&mut state, Some(STOP), 1)? };
        assert_eq!(state.registers, expected);
        assert_eq!(state.pc, STOP);
        assert_eq!(outcome.blocks_executed, 1);
        Ok(())
    }

    const TST_W8_ONE: u32 = 0x7200_011f;
    const CSEL_W11_W9_ZERO_NE: u32 = 0x1a9f_112b;
    const EOR_W8_W11_W8_LSR_ONE: u32 = 0x4a48_0568;
    const EOR_W8_W8_W8: u32 = 0x4a08_0108;
    const SUBS_W10_ONE: u32 = 0x7100_054a;
    const B_NE_FOUR_WORDS_BACK: u32 = 0x54ff_ff81;
    const CRC_POLYNOMIAL: u32 = 0xedb8_8320;
    const CRC_INITIAL: u32 = 0xabcd_ef01;
    const CRC_BITS: usize = u8::BITS as usize;
    const CRC_LOOP: [u32; 5] = [
        TST_W8_ONE,
        CSEL_W11_W9_ZERO_NE,
        EOR_W8_W11_W8_LSR_ONE,
        SUBS_W10_ONE,
        B_NE_FOUR_WORDS_BACK,
    ];

    fn ordinary(path: &std::path::Path, words: &[u32]) -> Result<BlockRuntime> {
        let mut runtime = BlockRuntime::new_for_target(
            1,
            path.to_path_buf(),
            BlockProfile::ORDINARY,
            stela_compiler::TargetCpu::Baseline,
        );
        runtime.register_code(
            BASE,
            words.iter().flat_map(|word| word.to_le_bytes()).collect(),
        )?;
        Ok(runtime)
    }

    fn crc_thread() -> (ThreadState, GuestState) {
        let mut state = thread(0);
        state.registers.x[8] = 0x1234_5678_0000_0000 | u64::from(CRC_INITIAL);
        state.registers.x[9] = 0x9876_5432_0000_0000 | u64::from(CRC_POLYNOMIAL);
        state.registers.x[10] = 0xffff_ffff_0000_0000 | CRC_BITS as u64;
        let mut expected = state.registers.clone();
        let mut crc = CRC_INITIAL;
        let mut selected = 0;
        for _ in 0..CRC_BITS {
            selected = if crc & 1 != 0 { CRC_POLYNOMIAL } else { 0 };
            crc = (crc >> 1) ^ selected;
        }
        expected.x[8] = u64::from(crc);
        expected.x[10] = 0;
        expected.x[11] = u64::from(selected);
        expected.nzcv = ARM_CARRY | ARM_ZERO;
        (state, expected)
    }

    #[test]
    fn ordinary_runtime_selects_mixed_artifact_abis_and_reuses_their_exact_cache() -> Result<()> {
        let cache = tempfile::tempdir()?;
        let words: Vec<_> = CRC_LOOP.into_iter().chain([RET_X30]).collect();
        let return_pc = GuestAddress(BASE.0 + (CRC_LOOP.len() * std::mem::size_of::<u32>()) as u64);
        let mut runtime = ordinary(cache.path(), &words)?;
        for loaded in [false, true] {
            let (mut state, expected) = crc_thread();
            // SAFETY: the scalar loop and RET cannot fault, and the block budget
            // and stop address bound the run.
            let outcome = unsafe { runtime.run(&mut state, Some(STOP), CRC_BITS + 1)? };
            assert_eq!(state.registers, expected);
            assert_eq!(state.pc, STOP);
            assert_eq!(outcome.reason, StopReason::StopAddress);
            assert_eq!(outcome.blocks_executed, CRC_BITS + 1);
            assert_eq!(outcome.compiled_blocks, if loaded { 0 } else { 2 });
            assert_eq!(outcome.memory_cache_hits, if loaded { 2 } else { 0 });
            assert_eq!(
                runtime.loaded_manifest(BASE).unwrap().identity.abi,
                BlockProfile::new(Features::RESIDENT_LOOPS).abi()
            );
            assert_eq!(
                runtime.loaded_manifest(return_pc).unwrap().identity.abi,
                BlockProfile::ORDINARY.abi()
            );
        }
        let mut disk_runtime = ordinary(cache.path(), &words)?;
        let (mut state, expected) = crc_thread();
        // SAFETY: the same source and state as above.
        let outcome = unsafe { disk_runtime.run(&mut state, Some(STOP), CRC_BITS + 1)? };
        assert_eq!(state.registers, expected);
        assert_eq!(outcome.blocks_executed, CRC_BITS + 1);
        assert_eq!(outcome.compiled_blocks, 0);
        assert_eq!(outcome.disk_cache_hits, 2);
        Ok(())
    }

    #[test]
    fn ordinary_source_replacement_switches_abis_and_zero_budget_stays_cold() -> Result<()> {
        let cache = tempfile::tempdir()?;
        let mut runtime = ordinary(cache.path(), &[SUBS_X0_ONE, B_NE_SELF])?;
        let mut state = thread(5);
        // SAFETY: a bounded subtraction loop with no data access.
        let outcome = unsafe { runtime.run(&mut state, None, 2)? };
        assert_eq!(outcome.blocks_executed, 2);
        assert_eq!(state.registers.x[0], 3);
        assert_eq!(
            runtime.loaded_manifest(BASE).unwrap().identity.abi,
            BlockProfile::new(Features::RESIDENT_LOOPS).abi()
        );
        runtime.register_code(
            BASE,
            [MOV_X0_99, RET_X30]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        )?;
        assert!(runtime.loaded_manifest(BASE).is_none());
        state.pc = BASE;
        let mut expected = state.registers.clone();
        expected.x[0] = 99;
        // SAFETY: the replacement is MOV/RET.
        let outcome = unsafe { runtime.run(&mut state, Some(STOP), 1)? };
        assert_eq!(outcome.blocks_executed, 1);
        assert_eq!(state.registers, expected);
        assert_eq!(
            runtime.loaded_manifest(BASE).unwrap().identity.abi,
            BlockProfile::ORDINARY.abi()
        );
        runtime.register_code(
            BASE,
            [SUBS_X0_ONE, B_NE_SELF]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        )?;
        state = thread(1);
        let before = state.registers.clone();
        // SAFETY: zero budget performs no preparation, mapping or native call.
        let outcome = unsafe { runtime.run(&mut state, None, 0)? };
        assert_eq!(state.registers, before);
        assert_eq!(state.pc, BASE);
        assert_eq!(outcome.blocks_executed, 0);
        assert!(runtime.loaded_manifest(BASE).is_none());
        // SAFETY: the restored source is the same bounded loop.
        let outcome = unsafe { runtime.run(&mut state, Some(FALLTHROUGH), 1)? };
        assert_eq!(outcome.blocks_executed, 1);
        assert_eq!(outcome.reason, StopReason::StopAddress);
        assert_eq!(
            runtime.loaded_manifest(BASE).unwrap().identity.abi,
            BlockProfile::new(Features::RESIDENT_LOOPS).abi()
        );
        Ok(())
    }

    #[test]
    fn ordinary_clobbered_host_flags_remain_resident_and_preserve_guest_flags() -> Result<()> {
        let cache = tempfile::tempdir()?;
        let source = [
            TST_W8_ONE,
            EOR_W8_W8_W8,
            CSEL_W11_W9_ZERO_NE,
            SUBS_X0_ONE,
            B_NE_FOUR_WORDS_BACK,
        ];
        let mut runtime = ordinary(cache.path(), &source)?;
        let mut state = thread(2);
        state.registers.x[8] = 1;
        state.registers.x[9] = u64::from(CRC_POLYNOMIAL);
        let mut expected = state.registers.clone();
        expected.x[0] = 1;
        expected.x[8] = 0;
        expected.x[11] = u64::from(CRC_POLYNOMIAL);
        expected.nzcv = ARM_CARRY;
        // SAFETY: one non-faulting scalar block. CSEL must see the guest TST even
        // though the EOR in between overwrites the host flags.
        let outcome = unsafe { runtime.run(&mut state, None, 1)? };
        assert_eq!(state.registers, expected);
        assert_eq!(state.pc, BASE);
        assert_eq!(outcome.blocks_executed, 1);
        assert_eq!(
            runtime.loaded_manifest(BASE).unwrap().identity.abi,
            BlockProfile::new(Features::RESIDENT_LOOPS).abi()
        );
        Ok(())
    }

    #[test]
    fn dirty_loop_header_inputs_survive_pressure_before_their_next_write() -> Result<()> {
        const CARRIED_GPRS: u32 = 10;
        const SOURCE_REGISTER_SHIFT: u32 = 5;
        const ADD_W_SELF_ONE: u32 = 0x1100_0400;
        const ADD_W22_W1_ONE: u32 = 0x1100_0436;
        const EOR_W23_W22_W22: u32 = 0x4a16_02d7;
        const MOV_W22_ZERO: u32 = 0x5280_0016;
        const B_NE_THIRTEEN_WORDS_BACK: u32 = 0x54ff_fe61;
        const ARM_NEGATIVE: u32 = 1 << 31;
        const BUDGET: usize = 4;
        const UPPER_INPUT: u64 = 0xabcd_dcba_0000_0000;
        let mut source: Vec<_> = (1..CARRIED_GPRS)
            .map(|register| ADD_W_SELF_ONE | (register << SOURCE_REGISTER_SHIFT) | register)
            .collect();
        source.extend([
            ADD_W22_W1_ONE,
            EOR_W23_W22_W22,
            MOV_W22_ZERO,
            SUBS_W0_ONE,
            B_NE_THIRTEEN_WORDS_BACK,
        ]);
        let cache = tempfile::tempdir()?;
        let mut runtime = ordinary(cache.path(), &source)?;
        let mut state = thread(UPPER_INPUT);
        let mut expected = state.registers.clone();
        expected.x[0] = u64::from(0u32.wrapping_sub(BUDGET as u32));
        for register in 1..CARRIED_GPRS as usize {
            expected.x[register] =
                u64::from((expected.x[register] as u32).wrapping_add(BUDGET as u32));
        }
        expected.x[22] = 0;
        expected.x[23] = 0;
        expected.nzcv = ARM_NEGATIVE | ARM_CARRY;
        // SAFETY: a non-faulting scalar loop with ten carried inputs and two
        // outputs. Register pressure can evict the counter before its SUBS; later
        // iterations must keep the carried value rather than reload stale state.
        let outcome = unsafe { runtime.run(&mut state, None, BUDGET)? };
        assert_eq!(state.registers, expected);
        assert_eq!(state.pc, BASE);
        assert_eq!(outcome.blocks_executed, BUDGET);
        assert_eq!(outcome.reason, StopReason::BudgetExhausted);
        assert_eq!(
            runtime.loaded_manifest(BASE).unwrap().identity.abi,
            BlockProfile::new(Features::RESIDENT_LOOPS).abi()
        );
        Ok(())
    }
}
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
mod system_boundary {
    use super::*;
    use crate::system::execution::{Boundary, Dispatcher, EntryBoundary, Failure};

    const ADDRESS_SPACE: u64 = 7;
    const BASE: GuestAddress = GuestAddress(0x1000);
    const ADD: u32 = 0x9100_0400;
    const SVC: u32 = 0xd400_0001;
    const UDF: u32 = 0x0000_0042;

    struct Recorder {
        seen: Vec<(u64, u32)>,
    }
    impl Dispatcher for Recorder {
        fn address_space(&self) -> u64 {
            ADDRESS_SPACE
        }
        fn validate_entry(
            &mut self,
            boundary: &EntryBoundary,
            source: &[u8],
            _: &GuestState,
        ) -> Result<(), Failure> {
            assert_eq!(boundary.entry(), BASE);
            assert!(source.len().is_multiple_of(INSTRUCTION_BYTES));
            assert!(source.len() <= MAX_BLOCK_INSTRUCTIONS * INSTRUCTION_BYTES);
            assert_eq!(
                u32::from_le_bytes(source[..INSTRUCTION_BYTES].try_into().unwrap()),
                boundary.word()
            );
            Ok(())
        }
        fn complete(
            &mut self,
            boundary: Boundary,
            _: &mut GuestState,
        ) -> Result<GuestAddress, Failure> {
            self.seen
                .push((boundary.source().generation(), boundary.instruction().word));
            Ok(boundary.instruction().next_pc)
        }
    }

    #[test]
    fn replacement_uses_new_registered_generation_and_original_word() -> Result<()> {
        let cache = tempfile::tempdir()?;
        let mut runtime = BlockRuntime::new_with_profile(
            ADDRESS_SPACE,
            cache.path().into(),
            BlockProfile::new(Features::SYSTEM),
        );
        let mut state = ThreadState {
            registers: GuestState::default(),
            pc: BASE,
        };
        let mut recorder = Recorder { seen: Vec::new() };
        let first = runtime.register_code(BASE, SVC.to_le_bytes().to_vec())?;
        // SAFETY: trusted test code; the service boundary performs no RAM access.
        let outcome = unsafe {
            runtime.run_with_system(&mut state, Some(GuestAddress(BASE.0 + 4)), 1, &mut recorder)?
        };
        assert!(matches!(outcome.reason, StopReason::StopAddress));
        let second = runtime.register_code(BASE, UDF.to_le_bytes().to_vec())?;
        assert!(second > first);
        state.pc = BASE;
        // SAFETY: replacement is serialized, and the original is revalidated.
        unsafe {
            runtime.run_with_system(&mut state, Some(GuestAddress(BASE.0 + 4)), 1, &mut recorder)?
        };
        assert_eq!(recorder.seen, [(first, SVC), (second, UDF)]);
        Ok(())
    }

    #[test]
    fn missing_system_context_stops_before_native_prefix() -> Result<()> {
        let cache = tempfile::tempdir()?;
        let mut runtime = BlockRuntime::new_with_profile(
            ADDRESS_SPACE,
            cache.path().into(),
            BlockProfile::new(Features::SYSTEM),
        );
        runtime.register_code(
            BASE,
            [ADD, SVC].into_iter().flat_map(u32::to_le_bytes).collect(),
        )?;
        let mut state = ThreadState {
            registers: GuestState::default(),
            pc: BASE,
        };
        let original = state.registers.clone();
        // SAFETY: trusted pure prefix; missing context must prevent invocation.
        let outcome = unsafe { runtime.run(&mut state, None, 1)? };
        assert!(matches!(
            outcome.reason,
            StopReason::SystemContextRequired {
                instruction_pc: BASE
            }
        ));
        assert_eq!(outcome.blocks_executed, 0);
        assert_eq!(state.registers, original);
        assert_eq!(state.pc, BASE);
        Ok(())
    }

    #[test]
    fn terminal_recovery_rejects_forged_pc_extent_and_non_system_word() {
        let source: Vec<_> = [ADD, SVC].into_iter().flat_map(u32::to_le_bytes).collect();
        let terminal = GuestAddress(BASE.0 + 4);
        assert!(validate_system_exit(BASE, terminal, source.len(), BASE.0, &source).is_ok());
        assert!(validate_system_exit(BASE, BASE, source.len(), BASE.0, &source).is_err());
        assert!(validate_system_exit(BASE, terminal, source.len() + 4, BASE.0, &source).is_err());
        assert!(validate_system_exit(BASE, BASE, 4, BASE.0, &source).is_err());
        assert!(validate_system_exit(BASE, terminal, source.len(), BASE.0, &source[..4]).is_err());
    }
}
mod trap_validation {
    use super::*;

    #[test]
    fn thread_register_exit_requires_exact_consumed_source_descriptor() {
        const MRS_TPIDRRO_EL0: u32 = 0xd53bd060;
        const ADD_X0_X0_ONE: u32 = 0x91000400;
        let base = GuestAddress(0x1000);
        let terminal = GuestAddress(base.0 + INSTRUCTION_BYTES as u64);
        for destination in 0..32 {
            let source: Vec<_> = [ADD_X0_X0_ONE, MRS_TPIDRRO_EL0 | destination]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            let instruction =
                validate_thread_register_exit(base, terminal, source.len(), base.0, &source)
                    .unwrap();
            assert_eq!(instruction.destination, destination as u8);
            for (returned, count, region) in [
                (base, 8, base.0),
                (terminal, 0, base.0),
                (terminal, 6, base.0),
                (GuestAddress(0x1008), 12, base.0),
                (terminal, 8, 0x2000),
            ] {
                assert!(
                    validate_thread_register_exit(base, returned, count, region, &source).is_err()
                );
            }
        }
        assert!(
            validate_thread_register_exit(base, base, 4, base.0, &ADD_X0_X0_ONE.to_le_bytes())
                .is_err()
        );
        assert!(
            validate_thread_register_exit(GuestAddress(u64::MAX - 3), GuestAddress(0), 8, 0, &[])
                .is_err()
        );
    }

    #[test]
    fn clock_exit_requires_exact_consumed_source_descriptor() {
        let base = GuestAddress(0x1000);
        let terminal = GuestAddress(0x1004);
        for word in [0xd5033fdf_u32, 0xd53be049, 0xd53be05f] {
            let source: Vec<_> = [0x91000400u32, word]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            assert_eq!(
                validate_clock_exit(base, terminal, 8, base.0, &source).unwrap(),
                decode_clock_instruction(terminal, word).unwrap().unwrap()
            );
            for (returned, count, region) in [
                (base, 8, base.0),
                (terminal, 0, base.0),
                (terminal, 6, base.0),
                (GuestAddress(0x1008), 12, base.0),
                (terminal, 8, 0x2000),
            ] {
                assert!(validate_clock_exit(base, returned, count, region, &source).is_err());
            }
        }
        assert!(validate_clock_exit(base, base, 4, base.0, &0xd503237fu32.to_le_bytes()).is_err());
    }

    #[test]
    fn pauth_exit_requires_the_exact_consumed_immutable_helper_instruction() {
        let base = GuestAddress(0x1000);
        let terminal = GuestAddress(0x1004);
        let source: Vec<_> = [0x91000400u32, 0xd503237f]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        assert_eq!(
            validate_pauth_exit(base, terminal, 8, base.0, &source).unwrap(),
            decode_pointer_authentication(terminal, 0xd503237f)
                .unwrap()
                .unwrap()
        );
        for (returned, bytes, region) in [
            (base, 8, base.0),
            (terminal, 0, base.0),
            (terminal, 6, base.0),
            (GuestAddress(0x1008), 12, base.0),
            (terminal, 8, 0x2000),
        ] {
            assert!(validate_pauth_exit(base, returned, bytes, region, &source).is_err());
        }
        assert!(validate_pauth_exit(base, base, 4, base.0, &source).is_err());
    }

    #[test]
    fn trap_exit_requires_the_exact_consumed_immutable_terminator() {
        let base = GuestAddress(0x1000);
        let terminal = GuestAddress(0x1004);
        let source: Vec<_> = [0x91000400u32, 0xd4001001]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(); // ADD; SVC #0x80
        assert_eq!(
            validate_trap_exit(base, terminal, 8, base.0, &source).unwrap(),
            decode_trap(terminal, 0xd4001001).unwrap().unwrap()
        );
        assert!(validate_trap_exit(base, base, 8, base.0, &source).is_err());
        assert!(validate_trap_exit(base, terminal, 0, base.0, &source).is_err());
        assert!(validate_trap_exit(base, terminal, 6, base.0, &source).is_err());
        assert!(validate_trap_exit(base, GuestAddress(0x1008), 12, base.0, &source).is_err());
        assert!(validate_trap_exit(base, terminal, 8, 0x2000, &source).is_err());
        let ordinary: Vec<_> = [0x91000400u32, 0xd65f03c0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        assert!(validate_trap_exit(base, terminal, 8, base.0, &ordinary).is_err());
    }
}

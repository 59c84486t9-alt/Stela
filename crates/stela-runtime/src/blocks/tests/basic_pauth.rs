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
            reserved: 0xc31a7e29,
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
    let mut vm =
        BlockRuntime::new_with_profile(9, cache.into(), BlockProfile::AppleArm64eSoftwarePauthV1);
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
        let instruction = decode_pointer_authentication(GuestAddress(BASE.0 + 4), word)?.unwrap();
        for flags in 0..16 {
            let mut state = initial(flags);
            if instruction.operation.is_return() {
                let key = runtime_pauth_key(instruction.operation.required_key().unwrap());
                state.registers.x[30] = context.sign(key, STOP.0, state.registers.sp)?;
            }
            let mut expected = state.registers.clone();
            expected.x[7] = 42;
            let (next_pc, authenticated) = complete_pauth(&context, &instruction, &mut expected)?;
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
                    PointerAuthenticationModifier::Register(index) => input.x[usize::from(index)],
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
                let word =
                    0xdac10000 | (opcode << 10) | ((zero as u32) << 13) | (rn << 5) | destination;
                let mut vm = runtime(cache.path(), &[word, 0])?;
                let instruction = decode_pointer_authentication(BASE, word)?.unwrap();
                let mut state = initial(15);
                let mut expected = state.registers.clone();
                let (next, authenticated) = complete_pauth(&context, &instruction, &mut expected)?;
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
fn authenticated_calls_snapshot_aliases_link_before_poison_and_never_fetch_failure() -> Result<()> {
    let context = full_context();
    let cache = tempfile::tempdir()?;
    for key in [pauth::Key::Ia, pauth::Key::Ib] {
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
                    | (u32::from(key == pauth::Key::Ib) << 10)
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
        state.registers.x[30] = full.sign(pauth::Key::Ia, STOP.0, state.registers.sp)?;
        let mut expected = state.registers.clone();
        expected.x[7] = expected.x[7].wrapping_add(1);
        // SAFETY: register prefix/helper only; missing key cannot touch guest RAM.
        let outcome = unsafe { vm.run_with_pauth(&mut state, None, 1, &ib_only)? };
        let instruction = decode_pointer_authentication(GuestAddress(BASE.0 + 4), word)?.unwrap();
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
    let signed = context.sign(pauth::Key::Ia, STOP.0, state.registers.sp)?;
    state.registers.x[30] = signed ^ (1 << 47);
    let expected = state.registers.clone();
    let target = context.authenticate(pauth::Key::Ia, state.registers.x[30], state.registers.sp)?;
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

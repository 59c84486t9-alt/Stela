use super::*;
use std::sync::Barrier;

const WFE: u32 = 0xd503_205f;
const WFI: u32 = 0xd503_207f;
const SEV: u32 = 0xd503_209f;
const SEVL: u32 = 0xd503_20bf;
const WFET: u32 = 0xd503_1000;
const WFIT: u32 = 0xd503_1020;
const PC: u64 = 0x1000;
const WFX_ESR: u32 = 0x07e0_0000;

fn profile(el: ExceptionLevel) -> Profile {
    Profile {
        current_el: el,
        security: SecurityState::NonSecure,
        el2_enabled: false,
        el3_present: false,
    }
}

fn context(trap: bool) -> Context {
    Context::new(
        profile(ExceptionLevel::El0),
        true,
        false,
        false,
        !trap,
        !trap,
    )
    .unwrap()
}

fn instruction(word: u32, value: u64) -> EventInstruction {
    let registers = GuestState {
        x: [value; 31],
        ..GuestState::default()
    };
    EventInstruction::decode(word, PC, &registers).unwrap()
}

fn no_counter() -> Result<u64, ()> {
    panic!("counter must not be sampled")
}

fn retired(outcome: Outcome, reason: RetireReason) {
    assert_eq!(
        outcome,
        Outcome::Retired {
            next_pc: PC + INSTRUCTION_BYTES,
            reason
        }
    );
}

#[test]
fn send_local_all_coalescing_and_registration_are_distinct() {
    let domain = EventDomain::new();
    let mut first = domain.register(false, None).unwrap();
    let second = domain.register(false, None).unwrap();
    for _ in 0..2 {
        retired(
            first
                .complete(
                    &domain,
                    instruction(SEVL, 0),
                    context(true),
                    false,
                    no_counter,
                )
                .unwrap(),
            RetireReason::EventSent,
        );
    }
    assert!(first.consume_if_set());
    assert!(!first.consume_if_set());
    assert!(!second.consume_if_set());
    retired(
        first
            .complete(
                &domain,
                instruction(SEV, 0),
                context(true),
                false,
                no_counter,
            )
            .unwrap(),
        RetireReason::EventSent,
    );
    assert!(first.consume_if_set());
    assert!(second.consume_if_set());
    assert!(!domain.register(false, None).unwrap().is_set());
}

#[test]
fn weak_producers_do_not_retain_or_retarget_retired_pes() {
    let domain = EventDomain::new();
    let first = domain.register(false, None).unwrap();
    let producer = first.producer();
    assert!(producer.same_endpoint(&first.producer()));
    assert!(producer.signal_local());
    assert!(first.consume_if_set());
    drop(first);
    assert!(!producer.signal_local());
    let next = domain.register(false, None).unwrap();
    assert!(!producer.same_endpoint(&next.producer()));
    assert!(!producer.signal_local());
    assert!(!next.is_set());
}

#[test]
fn wrong_domain_and_invalid_pc_fail_before_event_effects() {
    let domain = EventDomain::new();
    let other = EventDomain::new();
    let mut endpoint = domain.register(true, Some(77)).unwrap();
    assert_eq!(
        endpoint.complete(
            &other,
            instruction(WFE, 0),
            context(true),
            false,
            no_counter
        ),
        Err(Error::Domain(DomainError::WrongDomain))
    );
    for pc in [PC + 1, u64::MAX - (INSTRUCTION_BYTES - 1)] {
        let invalid = EventInstruction::decode(WFE, pc, &GuestState::default()).unwrap();
        assert_eq!(
            endpoint.complete(&domain, invalid, context(true), false, no_counter),
            Err(Error::InvalidInstructionPc)
        );
    }
    assert!(endpoint.is_set());
    assert_eq!(endpoint.local_timeout(), Some(77));
}

#[test]
fn context_rejects_unimplemented_privilege_delay_and_halt_profiles() {
    for el in [ExceptionLevel::El2, ExceptionLevel::El3] {
        assert_eq!(
            Context::new(profile(el), true, false, false, true, true),
            Err(ContextError::UnsupportedProfile)
        );
    }
    for unsupported in [
        Profile {
            security: SecurityState::Secure,
            ..profile(ExceptionLevel::El0)
        },
        Profile {
            security: SecurityState::Realm,
            ..profile(ExceptionLevel::El0)
        },
        Profile {
            el2_enabled: true,
            ..profile(ExceptionLevel::El0)
        },
        Profile {
            el3_present: true,
            ..profile(ExceptionLevel::El0)
        },
    ] {
        assert_eq!(
            Context::new(unsupported, true, false, false, true, true),
            Err(ContextError::UnsupportedProfile)
        );
    }
    assert_eq!(
        Context::new(profile(ExceptionLevel::El0), true, true, false, true, true),
        Err(ContextError::TrapDelayUnsupported)
    );
    assert_eq!(
        Context::new(profile(ExceptionLevel::El0), true, false, true, true, true),
        Err(ContextError::HaltedUnsupported)
    );
}

#[test]
fn wfe_consumes_before_trap_but_wfi_never_consumes() {
    let domain = EventDomain::new();
    let mut endpoint = domain.register(true, None).unwrap();
    let wait = instruction(WFI, 0);
    assert_eq!(
        endpoint
            .complete(&domain, wait, context(true), false, no_counter)
            .unwrap(),
        Outcome::Trap(El1Trap {
            instruction: wait,
            preferred_return_pc: PC,
            esr: WFX_ESR | ISS_WFI
        })
    );
    assert!(endpoint.is_set());
    retired(
        endpoint
            .complete(
                &domain,
                instruction(WFE, 0),
                context(true),
                false,
                no_counter,
            )
            .unwrap(),
        RetireReason::EventConsumed,
    );
    let wait = instruction(WFE, 0);
    assert_eq!(
        endpoint
            .complete(&domain, wait, context(true), false, no_counter)
            .unwrap(),
        Outcome::Trap(El1Trap {
            instruction: wait,
            preferred_return_pc: PC,
            esr: WFX_ESR | ISS_WFE
        })
    );
    endpoint.signal_local();
    retired(
        endpoint
            .complete(
                &domain,
                instruction(WFI, 0),
                context(true),
                true,
                no_counter,
            )
            .unwrap(),
        RetireReason::InterruptPending,
    );
    assert!(endpoint.is_set());
}

#[test]
fn timed_short_circuits_and_absent_feature_do_not_invent_effects() {
    let domain = EventDomain::new();
    let mut endpoint = domain.register(true, Some(77)).unwrap();
    retired(
        endpoint
            .complete(
                &domain,
                instruction(WFET, u64::MAX),
                context(true),
                false,
                no_counter,
            )
            .unwrap(),
        RetireReason::EventConsumed,
    );
    retired(
        endpoint
            .complete(
                &domain,
                instruction(WFIT, u64::MAX),
                context(true),
                true,
                no_counter,
            )
            .unwrap(),
        RetireReason::InterruptPending,
    );
    let absent = Context::new(
        profile(ExceptionLevel::El0),
        false,
        false,
        false,
        false,
        false,
    )
    .unwrap();
    endpoint.signal_local();
    let timed = instruction(WFET, 99);
    assert_eq!(
        endpoint
            .complete(&domain, timed, absent, false, no_counter)
            .unwrap(),
        Outcome::Undefined { instruction: timed }
    );
    assert!(endpoint.is_set());
    assert_eq!(endpoint.local_timeout(), Some(77));
}

#[test]
fn every_timed_register_has_exact_syndrome_and_one_operand_sample() {
    let domain = EventDomain::new();
    for base in [WFET, WFIT] {
        for register in 0..=ZERO_REGISTER {
            let mut endpoint = domain.register(false, None).unwrap();
            let mut registers = GuestState {
                x: [99; 31],
                nzcv: u32::MAX,
                ..GuestState::default()
            };
            let word = base | u32::from(register);
            let timed = EventInstruction::decode(word, PC, &registers).unwrap();
            let before = registers.clone();
            registers.x.fill(0);
            let mut reads = 0;
            let outcome = endpoint
                .complete(&domain, timed, context(true), false, || {
                    reads += 1;
                    Ok::<_, ()>(0)
                })
                .unwrap();
            assert_eq!(timed.word(), word);
            assert_eq!(timed.pc(), PC);
            assert_eq!(reads, 1);
            if register == ZERO_REGISTER {
                retired(outcome, RetireReason::DeadlineExpired);
                assert_eq!(endpoint.local_timeout(), None);
            } else {
                let kind = if base == WFET { ISS_WFET } else { ISS_WFIT };
                assert_eq!(
                    outcome,
                    Outcome::Trap(El1Trap {
                        instruction: timed,
                        preferred_return_pc: PC,
                        esr: WFX_ESR
                            | kind
                            | ISS_TIMED_REGISTER_VALID
                            | (u32::from(register) << ISS_TIMED_REGISTER_SHIFT)
                    })
                );
                assert_eq!(endpoint.local_timeout(), Some(99));
            }
            // The service cannot mutate the source register image it borrowed.
            assert_eq!(before.nzcv, u32::MAX);
            assert_eq!(
                registers,
                GuestState {
                    x: [0; 31],
                    ..before
                }
            );
        }
    }
}

#[test]
fn deadlines_are_unsigned_and_timeout_arming_precedes_traps() {
    let domain = EventDomain::new();
    for (deadline, now, expired) in [
        (0, 0, true),
        (1 << 63, (1 << 63) - 1, false),
        (1 << 63, 1 << 63, true),
        (u64::MAX, 0, false),
        (u64::MAX, u64::MAX, true),
        (0, u64::MAX, true),
    ] {
        let mut endpoint = domain.register(false, Some(77)).unwrap();
        let timed = instruction(WFET, deadline);
        let outcome = endpoint
            .complete(&domain, timed, context(true), false, || Ok::<_, ()>(now))
            .unwrap();
        if expired {
            retired(outcome, RetireReason::DeadlineExpired);
            assert_eq!(endpoint.local_timeout(), Some(77));
        } else {
            assert!(matches!(outcome, Outcome::Trap(_)));
            assert_eq!(endpoint.local_timeout(), Some(deadline));
        }
    }
}

#[test]
fn final_event_observation_preserves_the_new_bit_and_skips_second_counter() {
    let domain = EventDomain::new();
    let mut endpoint = domain.register(false, None).unwrap();
    let producer = endpoint.producer();
    let mut reads = 0;
    let outcome = endpoint
        .complete(
            &domain,
            instruction(WFET, 99),
            context(false),
            false,
            || {
                reads += 1;
                assert_eq!(reads, 1);
                assert!(producer.signal_local());
                Ok::<_, ()>(0)
            },
        )
        .unwrap();
    retired(outcome, RetireReason::EventObserved);
    assert!(endpoint.consume_if_set());
    assert_eq!(endpoint.local_timeout(), Some(99));
}

#[test]
fn counter_errors_preserve_prior_timeout_and_publication() {
    let domain = EventDomain::new();
    let mut endpoint = domain.register(false, Some(77)).unwrap();
    assert_eq!(
        endpoint.complete(
            &domain,
            instruction(WFIT, 99),
            context(false),
            false,
            || Err("first")
        ),
        Err(Error::Counter("first"))
    );
    assert_eq!(endpoint.local_timeout(), Some(77));
    let producer = endpoint.producer();
    let mut reads = 0;
    assert_eq!(
        endpoint.complete(
            &domain,
            instruction(WFIT, 99),
            context(false),
            false,
            || {
                reads += 1;
                if reads == 1 {
                    Ok(0)
                } else {
                    producer.signal_local();
                    Err("second")
                }
            }
        ),
        Err(Error::Counter("second"))
    );
    assert_eq!(endpoint.local_timeout(), Some(99));
    assert!(endpoint.is_set());
}

#[test]
fn explicit_cooperative_resume_and_el1_trap_scope() {
    let domain = EventDomain::new();
    let mut endpoint = domain.register(false, None).unwrap();
    for word in [WFE, WFI] {
        retired(
            endpoint
                .complete(
                    &domain,
                    instruction(word, 0),
                    context(false),
                    false,
                    no_counter,
                )
                .unwrap(),
            RetireReason::CooperativeResume,
        );
        let el1 = Context::new(
            profile(ExceptionLevel::El1),
            true,
            false,
            false,
            false,
            false,
        )
        .unwrap();
        retired(
            endpoint
                .complete(&domain, instruction(word, 0), el1, false, no_counter)
                .unwrap(),
            RetireReason::CooperativeResume,
        );
    }
    let mut reads = 0;
    retired(
        endpoint
            .complete(&domain, instruction(WFIT, 9), context(false), false, || {
                reads += 1;
                Ok::<_, ()>(if reads == 1 { 8 } else { 9 })
            })
            .unwrap(),
        RetireReason::DeadlineExpired,
    );
    assert_eq!(reads, 2);
    assert!(EventInstruction::decode(0xd503_201f, PC, &GuestState::default()).is_none());
}

#[test]
fn racing_signal_and_initial_consume_cannot_lose_an_event() {
    const ROUNDS: usize = 2000;
    let domain = EventDomain::new();
    let endpoint = domain.register(false, None).unwrap();
    let producer = endpoint.producer();
    let barrier = Barrier::new(2);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            for _ in 0..ROUNDS {
                barrier.wait();
                assert!(producer.signal_local());
                barrier.wait();
                barrier.wait();
            }
        });
        for _ in 0..ROUNDS {
            barrier.wait();
            let consumed = endpoint.consume_if_set();
            barrier.wait();
            let retained = endpoint.consume_if_set();
            assert_ne!(consumed, retained);
            barrier.wait();
        }
    });
}

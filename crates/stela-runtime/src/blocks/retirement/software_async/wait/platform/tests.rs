use super::super::tests::fixture;
use super::*;
use crate::system::access::{ExceptionLevel, Profile, SecurityState};
use stela_compiler::GuestState;

const WFE: u32 = 0xd503_205f;
const WFI: u32 = 0xd503_207f;
const WFET: u32 = 0xd503_1000;
const WFIT: u32 = 0xd503_1020;
const PC: u64 = 0x1000;

fn context() -> Context {
    Context::new(
        Profile {
            current_el: ExceptionLevel::El1,
            security: SecurityState::NonSecure,
            el2_enabled: false,
            el3_present: false,
        },
        true,
        false,
        false,
        true,
        true,
    )
    .unwrap()
}
fn instruction(word: u32, ticks: u64) -> EventInstruction {
    let mut registers = GuestState::default();
    registers.x[0] = ticks;
    EventInstruction::decode(word, PC, &registers).unwrap()
}

#[test]
fn dropping_pending_wait_poison_sticks_to_receiver() {
    let (mut domain, keys, mut counter, mut receiver, _) = fixture();
    let events = EventDomain::new();
    let mut endpoint = events.register(false, None).unwrap();
    {
        let sources = domain
            .lease_wait_sources(&keys, &mut receiver, &mut counter)
            .unwrap();
        let mut platform = sources.attach_events(&events, &mut endpoint).unwrap();
        assert!(matches!(
            platform
                .prepare(instruction(WFIT, u64::MAX), context())
                .unwrap(),
            Preparation(None)
        ));
        // Abandon the armed timer without cancelling it or inventing a receipt.
        // A new wrapper must not erase the pending wait.
    }
    assert!(matches!(
        domain.lease_wait_sources(&keys, &mut receiver, &mut counter),
        Err(AsyncError::SourceChanged)
    ));
    assert!(matches!(
        domain.lease_no_sources(),
        Err(AsyncError::RegisteredProducer)
    ));
}

#[test]
fn dropping_immediate_completion_cannot_reconstruct_an_idle_platform() {
    let (mut domain, keys, mut counter, mut receiver, _) = fixture();
    let events = EventDomain::new();
    let mut endpoint = events.register(true, None).unwrap();
    {
        let sources = domain
            .lease_wait_sources(&keys, &mut receiver, &mut counter)
            .unwrap();
        let mut platform = sources.attach_events(&events, &mut endpoint).unwrap();
        let Preparation(Some(completion)) =
            platform.prepare(instruction(WFE, 0), context()).unwrap()
        else {
            panic!("set event must retire");
        };
        assert!(matches!(
            completion.outcome(),
            Outcome::Retired {
                reason: RetireReason::EventConsumed,
                ..
            }
        ));
        // The event effect happened; dropping the receipt does not allow a retry
        // or rebuilding the platform.
        drop(completion);
    }
    assert!(matches!(
        domain.lease_wait_sources(&keys, &mut receiver, &mut counter),
        Err(AsyncError::SourceChanged)
    ));
}

#[test]
fn abandonment_poison_is_immediate_before_platform_drop() {
    let (mut domain, keys, mut counter, mut receiver, _) = fixture();
    let events = EventDomain::new();
    let mut endpoint = events.register(false, None).unwrap();
    let sources = domain
        .lease_wait_sources(&keys, &mut receiver, &mut counter)
        .unwrap();
    let mut platform = sources.attach_events(&events, &mut endpoint).unwrap();
    assert!(matches!(
        platform
            .prepare(instruction(WFIT, u64::MAX), context())
            .unwrap(),
        Preparation(None)
    ));
    assert!(platform.arm.is_some());
    platform.check_wait_resources().unwrap();
    platform.abandon();
    assert!(matches!(
        platform.check_resources(),
        Err(Error::Domain(AsyncError::SourceChanged))
    ));
    assert!(platform.arm.is_some());
    assert!(platform.waiting.is_some());
    assert!(matches!(
        platform.poll(),
        Err(Error::Domain(AsyncError::SourceChanged))
    ));
}

#[test]
fn sev_between_wfe_recheck_and_presented_irq_choice_stays_set() {
    let mut domain = unsafe { SoftwareAsyncDomain::fresh_software_pe() };
    let keys = [WaitSourceKind::Irq, WaitSourceKind::LocalTimeout]
        .into_iter()
        .map(|kind| domain.register_wait_source(kind).unwrap())
        .collect::<Vec<_>>();
    let mut counter = hosted::Counter::new();
    let (mut receiver, producers) = domain.bind_wait_transport(&keys, &counter).unwrap();
    let events = EventDomain::new();
    let mut endpoint = events.register(false, None).unwrap();
    let producer = endpoint.producer();
    let sources = domain
        .lease_wait_sources(&keys, &mut receiver, &mut counter)
        .unwrap();
    let mut platform = sources
        .attach_hosted_events(&events, &mut endpoint)
        .unwrap();
    assert!(matches!(
        platform.prepare(instruction(WFE, 0), context()).unwrap(),
        Preparation(None)
    ));
    producers[0].publish(true).unwrap();
    platform.sources.drain_inputs().unwrap();
    let wait = platform.waiting.as_ref().unwrap();
    assert!(
        platform
            .endpoint
            .recheck_wait(wait, false, || platform
                .sources
                .sample_counter()
                .map(|sample| sample.ticks()))
            .unwrap()
            .is_none()
    );
    let presented = platform.sources.presented_irq_wake().unwrap().unwrap();
    assert!(producer.signal_local());
    let completion = platform.complete_presented_wfe(presented).unwrap();
    assert!(matches!(
        completion.outcome(),
        Outcome::Retired {
            reason: RetireReason::EventObserved,
            ..
        }
    ));
    platform.settle(completion).unwrap();
    assert!(platform.endpoint.is_set());
    platform
        .irq_resources()
        .unwrap()
        .validate_presented()
        .unwrap();
}

#[test]
fn host_poll_returns_never_fabricate_a_guest_wakeup() {
    let (mut domain, keys, mut counter, mut receiver, _) = fixture();
    let events = EventDomain::new();
    let mut endpoint = events.register(false, None).unwrap();
    let producer = endpoint.producer();
    let sources = domain
        .lease_wait_sources(&keys, &mut receiver, &mut counter)
        .unwrap();
    let mut platform = sources.attach_events(&events, &mut endpoint).unwrap();
    assert!(matches!(
        platform.prepare(instruction(WFE, 0), context()).unwrap(),
        Preparation(None)
    ));
    for _ in 0..3 {
        let Poll::Sleep { requested } = platform.poll().unwrap() else {
            panic!("poll must not retire an unwoken WFE");
        };
        assert!(requested <= hosted::HOSTED_MAX_REQUESTED_SLEEP);
        // The test parks the thread itself, as Active does after its source
        // checks.
        std::thread::park_timeout(requested);
    }
    assert!(producer.signal_local());
    let Poll::Complete(completion) = platform.poll().unwrap() else {
        panic!("real event must complete WFE");
    };
    assert_eq!(
        completion.outcome(),
        Outcome::Retired {
            next_pc: PC + 4,
            reason: RetireReason::EventObserved
        }
    );
    assert!(platform.endpoint.is_set());
    assert!(matches!(platform.poll(), Err(Error::AwaitingSettlement)));
    platform.settle(completion).unwrap();
    assert!(platform.endpoint.is_set());
}

#[test]
fn threaded_assert_deassert_wakes_wfi_and_preserves_event_bit() {
    let (mut domain, keys, mut counter, mut receiver, producers) = fixture();
    let events = EventDomain::new();
    let mut endpoint = events.register(true, None).unwrap();
    let sources = domain
        .lease_wait_sources(&keys, &mut receiver, &mut counter)
        .unwrap();
    let mut platform = sources.attach_events(&events, &mut endpoint).unwrap();
    assert!(matches!(
        platform.prepare(instruction(WFI, 0), context()).unwrap(),
        Preparation(None)
    ));
    let producer = producers.into_iter().next().unwrap();
    std::thread::spawn(move || {
        producer.publish(true).unwrap();
        producer.publish(false).unwrap();
    })
    .join()
    .unwrap();
    let Poll::Complete(completion) = platform.poll().unwrap() else {
        panic!("registered wake episode must resume WFI");
    };
    assert_eq!(
        completion.outcome(),
        Outcome::Retired {
            next_pc: PC + 4,
            reason: RetireReason::InterruptPending
        }
    );
    assert!(!platform.sources.interrupt_pending().unwrap());
    assert!(platform.endpoint.is_set());
    platform.settle(completion).unwrap();
    assert!(platform.sources.wake_observation().unwrap().is_none());
    assert!(platform.endpoint.is_set());
}

#[test]
fn wfe_interrupt_arbitration_remains_explicit_without_inventing_an_event() {
    let (mut domain, keys, mut counter, mut receiver, producers) = fixture();
    let events = EventDomain::new();
    let mut endpoint = events.register(false, None).unwrap();
    let sources = domain
        .lease_wait_sources(&keys, &mut receiver, &mut counter)
        .unwrap();
    let mut platform = sources.attach_events(&events, &mut endpoint).unwrap();
    platform.prepare(instruction(WFE, 0), context()).unwrap();
    producers[0].publish(true).unwrap();
    assert!(matches!(
        platform.poll().unwrap(),
        Poll::InterruptArbitrationRequired
    ));
    assert!(!platform.endpoint.is_set());
    assert!(platform.sources.interrupt_pending().unwrap());
    assert!(platform.waiting.is_some());
}

#[test]
fn timed_deadline_is_generation_bound_and_requires_settlement() {
    let (mut domain, keys, mut counter, mut receiver, _) = fixture();
    let threshold = counter
        .sample()
        .unwrap()
        .ticks()
        .checked_add(1_000_000)
        .unwrap();
    let events = EventDomain::new();
    let mut endpoint = events.register(false, None).unwrap();
    let sources = domain
        .lease_wait_sources(&keys, &mut receiver, &mut counter)
        .unwrap();
    let mut platform = sources.attach_events(&events, &mut endpoint).unwrap();
    if let Preparation(Some(completion)) = platform
        .prepare(instruction(WFIT, threshold), context())
        .unwrap()
    {
        assert!(matches!(
            completion.outcome(),
            Outcome::Retired {
                reason: RetireReason::DeadlineExpired,
                ..
            }
        ));
        platform.settle(completion).unwrap();
        return;
    }
    for _ in 0..64 {
        match platform.poll().unwrap() {
            Poll::Sleep { requested } => std::thread::park_timeout(requested),
            Poll::Complete(completion) => {
                assert_eq!(
                    completion.outcome(),
                    Outcome::Retired {
                        next_pc: PC + 4,
                        reason: RetireReason::DeadlineExpired
                    }
                );
                assert!(completion.deadline.is_some());
                platform.settle(completion).unwrap();
                assert!(platform.sources.domain.pending.is_empty());
                return;
            }
            _ => panic!("no interrupt was published"),
        }
    }
    panic!("monotonic deadline was not observed");
}

#[test]
fn immediate_event_and_zero_deadline_keep_existing_preparation_order() {
    let (mut domain, keys, mut counter, mut receiver, _) = fixture();
    let events = EventDomain::new();
    let mut endpoint = events.register(true, None).unwrap();
    let sources = domain
        .lease_wait_sources(&keys, &mut receiver, &mut counter)
        .unwrap();
    let mut platform = sources.attach_events(&events, &mut endpoint).unwrap();
    let Preparation(Some(completion)) = platform.prepare(instruction(WFET, 0), context()).unwrap()
    else {
        panic!("initial event must complete before zero deadline");
    };
    assert!(matches!(
        completion.outcome(),
        Outcome::Retired {
            reason: RetireReason::EventConsumed,
            ..
        }
    ));
    assert!(!platform.endpoint.is_set());
    platform.settle(completion).unwrap();
    let Preparation(Some(completion)) = platform.prepare(instruction(WFIT, 0), context()).unwrap()
    else {
        panic!("zero deadline must complete immediately");
    };
    assert!(matches!(
        completion.outcome(),
        Outcome::Retired {
            reason: RetireReason::DeadlineExpired,
            ..
        }
    ));
    platform.settle(completion).unwrap();
    assert!(platform.sources.domain.pending.is_empty());
    assert!(platform.waiting.is_none());
}

#[test]
fn immediate_wfi_retires_only_its_observed_wake_before_next_deasserted_wait() {
    let (mut domain, keys, mut counter, mut receiver, producers) = fixture();
    let events = EventDomain::new();
    let mut endpoint = events.register(false, None).unwrap();
    let sources = domain
        .lease_wait_sources(&keys, &mut receiver, &mut counter)
        .unwrap();
    let mut platform = sources.attach_events(&events, &mut endpoint).unwrap();
    producers[0].publish(true).unwrap();
    let Preparation(Some(completion)) = platform.prepare(instruction(WFI, 0), context()).unwrap()
    else {
        panic!("current pending interrupt must complete WFI immediately");
    };
    assert!(matches!(
        completion.outcome(),
        Outcome::Retired {
            reason: RetireReason::InterruptPending,
            ..
        }
    ));
    assert!(completion.interrupt.is_some());
    assert!(matches!(
        platform.prepare(instruction(WFI, 0), context()),
        Err(Error::AwaitingSettlement)
    ));
    platform.settle(completion).unwrap();
    assert!(platform.sources.interrupt_pending().unwrap());
    producers[0].publish(false).unwrap();
    assert!(matches!(
        platform.prepare(instruction(WFI, 0), context()).unwrap(),
        Preparation(None)
    ));
    assert!(matches!(platform.poll().unwrap(), Poll::Sleep { .. }));
    assert!(!platform.sources.interrupt_pending().unwrap());
    assert!(platform.sources.wake_observation().unwrap().is_none());
}

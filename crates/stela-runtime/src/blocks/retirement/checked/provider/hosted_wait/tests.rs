use super::*;
use crate::{
    blocks::retirement::checked::software_el1::hosted::HostedWaitInstallation,
    system::{
        access::{ExceptionLevel, Profile, SecurityState},
        events::hosted,
    },
};
use stela_compiler::GuestState;

const PC: u64 = 0x1000;
const WFE: u32 = 0xd503_205f;
const WFI: u32 = 0xd503_207f;
const WFIT_X0: u32 = 0xd503_1020;

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
fn same_backend_retains_pending_descriptor_across_host_returns() {
    let (mut installation, _) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
    let events = EventDomain::new();
    let mut endpoint = events.register(false, None).unwrap();
    let producer = endpoint.producer();
    let mut resources = installation.resources(&events, &mut endpoint).unwrap();
    assert!(matches!(
        resources.prepare(instruction(WFE, 0), context()).unwrap(),
        WaitReply::Park { .. }
    ));
    assert!(resources.outcome().is_err());
    assert!(resources.prepare(instruction(WFE, 0), context()).is_err());
    let WaitReply::Park { requested } = resources.poll().unwrap() else {
        panic!("missing event cannot retire");
    };
    std::thread::park_timeout(requested);
    assert!(matches!(resources.poll().unwrap(), WaitReply::Park { .. }));
    assert!(producer.signal_local());
    assert!(matches!(
        resources.poll().unwrap(),
        WaitReply::CompletionReady
    ));
    assert!(matches!(
        resources.outcome().unwrap(),
        Outcome::Retired {
            reason: RetireReason::EventObserved,
            ..
        }
    ));
    assert!(matches!(
        resources.poll().unwrap(),
        WaitReply::CompletionReady
    ));
    resources.settle().unwrap();
    assert!(resources.outcome().is_err());
}

#[test]
fn immediate_irq_reply_retains_receipt_until_settlement() {
    let (mut installation, irq) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
    let events = EventDomain::new();
    let mut endpoint = events.register(false, None).unwrap();
    let mut resources = installation.resources(&events, &mut endpoint).unwrap();
    irq.publish(true).unwrap();
    assert!(matches!(
        resources.prepare(instruction(WFI, 0), context()).unwrap(),
        WaitReply::WakeIrqPending
    ));
    assert!(matches!(
        resources.outcome().unwrap(),
        Outcome::Retired {
            reason: RetireReason::InterruptPending,
            ..
        }
    ));
    assert!(matches!(
        resources.poll().unwrap(),
        WaitReply::WakeIrqPending
    ));
    // Masked-WFI arbitration may consume this wake; the adapter itself never
    // permits a masked wake or IRQ entry.
    resources.settle().unwrap();
    irq.publish(false).unwrap();
    assert!(matches!(
        resources.prepare(instruction(WFI, 0), context()).unwrap(),
        WaitReply::Park { .. }
    ));
}

#[test]
fn guest_read_and_timed_wait_use_the_same_counter() {
    use crate::system::{
        access::AccessKind,
        timer::{BackendRequest, CounterOffset, CounterOrdering, TimerKind},
    };
    let (mut installation, _) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
    let events = EventDomain::new();
    let mut endpoint = events.register(false, None).unwrap();
    let mut resources = installation.resources(&events, &mut endpoint).unwrap();
    let request = BackendRequest::Counter {
        kind: TimerKind::Virtual,
        offset: CounterOffset::None,
        ordering: CounterOrdering::CounterReads,
    };
    assert_eq!(
        resources
            .counter_view()
            .unwrap()
            .read(BackendRequest::Frequency(AccessKind::Read))
            .unwrap(),
        hosted::HOSTED_COUNTER_FREQUENCY
    );
    let before = resources.counter_view().unwrap().read(request).unwrap();
    assert!(matches!(
        resources
            .prepare(instruction(WFIT_X0, before), context())
            .unwrap(),
        WaitReply::CompletionReady
    ));
    assert!(matches!(
        resources.outcome().unwrap(),
        Outcome::Retired {
            reason: RetireReason::DeadlineExpired,
            ..
        }
    ));
    resources.settle().unwrap();
    let after = resources.counter_view().unwrap().read(request).unwrap();
    assert!(after >= before);
}

#[test]
fn registry_membership_check_is_not_native_pending_delivery_permission() {
    let (mut installation, irq) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
    let events = EventDomain::new();
    let mut endpoint = events.register(false, None).unwrap();
    let mut resources = installation.resources(&events, &mut endpoint).unwrap();
    let system = crate::system::state::SystemState::new(
        crate::system::state::PSTATE_EL1H,
        0,
        crate::system::state::El1Registers::new(0, 0, 0, 0, 0),
    )
    .unwrap();
    resources.check_native_boundary(&system).unwrap();
    irq.publish(true).unwrap();
    irq.publish(false).unwrap();
    resources.check_resources().unwrap();
    assert!(matches!(
        resources.check_native_boundary(&system),
        Err(HostedWaitError::InterruptArbitrationRequired)
    ));
    // Re-checking cannot acknowledge or discard the pending wake.
    assert!(matches!(
        resources.check_native_boundary(&system),
        Err(HostedWaitError::InterruptArbitrationRequired)
    ));
}

#[test]
fn masked_wfi_settlement_preserves_presented_irq_for_the_entry_owner() {
    let (mut installation, irq) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
    let events = EventDomain::new();
    let mut endpoint = events.register(false, None).unwrap();
    let mut resources = installation.resources(&events, &mut endpoint).unwrap();
    let masked = crate::system::state::SystemState::new(
        crate::system::state::PSTATE_EL1H | crate::system::pstate::DAIF_MASK,
        0,
        crate::system::state::El1Registers::new(0, 0, 0, 0, 0),
    )
    .unwrap();
    irq.publish(true).unwrap();
    assert!(matches!(
        resources.prepare(instruction(WFI, 0), context()).unwrap(),
        WaitReply::WakeIrqPending
    ));
    resources.settle().unwrap();
    resources.check_native_boundary(&masked).unwrap();
    {
        let original = resources.irq_resources().unwrap();
        let receipt = original.receipt().unwrap();
        receipt.validate().unwrap();
        // A later deassertion cannot rewrite the leased pending state; the
        // level is sampled again afterward.
        irq.publish(false).unwrap();
        receipt.validate().unwrap();
    }
    assert!(resources.irq_resources().unwrap().receipt().is_none());
}

#[test]
fn transient_wake_is_not_a_pending_irq_exception() {
    let (mut installation, irq) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
    let events = EventDomain::new();
    let mut endpoint = events.register(false, None).unwrap();
    let mut resources = installation.resources(&events, &mut endpoint).unwrap();
    irq.publish(true).unwrap();
    irq.publish(false).unwrap();
    // The receipt is only constructed beside its own endpoint; nothing
    // accepts a receipt and endpoint from different sources.
    let endpoint = resources.endpoint() as *const _;
    let original = resources.irq_resources().unwrap();
    assert!(original.receipt().is_none());
    assert!(core::ptr::eq(original.endpoint(), endpoint));
}

#[test]
fn active_wait_qualification_is_distinct_from_native_entry_permission() {
    let (mut installation, _) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
    let events = EventDomain::new();
    let mut endpoint = events.register(false, None).unwrap();
    let mut resources = installation.resources(&events, &mut endpoint).unwrap();
    let system = crate::system::state::SystemState::new(
        crate::system::state::PSTATE_EL1H | crate::system::pstate::DAIF_MASK,
        0,
        crate::system::state::El1Registers::new(0, 0, 0, 0, 0),
    )
    .unwrap();
    assert!(resources.check_wake_resources().is_err());
    assert!(matches!(
        resources.prepare(instruction(WFE, 0), context()).unwrap(),
        WaitReply::Park { .. }
    ));
    resources.check_wake_resources().unwrap();
    assert!(resources.check_native_boundary(&system).is_err());
    resources.abandon();
    assert!(resources.check_resources().is_err());
    assert!(resources.check_wake_resources().is_err());
}

#[test]
fn hosted_wfe_presented_irq_resume_preserves_event_and_pending_level() {
    let (mut installation, irq) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
    let events = EventDomain::new();
    let mut endpoint = events.register(false, None).unwrap();
    let mut resources = installation.resources(&events, &mut endpoint).unwrap();
    assert!(matches!(
        resources.prepare(instruction(WFE, 0), context()).unwrap(),
        WaitReply::Park { .. }
    ));
    irq.publish(true).unwrap();
    assert!(matches!(
        resources.poll().unwrap(),
        WaitReply::CompletionReady
    ));
    assert!(
        matches!(resources.outcome().unwrap(), Outcome::Retired { next_pc, reason: RetireReason::PresentedIrqResume } if next_pc == PC + 4)
    );
    assert!(!resources.endpoint().is_set());
    resources.settle().unwrap();
    assert!(!resources.endpoint().is_set());
    resources
        .irq_resources()
        .unwrap()
        .receipt()
        .unwrap()
        .validate()
        .unwrap();
}

#[test]
fn hosted_wfe_transient_wake_does_not_replace_event_or_presented_irq() {
    let (mut installation, irq) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
    let events = EventDomain::new();
    let mut endpoint = events.register(false, None).unwrap();
    let producer = endpoint.producer();
    let mut resources = installation.resources(&events, &mut endpoint).unwrap();
    assert!(matches!(
        resources.prepare(instruction(WFE, 0), context()).unwrap(),
        WaitReply::Park { .. }
    ));
    irq.publish(true).unwrap();
    irq.publish(false).unwrap();
    assert!(matches!(resources.poll().unwrap(), WaitReply::Park { .. }));
    assert!(resources.outcome().is_err());
    assert!(!resources.endpoint().is_set());
    assert!(producer.signal_local());
    assert!(matches!(
        resources.poll().unwrap(),
        WaitReply::CompletionReady
    ));
    assert!(matches!(
        resources.outcome().unwrap(),
        Outcome::Retired {
            reason: RetireReason::EventObserved,
            ..
        }
    ));
    resources.settle().unwrap();
}

#[test]
fn simultaneous_sev_and_irq_preserve_event_and_do_not_ack_irq() {
    let (mut installation, irq) = unsafe { HostedWaitInstallation::fresh() }.unwrap();
    let events = EventDomain::new();
    let mut endpoint = events.register(false, None).unwrap();
    let producer = endpoint.producer();
    let mut resources = installation.resources(&events, &mut endpoint).unwrap();
    assert!(matches!(
        resources.prepare(instruction(WFE, 0), context()).unwrap(),
        WaitReply::Park { .. }
    ));
    irq.publish(true).unwrap();
    assert!(producer.signal_local());
    assert!(matches!(
        resources.poll().unwrap(),
        WaitReply::CompletionReady
    ));
    assert!(matches!(
        resources.outcome().unwrap(),
        Outcome::Retired {
            reason: RetireReason::EventObserved,
            ..
        }
    ));
    resources.settle().unwrap();
    assert!(resources.endpoint().is_set());
    resources
        .irq_resources()
        .unwrap()
        .receipt()
        .unwrap()
        .validate()
        .unwrap();
    assert!(matches!(
        resources.prepare(instruction(WFE, 0), context()).unwrap(),
        WaitReply::CompletionReady
    ));
    assert!(matches!(
        resources.outcome().unwrap(),
        Outcome::Retired {
            reason: RetireReason::EventConsumed,
            ..
        }
    ));
    resources.settle().unwrap();
    assert!(!resources.endpoint().is_set());
}

use super::*;
use core::sync::atomic::AtomicUsize;

struct Kicks(Arc<AtomicUsize>);
impl Kick for Kicks {
    fn kick(&self, _pe: usize) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn hub(pes: usize) -> (Arc<Hub>, Arc<AtomicUsize>) {
    let kicks = Arc::new(AtomicUsize::new(0));
    let hub = Hub::new(pes, Kicks(Arc::clone(&kicks)));
    for pe in 0..pes {
        hub.set_live(pe, true);
    }
    (hub, kicks)
}

fn tlbi(kind: crate::machine::system::TlbiKind, operand: u64) -> Maintenance {
    use crate::machine::system::{Regime, Tlbi, TlbiAttr, TlbiLevel};
    Maintenance::Tlb(tlbi::Scope::new(
        &Tlbi {
            kind,
            regime: Regime::EL10,
            vmid: None,
            broadcast: Broadcast::ISH,
            level: TlbiLevel::Any,
            attr: TlbiAttr::AllAttr,
            operand,
        },
        tlbi::Context::default(),
    ))
}

/// A TLBI of another context leaves its mail for the PE's next read, and
/// neither interrupts it nor waits for it.
#[test]
fn a_tlbi_passes_by_a_pe_translating_another_context() {
    use crate::machine::system::TlbiKind::{ASID, VA, VAA};
    const ASID_5: u64 = 5 << 48;
    let (hub, _) = hub(2);
    let inbox = &hub.inboxes[1];
    let word = context_word(mmu::Regime::El10, 7);
    let epoch = || inbox.chain.interrupt_epoch().load(Ordering::Relaxed);
    assert_eq!(hub.broadcast(0, &[tlbi(ASID, ASID_5)]).len(), 1, "unpublished");
    inbox.translating.store(word, Ordering::Relaxed);
    let interrupts = epoch();
    let passes = [ASID_5, ASID_5 | 0x1234];
    for (kind, operand) in [ASID, VA].into_iter().zip(passes) {
        assert!(hub.broadcast(0, &[tlbi(kind, operand)]).is_empty());
    }
    assert_eq!(epoch(), interrupts);
    assert!(hub.pending(1));
    assert_eq!(hub.take(1).unwrap().maintenance.len(), 3);
    assert_eq!(
        hub.broadcast(0, &[tlbi(ASID, 7 << 48)]).len(),
        1,
        "its context"
    );
    assert_eq!(hub.broadcast(0, &[tlbi(VAA, 0x1234)]).len(), 1, "every ASID");
    assert!(inbox.lower_globals.widen(0x123_0000, 0x123_ffff));
    assert!(!inbox.lower_globals.widen(0x123_4000, 0x123_7fff));
    assert_eq!(
        hub.broadcast(0, &[tlbi(VA, ASID_5 | 0x1234)]).len(),
        1,
        "its global page"
    );
    assert!(hub.broadcast(0, &[tlbi(VA, ASID_5 | 0x4321)]).is_empty());
}

/// What a PE translates is published before its next mail read.
#[test]
fn a_pe_publishes_the_context_it_translates() {
    use super::super::tests::machine;
    let mut machine = machine(&[0xd503_201f]);
    let (hub, _) = hub(1);
    machine.enter_parallel(Arc::clone(&hub)).unwrap();
    assert_eq!(
        hub.inboxes[0].translating.load(Ordering::Relaxed),
        ANY_CONTEXT
    );
    machine.sync_host_regime();
    let controls = machine.cpu.controls(machine.cpu.regime());
    assert_eq!(
        hub.inboxes[0].translating.load(Ordering::Relaxed),
        context_word(controls.regime, mmu::current_asid(&controls))
    );
}

#[test]
fn duplicate_safe_attachment_refuses_without_replacing_the_live_owner() {
    use super::super::tests::{BASE, board};
    use crate::machine::NoDevices;
    use stela_contracts::identity::Identity;
    let identities = vec![Identity {
        midr: 0x611f_0320,
        mpidr: 0x8000_0000,
        clock: None,
        caches: None,
    }];
    let mut first = board(&[], NoDevices, identities.clone());
    let mut second = board(&[], NoDevices, identities);
    let (hub, _) = hub(1);
    first.enter_parallel(Arc::clone(&hub)).unwrap();
    let epoch = first.attached.as_ref().unwrap().epoch;
    let untouched = second.chain.snapshot();
    assert_eq!(
        second.enter_parallel(Arc::clone(&hub)),
        Err(ParallelAdmissionError::PeOwned { pe: 0 })
    );
    assert!(second.parallel.is_none() && second.attached.is_none());
    assert_eq!(second.chain.snapshot(), untouched);
    assert_eq!(
        first.enter_parallel(Arc::clone(&hub)),
        Err(ParallelAdmissionError::MachineAttached)
    );
    first.chain.budget().store(17, Ordering::Relaxed);
    hub.interrupt(0);
    assert_eq!(first.chain.budget().load(Ordering::Relaxed), 17);
    let pending = first.chain.snapshot();
    assert_ne!(pending.interrupt_epoch, pending.observed_interrupt_epoch);
    drop(first);
    second.enter_parallel(Arc::clone(&hub)).unwrap();
    assert!(second.attached.as_ref().unwrap().epoch > epoch);
    assert_eq!(second.cpu.pc, BASE);
}

#[test]
fn an_interrupt_borrow_survives_detach_and_reuse_without_a_raw_pointer_lease() {
    use std::sync::mpsc;
    let (hub, _) = hub(1);
    let weak = Arc::downgrade(&hub.inboxes[0].chain);
    let (attached, mut control) = Attached::new(&hub, 0, false).unwrap();
    control.initialize(11, [12, 13]);
    control.begin(9, 99);
    let (ready_tx, ready_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let foreign = Arc::clone(&hub);
    let reader = std::thread::spawn(move || {
        let epoch = foreign.inboxes[0].chain.interrupt_epoch();
        ready_tx.send(()).unwrap();
        resume_rx.recv().unwrap();
        epoch.fetch_add(1, Ordering::Release);
    });
    ready_rx.recv().unwrap();
    drop(attached);
    assert_ne!(
        hub.inboxes[0].owner.load(Ordering::Acquire),
        0,
        "the control owner retains the claim"
    );
    drop(control);
    assert_eq!(hub.inboxes[0].owner.load(Ordering::Acquire), 0);
    assert!(
        weak.upgrade().is_some(),
        "hub retains the physical allocation"
    );
    let (next, mut control) = Attached::new(&hub, 0, false).unwrap();
    control.initialize(21, [22, 23]);
    control.begin(2, 77);
    resume_tx.send(()).unwrap();
    reader.join().unwrap();
    let snapshot = control.snapshot();
    assert_eq!(
        (
            snapshot.budget,
            snapshot.retired,
            snapshot.hits,
            snapshot.linked
        ),
        (77, 0, 0, 0)
    );
    assert_eq!(
        (snapshot.block, snapshot.table, snapshot.contexts),
        (2, 21, [22, 23])
    );
    assert_ne!(snapshot.interrupt_epoch, snapshot.observed_interrupt_epoch);
    assert_eq!(hub.inboxes[0].owner.load(Ordering::Acquire), next.epoch);
    drop(control);
    drop(next);
    drop(hub);
    assert!(
        weak.upgrade().is_none(),
        "last hub/owner releases the allocation"
    );
}

#[test]
fn populated_machine_discards_thunks_before_adopting_a_hub_control() {
    use super::super::tests::{BASE, machine};
    use stela_compiler::block::ExitKind;
    let mut machine = machine(&[0x9100_0400, 0x1400_0002, 0, 0x9100_0400, 0x17ff_fffc]);
    let direct = |next_pc| super::super::NativeExit::Exit {
        next_pc,
        kind: ExitKind::Direct as u64,
    };
    machine.host.exits = vec![direct(BASE + 12), direct(BASE), direct(BASE + 12)];
    machine.step().unwrap();
    machine.step().unwrap();
    machine.step().unwrap();
    assert_eq!(machine.statistics.links, 2);
    assert!(!machine.host.installed.is_empty() && !machine.host.patches.is_empty());
    let old_address = machine.chain.address();
    let old_storage = machine.chain.weak_storage();
    let old_patches = machine.host.patches.len();
    let (hub, _) = hub(1);
    machine.enter_parallel(Arc::clone(&hub)).unwrap();
    assert_ne!(machine.chain.address(), old_address);
    assert!(old_storage.upgrade().is_none());
    assert!(
        machine.blocks.is_empty() && machine.index.is_empty() && machine.fault_recovery.is_empty()
    );
    assert!(machine.host.installed.is_empty());
    assert!(machine.targets.is_empty());
    machine.cpu.pc = BASE;
    machine.host.exits = vec![direct(BASE + 12), direct(BASE), direct(BASE + 12)];
    machine.step().unwrap();
    machine.step().unwrap();
    machine.step().unwrap();
    let current = machine.chain.address().to_le_bytes();
    let previous = old_address.to_le_bytes();
    let rebuilt = &machine.host.patches[old_patches..];
    assert!(
        rebuilt
            .iter()
            .any(|(_, bytes)| bytes.windows(8).any(|word| word == current))
    );
    assert!(
        rebuilt
            .iter()
            .all(|(_, bytes)| bytes.windows(8).all(|word| word != previous))
    );
}

#[test]
fn repeated_owner_reuse_keeps_remote_epoch_writes_disjoint() {
    use core::sync::atomic::AtomicBool;
    use std::sync::Barrier;
    let (hub, _) = hub(1);
    let started = Arc::new(Barrier::new(2));
    let done = Arc::new(AtomicBool::new(false));
    let foreign = Arc::clone(&hub);
    let worker_started = Arc::clone(&started);
    let worker_done = Arc::clone(&done);
    let interrupt = std::thread::spawn(move || {
        worker_started.wait();
        while !worker_done.load(Ordering::Acquire) {
            foreign.interrupt(0);
        }
    });
    started.wait();
    let mut last = 0;
    for index in 0..1000 {
        let (attached, mut control) = Attached::new(&hub, 0, false).unwrap();
        assert!(attached.epoch > last);
        last = attached.epoch;
        control.initialize(index, [index + 1, index + 2]);
        control.begin(index as usize, 31);
        let state = control.snapshot();
        assert_eq!(
            (state.block, state.table, state.contexts),
            (index, index, [index + 1, index + 2])
        );
        drop(attached);
        drop(control);
    }
    done.store(true, Ordering::Release);
    interrupt.join().unwrap();
    assert_eq!(hub.inboxes[0].owner.load(Ordering::Acquire), 0);
}

#[test]
fn parallel_pes_refuse_independent_idle_leaps() {
    use super::super::tests::{BASE, board};
    use {crate::machine::engine::NoDevices, stela_contracts::identity::Identity};

    let identities = (0..2)
        .map(|pe| Identity {
            midr: 0x611f_0320,
            mpidr: 0x8000_0000 | pe << 8,
            clock: None,
            caches: None,
        })
        .collect::<Vec<_>>();
    let mut home = board(&[], NoDevices, identities.clone());
    let prepared = board(&[], NoDevices, identities);
    let mut worker = Machine::new_at(
        prepared.cpu,
        prepared.host,
        prepared.devices,
        prepared.profile,
        prepared.target,
        1,
    )
    .unwrap();
    home.set_idle_skip(true).unwrap();
    let (hub, _) = hub(2);
    home.enter_parallel(Arc::clone(&hub)).unwrap();
    worker
        .start_parallel(hub, home.cpu.core_locks.clone(), BASE)
        .unwrap();
    for machine in [&mut home, &mut worker] {
        assert!(!machine.idle_skip);
        assert_eq!(
            machine.set_idle_skip(true),
            Err("idle skipping requires all PEs to share one scheduler")
        );
        assert!(!machine.idle_skip);
        machine.set_idle_skip(false).unwrap();
        machine.host.now = 1000;
    }
    assert_eq!(home.now(), worker.now());
    home.host.now = 2000;
    worker.host.now = 2000;
    assert_eq!(home.now(), worker.now());
}

#[test]
fn source_observation_uses_only_the_attached_owner_and_remains_stale() {
    use super::super::tests::{BASE, board};
    use crate::machine::engine::NoDevices;
    use stela_contracts::identity::Identity;

    let identities = (0..2)
        .map(|pe| Identity {
            midr: 0x611f_0320,
            mpidr: 0x8000_0000 | pe << 8,
            clock: None,
            caches: None,
        })
        .collect::<Vec<_>>();
    let mut home = board(&[], NoDevices, identities.clone());
    let prepared = board(&[], NoDevices, identities);
    let mut worker = Machine::new_at(
        prepared.cpu,
        prepared.host,
        prepared.devices,
        prepared.profile,
        prepared.target,
        1,
    )
    .unwrap();
    let (hub, kicks) = hub(2);
    home.enter_parallel(Arc::clone(&hub)).unwrap();
    worker
        .start_parallel(Arc::clone(&hub), home.cpu.core_locks.clone(), BASE)
        .unwrap();
    let reads = worker.host.counter_reads;
    worker.observe_parallel_source(SourcePhase::SliceEnter);
    assert_eq!(
        worker.host.counter_reads, reads,
        "disabled path reads no counter"
    );
    assert_eq!(hub.source_observation(1), None, "default off");
    hub.set_source_observations(true);
    worker.cpu.pc = BASE + 4;
    worker.cpu.state.sp = 0x8000;
    worker.cpu.state.x[29] = 0x8010;
    worker.cpu.state.x[30] = BASE + 8;
    worker.cpu.pstate.daif = 3;
    worker.host.now = 1000;
    let before = worker.cpu.state.clone();
    let counts = worker.counts();
    let sent = kicks.load(Ordering::Relaxed);
    worker.observe_parallel_source(SourcePhase::BroadcastEnter);
    let first = hub.source_observation(1).unwrap();
    assert_eq!(first.sequence, 2);
    assert_eq!(
        first.source,
        MaterializedSource {
            host_counter: 1000,
            phase: SourcePhase::BroadcastEnter,
            pc: BASE + 4,
            sp: 0x8000,
            fp: 0x8010,
            lr: BASE + 8,
            el: 2,
            daif: 3,
        }
    );
    assert_eq!(worker.cpu.state, before);
    assert_eq!(worker.counts(), counts);
    assert_eq!(kicks.load(Ordering::Relaxed), sent);
    assert_eq!(hub.source_observation(0), None);
    assert_eq!(hub.source_observation(2), None);
    assert_eq!(hub.source_observation(usize::MAX), None);

    // A caller cannot select another slot: attachment is private and
    // publication refuses a mismatched current-PE image.
    worker.current = 0;
    worker.observe_parallel_source(SourcePhase::SliceExit);
    assert_eq!(hub.source_observation(0), None);
    assert_eq!(hub.source_observation(1), Some(first));
    worker.current = 1;
    worker.cpu.pc = BASE + 16;
    worker.host.now = 2000;
    assert_eq!(
        hub.source_observation(1),
        Some(first),
        "no implicit refresh"
    );
    worker.observe_parallel_source(SourcePhase::SliceExit);
    let second = hub.source_observation(1).unwrap();
    assert_eq!(second.sequence, 4);
    assert_eq!(second.source.pc, BASE + 16);
    assert_eq!(second.source.host_counter, 2000);
    hub.set_source_observations(false);
    worker.observe_parallel_source(SourcePhase::ParkEnter);
    assert_eq!(hub.source_observation(1), None);
    hub.set_source_observations(true);
    assert_eq!(hub.source_observation(1), Some(second));

    // Real boundary hooks publish once at entry and once on return, not
    // on each wait-loop spin. A PE that stops reading mail needs not
    // acknowledge what was posted to it.
    home.post(Maintenance::Code(None));
    home.send_outgoing();
    hub.set_live(1, false);
    home.complete_maintenance().unwrap();
    let broadcast = hub.source_observation(0).unwrap();
    assert_eq!(broadcast.sequence, 4);
    assert_eq!(broadcast.source.phase, SourcePhase::BroadcastExit);
    home.device_transfer(0).unwrap();
    let dma = hub.source_observation(0).unwrap();
    assert_eq!(dma.sequence, 8);
    assert_eq!(dma.source.phase, SourcePhase::DeviceAdvanceExit);
    assert_eq!(hub.source_observation(1), Some(second));
}

/// A machine of PE 0 of two in `hub`, running `words`.
fn first_of_two(
    words: &[u32],
    hub: &Arc<Hub>,
) -> Machine<super::super::tests::FakeHost, crate::machine::NoDevices> {
    use stela_contracts::identity::Identity;
    let identities = (0..2)
        .map(|pe| Identity {
            midr: 0x611f_0320,
            mpidr: 0x8000_0000 | pe << 8,
            clock: None,
            caches: None,
        })
        .collect::<Vec<_>>();
    let mut machine = super::super::tests::board(words, crate::machine::NoDevices, identities);
    machine.enter_parallel(Arc::clone(hub)).unwrap();
    machine
}

#[test]
fn broadcast_profile_counts_posts_and_completion_waits_for_the_attached_owner() {
    let (hub, _) = hub(2);
    let mut machine = first_of_two(&[0xd503_201f], &hub);
    // Unobserved, a post reads no clock; the completion reads its two.
    let reads = machine.host.counter_reads;
    machine.post(Maintenance::Code(None));
    assert_eq!(machine.host.counter_reads, reads);
    machine.send_outgoing();
    hub.set_live(1, false);
    machine.complete_maintenance().unwrap();
    assert_eq!(machine.host.counter_reads - reads, 2);
    assert!(hub.broadcast_profile(0).is_none());

    hub.set_source_observations(true);
    hub.set_live(1, true);
    let reads = machine.host.counter_reads;
    machine.post(Maintenance::Code(Some(0x4000)));
    machine.post(Maintenance::Code(Some(0x4000)));
    machine.send_outgoing();
    hub.set_live(1, false);
    machine.complete_maintenance().unwrap();
    // A clock for the posts, and the completion's two and its two source
    // observations; accounting adds no native notification.
    assert_eq!(machine.host.counter_reads - reads, 5);
    let observed = hub.broadcast_profile(0).unwrap();
    let code = observed.kinds[BroadcastKind::Code.index()];
    assert_eq!(
        (code.started, code.completed, code.recipients, code.polls),
        (2, 2, 2, 0)
    );
    let completion = observed.kinds[BroadcastKind::Completion.index()];
    assert_eq!(
        (
            completion.started,
            completion.completed,
            completion.recipients
        ),
        (1, 1, 1)
    );
    assert_eq!((observed.active, observed.dropped_updates), (None, false));
    // PE 1 posted nothing.
    let idle = hub.broadcast_profile(1).unwrap();
    assert!(idle.kinds.iter().all(|counts| counts.started == 0));

    // With nothing posted, a completion waits for nothing.
    let reads = machine.host.counter_reads;
    machine.complete_maintenance().unwrap();
    assert_eq!(machine.host.counter_reads, reads);

    hub.set_live(1, true);
    let attached = machine.attached.take().unwrap();
    machine.post(Maintenance::Code(None));
    machine.send_outgoing();
    hub.set_live(1, false);
    machine.complete_maintenance().unwrap();
    assert_eq!(hub.broadcast_profile(0), Some(observed));
    machine.attached = Some(attached);
}

#[test]
fn maintenance_waits_for_the_dsb_and_reaches_a_pe_in_one_piece_of_mail() {
    let (hub, _) = hub(2);
    let mut machine = first_of_two(&[], &hub);
    machine.post(Maintenance::Code(Some(0x4000)));
    machine.post(Maintenance::Code(Some(0x8000)));
    assert!(hub.take(1).is_none());

    machine.send_outgoing();
    hub.set_live(1, false);
    machine.complete_maintenance().unwrap();
    let mail = hub.take(1).unwrap();
    assert_eq!(mail.maintenance.len(), 2);
    assert_eq!(mail.serial, 1);
}

#[test]
fn a_broadcast_passes_by_a_pe_outside_its_run() {
    let (hub, _) = hub(2);
    let mut machine = first_of_two(&[], &hub);
    let posted = hub.broadcast(1, &[Maintenance::Code(None)]);
    assert!(!hub.applied(&mut posted.clone()));
    machine.outside_run(|_| assert!(hub.applied(&mut posted.clone())));
    assert!(!hub.applied(&mut posted.clone()));
}

#[test]
fn a_full_list_of_maintenance_goes_out_without_a_dsb() {
    let (hub, _) = hub(2);
    let mut machine = first_of_two(&[], &hub);
    for page in 0..OUTGOING as u64 {
        machine.post(Maintenance::Code(Some(page << 14)));
    }
    assert_eq!(hub.take(1).unwrap().maintenance.len(), OUTGOING);
}

#[test]
fn a_page_invalidation_the_pe_has_yet_to_read_covers_the_same_page_again() {
    let (hub, _) = hub(2);
    let mut machine = first_of_two(&[], &hub);
    machine.post(Maintenance::Code(Some(0x4000)));
    machine.post(Maintenance::Code(Some(0x4000)));
    machine.post(Maintenance::Code(Some(0x8000)));
    machine.post(Maintenance::Code(None));
    machine.post(Maintenance::Code(Some(0xc000)));
    machine.send_outgoing();
    let mail = hub.take(1).unwrap();
    let pages: Vec<_> = mail
        .maintenance
        .iter()
        .map(|maintenance| match maintenance {
            Maintenance::Code(page) => *page,
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(pages, [Some(0x4000), Some(0x8000), None]);
    // The PE's acknowledgment of this mail is the one waited for.
    assert_eq!((mail.serial, machine.posted.as_slice()), (1, &[(1, 1)][..]));
}

#[test]
fn an_ic_ivau_reaches_other_pes_only_for_compiled_pages_once_per_dsb() {
    const PAGE: u64 = 0x4000_0000;
    let (hub, _) = hub(2);
    let mut machine = first_of_two(&[], &hub);
    // No PE compiled from it: the IC IVAU of each line stops here.
    machine.post_code_page(PAGE);
    assert!(machine.outgoing.is_empty());
    // The next lines of a page add nothing to its first one.
    hub.compiling(PAGE + 0x100);
    machine.post_code_page(PAGE + 0x40);
    machine.post_code_page(PAGE + 0x80);
    assert_eq!(machine.outgoing.len(), 1);
    // A DSB ends the run: what follows may have been written since.
    machine.send_outgoing();
    let mail = hub.take(1).unwrap();
    hub.acknowledge(1, mail.serial);
    machine.complete_maintenance().unwrap();
    machine.post_code_page(PAGE + 0x40);
    assert_eq!(machine.outgoing.len(), 1);
}

#[test]
fn maintenance_posted_to_another_pe_completes_at_the_next_dsb() {
    let (hub, _) = hub(2);
    // DSB ISH.
    let mut machine = first_of_two(&[0xd503_3b9f], &hub);
    machine.post(Maintenance::Code(Some(0x4000)));
    machine.send_outgoing();
    assert_eq!(machine.posted, [(1, 1)]);
    // PE 1 reads its mail at its next return to the engine.
    let mail = hub.take(1).unwrap();
    hub.acknowledge(1, mail.serial);
    machine.host.exits = vec![super::super::NativeExit::Exit {
        next_pc: super::super::tests::BASE,
        kind: stela_compiler::block::ExitKind::System as u64,
    }];
    machine.step().unwrap();
    assert!(machine.posted.is_empty());
    assert_eq!(machine.cpu.pc, super::super::tests::BASE + 4);
    // A PE outside its run loop reads its mail before it runs again: the
    // completion does not wait for it.
    machine.post(Maintenance::Code(None));
    hub.set_outside(1, true);
    machine.complete_maintenance().unwrap();
    assert!(machine.posted.is_empty());
    assert!(hub.take(1).is_some());
}

#[test]
fn notification_after_drain_survives_native_budget_reset() {
    use super::super::tests::machine;
    let mut machine = machine(&[0xd503_201f]);
    let (hub, _) = hub(1);
    machine.enter_parallel(Arc::clone(&hub)).unwrap();
    hub.post(0, |mail| mail.event = true);
    machine.read_mail().unwrap();
    let drained = machine.chain.snapshot();
    assert_eq!(drained.interrupt_epoch, drained.observed_interrupt_epoch);
    // This is the old lost-notification window: the owner has drained,
    // then a peer posts before the owner initializes its next budget.
    hub.post(0, |mail| mail.event = true);
    machine.chain.begin(0, 4096);
    let entered = machine.chain.snapshot();
    assert_eq!(entered.budget, 4096);
    assert_ne!(entered.interrupt_epoch, entered.observed_interrupt_epoch);
    assert_eq!(entered.observed_interrupt_epoch, drained.interrupt_epoch);
    machine.read_mail().unwrap();
    let next = machine.chain.snapshot();
    assert_eq!(next.interrupt_epoch, next.observed_interrupt_epoch);
}

#[test]
fn epoch_exhaustion_is_sticky_across_drain_detach_and_reuse() {
    use super::super::tests::machine;
    let mut machine = machine(&[0xd503_201f]);
    let (hub, _) = hub(1);
    machine.enter_parallel(Arc::clone(&hub)).unwrap();
    hub.inboxes[0]
        .chain
        .interrupt_epoch()
        .store(u64::MAX - 1, Ordering::Relaxed);
    hub.post(0, |mail| mail.event = true);
    machine.read_mail().unwrap();
    hub.interrupt(0);
    let exhausted = machine.chain.snapshot();
    assert_eq!(exhausted.interrupt_epoch, u64::MAX);
    assert_eq!(exhausted.observed_interrupt_epoch, u64::MAX - 1);
    drop(machine);
    let (_, mut next) = Attached::new(&hub, 0, false).unwrap();
    next.initialize(11, [12, 13]);
    next.acknowledge_interrupt(u64::MAX);
    next.begin(0, 4096);
    let reused = next.snapshot();
    assert_eq!(reused.interrupt_epoch, u64::MAX);
    assert_eq!(reused.observed_interrupt_epoch, u64::MAX - 1);
}

#[test]
fn mail_reaches_running_pes_and_kicks_only_a_sleeping_one() {
    let (hub, kicks) = hub(3);
    hub.event(0);
    assert_eq!(kicks.load(Ordering::Relaxed), 0, "no PE sleeps");
    assert!(hub.take(0).is_none(), "SEV reaches the others");
    assert!(hub.take(1).is_some_and(|mail| mail.event));
    // A PE that sleeps halts only without mail, and mail kicks it.
    let mut halts = 0;
    hub.sleep(1, hub.lines_epoch(1), || halts += 1);
    assert_eq!(halts, 1);
    hub.sleep(2, hub.lines_epoch(2), || halts += 1);
    assert_eq!(halts, 1, "PE 2 has mail");
    hub.inboxes[1].sleeping.store(true, Ordering::SeqCst);
    hub.start(1, 0x8000);
    assert_eq!(kicks.load(Ordering::Relaxed), 1);
}

#[test]
fn a_broadcast_is_applied_once_every_running_pe_acknowledged_it() {
    let (hub, kicks) = hub(3);
    let (attached, control) = Attached::new(&hub, 1, false).unwrap();
    control.budget().store(4096, Ordering::Relaxed);
    let mut posted = hub.broadcast(0, &[Maintenance::Code(None)]);
    assert_eq!(posted, [(1, 1), (2, 1)]);
    assert!(!hub.applied(&mut posted));
    // The running PE leaves native code at its next chained transfer.
    drop(attached);
    assert_eq!(control.budget().load(Ordering::Relaxed), 4096);
    let interrupted = control.snapshot();
    assert_ne!(
        interrupted.interrupt_epoch,
        interrupted.observed_interrupt_epoch
    );
    let mail = hub.take(1).unwrap();
    assert_eq!((mail.maintenance.len(), mail.serial), (1, 1));
    hub.acknowledge(1, mail.serial);
    assert!(!hub.applied(&mut posted));
    assert_eq!(posted, [(2, 1)]);
    // A PE that sleeps is neither woken nor waited for: it reads its
    // mail before it runs again.
    hub.inboxes[2].sleeping.store(true, Ordering::SeqCst);
    assert!(hub.applied(&mut posted));
    assert_eq!(kicks.load(Ordering::Relaxed), 0);
    hub.inboxes[2].sleeping.store(false, Ordering::SeqCst);
    assert!(hub.take(2).is_some_and(|mail| mail.serial == 1));
    // A PE that no longer reads mail holds no broadcast up.
    let mut posted = hub.broadcast(0, &[Maintenance::Code(None)]);
    hub.set_live(2, false);
    hub.acknowledge(1, 2);
    assert!(hub.applied(&mut posted));
    // Serials keep counting after a take.
    assert_eq!(hub.broadcast(0, &[Maintenance::Code(None)]), [(1, 3)]);
}

#[test]
fn a_host_call_ends_a_run_and_wakes_a_sleeping_pe() {
    let (hub, kicks) = hub(2);
    let (attached, control) = Attached::new(&hub, 1, false).unwrap();
    hub.call_host(1);
    let interrupted = control.snapshot();
    assert_ne!(
        interrupted.interrupt_epoch,
        interrupted.observed_interrupt_epoch
    );
    assert_eq!(kicks.load(Ordering::Relaxed), 0);
    assert!(hub.take_host_call(1));
    assert!(!hub.take_host_call(1), "taken once");
    drop(attached);
    // A sleep does not start over a call, and a sleeper is woken for one.
    hub.call_host(1);
    let mut halted = false;
    hub.sleep(1, 0, || halted = true);
    assert!(!halted);
    assert!(hub.take_host_call(1));
    hub.inboxes[1].sleeping.store(true, Ordering::SeqCst);
    hub.call_host(1);
    assert_eq!(kicks.load(Ordering::Relaxed), 1);
    hub.inboxes[1].sleeping.store(false, Ordering::SeqCst);
}

#[test]
fn a_line_notification_observes_pins_before_the_producer_unlocks() {
    #[derive(Default)]
    struct Latched(Lines);
    impl Devices for Latched {
        fn read(&mut self, _: usize, _: u64, _: u8, _: u64) -> Result<u64, DeviceError> {
            Ok(0)
        }
        fn write(&mut self, _: usize, _: u64, _: u8, _: u64, _: u64) -> Result<(), DeviceError> {
            Ok(())
        }
        fn lines(&mut self, pe: usize, _: u64) -> Lines {
            if pe == 1 { self.0 } else { Lines::default() }
        }
        fn pins(&mut self, pe: usize) -> Option<Lines> {
            Some(self.lines(pe, 0))
        }
    }
    struct ReadPins {
        worker: Arc<Mutex<Option<SharedDevices<Latched>>>>,
        observed: Arc<Mutex<Vec<Lines>>>,
    }
    impl Kick for ReadPins {
        fn kick(&self, pe: usize) {
            // A receiver may run as soon as it is notified, before the
            // producer releases the board lock. Latched pins are lockless.
            let mut worker = self.worker.lock().unwrap();
            let worker = worker.as_mut().unwrap();
            assert!(worker.board.devices.try_lock().is_err());
            let lines = worker.lines(pe, 0);
            self.observed.lock().unwrap().push(lines);
        }
    }
    let worker = Arc::new(Mutex::new(None));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let hub = Hub::new(
        2,
        ReadPins {
            worker: Arc::clone(&worker),
            observed: Arc::clone(&observed),
        },
    );
    for pe in 0..2 {
        hub.set_live(pe, true);
    }
    let home = SharedDevices::new(Latched::default(), Arc::clone(&hub));
    *worker.lock().unwrap() = Some(home.worker());
    let changes = [
        Lines {
            irq: true,
            fiq: false,
        },
        Lines {
            irq: false,
            fiq: true,
        },
        Lines::default(),
    ];
    for lines in changes {
        hub.inboxes[1].sleeping.store(true, Ordering::SeqCst);
        home.serve(|devices| devices.0 = lines);
    }
    worker.lock().unwrap().take();
    assert_eq!(*observed.lock().unwrap(), changes);
}

/// A write of 1 requests a restart, of 2 starts PE 1 at 0x800 and of 3
/// leaves bytes for the host; any other value sets the DMA deadline, 0
/// clearing it. Also raises PE 1's IRQ from count `irq_at`.
#[derive(Default)]
struct Pending {
    reset: Option<Reset>,
    dma: Option<u64>,
    irq_at: Option<u64>,
    starts: Vec<Start>,
    service: bool,
    register_calls: usize,
}

/// The one IMPLEMENTATION DEFINED register [`Pending`] serves.
const SERVED: Encoding = Encoding::new(3, 5, 15, 0, 1);

impl Devices for Pending {
    fn read(&mut self, _: usize, _: u64, _: u8, _: u64) -> Result<u64, DeviceError> {
        Ok(0)
    }
    fn write(&mut self, _: usize, _: u64, _: u8, value: u64, _: u64) -> Result<(), DeviceError> {
        match value {
            1 => {
                self.reset = Some(Reset {
                    transition: stela_contracts::bus::Transition::Restart,
                    reason: "test".into(),
                })
            }
            2 => self.starts.push(Start {
                cpu: 1,
                address: 0x800,
            }),
            3 => self.service = true,
            0 => self.dma = None,
            deadline => self.dma = Some(deadline),
        }
        Ok(())
    }
    fn lines(&mut self, pe: usize, now: u64) -> Lines {
        Lines {
            irq: pe == 1 && self.irq_at.is_some_and(|at| now >= at),
            ..Lines::default()
        }
    }
    fn deadline(&mut self, now: u64) -> Option<u64> {
        self.irq_at.filter(|&at| at > now)
    }
    fn take_reset(&mut self) -> Option<Reset> {
        self.reset.take()
    }
    fn take_start(&mut self) -> Option<Start> {
        self.starts.pop()
    }
    fn dma_deadline(&self) -> Option<u64> {
        self.dma
    }
    fn take_host_service(&mut self) -> bool {
        core::mem::take(&mut self.service)
    }
    fn system_register(
        &mut self,
        _: usize,
        encoding: Encoding,
        _: Option<u64>,
        _: u64,
    ) -> Option<Result<u64, &'static str>> {
        self.register_calls += 1;
        (encoding == SERVED).then_some(Ok(7))
    }
    fn serves_register(&self, encoding: Encoding) -> bool {
        encoding == SERVED
    }
}

#[test]
fn only_the_registers_the_devices_serve_reach_them() {
    let (hub, _) = hub(2);
    let mut worker = SharedDevices::new(Pending::default(), hub).worker();
    assert_eq!(worker.system_register(1, SERVED, None, 0), Some(Ok(7)));
    let other = Encoding::new(3, 6, 15, 1, 0);
    assert_eq!(worker.system_register(1, other, Some(1), 0), None);
    assert!(worker.serves_register(SERVED) && !worker.serves_register(other));
    assert_eq!(worker.with(|devices| devices.register_calls), 1);
}

#[test]
fn bytes_for_the_host_wake_one_sleeping_pe_and_reach_one_machine_once() {
    let (hub, kicks) = hub(3);
    let home = SharedDevices::new(Pending::default(), Arc::clone(&hub));
    let mut worker = home.worker();
    // With no PE asleep, the next to wait takes it, and none halts
    // meanwhile.
    worker.write(1, 0, 4, 3, 0).unwrap();
    assert_eq!(kicks.load(Ordering::Relaxed), 0);
    let mut halts = 0;
    hub.sleep(2, hub.lines_epoch(2), || halts += 1);
    assert_eq!(halts, 0, "the service is due");
    let mut home = home;
    assert!(home.take_host_service());
    assert!(!worker.take_host_service(), "taken once");
    // One sleeping PE wakes for it, and a request already due wakes none.
    hub.inboxes[1].sleeping.store(true, Ordering::SeqCst);
    hub.inboxes[2].sleeping.store(true, Ordering::SeqCst);
    worker.write(1, 0, 4, 3, 0).unwrap();
    worker.write(1, 0, 4, 3, 0).unwrap();
    assert_eq!(kicks.load(Ordering::Relaxed), 1);
    assert!(worker.take_host_service());
}

#[test]
fn the_home_machine_sees_any_pes_reset_and_dma_without_the_lock() {
    let (hub, _) = hub(2);
    let mut home = SharedDevices::new(
        Pending {
            dma: Some(7),
            ..Pending::default()
        },
        hub,
    );
    let mut worker = home.worker();
    assert_eq!(home.dma_deadline(), Some(7), "as the board was made");
    worker.write(1, 0, 4, 90, 0).unwrap();
    assert_eq!(
        (home.dma_deadline(), worker.dma_deadline()),
        (Some(90), None)
    );
    worker.write(1, 0, 4, 0, 0).unwrap();
    assert_eq!(home.dma_deadline(), None);
    // A reset another PE's access requested reaches the home machine
    // once, and never the worker.
    worker.write(1, 0, 4, 1, 0).unwrap();
    assert!(worker.take_reset().is_none());
    assert!(
        home.take_reset()
            .is_some_and(|reset| reset.reason == "test")
    );
    assert!(home.take_reset().is_none());
    // A start reaches whichever machine asks first, once.
    home.write(0, 0, 4, 2, 0).unwrap();
    worker.write(1, 0, 4, 2, 0).unwrap();
    let start = worker.take_start().unwrap();
    assert_eq!((start.cpu, start.address), (1, 0x800));
    assert!(home.take_start().is_some());
    assert!(home.take_start().is_none() && worker.take_start().is_none());
    assert_eq!(home.waits(), [0; Call::ALL.len()]);
}

#[test]
fn only_the_home_machine_advances_the_devices_with_time_and_tells_the_others() {
    let (hub, _) = hub(2);
    let mut home = SharedDevices::new(
        Pending {
            irq_at: Some(20),
            ..Pending::default()
        },
        Arc::clone(&hub),
    );
    let mut worker = home.worker();
    assert_eq!(worker.deadline(10), None, "the worker waits to be told");
    assert_eq!(home.deadline(10), Some(20));
    let epoch = hub.lines_epoch(1);
    assert_eq!(home.deadline(25), None);
    assert_eq!(hub.lines_epoch(1), epoch + 1, "PE 1's IRQ rose");
    assert!(worker.lines(1, 25).irq);
    // Asking again changes nothing.
    home.deadline(30);
    assert_eq!(hub.lines_epoch(1), epoch + 1);
}

#[test]
fn a_pe_without_a_machine_waits_for_its_first_start() {
    let (hub, _) = hub(2);
    hub.event(0);
    hub.start(1, 0x1000);
    let mut halts = 0;
    assert_eq!(hub.first_start(1, || halts += 1), 0x1000);
    assert_eq!(halts, 0);
}

#[test]
fn a_shared_board_classifies_and_serves_a_scalar_access_in_one_call() {
    use super::super::tests::board;
    use stela_contracts::identity::Identity;
    const CANONICAL: u64 = 0x10;
    const SAMPLER: u64 = 0x20;
    #[derive(Default)]
    struct Classified {
        reads: usize,
        writes: usize,
    }
    impl Devices for Classified {
        fn pc_sample_target(&self, physical: u64, _: u8) -> Option<usize> {
            (physical == SAMPLER).then_some(1)
        }
        fn requires_canonical_read(&self, _: usize, physical: u64, _: DeviceReadShape) -> bool {
            physical == CANONICAL
        }
        fn requires_canonical_write(&self, _: usize, physical: u64, _: u8) -> bool {
            physical == CANONICAL
        }
        fn read(&mut self, _: usize, _: u64, _: u8, _: u64) -> Result<u64, DeviceError> {
            self.reads += 1;
            Ok(7)
        }
        fn write(&mut self, _: usize, _: u64, _: u8, _: u64, _: u64) -> Result<(), DeviceError> {
            self.writes += 1;
            Ok(())
        }
        fn lines(&mut self, _: usize, _: u64) -> Lines {
            Lines::default()
        }
    }
    let (hub, _) = hub(2);
    let mut worker = SharedDevices::new(Classified::default(), hub).worker();
    assert_eq!(worker.read_scalar(1, 0x30, 4, 0), ScalarRead::Served(Ok(7)));
    assert_eq!(
        worker.read_scalar(1, CANONICAL, 4, 0),
        ScalarRead::Canonical
    );
    assert_eq!(worker.read_scalar(1, SAMPLER, 4, 0), ScalarRead::Sample(1));
    let identities = vec![Identity {
        midr: 0x611f_0320,
        mpidr: 0x8000_0000,
        clock: None,
        caches: None,
    }];
    let mut machine = board(&[], worker, identities);
    let (devices, processors) = machine.processor_write_parts();
    assert!(
        devices
            .write_plain(0, CANONICAL, 4, 1, 0, processors)
            .is_none()
    );
    let (devices, processors) = machine.processor_write_parts();
    assert_eq!(
        devices.write_plain(0, 0x30, 4, 1, 0, processors),
        Some(Ok(()))
    );
    // Only the plain accesses reached the registers.
    assert_eq!(
        machine
            .devices
            .with(|devices| (devices.reads, devices.writes)),
        (1, 1)
    );
}

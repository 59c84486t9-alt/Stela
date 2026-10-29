//! Closed Host effects on a recovered, held physical worker. No CPU, Machine,
//! raw callback or borrowed Host is transported to another core.
use super::*;
use crate::machine::{
    Regime,
    mmu::tlbi::{Everywhere, Reach},
};
use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The owner-local part of stopped source-instruction settlement. RAM access
/// stays with the canonical all-writer owner; native entry uses NativeLoan.
#[derive(Debug)]
pub enum HostEffect {
    Regime(Box<Regime>),
    InvalidateTranslations,
    InvalidateReach(Reach, Everywhere),
    IsolatePredictions,
    CodeInvalidated(Option<u64>),
    ArmTimer(Option<u64>),
    DiscardCode,
    MemoryBarrier,
}

#[derive(Debug)]
pub(super) struct ServiceIdentity {
    open: AtomicBool,
    completed: AtomicU64,
}
impl ServiceIdentity {
    fn reopen(mut closed: Arc<Self>) -> Option<Arc<Self>> {
        // A stale command/receipt or even a Weak observer must keep its old
        // identity permanently separate. Only an unaliased closed allocation
        // can become the next session; pointer equality alone is insufficient.
        let identity = Arc::get_mut(&mut closed)?;
        if *identity.open.get_mut() {
            return None;
        }
        *identity.completed.get_mut() = 0;
        *identity.open.get_mut() = true;
        Some(closed)
    }
}

/// A linear service session for one worker in one actual stopped cohort.
/// Dropping it cannot release that cohort. Only one effect may be outstanding;
/// its actual owner's receipt is required before another effect or close.
#[derive(Debug)]
#[must_use = "close the actual service session before releasing its cohort"]
pub struct WorkerServices {
    identity: Arc<Identity>,
    session: Arc<ServiceIdentity>,
    binding: WorkerBinding,
    stop: u64,
    issued: u64,
    pending: bool,
}

#[derive(Debug)]
#[must_use = "apply on the assigned held physical Host"]
pub struct HostEffectCommand {
    identity: Arc<Identity>,
    session: Arc<ServiceIdentity>,
    binding: WorkerBinding,
    stop: u64,
    sequence: u64,
    effect: HostEffect,
}

#[derive(Debug)]
#[must_use = "consume the actual Host effect receipt in its service session"]
pub struct HostEffectReceipt {
    command: HostEffectCommand,
}

impl WorkerPublications {
    /// Exact explicit roster for leaf services which borrow only instantiated
    /// Cpu owners. Whole-ProcessorWrite still requires its full modeled roster.
    pub(in crate::machine::engine) fn require_held_members(
        &self,
        members: &[usize],
    ) -> Result<(), PublicationError> {
        self.require_held_roster(members.iter().copied())
    }
    /// Borrow either source PE numbers or the existing held binding slice;
    /// membership validation never needs a temporary owning allocation.
    fn require_held_roster(
        &self,
        members: impl ExactSizeIterator<Item = usize> + Clone,
    ) -> Result<(), PublicationError> {
        let count = members.len();
        if count == 0
            || self.slots.len() != count
            || self
                .slots
                .iter()
                .any(|slot| !members.clone().any(|pe| pe == slot.binding.pe))
            || members
                .clone()
                .enumerate()
                .any(|(i, pe)| members.clone().take(i).any(|before| before == pe))
        {
            return Err(PublicationError::ProcessorCount {
                expected: count,
                actual: self.slots.len(),
            });
        }
        let mut generation = None;
        for slot in &self.slots {
            if !matches!(slot.frame, Frame::Recovered(_)) {
                return Err(PublicationError::InFlight);
            }
            let Some((stop, StopPhase::Held)) = slot.stop else {
                return Err(PublicationError::MissingInvalidation);
            };
            if generation.is_some_and(|before| before != stop) {
                return Err(PublicationError::StaleStop);
            }
            generation = Some(stop);
        }
        Ok(())
    }
    pub(in crate::machine::engine) fn require_all_held(
        &self,
        held: &StoppedWorkers,
    ) -> Result<(), PublicationError> {
        self.check_stop(&held.request, StopPhase::Held)?;
        self.require_held_roster(held.request.members.iter().map(|binding| binding.pe))
    }
    pub(in crate::machine::engine) fn require_recovered(
        &self,
        binding: WorkerBinding,
        generation: u64,
    ) -> Result<(), PublicationError> {
        let slot = &self.slots[self.slot(binding.pe)?];
        if slot.binding != binding || slot.frame != Frame::Recovered(Some(generation)) {
            return Err(PublicationError::StaleRun);
        }
        Ok(())
    }

    pub fn bindings(&self) -> impl Iterator<Item = WorkerBinding> + '_ {
        self.slots.iter().map(|slot| slot.binding)
    }

    pub fn open_services(
        &mut self,
        held: &StoppedWorkers,
        pe: usize,
    ) -> Result<WorkerServices, PublicationError> {
        self.check_stop(&held.request, StopPhase::Held)?;
        let index = self.slot(pe)?;
        let slot = &mut self.slots[index];
        if !held.request.members.contains(&slot.binding) {
            return Err(PublicationError::UnknownPe(pe));
        }
        if slot.services.is_some() {
            return Err(PublicationError::ServiceBusy);
        }
        let session = slot
            .closed_services
            .take()
            .and_then(ServiceIdentity::reopen)
            .unwrap_or_else(|| {
                Arc::new(ServiceIdentity {
                    open: AtomicBool::new(true),
                    completed: AtomicU64::new(0),
                })
            });
        slot.services = Some(Arc::clone(&session));
        Ok(WorkerServices {
            identity: Arc::clone(&self.identity),
            session,
            binding: slot.binding,
            stop: held.request.generation,
            issued: 0,
            pending: false,
        })
    }

    pub fn close_services(
        &mut self,
        services: WorkerServices,
    ) -> Result<(), WithPayload<WorkerServices>> {
        let check = (|| {
            self.identity(&services.identity)?;
            let index = self.slot(services.binding.pe)?;
            let slot = &self.slots[index];
            if slot.binding != services.binding
                || slot.stop != Some((services.stop, StopPhase::Held))
                || !slot
                    .services
                    .as_ref()
                    .is_some_and(|session| Arc::ptr_eq(session, &services.session))
            {
                return Err(PublicationError::StaleService);
            }
            if services.pending
                || services.session.completed.load(Ordering::Acquire) != services.issued
            {
                return Err(PublicationError::ServiceBusy);
            }
            Ok(index)
        })();
        match check {
            Ok(index) => {
                services.session.open.store(false, Ordering::Release);
                self.slots[index].services = None;
                // Consume the actual completed session, after all existing
                // generation/pending/receipt checks. The next open must prove
                // that no reference to this closed identity survives.
                self.slots[index].closed_services = Some(services.session);
                Ok(())
            }
            Err(error) => Err(WithPayload {
                error,
                payload: services,
            }),
        }
    }
}

impl WorkerServices {
    pub fn binding(&self) -> WorkerBinding {
        self.binding
    }

    pub fn command(&mut self, effect: HostEffect) -> Result<HostEffectCommand, PublicationError> {
        if self.pending {
            return Err(PublicationError::ServiceBusy);
        }
        if !self.session.open.load(Ordering::Acquire) {
            return Err(PublicationError::StaleService);
        }
        let sequence = self
            .issued
            .checked_add(1)
            .ok_or(PublicationError::GenerationExhausted)?;
        self.issued = sequence;
        self.pending = true;
        Ok(HostEffectCommand {
            identity: Arc::clone(&self.identity),
            session: Arc::clone(&self.session),
            binding: self.binding,
            stop: self.stop,
            sequence,
            effect,
        })
    }

    pub fn accept(
        &mut self,
        receipt: HostEffectReceipt,
    ) -> Result<(), WithPayload<HostEffectReceipt>> {
        let command = &receipt.command;
        if !self.pending
            || !Arc::ptr_eq(&self.identity, &command.identity)
            || !Arc::ptr_eq(&self.session, &command.session)
            || self.binding != command.binding
            || self.stop != command.stop
            || self.issued != command.sequence
            || self.session.completed.load(Ordering::Acquire) != command.sequence
        {
            return Err(WithPayload {
                error: PublicationError::StaleService,
                payload: receipt,
            });
        }
        self.pending = false;
        Ok(())
    }
}

impl HostEffectCommand {
    pub fn binding(&self) -> WorkerBinding {
        self.binding
    }
    pub fn generation(&self) -> u64 {
        self.stop
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn effect_name(&self) -> &'static str {
        match self.effect {
            HostEffect::Regime(_) => "regime",
            HostEffect::InvalidateTranslations => "invalidate",
            HostEffect::InvalidateReach(..) => "reach",
            HostEffect::IsolatePredictions => "isolate",
            HostEffect::CodeInvalidated(_) => "code",
            HostEffect::ArmTimer(_) => "timer",
            HostEffect::DiscardCode => "discard",
            HostEffect::MemoryBarrier => "cpu-memory-fence",
        }
    }
}

impl WorkerOwner {
    pub fn apply_host_effect(
        &mut self,
        command: HostEffectCommand,
        host: &mut dyn Host,
    ) -> Result<HostEffectReceipt, WithPayload<HostEffectCommand>> {
        let check = self.check(&command.identity, command.binding)
            .and_then(|()| self.check_host(host))
            .and_then(|()| {
                if !matches!(self.state, OwnerState::Held { generation, .. } if generation == command.stop)
                    || !command.session.open.load(Ordering::Acquire)
                    || command.session.completed.load(Ordering::Acquire).checked_add(1) != Some(command.sequence)
                {
                    Err(PublicationError::StaleService)
                } else {
                    Ok(())
                }
            });
        if let Err(error) = check {
            return Err(WithPayload {
                error,
                payload: command,
            });
        }
        match &command.effect {
            HostEffect::Regime(regime) => host.set_regime(regime),
            HostEffect::InvalidateTranslations => host.invalidate_translations(),
            HostEffect::InvalidateReach(reach, everywhere) => {
                host.invalidate_reach(*reach, *everywhere)
            }
            HostEffect::IsolatePredictions => host.isolate_predictions(),
            HostEffect::CodeInvalidated(page) => host.code_invalidated(*page),
            HostEffect::ArmTimer(deadline) => host.arm_timer(*deadline),
            HostEffect::DiscardCode => host.discard_code(),
            HostEffect::MemoryBarrier => host.memory_barrier(),
        }
        command
            .session
            .completed
            .store(command.sequence, Ordering::Release);
        Ok(HostEffectReceipt { command })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::{InstallError, NativeCode, NativeExit};
    use stela_compiler::GuestState;

    struct LocalHost {
        worker: WorkerId,
        effects: Vec<&'static str>,
        regime: Option<Regime>,
    }
    impl Host for LocalHost {
        fn native_worker(&self) -> Option<WorkerId> {
            Some(self.worker)
        }
        fn read_ram(&mut self, _: u64, _: &mut [u8]) -> bool {
            unreachable!()
        }
        fn write_ram(&mut self, _: u64, _: &[u8]) -> bool {
            unreachable!()
        }
        fn install(&mut self, _: &[u8]) -> Result<NativeCode, InstallError> {
            unreachable!()
        }
        fn patch(&mut self, _: NativeCode, _: &[u8]) {
            unreachable!()
        }
        fn discard_code(&mut self) {
            self.effects.push("discard");
        }
        unsafe fn execute(&mut self, _: NativeCode, _: &mut GuestState) -> NativeExit {
            unreachable!()
        }
        fn set_regime(&mut self, regime: &Regime) {
            self.regime = Some(*regime);
            self.effects.push("regime");
        }
        fn invalidate_translations(&mut self) {
            self.effects.push("invalidate");
        }
        fn invalidate_reach(&mut self, _: Reach, _: Everywhere) {
            self.effects.push("reach");
        }
        fn isolate_predictions(&mut self) {
            self.effects.push("isolate");
        }
        fn code_invalidated(&mut self, _: Option<u64>) {
            self.effects.push("code");
        }
        fn counter(&mut self) -> u64 {
            unreachable!()
        }
        fn arm_timer(&mut self, _: Option<u64>) {
            self.effects.push("timer");
        }
        fn wait_for_interrupt(&mut self) {
            unreachable!()
        }
    }
    fn held() -> (
        WorkerPublications,
        Vec<WorkerOwner>,
        Vec<LocalHost>,
        StoppedWorkers,
    ) {
        let bindings = [
            WorkerBinding {
                pe: 0,
                worker: WorkerId(17),
            },
            WorkerBinding {
                pe: 1,
                worker: WorkerId(42),
            },
        ];
        let (mut inventory, mut owners) = WorkerPublications::new(&bindings).unwrap();
        let mut hosts: Vec<_> = bindings
            .iter()
            .map(|binding| LocalHost {
                worker: binding.worker,
                effects: Vec::new(),
                regime: None,
            })
            .collect();
        for (owner, host) in owners.iter_mut().zip(&mut hosts) {
            inventory
                .accept_initial(owner.publish_initial(host).unwrap())
                .unwrap();
        }
        let request = inventory.request_stop(&[0, 1]).unwrap();
        for ((command, owner), host) in inventory
            .native_stop_commands(&request)
            .unwrap()
            .into_iter()
            .zip(&mut owners)
            .zip(&mut hosts)
        {
            inventory
                .accept_invalidation(owner.invalidate(command, host).unwrap())
                .unwrap();
        }
        let held = inventory.hold_stop(request).unwrap();
        (inventory, owners, hosts, held)
    }
    #[test]
    fn complete_held_roster_accepts_permutations_and_rejects_missing_or_duplicate_members() {
        let (inventory, _, _, mut stopped) = held();
        assert_eq!(inventory.require_all_held(&stopped), Ok(()));
        stopped.request.members.reverse();
        assert_eq!(inventory.require_all_held(&stopped), Ok(()));
        assert_eq!(inventory.require_held_members(&[1, 0]), Ok(()));

        // Start with actual owner-fenced receipts, then corrupt only the test
        // token. Its repeated member must not stand in for the omitted owner.
        stopped.request.members[1] = stopped.request.members[0];
        assert_eq!(
            inventory.require_all_held(&stopped),
            Err(PublicationError::ProcessorCount {
                expected: 2,
                actual: 2,
            })
        );
        stopped.request.members.pop();
        assert_eq!(
            inventory.require_all_held(&stopped),
            Err(PublicationError::ProcessorCount {
                expected: 1,
                actual: 2,
            })
        );
        stopped.request.members.clear();
        assert_eq!(
            inventory.require_all_held(&stopped),
            Err(PublicationError::ProcessorCount {
                expected: 0,
                actual: 2,
            })
        );
    }

    #[test]
    fn held_roster_checks_inventory_binding_and_generation_before_membership() {
        let (inventory, _, _, mut stopped) = held();
        let (foreign, _, _, _) = held();
        stopped.request.members.pop();
        assert_eq!(
            foreign.require_all_held(&stopped),
            Err(PublicationError::WrongInventory)
        );
        let worker = stopped.request.members[0].worker;
        stopped.request.members[0].worker = WorkerId(worker.0 + 1);
        assert_eq!(
            inventory.require_all_held(&stopped),
            Err(PublicationError::StaleStop)
        );
        stopped.request.members[0].worker = worker;
        stopped.request.generation += 1;
        assert_eq!(
            inventory.require_all_held(&stopped),
            Err(PublicationError::StaleStop)
        );
    }

    #[test]
    fn held_roster_requires_each_actual_frame_and_completed_hold() {
        let (mut inventory, _, _, stopped) = held();
        inventory.slots[1].frame = Frame::InFlight(stopped.request.generation);
        assert_eq!(
            inventory.require_all_held(&stopped),
            Err(PublicationError::InFlight)
        );
        assert_eq!(
            inventory.require_held_members(&[0, 1]),
            Err(PublicationError::InFlight)
        );
        inventory.slots[1].frame = Frame::Recovered(None);
        for phase in [
            None,
            Some(StopPhase::Requested),
            Some(StopPhase::Invalidated),
        ] {
            inventory.slots[1].stop = phase.map(|phase| (stopped.request.generation, phase));
            assert_eq!(
                inventory.require_all_held(&stopped),
                Err(PublicationError::StaleStop)
            );
            assert_eq!(
                inventory.require_held_members(&[0, 1]),
                Err(PublicationError::MissingInvalidation)
            );
        }
        inventory.slots[1].stop = Some((stopped.request.generation + 1, StopPhase::Held));
        assert_eq!(
            inventory.require_all_held(&stopped),
            Err(PublicationError::StaleStop)
        );
        assert_eq!(
            inventory.require_held_members(&[0, 1]),
            Err(PublicationError::StaleStop)
        );
        inventory.slots[1].stop = Some((stopped.request.generation, StopPhase::Held));
        assert_eq!(inventory.require_all_held(&stopped), Ok(()));
    }

    #[test]
    fn held_roster_membership_error_precedes_frame_state_error() {
        let (mut inventory, _, _, mut stopped) = held();
        inventory.slots[1].frame = Frame::InFlight(stopped.request.generation);
        assert_eq!(
            inventory.require_held_members(&[0, 0]),
            Err(PublicationError::ProcessorCount {
                expected: 2,
                actual: 2,
            })
        );
        // check_stop observes only the token's first owner; whole membership
        // still rejects the partial token before checking an omitted frame.
        stopped.request.members.pop();
        assert_eq!(
            inventory.require_all_held(&stopped),
            Err(PublicationError::ProcessorCount {
                expected: 1,
                actual: 2,
            })
        );
        stopped.request.members[0].pe = usize::MAX;
        assert_eq!(
            inventory.require_all_held(&stopped),
            Err(PublicationError::UnknownPe(usize::MAX))
        );
    }

    #[test]
    fn sparse_leaf_roster_hold_does_not_authorize_whole_processor_write() {
        let binding = WorkerBinding {
            pe: 7,
            worker: WorkerId(41),
        };
        let (mut inventory, mut owners) = WorkerPublications::new(&[binding]).unwrap();
        let mut host = LocalHost {
            worker: binding.worker,
            effects: Vec::new(),
            regime: None,
        };
        inventory
            .accept_initial(owners[0].publish_initial(&mut host).unwrap())
            .unwrap();
        assert!(inventory.require_held_members(&[7]).is_err());
        let request = inventory.request_stop(&[7]).unwrap();
        let command = inventory
            .native_stop_commands(&request)
            .unwrap()
            .pop()
            .unwrap();
        inventory
            .accept_invalidation(owners[0].invalidate(command, &mut host).unwrap())
            .unwrap();
        let held = inventory.hold_stop(request).unwrap();
        inventory.require_all_held(&held).unwrap();
        inventory.require_held_members(&[7]).unwrap();
        assert!(inventory.require_held_members(&[0]).is_err());
        assert!(inventory.require_held_members(&[7, 7]).is_err());
        assert!(inventory.require_stopped(1, &[7]).is_err());
        assert!(inventory.require_stopped(10, &[7]).is_err());
        let (foreign, _, _, _) = self::held();
        assert_eq!(
            foreign.require_all_held(&held),
            Err(PublicationError::WrongInventory)
        );
        let release = inventory.release(held).unwrap().pop().unwrap();
        inventory
            .accept_release(owners[0].release(release).unwrap())
            .unwrap();
        assert!(inventory.require_held_members(&[7]).is_err());
    }

    #[test]
    fn effects_require_actual_assigned_host_and_receipt_before_close_or_release() {
        let (mut inventory, mut owners, mut hosts, held) = held();
        let mut services = inventory.open_services(&held, 1).unwrap();
        assert!(matches!(
            inventory.open_services(&held, 1),
            Err(PublicationError::ServiceBusy)
        ));
        let command = services.command(HostEffect::ArmTimer(Some(123))).unwrap();
        assert!(matches!(
            services.command(HostEffect::DiscardCode),
            Err(PublicationError::ServiceBusy)
        ));
        let before = hosts[0].effects.clone();
        let error = owners[1]
            .apply_host_effect(command, &mut hosts[0])
            .unwrap_err();
        assert_eq!(error.error, PublicationError::WrongOwner);
        assert_eq!(hosts[0].effects, before);
        let services = inventory.close_services(services).unwrap_err();
        assert_eq!(services.error, PublicationError::ServiceBusy);
        let mut services = services.payload;
        let held = inventory.release(held).unwrap_err();
        assert_eq!(held.error, PublicationError::ServiceBusy);
        let receipt = owners[1]
            .apply_host_effect(error.payload, &mut hosts[1])
            .unwrap();
        assert_eq!(hosts[1].effects.last(), Some(&"timer"));
        services.accept(receipt).unwrap();
        for (effect, expected) in [
            (HostEffect::InvalidateTranslations, "invalidate"),
            (
                HostEffect::InvalidateReach(Reach::All, Everywhere::All),
                "reach",
            ),
            (HostEffect::IsolatePredictions, "isolate"),
            (HostEffect::CodeInvalidated(Some(0x1000)), "code"),
            (HostEffect::DiscardCode, "discard"),
        ] {
            let command = services.command(effect).unwrap();
            services
                .accept(owners[1].apply_host_effect(command, &mut hosts[1]).unwrap())
                .unwrap();
            assert_eq!(hosts[1].effects.last(), Some(&expected));
        }
        inventory.close_services(services).unwrap();
        for release in inventory.release(held.payload).unwrap() {
            let pe = release.binding().pe;
            inventory
                .accept_release(owners[pe].release(release).unwrap())
                .unwrap();
        }
    }
    #[test]
    fn cross_worker_receipt_cannot_finish_another_live_session() {
        let (mut inventory, mut owners, mut hosts, held) = held();
        let mut first = inventory.open_services(&held, 0).unwrap();
        let mut second = inventory.open_services(&held, 1).unwrap();
        let command = first.command(HostEffect::InvalidateTranslations).unwrap();
        let receipt = owners[0].apply_host_effect(command, &mut hosts[0]).unwrap();
        let error = second.accept(receipt).unwrap_err();
        assert_eq!(error.error, PublicationError::StaleService);
        first.accept(error.payload).unwrap();
        inventory.close_services(first).unwrap();
        inventory.close_services(second).unwrap();
        assert!(inventory.release(held).is_ok());
    }

    #[test]
    fn closed_unique_session_reopens_with_fresh_sequence_without_growing_the_slot() {
        let (mut inventory, mut owners, mut hosts, held) = held();
        let mut services = inventory.open_services(&held, 0).unwrap();
        let allocation = Arc::as_ptr(&services.session);
        for _ in 0..32 {
            assert_eq!(Arc::as_ptr(&services.session), allocation);
            assert_eq!(services.issued, 0);
            assert_eq!(services.session.completed.load(Ordering::Acquire), 0);
            let command = services.command(HostEffect::ArmTimer(Some(123))).unwrap();
            assert_eq!(command.sequence(), 1);
            services
                .accept(owners[0].apply_host_effect(command, &mut hosts[0]).unwrap())
                .unwrap();
            inventory.close_services(services).unwrap();
            let slot = &inventory.slots[0];
            assert!(slot.services.is_none());
            let closed = slot.closed_services.as_ref().unwrap();
            assert!(!closed.open.load(Ordering::Acquire));
            assert_eq!(Arc::strong_count(closed), 1);
            assert_eq!(Arc::weak_count(closed), 0);
            services = inventory.open_services(&held, 0).unwrap();
        }
        inventory.close_services(services).unwrap();
        assert_eq!(
            hosts[0]
                .effects
                .iter()
                .filter(|effect| **effect == "timer")
                .count(),
            32
        );
        assert!(inventory.release(held).is_ok());
    }

    #[test]
    fn closed_session_with_weak_observer_keeps_its_identity_separate() {
        let (mut inventory, _, _, held) = held();
        let services = inventory.open_services(&held, 0).unwrap();
        let observer = Arc::downgrade(&services.session);
        inventory.close_services(services).unwrap();
        assert_eq!(observer.strong_count(), 1); // only the closed slot
        let reopened = inventory.open_services(&held, 0).unwrap();
        assert_ne!(observer.as_ptr(), Arc::as_ptr(&reopened.session));
        assert!(observer.upgrade().is_none());
        inventory.close_services(reopened).unwrap();
    }

    #[test]
    fn retained_stale_command_cannot_alias_or_replay_a_reopened_session() {
        let (mut inventory, mut owners, mut hosts, held) = held();
        let mut services = inventory.open_services(&held, 0).unwrap();
        let command = services.command(HostEffect::DiscardCode).unwrap();
        // Retain an adversarial historical command reference. Production
        // commands are non-Clone; even a future alias must prevent recycling.
        let stale = HostEffectCommand {
            identity: Arc::clone(&command.identity),
            session: Arc::clone(&command.session),
            binding: command.binding,
            stop: command.stop,
            sequence: command.sequence,
            effect: HostEffect::DiscardCode,
        };
        services
            .accept(owners[0].apply_host_effect(command, &mut hosts[0]).unwrap())
            .unwrap();
        inventory.close_services(services).unwrap();
        let reopened = inventory.open_services(&held, 0).unwrap();
        assert!(!Arc::ptr_eq(&reopened.session, &stale.session));
        let before = hosts[0].effects.clone();
        assert_eq!(
            owners[0]
                .apply_host_effect(stale, &mut hosts[0])
                .unwrap_err()
                .error,
            PublicationError::StaleService
        );
        assert_eq!(hosts[0].effects, before);
        inventory.close_services(reopened).unwrap();
    }

    #[test]
    fn refused_close_keeps_pending_authority_and_cannot_populate_reuse_slot() {
        let (mut inventory, mut owners, mut hosts, held) = held();
        let mut services = inventory.open_services(&held, 1).unwrap();
        let allocation = Arc::as_ptr(&services.session);
        let command = services.command(HostEffect::MemoryBarrier).unwrap();
        let refused = inventory.close_services(services).unwrap_err();
        assert_eq!(refused.error, PublicationError::ServiceBusy);
        assert!(inventory.slots[1].closed_services.is_none());
        assert!(matches!(
            inventory.open_services(&held, 1),
            Err(PublicationError::ServiceBusy)
        ));
        let mut services = refused.payload;
        assert_eq!(Arc::as_ptr(&services.session), allocation);
        services
            .accept(owners[1].apply_host_effect(command, &mut hosts[1]).unwrap())
            .unwrap();
        inventory.close_services(services).unwrap();
        let reopened = inventory.open_services(&held, 1).unwrap();
        assert_eq!(Arc::as_ptr(&reopened.session), allocation);
        inventory.close_services(reopened).unwrap();
    }

    #[test]
    fn unique_closed_allocation_can_serve_a_new_actual_stop_generation() {
        let (mut inventory, mut owners, mut hosts, stopped) = held();
        let services = inventory.open_services(&stopped, 0).unwrap();
        let generation = services.stop;
        let allocation = Arc::as_ptr(&services.session);
        inventory.close_services(services).unwrap();
        for release in inventory.release(stopped).unwrap() {
            let pe = release.binding().pe;
            inventory
                .accept_release(owners[pe].release(release).unwrap())
                .unwrap();
        }
        let request = inventory.request_stop(&[0, 1]).unwrap();
        for command in inventory.native_stop_commands(&request).unwrap() {
            let pe = command.binding().pe;
            inventory
                .accept_invalidation(owners[pe].invalidate(command, &mut hosts[pe]).unwrap())
                .unwrap();
        }
        let stopped = inventory.hold_stop(request).unwrap();
        let mut reopened = inventory.open_services(&stopped, 0).unwrap();
        assert!(reopened.stop > generation);
        assert_eq!(Arc::as_ptr(&reopened.session), allocation);
        let command = reopened.command(HostEffect::ArmTimer(None)).unwrap();
        assert_eq!(command.generation(), reopened.stop);
        assert_eq!(command.sequence(), 1);
        reopened
            .accept(owners[0].apply_host_effect(command, &mut hosts[0]).unwrap())
            .unwrap();
        inventory.close_services(reopened).unwrap();
    }

    #[test]
    fn replacement_inventory_starts_empty_and_refuses_an_old_inventory_hold() {
        let (mut inventory, _, _, stopped) = held();
        let services = inventory.open_services(&stopped, 0).unwrap();
        let retired = Arc::clone(&services.session);
        inventory.close_services(services).unwrap();
        let (mut replacement, _, _, replacement_stop) = held();
        assert!(
            replacement
                .slots
                .iter()
                .all(|slot| slot.closed_services.is_none())
        );
        assert!(matches!(
            replacement.open_services(&stopped, 0),
            Err(PublicationError::WrongInventory)
        ));
        let reopened = replacement.open_services(&replacement_stop, 0).unwrap();
        assert!(!Arc::ptr_eq(&retired, &reopened.session));
        assert!(!retired.open.load(Ordering::Acquire));
        replacement.close_services(reopened).unwrap();
    }
    #[test]
    fn dropping_session_never_grants_stopped_worker_release() {
        let (mut inventory, _, _, held) = held();
        drop(inventory.open_services(&held, 0).unwrap());
        assert_eq!(
            inventory.release(held).unwrap_err().error,
            PublicationError::ServiceBusy
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn boxed_controls_are_consumed_on_the_actual_owner_thread_before_receipt() {
        let (mut inventory, mut owners, mut hosts, held) = held();
        let mut services = inventory.open_services(&held, 1).unwrap();
        let cpu = crate::machine::Cpu::of(
            stela_contracts::Chip::AppleM1,
            0,
            crate::machine::exception::Pstate::reset(2),
        );
        let regime = Regime {
            controls: cpu.controls(cpu.regime()),
            requester: cpu.requester(),
            watch: crate::machine::engine::Watch::default(),
            tag_checks: [false; 2],
        };
        let command = services
            .command(HostEffect::Regime(Box::new(regime)))
            .unwrap();
        let owner = &mut owners[1];
        let host = &mut hosts[1];
        let receipt = std::thread::scope(|scope| {
            scope
                .spawn(move || owner.apply_host_effect(command, host))
                .join()
                .unwrap()
        })
        .unwrap();
        services.accept(receipt).unwrap();
        assert_eq!(hosts[1].regime, Some(regime));
        assert_eq!(hosts[0].regime, None);
        inventory.close_services(services).unwrap();
        assert!(inventory.release(held).is_ok());
    }
}

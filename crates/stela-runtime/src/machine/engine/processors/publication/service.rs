//! Closed Host effects on a recovered, held physical worker. No CPU, Machine,
//! raw callback or borrowed Host is transported to another core.
use super::*;
use crate::machine::{Regime, mmu::tlbi::Reach};
use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The owner-local part of stopped source-instruction settlement. RAM access
/// stays with the canonical all-writer owner; native entry uses NativeLoan.
#[derive(Debug)]
pub enum HostEffect {
    Regime(Box<Regime>),
    InvalidateTranslations,
    InvalidateReach(Reach),
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
        if members.is_empty()
            || self.slots.len() != members.len()
            || self
                .slots
                .iter()
                .any(|slot| !members.contains(&slot.binding.pe))
            || members
                .iter()
                .enumerate()
                .any(|(i, pe)| members[..i].contains(pe))
        {
            return Err(PublicationError::ProcessorCount {
                expected: members.len(),
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
        let members: Vec<_> = held
            .request
            .members
            .iter()
            .map(|binding| binding.pe)
            .collect();
        self.require_held_members(&members)
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
        let session = Arc::new(ServiceIdentity {
            open: AtomicBool::new(true),
            completed: AtomicU64::new(0),
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
            HostEffect::InvalidateReach(_) => "reach",
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
            HostEffect::InvalidateReach(reach) => host.invalidate_reach(*reach),
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
        fn invalidate_reach(&mut self, _: Reach) {
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
            (HostEffect::InvalidateReach(Reach::All), "reach"),
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
            crate::machine::Chip::AppleM1,
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

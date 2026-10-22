//! BSP control-plane Host routing during a true all-worker stop. Only the
//! closed native effects cross cores; the Machine and Cpu never do.
use super::super::publication;
use super::*;
use crate::machine::{InstallError, NativeCode, NativeExit, Regime, mmu};
use publication::{
    HostEffect, HostEffectCommand, HostEffectReceipt, WithPayload, WorkerId, WorkerServices,
};
use stela_compiler::{GuestState, context::ExecutionContext};

/// Synchronous transport to the already-held actual native owner. Failure must
/// stop before any later source/controller effect or ACK can occur.
pub trait ServiceTransport {
    fn apply(
        &mut self,
        local: &mut dyn Host,
        command: HostEffectCommand,
    ) -> Result<HostEffectReceipt, WithPayload<HostEffectCommand>>;
    fn fail_stopped(&mut self, reason: &'static str) -> !;
}

/// The one existing Machine Host interface, with scoped physical-owner routing.
/// Canonical RAM access stays on its retained all-writer owner. The local Host
/// remains the BSP's actual Host, including native entry and diagnostic reports.
pub struct ServiceHost<H, T> {
    pub(super) local: H,
    pub(super) transport: T,
    ram: Arc<RegisteredSystemRam>,
    services: Vec<WorkerServices>,
    selected: Option<usize>,
}
/// Existing fixed-owner execution/stop transport, retaining the actual frame
/// loans and generation-bound owner tokens. No metadata-only completion exists.
///
/// # Safety
/// Every submitted frame must be joined and actually recovered before return,
/// including error paths. Stop/release operate on all actual assigned owners;
/// a missing native return or effect must fail stopped without freeing loans.
pub unsafe trait NativeTransport: ServiceTransport {
    fn initialize(
        &mut self,
        local: &mut dyn Host,
        inventory: &mut publication::WorkerPublications,
        owners: Vec<publication::WorkerOwner>,
    );
    fn execute<'a>(
        &mut self,
        local: &mut dyn Host,
        inventory: &mut publication::WorkerPublications,
        frames: Vec<super::NativeRun<'a>>,
    ) -> Vec<super::NativeRunObservation>;
    fn hold_all(
        &mut self,
        local: &mut dyn Host,
        inventory: &mut publication::WorkerPublications,
    ) -> publication::StoppedWorkers;
    fn release(
        &mut self,
        local: &mut dyn Host,
        inventory: &mut publication::WorkerPublications,
        held: publication::StoppedWorkers,
    );
}
impl<H: Host, T: ServiceTransport> ServiceHost<H, T> {
    pub fn new(local: H, transport: T, ram: Arc<RegisteredSystemRam>) -> Self {
        Self {
            local,
            transport,
            ram,
            services: Vec::new(),
            selected: None,
        }
    }
    /// Each linear session was opened from the exact currently-held cohort.
    /// A failed or dropped session leaves publication release refused.
    pub fn begin_services(
        &mut self,
        services: Vec<WorkerServices>,
    ) -> Result<(), Vec<WorkerServices>> {
        if !self.services.is_empty() || self.selected.is_some() || services.is_empty() {
            return Err(services);
        }
        self.services = services;
        Ok(())
    }
    /// Return every actual session for publication close before cohort release.
    pub fn end_services(&mut self) -> Vec<WorkerServices> {
        self.selected = None;
        core::mem::take(&mut self.services)
    }
    fn effect(&mut self, effect: HostEffect) {
        let Some(index) = self.selected else {
            self.transport
                .fail_stopped("native Host effect has no selected stopped worker");
        };
        let command = match self.services[index].command(effect) {
            Ok(command) => command,
            Err(_) => self
                .transport
                .fail_stopped("native Host effect session refused command"),
        };
        let receipt = match self.transport.apply(&mut self.local, command) {
            Ok(receipt) => receipt,
            Err(_) => self
                .transport
                .fail_stopped("actual held native Host refused its effect"),
        };
        if self.services[index].accept(receipt).is_err() {
            self.transport
                .fail_stopped("actual native Host effect receipt mismatched session");
        }
    }
    fn source_service(&self) -> bool {
        !self.services.is_empty()
    }
    fn native_entry(&mut self) {
        if self.source_service() {
            self.transport
                .fail_stopped("native code entry/patch during stopped source service");
        }
    }
}
impl<H: Host, T: ServiceTransport> Host for ServiceHost<H, T> {
    fn memory_barrier(&mut self) {
        // Source helpers may have performed canonical copyout on the BSP;
        // complete those stores as well as the source PE's actual native ones.
        self.local.memory_barrier();
        if self.source_service() {
            self.effect(HostEffect::MemoryBarrier);
        }
    }
    fn select_native_service(&mut self, worker: WorkerId) -> bool {
        let selected = self
            .services
            .iter()
            .position(|session| session.binding().worker == worker);
        self.selected = selected;
        selected.is_some()
    }
    fn native_worker(&self) -> Option<WorkerId> {
        self.local.native_worker()
    }
    fn read_ram(&mut self, physical: u64, buffer: &mut [u8]) -> bool {
        // SAFETY: the retained canonical owner supplies mapping and all-reader
        // exclusion. No identity/raw-RAM fallback is admitted by this adapter.
        unsafe { self.ram.read_physical(physical, buffer).is_ok() }
    }
    fn write_ram(&mut self, physical: u64, data: &[u8]) -> bool {
        // SAFETY: every source/host/alias writer uses this same physical domain.
        unsafe { self.ram.publish_physical(physical, data).is_ok() }
    }
    fn install(&mut self, code: &[u8]) -> Result<NativeCode, InstallError> {
        self.native_entry();
        self.local.install(code)
    }
    fn patch(&mut self, code: NativeCode, bytes: &[u8]) {
        self.native_entry();
        self.local.patch(code, bytes);
    }
    fn discard_code(&mut self) {
        if self.source_service() {
            self.effect(HostEffect::DiscardCode);
        } else {
            self.local.discard_code();
        }
    }
    fn reclaim_code(&mut self) -> Option<core::ops::Range<usize>> {
        self.native_entry();
        self.local.reclaim_code()
    }
    fn memory_low(&self) -> bool {
        self.local.memory_low()
    }
    unsafe fn execute(&mut self, code: NativeCode, state: &mut GuestState) -> NativeExit {
        self.native_entry();
        // SAFETY: caller retains the existing installed system block contract;
        // stopped source services are excluded above.
        unsafe { self.local.execute(code, state) }
    }
    unsafe fn execute_context(
        &mut self,
        code: NativeCode,
        state: &mut GuestState,
        context: &mut ExecutionContext,
    ) -> Option<NativeExit> {
        self.native_entry();
        // SAFETY: caller retains actual context/code/frame owners on this BSP.
        unsafe { self.local.execute_context(code, state, context) }
    }
    fn context_entry(&mut self, code: NativeCode) -> Option<usize> {
        if self.source_service() {
            None
        } else {
            self.local.context_entry(code)
        }
    }
    fn fetch_permitted(&mut self, virtual_address: u64) -> bool {
        self.local.fetch_permitted(virtual_address)
    }
    fn placement(&self) -> mmu::placement::Placement {
        self.local.placement()
    }
    fn translation_helper(&self) -> Option<u64> {
        None
    }
    fn set_regime(&mut self, regime: &Regime) {
        if self.source_service() {
            self.effect(HostEffect::Regime(alloc::boxed::Box::new(*regime)));
        } else {
            self.local.set_regime(regime);
        }
    }
    fn isolate_predictions(&mut self) {
        if self.source_service() {
            self.effect(HostEffect::IsolatePredictions);
        } else {
            self.local.isolate_predictions();
        }
    }
    fn speculation_barrier(&self) {
        self.local.speculation_barrier();
    }
    fn code_invalidated(&mut self, page: Option<u64>) {
        if self.source_service() {
            self.effect(HostEffect::CodeInvalidated(page));
        } else {
            self.local.code_invalidated(page);
        }
    }
    fn invalidate_translations(&mut self) {
        if self.source_service() {
            self.effect(HostEffect::InvalidateTranslations);
        } else {
            self.local.invalidate_translations();
        }
    }
    fn invalidate_reach(&mut self, reach: mmu::tlbi::Reach) {
        if self.source_service() {
            self.effect(HostEffect::InvalidateReach(reach));
        } else {
            self.local.invalidate_reach(reach);
        }
    }
    fn counter(&mut self) -> u64 {
        self.local.counter()
    }
    fn arm_timer(&mut self, deadline: Option<u64>) {
        if self.source_service() {
            self.effect(HostEffect::ArmTimer(deadline));
        } else {
            self.local.arm_timer(deadline);
        }
    }
    fn wait_for_interrupt(&mut self) {
        if self.source_service() {
            self.transport
                .fail_stopped("waiting inside stopped native source service");
        }
        self.local.wait_for_interrupt();
    }
    fn report(&mut self, event: &crate::machine::Event) {
        self.local.report(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::{
        engine::NoDevices,
        engine::publication::{WorkerBinding, WorkerOwner, WorkerPublications},
    };
    struct Local;
    impl Host for Local {
        fn native_worker(&self) -> Option<WorkerId> {
            Some(WorkerId(17))
        }
        fn read_ram(&mut self, _: u64, _: &mut [u8]) -> bool {
            panic!("raw RAM fallback");
        }
        fn write_ram(&mut self, _: u64, _: &[u8]) -> bool {
            panic!("raw RAM fallback");
        }
        fn install(&mut self, _: &[u8]) -> Result<NativeCode, InstallError> {
            panic!("CPL0 refusal must precede native install");
        }
        fn patch(&mut self, _: NativeCode, _: &[u8]) {
            unreachable!()
        }
        fn discard_code(&mut self) {}
        unsafe fn execute(&mut self, _: NativeCode, _: &mut GuestState) -> NativeExit {
            unreachable!()
        }
        fn set_regime(&mut self, _: &Regime) {}
        fn invalidate_translations(&mut self) {}
        fn counter(&mut self) -> u64 {
            1
        }
        fn arm_timer(&mut self, _: Option<u64>) {}
        fn wait_for_interrupt(&mut self) {
            unreachable!()
        }
    }
    struct OneWorker(Option<WorkerOwner>);
    impl OneWorker {
        fn owner(&mut self) -> &mut WorkerOwner {
            self.0.as_mut().unwrap()
        }
    }
    impl ServiceTransport for OneWorker {
        fn apply(
            &mut self,
            local: &mut dyn Host,
            command: HostEffectCommand,
        ) -> Result<HostEffectReceipt, WithPayload<HostEffectCommand>> {
            self.owner().apply_host_effect(command, local)
        }
        fn fail_stopped(&mut self, reason: &'static str) -> ! {
            panic!("{reason}");
        }
    }
    // SAFETY: this one-worker test transport actually consumes/recover every
    // sealed frame and uses the real publication stop/effect/release protocol.
    // It does not forge CPL0 admission or claim actual native code execution.
    unsafe impl NativeTransport for OneWorker {
        fn initialize(
            &mut self,
            local: &mut dyn Host,
            inventory: &mut WorkerPublications,
            mut owners: Vec<WorkerOwner>,
        ) {
            assert_eq!(owners.len(), 1);
            let mut owner = owners.pop().unwrap();
            inventory
                .accept_initial(owner.publish_initial(local).unwrap())
                .unwrap();
            self.0 = Some(owner);
        }
        fn execute<'a>(
            &mut self,
            local: &mut dyn Host,
            inventory: &mut WorkerPublications,
            frames: Vec<NativeRun<'a>>,
        ) -> Vec<NativeRunObservation> {
            frames
                .into_iter()
                .map(|frame| {
                    let loan = super::super::dispatch_native_run(inventory, frame)
                        .unwrap_or_else(|_| panic!("frame dispatch"));
                    let returned = self
                        .owner()
                        .execute(loan, local)
                        .unwrap_or_else(|_| panic!("frame return"));
                    super::super::recover_native_run(inventory, returned)
                        .unwrap_or_else(|_| panic!("actual recovery"))
                })
                .collect()
        }
        fn hold_all(
            &mut self,
            local: &mut dyn Host,
            inventory: &mut WorkerPublications,
        ) -> publication::StoppedWorkers {
            let request = inventory.request_stop(&[0]).unwrap();
            let command = inventory
                .native_stop_commands(&request)
                .unwrap()
                .pop()
                .unwrap();
            inventory
                .accept_invalidation(self.owner().invalidate(command, local).unwrap())
                .unwrap();
            inventory.hold_stop(request).unwrap()
        }
        fn release(
            &mut self,
            _: &mut dyn Host,
            inventory: &mut WorkerPublications,
            held: publication::StoppedWorkers,
        ) {
            let release = inventory.release(held).unwrap().pop().unwrap();
            inventory
                .accept_release(self.owner().release(release).unwrap())
                .unwrap();
        }
    }
    #[test]
    fn unprivileged_round_recovers_refusal_without_source_execution_or_raw_ram_fallback() {
        let (mut cpu, profile, missing, ram) = super::super::policy::tests::fixture();
        cpu.pc = 0x4000;
        const SOURCE_PA: u64 = 0x14000;
        const B_SELF: u32 = 0x14000000;
        unsafe { ram.publish_physical(SOURCE_PA, &B_SELF.to_le_bytes()) }.unwrap();
        let host = ServiceHost::new(Local, OneWorker(None), Arc::clone(&ram));
        let mut machine = Machine::new(cpu, host, NoDevices, profile, ram.target());
        machine.profile_missing = missing;
        let events = crate::system::events::EventDomain::new();
        machine
            .install_shared_memory_for_processors(ram, &events)
            .unwrap();
        let binding = WorkerBinding {
            pe: 0,
            worker: WorkerId(17),
        };
        let owners = machine.bind_native_workers(&[binding]).unwrap();
        machine.initialize_native_transport(owners);
        let before = (
            machine.cpu.state.clone(),
            machine.cpu.pc,
            machine.cpu.retired,
        );
        // SAFETY: closed one-worker model fixture, actual canonical byte owner,
        // no concurrent writer. The real CPL0 authority must refuse on this host.
        let stop = unsafe { machine.native_round() }.unwrap_err();
        assert!(matches!(stop, crate::machine::Stop::Unsupported(_)));
        assert_eq!(
            (
                machine.cpu.state.clone(),
                machine.cpu.pc,
                machine.cpu.retired
            ),
            before
        );
        assert_eq!(machine.statistics.blocks, 0);
        assert!(
            machine
                .native_publication
                .as_ref()
                .unwrap()
                .require_stopped(1, &[0])
                .is_ok()
        );
        assert_eq!(machine.host.services.len(), 1); // refusal does not release
    }
}

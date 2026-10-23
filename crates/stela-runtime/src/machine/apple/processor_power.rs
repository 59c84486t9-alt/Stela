//! Assigned CPU participants of the actual placed PMGR, not firmware state.
//! Physical associations come from the full original source resolver; only the
//! retained Plan may project them to runtime PEs. A register ACK follows the
//! real stopped-cohort CPU settlement and all model lifecycle preflights.
mod projection;

use super::*;
use crate::machine::{
    CpuProfile,
    adt::Node,
    engine::{CanonicalDeviceWrite, ConsumedWrite, ProcessorBinding, ProcessorWrite},
    soc::{PowerStates, assigned::Plan},
};
pub(super) use projection::AssignedPower;
use projection::Request;

impl AppleDevices {
    /// Cold placement only. Retain `plan` and its source/roster owners through
    /// execution and pass the returned bindings to canonical preparation before
    /// publishing any worker. The full source graph is never pruned or changed.
    /// Initial lifecycle is sampled from the actual Stela PMGR model; even an
    /// ACTIVE word is a declared software state, not an Apple handoff capture.
    pub fn connect_processor_power(
        &mut self,
        states: &PowerStates,
        original: &Node<'_>,
        full_profile: &CpuProfile,
        plan: &Plan<'_>,
        effective_acc_harvesting: u32,
    ) -> Result<Vec<ProcessorBinding>, String> {
        if self.processor_power.is_some() || !self.power_configured {
            return Err("CPU power requires one completed actual PMGR resource placement".into());
        }
        plan.revalidate()
            .map_err(|e| format!("CPU power assignment is stale: {e:?}"))?;
        if full_profile.chip != plan.chip() {
            return Err("CPU power source profile differs from the assigned chip".into());
        }
        let associations = states.processor_associations(
            full_profile.chip,
            original,
            &full_profile.processors,
            effective_acc_harvesting,
        )?;
        let cpus = original
            .child("cpus")
            .and_then(|cpus| cpus.children())
            .ok_or("CPU power requires the complete original CPU nodes")?;
        let regs = cpus
            .iter()
            .map(|cpu| {
                cpu.property("reg")
                    .and_then(|value| value.try_into().ok())
                    .map(u32::from_le_bytes)
                    .ok_or_else(|| String::from("CPU power source reg is not one u32"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let pmgr = self
            .pmgr
            .and_then(|id| self.bus.device::<Pmgr>(id))
            .ok_or("CPU power has no actual placed PMGR")?;
        let assigned = AssignedPower::prepare(
            plan.identity(),
            plan.pes(),
            &regs,
            &full_profile.processors,
            &associations,
            pmgr,
        )?;
        // Recheck after source/placed-state preparation, before publishing the
        // mapping. The immutable retained Plan cannot be replaced by an ID list.
        plan.revalidate()
            .map_err(|e| format!("CPU power assignment changed: {e:?}"))?;
        let bindings = assigned.bindings();
        self.processor_power = Some(assigned);
        Ok(bindings)
    }

    /// Effect-free classification for scalar/pair/raw dispatch. Every original
    /// CPU domain remains classified, including positively unassigned cores.
    pub(super) fn is_processor_power_register(&self, physical: u64) -> bool {
        self.processor_power
            .as_ref()
            .is_some_and(|assigned| assigned.contains(physical))
    }

    /// The legacy/raw path may preserve configuration/W1C behavior but cannot
    /// change a CPU's lifecycle without actual execution-owner settlement.
    pub(super) fn check_raw_processor_power_write(
        &self,
        physical: u64,
        bytes: u8,
        value: u64,
    ) -> Result<(), DeviceError> {
        let Some(request) = self.processor_power_request(physical, bytes, value)? else {
            return Ok(());
        };
        if request.transition.before != request.transition.after {
            return Err(DeviceError::TransferRefused(
                "CPU PMGR lifecycle write requires the actual canonical processor owners".into(),
            ));
        }
        Ok(())
    }

    /// Call BEFORE RTC publication, queued lifecycle replay or any bus/device
    /// write. `None` leaves ordinary non-CPU writes to the existing path.
    pub(super) fn consume_processor_power_write(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
        owners: &mut dyn CanonicalDeviceWrite,
    ) -> Result<Option<ConsumedWrite>, DeviceError> {
        let Some(request) = self.prepare_processor_power_write(physical, bytes, value)? else {
            return Ok(None);
        };
        let processors = owners.processors()?;
        self.commit_processor_power_write(cpu, now, request, processors)
            .map(Some)
    }

    fn prepare_processor_power_write(
        &mut self,
        physical: u64,
        bytes: u8,
        value: u64,
    ) -> Result<Option<Request>, DeviceError> {
        let request = self.processor_power_request(physical, bytes, value)?;
        if request.is_some() {
            // Every actual model's potentially fallible lifecycle hook precedes
            // the CPU owner lease. No queued edge has been applied here.
            self.check_power_request(physical, value)?;
        }
        Ok(request)
    }

    fn processor_power_request(
        &self,
        physical: u64,
        bytes: u8,
        value: u64,
    ) -> Result<Option<Request>, DeviceError> {
        if !self.is_processor_power_register(physical) {
            return Ok(None);
        }
        let assigned = self
            .processor_power
            .as_ref()
            .expect("classified CPU domain");
        if bytes != 4 {
            return Err(DeviceError::TransferRefused(
                "CPU PMGR registers require one complete 32-bit scalar write".into(),
            ));
        }
        let pmgr_id = self
            .pmgr
            .expect("assigned CPU power retains its placed PMGR");
        if self.bus.route(physical, Width::Word).ok() != Some((pmgr_id, physical)) {
            return Err(DeviceError::TransferRefused(
                "CPU PMGR register no longer belongs to its original placed owner".into(),
            ));
        }
        let pmgr = self.bus.device::<Pmgr>(pmgr_id).expect("placed PMGR type");
        assigned.preview(pmgr, physical, value as u32).map(Some)
    }

    fn commit_processor_power_write(
        &mut self,
        cpu: usize,
        now: u64,
        request: Request,
        processors: ProcessorWrite<'_>,
    ) -> Result<ConsumedWrite, DeviceError> {
        // apply validates the WHOLE held native cohort, current/parked owners,
        // native controls and exclusive monitors before its first CPU effect.
        // Retain either actual owner borrow through the controller/client ACK.
        let mut unchanged = None;
        let _settled = if let Some(change) = request.change {
            Some(processors.apply(&[change]).map_err(|error| {
                DeviceError::TransferRefused(format!("CPU PMGR settlement refused: {error:?}"))
            })?)
        } else {
            unchanged = Some(processors);
            None
        };
        let mut access = Access::new(cpu, now, &mut self.latch);
        // The exact Word was previewed against this same exclusive PMGR borrow.
        // Neither CPU settlement nor a model preflight can mutate its register,
        // lifecycle bindings or bus route. No fallible operation remains before
        // this controller commit; Pmgr::write's sole checks are that preview.
        self.bus
            .device_mut::<Pmgr>(self.pmgr.expect("retained PMGR"))
            .expect("retained PMGR type")
            .write(
                request.transition.address,
                Width::Word,
                u64::from(request.value),
                &mut access,
            )
            .expect("exclusive validated PMGR request commits infallibly");
        self.processor_power
            .as_mut()
            .expect("retained assigned CPU mapping")
            .committed(&request);
        // Time publication follows acceptance too: a failed transaction cannot
        // leave an unrelated RTC/device prefix before its CPU preflight.
        let published = self.publish_rtc_time(now);
        self.settle_lifecycle(cpu, now);
        // Bus/wire settlement can fail after the completed controller/client
        // transaction. Preserve that completion; never return an outer no-effect
        // error or replay the source store after an ACK has become observable.
        let settlement = published.and(self.settle(cpu, now, None));
        #[allow(
            clippy::drop_non_drop,
            reason = "retain the exclusive processor borrow through the PMGR commit and wire settlement"
        )]
        drop(unchanged);
        Ok(ConsumedWrite::Complete { settlement })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::{
        Cpu, Host, Machine,
        engine::{InstallError, NativeCode, NativeExit},
        exception::Pstate,
    };
    use crate::platform::apple::bus::Lifecycle;
    use alloc::{rc::Rc, vec};
    use core::cell::Cell;
    use projection::tests::{BASE, COMPLEX, CORE};
    use stela_compiler::{GuestState, TargetCpu};

    struct Local;
    impl Host for Local {
        fn read_ram(&mut self, _: u64, _: &mut [u8]) -> bool {
            false
        }
        fn write_ram(&mut self, _: u64, _: &[u8]) -> bool {
            false
        }
        fn install(&mut self, _: &[u8]) -> Result<NativeCode, InstallError> {
            Err(InstallError::Full)
        }
        fn patch(&mut self, _: NativeCode, _: &[u8]) {
            panic!("no native code in owner test")
        }
        fn discard_code(&mut self) {}
        fn set_regime(&mut self, _: &crate::machine::engine::Regime) {}
        fn invalidate_translations(&mut self) {}
        unsafe fn execute(&mut self, _: NativeCode, _: &mut GuestState) -> NativeExit {
            panic!("no native execution in owner test")
        }
        fn counter(&mut self) -> u64 {
            0
        }
        fn arm_timer(&mut self, _: Option<u64>) {}
        fn wait_for_interrupt(&mut self) {}
    }

    struct Bank {
        reject_clock_gate: bool,
        commits: Rc<Cell<usize>>,
    }
    impl Lifecycle for Bank {
        fn check_lifecycle(&self, state: LifecycleState) -> Result<(), &'static str> {
            if self.reject_clock_gate && !state.clocked {
                Err("gate rejected")
            } else {
                Ok(())
            }
        }
        fn set_lifecycle(&mut self, _: LifecycleState, _: &mut Access<'_>) {
            self.commits.set(self.commits.get() + 1);
        }
    }
    impl MmioDevice for Bank {
        fn name(&self) -> &'static str {
            "CPU domain lifecycle test bank"
        }
        fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
            Some(self)
        }
        fn read(&mut self, _: u64, _: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
            Ok(0)
        }
        fn write(&mut self, _: u64, _: Width, _: u64, _: &mut Access<'_>) -> Result<(), MmioError> {
            Ok(())
        }
    }

    fn devices(assigned: AssignedPower, pmgr: Pmgr) -> AppleDevices {
        let mut devices = AppleDevices::new();
        let id = devices
            .bus
            .install(Box::new(pmgr), &[(BASE, 24, BASE)])
            .unwrap();
        devices.pmgr = Some(id);
        devices.power_configured = true;
        devices.processor_power = Some(assigned);
        devices
    }
    fn word(devices: &AppleDevices, address: u64) -> u32 {
        devices
            .bus
            .device::<Pmgr>(devices.pmgr.unwrap())
            .unwrap()
            .control_word(address)
            .unwrap()
    }
    fn bank(devices: &mut AppleDevices, reject: bool) -> Rc<Cell<usize>> {
        let commits = Rc::new(Cell::new(0));
        let device = devices.bus.add(Box::new(Bank {
            reject_clock_gate: reject,
            commits: Rc::clone(&commits),
        }));
        let state = devices
            .bus
            .device::<Pmgr>(devices.pmgr.unwrap())
            .unwrap()
            .domain_state(CORE)
            .unwrap();
        devices.power_clients.push(PowerClient {
            resources: "actual lifecycle hook fixture".into(),
            device,
            owner: PowerOwner::Mmio(0x8000),
            domains: vec![(CORE, state)],
            retention: false,
        });
        commits
    }
    fn machine(plan: &Plan<'_>, bindings: &[ProcessorBinding]) -> Machine<Local, AppleDevices> {
        let profile = CpuProfile {
            name: "CPU PMGR owner fixture",
            chip: plan.chip(),
            counter_frequency: 24_000_000,
            processors: plan.pes().iter().map(|pe| pe.identity).collect(),
            fixed: vec![],
        };
        let mut machine = Machine::new(
            Cpu::of(plan.chip(), 0x8000, Pstate::reset(2)),
            Local,
            AppleDevices::new(),
            profile,
            TargetCpu::Baseline,
        );
        machine.bind_processor_power(bindings).unwrap();
        machine
    }
    fn write(
        devices: &mut AppleDevices,
        machine: &mut Machine<Local, AppleDevices>,
        address: u64,
        value: u64,
    ) -> Result<ConsumedWrite, DeviceError> {
        let request = devices
            .prepare_processor_power_write(address, 4, value)?
            .unwrap();
        devices.commit_processor_power_write(0, 0, request, machine.processor_write())
    }

    #[test]
    fn clock_gate_and_release_settle_actual_cpu_before_controller_and_client_ack() {
        let (roster, inventory) = projection::tests::fixture();
        let plan = projection::tests::plan(&roster, &inventory);
        let pmgr = projection::tests::model(ACTIVE);
        let assigned = projection::tests::assigned(&plan, &pmgr);
        let mut machine = machine(&plan, &assigned.bindings());
        let mut devices = devices(assigned, pmgr);
        let commits = bank(&mut devices, false);
        machine.cpu.state.x[7] = 0x1234;
        machine.cpu.state.v[4] = [0x1122, 0x3344];
        machine.cpu.event = true;
        let before = machine.cpu.state.clone();
        assert!(matches!(
            write(&mut devices, &mut machine, CORE, 4),
            Ok(ConsumedWrite::Complete { settlement: Ok(()) })
        ));
        assert_eq!(machine.processors().paused(0), Some(true));
        assert_eq!(word(&devices, CORE) & 0xff, 0x44);
        assert_eq!(commits.get(), 1);
        assert_eq!(machine.cpu.state, before);
        assert!(machine.cpu.event);
        // A different physical complex input keeps the PE paused after the
        // core clock resumes; only the last qualified input releases it.
        write(&mut devices, &mut machine, COMPLEX, 4).unwrap();
        write(&mut devices, &mut machine, CORE, 15).unwrap();
        assert_eq!(machine.processors().paused(0), Some(true));
        write(&mut devices, &mut machine, COMPLEX, 15).unwrap();
        assert_eq!(machine.processors().paused(0), Some(false));
        assert_eq!(machine.cpu.state, before);
    }

    #[test]
    fn later_device_preflight_cpu_supply_loss_and_reset_refuse_before_any_effect() {
        let (roster, inventory) = projection::tests::fixture();
        let plan = projection::tests::plan(&roster, &inventory);
        let pmgr = projection::tests::model(ACTIVE);
        let assigned = projection::tests::assigned(&plan, &pmgr);
        let mut machine = machine(&plan, &assigned.bindings());
        let mut devices = devices(assigned, pmgr);
        let accepted = bank(&mut devices, false);
        let rejected = bank(&mut devices, true);
        let before = word(&devices, CORE);
        let state = machine.cpu.state.clone();
        assert!(write(&mut devices, &mut machine, CORE, 4).is_err());
        assert_eq!((accepted.get(), rejected.get()), (0, 0));
        assert_eq!(word(&devices, CORE), before);
        assert_eq!(machine.processors().paused(0), Some(false));
        assert_eq!(machine.cpu.state, state);
        // Remove only the test's deliberate rejection. The actual CPU owner
        // still refuses supply loss and reset before PMGR/device mutation.
        devices.power_clients.clear();
        for value in [0, (1 << 31) | 15, 0x8000_040f] {
            assert!(write(&mut devices, &mut machine, CORE, value).is_err());
            assert_eq!(word(&devices, CORE), before);
            assert_eq!(machine.processors().paused(0), Some(false));
            assert_eq!(machine.cpu.state, state);
        }
    }

    #[test]
    fn raw_and_unassigned_lifecycle_refuse_but_neutral_configuration_is_preserved() {
        let (roster, inventory) = projection::tests::fixture();
        let plan = projection::tests::plan(&roster, &inventory);
        let pmgr = projection::tests::model(ACTIVE);
        let assigned = projection::tests::assigned(&plan, &pmgr);
        let mut machine = machine(&plan, &assigned.bindings());
        let mut devices = devices(assigned, pmgr);
        let before = [BASE, CORE, COMPLEX].map(|a| word(&devices, a));
        assert!(devices.check_raw_processor_power_write(CORE, 4, 4).is_err());
        assert!(write(&mut devices, &mut machine, BASE, 4).is_err());
        assert!(devices.processor_power_request(CORE, 8, 15).is_err());
        assert_eq!([BASE, CORE, COMPLEX].map(|a| word(&devices, a)), before);
        assert!(
            devices
                .check_raw_processor_power_write(CORE, 4, 0x1000_000f)
                .is_ok()
        );
        write(&mut devices, &mut machine, CORE, 0x1000_000f).unwrap();
        assert_eq!(word(&devices, CORE), 0x1000_00ff);
        assert_eq!(machine.processors().paused(0), Some(false));
    }
}

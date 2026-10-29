//! Optional raw GXF boundary diagnostics. These observe the existing owners in
//! `guarded`, `take` and `exception_return`; they implement no monitor ABI.
use super::{Devices, Event, Host, Machine, Vector};

/// The architectural location on one side of a guarded boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorLocation {
    pub pc: u64,
    pub el: u8,
    pub guarded: bool,
    /// PSTATE.IL, including an ERET that completed as an illegal return.
    pub illegal: bool,
}

/// The operation that actually changed architectural state. Exceptions include
/// faults and interrupts as well as calls; no endpoint or call pairing is inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorKind {
    GuardedEnter {
        immediate: u8,
    },
    GuardedExit,
    Exception {
        vector: Vector,
        syndrome: u64,
        return_address: u64,
        fault_address: Option<u64>,
    },
    ExceptionReturn,
}

/// One completed boundary involving guarded execution, emitted through
/// [`Host::report`]. Registers are raw values immediately before the transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorEvent {
    pub pe: usize,
    pub kind: MonitorKind,
    pub from: MonitorLocation,
    pub to: MonitorLocation,
    pub arguments: [u64; 8],
    pub x16: u64,
    pub x17: u64,
    pub lr: u64,
}

impl<H: Host, D: Devices> Machine<H, D> {
    /// Emit GENTER/GEXIT and guarded exception/ERET boundaries synchronously
    /// through [`Host::report`], off by default. This adds no guest memory reads,
    /// counter samples, endpoint interpretation or retained call stack. The host
    /// controls diagnostic output cost; there is no queue or silent hit limit.
    pub fn set_monitor_tracing(&mut self, enabled: bool) {
        self.monitor_tracing = enabled;
    }

    fn monitor_location(&self) -> MonitorLocation {
        MonitorLocation {
            pc: self.cpu.pc,
            el: self.cpu.pstate.el,
            guarded: self.cpu.pstate.guarded,
            illegal: self.cpu.pstate.il,
        }
    }

    pub(super) fn monitor_before(&self, kind: MonitorKind) -> Option<MonitorEvent> {
        self.monitor_tracing.then(|| MonitorEvent {
            pe: self.current,
            kind,
            from: self.monitor_location(),
            to: self.monitor_location(),
            arguments: core::array::from_fn(|i| self.cpu.state.x[i]),
            x16: self.cpu.state.x[16],
            x17: self.cpu.state.x[17],
            lr: self.cpu.state.x[30],
        })
    }

    pub(super) fn monitor_after(&mut self, trace: Option<MonitorEvent>) {
        if let Some(mut trace) = trace {
            trace.to = self.monitor_location();
            if trace.from.guarded || trace.to.guarded {
                self.host.report(&Event::Monitor(trace));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::guarded::tests::gxf;
    use super::super::{
        NoDevices,
        tests::{BASE, FakeHost},
    };
    use super::*;
    use alloc::{format, vec::Vec};
    use {
        crate::machine::exception::Pstate, stela_contracts::Chip,
        stela_contracts::identity::Identity,
    };

    const GENTER: u32 = 0x0020_1420;
    const GEXIT: u32 = 0x0020_1400;
    const ERET: u32 = 0xd69f_03e0;
    const SVC: u32 = 0xd400_0001;

    fn traces(machine: &Machine<FakeHost, NoDevices>) -> Vec<MonitorEvent> {
        machine
            .host
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Monitor(trace) => Some(*trace),
                _ => None,
            })
            .collect()
    }

    fn boot_on_pe_four() -> Machine<FakeHost, NoDevices> {
        let mut configured = gxf(Chip::AppleM2);
        configured.cpu.pc = BASE;
        configured.profile.processors = (0..5)
            .map(|pe| Identity {
                midr: 0x611f_0320,
                mpidr: 0x8000_0000 | pe,
                clock: None,
                caches: None,
            })
            .collect();
        Machine::new_at(
            configured.cpu,
            configured.host,
            configured.devices,
            configured.profile,
            configured.target,
            4,
        )
        .unwrap()
    }

    #[test]
    fn monitor_tracing_observes_nested_entries_and_raw_dispatch_without_cpu_effects() {
        let mut traced = boot_on_pe_four();
        let mut plain = boot_on_pe_four();
        traced.set_monitor_tracing(true);
        // Distinct PE and register identities, including the SPTM dispatch
        // register x16, without assigning an endpoint ABI to its value.
        for machine in [&mut traced, &mut plain] {
            for i in 0..31 {
                machine.cpu.state.x[i] = 0x1000 + i as u64;
            }
        }
        for word in [GENTER | 3, GENTER | 8, GEXIT] {
            traced.system_instruction(word).unwrap();
            plain.system_instruction(word).unwrap();
            assert_eq!(format!("{:?}", traced.cpu), format!("{:?}", plain.cpu));
            assert_eq!(traced.host.ram, plain.host.ram);
            assert_eq!(traced.host.regimes, plain.host.regimes);
            assert_eq!(traced.host.counter_reads, plain.host.counter_reads);
        }
        assert!(traces(&plain).is_empty());
        let hits = traces(&traced);
        assert_eq!(hits.len(), 3);
        let first = hits[0];
        assert_eq!(
            (first.pe, first.from.pc, first.from.el, first.from.guarded),
            (4, BASE, 1, false)
        );
        assert_eq!(first.kind, MonitorKind::GuardedEnter { immediate: 3 });
        assert_eq!(first.arguments, core::array::from_fn(|i| 0x1000 + i as u64));
        assert_eq!((first.x16, first.x17, first.lr), (0x1010, 0x1011, 0x101e));
        assert!(first.to.guarded && hits[1].from.guarded && hits[2].to.guarded);
        assert_eq!(hits[1].kind, MonitorKind::GuardedEnter { immediate: 8 });
        assert_eq!(hits[2].kind, MonitorKind::GuardedExit);
        assert_eq!(hits[2].to.pc, hits[1].from.pc + 4);
        traced.set_monitor_tracing(false);
        traced.system_instruction(GENTER).unwrap();
        assert_eq!(traces(&traced), hits);
    }

    #[test]
    fn monitor_tracing_covers_guarded_el0_svc_and_return_values() {
        let mut machine = gxf(Chip::AppleM2);
        machine.set_monitor_tracing(true);
        machine.system_instruction(GENTER).unwrap();
        let bank = &mut machine.cpu.apple.guarded[0];
        bank.vbar = BASE + 0xa000;
        bank.spsr = 0x3c0; // GL0t with DAIF masked, as the existing GXF owner.
        bank.elr = BASE + 0xb000;
        machine.cpu.state.x[0] = 0x1234;
        machine.system_instruction(ERET).unwrap();
        assert_eq!(
            (machine.cpu.pstate.el, machine.cpu.pstate.guarded),
            (0, true)
        );
        machine.system_instruction(SVC | (0x73 << 5)).unwrap();
        machine.cpu.state.x[0] = 0x5678;
        machine.system_instruction(ERET).unwrap();
        let hits = traces(&machine);
        assert_eq!(hits.len(), 4);
        assert_eq!(hits[1].kind, MonitorKind::ExceptionReturn);
        assert_eq!(
            (hits[1].from.el, hits[1].to.el, hits[1].arguments[0]),
            (1, 0, 0x1234)
        );
        assert!(
            matches!(hits[2].kind, MonitorKind::Exception { vector: Vector::Synchronous, syndrome, return_address, fault_address: None }
            if syndrome >> 26 == 0x15 && syndrome & 0xffff == 0x73 && return_address == BASE + 0xb004)
        );
        assert_eq!((hits[2].from.el, hits[2].to.el), (0, 1));
        assert_eq!(
            (hits[3].to.pc, hits[3].arguments[0]),
            (BASE + 0xb004, 0x5678)
        );
    }

    #[test]
    fn monitor_tracing_retains_gl2_interrupts_faults_and_illegal_erets() {
        use super::super::Exception;
        let mut machine = gxf(Chip::AppleM2);
        machine.cpu.set_pstate(Pstate::reset(2));
        machine.cpu.apple.gxf_config[1] = 1;
        machine.cpu.apple.guarded[1].enter = BASE + 0x9000;
        machine.cpu.apple.guarded[1].vbar = BASE + 0xa000;
        machine.set_monitor_tracing(true);
        machine.system_instruction(GENTER).unwrap();
        let interrupted = machine.cpu.pc;
        machine.take(Exception {
            vector: Vector::Irq,
            syndrome: 0,
            fault_address: None,
            return_address: interrupted,
            target: None,
        });
        machine.system_instruction(ERET).unwrap();
        assert_eq!(machine.cpu.pc, interrupted);
        let mut fault = Exception::undefined(interrupted);
        fault.fault_address = Some(0xdead_0000);
        machine.take(fault);
        // An illegal return is observable state (IL), not a refused ERET.
        machine.cpu.apple.guarded[1].spsr = 0b1111;
        machine.system_instruction(ERET).unwrap();
        let hits = traces(&machine);
        assert_eq!(hits.len(), 5);
        assert_eq!((hits[0].from.el, hits[0].to.el), (2, 2));
        assert!(
            matches!(hits[1].kind, MonitorKind::Exception { vector: Vector::Irq, return_address, .. } if return_address == interrupted)
        );
        assert!(matches!(
            hits[3].kind,
            MonitorKind::Exception {
                fault_address: Some(0xdead_0000),
                ..
            }
        ));
        assert_eq!(hits[4].kind, MonitorKind::ExceptionReturn);
        assert!(hits[4].to.illegal);
    }

    #[test]
    fn monitor_tracing_distinguishes_refused_and_undefined_operations() {
        let mut machine = gxf(Chip::AppleM2);
        machine.set_monitor_tracing(true);
        // Outside a GL, GEXIT is UNDEFINED; no guarded boundary occurred.
        machine.system_instruction(GEXIT).unwrap();
        assert!(traces(&machine).is_empty());
        machine.cpu.pc = BASE;
        machine.system_instruction(GENTER).unwrap();
        machine.cpu.set_pstate(Pstate {
            el: 0,
            sp: false,
            guarded: true,
            ..Pstate::reset(1)
        });
        let count = traces(&machine).len();
        machine.system_instruction(GENTER).unwrap();
        let hits = traces(&machine);
        assert_eq!(hits.len(), count + 1);
        // GL0 GENTER takes UNDEFINED, never a successful call.
        assert!(
            matches!(hits.last().unwrap().kind, MonitorKind::Exception { syndrome, .. } if syndrome >> 26 == 0)
        );
    }
}

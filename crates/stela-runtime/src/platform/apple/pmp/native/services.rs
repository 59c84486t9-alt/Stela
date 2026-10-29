//! Cooperative native endpoint3/4 and MC destination composition.
//!
//! Source: original26A434 T8112 PMP b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c,
//! pmgr/metrics-backend-destinations-r1 and native-scheduler-r1. No firmware
//! executes. Mailboxes are paired RTKit slots; mappings keep the real
//! DMA broker. Startup never supplies an AP allocation or echoes an AP message.
use super::{dma, platform::owner::Completion, reporting, scheduler, trace};
use alloc::{
    boxed::Box,
    rc::{Rc, Weak},
};
use core::cell::{Cell, RefCell};
use {
    crate::platform::apple::rtkit, crate::platform::apple::rtkit::channel,
    stela_contracts::bus::Access,
};

mod clock;
mod metrics_backend;
mod reporting_backend;
mod trace_backend;
pub use clock::Clock;
pub use metrics_backend::MetricsBackend;

type Report = reporting::Owner<reporting_backend::Resources>;
type Trace = trace::Owner<trace_backend::Resources>;
type Slot<T> = Rc<RefCell<Weak<RefCell<T>>>>;
fn done<T>(value: T) -> Completion<T> {
    Completion::Retired {
        value,
        refusal: None,
    }
}
fn runtime(weak: &scheduler::WeakRuntime) -> Result<scheduler::Runtime, &'static str> {
    weak.upgrade().ok_or("native services scheduler abandoned")
}
fn current(weak: &scheduler::WeakRuntime) -> Result<scheduler::Invocation, &'static str> {
    runtime(weak)?
        .current()
        .ok_or("native service requires actual cooperative invocation")
}
fn owner<T>(slot: &Slot<T>) -> Result<Rc<RefCell<T>>, &'static str> {
    slot.borrow()
        .upgrade()
        .ok_or("native service owner abandoned")
}
fn trace_error(error: trace::Error) -> &'static str {
    match error {
        trace::Error::Contract(e) | trace::Error::Backend(e) => e,
    }
}
fn schedule_error(error: scheduler::Error) -> &'static str {
    match error {
        scheduler::Error::Contract(e) | scheduler::Error::Callback(e) => e,
    }
}

pub struct Progress {
    pub reporting_ready: bool,
    pub trace_initialized: bool,
    pub work: scheduler::Progress,
}
/// Own this with the real Broker dispatcher and returned RTKit endpoints.
/// Dropping it does not claim an unmap, source reset or remote acknowledgement.
pub struct Services {
    runtime: scheduler::Runtime,
    global: scheduler::Queue,
    report: Rc<RefCell<Report>>,
    trace: Rc<RefCell<Trace>>,
    report_shared: Rc<reporting_backend::Shared>,
    trace_shared: Rc<trace_backend::Shared>,
    report_init: scheduler::Immediate,
    trace_init: scheduler::Immediate,
    report_input: scheduler::Immediate,
    trace_input: scheduler::Immediate,
}
impl Services {
    /// Bind source T8112 defaults to native resources.
    ///
    /// # Safety
    /// All calls/callbacks must execute on the same cooperative BSP,
    /// under the root's stopped-worker/all-writer canonical transfer ownership.
    /// Broker must name that same registered RAM, DART and AP allocator.
    /// Source DMA synchronize must retire before local fences. The caller must
    /// keep these ownership guarantees for the complete Services lifetime;
    /// fences here do not prove an MCC drain or acknowledge any hardware event.
    pub unsafe fn t8112(
        broker: dma::Broker,
        clock: Clock,
    ) -> Result<(Self, rtkit::SystemEndpoints), &'static str> {
        let runtime = scheduler::Runtime::new();
        let global = runtime.global_reporting_queue().map_err(schedule_error)?;
        let (report_endpoint, report_mailbox) = channel::channel();
        let (trace_endpoint, trace_mailbox) = channel::channel();
        let report_slot: Slot<Report> = Rc::new(RefCell::new(Weak::new()));
        let trace_slot: Slot<Trace> = Rc::new(RefCell::new(Weak::new()));
        let report_shared = Rc::new(reporting_backend::Shared::new(
            runtime.downgrade(),
            global.clone(),
            broker.clone(),
            clock,
            report_mailbox,
            report_slot.clone(),
        ));
        let report = Rc::new(RefCell::new(reporting::Owner::new(
            reporting_backend::Resources::new(report_shared.clone()),
        )));
        *report_slot.borrow_mut() = Rc::downgrade(&report);
        let receiver = report.borrow().receiver();
        let trace_shared = Rc::new(trace_backend::Shared::new(
            runtime.downgrade(),
            global.clone(),
            broker,
            clock,
            trace_mailbox,
            trace_slot.clone(),
        ));
        let trace = Rc::new(RefCell::new(trace::Owner::initialized(
            trace::Configuration::t8112(),
            trace_backend::Resources::new(trace_shared.clone()),
        )));
        *trace_slot.borrow_mut() = Rc::downgrade(&trace);
        let report_init = runtime
            .register_immediate(
                "IOReporting source enter",
                57,
                reporting_backend::Initialize::new(report_shared.clone()),
            )
            .map_err(schedule_error)?;
        let trace_init = runtime
            .register_immediate(
                "trace source initialize",
                57,
                trace_backend::Initialize::new(trace_shared.clone()),
            )
            .map_err(schedule_error)?;
        let report_input = runtime
            .register_immediate(
                "IOReporting actual AP receive",
                63,
                reporting_backend::Input::new(report_shared.clone(), receiver),
            )
            .map_err(schedule_error)?;
        let trace_input = runtime
            .register_immediate(
                "trace actual AP receive",
                63,
                trace_backend::Input::new(trace_shared.clone()),
            )
            .map_err(schedule_error)?;
        Ok((
            Self {
                runtime,
                global,
                report,
                trace,
                report_shared,
                trace_shared,
                report_init,
                trace_init,
                report_input,
                trace_input,
            },
            rtkit::SystemEndpoints {
                trace: Some(Box::new(trace_endpoint)),
                reporting: Some(Box::new(report_endpoint)),
            },
        ))
    }
    pub fn runtime(&self) -> scheduler::Runtime {
        self.runtime.clone()
    }
    /// A real required callback. Production callers capture Weak MC service
    /// ownership and call its dispatch_metrics(Invocation, Samples).
    /// Missing/abandoned service ownership must return Refused, never Retired0.
    pub fn metrics_backend<C: scheduler::Callback + 'static>(&self, callback: C) -> MetricsBackend {
        MetricsBackend::new(
            self.runtime.clone(),
            self.global.clone(),
            Rc::downgrade(&self.report),
            Rc::downgrade(&self.trace),
            callback,
        )
    }
    pub fn reporting_ready(&self) -> bool {
        self.report_shared.ready.get()
    }
    /// Initializer return, not its earlier source software-cell write.
    pub fn trace_initialized(&self) -> bool {
        self.trace_shared.init_complete.get()
    }
    /// Stela scheduling deadline, independent of raw/converted source clock.
    /// Waiting for an AP allocation/ACK alone supplies no zero-deadline spin.
    pub fn deadline(&self) -> Option<u64> {
        if (self.report_shared.started()
            && (!self.report_shared.init_started.get() || self.report_shared.pending_input()))
            || (self.trace_shared.started()
                && (!self.trace_shared.init_started.get() || self.trace_shared.pending_input()))
        {
            return Some(0);
        }
        if !self.trace_shared.lifecycle_input.borrow().is_empty() {
            return Some(0);
        }
        self.runtime.next_deadline()
    }
    /// Source lifecycle DATA request; the registered native callback
    /// performs pause/flush/wait/resume under the real global queue lease.
    pub fn begin_trace_lifecycle(&mut self, prior: u32, next: u32) -> Result<(), &'static str> {
        if !self.trace_initialized() {
            return Err("trace lifecycle before source initialization");
        }
        if !self.trace_shared.lifecycle_input.borrow().is_empty() {
            return Err("trace lifecycle input already retained");
        }
        self.trace_shared
            .lifecycle_input
            .borrow_mut()
            .push_back((prior, next));
        Ok(())
    }
    /// Bounded inbox/startup dispatch plus one queued-work step.
    /// Independent reporting ACK input can retire while registration waits.
    pub fn advance(&mut self, access: &mut Access<'_>) -> Result<Progress, &'static str> {
        if self.report_shared.started() {
            if !self.report_shared.ready.get() {
                self.runtime
                    .invoke(&self.report_init, access)
                    .map_err(schedule_error)?;
            }
            if self.report_shared.claimed.get() {
                self.runtime
                    .invoke(&self.report_input, access)
                    .map_err(schedule_error)?;
            }
        }
        if self.trace_shared.started() {
            if !self.trace_initialized() {
                self.runtime
                    .invoke(&self.trace_init, access)
                    .map_err(schedule_error)?;
            }
            if self.trace_shared.work.borrow().is_some() {
                self.runtime
                    .invoke(&self.trace_input, access)
                    .map_err(schedule_error)?;
            }
        }
        self.trace_shared.advance_lifecycle(access)?;
        let work = self.runtime.step(access).map_err(schedule_error)?;
        Ok(Progress {
            reporting_ready: self.reporting_ready(),
            trace_initialized: self.trace_initialized(),
            work,
        })
    }
    /// Memory-loss/replacement is not an implicit Drop reset. Reporting's real
    /// exit and trace mapping ownership must be joined to a source
    /// lifecycle invocation before RTKit reset is admitted.
    pub fn check_reset(&self) -> Result<(), &'static str> {
        Err("native reporting/trace memory-loss lifecycle is not joined to RTKit reset")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use stela_contracts::interrupt::InterruptLatch;
    fn ticks() -> u64 {
        24_000_000
    }
    fn fixture() -> (Services, rtkit::SystemEndpoints, dma::Service) {
        let (broker, dispatcher) = dma::pair(
            dma::Route {
                mapper: 1,
                iommu: 0,
                instance: 0,
                context: 0,
                stream: 0,
            },
            dma::Owners {
                dart: Rc::new(()),
                canonical_ram: Rc::new(()),
                allocator: Rc::new(()),
            },
            dma::Configuration {
                mapper_index: 0,
                asc_dram_mask: 0,
                synchronization_granule: 8,
            },
        )
        .unwrap();
        // This fixture exercises only transport/software/no-buffer branches;
        // no DMA grant retires and no canonical memory/fence is invented.
        let (services, endpoints) =
            // SAFETY: the fixture's broker and clock are its own, and these branches retire no DMA
            // grant.
            unsafe { Services::t8112(broker, Clock::new(ticks, 24_000_000, 0).unwrap()).unwrap() };
        (services, endpoints, dispatcher)
    }
    fn advance(s: &mut Services) {
        let mut irq = InterruptLatch::new();
        s.advance(&mut Access::new(0, 999, &mut irq)).unwrap();
    }
    #[test]
    fn real_endpoint_start_gates_native_initialization_and_trace_input() {
        let (mut services, mut endpoints, _dispatcher) = fixture();
        assert_eq!(services.deadline(), None);
        advance(&mut services);
        assert!(!services.trace_initialized() && !services.reporting_ready());
        let trace = endpoints.trace.as_mut().unwrap();
        let mut output = Vec::new();
        trace.start(&mut output).unwrap();
        assert_eq!(services.deadline(), Some(0));
        for _ in 0..24 {
            advance(&mut services);
            if services.trace_initialized() {
                break;
            }
        }
        assert!(services.trace_initialized());
        assert!(!services.reporting_ready());
        trace.receive(8 << 48, &mut output).unwrap();
        for _ in 0..24 {
            advance(&mut services);
            trace.poll(&mut output).unwrap();
            if !output.is_empty() {
                break;
            }
        }
        assert_eq!(output, alloc::vec![(1 << 48) | 0x8001]);
        assert!(services.check_reset().is_err());
    }
    #[test]
    fn trace_work_waits_for_initializer_return_after_software_flag_write() {
        let (mut services, mut endpoints, _dispatcher) = fixture();
        let endpoint = endpoints.trace.as_mut().unwrap();
        let mut output = Vec::new();
        endpoint.start(&mut output).unwrap();
        endpoint.receive(8 << 48, &mut output).unwrap();
        let mut reached_partial = false;
        for _ in 0..24 {
            advance(&mut services);
            if services.trace.borrow().is_initialized() && !services.trace_initialized() {
                reached_partial = true;
                break;
            }
        }
        assert!(reached_partial);
        assert!(services.trace.borrow().foreground_pending());
        assert!(!services.trace.borrow().dispatch_pending());
        assert_eq!(services.deadline(), Some(0));
        // Continue the SAME initializer until its terminal source return;
        // only then may the queued command begin protocol execution.
        advance(&mut services);
        assert!(services.trace_initialized());
        assert!(!services.trace.borrow().foreground_pending());
        for _ in 0..24 {
            advance(&mut services);
            endpoint.poll(&mut output).unwrap();
            if !output.is_empty() {
                break;
            }
        }
        assert_eq!(output, alloc::vec![(1 << 48) | 0x8001]);
    }
    #[test]
    fn reporting_real_request_waits_for_ap_input_without_fake_allocation_or_spin() {
        let (mut services, mut endpoints, _dispatcher) = fixture();
        let report = endpoints.reporting.as_mut().unwrap();
        let mut output = Vec::new();
        report.start(&mut output).unwrap();
        for _ in 0..12 {
            advance(&mut services);
            report.poll(&mut output).unwrap();
            if !output.is_empty() {
                break;
            }
        }
        assert_eq!(output, alloc::vec![reporting::wire::BUFFER_REQUEST]);
        assert_eq!(services.deadline(), None);
        assert!(!services.reporting_ready());
        // A real consumed AP reply wakes startup, but the unresolved DMA
        // map still cannot become READY or an AP buffer advertisement.
        report
            .receive((1 << 52) | (0x48 << 44) | 0x4000, &mut Vec::new())
            .unwrap();
        assert_eq!(services.deadline(), Some(0));
        for _ in 0..8 {
            advance(&mut services);
        }
        report.poll(&mut output).unwrap();
        assert_eq!(output.len(), 1);
        assert!(!services.reporting_ready());
    }
}

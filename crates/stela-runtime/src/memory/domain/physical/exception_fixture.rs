//! Test-only observations of the SAME original PE's local reservation.
//! A real monitor load seeds the actual original context; a metadata-only
//! conditional callback probes it after the PE ends. Neither is a guest ISA
//! execution claim and the probe writes no target RAM.
use super::PhysicalAddressSpace;
use crate::memory::{
    backing::{MemoryBacking, MemoryView},
    domain::{MappingAttributes, MemoryDomain, MemoryExecutionLoan, MemoryThread},
    monitor,
    policy::MemoryControls,
};
use std::sync::Arc;
use stela_compiler::TargetCpu;
const RESERVATION_BYTES: usize = size_of::<u64>();

pub(crate) struct ExceptionReservationProbe {
    domain: Arc<MemoryDomain>,
    thread: *const MemoryThread<MemoryControls>,
    access: monitor::Access<MemoryBacking, MemoryView, MappingAttributes>,
}
impl ExceptionReservationProbe {
    pub(crate) fn probe_after_pe(
        self,
        actual: &mut MemoryThread<MemoryControls>,
    ) -> Result<bool, String> {
        if !Arc::ptr_eq(&self.domain, &actual.domain) || !std::ptr::eq(self.thread, actual) {
            return Err("exception probe lost the original reservation context".into());
        }
        self.domain
            .check_execution()
            .map_err(|e| format!("{e:?}"))?;
        let result = self
            .domain
            .system
            .reservations
            .store(&mut actual.reservation, &self.access, || Ok::<(), ()>(()))
            .map_err(|e| format!("{e:?}"))?;
        Ok(matches!(result, monitor::ConditionalWrite::Stored(())))
    }
}
impl PhysicalAddressSpace {
    pub(crate) fn seed_exception_reservation_for_fixture(
        &self,
        outer: &MemoryExecutionLoan,
        actual: &mut MemoryThread<MemoryControls>,
        address: u64,
    ) -> Result<ExceptionReservationProbe, String> {
        self.check_execution_loan(outer)
            .map_err(|e| format!("{e:?}"))?;
        outer
            .check_thread_domain(actual)
            .map_err(|e| format!("{e:?}"))?;
        let pin = self
            .resolve_ram8(outer, address)
            .map_err(|e| format!("{e:?}"))?;
        let registered = self.domain.registered_views();
        let mapping = registered
            .iter()
            .find(|r| Arc::ptr_eq(&r.view, pin.reached.first().view()))
            .ok_or("exception canary is not an original registered physical view")?;
        let access = monitor::Access::new(
            Arc::clone(pin.reached.first().view().backing()),
            Arc::clone(&mapping.monitor),
            pin.reached.first().backing_offset() as u64,
            RESERVATION_BYTES as u8,
            monitor::Shape::Scalar,
        )
        .map_err(|e| format!("{e:?}"))?;
        self.domain
            .system
            .reservations
            .load(&mut actual.reservation, &access, || {
                pin.check_current().map_err(|e| format!("{e:?}"))?;
                // SAFETY: the original source physical owner and SAME outer/pin
                // retain this exact aligned readable coherent-RAM eight-byte extent.
                unsafe {
                    crate::memory::access::read_part(
                        pin.pointer(),
                        RESERVATION_BYTES,
                        TargetCpu::Baseline,
                    )
                }
                .map_err(|e| format!("{e:?}"))
            })
            .map_err(|e| format!("{e:?}"))?;
        Ok(ExceptionReservationProbe {
            domain: Arc::clone(&self.domain),
            thread: std::ptr::from_ref(actual),
            access,
        })
    }
}

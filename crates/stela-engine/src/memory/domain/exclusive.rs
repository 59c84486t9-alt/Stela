//! Exclusive accesses over the shared memory and monitor.

use super::{
    AccessKind, Arc, DataOperation, DataPart, DataPolicy, DataRequest, MemoryThread, SCA_BYTES,
    access, monitor,
};
use stela_compiler::{
    TargetCpu,
    context::memory::{
        MemoryContextView, MemoryOrder, MemoryRequest, MemoryRequirements, MemoryStatus,
        SpAlignmentRequirement,
        exclusive::{
            EXCLUSIVE_DATA_ALIGNMENT, EXCLUSIVE_FAILED, EXCLUSIVE_STORED, ExclusiveData,
            ExclusiveOperation, ExclusiveShape,
        },
        flags, host_caps, profile_requirements,
    },
};

const SCA_MASK: u64 = SCA_BYTES as u64 - 1;
const EXCLUSIVE_ALLOWED: u32 = flags::EXCLUSIVE | flags::WRITE | flags::TAG_CHECKED;

impl<P: DataPolicy> MemoryThread<P> {
    /// Perform one checked exclusive load, conditional store or CLREX. The
    /// dispatcher contains panics and settles faults; outputs are staged until
    /// the whole operation completes.
    ///
    /// # Safety
    /// Request data is 32 initialized bytes of aligned, disjoint private
    /// ExclusiveData staging, not just `request.bytes`. The checked entry keeps
    /// the CPU policy and the PE's endpoint live through the call. Backing
    /// rights and lifetime follow `with_view`'s contract.
    pub(super) unsafe fn transfer_exclusive(
        &mut self,
        view: &mut MemoryContextView,
        request: &MemoryRequest,
    ) -> Result<(), (MemoryStatus, u64)> {
        let raw = request.address;
        let fail = |status| (status, raw);
        if request.flags & flags::EXCLUSIVE == 0
            || request.flags & !EXCLUSIVE_ALLOWED != 0
            || request.data.is_null()
            || request.data as usize & (EXCLUSIVE_DATA_ALIGNMENT - 1) != 0
            || view.completed_bytes != 0
        {
            return Err(fail(MemoryStatus::InvalidRequest));
        }
        // SAFETY: the dedicated category grants the complete private payload.
        // No unchecked integer is interpreted as a Rust enum.
        let data = unsafe { request.data.cast::<ExclusiveData>().read() };
        let (operation, order, shape) = data
            .validate(request.bytes)
            .ok_or_else(|| fail(MemoryStatus::InvalidRequest))?;
        let write = operation == ExclusiveOperation::Store;
        if (request.flags & flags::WRITE != 0) != write
            || operation == ExclusiveOperation::Clear
                && (raw != 0 || request.flags != flags::EXCLUSIVE)
        {
            return Err(fail(MemoryStatus::InvalidRequest));
        }
        self.validate_execution(request.flags).map_err(fail)?;
        if operation == ExclusiveOperation::Clear {
            return self.clear_reservation().map_err(fail);
        }
        let writeback_read = !write
            && self.domain.role == super::DomainRole::NativeSystemRam
            && !self.domain.target.supports(TargetCpu::AtomicLoad16);
        let requirements = MemoryRequirements {
            required_pointer_arithmetic: None,
            required_address_checks: Default::default(),
            required_flags: request.flags,
            required_host_caps: if writeback_read {
                host_caps::CX16
            } else if request.bytes as usize == SCA_BYTES {
                if write {
                    host_caps::CX16
                } else {
                    host_caps::ATOMIC_LOAD16
                }
            } else {
                0
            },
            required_profile: profile_requirements::NATIVE_ACCESS
                | if writeback_read {
                    profile_requirements::SYSTEM_ATOMIC_READ_WRITEBACK
                } else {
                    0
                }
                | if request.flags & flags::TAG_CHECKED != 0 {
                    profile_requirements::TAG_GRANULES
                } else {
                    0
                },
            required_sp_alignment: SpAlignmentRequirement::Any,
            ..MemoryRequirements::default()
        };
        self.domain
            .profile()
            .map_err(fail)?
            .validate(requirements, self.domain.target)
            .map_err(fail)?;
        // Selected June AllInSCAGranule quantity is 16 with LSE2 and alignment
        // enforcement off. Sub-16 unaligned quantities within it remain valid.
        if raw & SCA_MASK > SCA_BYTES as u64 - u64::from(request.bytes) {
            return Err(fail(MemoryStatus::Alignment));
        }
        let intent = DataRequest::native(request, DataOperation::Exclusive);
        self.policy.validate_data_request(intent).map_err(fail)?;
        let kind = if write {
            AccessKind::Write
        } else {
            AccessKind::Read
        };
        let address = self.policy.translate_part(
            intent,
            DataPart {
                address: raw,
                bytes: request.bytes as usize,
                kind,
            },
        )?;
        if address & SCA_MASK != raw & SCA_MASK {
            return Err(fail(MemoryStatus::Unsupported));
        }
        let bytes = request.bytes as usize;
        // The architecture allows abort detection before the local-monitor
        // check. A store requires only guest write permission; the helper's
        // read-modify-write readability is a host footprint condition below.
        let physical = self
            .domain
            .resolve(
                address,
                bytes,
                if write {
                    AccessKind::Write
                } else {
                    AccessKind::Read
                },
            )
            .map_err(fail)?;
        let first = physical.first();
        let pointer = first
            .view()
            .backing()
            .host_pointer(
                first.backing_offset(),
                bytes,
                if write {
                    AccessKind::Write
                } else {
                    AccessKind::Read
                },
            )
            .map_err(|_| fail(MemoryStatus::Unsupported))?
            .as_ptr();
        if pointer as usize & (SCA_BYTES - 1) != address as usize & (SCA_BYTES - 1) {
            return Err(fail(MemoryStatus::Unsupported));
        }
        let target = self.domain.target;
        if write {
            first
                .view()
                .backing()
                .host_pointer(first.backing_offset(), bytes, AccessKind::Read)
                .map_err(|_| fail(MemoryStatus::Unsupported))?;
            if bytes == SCA_BYTES && !target.supports(TargetCpu::Cx16) {
                return Err(fail(MemoryStatus::Unsupported));
            }
        }
        let read = if write {
            None
        } else {
            Some(self.domain.prepare_read(first, bytes).map_err(fail)?)
        };
        // Resolution already covered the whole quantity; this lookup returns
        // its first mapping without creating another monitor.
        let state = self
            .domain
            .state
            .lock()
            .map_err(|_| fail(MemoryStatus::Domain))?;
        let registered = state
            .snapshot
            .views
            .binary_search_by_key(&first.view().guest_base(), |view| view.view.guest_base())
            .map_err(|_| fail(MemoryStatus::Domain))?;
        let reserved = monitor::Access::new(
            Arc::clone(first.view().backing()),
            Arc::clone(&state.snapshot.views[registered].monitor),
            first.backing_offset() as u64,
            request.bytes as u8,
            match shape {
                ExclusiveShape::Scalar => monitor::Shape::Scalar,
                ExclusiveShape::Pair => monitor::Shape::Pair,
            },
        )
        .map_err(|_| fail(MemoryStatus::Domain))?;
        drop(state);
        let mut output = data;
        if write {
            let value = u128::from(data.value[0]) | u128::from(data.value[1]) << u64::BITS;
            let mut mutation = self
                .domain
                .system
                .prepare_source_write(first.view().backing(), first.backing_offset(), bytes)
                .map_err(fail)?;
            let result = self
                .domain
                .system
                .reservations
                .store(&mut self.reservation, &reserved, || {
                    physical.check_current()?;
                    self.policy
                        .check(physical.data(raw, bytes, request.flags))?;
                    self.domain.check_execution()?;
                    // XCHG/CX16 supplies conservative full WB ordering for the
                    // release variant too; no dependency on ordinary MOV stores.
                    mutation.attempting();
                    // SAFETY: physical.check_current and policy checked the whole pinned quantity,
                    // its native rights and target; the reservation store holds the writer gate.
                    unsafe { access::write_part(pointer, bytes, value, target) }
                        .map_err(|_| MemoryStatus::Unsupported)?;
                    let _receipt = mutation.complete();
                    // Record the committed bytes in case a later state is
                    // terminal; no payload or register result is published on
                    // that error.
                    view.completed_bytes = u64::from(request.bytes);
                    Ok::<_, MemoryStatus>(())
                })
                .map_err(|error| fail(exclusive_error(error)))?;
            output.status = match result {
                monitor::ConditionalWrite::Stored(()) => EXCLUSIVE_STORED,
                monitor::ConditionalWrite::Failed => EXCLUSIVE_FAILED,
            };
        } else {
            let scope = if physical.attributes.shareable {
                monitor::ReservationScope::Global
            } else {
                monitor::ReservationScope::Local
            };
            let value = self
                .domain
                .system
                .reservations
                .load_with_scope(&mut self.reservation, &reserved, scope, || {
                    physical.check_current()?;
                    self.policy
                        .check(physical.data(raw, bytes, request.flags))?;
                    self.domain.check_execution()?;
                    if order == MemoryOrder::AcquireRcsc {
                        // Conservative fences for x86 write-back memory.
                        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
                    }
                    // SAFETY: the requested part and read envelope are live, no
                    // Rust reference to the RAM exists, and the host features
                    // are checked.
                    // ERGs are at least SCA16 and congruent with this source
                    // quantity, so the held reservation gate covers the entire
                    // aligned read/writeback envelope without invalidating it.
                    unsafe {
                        read.as_ref()
                            .expect("load has a prepared read")
                            .read_in_observer()
                    }
                })
                .map_err(|error| fail(exclusive_error(error)))?;
            output.value = [value as u64, (value >> u64::BITS) as u64];
            view.completed_bytes = u64::from(request.bytes);
        }
        self.domain.check_execution().map_err(fail)?;
        // SAFETY: only complete success publishes the initialized private result.
        unsafe { request.data.cast::<ExclusiveData>().write(output) };
        Ok(())
    }
}

fn exclusive_error(error: monitor::AccessError<MemoryStatus>) -> MemoryStatus {
    match error {
        monitor::AccessError::Monitor(_) => MemoryStatus::Domain,
        monitor::AccessError::Memory(status) => status,
    }
}

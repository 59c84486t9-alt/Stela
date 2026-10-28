//! LSE and ordered operations over the same physical all-writer protocol as
//! ordinary stores, exclusive stores and host publication. No direct/DMA writer
//! may bypass it. Each typed request owns initialized disjoint private staging.
use super::{
    AccessKind, Arc, DataOperation, DataPart, DataPolicy, DataRequest, MemoryThread, SCA_BYTES,
    access, monitor,
};
use core::sync::atomic::{Ordering, fence};
use stela_compiler::{
    TargetCpu,
    context::memory::{
        FaultAccess, InstructionRequirements, MemoryContextView, MemoryRequest, MemoryStatus,
        atomic::{AtomicData, AtomicOperation},
        flags,
        ordered::{OrderedData, OrderedOperation},
    },
};
const SHARED_ALLOWED: u32 = flags::ATOMIC | flags::ORDERED | flags::WRITE | flags::TAG_CHECKED;
impl<P: DataPolicy> MemoryThread<P> {
    /// # Safety
    /// ATOMIC grants a complete aligned AtomicData, ORDERED an OrderedData;
    /// neither is a byte-count-sized buffer. All with_view storage rules apply.
    pub(super) unsafe fn transfer_shared(
        &mut self,
        view: &mut MemoryContextView,
        request: &MemoryRequest,
    ) -> Result<(), (MemoryStatus, u64)> {
        let fail = |status| (status, request.address);
        if request.flags & !SHARED_ALLOWED != 0
            || request.data.is_null()
            || request.data as usize & 7 != 0
            || view.completed_bytes != 0
            || (request.flags & (flags::ATOMIC | flags::ORDERED)).count_ones() != 1
        {
            return Err(fail(MemoryStatus::InvalidRequest));
        }
        self.validate_execution(request.flags).map_err(fail)?;
        if request.flags & flags::ATOMIC != 0 {
            // SAFETY: this typed category grants all 64 initialized bytes.
            let data = unsafe { request.data.cast::<AtomicData>().read() };
            let (operation, _) = data
                .validate(request.bytes)
                .ok_or_else(|| fail(MemoryStatus::InvalidRequest))?;
            if request.flags & flags::WRITE == 0 {
                return Err(fail(MemoryStatus::InvalidRequest));
            }
            self.policy
                .validate_instructions(InstructionRequirements::LSE)
                .map_err(fail)?;
            // SAFETY: payload and owner were validated above.
            unsafe { self.atomic(view, request, data, operation) }
        } else {
            // SAFETY: the ordered category grants its full initialized payload.
            let mut data = unsafe { request.data.cast::<OrderedData>().read() };
            let (operation, _, feature) = data
                .validate(request.bytes)
                .ok_or_else(|| fail(MemoryStatus::InvalidRequest))?;
            if (request.flags & flags::WRITE != 0) != (operation == OrderedOperation::Store) {
                return Err(fail(MemoryStatus::InvalidRequest));
            }
            self.policy
                .validate_instructions(feature.requirements())
                .map_err(fail)?;
            if operation == OrderedOperation::Barrier {
                if request.address != 0 || request.flags != flags::ORDERED {
                    return Err(fail(MemoryStatus::InvalidRequest));
                }
                // Scope strengthens to coherent host WB memory. x86 already
                // orders LD/ST subsets; Rust fences retain compiler ordering.
                // Reserved xx00 options have the architectural SY fallback.
                fence(match data.barrier & 3 {
                    1 => Ordering::Acquire,
                    2 => Ordering::Release,
                    _ => Ordering::SeqCst,
                });
            } else {
                if request.address & (SCA_BYTES as u64 - 1)
                    > SCA_BYTES as u64 - u64::from(request.bytes)
                {
                    return Err(fail(MemoryStatus::Alignment));
                }
                let transfer = MemoryRequest {
                    address: request.address,
                    bytes: request.bytes,
                    flags: request.flags & !flags::ORDERED,
                    pc: request.pc,
                    data: core::ptr::from_mut(&mut data.value).cast(),
                };
                // SAFETY: exact value staging is private and the ordinary path
                // shares the same checked writer and SCA-reader services.
                unsafe { self.transfer_ordinary(view, &transfer, DataOperation::Ordered)? };
                if operation == OrderedOperation::Load {
                    // MOV reads are acquire on coherent x86 WB RAM; a compiler
                    // acquire fence is sufficient, with XCHG source releases.
                    fence(Ordering::Acquire);
                }
            }
            // SAFETY: only complete success publishes initialized staged output.
            unsafe { request.data.cast::<OrderedData>().write(data) };
            Ok(())
        }
    }

    unsafe fn atomic(
        &mut self,
        view: &mut MemoryContextView,
        request: &MemoryRequest,
        mut data: AtomicData,
        operation: AtomicOperation,
    ) -> Result<(), (MemoryStatus, u64)> {
        let raw = request.address;
        let fail = |status| (status, raw);
        let bytes = request.bytes as usize;
        if raw & (SCA_BYTES as u64 - 1) > SCA_BYTES as u64 - u64::from(request.bytes) {
            return Err(fail(MemoryStatus::Alignment));
        }
        let intent = DataRequest::native(request, DataOperation::Atomic);
        self.policy.validate_data_request(intent).map_err(fail)?;
        view.fault_access = FaultAccess::Read as u32;
        let address = self.policy.translate_part(
            intent,
            DataPart {
                address: raw,
                bytes,
                kind: AccessKind::Read,
            },
        )?;
        if address & (SCA_BYTES as u64 - 1) != raw & (SCA_BYTES as u64 - 1) {
            return Err(fail(MemoryStatus::Unsupported));
        }
        let read = self
            .domain
            .resolve(address, bytes, AccessKind::Read)
            .map_err(fail)?;
        view.fault_access = FaultAccess::Write as u32;
        let write_address = self.policy.translate_part(
            intent,
            DataPart {
                address: raw,
                bytes,
                kind: AccessKind::Write,
            },
        )?;
        if write_address != address {
            // No RMW may combine a read from one physical identity with a
            // write to another if the dynamic source mapping changed.
            return Err(fail(MemoryStatus::Unsupported));
        }
        let write = self
            .domain
            .resolve(address, bytes, AccessKind::Write)
            .map_err(fail)?;
        let first = write.first();
        let pointer = first
            .view()
            .backing()
            .host_pointer(first.backing_offset(), bytes, AccessKind::Write)
            .map_err(|_| fail(MemoryStatus::Unsupported))?
            .as_ptr();
        first
            .view()
            .backing()
            .host_pointer(first.backing_offset(), bytes, AccessKind::Read)
            .map_err(|_| fail(MemoryStatus::Unsupported))?;
        if pointer as usize & (SCA_BYTES - 1) != address as usize & (SCA_BYTES - 1)
            || bytes == SCA_BYTES && !self.domain.target.supports(TargetCpu::Cx16)
        {
            return Err(fail(MemoryStatus::Unsupported));
        }
        let range = monitor::WriteRange::new(
            Arc::clone(first.view().backing()),
            first.backing_offset() as u64,
            bytes as u64,
        )
        .map_err(|_| fail(MemoryStatus::Domain))?;
        let mut mutation = self
            .domain
            .system
            .prepare_source_write(first.view().backing(), first.backing_offset(), bytes)
            .map_err(fail)?;
        let target = self.domain.target;
        let operand = u128::from(data.operand[0]) | u128::from(data.operand[1]) << 64;
        let compare = u128::from(data.compare[0]) | u128::from(data.compare[1]) << 64;
        let invalidation = if write.attributes.shareable {
            monitor::Invalidation::BeforeAttempt
        } else {
            monitor::Invalidation::OnCommit
        };
        let old = self
            .domain
            .system
            .reservations
            .with_writer(&range, invalidation, || {
                read.check_current()?;
                write.check_current()?;
                view.fault_access = FaultAccess::Read as u32;
                self.policy
                    .check(read.data(raw, bytes, request.flags & !flags::WRITE))?;
                view.fault_access = FaultAccess::Write as u32;
                self.policy.check(write.data(raw, bytes, request.flags))?;
                self.domain.check_execution()?;
                // A private exact-width read is stable under this physical gate:
                // every alias/source/host writer participates, mappings are pinned,
                // and no external/DMA writer or Rust RAM reference is admitted.
                // Ordinary readers still require their independent SCA capabilities.
                mutation.attempting();
                // The publication itself MUST be SCA for ordinary readers. Exact
                // Scalar arithmetic uses a gate-stable read followed by SCA
                // XCHG; pair16 CASP uses its source comparison in one CX16.
                let old =
                    unsafe { native_update(pointer, bytes, operation, operand, compare, target) }
                        .map_err(|_| MemoryStatus::Unsupported)?;
                let _receipt = mutation.complete();
                view.completed_bytes = u64::from(request.bytes);
                Ok(old)
            })
            .map_err(|error| {
                fail(match error {
                    monitor::AccessError::Monitor(_) => MemoryStatus::Domain,
                    monitor::AccessError::Memory(status) => status,
                })
            })?;
        self.domain.check_execution().map_err(fail)?;
        data.result = [old as u64, (old >> 64) as u64];
        // SAFETY: complete success publishes the private result; all fault paths
        // withhold it, including terminal finalization after a committed prefix.
        unsafe { request.data.cast::<AtomicData>().write(data) };
        Ok(())
    }
}
#[inline]
unsafe fn native_update(
    pointer: *mut u8,
    bytes: usize,
    operation: AtomicOperation,
    operand: u128,
    compare: u128,
    target: TargetCpu,
) -> Result<u128, access::AccessError> {
    // SAFETY: caller holds all physical gates and exact read/write rights for
    // pinned WB RAM; publication remains one SCA writer event. Scalar recipes
    // deliberately use the measured compact generic path. Pair16 can directly
    // supply the source comparison to one CX16, without a separate load/retry.
    unsafe {
        if operation == AtomicOperation::CompareExchangePair && bytes == SCA_BYTES {
            access::compare_exchange_part(pointer, bytes, compare, operand, target)
        } else {
            let old = private_read(pointer, bytes);
            let value = updated(operation, bytes, old, operand, compare);
            access::write_part(pointer, bytes, value, target)?;
            Ok(old)
        }
    }
}

unsafe fn private_read(pointer: *const u8, bytes: usize) -> u128 {
    // SAFETY: caller holds every touched physical writer gate and live exact
    // read rights, and never creates references to guest RAM.
    unsafe {
        match bytes {
            1 => u128::from(pointer.read()),
            2 => u128::from(pointer.cast::<u16>().read_unaligned()),
            4 => u128::from(pointer.cast::<u32>().read_unaligned()),
            8 => u128::from(pointer.cast::<u64>().read_unaligned()),
            16 => pointer.cast::<u128>().read_unaligned(),
            _ => unreachable!("validated atomic width"),
        }
    }
}
fn updated(
    operation: AtomicOperation,
    bytes: usize,
    old: u128,
    operand: u128,
    compare: u128,
) -> u128 {
    let shift = (16 - bytes) * 8;
    let mask = u128::MAX >> shift;
    let signed = |value: u128| ((value << shift) as i128) >> shift;
    (match operation {
        AtomicOperation::CompareExchange | AtomicOperation::CompareExchangePair => {
            if old == compare { operand } else { old }
        }
        AtomicOperation::Add => old.wrapping_add(operand),
        AtomicOperation::Clear => old & !operand,
        AtomicOperation::Xor => old ^ operand,
        AtomicOperation::Set => old | operand,
        AtomicOperation::SignedMax => {
            if signed(old) > signed(operand) {
                old
            } else {
                operand
            }
        }
        AtomicOperation::SignedMin => {
            if signed(old) < signed(operand) {
                old
            } else {
                operand
            }
        }
        AtomicOperation::UnsignedMax => old.max(operand),
        AtomicOperation::UnsignedMin => old.min(operand),
        AtomicOperation::Swap => operand,
    }) & mask
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use std::{
        cell::UnsafeCell,
        sync::{Arc, Barrier},
        time::Instant,
    };
    #[repr(align(64))]
    struct Storage(UnsafeCell<[u64; 64]>);
    // SAFETY: raw bytes are used only under the same monitor writer gate; no
    // reference to a shared RAM element is created by either candidate.
    unsafe impl Send for Storage {}
    unsafe impl Sync for Storage {}
    #[inline(never)]
    unsafe fn generic_candidate(
        pointer: *mut u8,
        operation: AtomicOperation,
        operand: u128,
        compare: u128,
        target: TargetCpu,
    ) -> u128 {
        // SAFETY: benchmark's gate owns the exact eight-byte pinned quantity.
        unsafe {
            let old = private_read(pointer, 8);
            let value = updated(operation, 8, old, operand, compare);
            access::write_part(pointer, 8, value, target).unwrap();
            old
        }
    }
    #[inline(never)]
    unsafe fn direct_candidate(
        pointer: *mut u8,
        operation: AtomicOperation,
        operand: u128,
        compare: u128,
        target: TargetCpu,
    ) -> u128 {
        // SAFETY: same exact pinned storage/gate as the generic candidate. These
        // direct recipes are candidates, not the selected scalar production path.
        unsafe {
            match operation {
                AtomicOperation::Add => access::add_part(pointer, 8, operand),
                AtomicOperation::Swap => access::exchange_part(pointer, 8, operand),
                AtomicOperation::CompareExchange => {
                    access::compare_exchange_part(pointer, 8, compare, operand, target)
                }
                _ => native_update(pointer, 8, operation, operand, compare, target),
            }
            .unwrap()
        }
    }
    #[test]
    #[ignore = "manual: opt-in"]
    fn benchmark_locked_recipes_with_identical_writer_gates() {
        const ITERATIONS: usize = 100_000;
        for operation in [
            AtomicOperation::Add,
            AtomicOperation::Swap,
            AtomicOperation::CompareExchange,
        ] {
            for case in ["dependent", "independent", "contended"] {
                for trial in 0..5 {
                    // Both recipes use the same backing identity, physical granules,
                    // stripe assignment and gate allocation for this paired trial.
                    let target = TargetCpu::detect();
                    let storage = Arc::new(Storage(UnsafeCell::new([0; 64])));
                    let monitor = monitor::MonitorDomain::<Storage, (), ()>::new(64, 16).unwrap();
                    for direct in [trial % 2 == 0, trial % 2 != 0] {
                        let whole = monitor::WriteRange::new(Arc::clone(&storage), 0, 512).unwrap();
                        monitor
                            .with_writer(&whole, monitor::Invalidation::BeforeAttempt, || {
                                // SAFETY: all prior workers were joined; the whole writer
                                // gate owns this private reset, with no live RAM reference.
                                unsafe {
                                    storage.0.get().write([0; 64]);
                                }
                                Ok::<_, ()>(())
                            })
                            .unwrap();
                        let ready = Arc::new(Barrier::new(3));
                        let start_workers = Arc::new(Barrier::new(3));
                        let joins: Vec<_> = (0..2)
                            .map(|worker| {
                                let storage = Arc::clone(&storage);
                                let monitor = Arc::clone(&monitor);
                                let ready = Arc::clone(&ready);
                                let start_workers = Arc::clone(&start_workers);
                                std::thread::spawn(move || {
                                    let mut dependency = 1u128;
                                    ready.wait();
                                    start_workers.wait();
                                    for index in 0..ITERATIONS {
                                        let slot = if case == "contended" {
                                            0
                                        } else if case == "dependent" {
                                            worker * 32
                                        } else {
                                            worker * 32 + (index % 4) * 8
                                        };
                                        let range = monitor::WriteRange::new(
                                            Arc::clone(&storage),
                                            (slot * 8) as u64,
                                            8,
                                        )
                                        .unwrap();
                                        let operand = if case == "dependent" {
                                            dependency.wrapping_add(1)
                                        } else {
                                            1
                                        };
                                        // SAFETY: stable raw allocation, exact width, no
                                        // RAM references; this range gate owns all writers.
                                        let pointer = unsafe {
                                            storage.0.get().cast::<u64>().add(slot).cast::<u8>()
                                        };
                                        dependency = monitor
                                            .with_writer(
                                                &range,
                                                monitor::Invalidation::BeforeAttempt,
                                                || {
                                                    Ok::<_, ()>(unsafe {
                                                        if direct {
                                                            direct_candidate(
                                                                pointer, operation, operand,
                                                                dependency, target,
                                                            )
                                                        } else {
                                                            generic_candidate(
                                                                pointer, operation, operand,
                                                                dependency, target,
                                                            )
                                                        }
                                                    })
                                                },
                                            )
                                            .unwrap();
                                        std::hint::black_box(dependency);
                                    }
                                })
                            })
                            .collect();
                        ready.wait();
                        let start = Instant::now();
                        start_workers.wait();
                        for join in joins {
                            join.join().unwrap();
                        }
                        println!(
                            "RECIPE operation={operation:?} case={case} trial={trial} direct={direct} operations={} wall_ns={}",
                            2 * ITERATIONS,
                            start.elapsed().as_nanos()
                        );
                    }
                }
            }
        }
    }
}

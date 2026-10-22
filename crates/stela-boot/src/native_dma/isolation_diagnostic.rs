//! Two exact QEMU EDU requesters; no native-machine ownership/coherency grant.
use super::{
    diagnostic::{Device, Prepared},
    requester::RequesterClaim,
    vtd::{MmioRegisters, RequesterDomain, Unit},
};
use alloc::{format, string::String, sync::Arc, vec::Vec};
use core::ptr::NonNull;
use stela_drivers::bus::dma::{
    mapping::{Direction, DmaMapping},
    memory::{CacheAttribute, CpuMapping, PageSource, PinnedPages},
};

const BYTES: usize = 4096;
const BUFFER: u64 = 0x40000;
const TIMEOUT_US: u64 = 2_000_000;

struct Buffer {
    pages: PinnedPages,
    cpu: CpuMapping,
    dma: DmaMapping,
}
impl Buffer {
    fn new(
        domain: Arc<RequesterDomain<MmioRegisters>>,
        direction: Direction,
    ) -> Result<Self, String> {
        let pages = crate::native_memory::SOURCE
            .allocate(BYTES, BYTES, CacheAttribute::WriteBack)
            .map_err(|e| format!("isolation pages: {e:?}"))?;
        let cpu = pages
            .cpu_mapping(CacheAttribute::WriteBack)
            .map_err(|e| format!("isolation CPU map: {e:?}"))?;
        let dma = DmaMapping::map(domain, pages.clone(), direction, 0x0fff_ffff)
            .map_err(|e| format!("isolation DMA map: {e:?}"))?;
        Ok(Self { pages, cpu, dma })
    }
    fn fill(&self, seed: u8) -> Result<(), String> {
        let pointer = self
            .cpu
            .address(0, BYTES)
            .map_err(|e| format!("CPU bounds: {e:?}"))?;
        for i in 0..BYTES {
            // SAFETY: stopped/completed fixture DMA; exclusive retained CPU pin.
            unsafe {
                pointer
                    .as_ptr()
                    .add(i)
                    .write_volatile(seed.wrapping_add(i as u8))
            };
        }
        Ok(())
    }
    fn check(&self, seed: u8) -> Result<(), String> {
        let pointer = self
            .cpu
            .address(0, BYTES)
            .map_err(|e| format!("CPU bounds: {e:?}"))?;
        for i in 0..BYTES {
            // SAFETY: caller observed actual RUN-clear, or a matched rejected
            // transaction; retained mapping prevents target reuse throughout.
            if unsafe { pointer.as_ptr().add(i).read_volatile() } != seed.wrapping_add(i as u8) {
                return Err(format!("isolation retained RAM mismatch at {i}"));
            }
        }
        Ok(())
    }
    fn address(&self) -> Result<u64, String> {
        self.dma
            .address()
            .map_err(|e| format!("isolation IOVA: {e:?}"))
    }
    fn publish(&self) -> Result<(), String> {
        self.dma
            .sync_for_device(0..BYTES)
            .map_err(|e| format!("device visibility: {e:?}"))
    }
    fn complete(&self) -> Result<(), String> {
        // SAFETY: exact EDU RUN-clear; no IRQ/work/submission can restart DMA.
        unsafe { self.dma.sync_for_cpu(0..BYTES) }.map_err(|e| format!("CPU visibility: {e:?}"))
    }
    fn unmap(&mut self) -> Result<(), String> {
        // SAFETY: exact requester idle and BM disabled, no IRQ/work producer.
        // Actual context IOTLB acknowledgement precedes return/reuse.
        unsafe { self.dma.unmap() }.map_err(|e| format!("isolation unmap: {e:?}"))
    }
}
fn roundtrip(device: &Device, send: &Buffer, receive: &Buffer, seed: u8) -> Result<(), String> {
    send.publish()?;
    receive.publish()?;
    device.transfer(send.address()?, BUFFER, false)?;
    device.transfer(BUFFER, receive.address()?, true)?;
    receive.complete()?;
    receive.check(seed)
}

/// Called only after Prepared's actual common post-EBS quiescence sequence.
/// Any error is fatal to host-check; uncertain mappings/contexts quarantine.
pub(super) fn run(mut prepared: Prepared) -> Result<String, String> {
    let (second_index, second_bar) = prepared
        .second
        .take()
        .ok_or_else(|| String::from("second isolation requester missing"))?;
    let a = Device {
        edu_registers: prepared.edu_registers.clone(),
        clock: prepared.clock,
    };
    let b = Device {
        edu_registers: second_bar,
        clock: prepared.clock,
    };
    let timeout = prepared
        .clock
        .ticks_per_microsecond
        .checked_mul(TIMEOUT_US)
        .ok_or_else(|| String::from("isolation timeout overflow"))?;
    // SAFETY: complete actual DMAR ownership, UC fixture root mapping retained;
    // both EDUs idle, virtio reset acknowledged and legacy channels masked.
    let registers = unsafe {
        MmioRegisters::new(
            NonNull::new(prepared.hardware.base as *mut u8)
                .ok_or_else(|| String::from("zero isolation unit"))?,
            prepared.hardware.bytes,
            crate::apic::rdtsc,
            timeout,
        )
    }
    .map_err(|e| format!("isolation registers: {e:?}"))?;
    let requesters: Vec<u16> = prepared
        .functions
        .iter()
        .map(|f| u16::from(f.address.device) * 8 + u16::from(f.address.function))
        .collect();
    // Remove descending indices so both genuine unique configuration owners
    // survive inventory changes. Neither a RID nor an address creates a claim.
    let mut indices = [prepared.edu, second_index];
    indices.sort_unstable();
    let second_function = prepared.functions.remove(indices[1]);
    let first_function = prepared.functions.remove(indices[0]);
    let mut claims = Vec::new();
    for function in [first_function, second_function] {
        // SAFETY: granted exact coherent QEMU endpoint, stopped/drained above;
        // permanent host-check root retained; ATS/PRI/PASID/NoSnoop off.
        claims.push(
            unsafe { RequesterClaim::from_stopped_pci(function) }
                .map_err(|e| format!("isolation requester claim: {e:?}"))?,
        );
    }
    claims.sort_unstable_by_key(RequesterClaim::requester);
    // SAFETY: actual complete exclusive fixture unit and all masters stopped.
    let unit = unsafe {
        Unit::take_over(
            registers,
            &crate::native_memory::SOURCE,
            &requesters,
            prepared.hardware.physical_bits,
        )
    }
    .map_err(|e| format!("isolation takeover: {e:?}"))?;
    let mut domains = Vec::new();
    for claim in claims {
        // SAFETY: actual retained stopped claim, same independently qualified
        // endpoint coherency grant, no alternate config/reset/IRQ owner.
        domains.push(
            unsafe { unit.attach_requester(claim) }
                .map_err(|e| format!("isolation context: {e:?}"))?,
        );
    }
    let da = &domains[0];
    let db = &domains[1];
    if da.requester() != 0x10 || db.requester() != 0x18 || da.domain_id() == db.domain_id() {
        return Err(String::from(
            "isolation context identities differ from fixture",
        ));
    }
    if !unit
        .pending_faults()
        .map_err(|e| format!("initial faults: {e:?}"))?
        .is_empty()
    {
        return Err(String::from("prior isolation faults"));
    }
    let mut send_a = Buffer::new(da.clone(), Direction::ToDevice)?;
    let mut receive_a = Buffer::new(da.clone(), Direction::FromDevice)?;
    let mut protected_a = Buffer::new(da.clone(), Direction::FromDevice)?;
    let mut send_b = Buffer::new(db.clone(), Direction::ToDevice)?;
    let mut receive_b = Buffer::new(db.clone(), Direction::FromDevice)?;
    send_a.fill(0x31)?;
    send_b.fill(0x97)?;
    receive_a.fill(0)?;
    receive_b.fill(0)?;
    protected_a.fill(0xd3)?;
    let mut physical: Vec<u64> = [&send_a, &receive_a, &protected_a, &send_b, &receive_b]
        .iter()
        .map(|b| b.pages.physical_pages()[0])
        .collect();
    physical.sort_unstable();
    if send_a.address()? != send_b.address()?
        || receive_a.address()? != receive_b.address()?
        || protected_a.address()? != 0x3000
        || physical.windows(2).any(|p| p[0] == p[1])
        || [&send_a, &receive_a, &protected_a, &send_b, &receive_b]
            .iter()
            .any(|b| {
                b.address()
                    .is_ok_and(|iova| iova == b.pages.physical_pages()[0])
            })
    {
        return Err(String::from(
            "fixture did not establish same-IOVA disjoint nonidentity RAM",
        ));
    }
    protected_a.publish()?;
    // SAFETY: all ordinary DMA targets mapped in this exact context. The
    // controlled wrong-domain probe also retains the possible target backing.
    unsafe { da.set_bus_master(true) }.map_err(|e| format!("A BM: {e:?}"))?;
    unsafe { db.set_bus_master(true) }.map_err(|e| format!("B BM: {e:?}"))?;
    roundtrip(&a, &send_a, &receive_a, 0x31)?;
    roundtrip(&b, &send_b, &receive_b, 0x97)?;
    if !unit
        .pending_faults()
        .map_err(|e| format!("roundtrip faults: {e:?}"))?
        .is_empty()
    {
        return Err(String::from("unexpected two-domain roundtrip fault"));
    }
    let protected_iova = protected_a.address()?;
    b.transfer(BUFFER, protected_iova, true)?;
    let faults = unit
        .pending_faults()
        .map_err(|e| format!("wrong-domain faults: {e:?}"))?;
    let fault = faults
        .iter()
        .find(|f| {
            f.requester == db.requester() && f.address == protected_iova && !f.read && f.reason != 0
        })
        .ok_or_else(|| format!("missing matched wrong-domain fault: {faults:?}"))?;
    protected_a.check(0xd3)?;
    unit.acknowledge_fault(fault.index)
        .map_err(|e| format!("wrong-domain fault ACK: {e:?}"))?;
    // The identical IOVA really exists in A: after B's rejected transaction,
    // A writes its own retained page, then actual completion permits CPU read.
    a.transfer(BUFFER, protected_a.address()?, true)?;
    protected_a.complete()?;
    protected_a.check(0x31)?;
    unsafe { da.set_bus_master(false) }.map_err(|e| format!("A stop BM: {e:?}"))?;
    send_a.unmap()?;
    receive_a.unmap()?;
    protected_a.unmap()?;
    // SAFETY: A idle, no mappings or callbacks; detach awaits real context and
    // IOTLB invalidation ACK while B's separate context remains running.
    let owner_a = unsafe { da.detach() }.map_err(|e| format!("A detach: {e:?}"))?;
    roundtrip(&b, &send_b, &receive_b, 0x97)?;
    if !unit
        .pending_faults()
        .map_err(|e| format!("post-detach faults: {e:?}"))?
        .is_empty()
    {
        return Err(String::from("B affected by A context removal"));
    }
    unsafe { db.set_bus_master(false) }.map_err(|e| format!("B stop BM: {e:?}"))?;
    send_b.unmap()?;
    receive_b.unmap()?;
    // SAFETY: B idle, mapping/work/IRQ-free; actual context/IOTLB ACK required.
    let owner_b = unsafe { db.detach() }.map_err(|e| format!("B detach: {e:?}"))?;
    let did_a = da.domain_id();
    let did_b = db.domain_id();
    drop(domains);
    // SAFETY: all requesters stopped, all contexts detached with hardware ACK.
    unsafe { unit.shut_down() }.map_err(|e| format!("isolation TE-off ACK: {e:?}"))?;
    drop((owner_a, owner_b, prepared.functions));
    Ok(format!(
        "QEMU two-EDU rid_a=0x0010 did_a={did_a} rid_b=0x0018 did_b={did_b} same_iova=disjoint-ram send_pa_a={:#x} receive_pa_a={:#x} protected_pa_a={:#x} send_pa_b={:#x} receive_pa_b={:#x} roundtrip_a=verified roundtrip_b=verified wrong_domain_rid={:#06x} wrong_domain_address={:#x} wrong_domain_reason={:#x} retained_ram=unchanged owner_access=verified other_context_after_detach=verified teardown=context+IOTLB+TE-off-ack",
        send_a.pages.physical_pages()[0],
        receive_a.pages.physical_pages()[0],
        protected_a.pages.physical_pages()[0],
        send_b.pages.physical_pages()[0],
        receive_b.pages.physical_pages()[0],
        fault.requester,
        fault.address,
        fault.reason
    ))
}

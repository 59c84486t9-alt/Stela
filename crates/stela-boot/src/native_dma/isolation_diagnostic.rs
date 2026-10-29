//! Two exact QEMU EDU requesters; no native-machine ownership/coherency grant.
use super::{
    diagnostic::{Device, Prepared},
    requester::RequesterClaim,
    vtd::{MmioRegisters, RequesterDomain, Unit},
};
use crate::Result;
use alloc::{format, string::String, sync::Arc, vec::Vec};
use core::ptr::NonNull;
use stela_contracts::refuse;
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
    fn new(domain: Arc<RequesterDomain<MmioRegisters>>, direction: Direction) -> Result<Self> {
        let pages = crate::native_memory::SOURCE
            .allocate(BYTES, BYTES, CacheAttribute::WriteBack)
            .map_err(|e| refuse!("isolation pages: {e}", ?e))?;
        let cpu = pages
            .cpu_mapping(CacheAttribute::WriteBack)
            .map_err(|e| refuse!("isolation CPU map: {e}", ?e))?;
        let dma = DmaMapping::map(domain, pages.clone(), direction, 0x0fff_ffff)
            .map_err(|e| refuse!("isolation DMA map: {e}", ?e))?;
        Ok(Self { pages, cpu, dma })
    }
    fn fill(&self, seed: u8) -> Result<()> {
        let pointer = self
            .cpu
            .address(0, BYTES)
            .map_err(|e| refuse!("CPU bounds: {e}", ?e))?;
        for i in 0..BYTES {
            // SAFETY: stopped/completed fixture DMA; exclusive kept CPU pin.
            unsafe {
                pointer
                    .as_ptr()
                    .add(i)
                    .write_volatile(seed.wrapping_add(i as u8))
            };
        }
        Ok(())
    }
    fn check(&self, seed: u8) -> Result<()> {
        let pointer = self
            .cpu
            .address(0, BYTES)
            .map_err(|e| refuse!("CPU bounds: {e}", ?e))?;
        for i in 0..BYTES {
            // SAFETY: caller observed RUN-clear, or a matched rejected
            // transaction; mapping prevents target reuse throughout.
            if unsafe { pointer.as_ptr().add(i).read_volatile() } != seed.wrapping_add(i as u8) {
                return Err(refuse!("isolation retained RAM mismatch at {i}", i));
            }
        }
        Ok(())
    }
    fn address(&self) -> Result<u64> {
        self.dma
            .address()
            .map_err(|e| refuse!("isolation IOVA: {e}", ?e))
    }
    fn publish(&self) -> Result<()> {
        self.dma
            .sync_for_device(0..BYTES)
            .map_err(|e| refuse!("device visibility: {e}", ?e))
    }
    fn complete(&self) -> Result<()> {
        // SAFETY: exact EDU RUN-clear; no IRQ/work/submission can restart DMA.
        unsafe { self.dma.sync_for_cpu(0..BYTES) }.map_err(|e| refuse!("CPU visibility: {e}", ?e))
    }
    fn unmap(&mut self) -> Result<()> {
        // SAFETY: requester idle and BM disabled, no IRQ/work producer.
        // Context IOTLB acknowledgement precedes return/reuse.
        unsafe { self.dma.unmap() }.map_err(|e| refuse!("isolation unmap: {e}", ?e))
    }
}
fn roundtrip(device: &Device, send: &Buffer, receive: &Buffer, seed: u8) -> Result<()> {
    send.publish()?;
    receive.publish()?;
    device.transfer(send.address()?, BUFFER, false)?;
    device.transfer(BUFFER, receive.address()?, true)?;
    receive.complete()?;
    receive.check(seed)
}

/// Called only after Prepared's common post-EBS quiescence sequence.
/// Any error is fatal to host-check; uncertain mappings/contexts quarantine.
pub(super) fn run(
    mut prepared: Prepared<
        stela_drivers::bus::pci::Function<stela_drivers::bus::pci::owned::OwnedConfig>,
    >,
) -> Result<String> {
    let (second_index, second_bar) = prepared
        .second
        .take()
        .ok_or_else(|| refuse!("second isolation requester missing"))?;
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
        .ok_or_else(|| refuse!("isolation timeout overflow"))?;
    // SAFETY: complete DMAR ownership, UC fixture root mapping kept;
    // both EDUs idle, virtio reset acknowledged and legacy channels masked.
    let registers = unsafe {
        MmioRegisters::new(
            NonNull::new(prepared.hardware.base as *mut u8)
                .ok_or_else(|| refuse!("zero isolation unit"))?,
            prepared.hardware.bytes,
            crate::apic::rdtsc,
            timeout,
        )
    }
    .map_err(|e| refuse!("isolation registers: {e}", ?e))?;
    let requesters: Vec<u16> = prepared
        .functions
        .iter()
        .map(|f| u16::from(f.address.device) * 8 + u16::from(f.address.function))
        .collect();
    // Remove descending indices so both unique configuration owners
    // survive inventory changes. Neither a RID nor an address creates a claim.
    let mut indices = [prepared.edu, second_index];
    indices.sort_unstable();
    let second_function = prepared.functions.remove(indices[1]);
    let first_function = prepared.functions.remove(indices[0]);
    let mut claims = Vec::new();
    for function in [first_function, second_function] {
        // SAFETY: granted exact coherent QEMU endpoint, stopped/drained above;
        // permanent host-check root kept; ATS/PRI/PASID/NoSnoop off.
        claims.push(
            unsafe { RequesterClaim::from_stopped_pci(function) }
                .map_err(|e| refuse!("isolation requester claim: {e}", ?e))?,
        );
    }
    claims.sort_unstable_by_key(RequesterClaim::requester);
    // SAFETY: complete exclusive fixture unit and all masters stopped.
    let unit = unsafe {
        Unit::take_over(
            registers,
            &crate::native_memory::SOURCE,
            &requesters,
            prepared.hardware.physical_bits,
            &[],
        )
    }
    .map_err(|e| refuse!("isolation takeover: {e}", ?e))?;
    let mut domains = Vec::new();
    for claim in claims {
        // SAFETY: stopped claim, same checked
        // endpoint coherency grant, no alternate config/reset/IRQ owner.
        domains.push(
            unsafe { unit.attach_requester(claim) }
                .map_err(|e| refuse!("isolation context: {e}", ?e))?,
        );
    }
    let da = &domains[0];
    let db = &domains[1];
    if da.requester() != 0x10 || db.requester() != 0x18 || da.domain_id() == db.domain_id() {
        return Err(refuse!("isolation context identities differ from fixture"));
    }
    if !unit
        .pending_faults()
        .map_err(|e| refuse!("initial faults: {e}", ?e))?
        .is_empty()
    {
        return Err(refuse!("prior isolation faults"));
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
        return Err(refuse!(
            "fixture did not establish same-IOVA disjoint nonidentity RAM"
        ));
    }
    protected_a.publish()?;
    // SAFETY: all ordinary DMA targets mapped in this exact context. The
    // controlled wrong-domain probe also keeps the possible target backing.
    unsafe { da.set_bus_master(true) }.map_err(|e| refuse!("A BM: {e}", ?e))?;
    // SAFETY: every ordinary DMA target of B's context is mapped in it as well.
    unsafe { db.set_bus_master(true) }.map_err(|e| refuse!("B BM: {e}", ?e))?;
    roundtrip(&a, &send_a, &receive_a, 0x31)?;
    roundtrip(&b, &send_b, &receive_b, 0x97)?;
    if !unit
        .pending_faults()
        .map_err(|e| refuse!("roundtrip faults: {e}", ?e))?
        .is_empty()
    {
        return Err(refuse!("unexpected two-domain roundtrip fault"));
    }
    let protected_iova = protected_a.address()?;
    b.transfer(BUFFER, protected_iova, true)?;
    let faults = unit
        .pending_faults()
        .map_err(|e| refuse!("wrong-domain faults: {e}", ?e))?;
    let fault = faults
        .iter()
        .find(|f| {
            f.requester == db.requester() && f.address == protected_iova && !f.read && f.reason != 0
        })
        .ok_or_else(|| refuse!("missing matched wrong-domain fault: {faults}", ?faults))?;
    protected_a.check(0xd3)?;
    unit.acknowledge_fault(fault.index)
        .map_err(|e| refuse!("wrong-domain fault ACK: {e}", ?e))?;
    // The identical IOVA really exists in A: after B's rejected transaction,
    // A writes its own page, then completion permits CPU read.
    a.transfer(BUFFER, protected_a.address()?, true)?;
    protected_a.complete()?;
    protected_a.check(0x31)?;
    // SAFETY: stopping bus mastering only revokes the requester's DMA.
    unsafe { da.set_bus_master(false) }.map_err(|e| refuse!("A stop BM: {e}", ?e))?;
    send_a.unmap()?;
    receive_a.unmap()?;
    protected_a.unmap()?;
    // SAFETY: A idle, no mappings or callbacks; detach awaits real context and
    // IOTLB invalidation ACK while B's separate context remains running.
    let owner_a = unsafe { da.detach() }.map_err(|e| refuse!("A detach: {e}", ?e))?;
    roundtrip(&b, &send_b, &receive_b, 0x97)?;
    if !unit
        .pending_faults()
        .map_err(|e| refuse!("post-detach faults: {e}", ?e))?
        .is_empty()
    {
        return Err(refuse!("B affected by A context removal"));
    }
    // SAFETY: stopping bus mastering only revokes the requester's DMA.
    unsafe { db.set_bus_master(false) }.map_err(|e| refuse!("B stop BM: {e}", ?e))?;
    send_b.unmap()?;
    receive_b.unmap()?;
    // SAFETY: B idle, mapping/work/IRQ-free; context/IOTLB ACK required.
    let owner_b = unsafe { db.detach() }.map_err(|e| refuse!("B detach: {e}", ?e))?;
    let did_a = da.domain_id();
    let did_b = db.domain_id();
    drop(domains);
    // SAFETY: all requesters stopped, all contexts detached with hardware ACK.
    unsafe { unit.shut_down() }.map_err(|e| refuse!("isolation TE-off ACK: {e}", ?e))?;
    for owner in [owner_a, owner_b] {
        let function = owner
            .into_function()
            .map_err(|error| refuse!("isolation original config owner: {error}", ?error))?;
        super::diagnostic::retire_function(function)?;
    }
    for function in prepared.functions {
        super::diagnostic::retire_function(function)?;
    }
    super::diagnostic::retire_registers(prepared.register_mappings)?;
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

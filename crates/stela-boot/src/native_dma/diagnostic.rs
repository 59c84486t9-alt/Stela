//! Explicit QEMU TCG/EDU acceptance fixture. This is never a physical-machine
//! takeover path. Unknown devices, routes or active translation features fail.
use super::{
    dmar::{self, HardwareUnit},
    vtd::{self, MmioRegisters, Registers, Unit},
};
use alloc::{format, string::String, vec::Vec};
use core::{ops::Range, ptr::NonNull};
use stela_drivers::{
    Clock, Handoff,
    bus::{
        dma::{
            mapping::{Direction, DmaMapping},
            memory::{CacheAttribute, PageSource},
        },
        pci::{Bar, CAPABILITY_VENDOR, ConfigSpace, Function},
    },
};
use stela_runtime::pc::acpi;

const EDU_VENDOR: u16 = 0x1234;
const EDU_DEVICE: u16 = 0x11e8;
const COMMAND: u16 = 4;
const BUS_MASTER: u16 = 4;
const MEMORY: u16 = 2;
const INTX_DISABLE: u16 = 1 << 10;
const DEVICE_BUFFER: u64 = 0x40000;
const DMA_SOURCE: usize = 0x80;
const DMA_DESTINATION: usize = 0x88;
const DMA_COUNT: usize = 0x90;
const DMA_COMMAND: usize = 0x98;
const DMA_RUN: u64 = 1;
const DMA_TO_RAM: u64 = 2;
const BYTES: usize = 4096;
const TIMEOUT_US: u64 = 2_000_000;

pub(crate) struct Prepared {
    pub(super) hardware: HardwareUnit,
    pub(super) functions: Vec<Function>,
    pub(super) edu: usize,
    virtio: usize,
    pub(super) edu_registers: Range<u64>,
    virtio_status: u64,
    pub(super) clock: Clock,
    level: Option<crate::native_irq::level_diagnostic::Prepared>,
    pub(super) second: Option<(usize, Range<u64>)>,
}

fn memory_bar(bar: Option<Bar>) -> Result<Range<u64>, String> {
    let Some(Bar::Memory { address, size, .. }) = bar else {
        return Err(String::from("fixture needs a memory BAR"));
    };
    let end = address
        .checked_add(size)
        .filter(|end| *end > address)
        .ok_or_else(|| String::from("invalid fixture BAR span"))?;
    Ok(address..end)
}

fn translation_features_stopped(function: &mut Function) -> Result<(), String> {
    for (offset, id) in function.capabilities() {
        if id == 0x10 && function.config().read16(u16::from(offset) + 8) & (1 << 11) != 0 {
            return Err(String::from("fixture PCIe NoSnoop is enabled"));
        }
    }
    let mut visited = Vec::new();
    let mut offset = 0x100u16;
    loop {
        if !(0x100..=0xffc).contains(&offset)
            || !offset.is_multiple_of(4)
            || visited.contains(&offset)
        {
            return Err(String::from("malformed fixture extended capabilities"));
        }
        visited.push(offset);
        let header = function.config().read32(offset);
        if matches!(header, 0 | u32::MAX) {
            return Ok(());
        }
        if matches!(header as u16, 0x000f | 0x0013 | 0x001b) && offset > 0xff8 {
            return Err(String::from("truncated fixture translation capability"));
        }
        let active = match header as u16 {
            0x000f => function.config().read16(offset + 6) & (1 << 15) != 0,
            0x0013 => function.config().read16(offset + 4) & 1 != 0,
            0x001b => function.config().read16(offset + 6) & 1 != 0,
            _ => false,
        };
        if active {
            return Err(String::from("fixture ATS/PRI/PASID is enabled"));
        }
        offset = (header >> 20) as u16;
        if offset == 0 {
            return Ok(());
        }
    }
}

impl Prepared {
    /// Before EBS, with firmware callbacks excluded by TPL_HIGH_LEVEL. No
    /// takeover or DMA occurs here; BAR sizing restores decoding immediately.
    pub(crate) fn prepare(handoff: &Handoff, isolation: bool) -> Result<Self, String> {
        let hv = core::arch::x86_64::__cpuid(0x4000_0000);
        let signature = [
            hv.ebx.to_le_bytes(),
            hv.ecx.to_le_bytes(),
            hv.edx.to_le_bytes(),
        ]
        .concat();
        if signature != b"TCGTCGTCGTCG" {
            return Err(String::from("native DMA fixture requires QEMU TCG"));
        }
        if handoff.ecam.len() != 1 || handoff.ecam[0].segment != 0 || handoff.ecam[0].start_bus != 0
        {
            return Err(String::from(
                "fixture needs one flat segment-zero ECAM window",
            ));
        }
        let rsdp = crate::storage::rsdp().ok_or_else(|| String::from("fixture has no RSDP"))?;
        // SAFETY: the firmware's RSDP/tables remain mapped before EBS.
        let table = unsafe { acpi::find(rsdp, b"DMAR") }
            .map_err(|error| format!("fixture DMAR: {error:?}"))?;
        // QEMU's FADT builder emits SMI_CMD and ACPI enable/disable only when
        // SMM is enabled. This is a source-bound fixture check, not a general
        // proof about physical SMM ownership.
        let fadt = unsafe { acpi::find(rsdp, b"FACP") }
            .map_err(|error| format!("fixture FADT: {error:?}"))?;
        if fadt.get(48..54) != Some(&[0; 6]) {
            return Err(String::from("fixture requires QEMU SMM off"));
        }
        // SAFETY: actual firmware ECAM mapping; TPL excludes firmware callbacks.
        let mut functions = unsafe { Function::enumerate(&handoff.ecam[0]) };
        let mut edus = Vec::new();
        let (mut edu, mut virtio, mut host, mut isa) = (None, None, false, false);
        for (index, function) in functions.iter_mut().enumerate() {
            if function.address.bus != 0 {
                return Err(String::from("fixture has a non-flat PCI route"));
            }
            translation_features_stopped(function)?;
            if (function.vendor, function.device) == (EDU_VENDOR, EDU_DEVICE) {
                edus.push(index);
                if edu.is_none() {
                    edu = Some(index);
                }
            } else if function.vendor == 0x1af4 && matches!(function.device, 0x1001 | 0x1042) {
                if virtio.replace(index).is_some() {
                    return Err(String::from("multiple fixture boot virtio devices"));
                }
            } else if function.vendor == 0x8086
                && function.device == 0x29c0
                && function.address.device == 0
                && function.address.function == 0
                && function.class == [6, 0, 0]
                && !host
            {
                host = true;
            } else if function.vendor == 0x8086
                && function.device == 0x2918
                && function.address.device == 31
                && function.address.function == 0
                && function.class == [6, 1, 0]
                && !isa
            {
                isa = true;
            } else {
                return Err(format!(
                    "unknown fixture requester {} {:04x}:{:04x}",
                    function.address, function.vendor, function.device
                ));
            }
        }
        if edus.len() != if isolation { 2 } else { 1 } {
            return Err(String::from("unexpected fixture EDU requester count"));
        }
        if isolation
            && edus.iter().enumerate().any(|(n, &i)| {
                functions[i].address.device != n as u8 + 2 || functions[i].address.function != 0
            })
        {
            return Err(String::from(
                "isolation fixture requires EDU 00:02.0 and 00:03.0",
            ));
        }
        let edu = edu.ok_or_else(|| String::from("fixture EDU requester missing"))?;
        let virtio = virtio.ok_or_else(|| String::from("fixture boot virtio missing"))?;
        if !host || !isa {
            return Err(String::from("fixture needs exact Q35/ICH9 chipset"));
        }
        let requesters: Vec<u16> = functions
            .iter()
            .map(|function| {
                u16::from(function.address.bus) << 8
                    | u16::from(function.address.device) << 3
                    | u16::from(function.address.function)
            })
            .collect();
        let hardware = dmar::single_flat_owner(table, 0, &requesters)
            .map_err(|error| format!("fixture DMAR ownership: {error:?}"))?;
        if hardware.bytes > 65536 {
            return Err(String::from("fixture remapping register span unsupported"));
        }
        let edu_registers = memory_bar(functions[edu].bars()[0])?;
        if edu_registers.end - edu_registers.start != 1 << 20 {
            return Err(String::from("unexpected EDU register span"));
        }
        let bars = functions[virtio].bars();
        let mut virtio_status = None;
        for (offset, id) in functions[virtio].capabilities() {
            if id != CAPABILITY_VENDOR {
                continue;
            }
            let base = u16::from(offset);
            let config = functions[virtio].config();
            if config.read8(base + 3) != 1 {
                continue;
            }
            let capability_bytes = u16::from(config.read8(base + 2));
            if capability_bytes < 16 || base + capability_bytes > 256 {
                return Err(String::from("short virtio common capability"));
            }
            let bar = memory_bar(
                bars.get(usize::from(config.read8(base + 4)))
                    .copied()
                    .flatten(),
            )?;
            let start = bar
                .start
                .checked_add(u64::from(config.read32(base + 8)))
                .ok_or_else(|| String::from("virtio common offset overflow"))?;
            let bytes = u64::from(config.read32(base + 12));
            if bytes < 0x15 || start.checked_add(bytes).is_none_or(|end| end > bar.end) {
                return Err(String::from("virtio common capability outside BAR"));
            }
            if virtio_status.replace(start + 0x14).is_some() {
                return Err(String::from("duplicate virtio common capability"));
            }
        }
        let level = if isolation {
            None
        } else {
            Some(crate::native_irq::level_diagnostic::Prepared::prepare(
                rsdp, fadt,
            )?)
        };
        let second = if isolation {
            let i = edus[1];
            let bar = memory_bar(functions[i].bars()[0])?;
            if bar.end - bar.start != 1 << 20 {
                return Err(String::from("unexpected second EDU register span"));
            }
            Some((i, bar))
        } else {
            None
        };
        Ok(Self {
            level,
            second,
            hardware,
            functions,
            edu,
            virtio,
            edu_registers,
            virtio_status: virtio_status
                .ok_or_else(|| String::from("virtio reset register missing"))?,
            clock: handoff.clock,
        })
    }

    pub(crate) fn mappings(&self) -> Vec<Range<u64>> {
        let mut ranges = alloc::vec![
            self.hardware.base..self.hardware.base + self.hardware.bytes as u64,
            self.edu_registers.clone(),
            self.virtio_status & !4095..(self.virtio_status & !4095) + 4096,
        ];
        if let Some(level) = &self.level {
            ranges.push(level.mapping());
        }
        if let Some((_, bar)) = &self.second {
            ranges.push(bar.clone());
        }
        ranges
    }

    fn device(&self) -> Device {
        Device {
            edu_registers: self.edu_registers.clone(),
            clock: self.clock,
        }
    }

    /// Only after EBS on the prepared UC mappings, with interrupts off. Any
    /// error must stop the host check; normal probing cannot resume into an
    /// uncertain translation state. Unit/lease Drop retains uncertain resources.
    pub(crate) fn run(mut self) -> Result<Report, String> {
        self.quiesce()?;
        if self.second.is_some() {
            return super::isolation_diagnostic::run(self).map(Report::Isolation);
        }
        self.run_single(None)
            .map(|(dma, irq)| Report::Single(dma, irq))
    }

    pub(crate) fn run_irq_work(
        mut self,
        work: crate::native_work_check::Prepared,
    ) -> Result<Report, String> {
        self.quiesce()?;
        if self.second.is_some() {
            return Err(String::from("IRQ work requires the single EDU grant"));
        }
        self.run_single(Some(work))
            .map(|(dma, irq)| Report::IrqWork(format!("{dma}; {irq}")))
    }

    fn quiesce(&mut self) -> Result<(), String> {
        // QEMU v11.1.2 i8257.c: write-all-mask stops each channel, including
        // controller two's cascade. Its single-threaded device callbacks are
        // synchronous; the next run sees all masks before any channel handler.
        // Read-mask is controller offset one (0x09 and 0xd2), not write-all-mask.
        // The exact Q35 host bridge has no DMA engine. This qualification is
        // specific to the granted TCG fixture and never physical quiescence.
        for (write, read) in [(0x0fu16, 0x09u16), (0xde, 0xd2)] {
            let mask: u8;
            // SAFETY: exclusive known QEMU i8257 controllers after EBS; all
            // channels are intentionally disabled for this bounded fixture.
            unsafe {
                core::arch::asm!("out dx, al", in("dx") write, in("al") 15u8, options(nostack, preserves_flags));
                core::arch::asm!("in al, dx", in("dx") read, out("al") mask, options(nostack, preserves_flags));
            }
            if mask & 15 != 15 {
                return Err(String::from("fixture legacy DMA mask did not latch"));
            }
        }
        for (index, function) in self.functions.iter_mut().enumerate() {
            if index != self.edu
                && self.second.as_ref().is_none_or(|(i, _)| index != *i)
                && index != self.virtio
            {
                let config = function.config();
                let command = config.read16(COMMAND);
                config.write16(COMMAND, command & !BUS_MASTER);
                if config.read16(COMMAND) & BUS_MASTER != 0 {
                    return Err(String::from("fixture chipset bus master remained enabled"));
                }
            }
        }
        // Reset the actual firmware boot virtio device and observe status zero
        // before clearing bus mastering. Its reset acknowledgement, not the
        // command bit alone, proves virtio has stopped accessing its queues.
        unsafe { (self.virtio_status as *mut u8).write_volatile(0) };
        if !self.clock.wait(
            TIMEOUT_US,
            || unsafe { (self.virtio_status as *const u8).read_volatile() } == 0,
        ) {
            return Err(String::from("virtio reset did not quiesce DMA"));
        }
        let config = self.functions[self.virtio].config();
        let command = config.read16(COMMAND);
        config.write16(COMMAND, command & !BUS_MASTER);
        if config.read16(COMMAND) & BUS_MASTER != 0 {
            return Err(String::from("virtio bus master remained enabled"));
        }
        let mut devices = alloc::vec![(self.edu, self.edu_registers.clone())];
        if let Some(second) = &self.second {
            devices.push(second.clone());
        }
        for (index, bar) in devices {
            let config = self.functions[index].config();
            let command = config.read16(COMMAND);
            if command == u16::MAX {
                return Err(String::from("EDU command read failed"));
            }
            config.write16(COMMAND, (command | MEMORY | INTX_DISABLE) & !BUS_MASTER);
            let device = Device {
                edu_registers: bar,
                clock: self.clock,
            };
            if device.read32(0) != 0x010000ed
                || device.read32(0x20) & 1 != 0
                || device.read64(DMA_COMMAND) & DMA_RUN != 0
                || device.read32(0x24) != 0
            {
                return Err(String::from("EDU is not the supported idle QEMU fixture"));
            }
            device.write32(0x20, 0);
            device.write32(0x64, u32::MAX);
        }
        Ok(())
    }

    fn run_single(
        mut self,
        work: Option<crate::native_work_check::Prepared>,
    ) -> Result<(String, String), String> {
        let device = self.device();
        let timeout = self
            .clock
            .ticks_per_microsecond
            .checked_mul(TIMEOUT_US)
            .ok_or_else(|| String::from("fixture timeout overflow"))?;
        // SAFETY: strict fixture discovery supplies the actual UC unit window;
        // root mappings retain it, clock advances on this one BSP.
        let registers = unsafe {
            MmioRegisters::new(
                NonNull::new(self.hardware.base as *mut u8)
                    .ok_or_else(|| String::from("zero unit base"))?,
                self.hardware.bytes,
                crate::apic::rdtsc,
                timeout,
            )
        }
        .map_err(|error| format!("VT-d registers: {error:?}"))?;
        let table_walk_coherent = registers.read64(0x10) & 1 != 0;
        let address = self.functions[self.edu].address;
        let requester = u16::from(address.bus) << 8
            | u16::from(address.device) << 3
            | u16::from(address.function);
        // SAFETY: QEMU-only flat topology, exact matched DMAR owner; all
        // other requesters are reset/drained, EDU idle, ATS/NoSnoop off.
        let requesters: Vec<u16> = self
            .functions
            .iter()
            .map(|f| u16::from(f.address.device) * 8 + u16::from(f.address.function))
            .collect();
        let function = self.functions.swap_remove(self.edu);
        // SAFETY: same actual exclusive, idle fixture function and retained root.
        let claim = unsafe { super::requester::RequesterClaim::from_stopped_pci(function) }
            .map_err(|error| format!("requester claim: {error:?}"))?;
        let unit = unsafe {
            Unit::take_over(
                registers,
                &crate::native_memory::SOURCE,
                &requesters,
                self.hardware.physical_bits,
            )
        }
        .map_err(|error| format!("VT-d takeover: {error:?}; no normal probing permitted"))?;
        // SAFETY: same actual retained stopped requester epoch and coherent grant.
        let domain = unsafe { unit.attach_requester(claim) }
            .map_err(|error| format!("requester domain: {error:?}"))?;
        if !unit
            .pending_faults()
            .map_err(|error| format!("VT-d initial faults: {error:?}"))?
            .is_empty()
        {
            return Err(String::from("VT-d had prior faults"));
        }
        let send = crate::native_memory::SOURCE
            .allocate(BYTES, BYTES, CacheAttribute::WriteBack)
            .map_err(|error| format!("native DMA send pages: {error:?}"))?;
        let receive = crate::native_memory::SOURCE
            .allocate(BYTES, BYTES, CacheAttribute::WriteBack)
            .map_err(|error| format!("native DMA receive pages: {error:?}"))?;
        let send_cpu = send
            .cpu_mapping(CacheAttribute::WriteBack)
            .map_err(|error| format!("send CPU map: {error:?}"))?;
        let receive_cpu = receive
            .cpu_mapping(CacheAttribute::WriteBack)
            .map_err(|error| format!("receive CPU map: {error:?}"))?;
        let send_pointer = send_cpu
            .address(0, BYTES)
            .map_err(|error| format!("send bounds: {error:?}"))?
            .as_ptr();
        let receive_pointer = receive_cpu
            .address(0, BYTES)
            .map_err(|error| format!("receive bounds: {error:?}"))?
            .as_ptr();
        for index in 0..BYTES {
            unsafe {
                send_pointer
                    .add(index)
                    .write_volatile((index.wrapping_mul(37) + 11) as u8);
                receive_pointer.add(index).write_volatile(0xa7)
            };
        }
        let mut send_dma = DmaMapping::map(
            domain.clone(),
            send.clone(),
            Direction::ToDevice,
            0x0fff_ffff,
        )
        .map_err(|error| format!("send IOVA: {error:?}"))?;
        let mut receive_dma = DmaMapping::map(
            domain.clone(),
            receive.clone(),
            Direction::FromDevice,
            0x0fff_ffff,
        )
        .map_err(|error| format!("receive IOVA: {error:?}"))?;
        let send_iova = send_dma
            .address()
            .map_err(|error| format!("send IOVA unavailable: {error:?}"))?;
        let receive_iova = receive_dma
            .address()
            .map_err(|error| format!("receive IOVA unavailable: {error:?}"))?;
        if send_iova == send.physical_pages()[0] || receive_iova == receive.physical_pages()[0] {
            return Err(String::from("fixture did not establish nonidentity IOVAs"));
        }
        send_dma
            .sync_for_device(0..BYTES)
            .map_err(|error| format!("send visibility: {error:?}"))?;
        receive_dma
            .sync_for_device(0..BYTES)
            .map_err(|error| format!("receive visibility: {error:?}"))?;
        unsafe { domain.set_bus_master(true) }.map_err(|e| format!("EDU BM enable: {e:?}"))?;
        device.transfer(send_iova, DEVICE_BUFFER, false)?;
        device.transfer(DEVICE_BUFFER, receive_iova, true)?;
        // SAFETY: actual EDU RUN-clear completion; exclusive fixture has no
        // queued submission, IRQ callback or worker that could reuse the BO.
        unsafe { receive_dma.sync_for_cpu(0..BYTES) }
            .map_err(|error| format!("CPU DMA visibility: {error:?}"))?;
        for index in 0..BYTES {
            if unsafe { receive_pointer.add(index).read_volatile() }
                != (index.wrapping_mul(37) + 11) as u8
            {
                return Err(format!("DMA roundtrip mismatch at {index}"));
            }
        }
        if !unit
            .pending_faults()
            .map_err(|error| format!("VT-d roundtrip fault status: {error:?}"))?
            .is_empty()
        {
            return Err(String::from("unexpected VT-d roundtrip fault"));
        }
        unsafe { domain.set_bus_master(false) }.map_err(|e| format!("EDU BM disable: {e:?}"))?;
        // SAFETY: both actual transfers completed and submission is stopped;
        // no ISR/worker exists. Unmap awaits actual IOTLB acknowledgement.
        unsafe { send_dma.unmap() }.map_err(|error| format!("send unmap: {error:?}"))?;
        unsafe { receive_dma.unmap() }.map_err(|error| format!("receive unmap: {error:?}"))?;
        for index in 0..BYTES {
            unsafe { receive_pointer.add(index).write_volatile(0xd3) };
        }
        vtd::publish();
        // Controlled stale-IOVA transaction before any IOVA reuse. The CPU
        // mapping still pins the target RAM; a stale hardware translation
        // would corrupt the sentinel and fail the test.
        unsafe { domain.set_bus_master(true) }.map_err(|e| format!("EDU BM enable: {e:?}"))?;
        device.transfer(DEVICE_BUFFER, receive_iova, true)?;
        unsafe { domain.set_bus_master(false) }.map_err(|e| format!("EDU BM disable: {e:?}"))?;
        let faults = unit
            .pending_faults()
            .map_err(|error| format!("VT-d stale IOVA fault status: {error:?}"))?;
        let fault = faults
            .iter()
            .find(|fault| {
                fault.requester == requester
                    && fault.address == (receive_iova & !4095)
                    && !fault.read
                    && fault.reason != 0
            })
            .ok_or_else(|| format!("missing matching VT-d stale IOVA fault: {faults:?}"))?;
        for index in 0..BYTES {
            if unsafe { receive_pointer.add(index).read_volatile() } != 0xd3 {
                return Err(format!("stale IOVA modified retained CPU RAM at {index}"));
            }
        }
        unit.acknowledge_fault(fault.index)
            .map_err(|error| format!("fault acknowledgement: {error:?}"))?;
        // SAFETY: EDU idle, bus mastering stopped, both mappings removed with
        // IOTLB acknowledgements, no other DMA requester or IRQ work can start.
        let claim = unsafe { domain.detach() }.map_err(|e| format!("requester detach: {e:?}"))?;
        drop(domain);
        let function = claim
            .into_function()
            .map_err(|e| format!("retired PCI owner: {e:?}"))?;
        unsafe { unit.shut_down() }
            .map_err(|error| format!("VT-d TE-off acknowledgement failed: {error:?}"))?;
        let dma = format!(
            "QEMU EDU rid={requester:#06x} bytes={BYTES} table_walk_coherent={table_walk_coherent} send_iova={send_iova:#x} send_pa={:#x} receive_iova={receive_iova:#x} receive_pa={:#x} roundtrip=verified stale_fault_reason={:#x} retained_ram=unchanged teardown=IOTLB+TE-off-ack",
            send.physical_pages()[0],
            receive.physical_pages()[0],
            fault.reason
        );
        if let Some(work) = work {
            let irq = crate::native_irq::work_diagnostic::run(
                function,
                self.edu_registers.start,
                self.clock,
                work,
            )?;
            return Ok((dma, irq));
        }
        let (irq, function) =
            crate::native_irq::diagnostic::run(function, self.edu_registers.start, self.clock)?;
        // Other fixture owners can release now; the original EDU Function
        // passes directly from DMA through MSI retirement into the INTx phase.
        drop(self.functions);
        let level = self
            .level
            .ok_or_else(|| String::from("single fixture missing level preparation"))?
            .run(function, self.edu_registers.start, self.clock)?;
        Ok((dma, format!("{irq}; {level}")))
    }
}

pub(crate) enum Report {
    Single(String, String),
    Isolation(String),
    IrqWork(String),
}

pub(super) struct Device {
    pub(super) edu_registers: Range<u64>,
    pub(super) clock: Clock,
}
impl Device {
    pub(super) fn read32(&self, offset: usize) -> u32 {
        assert!(offset + 4 <= (self.edu_registers.end - self.edu_registers.start) as usize);
        // SAFETY: the fixture's real EDU BAR is retained and mapped UC.
        unsafe { ((self.edu_registers.start + offset as u64) as *const u32).read_volatile() }
    }
    pub(super) fn write32(&self, offset: usize, value: u32) {
        assert!(offset + 4 <= (self.edu_registers.end - self.edu_registers.start) as usize);
        // SAFETY: actual bounded, owned UC EDU register.
        unsafe { ((self.edu_registers.start + offset as u64) as *mut u32).write_volatile(value) };
    }
    pub(super) fn read64(&self, offset: usize) -> u64 {
        assert!(
            offset >= 0x80
                && offset + 8 <= (self.edu_registers.end - self.edu_registers.start) as usize
        );
        // SAFETY: EDU permits 64-bit accesses at these DMA register offsets.
        unsafe { ((self.edu_registers.start + offset as u64) as *const u64).read_volatile() }
    }
    pub(super) fn write64(&self, offset: usize, value: u64) {
        assert!(
            offset >= 0x80
                && offset + 8 <= (self.edu_registers.end - self.edu_registers.start) as usize
        );
        // SAFETY: as for read64, with exclusive fixture ownership.
        unsafe { ((self.edu_registers.start + offset as u64) as *mut u64).write_volatile(value) };
    }
    pub(super) fn transfer(
        &self,
        source: u64,
        destination: u64,
        to_ram: bool,
    ) -> Result<(), String> {
        if self.read64(DMA_COMMAND) & DMA_RUN != 0 {
            return Err(String::from("EDU DMA was already running"));
        }
        self.write64(DMA_SOURCE, source);
        self.write64(DMA_DESTINATION, destination);
        self.write64(DMA_COUNT, BYTES as u64);
        vtd::publish();
        self.write64(DMA_COMMAND, DMA_RUN | if to_ram { DMA_TO_RAM } else { 0 });
        if !self
            .clock
            .wait(TIMEOUT_US, || self.read64(DMA_COMMAND) & DMA_RUN == 0)
        {
            return Err(String::from(
                "EDU DMA completion timeout; domain quarantined",
            ));
        }
        Ok(())
    }
}

//! Actual QEMU-only shared level INTx proof after acknowledged MSI retirement.
//! The route is bound to the complete real DSDT evaluated independently with
//! pinned ACPICA (_PIC(1), PCI0._PRT and GSIG._CRS). This fixture grant never
//! supplies a production AML/PIRQ resolver or SCI deferred-work provider.
use super::{
    ioapic::{self, Devices},
    madt::{self, Routing},
};
use alloc::{boxed::Box, format, string::String, sync::Arc};
use core::{
    arch::asm,
    ops::Range,
    sync::atomic::{AtomicU64, Ordering},
};
use sha2::{Digest, Sha256};
use stela_drivers::{
    Clock,
    bus::{
        irq::{
            Disposition, Handler, IrqError, LineRoute, Platform, Polarity, SharedHandlers, Trigger,
        },
        pci::{ConfigSpace, Function},
    },
};
use stela_runtime::pc::acpi;

// Separately evaluated 8098-byte DSDTs from the Q35/TCG single-BSP fixture,
// using -cpu max and max,vendor=GenuineIntel respectively. Keep the original
// capture binding; docs/design/host-drivers.md records the new input's evidence.
// ACPICA returns unique _PRT entry [0x2ffff,0,Reference(\_SB_.GSIG),0]
// and GSIG._CRS [89,06,00,09,01,16,00,00,00,79,00]: high/shared/level GSI22.
const DSDT_HASH: [u8; 32] = [
    0xed, 0x48, 0xc9, 0x77, 0x2a, 0xee, 0x85, 0x40, 0x66, 0xc1, 0x4b, 0x36, 0xce, 0x8f, 0x78, 0x7b,
    0xb6, 0x9d, 0x27, 0x9a, 0xfa, 0x15, 0xde, 0xa7, 0x29, 0xb8, 0xba, 0x2f, 0x9b, 0x77, 0x25, 0x6d,
];
const INTEL_DSDT_HASH: [u8; 32] = [
    0xdf, 0xe8, 0xaf, 0xc1, 0x3a, 0x17, 0x52, 0x62, 0xe7, 0xbf, 0x69, 0x71, 0x0b, 0xf7, 0x73, 0x8c,
    0x11, 0xd2, 0x20, 0x51, 0x99, 0x8d, 0x20, 0xd8, 0x20, 0x68, 0x5f, 0x37, 0x3e, 0x31, 0xcf, 0x80,
];
const LINE: LineRoute = LineRoute {
    gsi: 22,
    polarity: Polarity::High,
    trigger: Trigger::Level,
};
const INTX_DISABLE: u16 = 1 << 10;
type Io = ioapic::Unit<ioapic::Mmio, super::NativePlatform>;

pub(crate) struct Prepared {
    routing: Routing,
    unit: madt::Unit,
    sci: LineRoute,
    madt_hash: [u8; 32],
    fadt_hash: [u8; 32],
    // Actual immutable ACPI reclaim pages remain reserved and identity-mapped
    // in the host-check root; no heap/guest allocator can reclaim this table.
    dsdt: &'static [u8],
    dsdt_hash: [u8; 32],
}
impl Prepared {
    /// Enclosed by the source-bound TCG/Q35/SMM-off fixture qualification,
    /// before EBS. Only ACPI/PCI reads; no interrupt takeover occurs here.
    pub(crate) fn prepare(rsdp: u64, fadt: &[u8]) -> Result<Self, String> {
        // SAFETY: actual firmware RSDP/tables remain mapped before EBS.
        let madt =
            unsafe { acpi::find(rsdp, b"APIC") }.map_err(|e| format!("fixture MADT: {e:?}"))?;
        if core::arch::x86_64::__cpuid(0x8000_0000).eax < 0x8000_0008 {
            return Err(String::from("fixture lacks actual CPU physical-width leaf"));
        }
        let physical_bits = (core::arch::x86_64::__cpuid(0x8000_0008).eax & 255) as u8;
        let routing = Routing::parse(madt, physical_bits)
            .map_err(|e| format!("fixture MADT route: {e:?}"))?;
        if routing.units.len() != 1
            || routing.units[0]
                != (madt::Unit {
                    id: 0,
                    base: 0xfec00000,
                    gsi_base: 0,
                })
        {
            return Err(String::from(
                "level fixture requires exact actual Q35 IOAPIC",
            ));
        }
        let sci = routing
            .sci(fadt)
            .map_err(|e| format!("fixture SCI route: {e:?}"))?;
        let legacy = u32::from_le_bytes(
            fadt.get(40..44)
                .ok_or("short FADT DSDT")?
                .try_into()
                .unwrap(),
        ) as u64;
        let extended = fadt
            .get(140..148)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            .unwrap_or(0);
        let address = if extended == 0 { legacy } else { extended };
        if address == 0 {
            return Err(String::from("fixture DSDT missing"));
        }
        let dsdt = unsafe { acpi::table(address) }.map_err(|e| format!("fixture DSDT: {e:?}"))?;
        let dsdt_hash = Sha256::digest(dsdt).into();
        if dsdt.len() != 8098
            || &dsdt[..4] != b"DSDT"
            || ![DSDT_HASH, INTEL_DSDT_HASH].contains(&dsdt_hash)
        {
            return Err(String::from(
                "fixture actual DSDT differs from ACPICA route receipt",
            ));
        }
        let unit = routing.units[0];
        Ok(Self {
            routing,
            unit,
            sci,
            madt_hash: Sha256::digest(madt).into(),
            fadt_hash: Sha256::digest(fadt).into(),
            dsdt,
            dsdt_hash,
        })
    }
    pub(crate) fn mapping(&self) -> Range<u64> {
        self.unit.base..self.unit.base + 4096
    }
    /// Consume the same original Function returned after real DMA and MSI
    /// retirement. No normal driver probing can occur before this returns.
    pub(crate) fn run(
        self,
        mut function: Function,
        base: u64,
        clock: Clock,
    ) -> Result<String, String> {
        // Recheck the actual mapped table after EBS, immediately before line
        // ownership. The capture/receipt cannot authorize a changed live input.
        if Sha256::digest(self.dsdt).as_slice() != self.dsdt_hash {
            return Err(String::from("fixture DSDT changed before INTx ownership"));
        }
        let platform = super::NativePlatform(());
        platform
            .check_cpu()
            .map_err(|e| format!("level CPU: {e:?}"))?;
        let svr = super::controller().read(0xf0);
        if svr == u32::MAX || svr & (1 << 12) != 0 {
            return Err(String::from("level fixture requires actual EOI broadcast"));
        }
        let registers = unsafe { ioapic::Mmio::new(self.unit.base as usize) }
            .map_err(|e| format!("IOAPIC mapping: {e:?}"))?;
        // SAFETY: exact previously qualified Q35 single-BSP fixture, retained
        // actual UC IOAPIC page, EOI broadcast on, no firmware/SMM/other owner.
        let unit =
            unsafe { ioapic::Unit::attach(registers, platform, self.unit.id, self.unit.gsi_base) }
                .map_err(|e| format!("IOAPIC attach: {e:?}"))?;
        self.routing
            .owner(LINE, &[(self.unit, unit.pins())])
            .map_err(|e| format!("live IOAPIC GSI owner: {e:?}"))?;
        if function.address.bus != 0
            || function.address.device != 2
            || function.address.function != 0
            || function.vendor != 0x1234
            || function.device != 0x11e8
        {
            return Err(String::from("level fixture original EDU owner mismatch"));
        }
        if function.config().read8(0x3d) != 1
            || function.config().read16(4) & (4 | INTX_DISABLE) != INTX_DISABLE
        {
            return Err(String::from("EDU INTA/MSI-retired state mismatch"));
        }
        let interrupts = function.interrupts();
        let msi = interrupts.msi.ok_or("EDU MSI metadata missing")?;
        if function.config().read16(u16::from(msi.offset) + 2) & 1 != 0 || interrupts.msix.is_some()
        {
            return Err(String::from("EDU MSI remains active before INTx"));
        }
        let edu = Arc::new(Edu {
            base: base as usize,
            unit: unit.clone(),
            first: AtomicU64::new(0),
            second: AtomicU64::new(0),
            remote: AtomicU64::new(0),
            bad: AtomicU64::new(0),
        });
        let first: Arc<dyn Handler> = Arc::new(Member(edu.clone(), 1));
        let second: Arc<dyn Handler> = Arc::new(Member(edu.clone(), 2));
        let handlers = Arc::new(
            SharedHandlers::new(alloc::vec![first, second])
                .map_err(|e| format!("shared group: {e:?}"))?,
        );
        // SAFETY: actual full DSDT hash proves the independent ACPICA routing
        // input, live direct EDU INTA agrees, boot virtio is reset/stopped and
        // all other exact fixture endpoints are quiescent; no hidden sharer.
        let pin = unsafe {
            unit.claim(
                LINE,
                Box::new(Contributors {
                    function,
                    edu: edu.clone(),
                }),
            )
        }
        .map_err(|e| format!("IOAPIC line claim: {e:?}"))?;
        let mut registration = super::service()
            .map_err(|e| format!("level service: {e:?}"))?
            .request(Box::new(pin), handlers.clone())
            .map_err(|e| format!("level request: {e:?}"))?;
        let vector = registration.vector();
        unsafe {
            asm!("sti", options(nostack));
        }
        edu.write(0x60, 3);
        let complete = clock.wait(2_000_000, || {
            edu.first.load(Ordering::Acquire) >= 2
                && edu.second.load(Ordering::Acquire) == 1
                && edu.read(0x24) == 0
        });
        unsafe {
            asm!("cli", options(nostack));
        }
        if !complete
            || edu.first.load(Ordering::Acquire) != 2
            || edu.second.load(Ordering::Acquire) != 1
            || edu.remote.load(Ordering::Relaxed) < 2
            || edu.bad.load(Ordering::Relaxed) != 0
            || registration.handled() != Ok(2)
        {
            return Err(format!(
                "actual level proof failed complete={complete} first={} second={} remote={} bad={} handled={:?}",
                edu.first.load(Ordering::Acquire),
                edu.second.load(Ordering::Acquire),
                edu.remote.load(Ordering::Relaxed),
                edu.bad.load(Ordering::Relaxed),
                registration.handled()
            ));
        }
        registration
            .retire()
            .map_err(|e| format!("level retirement: {e:?}"))?;
        let state = unit
            .state(LINE.gsi)
            .map_err(|e| format!("retired IOAPIC: {e:?}"))?;
        if !state.masked
            || state.remote_irr
            || state.delivery_pending
            || Arc::strong_count(&handlers) != 1
            || Arc::strong_count(&edu) != 3
        {
            return Err(format!(
                "level release proof failed state={state:?} handlers={} edu={}",
                Arc::strong_count(&handlers),
                Arc::strong_count(&edu)
            ));
        }
        drop(handlers);
        if Arc::strong_count(&edu) != 1 {
            return Err(String::from("shared members retained after group release"));
        }
        edu.write(0x60, 3);
        unsafe {
            asm!("sti", options(nostack));
        }
        let late = clock.wait(1000, || {
            edu.first.load(Ordering::Acquire) != 2 || edu.second.load(Ordering::Acquire) != 1
        });
        unsafe {
            asm!("cli", options(nostack));
        }
        edu.write(0x64, u32::MAX);
        if late || unit.quarantine_count() != 0 {
            return Err(String::from("level delivery survived retirement"));
        }
        Ok(format!(
            "INTx gsi=22 high+shared+level vector={vector:#x} first=2 second=1 hold→EOI→retrigger=verified RemoteIRR=observed/drained group_refs=released late_delivery=absent DSDT={:x} MADT={:x} FADT={:x} SCI_gsi={} SCI_polarity={:?} SCI_trigger={:?}",
            Sha256::digest(self.dsdt),
            sha2::digest::generic_array::GenericArray::from(self.madt_hash),
            sha2::digest::generic_array::GenericArray::from(self.fadt_hash),
            self.sci.gsi,
            self.sci.polarity,
            self.sci.trigger
        ))
    }
}
struct Edu {
    base: usize,
    unit: Arc<Io>,
    first: AtomicU64,
    second: AtomicU64,
    remote: AtomicU64,
    bad: AtomicU64,
}
impl Edu {
    fn read(&self, o: usize) -> u32 {
        unsafe { ((self.base + o) as *const u32).read_volatile() }
    }
    fn write(&self, o: usize, v: u32) {
        unsafe { ((self.base + o) as *mut u32).write_volatile(v) };
    }
}
struct Member(Arc<Edu>, u32);
impl Handler for Member {
    fn handle(&self) -> Disposition {
        let cause = self.0.read(0x24);
        if cause & self.1 == 0 {
            return Disposition::NotMine;
        }
        match self.0.unit.state(LINE.gsi) {
            Ok(state) if state.remote_irr => {
                self.0.remote.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.0.bad.fetch_add(1, Ordering::Relaxed);
            }
        }
        if self.1 == 1 {
            let n = self.0.first.load(Ordering::Relaxed);
            // First IRQ deliberately leaves a real asserted device level;
            // actual APIC EOI must clear RemoteIRR and deliver it again.
            if n != 0 {
                self.0.write(0x64, 1);
            }
            self.0.first.fetch_add(1, Ordering::Release);
        } else {
            self.0.write(0x64, 2);
            self.0.second.fetch_add(1, Ordering::Release);
        }
        Disposition::Handled
    }
}
struct Contributors {
    function: Function,
    edu: Arc<Edu>,
}
// SAFETY: exact synchronous QEMU fixture only, no DMA command/worker/timer,
// all other sharers stopped; INTx-disable readback and real EDU idle/cause ACK.
unsafe impl Devices for Contributors {
    fn mask(&mut self) -> Result<(), IrqError> {
        let command = self.function.config().read16(4);
        if command == u16::MAX {
            return Err(IrqError::FailedRead);
        }
        self.function.config().write16(4, command | INTX_DISABLE);
        let actual = self.function.config().read16(4);
        if actual == u16::MAX {
            return Err(IrqError::FailedRead);
        }
        if actual & INTX_DISABLE == 0 {
            return Err(IrqError::Mask);
        }
        Ok(())
    }
    fn quiesce(&mut self) -> Result<(), IrqError> {
        let dma = unsafe { ((self.edu.base + 0x98) as *const u64).read_volatile() };
        let command = self.function.config().read16(4);
        if command == u16::MAX {
            return Err(IrqError::FailedRead);
        }
        if dma & 1 != 0 || self.edu.read(0x20) & 1 != 0 || command & 4 != 0 {
            return Err(IrqError::Quiesce);
        }
        self.edu.write(0x64, u32::MAX);
        if self.edu.read(0x24) != 0 {
            return Err(IrqError::Quiesce);
        }
        Ok(())
    }
    unsafe fn enable(&mut self) -> Result<(), IrqError> {
        let command = self.function.config().read16(4);
        if command == u16::MAX {
            return Err(IrqError::FailedRead);
        }
        if command & 4 != 0 {
            return Err(IrqError::Quiesce);
        }
        self.function.config().write16(4, command & !INTX_DISABLE);
        let actual = self.function.config().read16(4);
        if actual == u16::MAX {
            return Err(IrqError::FailedRead);
        }
        if actual & (4 | INTX_DISABLE) != 0 {
            return Err(IrqError::Mask);
        }
        Ok(())
    }
}

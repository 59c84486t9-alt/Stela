//! Actual original AMD data-path retirement, retaining root/IRQ interpretation.
//! Generic unsafe transports are algorithmic boundaries; native success needs
//! the real complete Source/configuration/EBS/control producer, never a snapshot.
use super::tables::{self, ControlKind, Description, Inventory};
use crate::bus::dma::amd::format::{Command, PhysicalAddress};
use alloc::{boxed::Box, vec::Vec};
use core::mem::ManuallyDrop;

const IOMMU: u64 = 1;
const COHERENT: u64 = 1 << 10;
const COMMAND: u64 = 1 << 12;
const COMMAND_RUN: u64 = 1 << 4;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const BUFFER_MASK: u64 = ADDRESS | (15 << 56);
const BASE_CONTROL: u64 = IOMMU | COHERENT | 2 | (7 << 5) | (1 << 8) | (1 << 9) | (1 << 11);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Context,
    Register,
    Mode,
    Memory,
    Graph(tables::Error),
    Queue,
    Fault,
    Timeout,
    Epoch,
    SharedDeviceTable,
}

/// Real original UC unit/function/reset/root owner, not observed numbers.
/// # Safety
/// Every method uses that same owned original unit. enter retains actual
/// process/current-CPU/root exclusion for its guard lifetime. Firmware/other
/// unit writers are excluded. All original controls/backing remain held on
/// failed construction, unwind or incomplete consumption. Aligned accesses
/// are real UC accesses; ticks are a checked bounded monotonic source.
pub unsafe trait Registers {
    type Access<'a>
    where
        Self: 'a;
    fn enter(&self) -> Result<Self::Access<'_>, Error>;
    fn read(&self, offset: usize) -> Result<u64, Error>;
    /// # Safety
    /// The SAME complete actual source cohort is contained and sealed; original
    /// unit/root/control/backing owners remain held. Every published address
    /// names the caller's SAME actual Queue allocation in this unit's qualified
    /// physical/coherent epoch; values stay within its real bounds. Base/head
    /// changes require original CmdBufEn0/Run0 and no fetched/pending commands.
    /// Tail publication follows actual queue visibility; no active slot may be
    /// reused without the prior exact completion. No root/IRQ/log/bypass field
    /// may be written. Partial failure/unwind retains ALL possibly used owners.
    unsafe fn write(&self, offset: usize, value: u64) -> Result<(), Error>;
    fn ticks(&self) -> u64;
    fn timeout_ticks(&self) -> u64;
}
/// Actual fresh, pinned command/completion allocation owners. No pointer plan
/// or numeric address tuple can implement this contract for native hardware.
/// # Safety
/// The queue and completion allocations are CPU-exclusive, coherent WB,
/// unencrypted, disjoint and never lent to firmware/another engine. The exact
/// owners remain held after exposure/failure. All CPU operations honor original
/// context. publish performs actual DMA visibility, not a compiler-only fence.
pub unsafe trait Queue {
    fn command_base(&self) -> u64;
    fn command_bytes(&self) -> usize;
    fn completion_base(&self) -> u64;
    fn completion_bytes(&self) -> usize;
    fn initialize(&self) -> Result<(), Error>;
    fn command(&self, offset: usize, command: Command) -> Result<(), Error>;
    fn publish(&self) -> Result<(), Error>;
    fn completion(&self) -> Result<u64, Error>;
}
/// Original retained EBS/allocation memory, plus exact data-half mutation.
/// # Safety
/// The same actual OS-transferred device table/all original backing stays
/// owned. replace_data compares/stores the first128 bits atomically under a
/// real qualified CPU/control guard; IRQ words128..255 cannot change. No raw
/// writer or safe payload alias escapes. All related unit/data writers are
/// serialized and hardware table updates are disabled. This is not a receipt.
pub unsafe trait Memory: tables::Memory {
    fn replace_data(&self, physical: u64, expected: [u64; 2], new: [u64; 2]) -> Result<(), Error>;
    fn publish_data(&self) -> Result<(), Error>;
}

#[derive(Clone, Copy)]
struct Snapshot {
    device: u64,
    command: u64,
    event: u64,
    control: u64,
    status: u64,
    command_head: u64,
    command_tail: u64,
    event_head: u64,
    event_tail: u64,
    efr: u64,
    // Only architecturally implemented, non-clearing registers are captured.
    // In particular F0/F8 are alternate logs;150/158 are MSI registers.
    auxiliary: [(usize, u64); 24],
    auxiliary_len: usize,
}
impl Snapshot {
    fn read(r: &impl Registers) -> Result<Self, Error> {
        let mut s = Self {
            device: r.read(0)?,
            command: r.read(8)?,
            event: r.read(16)?,
            control: r.read(24)?,
            status: r.read(0x2020)?,
            command_head: r.read(0x2000)?,
            command_tail: r.read(0x2008)?,
            event_head: r.read(0x2010)?,
            event_tail: r.read(0x2018)?,
            efr: r.read(0x30)?,
            auxiliary: [(0, 0); 24],
            auxiliary_len: 0,
        };
        if [
            s.device,
            s.command,
            s.event,
            s.control,
            s.status,
            s.efr,
            s.command_head,
            s.command_tail,
            s.event_head,
            s.event_tail,
        ]
        .contains(&u64::MAX)
        {
            return Err(Error::Register);
        }
        for offset in [0x20, 0x28] {
            s.capture(r, offset)?;
        }
        if s.efr & (1 << 1) != 0 {
            for offset in [0x38, 0x2030, 0x2038] {
                s.capture(r, offset)?;
            }
        }
        if s.efr & (1 << 7) != 0 {
            for offset in [0xe0, 0xe8, 0x2040, 0x2048] {
                s.capture(r, offset)?;
            }
        }
        let segments = (s.efr >> 38) & 3;
        for index in 0..((1usize << segments) - 1) {
            s.capture(r, 0x100 + index * 8)?;
        }
        let ppr = (s.efr >> 24) & 3;
        let event = (s.efr >> 28) & 3;
        if ppr == 3 || event == 3 {
            return Err(Error::Mode);
        }
        if ppr != 0 {
            for offset in [0xf0, 0x2050, 0x2058] {
                s.capture(r, offset)?;
            }
        }
        if event != 0 {
            for offset in [0xf8, 0x2070, 0x2078] {
                s.capture(r, offset)?;
            }
        }
        if s.efr & (1 << 8) != 0 {
            s.capture(r, 0x50)?;
        }
        Ok(s)
    }
    fn capture(&mut self, r: &impl Registers, offset: usize) -> Result<(), Error> {
        let value = r.read(offset)?;
        if value == u64::MAX || self.auxiliary_len == self.auxiliary.len() {
            return Err(Error::Register);
        }
        self.auxiliary[self.auxiliary_len] = (offset, value);
        self.auxiliary_len += 1;
        Ok(())
    }
    fn qualify(self, r: &impl Registers) -> Result<(), Error> {
        if self.control & !BASE_CONTROL != 0
            || self.control & (IOMMU | COHERENT) != (IOMMU | COHERENT)
            || (self.control >> 5) & 7 == 7
            || self.status != 0
            || self.efr & (1 << 6) == 0
            || self.command_head != self.command_tail
            || self.efr & (1 << 63) != 0
            || (self.efr>>42)&3!=0 // MARC routing needs its own actual owner.
            || (self.efr>>10)&3==3
            || self.device & !(ADDRESS | 0x1ff) != 0
            || self.device & ADDRESS == 0
            || r.timeout_ticks() == 0
            || r.timeout_ticks() >= (1 << 63)
        {
            return Err(Error::Mode);
        }
        // Explicit first mode: dormant PPR/GA/alternate logs and segmented
        // tables have no base. Their implemented reset lengths are NOT RAM
        // pointers. Nonzero dormant backing remains an open ownership mode.
        // Cmd/Event old backing is positively inventoried separately below.
        for &(offset, value) in &self.auxiliary[..self.auxiliary_len] {
            let allowed = match offset {
                0x38 | 0xe0 | 0xf0 | 0xf8 => matches!(value, 0 | 0x0800_0000_0000_0000),
                _ => value == 0,
            };
            if !allowed {
                return Err(Error::Mode);
            }
        }
        Ok(())
    }
}
fn dormant_buffer(
    value: u64,
    head: u64,
    tail: u64,
    kind: ControlKind,
    memory: &impl Memory,
    out: &mut Vec<(u64, u64, ControlKind)>,
) -> Result<(), Error> {
    if value & !BUFFER_MASK != 0 {
        return Err(Error::Mode);
    }
    let length = ((value >> 56) & 15) as u32;
    let base = value & ADDRESS;
    // Zero base with reset size is an inactive register, not a RAM owner.
    if base == 0 {
        return if matches!(length, 0 | 8) && head == 0 && tail == 0 {
            Ok(())
        } else {
            Err(Error::Mode)
        };
    }
    if length < 8 {
        return Err(Error::Mode);
    }
    let bytes = 16u64 << length;
    if !memory.owns_os_ram(base, bytes)
        || head >= bytes
        || tail >= bytes
        || head & 15 != 0
        || tail & 15 != 0
    {
        return Err(Error::Memory);
    }
    out.push((base, bytes, kind));
    Ok(())
}

struct Unit<R, Q, M> {
    registers: R,
    queue: Q,
    memory: M,
    snapshot: Snapshot,
    inventory: Inventory,
    extra: Vec<(u64, u64, ControlKind)>,
    physical_bits: u8,
}
struct Resources<R, Q, M> {
    units: Vec<Unit<R, Q, M>>,
}
struct Kept<R, Q, M>(Option<Box<Resources<R, Q, M>>>);
impl<R, Q, M> Drop for Kept<R, Q, M> {
    fn drop(&mut self) {
        core::mem::forget(self.0.take());
    }
}
pub struct Input<R, Q, M> {
    pub registers: R,
    pub queue: Q,
    pub memory: M,
    pub sources: Vec<u16>,
    pub physical_bits: u8,
    pub maximum_levels: u8,
}
pub struct Plan<R, Q, M> {
    kept: Kept<R, Q, M>,
}
pub struct Failure<R, Q, M> {
    pub error: Error,
    _kept: Kept<R, Q, M>,
}
/// Actual original controls/table/queue owners after both acknowledged data
/// fences. Same root and IRQ fields remain active. No stopped engine/IRQ grant.
pub struct Retired<R, Q, M> {
    resources: ManuallyDrop<Box<Resources<R, Q, M>>>,
}

impl<R: Registers, Q: Queue, M: Memory> Plan<R, Q, M> {
    /// # Safety
    /// Inputs are the COMPLETE actual original unit/source cohort, with same
    /// original CPU/Source/allocation provenance. No hidden/alias/nonPCI/ATS,
    /// firmware continuing writer or mutable shared device-table owner is
    /// omitted. All known unsupported modes refuse before any control effect.
    /// Native callers must implement this real producer, not pass observations.
    pub unsafe fn preflight(inputs: Vec<Input<R, Q, M>>) -> Result<Self, Failure<R, Q, M>> {
        let mut plan = Self {
            kept: Kept(Some(Box::new(Resources { units: Vec::new() }))),
        };
        let mut pending = ManuallyDrop::new(inputs.into_iter());
        let result = (|| {
            for input in pending.by_ref() {
                // Retain actual owners before any fallible callback/validation.
                let Input {
                    registers,
                    queue,
                    memory,
                    sources,
                    physical_bits,
                    maximum_levels,
                } = input;
                let owners = ManuallyDrop::new((registers, queue, memory));
                let (r, q, m) = &*owners;
                let _guard = r.enter()?;
                let snapshot = Snapshot::read(r)?;
                snapshot.qualify(r)?;
                // HATS is a hardware bound, not permission inferred from the
                // caller's maximum_levels metadata (AMD3.4.1 pp227-228).
                if maximum_levels > 4 + ((snapshot.efr >> 10) & 3) as u8 {
                    return Err(Error::Mode);
                }
                let bytes = ((snapshot.device & 0x1ff) + 1) * 4096;
                let description = Description {
                    base: snapshot.device & ADDRESS,
                    bytes,
                    physical_bits,
                    maximum_levels,
                };
                let inventory = tables::inspect(m, description, &sources).map_err(Error::Graph)?;
                let qbytes = q.command_bytes();
                let cbytes = q.completion_bytes();
                if !qbytes.is_power_of_two()
                    || !(4096..=512 * 1024).contains(&qbytes)
                    || cbytes < 4096
                    || !q.command_base().is_multiple_of(4096)
                    || !q.completion_base().is_multiple_of(4096)
                    || q.command_base()
                        .checked_add(qbytes as u64)
                        .is_none_or(|n| n > 1u64 << physical_bits)
                    || q.completion_base()
                        .checked_add(cbytes as u64)
                        .is_none_or(|n| n > 1u64 << physical_bits)
                {
                    return Err(Error::Queue);
                }
                let mut extra = Vec::new();
                dormant_buffer(
                    snapshot.command,
                    snapshot.command_head,
                    snapshot.command_tail,
                    ControlKind::Command,
                    m,
                    &mut extra,
                )?;
                dormant_buffer(
                    snapshot.event,
                    snapshot.event_head,
                    snapshot.event_tail,
                    ControlKind::Event,
                    m,
                    &mut extra,
                )?;
                if extra.iter().any(|(base, bytes, _)| {
                    base.checked_add(*bytes)
                        .is_none_or(|end| end > 1u64 << physical_bits)
                }) {
                    return Err(Error::Memory);
                }
                let index = plan.kept.0.as_ref().unwrap().units.len();
                extra.push((
                    q.command_base(),
                    qbytes as u64,
                    ControlKind::RetirementCommand(index),
                ));
                extra.push((
                    q.completion_base(),
                    cbytes as u64,
                    ControlKind::RetirementCompletion(index),
                ));
                drop(_guard);
                let (r, q, m) = ManuallyDrop::into_inner(owners);
                plan.kept.0.as_mut().unwrap().units.push(Unit {
                    registers: r,
                    queue: q,
                    memory: m,
                    snapshot,
                    inventory,
                    extra,
                    physical_bits,
                });
            }
            let units = &plan.kept.0.as_ref().unwrap().units;
            if units.is_empty() {
                return Err(Error::Mode);
            }
            // This first adopter owns each mutable device table once. A shared
            // table needs one real aggregate owner+all-unit invalidations;
            // independent clones of numeric table pointers are not supported.
            for (index, unit) in units.iter().enumerate() {
                let base = unit.snapshot.device & ADDRESS;
                let bytes = ((unit.snapshot.device & 0x1ff) + 1) * 4096;
                if units[..index].iter().any(|u| {
                    let p = u.snapshot.device & ADDRESS;
                    let n = ((u.snapshot.device & 0x1ff) + 1) * 4096;
                    p < base + bytes && base < p + n
                }) {
                    return Err(Error::SharedDeviceTable);
                }
            }
            let inventories = units.iter().map(|u| &u.inventory).collect::<Vec<_>>();
            let extra = units
                .iter()
                .flat_map(|u| u.extra.iter().copied())
                .collect::<Vec<_>>();
            tables::validate_refs(&inventories, &extra).map_err(Error::Graph)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                // SAFETY: fully exhausted iterator; no original unprocessed owner remains.
                unsafe { ManuallyDrop::drop(&mut pending) };
                Ok(plan)
            }
            Err(error) => Err(Failure {
                error,
                _kept: plan.kept,
            }),
        }
    }

    /// # Safety
    /// The SAME actual complete source/configuration cohort is now contained,
    /// BME transport-sealed and qualified ordinary read pushes have completed
    /// leaf-first. Its owners/backing remain kept unchanged through this call.
    /// No device/firmware/ATS/alias/new-source writer can restart. This precondition
    /// must come from the native consumed source owner, not a boolean or claim
    /// that no Stela driver started. Old IRQ classes/targets are NOT certified.
    pub unsafe fn retire_after_containment(mut self) -> Result<Retired<R, Q, M>, Failure<R, Q, M>> {
        let result = (|| {
            let units = &self.kept.0.as_ref().unwrap().units;
            // Repeat EVERY actual unit/table observation before ANY queue/control
            // publication. Old roots stay active; no IommuEn toggle occurs.
            for unit in units {
                unit.check_initial()?;
                unit.check_dtes()?;
            }
            for unit in units {
                unit.start_queue()?;
                unit.wait_batch(0, 1)?;
            }
            // All old-path payload fences acknowledged. Change only first128
            // data bits; original IRQ words and global interrupt controls remain.
            for unit in units {
                unit.block_data()?;
            }
            for unit in units {
                unit.wait_batch(32, 2)?;
                unit.check_blocked()?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(Retired {
                resources: ManuallyDrop::new(self.kept.0.take().unwrap()),
            }),
            Err(error) => Err(Failure {
                error,
                _kept: self.kept,
            }),
        }
    }
}

impl<R: Registers, Q: Queue, M: Memory> Unit<R, Q, M> {
    fn timeout(&self, start: u64) -> bool {
        self.registers.ticks().wrapping_sub(start) >= self.registers.timeout_ticks()
    }
    fn check_initial(&self) -> Result<(), Error> {
        let _guard = self.registers.enter()?;
        self.check_initial_locked()
    }
    fn check_initial_locked(&self) -> Result<(), Error> {
        let s = Snapshot::read(&self.registers)?;
        s.qualify(&self.registers)?;
        let p = self.snapshot;
        if [
            s.device,
            s.command,
            s.event,
            s.control,
            s.status,
            s.command_head,
            s.command_tail,
            s.event_head,
            s.event_tail,
            s.efr,
        ] != [
            p.device,
            p.command,
            p.event,
            p.control,
            p.status,
            p.command_head,
            p.command_tail,
            p.event_head,
            p.event_tail,
            p.efr,
        ] {
            return Err(Error::Epoch);
        }
        if s.auxiliary_len != p.auxiliary_len || s.auxiliary != p.auxiliary {
            return Err(Error::Epoch);
        }
        Ok(())
    }
    fn check_dtes(&self) -> Result<(), Error> {
        let _guard = self.registers.enter()?;
        self.check_dtes_locked()
    }
    fn check_dtes_locked(&self) -> Result<(), Error> {
        let base = self.snapshot.device & ADDRESS;
        for &(rid, dte) in self.inventory.dtes() {
            let at = base + u64::from(rid) * 32;
            let expected = dte.words();
            for (index, word) in expected.into_iter().enumerate() {
                if self
                    .memory
                    .read(at + index as u64 * 8)
                    .map_err(Error::Graph)?
                    != word
                {
                    return Err(Error::Epoch);
                }
            }
        }
        Ok(())
    }
    fn command_register(&self) -> u64 {
        self.queue.command_base() | u64::from(self.queue.command_bytes().trailing_zeros() - 4) << 56
    }
    fn health(&self) -> Result<(), Error> {
        let r = &self.registers;
        if r.read(0)? != self.snapshot.device
            || r.read(24)? != self.snapshot.control | COMMAND
            || r.read(8)? != self.command_register()
            || r.read(16)? != self.snapshot.event
            || r.read(0x2010)? != self.snapshot.event_head
            || r.read(0x2018)? != self.snapshot.event_tail
            || r.read(0x2020)? != COMMAND_RUN
            || r.read(0x30)? != self.snapshot.efr
        {
            return Err(Error::Fault);
        }
        for &(offset, value) in &self.snapshot.auxiliary[..self.snapshot.auxiliary_len] {
            if r.read(offset)? != value {
                return Err(Error::Fault);
            }
        }
        Ok(())
    }
    fn start_queue(&self) -> Result<(), Error> {
        let _guard = self.registers.enter()?;
        self.check_initial_locked()?;
        self.queue.initialize()?;
        // AMD2.4 requires CmdBufRun0 for these changes; preflight+recheck above
        // established it while ORIGINAL DeviceTableBase/IommuEn stay unchanged.
        // SAFETY: consumed actual complete source containment is this method's
        // enclosing retirement precondition. All-unit graph/control preflight
        // and immediate SAME original Run0 recheck passed; this exact kept Q
        // allocation was initialized/published above. Old root/IRQ control and
        // all backing remain retained; no other owner can enable the queue.
        unsafe {
            self.registers.write(8, self.command_register())?;
            self.registers.write(0x2000, 0)?;
            self.registers.write(0x2008, 0)?;
            self.registers.write(24, self.snapshot.control | COMMAND)?;
        }
        let start = self.registers.ticks();
        loop {
            if self.registers.read(0x2020)? == COMMAND_RUN {
                break;
            }
            if self.timeout(start) {
                return Err(Error::Timeout);
            }
            core::hint::spin_loop();
        }
        self.health()
    }
    fn wait_batch(&self, offset: usize, sequence: u64) -> Result<(), Error> {
        let _guard = self.registers.enter()?;
        self.health()?;
        if self.registers.read(0x2000)? != offset as u64
            || self.registers.read(0x2008)? != offset as u64
        {
            return Err(Error::Queue);
        }
        let completion = Command::completion(
            PhysicalAddress::new(self.queue.completion_base(), self.physical_bits)
                .map_err(|_| Error::Queue)?,
            sequence,
            false,
        )
        .map_err(|_| Error::Queue)?;
        self.queue.command(offset, Command::invalidate_all())?;
        self.queue.command(offset + 16, completion)?;
        self.queue.publish()?;
        let next = offset + 32;
        // SAFETY: same contained original cohort/root/queue owners; prior exact
        // completion+head/tail admit these bounded actual slots and the new
        // commands were made visible above. No arbitrary PA or descriptor
        // snapshot can authorize this write. Failure keeps the active graph.
        unsafe { self.registers.write(0x2008, next as u64) }?;
        let start = self.registers.ticks();
        loop {
            self.health()?;
            let observed = self.queue.completion()?;
            let head = self.registers.read(0x2000)?;
            if head >= self.queue.command_bytes() as u64 || head & 15 != 0 || observed > sequence {
                return Err(Error::Queue);
            }
            // Exact coherent store acknowledges prior matched invalidations.
            // Head equality ALONE is only fetch progress and never a receipt.
            if observed == sequence && head == next as u64 {
                return Ok(());
            }
            if self.timeout(start) {
                return Err(Error::Timeout);
            }
            core::hint::spin_loop();
        }
    }
    fn block_data(&self) -> Result<(), Error> {
        let _guard = self.registers.enter()?;
        self.health()?;
        self.check_dtes_locked()?;
        let base = self.snapshot.device & ADDRESS;
        for &(rid, dte) in self.inventory.dtes() {
            let old = dte.words();
            let new = dte.blocked_data();
            if old[..2] != new[..2] {
                self.memory.replace_data(
                    base + u64::from(rid) * 32,
                    [old[0], old[1]],
                    [new[0], new[1]],
                )?;
            }
        }
        self.memory.publish_data()?;
        self.health()
    }
    fn check_blocked(&self) -> Result<(), Error> {
        let _guard = self.registers.enter()?;
        self.health()?;
        let base = self.snapshot.device & ADDRESS;
        for &(rid, dte) in self.inventory.dtes() {
            for (index, word) in dte.blocked_data().into_iter().enumerate() {
                if self
                    .memory
                    .read(base + u64::from(rid) * 32 + index as u64 * 8)
                    .map_err(Error::Graph)?
                    != word
                {
                    return Err(Error::Epoch);
                }
            }
        }
        Ok(())
    }
}

/// Actual objects consumed by native adopted-table/runtime construction. No
/// numeric table descriptor or prior completion snapshot can construct this.
pub struct Adopted<R, Q, M> {
    unit: ManuallyDrop<Unit<R, Q, M>>,
}
/// Descriptive register/ring position accompanying consumed REAL owners. This
/// value alone cannot construct Adopted or authorize any native takeover.
pub struct Position {
    pub device_register: u64,
    pub control: u64,
    pub command_tail: usize,
    pub sequence: u64,
}
impl<R, Q, M> Adopted<R, Q, M> {
    /// # Safety
    /// The recipient immediately retains these SAME active-root/queue/table
    /// owners in its permanent native quarantine graph BEFORE any fallible
    /// callback, allocation, unwind or return. Drop cannot free active backing.
    /// No new Source/configuration/IRQ grant may be reconstructed from Position.
    pub unsafe fn into_parts(self) -> (R, Q, M, Position) {
        let Unit {
            registers,
            queue,
            memory,
            snapshot,
            ..
        } = ManuallyDrop::into_inner(self.unit);
        (
            registers,
            queue,
            memory,
            Position {
                device_register: snapshot.device,
                control: snapshot.control | COMMAND,
                command_tail: 64,
                sequence: 2,
            },
        )
    }
}
impl<R, Q, M> Retired<R, Q, M> {
    pub fn into_adopted(self) -> Vec<Adopted<R, Q, M>> {
        let Resources { units } = *ManuallyDrop::into_inner(self.resources);
        units
            .into_iter()
            .map(|unit| Adopted {
                unit: ManuallyDrop::new(unit),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;

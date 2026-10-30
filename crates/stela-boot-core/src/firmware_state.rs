// SPDX-License-Identifier: GPL-2.0-only
// Copyright © 2006-2015 Intel Corporation.
// Copyright (C) 2007-2010 Advanced Micro Devices, Inc.
// Disable sequences adapted from Linux drivers/iommu/intel/{iommu.c,dmar.c,
// irq_remapping.c} (iommu_disable_protect_mem_regions, iommu_disable_translation,
// dmar_disable_qi, iommu_disable_irq_remapping) at commit
// a804c5742bff224d4cb4d25dd383554d598be32b, and drivers/iommu/amd/init.c
// (iommu_disable) at commit cc9de5d4b5ab6459f5774946aa3195ad51236fa8. Source
// hashes and license terms: crates/stela-driver-base/src/platform/THIRD_PARTY.md
// and LICENSES/GPL-2.0-only.txt.
//! IOMMU state the firmware leaves on at ExitBootServices. VT-d translation,
//! queued invalidation and interrupt remapping, and AMD-Vi translation and
//! logs, read tables in boot-services memory that Stela reuses as guest RAM;
//! VT-d Protected Memory Regions block device DMA into their ranges. Every
//! unit the DMAR and IVRS tables list is read before any Stela driver runs or
//! firmware memory is reused, and each such feature is turned off, leaving
//! host DMA untranslated, or the boot refuses.
//!
//! Register layouts: Intel VT-d specification rev. 4.1 section 11.4; AMD I/O
//! Virtualization Technology specification 48882 rev. 3.11 section 3.4.

/// Units one boot checks; a host listing more refuses.
pub const MAX_UNITS: usize = 64;

const TABLE_HEADER: usize = 48;

// VT-d registers and bits.
const CAP: usize = 0x08;
const GCMD: usize = 0x18;
const GSTS: usize = 0x1c;
const FECTL: usize = 0x38;
const PMEN: usize = 0x64;
const IQH: usize = 0x80;
const IQT: usize = 0x88;
const TRANSLATION: u32 = 1 << 31;
const QUEUED_INVALIDATION: u32 = 1 << 26;
const INTERRUPT_REMAP: u32 = 1 << 25;
const PROTECT_ENABLE: u32 = 1 << 31;
const PROTECT_STATUS: u32 = 1;
const FAULT_MASK: u32 = 1 << 31;
const CAP_PLMR: u64 = 1 << 5;
const CAP_PHMR: u64 = 1 << 6;

// AMD-Vi registers and control bits (Linux amd_iommu_types.h CONTROL_*).
const CONTROL: usize = 0x18;
const STATUS: usize = 0x2020;
const IOMMU_ENABLE: u64 = 1 << 0;
const EVENT_LOG: u64 = 1 << 2;
const EVENT_INTERRUPT: u64 = 1 << 3;
const COMMAND_BUFFER: u64 = 1 << 12;
const PPR_LOG: u64 = 1 << 13;
const PPR_INTERRUPT: u64 = 1 << 14;
const GA_LOG: u64 = 1 << 28;
const GA_INTERRUPT: u64 = 1 << 29;
const IRTE_CACHE_DISABLE: u64 = 1 << 59;
/// Linux iommu_disable's order: command buffer, event interrupt and log,
/// GA log, PPR log, then translation itself.
const AMD_DISABLE_ORDER: [u64; 8] = [
    COMMAND_BUFFER,
    EVENT_INTERRUPT,
    EVENT_LOG,
    GA_LOG,
    GA_INTERRUPT,
    PPR_LOG,
    PPR_INTERRUPT,
    IOMMU_ENABLE,
];
const AMD_ACTIVE: u64 = IOMMU_ENABLE
    | EVENT_LOG
    | EVENT_INTERRUPT
    | COMMAND_BUFFER
    | PPR_LOG
    | PPR_INTERRUPT
    | GA_LOG
    | GA_INTERRUPT;
/// EventLogRun, CmdBufRun, PprLogRun and GALogRun.
const AMD_RUNNING: u64 = (1 << 3) | (1 << 4) | (1 << 7) | (1 << 8);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Vtd,
    AmdVi,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Unit {
    pub kind: Kind,
    pub base: u64,
    pub segment: u16,
}

/// Every remapping unit the firmware tables list, deduplicated by base.
#[derive(Clone, Copy, Debug)]
pub struct Units {
    units: [Unit; MAX_UNITS],
    count: usize,
    /// DMAR flags: bit 0 INTR_REMAP, bit 1 X2APIC_OPT_OUT, bit 2
    /// DMA_CTRL_PLATFORM_OPT_IN (the firmware asks the OS to keep DMA
    /// protection on).
    pub dmar_flags: u8,
}

impl Default for Units {
    fn default() -> Self {
        Self {
            units: [Unit {
                kind: Kind::Vtd,
                base: 0,
                segment: 0,
            }; MAX_UNITS],
            count: 0,
            dmar_flags: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableError {
    /// Signature, length or reserved header fields are invalid.
    Header,
    /// The structure at this offset has an invalid length; units after it
    /// are unknown.
    Structure(usize),
    /// More than `MAX_UNITS` units.
    Capacity,
}

impl Units {
    pub fn as_slice(&self) -> &[Unit] {
        &self.units[..self.count]
    }

    fn push(&mut self, unit: Unit, at: usize) -> Result<(), TableError> {
        if unit.base == 0 || !unit.base.is_multiple_of(4096) {
            return Err(TableError::Structure(at));
        }
        if self.as_slice().iter().any(|known| known.base == unit.base) {
            return Ok(());
        }
        let slot = self.units.get_mut(self.count).ok_or(TableError::Capacity)?;
        *slot = unit;
        self.count += 1;
        Ok(())
    }

    /// Add each DRHD of a DMAR table. Other structures (RMRR, ATSR, RHSA,
    /// ANDD, SATC, SIDP) name no register window and are passed over.
    pub fn add_dmar(&mut self, table: &[u8]) -> Result<(), TableError> {
        header(table, b"DMAR")?;
        self.dmar_flags = table[37];
        walk(table, 2, |at, kind, entry| {
            if kind != 0 {
                return Ok(());
            }
            if entry.len() < 16 {
                return Err(TableError::Structure(at));
            }
            let unit = Unit {
                kind: Kind::Vtd,
                base: u64::from_le_bytes(entry[8..16].try_into().unwrap()),
                segment: u16::from_le_bytes([entry[6], entry[7]]),
            };
            self.push(unit, at)
        })
    }

    /// Add each IVHD (types 10h, 11h and 40h) of an IVRS table. Blocks of
    /// several types describing one IOMMU share its base. IVMD blocks name no
    /// register window and are passed over.
    pub fn add_ivrs(&mut self, table: &[u8]) -> Result<(), TableError> {
        header(table, b"IVRS")?;
        walk(table, 1, |at, kind, entry| {
            if !matches!(kind, 0x10 | 0x11 | 0x40) {
                return Ok(());
            }
            if entry.len() < 24 {
                return Err(TableError::Structure(at));
            }
            let unit = Unit {
                kind: Kind::AmdVi,
                base: u64::from_le_bytes(entry[8..16].try_into().unwrap()),
                segment: u16::from_le_bytes([entry[16], entry[17]]),
            };
            self.push(unit, at)
        })
    }
}

fn header(table: &[u8], signature: &[u8; 4]) -> Result<(), TableError> {
    if table.len() < TABLE_HEADER
        || &table[..4] != signature
        || u32::from_le_bytes(table[4..8].try_into().unwrap()) as usize != table.len()
    {
        return Err(TableError::Header);
    }
    Ok(())
}

/// Visit each structure after the header as `(offset, type, bytes)`. The type
/// field is `type_bytes` wide; the 16-bit length is at offset 2.
fn walk(
    table: &[u8],
    type_bytes: usize,
    mut visit: impl FnMut(usize, u16, &[u8]) -> Result<(), TableError>,
) -> Result<(), TableError> {
    let mut offset = TABLE_HEADER;
    while offset < table.len() {
        let head = table
            .get(offset..offset + 4)
            .ok_or(TableError::Structure(offset))?;
        let kind = if type_bytes == 2 {
            u16::from_le_bytes([head[0], head[1]])
        } else {
            u16::from(head[0])
        };
        let length = usize::from(u16::from_le_bytes([head[2], head[3]]));
        let entry = table
            .get(offset..offset + length)
            .filter(|_| length >= 4)
            .ok_or(TableError::Structure(offset))?;
        visit(offset, kind, entry)?;
        offset += length;
    }
    Ok(())
}

/// One unit's register window and a monotonic deadline clock.
///
/// # Safety
/// Accesses reach the unit's registers with their real effects, uncached, in
/// program order. They stay within the unit's first 4 KiB (VT-d, through
/// IQT) or 16 KiB (AMD-Vi, through the status register).
pub unsafe trait Window {
    fn read32(&self, offset: usize) -> u32;
    fn read64(&self, offset: usize) -> u64;
    fn write32(&self, offset: usize, value: u32);
    fn write64(&self, offset: usize, value: u64);
    /// True once the operation's deadline has passed.
    fn expired(&self, start: u64) -> bool;
    fn now(&self) -> u64;
}

/// What a unit was doing when Stela found it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Found {
    /// Translation, logs and protected regions were all off.
    Inactive,
    /// VT-d with the global status and protected-memory enable registers the
    /// firmware left.
    Vtd { status: u32, protected: u32 },
    /// AMD-Vi with the control register the firmware left.
    AmdVi { control: u64 },
    /// The registers read all ones; Linux's map_iommu ignores such a unit.
    Unreadable,
}

impl Found {
    /// The firmware left a feature on that Stela must turn off.
    pub fn active(self) -> bool {
        matches!(self, Self::Vtd { .. } | Self::AmdVi { .. })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    /// The named feature still reported on after the deadline.
    Timeout(&'static str),
}

/// Read the unit's state without changing it.
pub fn inspect(kind: Kind, window: &impl Window) -> Found {
    match kind {
        Kind::Vtd => {
            let status = window.read32(GSTS);
            let protected = window.read32(PMEN);
            if status == u32::MAX || protected == u32::MAX {
                Found::Unreadable
            } else if status & (TRANSLATION | QUEUED_INVALIDATION | INTERRUPT_REMAP) != 0
                || protected & (PROTECT_ENABLE | PROTECT_STATUS) != 0
            {
                Found::Vtd { status, protected }
            } else {
                Found::Inactive
            }
        }
        Kind::AmdVi => {
            let control = window.read64(CONTROL);
            if control == u64::MAX {
                Found::Unreadable
            } else if control & AMD_ACTIVE != 0 {
                Found::AmdVi { control }
            } else {
                Found::Inactive
            }
        }
    }
}

/// Turn off every feature `inspect` found on. Host devices then DMA
/// untranslated and unprotected.
///
/// # Safety
/// Runs after ExitBootServices, before Stela's drivers start DMA or firmware
/// memory is reused, with no other CPU or firmware owner of the unit. Devices
/// may still be bus masters; their DMA then reaches memory untranslated.
pub unsafe fn release(kind: Kind, window: &impl Window) -> Result<Found, Failure> {
    let found = inspect(kind, window);
    match found {
        Found::Vtd { status, protected } => release_vtd(window, status, protected)?,
        Found::AmdVi { control } => release_amd(window, control)?,
        Found::Inactive | Found::Unreadable => {}
    }
    Ok(found)
}

fn wait(
    window: &impl Window,
    feature: &'static str,
    done: impl Fn() -> bool,
) -> Result<(), Failure> {
    let start = window.now();
    while !done() {
        if window.expired(start) {
            return Err(Failure::Timeout(feature));
        }
        core::hint::spin_loop();
    }
    Ok(())
}

fn release_vtd(window: &impl Window, status: u32, protected: u32) -> Result<(), Failure> {
    // Fault events would reach a firmware handler that no longer exists.
    window.write32(FECTL, FAULT_MASK);
    if protected & (PROTECT_ENABLE | PROTECT_STATUS) != 0
        && window.read64(CAP) & (CAP_PLMR | CAP_PHMR) != 0
    {
        window.write32(PMEN, protected & !PROTECT_ENABLE);
        wait(window, "protected memory regions", || {
            window.read32(PMEN) & PROTECT_STATUS == 0
        })?;
    }
    // GCMD takes the persistent enables; the one-shot commands stay clear.
    let mut command = status & (TRANSLATION | QUEUED_INVALIDATION | INTERRUPT_REMAP);
    for (bit, feature) in [
        (TRANSLATION, "DMA translation"),
        (INTERRUPT_REMAP, "interrupt remapping"),
        (QUEUED_INVALIDATION, "queued invalidation"),
    ] {
        if command & bit == 0 {
            continue;
        }
        if bit == QUEUED_INVALIDATION {
            // Let the queue drain its pending descriptors first.
            let _ = wait(window, feature, || window.read64(IQH) == window.read64(IQT));
        }
        command &= !bit;
        window.write32(GCMD, command);
        wait(window, feature, || window.read32(GSTS) & bit == 0)?;
    }
    Ok(())
}

fn release_amd(window: &impl Window, control: u64) -> Result<(), Failure> {
    let mut control = control;
    for bit in AMD_DISABLE_ORDER {
        if control & bit != 0 {
            control &= !bit;
            window.write64(CONTROL, control);
        }
    }
    if control & IRTE_CACHE_DISABLE != 0 {
        control &= !IRTE_CACHE_DISABLE;
        window.write64(CONTROL, control);
    }
    wait(window, "AMD-Vi translation", || {
        window.read64(CONTROL) & AMD_ACTIVE == 0
    })?;
    wait(window, "AMD-Vi command and log engines", || {
        window.read64(STATUS) & AMD_RUNNING == 0
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{collections::BTreeMap, vec, vec::Vec};
    use core::cell::{Cell, RefCell};

    fn sealed(signature: &[u8; 4], flags: u8, body: &[u8]) -> Vec<u8> {
        let mut table = vec![0; TABLE_HEADER];
        table[..4].copy_from_slice(signature);
        table[37] = flags;
        table.extend_from_slice(body);
        let bytes = table.len() as u32;
        table[4..8].copy_from_slice(&bytes.to_le_bytes());
        table
    }

    fn drhd(base: u64, segment: u16) -> Vec<u8> {
        let mut entry = vec![0; 16];
        entry[2..4].copy_from_slice(&16u16.to_le_bytes());
        entry[6..8].copy_from_slice(&segment.to_le_bytes());
        entry[8..16].copy_from_slice(&base.to_le_bytes());
        entry
    }

    fn ivhd(kind: u8, base: u64, length: u16) -> Vec<u8> {
        let mut block = vec![0; usize::from(length)];
        block[0] = kind;
        block[2..4].copy_from_slice(&length.to_le_bytes());
        block[8..16].copy_from_slice(&base.to_le_bytes());
        block
    }

    #[test]
    fn dmar_lists_every_unit_and_passes_over_reserved_memory_structures() {
        let mut body = drhd(0xfed9_0000, 0);
        body.extend([1, 0, 8, 0, 0, 0, 0, 0]); // RMRR header only
        body.extend(drhd(0xfed9_1000, 0));
        body.extend(drhd(0xfed9_0000, 0)); // duplicate base
        body.extend(drhd(0x2_0000_0000, 1));
        let mut units = Units::default();
        units.add_dmar(&sealed(b"DMAR", 4, &body)).unwrap();
        let bases: Vec<_> = units.as_slice().iter().map(|unit| unit.base).collect();
        assert_eq!(bases, [0xfed9_0000, 0xfed9_1000, 0x2_0000_0000]);
        assert_eq!(units.as_slice()[2].segment, 1);
        assert_eq!(units.dmar_flags, 4);
    }

    #[test]
    fn ivrs_merges_blocks_of_one_iommu_and_skips_memory_definitions() {
        let mut body = ivhd(0x10, 0xfd20_0000, 24);
        body.extend(ivhd(0x11, 0xfd20_0000, 40));
        body.extend(ivhd(0x20, 0, 32)); // IVMD
        body.extend(ivhd(0x40, 0xfd30_0000, 40));
        let mut units = Units::default();
        units.add_ivrs(&sealed(b"IVRS", 0, &body)).unwrap();
        let found: Vec<_> = units
            .as_slice()
            .iter()
            .map(|unit| (unit.kind, unit.base))
            .collect();
        assert_eq!(
            found,
            [(Kind::AmdVi, 0xfd20_0000), (Kind::AmdVi, 0xfd30_0000)]
        );
    }

    #[test]
    fn malformed_tables_keep_units_found_before_the_bad_structure() {
        let mut body = drhd(0xfed9_0000, 0);
        body.extend([0, 0, 2, 0]); // length below the header
        let mut units = Units::default();
        assert_eq!(
            units.add_dmar(&sealed(b"DMAR", 0, &body)),
            Err(TableError::Structure(64))
        );
        assert_eq!(units.as_slice().len(), 1);
        let mut short = drhd(0xfed9_0000, 0);
        short[2..4].copy_from_slice(&8u16.to_le_bytes());
        short.truncate(8);
        assert_eq!(
            Units::default().add_dmar(&sealed(b"DMAR", 0, &short)),
            Err(TableError::Structure(48))
        );
        assert_eq!(
            Units::default().add_dmar(&sealed(b"IVRS", 0, &[])),
            Err(TableError::Header)
        );
        let mut truncated = sealed(b"DMAR", 0, &drhd(1 << 12, 0));
        truncated.pop();
        assert_eq!(
            Units::default().add_dmar(&truncated),
            Err(TableError::Header)
        );
    }

    #[test]
    fn more_units_than_capacity_refuse() {
        let body: Vec<u8> = (0..=MAX_UNITS as u64)
            .flat_map(|index| drhd(0xfe00_0000 + index * 4096, 0))
            .collect();
        assert_eq!(
            Units::default().add_dmar(&sealed(b"DMAR", 0, &body)),
            Err(TableError::Capacity)
        );
    }

    /// Registers whose status bits follow their command bits after a number
    /// of reads, like hardware completing a command.
    struct Fake {
        kind: Kind,
        registers: RefCell<BTreeMap<usize, u64>>,
        writes: RefCell<Vec<(usize, u64)>>,
        stuck: u64,
        clock: Cell<u64>,
    }

    impl Fake {
        fn new(kind: Kind, values: &[(usize, u64)]) -> Self {
            Self {
                kind,
                registers: RefCell::new(values.iter().copied().collect()),
                writes: RefCell::new(Vec::new()),
                stuck: 0,
                clock: Cell::new(0),
            }
        }
        fn get(&self, offset: usize) -> u64 {
            self.registers.borrow().get(&offset).copied().unwrap_or(0)
        }
        fn set(&self, offset: usize, value: u64) {
            self.registers.borrow_mut().insert(offset, value);
        }
    }

    // SAFETY: the fake registers model one unit's window and are owned by one test.
    unsafe impl Window for Fake {
        fn read32(&self, offset: usize) -> u32 {
            self.clock.set(self.clock.get() + 1);
            self.get(offset) as u32
        }
        fn read64(&self, offset: usize) -> u64 {
            self.clock.set(self.clock.get() + 1);
            self.get(offset)
        }
        fn write32(&self, offset: usize, value: u32) {
            self.write64(offset, u64::from(value));
        }
        fn write64(&self, offset: usize, value: u64) {
            self.writes.borrow_mut().push((offset, value));
            self.set(offset, value);
            match (self.kind, offset) {
                (Kind::Vtd, GCMD) => {
                    let status = (self.get(GSTS) & !0xffff_ffff_u64)
                        | (value & !self.stuck)
                        | (self.get(GSTS) & self.stuck);
                    self.set(GSTS, status);
                }
                (Kind::Vtd, PMEN) if value & u64::from(PROTECT_ENABLE) == 0 => {
                    self.set(PMEN, 0);
                }
                (Kind::AmdVi, CONTROL) => self.set(STATUS, 0),
                _ => {}
            }
        }
        fn expired(&self, start: u64) -> bool {
            self.clock.get() - start > 100
        }
        fn now(&self) -> u64 {
            self.clock.get()
        }
    }

    #[test]
    fn vtd_translation_remapping_and_protected_regions_turn_off_in_linux_order() {
        let status = TRANSLATION | QUEUED_INVALIDATION | INTERRUPT_REMAP | (1 << 30);
        let fake = Fake::new(
            Kind::Vtd,
            &[
                (CAP, CAP_PLMR),
                (GSTS, u64::from(status)),
                (PMEN, u64::from(PROTECT_ENABLE | PROTECT_STATUS)),
            ],
        );
        // SAFETY: the fake window stands in for the unit, and this test is its only owner.
        let found = unsafe { release(Kind::Vtd, &fake) }.unwrap();
        assert!(found.active());
        assert_eq!(inspect(Kind::Vtd, &fake), Found::Inactive);
        let commands: Vec<_> = fake
            .writes
            .borrow()
            .iter()
            .filter(|(offset, _)| *offset == GCMD)
            .map(|&(_, value)| value as u32)
            .collect();
        // Root-pointer status is never written back as a one-shot command.
        assert_eq!(
            commands,
            [
                QUEUED_INVALIDATION | INTERRUPT_REMAP,
                QUEUED_INVALIDATION,
                0
            ]
        );
        assert_eq!(fake.writes.borrow()[0], (FECTL, u64::from(FAULT_MASK)));
    }

    #[test]
    fn vtd_inactive_and_all_ones_units_are_left_unchanged() {
        let idle = Fake::new(Kind::Vtd, &[(GSTS, 1 << 30)]);
        // SAFETY: the fake window stands in for the unit, and this test is its only owner.
        assert_eq!(unsafe { release(Kind::Vtd, &idle) }, Ok(Found::Inactive));
        assert!(idle.writes.borrow().is_empty());
        let absent = Fake::new(Kind::Vtd, &[(GSTS, u64::MAX), (PMEN, u64::MAX)]);
        assert_eq!(
            // SAFETY: the fake window stands in for the unit, and this test is its only owner.
            unsafe { release(Kind::Vtd, &absent) },
            Ok(Found::Unreadable)
        );
        assert!(absent.writes.borrow().is_empty());
    }

    #[test]
    fn vtd_translation_that_stays_on_times_out_with_its_feature() {
        let mut fake = Fake::new(Kind::Vtd, &[(GSTS, u64::from(TRANSLATION))]);
        fake.stuck = u64::from(TRANSLATION);
        assert_eq!(
            // SAFETY: the fake window stands in for the unit, and this test is its only owner.
            unsafe { release(Kind::Vtd, &fake) },
            Err(Failure::Timeout("DMA translation"))
        );
    }

    #[test]
    fn amd_vi_turns_off_engines_before_translation() {
        let control = IOMMU_ENABLE | COMMAND_BUFFER | EVENT_LOG | (1 << 10);
        let fake = Fake::new(Kind::AmdVi, &[(CONTROL, control), (STATUS, 1 << 4)]);
        // SAFETY: the fake window stands in for the unit, and this test is its only owner.
        let found = unsafe { release(Kind::AmdVi, &fake) }.unwrap();
        assert_eq!(found, Found::AmdVi { control });
        let writes: Vec<_> = fake
            .writes
            .borrow()
            .iter()
            .map(|&(_, value)| value)
            .collect();
        assert_eq!(
            writes,
            [
                IOMMU_ENABLE | EVENT_LOG | (1 << 10),
                IOMMU_ENABLE | (1 << 10),
                1 << 10
            ]
        );
        assert_eq!(inspect(Kind::AmdVi, &fake), Found::Inactive);
        let idle = Fake::new(Kind::AmdVi, &[(CONTROL, 1 << 10)]);
        // SAFETY: the fake window stands in for the unit, and this test is its only owner.
        assert_eq!(unsafe { release(Kind::AmdVi, &idle) }, Ok(Found::Inactive));
    }
}

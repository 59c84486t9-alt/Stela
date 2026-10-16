//! VMSAv8-64 stage-1 translation for the EL1&0 regime.
//!
//! One software walker serves instruction fetch, shadow-page fills, AT and
//! fault reporting, so every consumer sees the same translation and the same
//! fault. Sources: Arm ARM DDI0487 (June 2026) D8.1–D8.4 (VMSAv8-64 translation,
//! descriptors, permissions, Access flag) and D8.13 (fault prioritization).

/// Translation controls of the EL1&0 regime, as last written by the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Controls {
    pub sctlr: u64,
    pub tcr: u64,
    pub ttbr0: u64,
    pub ttbr1: u64,
    pub mair: u64,
}

pub const SCTLR_M: u64 = 1 << 0;
pub const SCTLR_WXN: u64 = 1 << 19;
pub const SCTLR_SPAN: u64 = 1 << 23;

const TCR_EPD0: u64 = 1 << 7;
const TCR_EPD1: u64 = 1 << 23;
const TCR_A1: u64 = 1 << 22;
const TCR_AS: u64 = 1 << 36;
const TCR_TBI0: u64 = 1 << 37;
const TCR_TBI1: u64 = 1 << 38;
const TCR_HA: u64 = 1 << 39;
const TCR_HD: u64 = 1 << 40;
const TCR_HPD0: u64 = 1 << 41;
const TCR_HPD1: u64 = 1 << 42;
const TCR_TBID0: u64 = 1 << 51;
const TCR_TBID1: u64 = 1 << 52;

const DESCRIPTOR_VALID: u64 = 1;
const DESCRIPTOR_TABLE: u64 = 2;
const AP_EL0: u64 = 1 << 6;
const AP_READ_ONLY: u64 = 1 << 7;
const ACCESS_FLAG: u64 = 1 << 10;
const NOT_GLOBAL: u64 = 1 << 11;
const DIRTY_BIT_MODIFIER: u64 = 1 << 51;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;
const PXN_TABLE: u64 = 1 << 59;
const UXN_TABLE: u64 = 1 << 60;
const AP_TABLE_NO_EL0: u64 = 1 << 61;
const AP_TABLE_READ_ONLY: u64 = 1 << 62;
/// Output address bits [47:12] of a 48-bit descriptor.
const OUTPUT_ADDRESS: u64 = 0x0000_ffff_ffff_f000;
/// The largest physical address this profile implements (48 bits).
pub const PHYSICAL_ADDRESS_BITS: u32 = 48;

/// The kind of access being translated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Execute,
}

/// Who is accessing: the current EL and whether PSTATE.PAN applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Requester {
    pub el: u8,
    pub pan: bool,
    /// LDTR/STTR and AT S1E0*: an EL1 access checked with EL0 permissions.
    pub unprivileged: bool,
}

/// The architectural fault, with the level it was found at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    AddressSize,
    Translation,
    AccessFlag,
    Permission,
    /// The walk read a descriptor outside RAM.
    ExternalOnWalk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault {
    pub kind: FaultKind,
    pub level: i8,
}

impl Fault {
    /// The DFSC/IFSC encoding (levels 0–3; ESR ISS[5:0]).
    pub fn status_code(self) -> u32 {
        let level = (self.level.clamp(0, 3)) as u32;
        match self.kind {
            FaultKind::AddressSize => level,
            FaultKind::Translation => 0b00_0100 | level,
            FaultKind::AccessFlag => 0b00_1000 | level,
            FaultKind::Permission => 0b00_1100 | level,
            FaultKind::ExternalOnWalk => 0b01_0100 | level,
        }
    }
}

/// Memory type from MAIR, reduced to what the engine distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    Device,
    Normal,
}

/// A completed translation of one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Translation {
    pub physical: u64,
    pub memory: MemoryType,
    /// Permissions at the requesting EL after PAN, for the whole page.
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub global: bool,
    pub asid: u16,
    /// Bytes mapped by the descriptor (page or block size).
    pub size: u64,
}

/// Physical memory the walker reads descriptors from and, for hardware
/// Access-flag and dirty-state updates, writes them back to.
pub trait TableMemory {
    fn read_descriptor(&mut self, physical: u64) -> Option<u64>;
    /// Replace `old` with `new` only if the descriptor still holds `old`.
    fn update_descriptor(&mut self, physical: u64, old: u64, new: u64) -> Option<bool>;
}

/// Refusals that are limits of this implementation, not guest faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    /// TG0/TG1 select a granule this walker does not implement.
    Granule { bits: u32 },
    /// TnSZ outside 16..=39 (no LVA/LPA2 or ST support).
    RegionSize { tnsz: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Mapped(Translation),
    Fault(Fault),
    Unsupported(Unsupported),
}

struct Range {
    ttbr: u64,
    tnsz: u32,
    granule_bits: u32,
    disabled: bool,
    hierarchical: bool,
}

/// Whether top-byte-ignore applies to this access in this half.
fn top_byte_ignored(tcr: u64, upper: bool, access: Access) -> bool {
    let (tbi, tbid) = if upper {
        (TCR_TBI1, TCR_TBID1)
    } else {
        (TCR_TBI0, TCR_TBID0)
    };
    tcr & tbi != 0 && !(access == Access::Execute && tcr & tbid != 0)
}

fn range(controls: &Controls, upper: bool) -> Result<Range, Unsupported> {
    let tcr = controls.tcr;
    let (tnsz, granule, ttbr, disabled, hierarchical) = if upper {
        let granule = match (tcr >> 30) & 3 {
            1 => 14,
            2 => 12,
            3 => 16,
            _ => 12,
        };
        (
            ((tcr >> 16) & 63) as u32,
            granule,
            controls.ttbr1,
            tcr & TCR_EPD1 != 0,
            tcr & TCR_HPD1 == 0,
        )
    } else {
        let granule = match (tcr >> 14) & 3 {
            0 => 12,
            1 => 16,
            2 => 14,
            _ => 12,
        };
        (
            (tcr & 63) as u32,
            granule,
            controls.ttbr0,
            tcr & TCR_EPD0 != 0,
            tcr & TCR_HPD0 == 0,
        )
    };
    if granule == 16 {
        return Err(Unsupported::Granule { bits: granule });
    }
    if !(16..=39).contains(&tnsz) {
        return Err(Unsupported::RegionSize { tnsz });
    }
    Ok(Range {
        ttbr,
        tnsz,
        granule_bits: granule,
        disabled,
        hierarchical,
    })
}

fn memory_type(mair: u64, descriptor: u64) -> MemoryType {
    let index = (descriptor >> 2) & 7;
    let attribute = (mair >> (index * 8)) & 0xff;
    if attribute & 0xf0 == 0 {
        MemoryType::Device
    } else {
        MemoryType::Normal
    }
}

/// The ASID that tags non-global entries of this regime.
pub fn current_asid(controls: &Controls) -> u16 {
    let ttbr = if controls.tcr & TCR_A1 != 0 {
        controls.ttbr1
    } else {
        controls.ttbr0
    };
    let asid = (ttbr >> 48) as u16;
    if controls.tcr & TCR_AS != 0 {
        asid
    } else {
        asid & 0xff
    }
}

/// Translate `address` for `access` by `requester`.
pub fn translate(
    controls: &Controls,
    address: u64,
    access: Access,
    requester: Requester,
    memory: &mut dyn TableMemory,
) -> Outcome {
    if controls.sctlr & SCTLR_M == 0 {
        // MMU off: flat, Device for data and Normal for instruction fetch.
        if address >> PHYSICAL_ADDRESS_BITS != 0 {
            return Outcome::Fault(Fault {
                kind: FaultKind::AddressSize,
                level: 0,
            });
        }
        return Outcome::Mapped(Translation {
            physical: address,
            memory: if access == Access::Execute {
                MemoryType::Normal
            } else {
                MemoryType::Device
            },
            readable: true,
            writable: true,
            executable: true,
            global: true,
            asid: 0,
            size: 1 << 12,
        });
    }
    let upper = address & (1 << 55) != 0;
    let range = match range(controls, upper) {
        Ok(range) => range,
        Err(unsupported) => return Outcome::Unsupported(unsupported),
    };
    let level0_translation = Fault {
        kind: FaultKind::Translation,
        level: 0,
    };
    // Every bit above the region must equal bit 55; with TBI the top byte is
    // excluded from that check.
    let va_bits = 64 - range.tnsz;
    let checked_top = if top_byte_ignored(controls.tcr, upper, access) {
        56
    } else {
        64
    };
    let extension = (address >> va_bits) & ((1u64 << (checked_top - va_bits)) - 1);
    let expected = if upper {
        (1u64 << (checked_top - va_bits)) - 1
    } else {
        0
    };
    if extension != expected || range.disabled {
        return Outcome::Fault(level0_translation);
    }
    let granule = range.granule_bits;
    let stride = granule - 3;
    let levels = (va_bits - granule).div_ceil(stride);
    let mut level = 4 - levels as i8;
    // BADDR[47:1]; a start-level table smaller than a granule is aligned to
    // its own size, so no granule alignment is imposed here.
    let mut table = range.ttbr & 0x0000_ffff_ffff_fffe;
    // Hierarchical permission limits collected from table descriptors.
    let (mut no_el0, mut read_only, mut pxn_table, mut uxn_table) = (false, false, false, false);
    loop {
        let shift = granule + stride * (3 - level) as u32;
        let index_bits = if level == 4 - levels as i8 {
            va_bits - shift
        } else {
            stride
        };
        let index = (address >> shift) & ((1u64 << index_bits) - 1);
        let descriptor_address = table + index * 8;
        let Some(descriptor) = memory.read_descriptor(descriptor_address) else {
            return Outcome::Fault(Fault {
                kind: FaultKind::ExternalOnWalk,
                level,
            });
        };
        if descriptor & DESCRIPTOR_VALID == 0 {
            return Outcome::Fault(Fault {
                kind: FaultKind::Translation,
                level,
            });
        }
        let is_table = descriptor & DESCRIPTOR_TABLE != 0;
        if level < 3 && is_table {
            if range.hierarchical {
                no_el0 |= descriptor & AP_TABLE_NO_EL0 != 0;
                read_only |= descriptor & AP_TABLE_READ_ONLY != 0;
                pxn_table |= descriptor & PXN_TABLE != 0;
                uxn_table |= descriptor & UXN_TABLE != 0;
            }
            table = descriptor & OUTPUT_ADDRESS & !((1u64 << granule) - 1);
            level += 1;
            continue;
        }
        // Blocks: 4 KiB at levels 1–2, 16 KiB at level 2; level 3 must be a page.
        let block_allowed = match granule {
            12 => level == 1 || level == 2,
            _ => level == 2,
        };
        if level < 3 && !block_allowed || level == 3 && !is_table {
            return Outcome::Fault(Fault {
                kind: FaultKind::Translation,
                level,
            });
        }
        let size = 1u64 << shift;
        return leaf(
            controls,
            address,
            access,
            requester,
            memory,
            Leaf {
                descriptor,
                descriptor_address,
                level,
                size,
                no_el0,
                read_only,
                pxn_table,
                uxn_table,
            },
        );
    }
}

struct Leaf {
    descriptor: u64,
    descriptor_address: u64,
    level: i8,
    size: u64,
    no_el0: bool,
    read_only: bool,
    pxn_table: bool,
    uxn_table: bool,
}

fn leaf(
    controls: &Controls,
    address: u64,
    access: Access,
    requester: Requester,
    memory: &mut dyn TableMemory,
    leaf: Leaf,
) -> Outcome {
    let level = leaf.level;
    let mut descriptor = leaf.descriptor;
    let output = descriptor & OUTPUT_ADDRESS & !(leaf.size - 1);
    if output >> PHYSICAL_ADDRESS_BITS != 0 {
        return Outcome::Fault(Fault {
            kind: FaultKind::AddressSize,
            level,
        });
    }
    let fault = |kind| Outcome::Fault(Fault { kind, level });
    if descriptor & ACCESS_FLAG == 0 {
        if controls.tcr & TCR_HA == 0 {
            return fault(FaultKind::AccessFlag);
        }
        match memory.update_descriptor(
            leaf.descriptor_address,
            descriptor,
            descriptor | ACCESS_FLAG,
        ) {
            Some(true) => descriptor |= ACCESS_FLAG,
            // A concurrent change: walk again from the guest's new tables.
            Some(false) => return translate(controls, address, access, requester, memory),
            None => return fault(FaultKind::ExternalOnWalk),
        }
    }
    let el0_access = descriptor & AP_EL0 != 0 && !leaf.no_el0;
    let read_only = descriptor & AP_READ_ONLY != 0 || leaf.read_only;
    let el0_writable = el0_access && !read_only;
    let as_el0 = requester.el == 0 || requester.unprivileged;
    let pan_blocks = requester.el == 1 && requester.pan && !requester.unprivileged && el0_access;
    let (mut readable, mut writable) = if as_el0 {
        (el0_access, el0_writable)
    } else {
        (!pan_blocks, !pan_blocks && !read_only)
    };
    let executable = if requester.el == 0 {
        descriptor & UXN == 0 && !leaf.uxn_table && el0_access
    } else {
        descriptor & PXN == 0 && !leaf.pxn_table && !el0_writable
    } && !(controls.sctlr & SCTLR_WXN != 0 && writable);
    // Hardware dirty state: a writable-clean DBM page becomes dirty on write.
    if access == Access::Write
        && !writable
        && descriptor & AP_READ_ONLY != 0
        && !leaf.read_only
        && descriptor & DIRTY_BIT_MODIFIER != 0
        && controls.tcr & TCR_HD != 0
        && (if as_el0 { el0_access } else { !pan_blocks })
    {
        match memory.update_descriptor(
            leaf.descriptor_address,
            descriptor,
            descriptor & !AP_READ_ONLY,
        ) {
            Some(true) => {
                writable = true;
                readable = true;
            }
            Some(false) => return translate(controls, address, access, requester, memory),
            None => return fault(FaultKind::ExternalOnWalk),
        }
    }
    let permitted = match access {
        Access::Read => readable,
        Access::Write => writable,
        Access::Execute => executable,
    };
    if !permitted {
        return fault(FaultKind::Permission);
    }
    let global = descriptor & NOT_GLOBAL == 0;
    Outcome::Mapped(Translation {
        physical: output | (address & (leaf.size - 1) & ((1u64 << 48) - 1)),
        memory: memory_type(controls.mair, descriptor),
        readable,
        writable,
        executable,
        global,
        asid: if global { 0 } else { current_asid(controls) },
        size: leaf.size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    #[derive(Default)]
    struct Tables(BTreeMap<u64, u64>);

    impl TableMemory for Tables {
        fn read_descriptor(&mut self, physical: u64) -> Option<u64> {
            (physical < 0x1_0000_0000).then(|| self.0.get(&physical).copied().unwrap_or(0))
        }
        fn update_descriptor(&mut self, physical: u64, old: u64, new: u64) -> Option<bool> {
            let slot = self.0.entry(physical).or_insert(0);
            if *slot != old {
                return Some(false);
            }
            *slot = new;
            Some(true)
        }
    }

    const KERNEL: Requester = Requester {
        el: 1,
        pan: false,
        unprivileged: false,
    };
    const USER: Requester = Requester {
        el: 0,
        pan: false,
        unprivileged: false,
    };
    // 16 KiB granules for both halves, 47-bit low and 36-bit high regions.
    const TCR: u64 = (2 << 14) | 17 | (1 << 30) | (28 << 16) | TCR_TBI0;
    const PAGE: u64 = 1 << 14;
    const ATTRS: u64 = DESCRIPTOR_VALID | DESCRIPTOR_TABLE | ACCESS_FLAG | (1 << 2);

    fn controls() -> Controls {
        Controls {
            sctlr: SCTLR_M,
            tcr: TCR,
            ttbr0: 0x10_0000 | (5 << 48),
            ttbr1: 0x20_0000,
            mair: 0xff00, // index 0 Device-nGnRnE, index 1 Normal WB
        }
    }

    /// Map `va` to `pa` at level 3 of a 16 KiB, 47-bit low-half walk (levels
    /// 1–3) or a 36-bit high-half walk (levels 2–3).
    fn map(tables: &mut Tables, controls: &Controls, va: u64, pa: u64, leaf: u64) {
        let upper = va & (1 << 55) != 0;
        let (root, levels): (u64, &[u32]) = if upper {
            (controls.ttbr1 & OUTPUT_ADDRESS, &[25])
        } else {
            (controls.ttbr0 & OUTPUT_ADDRESS, &[36, 25])
        };
        let mut table = root;
        for (depth, shift) in levels.iter().enumerate() {
            let index = (va >> shift) & 0x7ff;
            let slot = table + index * 8;
            let next = 0x100_0000 + (u64::from(upper as u8) << 20) + depth as u64 * PAGE;
            tables
                .0
                .entry(slot)
                .or_insert(next | DESCRIPTOR_VALID | DESCRIPTOR_TABLE);
            table = tables.0[&slot] & OUTPUT_ADDRESS;
        }
        let index = (va >> 14) & 0x7ff;
        tables.0.insert(table + index * 8, pa | leaf);
    }

    #[test]
    fn walks_16k_tables_in_both_halves_with_permissions_and_types() {
        let controls = controls();
        let mut tables = Tables::default();
        let kernel_va = 0xffff_fff0_0000_4000_u64;
        let user_va = 0x1_0000_8000_u64;
        map(
            &mut tables,
            &controls,
            kernel_va,
            0x8_0000_4000,
            ATTRS | UXN,
        );
        map(
            &mut tables,
            &controls,
            user_va,
            0x8_0010_0000,
            DESCRIPTOR_VALID | DESCRIPTOR_TABLE | ACCESS_FLAG | AP_EL0 | PXN | NOT_GLOBAL,
        );
        let Outcome::Mapped(kernel) = translate(
            &controls,
            kernel_va + 0x123,
            Access::Execute,
            KERNEL,
            &mut tables,
        ) else {
            panic!("kernel text")
        };
        assert_eq!(kernel.physical, 0x8_0000_4123);
        assert_eq!(kernel.memory, MemoryType::Normal);
        assert!(kernel.global && kernel.writable && kernel.size == PAGE);
        assert_eq!(
            translate(&controls, kernel_va, Access::Read, USER, &mut tables),
            Outcome::Fault(Fault {
                kind: FaultKind::Permission,
                level: 3
            })
        );
        // User data: Device type, EL0 writable, never EL1-executable, tagged ASID.
        let Outcome::Mapped(user) =
            translate(&controls, user_va + 8, Access::Write, USER, &mut tables)
        else {
            panic!("user data")
        };
        assert_eq!(user.physical, 0x8_0010_0008);
        assert_eq!(
            (user.memory, user.global, user.asid),
            (MemoryType::Device, false, 5)
        );
        assert!(user.executable, "EL0 may execute its own writable page");
        assert!(matches!(
            translate(&controls, user_va, Access::Execute, KERNEL, &mut tables),
            Outcome::Fault(Fault {
                kind: FaultKind::Permission,
                ..
            })
        ));
        // PAN blocks EL1 data access to EL0 pages but not unprivileged access.
        let pan = Requester {
            pan: true,
            ..KERNEL
        };
        assert!(matches!(
            translate(&controls, user_va, Access::Read, pan, &mut tables),
            Outcome::Fault(Fault {
                kind: FaultKind::Permission,
                ..
            })
        ));
        let unprivileged = Requester {
            unprivileged: true,
            ..pan
        };
        assert!(matches!(
            translate(&controls, user_va, Access::Write, unprivileged, &mut tables),
            Outcome::Mapped(_)
        ));
        // TBI0 ignores the top byte of low-half data, never of TTBR1 addresses.
        assert!(matches!(
            translate(
                &controls,
                user_va | (0x5a << 56),
                Access::Read,
                USER,
                &mut tables
            ),
            Outcome::Mapped(_)
        ));
        assert_eq!(
            translate(
                &controls,
                kernel_va & !(1 << 60),
                Access::Read,
                KERNEL,
                &mut tables
            ),
            Outcome::Fault(Fault {
                kind: FaultKind::Translation,
                level: 0
            })
        );
    }

    #[test]
    fn reports_translation_access_flag_and_address_size_faults() {
        let mut controls = controls();
        let mut tables = Tables::default();
        let va = 0x2_0000_0000_u64;
        assert_eq!(
            translate(&controls, va, Access::Read, KERNEL, &mut tables),
            Outcome::Fault(Fault {
                kind: FaultKind::Translation,
                level: 1
            })
        );
        map(
            &mut tables,
            &controls,
            va,
            0x8_0000_0000,
            DESCRIPTOR_VALID | DESCRIPTOR_TABLE,
        );
        let access_flag = Outcome::Fault(Fault {
            kind: FaultKind::AccessFlag,
            level: 3,
        });
        assert_eq!(
            access_flag,
            translate(&controls, va, Access::Read, KERNEL, &mut tables)
        );
        assert_eq!(
            Fault {
                kind: FaultKind::AccessFlag,
                level: 3
            }
            .status_code(),
            0b00_1011
        );
        // Hardware Access-flag update sets AF in the guest descriptor.
        controls.tcr |= TCR_HA;
        assert!(matches!(
            translate(&controls, va, Access::Read, KERNEL, &mut tables),
            Outcome::Mapped(_)
        ));
        let leaf = tables
            .0
            .values()
            .any(|&d| d == 0x8_0000_0000 | 3 | ACCESS_FLAG);
        assert!(leaf);
        // Bits above the 47-bit region fault at level 0; EPD0 does too.
        assert_eq!(
            translate(&controls, 1 << 47, Access::Read, KERNEL, &mut tables),
            Outcome::Fault(Fault {
                kind: FaultKind::Translation,
                level: 0
            })
        );
        controls.tcr |= TCR_EPD0;
        assert!(matches!(
            translate(&controls, va, Access::Read, KERNEL, &mut tables),
            Outcome::Fault(Fault { level: 0, .. })
        ));
        // MMU off is flat up to 48 bits.
        controls.sctlr = 0;
        assert!(matches!(
            translate(&controls, 1 << 48, Access::Read, KERNEL, &mut tables),
            Outcome::Fault(Fault {
                kind: FaultKind::AddressSize,
                ..
            })
        ));
    }

    #[test]
    fn hardware_dirty_state_and_unsupported_granules() {
        let mut controls = controls();
        controls.tcr |= TCR_HD;
        let mut tables = Tables::default();
        let va = 0x3_0000_0000_u64;
        map(
            &mut tables,
            &controls,
            va,
            0x8_0002_0000,
            ATTRS | AP_READ_ONLY | DIRTY_BIT_MODIFIER,
        );
        assert!(matches!(
            translate(&controls, va, Access::Write, KERNEL, &mut tables),
            Outcome::Mapped(Translation { writable: true, .. })
        ));
        controls.tcr = (controls.tcr & !(3 << 14)) | (1 << 14);
        assert_eq!(
            translate(&controls, va, Access::Read, KERNEL, &mut tables),
            Outcome::Unsupported(Unsupported::Granule { bits: 16 })
        );
    }
}

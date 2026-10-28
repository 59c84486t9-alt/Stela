//! Apple's core CTRR registers: physical regions the cores protect after
//! translation. Two generations exist ([`generation`]).
//!
//! # M1 to M3: the A group
//!
//! One register group for EL1 and one for EL2, shared by the PEs of a
//! cluster. Public XNU `xnu-6153.141.1` names them
//! (`pexpert/pexpert/arm64/arm64_common.h:194-226`, `HAS_CTRR`):
//! `ARM64_REG_CTRR_A_LWR_EL1` `S3_4_C15_C2_3`, `_A_UPR_EL1` `C2_4`,
//! `_CTL_EL1` `C2_5`, `_LOCK_EL1` `C2_2`, and the per-cluster
//! `ACC_CTRR_A_LWR_EL2`, `_A_UPR_EL2`, `_CTL_EL2` and `_LOCK_EL2` at
//! `S3_4_C15_C11_0`, `C11_1`, `C11_4` and `C11_5`, which "can only be
//! written in EL2". Its control bits are `A_MMUOFF_WRPROTECT` (0),
//! `A_MMUON_WRPROTECT` (1), `B_MMUOFF_WRPROTECT` (2), `B_MMUON_WRPROTECT`
//! (3), `A_PXN` (4), `B_PXN` (5), `A_UXN` (6) and `B_UXN` (7). Its lockdown
//! (`osfmk/arm64/machine_routines.c:491-516`) writes LWR and UPR, invalidates
//! the TLB, sets `A_PXN | A_MMUON_WRPROTECT` and writes 1 to LOCK, then
//! repeats that on the `ACC_` group at EL2; public XNU `arm_init_sptm.c`
//! locks CTRR once per cluster (`ctrr_cluster_locked`). SPTM 26A434 (T8112)
//! does the same in `ctrr_lock_boot` and the function it calls
//! (`__text+0x1c6c8`), on each cluster's first PE:
//!
//! - it reads CTL and stops if bit 1 is set ("CTRR-A already enabled!"),
//!   and skips the cluster when LOCK reads non-zero;
//! - it writes the first byte of the region to LWR and its last byte to UPR,
//!   both physical addresses that the AMCC's CTRR-A limits give, ORs 0x13
//!   (both write protections and `A_PXN`) into CTL and writes 1 to LOCK;
//! - at EL2 it repeats that on the `ACC_` group.
//!
//! Registers reset to 0 (inference: SPTM requires an unlocked, disabled
//! group at boot). The model has region A only: `A_PXN` is taken to forbid
//! privileged execution outside the region (the KTRR behavior CTRR
//! succeeds, Siguza "KTRR"; inference), and the B and UXN bits, which no
//! component sets, refuse. A forbidden store or privileged fetch takes a
//! level-3 Permission fault, as XNU xnu-12377.121.6 `platform_tests.c`'s
//! `ctrr_test_ro_fault_handler` and `ctrr_test_nx_fault_handler` require.
//! Changes to the configuration after its lock still refuse.
//!
//! # M4 and later: CTRR-C/D and CTXR-A..D (XNU `HAS_CTRR3`)
//!
//! Public XNU `xnu-12377.121.6` gives the H16 (M4) and H17 (M5) platforms
//! `HAS_CTRR3`, "CTRRv3 registers" (`pexpert/arm64/H16.h`, `H17.h`,
//! `apple_arm64_common.h`: `KERNEL_CTRR_VERSION 3`). The 26A434 census
//! shows CRn-11 accesses only in the T8132,
//! T6040/1, T8140, T8142, T6050 and T8152 SPTMs and kernels. m1n1
//! `src/cpu_regs.h` (7cde7d1a, "M4 CTRR/CTXR registers") names the EL1, EL12
//! and per-cluster `ACC_*_EL2` copies of six regions ([`LockRegion`]) and the
//! EL2 limits of CTRR-C/D; the EL2 controls and CTXR limits follow the same
//! VHE layout (Binary Ninja's `sysregs_gen.h` names, as qemu-sptm's
//! `scripts/darwin/sysregs.py` lists them; inference for the encodings no
//! censused component uses).
//!
//! SPTM 26A434 (T8132 link addresses; T8142 and T8152 match):
//!
//! - It derives the six regions from `/chosen/memory-map` (`0x...bebec..
//!   0x...bed5c`): CTRR-C from `CL4-rx` (`DeviceTree` when absent) to the
//!   end of `SPTM-rx`, CTRR-D from `TXM-ro` to the end of `BootKC-rs`,
//!   CTXR-A `SPTM-rx`, CTXR-B `CL4-rx` (else `CL4-dummypage`), CTXR-C
//!   `TXM-rx` to `TXM-bx`, CTXR-D `AuxKC-rx` (else `BootKC-rx`) to
//!   `BootKC-bx`.
//! - It writes them through the EL1 names (`0x...c6f20`) and programs the
//!   CTXR controls 0x4000000000000000, then 0x4000000000aa019a-style words,
//!   then the same with bit 63 (`0x...c7174`). `ctrr_lock_sptm` (`0x...c7234`)
//!   panics "CTRR-C already locked!" when CTRR-C's control has bit 63 on the
//!   boot CPU, then writes 1 and 0x8000000000000001; CTRR-D follows unless
//!   `/chosen kernel-ctrr-to-be-enabled` is 0 (`0x...bdb68`).
//! - `ctXr_check_all_regions` (`0x...bf3e0`) requires the per-cluster copies
//!   iBoot locked: controls 0x8000000000000001 for CTRR-C/D and
//!   [`CTXR_HANDOFF`] for CTXR-A..D, limits equal to the derived regions
//!   with the upper limit's bits 11:0 clear, and CTRR-A/B's per-core and
//!   per-cluster controls 0x8000000000000001 ("CTRR-A per-core register not
//!   locked by iBoot"). On a secondary CPU it also checks the per-core
//!   copies it wrote.
//!
//! M5 iBoot (`iBoot.j813`, decoded SHA-256 `db365eda...`) writes the per-core
//! and per-cluster copies together (`0x31588`, `0x31658`, `0x316e0`), CTRR-B's
//! limits at `S3_4_C15_C1_7`, `C1_6` and `S3_4_C15_C11_2`, `C11_3`, and locks
//! a CTRR group with 0x8000000000000001 (`0x317b0`): on these chips
//! `S3_4_C15_C2_2` and `C11_5` are CTRR-B's controls, not locks. SPTM runs with
//! HCR_EL2.E2H set and never accesses the EL2 names, yet the kernel reads
//! CTRR-D's EL2 limits (`S3_0_C11_C1_2`, `C1_3`; T8132 kernel
//! `0xfffffe000be12020`) as its read-only region: SPTM's EL1-name writes at
//! EL2 reach the EL2 copy, as Arm's VHE redirection does ([`View::holder`];
//! inference). The kernel saves and restores the `*_EL12` copies around
//! guests.
//!
//! The limit registers drop bits 11:0 (m1n1 `src/hv/hv_sprr.c`: "SPTM writes
//! the end address, then reads it back and checks if the lower bits are
//! cleared"); a region covers `[lower, upper | 0xfff]`. A control's bit 63
//! locks its region; CTRR's bit 0 enables it, taken as write protection with
//! the MMU on or off (inference: XNU `platform_tests.c` expects a
//! permission fault on a write into the read-only region). CTXR's bit 62 and
//! its 2-bit fields (bits 23:0) choose which contexts may execute in the
//! region; their meaning is undocumented, so a CTXR enable completes and is
//! reported as unmodeled. The per-cluster copies take no effect here: their
//! enforcement is undocumented, and SPTM programs identical per-core ones.
//! CTRR-A/B on these chips are iBoot-locked handoff values whose limits no
//! component reads (m1n1 `src/kboot.c` reports a small CTRR-C region left
//! enabled on secondary cores at power-on, not modeled).
use super::Chip;
use super::mmu;
use super::registers::encodings::Encoding;
pub use crate::boot_bundle::schema::{CoreLocks, LockRegion, Locked};

const fn sys(op1: u8, crn: u8, crm: u8, op2: u8) -> Encoding {
    Encoding::new(3, op1, crn, crm, op2)
}

/// The register set a chip implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Generation {
    /// M1 to M3: the A group, at EL1 and per cluster at EL2.
    A,
    /// M4 and later: CTRR-C/D and CTXR-A..D per core and per cluster.
    Ctrr3,
}

pub const fn generation(chip: Chip) -> Generation {
    match chip {
        Chip::AppleM1 | Chip::AppleM2 | Chip::AppleM3 => Generation::A,
        Chip::AppleM4 | Chip::AppleM5 | Chip::AppleM6 => Generation::Ctrr3,
    }
}

const LOCK_EL1: Encoding = sys(4, 15, 2, 2);
const LOWER_EL1: Encoding = sys(4, 15, 2, 3);
const UPPER_EL1: Encoding = sys(4, 15, 2, 4);
const CONTROL_EL1: Encoding = sys(4, 15, 2, 5);
const LOWER_EL2: Encoding = sys(4, 15, 11, 0);
const UPPER_EL2: Encoding = sys(4, 15, 11, 1);
const CONTROL_EL2: Encoding = sys(4, 15, 11, 4);
const LOCK_EL2: Encoding = sys(4, 15, 11, 5);

/// CTL bits SPTM sets: XNU's `CTRR_CTL_EL1_A_MMUOFF_WRPROTECT`,
/// `A_MMUON_WRPROTECT` and `A_PXN`.
pub const WRITE_PROTECT_MMU_OFF: u64 = 1 << 0;
pub const WRITE_PROTECT_MMU_ON: u64 = 1 << 1;
pub const EXECUTE_INSIDE_ONLY: u64 = 1 << 4;
const CONTROL_BITS: u64 = WRITE_PROTECT_MMU_OFF | WRITE_PROTECT_MMU_ON | EXECUTE_INSIDE_ONLY;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Lower,
    Upper,
    Control,
    Lock,
}

/// What an encoding names on a chip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    /// M1 to M3: a level's field, 0 for EL1 and 1 for EL2.
    A { level: usize, field: Field },
    /// M4 and later: a region's lower limit, upper limit or control in one
    /// copy.
    Region {
        view: View,
        region: LockRegion,
        field: Field,
    },
    /// M4 and later: CTRR-A's (0) or CTRR-B's (1) control, per core or per
    /// cluster.
    Legacy { cluster: bool, index: usize },
}

/// The register an encoding names on `chip`.
pub fn decode(chip: Chip, encoding: Encoding) -> Option<Register> {
    match generation(chip) {
        Generation::A => {
            let (level, field) = match encoding {
                LOWER_EL1 => (0, Field::Lower),
                UPPER_EL1 => (0, Field::Upper),
                CONTROL_EL1 => (0, Field::Control),
                LOCK_EL1 => (0, Field::Lock),
                LOWER_EL2 => (1, Field::Lower),
                UPPER_EL2 => (1, Field::Upper),
                CONTROL_EL2 => (1, Field::Control),
                LOCK_EL2 => (1, Field::Lock),
                _ => return None,
            };
            Some(Register::A { level, field })
        }
        Generation::Ctrr3 => {
            let legacy = |cluster, index| Some(Register::Legacy { cluster, index });
            match encoding {
                CONTROL_EL1 => return legacy(false, 0),
                LOCK_EL1 => return legacy(false, 1),
                CONTROL_EL2 => return legacy(true, 0),
                LOCK_EL2 => return legacy(true, 1),
                _ => {}
            }
            VIEWS.iter().find_map(|&(view, table)| {
                table.iter().zip(REGIONS).find_map(|(row, region)| {
                    let field = [Field::Lower, Field::Upper, Field::Control]
                        [row.iter().position(|&e| e == encoding)?];
                    Some(Register::Region {
                        view,
                        region,
                        field,
                    })
                })
            })
        }
    }
}

/// Whether `encoding` is one of the M1 to M3 EL1 group's (`S3_4_C15_C2_2`
/// to `C2_5`), which HACR_EL2 bit 14 traps on every chip.
pub fn in_el1_range(encoding: Encoding) -> bool {
    matches!(encoding, LOCK_EL1 | LOWER_EL1 | UPPER_EL1 | CONTROL_EL1)
}

/// One level's registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Group {
    pub lower: u64,
    pub upper: u64,
    pub control: u64,
    pub locked: bool,
}

impl Group {
    fn get(&self, field: Field) -> u64 {
        match field {
            Field::Lower => self.lower,
            Field::Upper => self.upper,
            Field::Control => self.control,
            Field::Lock => u64::from(self.locked),
        }
    }

    /// The protection this group applies to its level, with the MMU on or
    /// off.
    pub fn region(&self, mmu_on: bool) -> Option<mmu::CtrrRegion> {
        let write = if mmu_on {
            WRITE_PROTECT_MMU_ON
        } else {
            WRITE_PROTECT_MMU_OFF
        };
        let region = mmu::CtrrRegion {
            first: self.lower,
            last: self.upper,
            write_protect: self.control & write != 0,
            execute_inside_only: self.control & EXECUTE_INSIDE_ONLY != 0,
        };
        (region.write_protect || region.execute_inside_only).then_some(region)
    }
}

/// A cluster's CTRR registers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cluster {
    /// M1 to M3: the EL1 and EL2 groups.
    pub levels: [Group; 2],
    /// M4 and later: the per-cluster `ACC_*_EL2` copies.
    pub copies: Bank,
}

impl Cluster {
    /// The registers iBoot leaves in a cluster.
    pub fn handed_off(handoff: &CoreLocks) -> Self {
        let mut copies = Bank::default();
        for locked in &handoff.locked {
            copies.windows[locked.region as usize] = Window {
                lower: locked.first & LIMIT_MASK,
                upper: locked.last & LIMIT_MASK,
                control: handoff_control(locked.region),
            };
        }
        if handoff.legacy_locked {
            copies.legacy = [LEGACY_HANDOFF; 2];
        }
        Self {
            levels: Default::default(),
            copies,
        }
    }

    pub fn read(&self, level: usize, field: Field) -> u64 {
        self.levels[level].get(field)
    }

    /// A write, or why it cannot complete.
    pub fn write(&mut self, level: usize, field: Field, value: u64) -> Result<(), &'static str> {
        let group = &mut self.levels[level];
        if group.locked {
            return if value == group.get(field) {
                Ok(())
            } else {
                Err(CHANGE_AFTER_LOCK)
            };
        }
        match field {
            Field::Lower => group.lower = value,
            Field::Upper => group.upper = value,
            Field::Control if value & !CONTROL_BITS != 0 => {
                return Err("CTRR control bit without observed meaning");
            }
            Field::Control => group.control = value,
            Field::Lock if value > 1 => return Err("CTRR lock value other than 0 or 1"),
            Field::Lock => group.locked = value == 1,
        }
        Ok(())
    }
}

const CHANGE_AFTER_LOCK: &str = "CTRR register change after its lock";

const REGIONS: [LockRegion; 6] = [
    LockRegion::CtrrC,
    LockRegion::CtrrD,
    LockRegion::CtxrA,
    LockRegion::CtxrB,
    LockRegion::CtxrC,
    LockRegion::CtxrD,
];

fn execute_range(region: LockRegion) -> bool {
    !matches!(region, LockRegion::CtrrC | LockRegion::CtrrD)
}

/// The control iBoot locks into `region`'s per-cluster copy and SPTM
/// requires.
pub const fn handoff_control(region: LockRegion) -> u64 {
    match region {
        LockRegion::CtrrC | LockRegion::CtrrD => CTRR_HANDOFF,
        LockRegion::CtxrA => CTXR_HANDOFF[0],
        LockRegion::CtxrB => CTXR_HANDOFF[1],
        LockRegion::CtxrC => CTXR_HANDOFF[2],
        LockRegion::CtxrD => CTXR_HANDOFF[3],
    }
}

/// Which copy of the M4 and later registers an encoding names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    El1,
    El12,
    El2,
    /// The per-cluster `ACC_*_EL2` copy.
    Cluster,
}

/// The copy an access at `el` reaches: with HCR_EL2.E2H RES1 the EL1
/// names reach the EL2 copy at EL2 and the EL12 names the EL1 copy;
/// `None` is UNDEFINED.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holder {
    CoreEl1,
    CoreEl2,
    Cluster,
}

impl View {
    pub fn holder(self, el: u8) -> Option<Holder> {
        Some(match (self, el) {
            (View::El1, 1) | (View::El12, 2) => Holder::CoreEl1,
            (View::El1 | View::El2, 2) => Holder::CoreEl2,
            (View::Cluster, 2) => Holder::Cluster,
            _ => return None,
        })
    }
}

const fn crn11(crm: u8, op2: u8) -> Encoding {
    sys(0, 11, crm, op2)
}

/// Each view's lower, upper and control encodings, in [`REGIONS`] order.
type Table = [[Encoding; 3]; 6];
const VIEWS: [(View, Table); 4] = [
    (
        View::El1,
        [
            [crn11(0, 0), crn11(0, 1), crn11(1, 4)],
            [crn11(0, 2), crn11(0, 3), crn11(1, 5)],
            [crn11(2, 2), crn11(2, 3), crn11(5, 2)],
            [crn11(2, 4), crn11(2, 5), crn11(5, 3)],
            [crn11(2, 6), crn11(2, 7), crn11(5, 4)],
            [crn11(3, 0), crn11(3, 1), crn11(5, 5)],
        ],
    ),
    (
        View::El12,
        [
            [crn11(0, 4), crn11(0, 5), crn11(1, 6)],
            [crn11(0, 6), crn11(0, 7), crn11(1, 7)],
            [crn11(3, 2), crn11(3, 3), crn11(5, 6)],
            [crn11(3, 4), crn11(3, 5), crn11(5, 7)],
            [crn11(3, 6), crn11(3, 7), crn11(6, 0)],
            [crn11(4, 0), crn11(4, 1), crn11(6, 1)],
        ],
    ),
    (
        View::El2,
        [
            [crn11(1, 0), crn11(1, 1), crn11(2, 0)],
            [crn11(1, 2), crn11(1, 3), crn11(2, 1)],
            [crn11(4, 2), crn11(4, 3), crn11(6, 2)],
            [crn11(4, 4), crn11(4, 5), crn11(6, 3)],
            [crn11(4, 6), crn11(4, 7), crn11(6, 4)],
            [crn11(5, 0), crn11(5, 1), crn11(6, 5)],
        ],
    ),
    (
        View::Cluster,
        [
            [crn11(6, 6), crn11(6, 7), crn11(8, 2)],
            [crn11(7, 0), crn11(7, 1), crn11(8, 3)],
            [crn11(7, 2), crn11(7, 3), crn11(8, 4)],
            [crn11(7, 4), crn11(7, 5), crn11(8, 5)],
            [crn11(7, 6), crn11(7, 7), crn11(8, 6)],
            [crn11(8, 0), crn11(8, 1), crn11(8, 7)],
        ],
    ),
];

/// A control's lock (bit 63), CTRR's enable (bit 0), and CTXR's enable
/// (bit 62) and execute-context fields (bits 23:0).
pub const LOCK: u64 = 1 << 63;
pub const CTRR_ENABLE: u64 = 1 << 0;
pub const CTXR_ENABLE: u64 = 1 << 62;
pub const CTXR_FIELDS: u64 = (1 << 24) - 1;
/// The limit registers keep bits 63:12.
const LIMIT_MASK: u64 = !0xfff;
/// What iBoot locks into a CTRR control: locked and enabled.
pub const CTRR_HANDOFF: u64 = LOCK | CTRR_ENABLE;
/// The CTXR-A..D controls SPTM requires in the per-cluster copies and
/// writes into the per-core ones (T8132 `0x...bf710..0x...bf960`, m1n1
/// `src/hv/hv_sprr.c` `sprr_init_cpu`).
pub const CTXR_HANDOFF: [u64; 4] = [
    0xc000_0000_00aa_019a,
    0xc000_0000_009a_02aa,
    0xc000_0000_00aa_026a,
    0xc000_0000_00aa_02a9,
];
/// CTRR-A's and CTRR-B's control as iBoot leaves them on these chips.
const LEGACY_HANDOFF: u64 = LOCK | CTRR_ENABLE;
const CTXR_UNMODELED: &str = "CTXR execute range enabled; which contexts its fields let \
    execute in the region is undocumented, so execution is not restricted";

/// One region's registers in one copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Window {
    pub lower: u64,
    pub upper: u64,
    pub control: u64,
}

/// One copy of the M4 and later registers: the six regions and the
/// CTRR-A/B controls (used by the per-core EL1 and per-cluster copies).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bank {
    pub windows: [Window; 6],
    pub legacy: [u64; 2],
}

impl Bank {
    pub fn read(&self, region: LockRegion, field: Field) -> u64 {
        let window = &self.windows[region as usize];
        match field {
            Field::Lower => window.lower,
            Field::Upper => window.upper,
            _ => window.control,
        }
    }

    /// A write: what it leaves unmodeled, or why it cannot complete.
    pub fn write(
        &mut self,
        region: LockRegion,
        field: Field,
        value: u64,
    ) -> Result<Option<&'static str>, &'static str> {
        let window = &mut self.windows[region as usize];
        let value = match field {
            Field::Lower | Field::Upper => value & LIMIT_MASK,
            _ => value,
        };
        if window.control & LOCK != 0 {
            let current = match field {
                Field::Lower => window.lower,
                Field::Upper => window.upper,
                _ => window.control,
            };
            return if value == current {
                Ok(None)
            } else {
                Err(CHANGE_AFTER_LOCK)
            };
        }
        let mut unmodeled = None;
        match field {
            Field::Lower => window.lower = value,
            Field::Upper => window.upper = value,
            _ => {
                let enable = if execute_range(region) {
                    CTXR_ENABLE | CTXR_FIELDS
                } else {
                    CTRR_ENABLE
                };
                if value & !(LOCK | enable) != 0 {
                    return Err("CTRR control bit without observed meaning");
                }
                if execute_range(region) && value & enable != 0 {
                    unmodeled = Some(CTXR_UNMODELED);
                }
                window.control = value;
            }
        }
        Ok(unmodeled)
    }

    /// CTRR-A's or CTRR-B's control: iBoot's locked handoff value, or what
    /// an unlocked one takes.
    pub fn write_legacy(&mut self, index: usize, value: u64) -> Result<(), &'static str> {
        let control = &mut self.legacy[index];
        if *control & LOCK != 0 {
            return if value == *control {
                Ok(())
            } else {
                Err(CHANGE_AFTER_LOCK)
            };
        }
        if value & !(LOCK | CTRR_ENABLE) != 0 {
            return Err("CTRR control bit without observed meaning");
        }
        *control = value;
        Ok(())
    }

    /// The write protection the enabled CTRR-C and CTRR-D regions apply.
    fn protection(&self) -> [Option<mmu::CtrrRegion>; 2] {
        [LockRegion::CtrrC, LockRegion::CtrrD].map(|region| {
            let window = &self.windows[region as usize];
            (window.control & CTRR_ENABLE != 0).then_some(mmu::CtrrRegion {
                first: window.lower,
                last: window.upper | !LIMIT_MASK,
                write_protect: true,
                execute_inside_only: false,
            })
        })
    }
}

/// A PE's own M4 and later registers: the EL1 copy (with CTRR-A/B's
/// per-core controls) and the EL2 copy. SPTM programs them again on every
/// PE start, so they start from the handoff on each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Core {
    pub el1: Bank,
    pub el2: Bank,
}

impl Core {
    pub fn handed_off(handoff: &CoreLocks) -> Self {
        let mut core = Self::default();
        if handoff.legacy_locked {
            core.el1.legacy = [LEGACY_HANDOFF; 2];
        }
        core
    }

    pub fn bank(&mut self, holder: Holder) -> Option<&mut Bank> {
        match holder {
            Holder::CoreEl1 => Some(&mut self.el1),
            Holder::CoreEl2 => Some(&mut self.el2),
            Holder::Cluster => None,
        }
    }
}

/// The protection the regime of level `el2` (EL2&0 when set, EL1&0 when
/// clear) applies, with the MMU on or off.
pub fn protection(
    chip: Chip,
    cluster: &Cluster,
    core: &Core,
    el2: bool,
    mmu_on: bool,
) -> [Option<mmu::CtrrRegion>; 2] {
    match generation(chip) {
        Generation::A => [cluster.levels[usize::from(el2)].region(mmu_on), None],
        Generation::Ctrr3 if el2 => core.el2.protection(),
        Generation::Ctrr3 => core.el1.protection(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sptms_sequence_programs_and_locks_a_level() {
        let mut cluster = Cluster::default();
        let Some(Register::A { level, field }) = decode(Chip::AppleM2, CONTROL_EL1) else {
            panic!("the M2's EL1 control")
        };
        assert_eq!((level, cluster.read(level, field)), (0, 0));
        cluster.write(0, Field::Lower, 0x8_0200_0000).unwrap();
        cluster.write(0, Field::Upper, 0x8_0778_ffff).unwrap();
        cluster.write(0, Field::Control, 0x13).unwrap();
        assert!(cluster.levels[0].region(true).is_some());
        cluster.write(0, Field::Lock, 1).unwrap();
        assert_eq!(cluster.read(0, Field::Lock), 1);
        // A locked level keeps its values; a repeat completes.
        cluster.write(0, Field::Control, 0x13).unwrap();
        assert!(cluster.write(0, Field::Lower, 0).is_err());
        assert!(cluster.write(0, Field::Lock, 0).is_err());
        let region = cluster.levels[0].region(true).unwrap();
        assert_eq!((region.first, region.last), (0x8_0200_0000, 0x8_0778_ffff));
        assert!(region.write_protect && region.execute_inside_only);
        // EL2's group is separate; unobserved bits stop.
        assert_eq!(
            decode(Chip::AppleM1, LOCK_EL2),
            Some(Register::A {
                level: 1,
                field: Field::Lock
            })
        );
        assert_eq!(cluster.levels[1].region(true), None);
        assert!(cluster.write(1, Field::Control, 1 << 2).is_err());
        assert!(cluster.write(1, Field::Lock, 2).is_err());
        // The M1 to M3 have no CRn-11 registers.
        assert_eq!(decode(Chip::AppleM3, crn11(0, 0)), None);
    }

    #[test]
    fn m4_encodings_name_the_vhe_copies_and_the_iboot_controls() {
        let region = |crm, op2| decode(Chip::AppleM4, crn11(crm, op2));
        let named = |view, region, field| {
            Some(Register::Region {
                view,
                region,
                field,
            })
        };
        assert_eq!(
            region(0, 0),
            named(View::El1, LockRegion::CtrrC, Field::Lower)
        );
        assert_eq!(
            region(1, 3),
            named(View::El2, LockRegion::CtrrD, Field::Upper)
        );
        assert_eq!(
            region(6, 1),
            named(View::El12, LockRegion::CtxrD, Field::Control)
        );
        assert_eq!(
            region(8, 4),
            named(View::Cluster, LockRegion::CtxrA, Field::Control)
        );
        assert_eq!(region(9, 0), None);
        assert_eq!(
            decode(Chip::AppleM6, LOCK_EL1),
            Some(Register::Legacy {
                cluster: false,
                index: 1
            })
        );
        assert_eq!(decode(Chip::AppleM5, LOWER_EL1), None);
        // Every table entry is distinct.
        let mut all: alloc::vec::Vec<_> =
            VIEWS.iter().flat_map(|(_, t)| t.iter().flatten()).collect();
        all.sort_by_key(|e| (e.crm(), e.op2()));
        all.dedup();
        assert_eq!(all.len(), 4 * 6 * 3);
        // The EL1 names reach EL2's copy at EL2; the EL12 and EL2 names are
        // EL2's.
        assert_eq!(View::El1.holder(1), Some(Holder::CoreEl1));
        assert_eq!(View::El1.holder(2), Some(Holder::CoreEl2));
        assert_eq!(View::El12.holder(2), Some(Holder::CoreEl1));
        assert_eq!(View::El12.holder(1), None);
        assert_eq!(View::Cluster.holder(1), None);
    }

    #[test]
    fn sptm_programs_and_locks_the_per_core_copies() {
        let mut core = Core::default();
        let bank = core.bank(Holder::CoreEl2).unwrap();
        // The limits drop bits 11:0, as SPTM's read-back expects.
        bank.write(LockRegion::CtrrC, Field::Lower, 0x100_06fb_8000)
            .unwrap();
        bank.write(LockRegion::CtrrC, Field::Upper, 0x100_0710_bfff)
            .unwrap();
        assert_eq!(bank.read(LockRegion::CtrrC, Field::Upper), 0x100_0710_b000);
        bank.write(LockRegion::CtrrC, Field::Control, CTRR_ENABLE)
            .unwrap();
        bank.write(LockRegion::CtrrC, Field::Control, CTRR_HANDOFF)
            .unwrap();
        assert!(bank.write(LockRegion::CtrrC, Field::Lower, 0).is_err());
        assert_eq!(
            bank.write(LockRegion::CtrrC, Field::Control, CTRR_HANDOFF),
            Ok(None)
        );
        assert!(
            bank.write(LockRegion::CtrrD, Field::Control, 1 << 1)
                .is_err()
        );
        // A CTXR enable completes and is reported.
        assert_eq!(
            bank.write(LockRegion::CtxrA, Field::Control, CTXR_ENABLE),
            Ok(Some(CTXR_UNMODELED))
        );
        assert_eq!(
            bank.write(LockRegion::CtxrA, Field::Control, CTXR_HANDOFF[0]),
            Ok(Some(CTXR_UNMODELED))
        );
        assert!(
            bank.write(LockRegion::CtxrB, Field::Control, 1 << 40)
                .is_err()
        );
        let [c, d] = protection(Chip::AppleM4, &Cluster::default(), &core, true, false);
        let c = c.unwrap();
        assert_eq!((c.first, c.last), (0x100_06fb_8000, 0x100_0710_bfff));
        assert!(c.write_protect && !c.execute_inside_only && d.is_none());
        assert_eq!(
            protection(Chip::AppleM4, &Cluster::default(), &core, false, true),
            [None, None]
        );
    }

    #[test]
    fn the_handoff_locks_the_cluster_copies_and_legacy_controls() {
        let handoff = CoreLocks {
            locked: alloc::vec![Locked {
                region: LockRegion::CtxrB,
                first: 0x100_0945_0000,
                last: 0x100_0945_3fff,
            }],
            legacy_locked: true,
            tag_offset: 0,
        };
        let mut cluster = Cluster::handed_off(&handoff);
        let window = cluster.copies.windows[LockRegion::CtxrB as usize];
        assert_eq!(
            (window.lower, window.upper, window.control),
            (0x100_0945_0000, 0x100_0945_3000, CTXR_HANDOFF[1])
        );
        assert_eq!(cluster.copies.legacy, [CTRR_HANDOFF; 2]);
        assert!(cluster.copies.write_legacy(0, 0).is_err());
        assert!(
            cluster
                .copies
                .write(LockRegion::CtxrB, Field::Upper, 0x100_0945_3fff)
                .is_ok()
        );
        // A region iBoot leaves unlocked resets to 0.
        assert_eq!(
            cluster.copies.windows[LockRegion::CtrrD as usize],
            Window::default()
        );
        let core = Core::handed_off(&handoff);
        assert_eq!(core.el1.legacy, [CTRR_HANDOFF; 2]);
        assert_eq!(core.el2, Bank::default());
        assert_eq!(
            Cluster::handed_off(&CoreLocks::default()),
            Cluster::default()
        );
    }
}

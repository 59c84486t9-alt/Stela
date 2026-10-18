//! Apple's core CTRR registers: a physical region the cores protect after
//! translation, one register group for EL1 and one for EL2, shared by the
//! PEs of a cluster.
//!
//! No public source documents these registers. m1n1 `cpu_regs.h` names
//! `S3_4_C15_C2_5` CTRR_A_CTL_EL1 and `S3_4_C15_C11_4` ACC_CTRR_A_CTL_EL2,
//! calls the `ACC_` registers per-cluster, and public XNU `arm_init_sptm.c`
//! locks CTRR once per cluster (`ctrr_cluster_locked`). The rest comes from
//! what SPTM 26A434 (T8112) does in `ctrr_lock_boot` and the function it
//! calls (`__text+0x1c6c8`), on each cluster's first PE:
//!
//! - it reads CTL (`C2_5`) and stops if bit 1 is set ("CTRR-A already
//!   enabled!"), and skips the cluster when LOCK (`C2_2`) reads non-zero;
//! - it writes the first byte of the region to LWR (`C2_3`) and its last
//!   byte to UPR (`C2_4`), both physical addresses that the AMCC's CTRR-A
//!   limits give, ORs 0x13 into CTL and writes 1 to LOCK;
//! - at EL2 it repeats that on `C11_0`, `C11_1`, `C11_4` and `C11_5`.
//!
//! m1n1 names `C2_2` and `C11_5` CTRR_B_CTL; SPTM uses them only as above,
//! so this model treats them as SPTM does. Registers reset to 0 (inference:
//! SPTM requires an unlocked, disabled group at boot).
//!
//! What CTL's bits protect is not documented. Bits 0 and 1 are taken to
//! write-protect the region with the MMU off and on, and bit 4 to forbid
//! privileged execution outside it, the KTRR behavior CTRR succeeds (Siguza,
//! "KTRR"; inference). The fault hardware reports is not documented either,
//! so the walker stops on any such access instead of faulting
//! (`mmu::Unsupported::Ctrr`). Other CTL bits, and changes after the lock,
//! stop as well.
use super::mmu;
use super::registers::encodings::Encoding;

const fn sys(op1: u8, crn: u8, crm: u8, op2: u8) -> Encoding {
    Encoding::new(3, op1, crn, crm, op2)
}

const LOCK_EL1: Encoding = sys(4, 15, 2, 2);
const LOWER_EL1: Encoding = sys(4, 15, 2, 3);
const UPPER_EL1: Encoding = sys(4, 15, 2, 4);
const CONTROL_EL1: Encoding = sys(4, 15, 2, 5);
const LOWER_EL2: Encoding = sys(4, 15, 11, 0);
const UPPER_EL2: Encoding = sys(4, 15, 11, 1);
const CONTROL_EL2: Encoding = sys(4, 15, 11, 4);
const LOCK_EL2: Encoding = sys(4, 15, 11, 5);

/// CTL bits SPTM sets: write protection with the MMU off (0) and on (1),
/// and privileged execution only inside the region (4).
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

/// The register an encoding names: its level (0 for EL1, 1 for EL2) and
/// field.
pub fn owns(encoding: Encoding) -> Option<(usize, Field)> {
    Some(match encoding {
        LOWER_EL1 => (0, Field::Lower),
        UPPER_EL1 => (0, Field::Upper),
        CONTROL_EL1 => (0, Field::Control),
        LOCK_EL1 => (0, Field::Lock),
        LOWER_EL2 => (1, Field::Lower),
        UPPER_EL2 => (1, Field::Upper),
        CONTROL_EL2 => (1, Field::Control),
        LOCK_EL2 => (1, Field::Lock),
        _ => return None,
    })
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
    pub levels: [Group; 2],
}

impl Cluster {
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
                Err("CTRR register change after its lock")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sptms_sequence_programs_and_locks_a_level() {
        let mut cluster = Cluster::default();
        let (level, field) = owns(CONTROL_EL1).unwrap();
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
        assert_eq!(owns(LOCK_EL2), Some((1, Field::Lock)));
        assert_eq!(cluster.levels[1].region(true), None);
        assert!(cluster.write(1, Field::Control, 1 << 2).is_err());
        assert!(cluster.write(1, Field::Lock, 2).is_err());
    }
}

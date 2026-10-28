//! The lockdown registers of a CPU implementation block: the per-PE
//! `cpu-impl-reg` and the per-cluster `cpm-impl-reg` of an ADT `/cpus` node.
//!
//! XNU names them (`xnu-7195.141.2` `pexpert/pexpert/arm64/spr_locks.h`):
//! `CPU_PIO_RO_CTL` (per PE) and `ACC_PIO_RO_CTL` (per cluster) select the
//! MMIO register groups to make read-only, and bit 0 of each block's
//! `*_PIO_LOCK_VAL` applies the lock. XNU's values leave the per-PE groups
//! [`CPU_PIO_DBG_WRAP`] and [`CPU_PIO_TRACE_CORE_CFG`] writable, and the
//! per-cluster [`ACC_PIO_WRITABLE`] groups (PBLK_OVRD, DBG_CTL, DBG_PMGR,
//! DBG_WRAP_GLB, TRACE_CTL, TRC_UT_CTL and OCLA_CTL). Their offsets come
//! from what SPTM 26A434 (T8112) does at the end of its CPU initialization
//! (`__text+0x1b0d8` to `__text+0x1b188`), the only access it or the kernel
//! makes to these words on that SoC:
//!
//! - the 64-bit MASK at CONTROL + 8 is read and ORed with every bit except
//!   54 (`cpu-impl-reg` + 0x5008, TRACE_CORE_CFG) or 53 and 55
//!   (`cpm-impl-reg` + 0x9008, TRACE_CTL and TRC_UT_CTL);
//! - then, under one boot configuration, bit 0 of the 64-bit CONTROL is ORed
//!   in (`+ 0x5000`, `+ 0x9000`);
//! - each PE of a cluster repeats the `cpm-impl-reg` sequence with the same
//!   values, and SPTM may read MASK back to record it.
//!
//! The other M1 to M3 SPTMs make the same accesses with their own masks:
//! the M3 ones set every
//! per-PE bit. MASK and CONTROL reset to 0 (inference). Once locked, a
//! write that keeps both values (as the cluster's other PEs make) completes;
//! one that changes them stops, because what hardware does is not
//! documented. Which block offsets a group covers is not public, so the lock
//! makes no other word read-only. This model owns only the lockdown pair
//! and, in a PE's block, RVBAR; other described words in the shared
//! implementation window belong to their own device models.
//!
//! A PE's `cpu-impl-reg` also holds its RVBAR at +0 (m1n1 `src/smp.c`): the
//! reset vector in bits 47:12, where the core leaves reset, and RVBAR_LOCK
//! in bit 0. Boot firmware programs and locks it before its client runs:
//! m1n1 finds it locked on the entry point iBoot gave it, and SPTM 26A434
//! (T8112) neither reads nor writes it, its warm reset path at the page
//! of its entry point (`b` to the code that looks the PE up by MPIDR). So a
//! block given the boot hand-off's entry point reads it locked, a write
//! that keeps it completes and one that changes it stops.
//!
//! A PE's block also holds two words XNU names (`xnu-12377.121.6`
//! `pexpert/pexpert/arm64/apple_arm64_regs.h`):
//!
//! - `CPU_STS` at +0x100, whose `cpuRunSt` bits 7:0 read 0 once the core is
//!   off. XNU's `cpu_exit_wait` polls it until 0 on every non-quiescing
//!   processor exit and panics after 10 s ("CPUn failed to shut down"),
//!   and m1n1's `smp_stop_secondaries` polls the same byte. A core out of
//!   reset and not powered down reads [`CPU_STS_RUNNING`], a nonzero state
//!   whose encoding is not public (inference: both consumers test only for
//!   0). Writes stop.
//! - `CORE_THRTL_CFG2` at +0x218, whose `c1pptThrtlRate` (bits 63:56) XNU
//!   sets to 0xb2 on cold boot on throttle-tunable MIDRs
//!   (`osfmk/arm/machine_routines_apple.c`), as the T6020 and M3 SPTMs do
//!   with read-modify-write (sptm.t6020 file 0xbb0b8..0xbb0c4). The
//!   emulated core has no power throttling, so the word holds what software
//!   writes, 0 from reset (inference).
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};

/// CONTROL and MASK.
pub const BYTES: u64 = 16;
/// Each word of a PE's block ([`PE_WORDS`]).
pub const WORD_BYTES: u64 = 8;
const LOCK: u64 = 1;
#[cfg(test)]
pub const CPU_PIO_TRACE_CORE_CFG: u64 = 1 << 54;
const RVBAR: u64 = 0;
const RVBAR_ADDRESS: u64 = 0x0000_ffff_ffff_f000;
/// XNU's `CPU_PIO_CPU_STS_OFFSET` and `CORE_THRTL_CFG2_OFFSET`.
pub const CPU_STS: u64 = 0x100;
pub const CORE_THRTL_CFG2: u64 = 0x218;
/// The 64-bit words of a PE's block besides the lockdown pair.
pub const PE_WORDS: [u64; 3] = [RVBAR, CPU_STS, CORE_THRTL_CFG2];
/// `cpuRunSt` of a core out of reset (any nonzero state; see the module).
pub const CPU_STS_RUNNING: u64 = 1;

/// The lockdown pair of one implementation block, with CONTROL at
/// `control` bytes from the block's start.
#[derive(Debug, Clone)]
pub struct Lockdown {
    name: &'static str,
    control: Option<u64>,
    lock: u64,
    mask: u64,
    pe: Option<Pe>,
}

/// The words of a PE's block.
#[derive(Debug, Clone, Copy)]
struct Pe {
    rvbar: u64,
    running: bool,
    throttle: u64,
}

impl Lockdown {
    pub fn new(name: &'static str, control: u64) -> Self {
        Self {
            name,
            control: Some(control),
            lock: 0,
            mask: 0,
            pe: None,
        }
    }

    /// A PE implementation block with no legacy lockdown pair. The M4 and
    /// later SPTM census describes no PIO lockdown writes, independently of
    /// the PE's RVBAR and CPU_STS contract. m1n1 7cde7d1a `src/smp.c`
    /// still accesses RVBAR at `cpu-impl-reg + 0` on those chips; XNU
    /// xnu-12377.121.6 `apple_arm64_regs.h` defines CPU_STS and throttle
    /// offsets independently of HAS_CTRR. No lock registers are fabricated.
    pub fn processor(entry: u64) -> Self {
        Self {
            name: "cpu-impl-reg",
            control: None,
            lock: 0,
            mask: 0,
            pe: None,
        }
        .with_reset_vector(entry)
    }

    /// A PE's block, whose RVBAR the boot firmware locked on `entry`; the
    /// PE is held in reset until [`Lockdown::set_running`].
    pub fn with_reset_vector(mut self, entry: u64) -> Self {
        self.pe = Some(Pe {
            rvbar: entry & RVBAR_ADDRESS | LOCK,
            running: false,
            throttle: 0,
        });
        self
    }

    /// Where the PE leaves reset, for a PE's block.
    pub fn reset_address(&self) -> Option<u64> {
        Some(self.pe?.rvbar & RVBAR_ADDRESS)
    }

    /// The PE left reset (`true`) or powered down, for a PE's block.
    pub fn set_running(&mut self, running: bool) {
        if let Some(pe) = self.pe.as_mut() {
            pe.running = running;
        }
    }

    /// Whether CONTROL bit 0 has applied the lock.
    pub fn locked(&self) -> bool {
        self.lock & LOCK != 0
    }

    fn register(&self, offset: u64, width: Width, direction: Direction) -> Result<bool, MmioError> {
        let refused = |reason| refuse(self.name, offset, width, direction, reason);
        let control = self
            .control
            .ok_or_else(|| refused("this PE implementation block has no legacy lockdown pair"))?;
        let is_mask = match offset.checked_sub(control) {
            Some(0) => false,
            Some(8) => true,
            _ => return Err(refused("register without public description")),
        };
        if width != Width::Double {
            return Err(refused("lockdown register access narrower than 64 bits"));
        }
        Ok(is_mask)
    }
}

impl MmioDevice for Lockdown {
    fn advance_policy(&self) -> super::bus::AdvancePolicy {
        super::bus::AdvancePolicy::Passive
    }
    fn name(&self) -> &'static str {
        self.name
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        if let Some(pe) = self.pe.filter(|_| width == Width::Double) {
            match offset {
                RVBAR => return Ok(pe.rvbar),
                CPU_STS => return Ok(if pe.running { CPU_STS_RUNNING } else { 0 }),
                CORE_THRTL_CFG2 => return Ok(pe.throttle),
                _ => {}
            }
        }
        Ok(if self.register(offset, width, Direction::Read)? {
            self.mask
        } else {
            self.lock
        })
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let refused = |reason| refuse(self.name, offset, width, Direction::Write, reason);
        if let Some(pe) = self.pe.as_mut().filter(|_| width == Width::Double) {
            match offset {
                RVBAR if value == pe.rvbar => return Ok(()),
                RVBAR => return Err(refused("RVBAR change after the boot firmware locked it")),
                CPU_STS => return Err(refused("write of the PE run-state status CPU_STS")),
                CORE_THRTL_CFG2 => {
                    pe.throttle = value;
                    return Ok(());
                }
                _ => {}
            }
        }
        let is_mask = self.register(offset, width, Direction::Write)?;
        let current = if is_mask { self.mask } else { self.lock };
        if self.locked() && value != current {
            return Err(refused("lockdown register change after the lock"));
        }
        if is_mask {
            self.mask = value;
        } else if value & !LOCK != 0 {
            return Err(refused("lockdown CONTROL bit without documented meaning"));
        } else {
            self.lock = value;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;

    #[test]
    fn sptms_lockdown_sequence_completes_and_locks_the_pair() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut block = Lockdown::new("cpu-impl-reg", 0x5000);
        let rmw = |block: &mut Lockdown, access: &mut Access<'_>, offset, bits: u64| {
            let value = block.read(offset, Width::Double, access).unwrap() | bits;
            block.write(offset, Width::Double, value, access)
        };
        // MASK, every bit but TRACE_CORE_CFG, then CONTROL bit 0.
        rmw(&mut block, &mut access, 0x5008, !CPU_PIO_TRACE_CORE_CFG).unwrap();
        assert!(!block.locked());
        rmw(&mut block, &mut access, 0x5000, 1).unwrap();
        assert!(block.locked());
        assert_eq!(
            block.read(0x5008, Width::Double, &mut access),
            Ok(!CPU_PIO_TRACE_CORE_CFG)
        );
        // Another PE of the cluster repeats it unchanged; a change stops.
        rmw(&mut block, &mut access, 0x5008, !CPU_PIO_TRACE_CORE_CFG).unwrap();
        rmw(&mut block, &mut access, 0x5000, 1).unwrap();
        assert!(
            block
                .write(0x5008, Width::Double, u64::MAX, &mut access)
                .is_err()
        );
        assert!(block.write(0x5000, Width::Double, 0, &mut access).is_err());
        // Undocumented bits, narrow accesses and other registers refuse.
        let mut fresh = Lockdown::new("cpm-impl-reg", 0x9000);
        assert!(fresh.write(0x9000, Width::Double, 2, &mut access).is_err());
        assert!(fresh.read(0x9008, Width::Word, &mut access).is_err());
        assert!(fresh.read(0x9010, Width::Double, &mut access).is_err());
        assert!(fresh.read(0x100, Width::Double, &mut access).is_err());
        assert!(fresh.read(0, Width::Double, &mut access).is_err());
    }

    #[test]
    fn a_pes_rvbar_reads_locked_on_the_boot_entry_page() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut block = Lockdown::new("cpu-impl-reg", 0x5000).with_reset_vector(0x8_0300_c388);
        assert_eq!(block.reset_address(), Some(0x8_0300_c000));
        assert_eq!(block.read(0, Width::Double, &mut access), Ok(0x8_0300_c001));
        block
            .write(0, Width::Double, 0x8_0300_c001, &mut access)
            .unwrap();
        assert!(
            block
                .write(0, Width::Double, 0x8_0400_0001, &mut access)
                .is_err()
        );
        assert!(block.read(0, Width::Word, &mut access).is_err());
    }

    #[test]
    fn processor_words_do_not_require_or_invent_a_legacy_lockdown_pair() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let entry = 0x100_0300_c000;
        let mut block = Lockdown::processor(entry);
        assert_eq!(block.reset_address(), Some(entry));
        assert_eq!(
            block.read(RVBAR, Width::Double, &mut access),
            Ok(entry | LOCK)
        );
        assert_eq!(block.read(CPU_STS, Width::Double, &mut access), Ok(0));
        block.set_running(true);
        assert_eq!(
            block.read(CPU_STS, Width::Double, &mut access),
            Ok(CPU_STS_RUNNING)
        );
        block.set_running(false);
        assert_eq!(block.read(CPU_STS, Width::Double, &mut access), Ok(0));
        block
            .write(CORE_THRTL_CFG2, Width::Double, 0xb2 << 56, &mut access)
            .unwrap();
        assert_eq!(
            block.read(CORE_THRTL_CFG2, Width::Double, &mut access),
            Ok(0xb2 << 56)
        );
        block
            .write(RVBAR, Width::Double, entry | LOCK, &mut access)
            .unwrap();
        assert!(
            block
                .write(RVBAR, Width::Double, (entry + 0x1000) | LOCK, &mut access)
                .is_err()
        );
        for offset in [0x5000, 0x5008, 0x9000, 0x9008] {
            assert!(block.read(offset, Width::Double, &mut access).is_err());
            assert!(block.write(offset, Width::Double, 0, &mut access).is_err());
        }
        assert!(block.write(CPU_STS, Width::Double, 0, &mut access).is_err());
        assert!(block.read(RVBAR, Width::Word, &mut access).is_err());
        assert!(!block.locked());
    }

    #[test]
    fn a_pes_run_state_follows_its_power_and_its_throttle_word_holds() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut block = Lockdown::new("cpu-impl-reg", 0x5000).with_reset_vector(0x8_0300_c000);
        let sts = |block: &mut Lockdown, access: &mut Access<'_>| {
            block.read(CPU_STS, Width::Double, access).unwrap() & 0xff
        };
        assert_eq!(sts(&mut block, &mut access), 0);
        block.set_running(true);
        assert_ne!(sts(&mut block, &mut access), 0);
        // XNU's cpu_exit_wait sees the core off once it powers down.
        block.set_running(false);
        assert_eq!(sts(&mut block, &mut access), 0);
        assert!(block.write(CPU_STS, Width::Double, 0, &mut access).is_err());
        // The SPTMs' and XNU's c1pptThrtlRate read-modify-write.
        let value = block
            .read(CORE_THRTL_CFG2, Width::Double, &mut access)
            .unwrap();
        let rate = value & !(0xff << 56) | 0xb2 << 56;
        block
            .write(CORE_THRTL_CFG2, Width::Double, rate, &mut access)
            .unwrap();
        assert_eq!(
            block.read(CORE_THRTL_CFG2, Width::Double, &mut access),
            Ok(rate)
        );
        // A cluster's block has neither word.
        let mut cluster = Lockdown::new("cpm-impl-reg", 0x9000);
        cluster.set_running(true);
        assert!(cluster.read(CPU_STS, Width::Double, &mut access).is_err());
    }
}

//! External-debug Software Lock and Apple UTTDBG PC sampling.
//!
//! Arm SysReg_xml_A_profile-2026-06 `ext-edlar.xml` and `ext-edlsr.xml`
//! specify the 32-bit write-only EDLAR at +0xfb0 and read-only EDLSR at
//! +0xfb4. The key 0xc5acce55 unlocks; every other word locks. EDLSR reports
//! the implemented lock in bit 0, its locked state in bit 1 and nTT as zero.
//! The reset state is locked. This is the optional Software Lock, distinct
//! from the PE's architectural OS Lock and its debug exception controls.
//!
//! The kernel initializes each CPU's debug component with that key (26A434
//! file offset 0x4d6f1b4 and 0x4d6f280), using `/cpus/coresight-reg` or
//! `reg-private` and a 4 KiB component map within the DT's larger CoreSight
//! region. Only the lock pair of that component is mapped here; other debug registers
//! and accesses with undescribed widths or directions still refuse.
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError, stela_contracts::bus::Width,
    stela_contracts::bus::refuse,
};

const NAME: &str = "coresight-software-lock";
/// Offset of the write-only external debug lock-access register.
pub const ACCESS: u64 = 0xfb0;
/// Offset of the read-only external debug lock-status register.
pub const STATUS: u64 = 0xfb4;
/// Size and alignment of an architectural CoreSight component map.
const KEY: u64 = 0xc5acce55;
const IMPLEMENTED: u64 = 1;
const LOCKED: u64 = 1 << 1;

/// The optional memory-mapped Software Lock of one debug component.
#[derive(Debug, Clone)]
pub struct SoftwareLock {
    locked: bool,
}

impl SoftwareLock {
    /// A component whose Software Lock starts locked after debug reset.
    pub fn new() -> Self {
        Self { locked: true }
    }
}

impl Default for SoftwareLock {
    fn default() -> Self {
        Self::new()
    }
}

impl MmioDevice for SoftwareLock {
    fn advance_policy(&self) -> super::bus::AdvancePolicy {
        super::bus::AdvancePolicy::Passive
    }
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        if offset != STATUS || width != Width::Word {
            return Err(refuse(
                NAME,
                offset,
                width,
                Direction::Read,
                "only the 32-bit external debug lock status is readable",
            ));
        }
        Ok(IMPLEMENTED | if self.locked { LOCKED } else { 0 })
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        if offset != ACCESS || width != Width::Word {
            return Err(refuse(
                NAME,
                offset,
                width,
                Direction::Write,
                "only the 32-bit external debug lock-access register is writable",
            ));
        }
        self.locked = value & width.mask() != KEY;
        Ok(())
    }
}

/// Apple UTTDBG is the fourth 64 KiB region of a CPU's CoreSight map
/// (XNU `osfmk/arm64/proc_reg.h`, `CORESIGHT_UTT`).
/// The UTTDBG PC sample register, relative to its own region.
pub const PC_SAMPLE: u64 = 0x90;

/// One PE's UTTDBG PC sampler.
///
/// XNU `osfmk/arm/model_dep.c` `panic_display_hung_cpus_help` first reads
/// +0x90 as a word to trigger a sample, then reads the same address as a
/// doubleword. Without the word read the initial result is zero. The exact
/// 26A434 kernel does both at file offsets 0x4d7dd60 and 0x4d7dd64.
/// The engine publishes execution PCs; the trigger latches that
/// observation so another PE's execution cannot change a sample being read.
/// XNU discards the trigger read's result. Returning the sampled PC's low
/// word is an inferred register alias, not a measured hardware encoding.
/// The debug-halt wrapper and all other UTTDBG registers remain unsupported.
#[derive(Debug, Clone, Default)]
pub struct PcSampler {
    observed: u64,
    sampled: u64,
}

impl PcSampler {
    /// Publish the most recent execution PC of the PE this sampler belongs to.
    /// This changes the sampling source, not an already-triggered sample.
    pub fn observe(&mut self, pc: u64) {
        self.observed = pc;
    }
}

impl MmioDevice for PcSampler {
    fn advance_policy(&self) -> super::bus::AdvancePolicy {
        super::bus::AdvancePolicy::Passive
    }
    fn name(&self) -> &'static str {
        "utt-pc-sampler"
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        match (offset, width) {
            (PC_SAMPLE, Width::Word) => {
                self.sampled = self.observed;
                Ok(self.sampled & Width::Word.mask())
            }
            (PC_SAMPLE, Width::Double) => Ok(self.sampled),
            _ => Err(refuse(
                self.name(),
                offset,
                width,
                Direction::Read,
                "only the word trigger and doubleword PC sample are described",
            )),
        }
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        _: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        Err(refuse(
            self.name(),
            offset,
            width,
            Direction::Write,
            "the PC sampler is read-only; UTTDBG halt controls are not modeled",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_contracts::interrupt::InterruptLatch;
    #[test]
    fn pc_sampler_latches_only_on_word_read_and_keeps_per_pe_state() {
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        let mut first = PcSampler::default();
        let mut second = PcSampler::default();
        let pc = 0xffff_fe00_3a3a_9d60;
        first.observe(pc);
        second.observe(pc + 4);
        assert_eq!(first.read(PC_SAMPLE, Width::Double, &mut access), Ok(0));
        assert_eq!(
            first.read(PC_SAMPLE, Width::Word, &mut access),
            Ok(pc & 0xffff_ffff)
        );
        first.observe(pc + 8);
        assert_eq!(first.read(PC_SAMPLE, Width::Double, &mut access), Ok(pc));
        assert_eq!(second.read(PC_SAMPLE, Width::Double, &mut access), Ok(0));
        second.read(PC_SAMPLE, Width::Word, &mut access).unwrap();
        assert_eq!(
            second.read(PC_SAMPLE, Width::Double, &mut access),
            Ok(pc + 4)
        );
        assert!(first.read(PC_SAMPLE, Width::Half, &mut access).is_err());
        assert!(first.read(PC_SAMPLE + 4, Width::Word, &mut access).is_err());
        assert!(first.write(PC_SAMPLE, Width::Word, 0, &mut access).is_err());
        assert_eq!(first.read(PC_SAMPLE, Width::Double, &mut access), Ok(pc));
        first.read(PC_SAMPLE, Width::Word, &mut access).unwrap();
        assert_eq!(
            first.read(PC_SAMPLE, Width::Double, &mut access),
            Ok(pc + 8)
        );
    }

    #[test]
    fn key_unlocks_other_words_relock_and_unsupported_accesses_preserve_state() {
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        let mut lock = SoftwareLock::new();
        assert_eq!(lock.read(STATUS, Width::Word, &mut a), Ok(3));
        lock.write(ACCESS, Width::Word, KEY, &mut a).unwrap();
        assert_eq!(lock.read(STATUS, Width::Word, &mut a), Ok(1));
        for (offset, width) in [
            (ACCESS, Width::Double),
            (STATUS, Width::Word),
            (0, Width::Word),
        ] {
            assert!(lock.write(offset, width, 0, &mut a).is_err());
        }
        assert_eq!(lock.read(STATUS, Width::Word, &mut a), Ok(1));
        assert!(lock.read(ACCESS, Width::Word, &mut a).is_err());
        lock.write(ACCESS, Width::Word, 0, &mut a).unwrap();
        assert_eq!(lock.read(STATUS, Width::Word, &mut a), Ok(3));
    }
}

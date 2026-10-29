//! CPU and CPM energy accumulators described by `/arm-io/pmgr/hw-dpe-reg`.
//!
//! The T8112 accessors `get/setCPMEnergyAccumulator` (kernel file offsets
//! 0x2fa05dc/0x2fa063c), core dynamic energy (0x2fa42c0/0x2fa4374) and SRAM
//! energy (0x2fa45a4..0x2fa4acc) describe two full 64-bit accumulators per
//! bank. `ApplePMGR::_readEnergyNodeCounter` (0x2b8403c) samples these with
//! one 64-bit load; these DT records do not select split-word sampling.
//!
//! An emulated die has neither physical switching energy nor SRAM leakage:
//! counts start at zero and hold software's saved samples, including while
//! enabled. No conversion from guest instructions or elapsed time to physical
//! energy is known. This is a model of absent physical activity, not a
//! claimed silicon reset image or calibrated power estimate.
//!
//! CPM +0x80 is the full-width configuration RMW used by
//! `enableCPUEnergyAccumulators` (0x2fa41e4); bits 63/61/59 enable the
//! accumulators. Stela's boot stage hands off with this configuration and
//! both counts zero: accumulators disabled, with no other field set, as a
//! boot chain that programs none of them would. Configuration then holds
//! full writes. iBoot's conditional programming is not reproduced.
use stela_contracts::refuse;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError, stela_contracts::bus::Width,
    stela_contracts::bus::refuse,
};

const NAME: &str = "cpu-energy";
const SRAM: u64 = 8;
const CONTROL: u64 = 0x80;
/// The two accumulators' span.
pub const COUNTER_BYTES: u64 = 16;
/// The CPM configuration's offset from its first accumulator.
pub const CONTROL_OFFSET: u64 = CONTROL;
/// CPM energy offset within a CPU cluster's ACC island (T8112 RegMap
/// 0xa/0x16, DT reg[7]/reg[16], plus 0x8000).
/// Core energy offset within its per-core `reg` window (RegMap 0xe..0x11
/// and 0x1a..0x1d, DT reg[10..13]/reg[19..22]).

#[derive(Debug, Clone)]
pub struct Energy {
    counts: [u64; 2],
    cpm: bool,
    control: u64,
}

impl Energy {
    pub fn new(cpm: bool) -> Self {
        Self {
            counts: [0; 2],
            cpm,
            control: 0,
        }
    }

    fn described(&self, offset: u64, width: Width) -> bool {
        width == Width::Double && (matches!(offset, 0 | SRAM) || self.cpm && offset == CONTROL)
    }
}

impl MmioDevice for Energy {
    fn advance_policy(&self) -> super::bus::AdvancePolicy {
        super::bus::AdvancePolicy::Passive
    }
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let value = if !self.described(offset, width) {
            Err(refuse!(
                "energy register or width without described meaning"
            ))
        } else if offset == CONTROL {
            Ok(self.control)
        } else {
            Ok(self.counts[(offset / SRAM) as usize])
        };
        value.map_err(|reason| refuse(NAME, offset, width, Direction::Read, reason))
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        if !self.described(offset, width) {
            return Err(refuse(
                NAME,
                offset,
                width,
                Direction::Write,
                "energy register or width without described meaning",
            ));
        }
        if offset == CONTROL {
            self.control = value;
        } else {
            self.counts[(offset / SRAM) as usize] = value;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_contracts::interrupt::InterruptLatch;

    #[test]
    fn the_boot_stage_hands_off_disabled_energy_and_samples_hold_without_physical_activity() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut cpm = Energy::new(true);
        assert_eq!(cpm.read(0, Width::Double, &mut access), Ok(0));
        assert_eq!(cpm.read(CONTROL, Width::Double, &mut access), Ok(0));
        assert_eq!(cpm.read(SRAM, Width::Double, &mut access), Ok(0));
        let control = 0xa800_0000_0000_0123;
        cpm.write(CONTROL, Width::Double, control, &mut access)
            .unwrap();
        for (offset, value) in [(0, u64::MAX), (SRAM, 0x1234_5678_9abc_def0)] {
            cpm.write(offset, Width::Double, value, &mut access)
                .unwrap();
            access.now += 24_000_000;
            cpm.advance(&mut access).unwrap();
            assert_eq!(cpm.read(offset, Width::Double, &mut access), Ok(value));
        }
        assert_eq!(cpm.read(CONTROL, Width::Double, &mut access), Ok(control));
        for (offset, width) in [
            (0, Width::Word),
            (4, Width::Word),
            (16, Width::Double),
            (CONTROL, Width::Word),
        ] {
            assert!(cpm.read(offset, width, &mut access).is_err());
            assert!(cpm.write(offset, width, 0, &mut access).is_err());
        }
        assert_eq!(cpm.read(0, Width::Double, &mut access), Ok(u64::MAX));
        let mut core = Energy::new(false);
        assert!(core.read(CONTROL, Width::Double, &mut access).is_err());
        assert!(core.write(CONTROL, Width::Double, 1, &mut access).is_err());
        core.write(SRAM, Width::Double, 19, &mut access).unwrap();
        assert_eq!(core.read(SRAM, Width::Double, &mut access), Ok(19));
    }
}

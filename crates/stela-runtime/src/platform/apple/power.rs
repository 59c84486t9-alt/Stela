//! PMGR SOC power configuration, placed by the DT `reg` map bindings of
//! `AppleT8112PMGR::initRegMaps` (kernel file 0x2fa31bc..0x2fa3620).
//!
//! VOLMAN (reg[31]): `restoreHW` 0x2fa3c80 checks channel bit24 before
//! clearing configuration, acknowledges channels at +0x24, enables the mask
//! at +0x3f8, and finalizes at +0x3fc. `panicOnDvcDoneErr` 0x2fa3e18 tests
//! low8 (optionally also bits23:16). Low8 writes acknowledge (W1C inference),
//! never inject errors. The emulated die has no voltage errors. A protected
//! channel cannot be rewritten; other configuration words retain full writes.
//!
//! The PS marker (reg[30]+0x17ffc, restoreHW 0x2fa3d88) is a firmware-owned
//! read-only whole-word marker, distinct from the `ps-regs` device registers.
//! GPCE (reg[34], `configCPUComplexPowerState` 0x2f9cab4) retains each complex's
//! low4 request, accepting idle/enable (0/f). Busy bit4 clears at once. These
//! enable autonomous complex power management, not an immediate core stop.
//! Power-gate enables (reg[32], restoreHW 0x2f9cc3c and
//! `_enableCPMPowerDomainGating` 0x2f9fd88) retain bit31 and other RMW fields.
//! They permit automatic gating; no electrical idle event is modeled, so they
//! do not invent a power-down of the existing PMGR device states.
//!
//! TVM controls (reg[35], `enableTVM` kernel file 0x2fa61f0) retain
//! configuration at four 0x400-spaced domain words. Disable finishes at once;
//! the +0x3e0 status words report no pending voltage/thermal decision.
//!
//! Stela's boot stage hands off idle/unlocked/disabled zero configuration,
//! a zero marker and healthy zero status. Conditional iBoot programming is
//! not reproduced. Only the described full32 registers are mapped.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use super::regfile::Held;
use alloc::vec::Vec;

const NAME: &str = "soc-power";
const STATUS: u64 = 0x24;
const CHANNEL: core::ops::Range<u64> = 0x30..0x50;
const LOCK: u64 = 1 << 24;
const ACK: u64 = 0xff;
const MASK: u64 = 0x3f8;
const FINAL: u64 = 0x3fc;
const REQUEST: u64 = 0xf;
const BUSY: u64 = 1 << 4;
pub const MARKER: u64 = 0x17ffc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Volman,
    Marker,
    Gpce,
    Gating,
    Tvm,
}

impl Kind {
    pub fn offsets(self) -> Vec<u64> {
        match self {
            Self::Volman => [
                alloc::vec![STATUS, MASK, FINAL],
                CHANNEL.step_by(4).collect(),
            ]
            .concat(),
            Self::Marker => alloc::vec![MARKER],
            Self::Gpce => alloc::vec![0, 4],
            Self::Gating => alloc::vec![0, 0x40, 0x80, 0x88],
            Self::Tvm => [0, 0x400, 0x800, 0xc00]
                .into_iter()
                .flat_map(|o| [o, o + 0x3e0])
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Power {
    kind: Kind,
    registers: Held,
}
impl Power {
    pub fn new(kind: Kind) -> Self {
        Self {
            kind,
            registers: Held::default(),
        }
    }
    fn check(&self, offset: u64, width: Width) -> Result<(), &'static str> {
        if width != Width::Word || !self.kind.offsets().contains(&offset) {
            return Err("SOC power register or width without described meaning");
        }
        Ok(())
    }
}
impl MmioDevice for Power {
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        self.check(offset, width)
            .map_err(|reason| refuse(NAME, offset, width, Direction::Read, reason))?;
        Ok(self.registers.get(offset))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        self.check(offset, width).map_err(fail)?;
        let value = value & Width::Word.mask();
        match self.kind {
            Kind::Tvm if offset % 0x400 == 0x3e0 => {
                return Err(fail("TVM idle status is read-only"));
            }
            Kind::Marker => {
                return Err(fail("PS initialization marker is owned by the boot stage"));
            }
            Kind::Volman if offset == STATUS => {
                if value & !ACK != 0 {
                    return Err(fail(
                        "VOLMAN acknowledgement outside the described low8 channels",
                    ));
                }
                self.registers
                    .set(offset, self.registers.get(offset) & !value);
                return Ok(());
            }
            Kind::Volman
                if CHANNEL.contains(&offset)
                    && self.registers.get(offset) & LOCK != 0
                    && self.registers.get(offset) != value =>
            {
                return Err(fail("VOLMAN channel configuration is protected by bit24"));
            }
            Kind::Volman if offset == FINAL && value & !1 != 0 => {
                return Err(fail(
                    "VOLMAN finalization fields other than bit0 are undescribed",
                ));
            }
            Kind::Gpce => {
                if !matches!(value & REQUEST, 0 | REQUEST) {
                    return Err(fail("unsupported partial GPCE complex request"));
                }
                self.registers.set(offset, value & !BUSY);
                return Ok(());
            }
            _ => (),
        }
        self.registers.set(offset, value);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;
    #[test]
    fn tvm_enable_and_disable_complete_with_healthy_idle_status() {
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        let mut p = Power::new(Kind::Tvm);
        for base in [0, 0x400, 0x800, 0xc00] {
            assert_eq!(p.read(base, Width::Word, &mut a), Ok(0));
            for value in [0x123, 0x122] {
                p.write(base, Width::Word, value, &mut a).unwrap();
                assert_eq!(p.read(base, Width::Word, &mut a), Ok(value));
                assert_eq!(p.read(base + 0x3e0, Width::Word, &mut a), Ok(0));
            }
            assert!(p.write(base + 0x3e0, Width::Word, 2, &mut a).is_err());
        }
    }

    #[test]
    fn volman_acknowledges_without_injecting_errors_and_protects_channels() {
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        let mut p = Power::new(Kind::Volman);
        for o in Kind::Volman.offsets() {
            assert_eq!(p.read(o, Width::Word, &mut a), Ok(0));
        }
        for channel in 0..8 {
            p.write(STATUS, Width::Word, 1 << channel, &mut a).unwrap();
        }
        assert_eq!(p.read(STATUS, Width::Word, &mut a), Ok(0));
        assert!(p.write(STATUS, Width::Word, 0x10000, &mut a).is_err());
        p.write(0x30, Width::Word, LOCK | 7, &mut a).unwrap();
        assert!(p.write(0x30, Width::Word, 0, &mut a).is_err());
        assert_eq!(p.read(0x30, Width::Word, &mut a), Ok(LOCK | 7));
        p.write(MASK, Width::Word, 0xff000, &mut a).unwrap();
        p.write(FINAL, Width::Word, 1, &mut a).unwrap();
        assert_eq!(p.read(MASK, Width::Word, &mut a), Ok(0xff000));
        assert_eq!(p.read(FINAL, Width::Word, &mut a), Ok(1));
        assert!(p.write(FINAL, Width::Word, 2, &mut a).is_err());
        assert!(p.read(0x28, Width::Word, &mut a).is_err());
        assert!(p.write(MASK, Width::Double, 0, &mut a).is_err());
    }
    #[test]
    fn marker_gpce_and_gating_have_separate_register_contracts() {
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        for kind in [Kind::Marker, Kind::Gpce, Kind::Gating] {
            let mut p = Power::new(kind);
            for o in kind.offsets() {
                assert_eq!(p.read(o, Width::Word, &mut a), Ok(0));
                if kind == Kind::Marker {
                    assert!(p.write(o, Width::Word, 1, &mut a).is_err());
                } else {
                    let value = if kind == Kind::Gpce {
                        0x20 | REQUEST | BUSY
                    } else {
                        0x8000_0023
                    };
                    p.write(o, Width::Word, value, &mut a).unwrap();
                    assert_eq!(
                        p.read(o, Width::Word, &mut a),
                        Ok(if kind == Kind::Gpce {
                            value & !BUSY
                        } else {
                            value
                        })
                    );
                    p.write(o, Width::Word, 0, &mut a).unwrap();
                }
            }
            assert!(p.read(3, Width::Word, &mut a).is_err());
            assert!(
                p.write(kind.offsets()[0], Width::Double, 0, &mut a)
                    .is_err()
            );
        }
        let mut p = Power::new(Kind::Gpce);
        assert!(p.write(0, Width::Word, 3, &mut a).is_err());
        assert_eq!(p.read(0, Width::Word, &mut a), Ok(0));
    }
}

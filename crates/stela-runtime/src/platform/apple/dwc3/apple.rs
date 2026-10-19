//! Apple's registers around the dual-role core that its xHCI host driver
//! programs: CIO link timing words and two unnamed globals in the core's
//! own space, and the `DRD_USB31_CFG` (reg[1]), `AUSBC_PWR_CTRL_BLK`
//! (reg[5]) and `AUSBC_CTLREG_BLK` (reg[6]) windows.
//!
//! Evidence (`docs/research/xhci.md`, 26A434 KC file offsets):
//! `AppleT8112USBXHCI::reset` (0x4457e68) read-modify-writes the CIO LFPS
//! and bandwidth negotiation offsets and link timers at core 0xcd38..0xcd40,
//! clears bit 13 of core 0xc680, polls `RAM0_WR_ACTIVE` (reg[1] +0 bit 15)
//! clear, polls `USB31DRD_PIPE_PHY_READY` (reg[1] +0x28 bit 30) unless the
//! pipehandler selects the dummy PIPE, and clears the five reg[6] +0xf0
//! force-clock-on bits. `setMaximumPortLinkSpeed` (0x4467cc0) sets or
//! clears `LLUCTL.FORCE_GEN1` (core 0xd024 bit 10). `setPowerStateGated`
//! (0x4463b38) requests D3/D0 through reg[5] +0 and reads the resulting
//! state from +0x4 and +0x8; `setUSB3Mode` (0x445b5d0) locks TX
//! detect-receive with the reg[5] +0x18/+0x1c request/acknowledge pair.
//!
//! The timing words, FORCE_GEN1 and the clock forcing only shape link
//! training and clock gating, which no modeled bus observes; the model
//! retains each traced field and refuses the rest. There is no PIPE PHY, so
//! its ready bit and lock state read clear, and the core's RAM is never
//! busy. A D3 request completes at once, powering USB off and reporting
//! SLEEP; D0 powers it on. The power block's interrupt (the controller's
//! fifth wire) is not modeled, so enabling any of its sources refuses; its
//! clear register has nothing pending. Handoff: every field zero, in D0.
//! These are Stela handoff choices, not captured reset values.

/// The reg[1], reg[5] and reg[6] windows' offsets in the core's model.
pub const CONFIG: u64 = super::PLATFORM_WINDOW_BASE + super::PLATFORM_WINDOW_STRIDE;
pub const POWER: u64 = super::PLATFORM_WINDOW_BASE + 5 * super::PLATFORM_WINDOW_STRIDE;
pub const CONTROL: u64 = super::PLATFORM_WINDOW_BASE + 6 * super::PLATFORM_WINDOW_STRIDE;

const CIO_LFPS_OFFSET: u64 = 0xcd38;
const CIO_BW_NEGOTIATION_OFFSET: u64 = 0xcd3c;
const CIO_LINK_TIMERS: u64 = 0xcd40;
const UNNAMED_C680: u64 = 0xc680;
const LLUCTL: u64 = 0xd024;
const RAM_STATUS: u64 = CONFIG;
const PIPE_STATUS: u64 = CONFIG + 0x28;
const HIBERNATION_CFG: u64 = POWER;
const HIBERNATION_STATUS: u64 = POWER + 0x4;
const HIBERNATION_UNMASKED: u64 = POWER + 0x8;
const HIBERNATION_ENABLE: u64 = POWER + 0x10;
const HIBERNATION_CLEAR: u64 = POWER + 0x14;
const TXDETRX_LOCK_REQ: u64 = POWER + 0x18;
const TXDETRX_LOCK_ACK: u64 = POWER + 0x1c;
const FORCE_CLOCKS: u64 = CONTROL + 0xf0;

const POWER_STATE_REQ: u32 = 3 << 4;
const D3: u32 = 3 << 4;
const SLEEP: u32 = 1 << 20;
const D0_ON: u32 = 1;
const VDD_USB_OFF: u32 = 1 << 1;
const INTERRUPTS: u32 = 0x1f;
const LOCK: u32 = 1;

/// The registers' retained fields, by offset.
const STORED: [(u64, u32); 8] = [
    (CIO_LFPS_OFFSET, u32::MAX),
    (CIO_BW_NEGOTIATION_OFFSET, u32::MAX),
    (CIO_LINK_TIMERS, 0x00ff_ffff),
    (UNNAMED_C680, 1 << 13),
    (LLUCTL, 1 << 10),
    (HIBERNATION_CFG, POWER_STATE_REQ),
    (TXDETRX_LOCK_REQ, LOCK),
    (FORCE_CLOCKS, 0x1f),
];

#[derive(Clone, Default)]
pub struct Registers {
    stored: [u32; STORED.len()],
}

impl Registers {
    /// Whether `offset` is one of these registers.
    pub fn claims(offset: u64) -> bool {
        Self::index(offset).is_some()
            || matches!(
                offset,
                RAM_STATUS
                    | PIPE_STATUS
                    | HIBERNATION_STATUS
                    | HIBERNATION_UNMASKED
                    | HIBERNATION_ENABLE
                    | HIBERNATION_CLEAR
                    | TXDETRX_LOCK_ACK
            )
    }

    fn index(offset: u64) -> Option<usize> {
        STORED.iter().position(|&(at, _)| at == offset)
    }

    fn stored(&self, offset: u64) -> u32 {
        Self::index(offset).map_or(0, |n| self.stored[n])
    }

    pub fn read(&self, offset: u64) -> Result<u32, &'static str> {
        let d3 = self.stored(HIBERNATION_CFG) == D3;
        Ok(match offset {
            // No RAM write in flight; no PIPE PHY ready or in LFPS.
            RAM_STATUS | PIPE_STATUS => 0,
            HIBERNATION_STATUS => {
                if d3 {
                    SLEEP
                } else {
                    0
                }
            }
            HIBERNATION_UNMASKED => {
                if d3 {
                    VDD_USB_OFF
                } else {
                    D0_ON
                }
            }
            HIBERNATION_ENABLE | HIBERNATION_CLEAR => 0,
            TXDETRX_LOCK_ACK => self.stored(TXDETRX_LOCK_REQ),
            _ => match Self::index(offset) {
                Some(n) => self.stored[n],
                None => return Err("not an Apple dual-role core register"),
            },
        })
    }

    pub fn write(&mut self, offset: u64, value: u32) -> Result<(), &'static str> {
        match offset {
            HIBERNATION_ENABLE if value & INTERRUPTS != 0 => {
                return Err("USB power-control interrupt sources are not modeled");
            }
            HIBERNATION_ENABLE => return Ok(()),
            // W1C of interrupt status, none of which is pending.
            HIBERNATION_CLEAR if value & !INTERRUPTS == 0 => return Ok(()),
            HIBERNATION_CFG if !matches!(value, 0 | D3) => {
                return Err("USB power states other than D0 and D3 are not modeled");
            }
            _ => {}
        }
        let n = Self::index(offset).ok_or("read-only or unmodeled Apple dual-role register")?;
        if value & !STORED[n].1 != 0 {
            return Err("unmodeled Apple dual-role register fields");
        }
        self.stored[n] = value;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_reset_and_power_transitions_follow_the_traced_sequences() {
        let mut r = Registers::default();
        // AppleT8112USBXHCI::reset's CIO and global RMWs.
        r.write(CIO_LFPS_OFFSET, 0x0f80_0f80).unwrap();
        r.write(CIO_LINK_TIMERS, 0x14_0a10).unwrap();
        assert_eq!(r.read(CIO_LINK_TIMERS), Ok(0x14_0a10));
        assert!(r.write(CIO_LINK_TIMERS, 1 << 24).is_err());
        r.write(UNNAMED_C680, 0).unwrap();
        assert!(r.write(UNNAMED_C680, 1).is_err());
        assert_eq!(r.read(RAM_STATUS), Ok(0));
        assert_eq!(r.read(PIPE_STATUS), Ok(0));
        r.write(FORCE_CLOCKS, 0).unwrap();
        // D3 and back to D0.
        assert_eq!(r.read(HIBERNATION_UNMASKED), Ok(D0_ON));
        r.write(HIBERNATION_CFG, D3).unwrap();
        assert_eq!(r.read(HIBERNATION_UNMASKED), Ok(VDD_USB_OFF));
        assert_eq!(r.read(HIBERNATION_STATUS), Ok(SLEEP));
        r.write(HIBERNATION_CLEAR, 2).unwrap();
        assert!(r.write(HIBERNATION_ENABLE, 0xc).is_err());
        r.write(HIBERNATION_ENABLE, 0).unwrap();
        r.write(HIBERNATION_CFG, 0).unwrap();
        assert_eq!(r.read(HIBERNATION_STATUS), Ok(0));
        assert!(r.write(HIBERNATION_CFG, 1 << 4).is_err());
        // setUSB3Mode's lock handshake.
        r.write(TXDETRX_LOCK_REQ, LOCK).unwrap();
        assert_eq!(r.read(TXDETRX_LOCK_ACK), Ok(LOCK));
        assert!(r.write(TXDETRX_LOCK_ACK, 0).is_err());
        assert!(r.write(PIPE_STATUS, 0).is_err());
        assert!(!Registers::claims(CONFIG + 4));
        assert!(r.read(CONTROL).is_err());
    }
}

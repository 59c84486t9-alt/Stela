//! Digital USB2 portion of `atc-phy,t8112`, including the pipehandler.
//!
//! Linux `drivers/phy/apple/atc.c` at a0ff06b3 supplies the USB2, core-power,
//! AUSPLL request/ack and pipehandler fields below. Original
//! `AppleT8103TypeCPhy::configureUSB2` (26A434 KC file 0x3148278) performs
//! full32 RMWs of USBCTL/CTL/SIG (0x31487ac, 0x3148b68, 0x31490ec).
//! `initRegisterSpaces` (0x3147734) maps the ADT's views; the views at
//! core+0x2000 and core+0x20000 alias the same physical words. Only canonical
//! offsets are stored, never the sum of the 29 ADT register lengths.
//!
//! Stela boot handoff leaves USB2 isolated, reset and in SIDDQ; the core is
//! clamped, with sleep requests and reset releases clear; PIPE is clamped and
//! reset. Configuration/tuning words start zero and retain documented writes.
//! These are emulated-die handoff choices, not captured iBoot/reset values.
//! Power and lock handshakes settle synchronously. SuperSpeed, DP and USB4
//! commands/links are unsupported; configuring their digital mux does not
//! establish a link. The AUSPLL's DP programming command 0x2800 refuses.
//!
//! View 1 is the core event block. `configureUSB2` sets its
//! `AUSBC_CORE_EVT_BLK_C0_USB2_CTL` LOAD_CNT (bit 3) and EVT_EN (bit 0) bits
//! (0x3149ad8 and 0x3149c40, named by the driver's own log strings). They are
//! retained. After ungating the USB2 PHY clocks it reads
//! `C0_UTMI_CLK_ACTIVE.EVT_CNT` at +0x20 (0x314a1f4) and only logs "EVT_CNT
//! is 0" when it is zero; both outcomes continue identically. Inferred: the
//! UTMI clock runs while the PHY is out of RESET and SIDDQ with its reference
//! clock ungated (Linux MISCTUNE bit 30, REFCLK_GATE_OFF), and setting
//! LOAD_CNT restarts the count. The model has no UTMI cycle clock, so the
//! count reports one event once the clock has been active with EVT_EN set,
//! not elapsed cycles. The block's other words refuse.
use super::{
    bus::{Access, Direction, MmioDevice, MmioError, Width, refuse},
    regfile::Held,
};

const NAME: &str = "Apple ATC PHY";
/// Logical device offsets, independent of physical placement or ADT view index.
pub const USB2: u64 = 0x10_0000;
pub const PIPE: u64 = 0x20_0000;
pub const EVENTS: u64 = 0x30_0000;
const USB2_EVENTS: u64 = EVENTS;
const EVENT_ENABLE: u32 = 1;
const LOAD_COUNT: u32 = 1 << 3;
const UTMI_CLOCK_EVENTS: u64 = EVENTS + 0x20;
const REFCLK_GATE_OFF: u32 = 1 << 30;
pub const CORE_BYTES: u64 = 0x4c000;
pub const WINDOW_BYTES: u64 = 0x4000;
const USBCTL: u64 = USB2;
const CTL: u64 = USB2 + 4;
const SIG: u64 = USB2 + 8;
const MISCTUNE: u64 = USB2 + 0x1c;
const RUN: u32 = 1 << 1;
const ISOLATE: u32 = 1 << 2;
const RESET: u32 = 1;
const PORT_RESET: u32 = 1 << 1;
const APB_RESET_N: u32 = 1 << 2;
const SIDDQ: u32 = 1 << 3;
const VBUS_FORCE: u32 = 0xf;
const HOST: u32 = 7 << 12;
const POWER_CTRL: u64 = 0x20000;
const POWER_STAT: u64 = 0x20004;
const MISC: u64 = 0x20008;
const SMALL: u32 = 1;
const BIG: u32 = 1 << 1;
const CLAMP: u32 = 1 << 2;
const CORE_APB_N: u32 = 1 << 3;
const CORE_PHY_N: u32 = 1 << 4;
const MISC_RESET_N: u32 = 1;
const LANE_SWAP: u32 = 1 << 2;
const PLL: u64 = 0x2000;
const REQUEST: u32 = 1;
const ACK: u32 = 1 << 1;
const PLL_COMMAND: u32 = 0x0fff_fff8;
const PLL_OVERRIDE: u32 = 1 << 28;
const COMMAND_READY: u64 = 0xa74;
const OVERRIDE: u64 = PIPE;
const OVERRIDE_VALUES: u64 = PIPE + 4;
const MUX: u64 = PIPE + 0xc;
const LOCK_REQ: u64 = PIPE + 0x10;
const LOCK_ACK: u64 = PIPE + 0x14;
const AON: u64 = PIPE + 0x1c;
const NONSELECTED: u64 = PIPE + 0x20;
const RESET_N: u32 = 1;
const FORCE_CLAMP: u32 = 1 << 4;
const LOCK: u32 = 1;
const MUX_CLOCK: u32 = 7 << 3;
const MUX_DATA: u32 = 7;

pub struct AtcPhy {
    held: Held,
    /// The UTMI clock has been active with EVT_EN since the last LOAD_CNT.
    utmi_clock_event: bool,
}
impl Default for AtcPhy {
    fn default() -> Self {
        Self::new()
    }
}
impl AtcPhy {
    pub fn new() -> Self {
        let mut held = Held::default();
        held.set(USBCTL, u64::from(ISOLATE));
        held.set(CTL, u64::from(RESET | PORT_RESET | SIDDQ));
        held.set(POWER_CTRL, u64::from(CLAMP));
        held.set(AON, u64::from(FORCE_CLAMP));
        Self {
            held,
            utmi_clock_event: false,
        }
    }
    fn sample_utmi_clock(&mut self) {
        let active =
            self.word(CTL) & (RESET | SIDDQ) == 0 && self.word(MISCTUNE) & REFCLK_GATE_OFF == 0;
        if active && self.word(USB2_EVENTS) & EVENT_ENABLE != 0 {
            self.utmi_clock_event = true;
        }
    }
    fn word(&self, offset: u64) -> u32 {
        self.held.get(offset) as u32
    }
    fn core_ready(&self) -> bool {
        self.word(POWER_CTRL) & (SMALL | BIG | CORE_APB_N) == (SMALL | BIG | CORE_APB_N)
            && self.word(MISC) & MISC_RESET_N != 0
    }
    /// Electrical USB2 readiness only. A controller must separately check its
    /// reset/clamp release and the shared Type-C port generation/role/VBUS.
    pub fn usb2_ready(&self) -> bool {
        self.word(USBCTL) & (RUN | ISOLATE) == RUN
            && self.word(CTL) & (RESET | PORT_RESET | APB_RESET_N | SIDDQ) == APB_RESET_N
    }
    pub fn controller_released(&self) -> bool {
        self.word(AON) & (RESET_N | FORCE_CLAMP) == RESET_N
    }
    /// No active SuperSpeed/DP/USB4 receiver exists in this digital profile.
    pub fn superspeed_link(&self) -> bool {
        false
    }
    fn mask(offset: u64) -> Option<u32> {
        Some(match offset {
            USBCTL => RUN | ISOLATE,
            CTL => RESET | PORT_RESET | APB_RESET_N | SIDDQ,
            SIG => VBUS_FORCE | HOST,
            // Full32 tuning storage; Linux names bits29/30 as clock gating.
            // Analog trim values are retained, with no analog calibration claim.
            MISCTUNE => u32::MAX,
            POWER_CTRL => SMALL | BIG | CLAMP | CORE_APB_N | CORE_PHY_N,
            MISC => MISC_RESET_N | LANE_SWAP,
            PLL => REQUEST | ACK | PLL_COMMAND | PLL_OVERRIDE,
            OVERRIDE => 1 | 1 << 2,
            OVERRIDE_VALUES => 1 << 1 | 1 << 2 | 1 << 4,
            MUX => MUX_CLOCK | MUX_DATA,
            LOCK_REQ => LOCK,
            AON => RESET_N | FORCE_CLAMP,
            NONSELECTED => 0xf | 1 << 12 | 1 << 15,
            USB2_EVENTS => EVENT_ENABLE | LOAD_COUNT,
            // Public AUSPLL FSM override and common wait-for-ready tuning.
            0x1014 => 0x1ff << 13,
            0x1028 => 1 << 24,
            _ => return None,
        })
    }
}
impl MmioDevice for AtcPhy {
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let err = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(err("ATC PHY registers require aligned 32-bit accesses"));
        }
        let value = match offset {
            POWER_STAT => self.word(POWER_CTRL) & (SMALL | BIG),
            COMMAND_READY => u32::from(self.core_ready()),
            LOCK_ACK => self.word(LOCK_REQ) & LOCK,
            UTMI_CLOCK_EVENTS => {
                self.sample_utmi_clock();
                u32::from(self.utmi_clock_event)
            }
            PLL => {
                self.word(PLL) & !ACK
                    | if self.word(PLL) & REQUEST != 0 && self.core_ready() {
                        ACK
                    } else {
                        0
                    }
            }
            _ if Self::mask(offset).is_some() => self.word(offset),
            _ => {
                return Err(err(
                    "unmodeled ATC PHY register, analog status or transport",
                ));
            }
        };
        Ok(u64::from(value))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let err = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(err("ATC PHY registers require aligned 32-bit accesses"));
        }
        let mask = Self::mask(offset)
            .ok_or_else(|| err("unmodeled ATC PHY register or read-only status"))?;
        let value = value as u32;
        if value & !mask != 0 {
            return Err(err("unmodeled ATC PHY register fields"));
        }
        if offset == PLL && value & REQUEST != 0 && value & PLL_COMMAND != 0 {
            return Err(err(
                "AUSPLL command effects beyond command zero are undetermined",
            ));
        }
        if offset == MUX
            && (!matches!((value & MUX_CLOCK) >> 3, 0 | 1 | 2 | 4) || value & MUX_DATA > 2)
        {
            return Err(err("reserved pipehandler clock/data mux selection"));
        }
        if offset == USB2_EVENTS && value & !self.word(offset) & LOAD_COUNT != 0 {
            self.utmi_clock_event = false;
        }
        // ACK is a hardware response even when included by a guest RMW.
        self.held.set(
            offset,
            u64::from(if offset == PLL { value & !ACK } else { value }),
        );
        self.sample_utmi_clock();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::{bus::Bus, interrupt::InterruptLatch};
    use alloc::boxed::Box;
    fn wr(p: &mut AtcPhy, a: &mut Access<'_>, o: u64, v: u32) {
        p.write(o, Width::Word, v.into(), a).unwrap();
    }
    fn rd(p: &mut AtcPhy, a: &mut Access<'_>, o: u64) -> u64 {
        p.read(o, Width::Word, a).unwrap()
    }
    #[test]
    fn usb2_reset_isolation_and_controller_reset_gate_readiness() {
        let mut p = AtcPhy::new();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        assert!(!p.usb2_ready());
        assert!(!p.controller_released());
        wr(&mut p, &mut a, SIG, VBUS_FORCE);
        wr(&mut p, &mut a, CTL, APB_RESET_N);
        wr(&mut p, &mut a, USBCTL, RUN | ISOLATE);
        assert!(!p.usb2_ready());
        wr(&mut p, &mut a, USBCTL, RUN);
        assert!(p.usb2_ready());
        wr(&mut p, &mut a, AON, RESET_N);
        assert!(p.controller_released());
        assert!(!p.superspeed_link());
        wr(&mut p, &mut a, CTL, APB_RESET_N | PORT_RESET);
        assert!(!p.usb2_ready());
        wr(&mut p, &mut a, MISCTUNE, 0x12345678);
        assert_eq!(rd(&mut p, &mut a, MISCTUNE), 0x12345678);
        // configureUSB2 loads and enables the USB2 core event counter. The
        // UTMI clock is stopped in PHY reset, gated...
        wr(&mut p, &mut a, CTL, APB_RESET_N | RESET);
        assert_eq!(rd(&mut p, &mut a, USB2_EVENTS), 0);
        wr(&mut p, &mut a, USB2_EVENTS, LOAD_COUNT);
        wr(&mut p, &mut a, USB2_EVENTS, LOAD_COUNT | EVENT_ENABLE);
        assert_eq!(rd(&mut p, &mut a, USB2_EVENTS), 9);
        assert_eq!(rd(&mut p, &mut a, UTMI_CLOCK_EVENTS), 0);
        // ...by REFCLK_GATE_OFF (bit 30 of 0x12345678 is clear)...
        wr(&mut p, &mut a, MISCTUNE, 0x12345678 | REFCLK_GATE_OFF);
        wr(&mut p, &mut a, CTL, APB_RESET_N | PORT_RESET);
        assert_eq!(rd(&mut p, &mut a, UTMI_CLOCK_EVENTS), 0);
        // ...and runs once ungated, port reset aside.
        wr(&mut p, &mut a, MISCTUNE, 0x12345678);
        assert_eq!(rd(&mut p, &mut a, UTMI_CLOCK_EVENTS), 1);
        // A clock event persists until LOAD_CNT restarts the count.
        wr(&mut p, &mut a, CTL, APB_RESET_N | SIDDQ);
        assert_eq!(rd(&mut p, &mut a, UTMI_CLOCK_EVENTS), 1);
        wr(&mut p, &mut a, USB2_EVENTS, 0);
        wr(&mut p, &mut a, USB2_EVENTS, LOAD_COUNT);
        assert_eq!(rd(&mut p, &mut a, UTMI_CLOCK_EVENTS), 0);
        assert!(p.write(UTMI_CLOCK_EVENTS, Width::Word, 0, &mut a).is_err());
        assert!(p.write(USB2_EVENTS, Width::Word, 2, &mut a).is_err());
        assert!(p.read(EVENTS + 4, Width::Word, &mut a).is_err());
    }
    #[test]
    fn power_pll_and_pipe_lock_handshakes_follow_requests_in_both_directions() {
        let mut p = AtcPhy::new();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        wr(&mut p, &mut a, PLL, REQUEST | PLL_OVERRIDE);
        assert_eq!(rd(&mut p, &mut a, PLL) & u64::from(ACK), 0);
        wr(&mut p, &mut a, POWER_CTRL, SMALL | BIG | CORE_APB_N);
        wr(&mut p, &mut a, MISC, MISC_RESET_N);
        assert_eq!(rd(&mut p, &mut a, POWER_STAT), 3);
        assert_eq!(rd(&mut p, &mut a, COMMAND_READY), 1);
        assert_ne!(rd(&mut p, &mut a, PLL) & u64::from(ACK), 0);
        wr(&mut p, &mut a, PLL, PLL_OVERRIDE | ACK);
        assert_eq!(rd(&mut p, &mut a, PLL), u64::from(PLL_OVERRIDE));
        wr(&mut p, &mut a, LOCK_REQ, 1);
        assert_eq!(rd(&mut p, &mut a, LOCK_ACK), 1);
        wr(&mut p, &mut a, LOCK_REQ, 0);
        assert_eq!(rd(&mut p, &mut a, LOCK_ACK), 0);
        wr(&mut p, &mut a, POWER_CTRL, CLAMP);
        assert_eq!(rd(&mut p, &mut a, POWER_STAT), 0);
        assert_eq!(rd(&mut p, &mut a, COMMAND_READY), 0);
    }
    #[test]
    fn aliased_core_views_share_storage_and_unknowns_refuse_without_changes() {
        let mut bus = Bus::new();
        let id = bus.add(Box::new(AtcPhy::new()));
        // One physical union; a driver's reg[3]+0x20000 and reg[2]+0
        // resolve to this same PA and model word.
        bus.map(id, 0x383000000, CORE_BYTES, 0).unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        bus.write(0x383020000, Width::Word, 3, &mut a).unwrap();
        assert_eq!(
            bus.read(0x383000000 + POWER_STAT, Width::Word, &mut a),
            Ok(3)
        );
        assert!(
            bus.write(0x383020000, Width::Word, 0x80000000, &mut a)
                .is_err()
        );
        assert_eq!(bus.read(0x383020000, Width::Word, &mut a), Ok(3));
        for (o, w) in [(0x1234, Width::Word), (POWER_CTRL, Width::Double)] {
            assert!(bus.read(0x383000000 + o, w, &mut a).is_err());
        }
        assert!(
            bus.write(
                0x383000000 + PLL,
                Width::Word,
                REQUEST as u64 | (0x2800 << 3),
                &mut a
            )
            .is_err()
        );
        assert_eq!(bus.read(0x383000000 + PLL, Width::Word, &mut a), Ok(0));
    }
}

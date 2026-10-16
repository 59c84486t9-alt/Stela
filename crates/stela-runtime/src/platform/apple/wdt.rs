//! The Apple SoC watchdog (`apple,t8112-wdt`, `apple,wdt`; ADT `/arm-io/wdt`).
//! A bite never resets the host: it becomes a [`super::bus::ResetRequest`]
//! that the engine reports when it stops the guest.
//!
//! Documented by Linux `drivers/watchdog/apple_wdt.c` and m1n1 `src/wdt.c`:
//! three watchdogs, each with CUR_TIME (a writable counter that increments
//! once per reference-clock tick), BITE_TIME and CTRL (IRQ_EN 0, IRQ_STATUS 1,
//! RESET_EN 2). The machine resets while RESET_EN is set and
//! CUR_TIME >= BITE_TIME; WD0 resets into recovery, WD1 and WD2 reset normally.
//! WD0 also has BARK_TIME; whenever IRQ_EN is set and CUR_TIME >= BARK_TIME
//! its interrupt and IRQ_STATUS are raised; writing 1 clears IRQ_STATUS. The reference
//! clock is the 24 MHz `clkref`, the system counter's rate.
//!
//! Inferred, not documented: CUR_TIME is a 32-bit count that wraps; the
//! interrupt output follows IRQ_STATUS while IRQ_EN is set; every watchdog starts
//! disarmed at zero, as m1n1 leaves the primary one, and BITE_TIME/BARK_TIME
//! are refused until written because their reset values are not known.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use super::interrupt::{AicInput, Wire};

const NAME: &str = "apple-wdt";

const CTRL_IRQ_EN: u32 = 1;
const CTRL_IRQ_STATUS: u32 = 1 << 1;
const CTRL_RESET_EN: u32 = 1 << 2;

const CUR_TIME: u64 = 0x0;
const BITE_TIME: u64 = 0x4;
const BARK_TIME: u64 = 0x8;
const CTRL: u64 = 0xc;
const STRIDE: u64 = 0x10;
const WATCHDOGS: usize = 3;

#[derive(Debug, Clone, Copy, Default)]
struct Watchdog {
    /// Counter value at which CUR_TIME was 0.
    base: u64,
    /// Counter value of the last evaluation.
    evaluated: u64,
    bite: Option<u32>,
    bark: Option<u32>,
    control: u32,
}
impl Watchdog {
    fn current(&self, now: u64) -> u32 {
        now.wrapping_sub(self.base) as u32
    }
    /// Whether CUR_TIME reached `target` in `(evaluated, now]`, or already
    /// was at or past it at `evaluated`.
    fn reached(&self, target: u32, now: u64) -> bool {
        let start = self.current(self.evaluated);
        start >= target || now - self.evaluated >= u64::from(target - start)
    }
    fn deadline(&self, target: u32, now: u64) -> u64 {
        let current = self.current(now);
        if current >= target {
            now
        } else {
            now.saturating_add(u64::from(target - current))
        }
    }
}

pub struct AppleWdt {
    watchdogs: [Watchdog; WATCHDOGS],
    irq: Option<AicInput>,
    irq_level: bool,
}
impl AppleWdt {
    /// `irq` is the node's DeviceTree `interrupts` AIC input; `now` the
    /// counter value at which every CUR_TIME reads 0.
    pub fn new(irq: Option<AicInput>, now: u64) -> Self {
        let watchdog = Watchdog {
            base: now,
            evaluated: now,
            ..Watchdog::default()
        };
        Self {
            watchdogs: [watchdog; WATCHDOGS],
            irq,
            irq_level: false,
        }
    }
    fn evaluate(&mut self, access: &mut Access<'_>) -> Option<u64> {
        let now = access.now;
        let mut next: Option<u64> = None;
        let mut earliest =
            |deadline: u64| next = Some(next.map_or(deadline, |next| next.min(deadline)));
        for (index, watchdog) in self.watchdogs.iter_mut().enumerate() {
            if watchdog.control & CTRL_RESET_EN != 0
                && let Some(bite) = watchdog.bite
            {
                if watchdog.reached(bite, now) {
                    access.request_reset(
                        NAME,
                        if index == 0 {
                            "watchdog 0 bit: reset into recovery requested"
                        } else {
                            "watchdog bit: system reset requested"
                        },
                    );
                } else {
                    earliest(watchdog.deadline(bite, now));
                }
            }
            if watchdog.control & (CTRL_IRQ_EN | CTRL_IRQ_STATUS) == CTRL_IRQ_EN
                && let Some(bark) = watchdog.bark
            {
                if watchdog.reached(bark, now) {
                    watchdog.control |= CTRL_IRQ_STATUS;
                } else {
                    earliest(watchdog.deadline(bark, now));
                }
            }
            watchdog.evaluated = now;
        }
        let level = self.watchdogs[0].control & (CTRL_IRQ_EN | CTRL_IRQ_STATUS)
            == CTRL_IRQ_EN | CTRL_IRQ_STATUS;
        if level != self.irq_level {
            self.irq_level = level;
            if let Some(irq) = self.irq {
                access.interrupts.set_level(Wire::Aic(irq), level);
            }
        }
        next
    }
    fn decode(offset: u64) -> Option<(usize, u64)> {
        let index = usize::try_from(offset / STRIDE)
            .ok()
            .filter(|&index| index < WATCHDOGS)?;
        let register = offset % STRIDE;
        (register != BARK_TIME || index == 0).then_some((index, register))
    }
}

impl MmioDevice for AppleWdt {
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(
        &mut self,
        offset: u64,
        width: Width,
        access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        if width != Width::Word {
            return Err(fail("watchdog registers are 32-bit"));
        }
        let (index, register) =
            Self::decode(offset).ok_or_else(|| fail("unknown watchdog register"))?;
        self.evaluate(access);
        let watchdog = &self.watchdogs[index];
        let value = match register {
            CUR_TIME => watchdog.current(access.now),
            BITE_TIME => watchdog
                .bite
                .ok_or_else(|| fail("BITE_TIME read before the guest wrote it"))?,
            BARK_TIME => watchdog
                .bark
                .ok_or_else(|| fail("BARK_TIME read before the guest wrote it"))?,
            _ => watchdog.control,
        };
        Ok(u64::from(value))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        if width != Width::Word {
            return Err(fail("watchdog registers are 32-bit"));
        }
        let (index, register) =
            Self::decode(offset).ok_or_else(|| fail("unknown watchdog register"))?;
        self.evaluate(access);
        let value = value as u32;
        let watchdog = &mut self.watchdogs[index];
        match register {
            CUR_TIME => watchdog.base = access.now.wrapping_sub(u64::from(value)),
            BITE_TIME => watchdog.bite = Some(value),
            BARK_TIME => watchdog.bark = Some(value),
            _ => {
                if value & !(CTRL_IRQ_EN | CTRL_IRQ_STATUS | CTRL_RESET_EN) != 0 {
                    return Err(fail("watchdog CTRL reserved field is not modeled"));
                }
                if index != 0 && value & CTRL_IRQ_EN != 0 {
                    return Err(fail("only watchdog 0 has a bark interrupt"));
                }
                let status = watchdog.control & CTRL_IRQ_STATUS & !value;
                watchdog.control = value & !CTRL_IRQ_STATUS | status;
            }
        }
        self.evaluate(access);
        Ok(())
    }
    fn advance(&mut self, access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        Ok(self.evaluate(access))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;

    const WD1: u64 = STRIDE;
    const IRQ: AicInput = AicInput::new(0, 379);

    fn write(
        wdt: &mut AppleWdt,
        latch: &mut InterruptLatch,
        now: u64,
        offset: u64,
        value: u32,
    ) -> Option<&'static str> {
        let mut access = Access::new(0, now, latch);
        wdt.write(offset, Width::Word, value.into(), &mut access)
            .unwrap();
        access.reset_request().map(|request| request.reason)
    }
    fn advance(wdt: &mut AppleWdt, latch: &mut InterruptLatch, now: u64) -> (Option<u64>, bool) {
        let mut access = Access::new(0, now, latch);
        let next = wdt.advance(&mut access).unwrap();
        (next, access.reset_request().is_some())
    }

    /// Linux `apple_wdt_set_timeout`, `apple_wdt_start` and `apple_wdt_ping`.
    #[test]
    fn linux_keepalive_then_expiry() {
        let mut latch = InterruptLatch::new();
        let mut wdt = AppleWdt::new(Some(IRQ), 0);
        let timeout = 24_000_000 * 30;
        assert_eq!(write(&mut wdt, &mut latch, 0, WD1 + CUR_TIME, 0), None);
        write(&mut wdt, &mut latch, 0, WD1 + BITE_TIME, timeout);
        write(&mut wdt, &mut latch, 10, WD1 + CUR_TIME, 0);
        assert_eq!(
            write(&mut wdt, &mut latch, 10, WD1 + CTRL, CTRL_RESET_EN),
            None
        );
        assert_eq!(
            advance(&mut wdt, &mut latch, 1000),
            (Some(10 + u64::from(timeout)), false)
        );
        let mut access = Access::new(0, 1000, &mut latch);
        assert_eq!(wdt.read(WD1 + CUR_TIME, Width::Word, &mut access), Ok(990));
        write(&mut wdt, &mut latch, 1000, WD1 + CUR_TIME, 0);
        assert_eq!(
            advance(&mut wdt, &mut latch, 1000 + u64::from(timeout) - 1),
            (Some(1000 + u64::from(timeout)), false)
        );
        assert!(advance(&mut wdt, &mut latch, 1000 + u64::from(timeout)).1);
    }

    /// Linux `apple_wdt_restart` and m1n1 `wdt_reboot` request a reset; the
    /// model reports it rather than resetting.
    #[test]
    fn restart_is_surfaced_as_a_reset_request() {
        let mut latch = InterruptLatch::new();
        let mut wdt = AppleWdt::new(None, 0);
        assert_eq!(
            write(&mut wdt, &mut latch, 5, WD1 + CTRL, CTRL_RESET_EN),
            None,
            "no BITE_TIME yet"
        );
        assert_eq!(
            write(&mut wdt, &mut latch, 6, WD1 + BITE_TIME, 0),
            Some("watchdog bit: system reset requested")
        );
        let mut wdt = AppleWdt::new(None, 0);
        write(&mut wdt, &mut latch, 0, WD1 + BITE_TIME, 0x10_0000);
        write(&mut wdt, &mut latch, 0, WD1 + CUR_TIME, 0);
        write(&mut wdt, &mut latch, 0, WD1 + CTRL, CTRL_RESET_EN);
        assert!(advance(&mut wdt, &mut latch, 0x10_0000).1);
    }

    #[test]
    fn late_evaluation_still_bites_after_wrap() {
        let mut latch = InterruptLatch::new();
        let mut wdt = AppleWdt::new(None, 0);
        write(&mut wdt, &mut latch, 0, WD1 + BITE_TIME, 100);
        write(&mut wdt, &mut latch, 0, WD1 + CTRL, CTRL_RESET_EN);
        assert!(advance(&mut wdt, &mut latch, (1 << 32) + 50).1);
    }

    #[test]
    fn bark_interrupt_latches_and_clears() {
        let mut latch = InterruptLatch::new();
        let mut wdt = AppleWdt::new(Some(IRQ), 0);
        write(&mut wdt, &mut latch, 0, BARK_TIME, 50);
        write(&mut wdt, &mut latch, 0, CTRL, CTRL_IRQ_EN);
        assert_eq!(advance(&mut wdt, &mut latch, 10), (Some(50), false));
        advance(&mut wdt, &mut latch, 60);
        assert!(latch.is_asserted(Wire::Aic(IRQ)));
        let mut access = Access::new(0, 60, &mut latch);
        assert_eq!(
            wdt.read(CTRL, Width::Word, &mut access),
            Ok(u64::from(CTRL_IRQ_EN | CTRL_IRQ_STATUS))
        );
        write(
            &mut wdt,
            &mut latch,
            60,
            CTRL,
            CTRL_IRQ_EN | CTRL_IRQ_STATUS,
        );
        assert!(
            latch.is_asserted(Wire::Aic(IRQ)),
            "the condition still holds"
        );
        write(&mut wdt, &mut latch, 60, CUR_TIME, 0);
        write(
            &mut wdt,
            &mut latch,
            60,
            CTRL,
            CTRL_IRQ_EN | CTRL_IRQ_STATUS,
        );
        assert!(!latch.is_asserted(Wire::Aic(IRQ)));
        assert_eq!(advance(&mut wdt, &mut latch, 70), (Some(110), false));
    }

    #[test]
    fn refuses_unknown_registers_and_fields() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut wdt = AppleWdt::new(None, 0);
        for offset in [WD1 + BARK_TIME, 0x30, BITE_TIME] {
            assert!(
                wdt.read(offset, Width::Word, &mut access).is_err(),
                "{offset:#x}"
            );
        }
        assert!(
            wdt.write(WD1 + CTRL, Width::Word, u64::from(CTRL_IRQ_EN), &mut access)
                .is_err()
        );
        assert!(wdt.write(CTRL, Width::Word, 1 << 3, &mut access).is_err());
        assert!(wdt.read(CUR_TIME, Width::Byte, &mut access).is_err());
    }
}

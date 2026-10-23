// SPDX-License-Identifier: GPL-2.0-only
// Controller quirks adapted from Linux xhci-pci.c and pci-quirks.c at
// a804c5742bff224d4cb4d25dd383554d598be32b.
//! Actual PCI-revision quirks; no device identity grants DMA isolation.
use super::*;
use crate::bus::pci::ConfigSpace;

const ASMEDIA: u16 = 0x1b21;
const ASMEDIA_FLOW_CONTROL: u16 = 0x1142;
const ASMEDIA_CONTROL: u16 = 0xe0;
const ASMEDIA_DATA0: u16 = 0xf8;
const ASMEDIA_DATA1: u16 = 0xfc;
const ASMEDIA_WRITE: u8 = 2;
const ASMEDIA_WRITE_COMMAND: u32 = 0x10423;
const ASMEDIA_FLOW_ADDRESS: u32 = 0xfa30;
const ASMEDIA_FLOW_VALUE: u32 = 0xba;
const ASMEDIA_RETRIES: usize = 1000;
const ASMEDIA_POLL_US: u64 = 50;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Profile {
    pub interval_limit: Option<u32>,
    pub slow_suspend: bool,
    pub suspend_delay: bool,
    pub reset_on_resume: bool,
    pub renesas_stale_high: bool,
}
impl Profile {
    pub fn pci<C: ConfigSpace>(function: &mut Function<C>) -> Result<Self, BlockError> {
        // Read back the actual owner. A copied Function identity is not proof.
        streams::pci_policy(function)?;
        let revision = function.config().read8(8);
        if (function.vendor, function.device, revision) == (0x1b73, 0x1000, 0) {
            return Err(BlockError::Unsupported(
                "Fresco evaluation controller requires deprecated reset-endpoint quirk",
            ));
        }
        Ok(Self::identity(function.vendor, function.device, revision))
    }
    fn identity(vendor: u16, device: u16, revision: u8) -> Self {
        Self {
            interval_limit: match (vendor, device) {
                (0x1022, 0x13ed | 0x13ee | 0x148c | 0x15d4 | 0x15d5 | 0x15e0 | 0x15e1 | 0x15e5)
                | (0x1002, 0x7316) => Some(9),
                (0x104c, 0x8241) => Some(7),
                _ => None,
            },
            slow_suspend: (vendor, device, revision) == (0x1b73, 0x1000, 4),
            suspend_delay: vendor == 0x1022 && matches!(device, 0x145c | 0x15e0 | 0x15e1 | 0x43bb),
            reset_on_resume: matches!(
                (vendor, device),
                (0x1022, 0x15e5)
                    | (0x1912, 0x0015)
                    | (0x1b21, 0x3042)
                    | (0x1b6f, 0x7023 | 0x7052)
                    // Both Zhaoxin IDs need ring overfetch, but only 9202
                    // requires fresh controller state after resume (xhci-pci.c).
                    | (0x1d17, 0x9202)
            ) || vendor == 0x1106,
            renesas_stale_high: vendor == 0x1912 && matches!(device, 0x0014 | 0x0015),
        }
    }
    pub fn endpoint(self, context: endpoint::Context) -> Result<endpoint::Context, BlockError> {
        if self
            .interval_limit
            .is_some_and(|maximum| context.info >> 16 & 0xff > maximum)
        {
            // Linux shortens the interval. Preserve the requested service contract
            // until that negotiation can be reflected to the USB owner instead.
            return Err(BlockError::Unsupported(
                "endpoint interval exceeds controller quirk limit",
            ));
        }
        Ok(context)
    }
}

fn asmedia_ready<C: ConfigSpace>(config: &mut C, clock: Clock) -> Result<(), BlockError> {
    for _ in 0..ASMEDIA_RETRIES {
        let control = config.read8(ASMEDIA_CONTROL);
        if control == u8::MAX {
            return Err(BlockError::Unsupported(
                "ASMedia PCI function disappeared during flow control",
            ));
        }
        if control & ASMEDIA_WRITE == 0 {
            return Ok(());
        }
        clock.delay(ASMEDIA_POLL_US);
    }
    Err(BlockError::Timeout)
}

/// After HCRST has completed, before any controller ring is published. Keep
/// the real PCI owner borrowed until both mailbox writes acknowledge.
pub(super) fn after_reset<C: ConfigSpace>(
    function: &mut Function<C>,
    clock: Clock,
) -> Result<(), BlockError> {
    streams::pci_policy(function)?;
    if (function.vendor, function.device) != (ASMEDIA, ASMEDIA_FLOW_CONTROL) {
        return Ok(());
    }
    let config = function.config();
    asmedia_ready(config, clock)?;
    config.write32(ASMEDIA_DATA0, ASMEDIA_WRITE_COMMAND);
    config.write32(ASMEDIA_DATA1, ASMEDIA_FLOW_ADDRESS);
    config.write8(ASMEDIA_CONTROL, ASMEDIA_WRITE);
    asmedia_ready(config, clock)?;
    config.write32(ASMEDIA_DATA0, ASMEDIA_FLOW_VALUE);
    config.write32(ASMEDIA_DATA1, 0);
    config.write8(ASMEDIA_CONTROL, ASMEDIA_WRITE);
    asmedia_ready(config, clock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::pci::Address;
    use core::cell::Cell;

    struct Config {
        id: u32,
        control: Cell<u8>,
        writes: Vec<(u16, u32, u8)>,
        acknowledge: bool,
    }
    impl ConfigSpace for Config {
        fn read32(&self, at: u16) -> u32 {
            match at {
                0 => self.id,
                8 => 0x0c03_3000,
                _ => 0,
            }
        }
        fn read8(&self, at: u16) -> u8 {
            if at == ASMEDIA_CONTROL {
                let value = self.control.get();
                if self.acknowledge {
                    self.control.set(0);
                }
                value
            } else {
                (self.read32(at & !3) >> ((at & 3) * 8)) as u8
            }
        }
        fn write32(&mut self, at: u16, value: u32) {
            self.writes.push((at, value, 4));
        }
        fn write8(&mut self, at: u16, value: u8) {
            self.writes.push((at, u32::from(value), 1));
            if at == ASMEDIA_CONTROL {
                self.control.set(value);
            }
        }
    }
    fn function(acknowledge: bool) -> Function<Config> {
        Function::new(
            Address {
                segment: 0,
                bus: 0,
                device: 1,
                function: 0,
            },
            Config {
                id: u32::from(ASMEDIA) | u32::from(ASMEDIA_FLOW_CONTROL) << 16,
                control: Cell::new(0),
                writes: Vec::new(),
                acknowledge,
            },
        )
        .unwrap()
    }
    #[test]
    fn actual_asmedia_owner_acknowledges_both_mailbox_phases_with_narrow_control_stores() {
        let mut f = function(true);
        after_reset(
            &mut f,
            Clock {
                ticks_per_microsecond: 1,
            },
        )
        .unwrap();
        assert_eq!(
            f.config().writes,
            [
                (ASMEDIA_DATA0, ASMEDIA_WRITE_COMMAND, 4),
                (ASMEDIA_DATA1, ASMEDIA_FLOW_ADDRESS, 4),
                (ASMEDIA_CONTROL, 2, 1),
                (ASMEDIA_DATA0, ASMEDIA_FLOW_VALUE, 4),
                (ASMEDIA_DATA1, 0, 4),
                (ASMEDIA_CONTROL, 2, 1),
            ]
        );
        let mut f = function(false);
        assert_eq!(
            after_reset(
                &mut f,
                Clock {
                    ticks_per_microsecond: 1
                }
            ),
            Err(BlockError::Timeout)
        );
        assert_eq!(f.config().writes.len(), 3);
        let mut f = function(true);
        f.config().control.set(u8::MAX);
        assert!(
            after_reset(
                &mut f,
                Clock {
                    ticks_per_microsecond: 1
                }
            )
            .is_err()
        );
        assert!(f.config().writes.is_empty());
    }
    #[test]
    fn endpoint_limits_are_exact_and_preserve_the_requested_service_contract() {
        let ep = Endpoint {
            address: 0x81,
            attributes: 3,
            max_packet: 64,
            interval: 16,
            companion: None,
        };
        let context = endpoint::Context::new(&ep, HIGH_SPEED).unwrap();
        assert!(
            Profile::identity(0x1022, 0x15e0, 0)
                .endpoint(context)
                .is_err()
        );
        let context = endpoint::Context::new(&ep, HIGH_SPEED).unwrap();
        assert!(
            Profile::identity(0x1022, 0x15b6, 0)
                .endpoint(context)
                .is_ok()
        );
        assert!(Profile::identity(0x1b73, 0x1000, 4).slow_suspend);
        assert!(!Profile::identity(0x1b73, 0x1000, 5).slow_suspend);
        assert!(Profile::identity(0x1912, 0x0014, 0).renesas_stale_high);
        assert!(!Profile::identity(0x1912, 0x0014, 0).reset_on_resume);
    }
}

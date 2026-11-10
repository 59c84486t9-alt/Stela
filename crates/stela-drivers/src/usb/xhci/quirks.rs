// SPDX-License-Identifier: GPL-2.0-only
// Controller quirks adapted from Linux xhci-pci.c and pci-quirks.c at
// a804c5742bff224d4cb4d25dd383554d598be32b.
//! PCI-revision quirks; no device identity grants DMA isolation.
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

/// XHCI_LIMIT_ENDPOINT_INTERVAL_7/9: the controller cannot schedule a
/// periodic endpoint at an xHCI interval of `limit` or more.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct IntervalLimit {
    pub limit: u32,
    /// Only high-speed and faster endpoints are limited.
    pub high_speed_only: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Profile {
    pub interval_limit: Option<IntervalLimit>,
    pub slow_suspend: bool,
    pub suspend_delay: bool,
    pub reset_on_resume: bool,
    pub renesas_stale_high: bool,
    /// XHCI_NO_SOFT_RETRY: transaction errors are not retried in place.
    pub no_soft_retry: bool,
}
impl Profile {
    pub fn pci<C: ConfigSpace>(function: &mut Function<C>) -> Result<Self, BlockError> {
        // Read back the owner. A copied Function identity is not proof.
        streams::pci_policy(function)?;
        let revision = function.config().read8(8).map_err(BlockError::Config)?;
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
                | (0x1002, 0x7316) => Some(IntervalLimit {
                    limit: 9,
                    high_speed_only: false,
                }),
                (0x104c, 0x8241) => Some(IntervalLimit {
                    limit: 7,
                    high_speed_only: true,
                }),
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
            // AMD Promontory A and Etron EJ168/EJ188.
            no_soft_retry: matches!(
                (vendor, device),
                (0x1022, 0x43b9 | 0x43bb) | (0x1b6f, 0x7023 | 0x7052)
            ),
        }
    }
    /// Linux `xhci_endpoint_init`'s periodic interval limit: an interrupt or
    /// isochronous endpoint of device `speed` whose interval reaches the
    /// controller's limit is serviced one step under it, twice as often as
    /// the descriptor asks, which every periodic USB endpoint tolerates.
    /// USB 2 hubs' 256 ms status endpoints need this on AMD controllers.
    pub fn endpoint(self, mut context: endpoint::Context, speed: u8) -> endpoint::Context {
        let periodic = matches!(context.info2 >> 3 & 7, 1 | 3 | 5 | 7);
        let interval = context.info >> 16 & 0xff;
        if let Some(IntervalLimit {
            limit,
            high_speed_only,
        }) = self.interval_limit
            && periodic
            && interval >= limit
            && (!high_speed_only || matches!(speed, HIGH_SPEED | SUPER_SPEED | SUPER_SPEED_PLUS))
        {
            context.info = context.info & !(0xff << 16) | (limit - 1) << 16;
        }
        context
    }
}

fn asmedia_ready<C: ConfigSpace>(config: &mut C, clock: Clock) -> Result<(), BlockError> {
    for _ in 0..ASMEDIA_RETRIES {
        let control = config.read8(ASMEDIA_CONTROL).map_err(BlockError::Config)?;
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
    config.write32(ASMEDIA_DATA0, ASMEDIA_WRITE_COMMAND)?;
    config
        .write32(ASMEDIA_DATA1, ASMEDIA_FLOW_ADDRESS)
        .map_err(|error| published(BlockError::Config(error), ASMEDIA_DATA0, 4))?;
    config
        .write8(ASMEDIA_CONTROL, ASMEDIA_WRITE)
        .map_err(|error| published(BlockError::Config(error), ASMEDIA_DATA1, 4))?;
    asmedia_ready(config, clock).map_err(|error| published(error, ASMEDIA_CONTROL, 1))?;
    config
        .write32(ASMEDIA_DATA0, ASMEDIA_FLOW_VALUE)
        .map_err(|error| published(BlockError::Config(error), ASMEDIA_CONTROL, 1))?;
    config
        .write32(ASMEDIA_DATA1, 0)
        .map_err(|error| published(BlockError::Config(error), ASMEDIA_DATA0, 4))?;
    config
        .write8(ASMEDIA_CONTROL, ASMEDIA_WRITE)
        .map_err(|error| published(BlockError::Config(error), ASMEDIA_DATA1, 4))?;
    asmedia_ready(config, clock).map_err(|error| published(error, ASMEDIA_CONTROL, 1))
}

fn published(error: BlockError, offset: u16, width: u8) -> BlockError {
    match error {
        BlockError::Config(error) if error.effect == crate::bus::pci::ConfigEffect::None => {
            BlockError::Config(crate::bus::pci::ConfigError::write_may_have_applied(
                offset,
                width,
                error.reason,
            ))
        }
        error => error,
    }
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
        fn read32(&self, at: u16) -> core::result::Result<u32, crate::bus::pci::ConfigError> {
            Ok({
                match at {
                    0 => self.id,
                    8 => 0x0c03_3000,
                    _ => 0,
                }
            })
        }
        fn read8(&self, at: u16) -> core::result::Result<u8, crate::bus::pci::ConfigError> {
            Ok({
                if at == ASMEDIA_CONTROL {
                    let value = self.control.get();
                    if self.acknowledge {
                        self.control.set(0);
                    }
                    value
                } else {
                    (self.read32(at & !3)? >> ((at & 3) * 8)) as u8
                }
            })
        }
        fn write32(
            &mut self,
            at: u16,
            value: u32,
        ) -> core::result::Result<(), crate::bus::pci::ConfigError> {
            self.writes.push((at, value, 4));

            Ok(())
        }
        fn write8(
            &mut self,
            at: u16,
            value: u8,
        ) -> core::result::Result<(), crate::bus::pci::ConfigError> {
            self.writes.push((at, u32::from(value), 1));
            if at == ASMEDIA_CONTROL {
                self.control.set(value);
            }

            Ok(())
        }

        fn read16(&self, offset: u16) -> core::result::Result<u16, crate::bus::pci::ConfigError> {
            Ok((self.read32(offset & !3)? >> ((offset & 2) * 8)) as u16)
        }
        fn write16(
            &mut self,
            offset: u16,
            value: u16,
        ) -> core::result::Result<(), crate::bus::pci::ConfigError> {
            let shift = (offset & 2) * 8;
            let word = self.read32(offset & !3)? & !(0xffff << shift) | u32::from(value) << shift;
            self.write32(offset & !3, word)
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
    fn asmedia_owner_acknowledges_both_mailbox_phases_with_narrow_control_stores() {
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
    fn interval(context: &endpoint::Context) -> u32 {
        context.info >> 16 & 0xff
    }
    fn endpoint(attributes: u8, max_packet: u16, interval: u8) -> Endpoint {
        Endpoint {
            address: 0x81,
            attributes,
            max_packet,
            interval,
            companion: None,
        }
    }
    #[test]
    fn amd_controllers_shorten_a_high_speed_hub_status_interval() {
        // A USB 2 hub's status endpoint: bInterval 12, xHCI interval 11.
        let hub = endpoint(3, 1, 12);
        let context = endpoint::Context::new(&hub, HIGH_SPEED).unwrap();
        assert_eq!(interval(&context), 11);
        let context = Profile::identity(0x1022, 0x15e0, 0).endpoint(context, HIGH_SPEED);
        assert_eq!(interval(&context), 8);
        // A 255 ms full-speed keyboard endpoint is limited too.
        let keyboard = endpoint(3, 8, 255);
        let context = endpoint::Context::new(&keyboard, FULL_SPEED).unwrap();
        assert_eq!(interval(&context), 10);
        let context = Profile::identity(0x1022, 0x148c, 0).endpoint(context, FULL_SPEED);
        assert_eq!(interval(&context), 8);
        // Under the limit, and on other controllers, the interval stands.
        let fast = endpoint(3, 64, 8);
        let context = endpoint::Context::new(&fast, HIGH_SPEED).unwrap();
        assert_eq!(
            Profile::identity(0x1022, 0x15e0, 0).endpoint(context, HIGH_SPEED),
            endpoint::Context::new(&fast, HIGH_SPEED).unwrap()
        );
        let context = endpoint::Context::new(&hub, HIGH_SPEED).unwrap();
        assert_eq!(
            interval(&Profile::identity(0x1022, 0x15b6, 0).endpoint(context, HIGH_SPEED)),
            11
        );
    }
    #[test]
    fn the_ti_limit_leaves_full_speed_and_bulk_endpoints_alone() {
        let ti = Profile::identity(0x104c, 0x8241, 0);
        let hub = endpoint(3, 1, 12);
        let context = endpoint::Context::new(&hub, HIGH_SPEED).unwrap();
        assert_eq!(interval(&ti.endpoint(context, HIGH_SPEED)), 6);
        let keyboard = endpoint(3, 8, 255);
        let context = endpoint::Context::new(&keyboard, FULL_SPEED).unwrap();
        assert_eq!(interval(&ti.endpoint(context, FULL_SPEED)), 10);
        // A high-speed bulk endpoint's NAK interval is not periodic.
        let bulk = endpoint(2, 512, 255);
        let context = endpoint::Context::new(&bulk, HIGH_SPEED).unwrap();
        assert_eq!(interval(&context), 7);
        assert_eq!(interval(&ti.endpoint(context, HIGH_SPEED)), 7);
    }
    #[test]
    fn profiles_follow_the_controller_identity() {
        assert!(Profile::identity(0x1b73, 0x1000, 4).slow_suspend);
        assert!(!Profile::identity(0x1b73, 0x1000, 5).slow_suspend);
        assert!(Profile::identity(0x1912, 0x0014, 0).renesas_stale_high);
        assert!(!Profile::identity(0x1912, 0x0014, 0).reset_on_resume);
        assert!(Profile::identity(0x1022, 0x43bb, 0).no_soft_retry);
        assert!(Profile::identity(0x1b6f, 0x7052, 0).no_soft_retry);
        assert!(!Profile::identity(0x1022, 0x43f7, 0).no_soft_retry);
    }
    mod config_access;
}

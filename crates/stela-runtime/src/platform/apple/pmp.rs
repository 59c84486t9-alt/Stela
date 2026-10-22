//! The power management processor's application endpoint, native at its
//! RTKit boundary: the `PMPEndpoint1` protocol ApplePMPv2 speaks on
//! endpoint 0x20. The PMP's PTD duties are [`super::ptd`]'s.
//!
//! Evidence (26A434 J473AP kernel, KC file offsets): `/arm-io/pmgr` `pmp`
//! = 2 makes `ApplePMPv2::probe` (0x2bd9884) outbid ApplePMP's score of 1
//! (0x2bd147c), so ApplePMPv2 drives the endpoint; ApplePMP's
//! `pmp-msg-timout-panic` (`ApplePMP::start` 0x2bd1a54) is not on this path.
//! `ApplePMPv2::messageHandler` (0x2bce4f4) dispatches on the message class
//! in bits 55:52 and its kind in bits 51:48:
//!
//! - class 1, memory: the PMP's requests for AP memory (kind 0 init,
//!   `handleMemInitReq` 0x2bda2dc; 2 allocate, 0x2bcf2c0; 4 free,
//!   0x2bcf4a0), answered with class 1 replies;
//! - class 2, power management: kind 1 confirms the AP's ping
//!   (`handlePMMessage` 0x2bcf130). The ping is class 2 kind 0 with the low
//!   32 bits of the AP's time (`pingGated` 0x2bcef90); the AP waits a
//!   second for the confirmation and then reports kIOReturnTimeout;
//! - classes 3 and 4, registry: the PMP's requests to publish IORegistry
//!   entries (kinds 0 init, 2 add, 4 remove, 6 set), and kind 7 confirming
//!   an AP-side set (`handleRegistryMessage` 0x2bcf1c4).
//!
//! Every other class panics the AP ("Unknown message"), so the PMP must
//! not send one. Everything else is driven by the PMP: ApplePMPv2::start
//! (0x2bd9a38) sends nothing and waits for nothing on the endpoint. This
//! minimal endpoint has no firmware services that need AP memory or registry entries,
//! so it sends no requests: the AP then has no dashboard window, and
//! `writeDashboard` (0x2bcedc8) answers its callers with an error rather
//! than a write that goes nowhere. It answers the ping. The AP's registry
//! set requests (`setRegistryEntry`, from `setProperties`) and any other
//! AP message refuse.
//!
//! `PMPEndpoint2` (ApplePMPThermal, 0x2bd8818) is the fan: the PMP says
//! hello (class 0), and the AP then sets a target speed (class 2) and reads
//! the measured one (class 4, answered with class 5;
//! `_set_rpmGated`/`_get_rpmGated` 0x2bd8ce4/0x2bd8e20). The machine has no
//! fan whose speed could be measured, so the endpoint is not provided and
//! ApplePMPThermal does not start.
//!
//! [`native`] separately retains T6000 startup/exit resources and the actual
//! local PTD recipient. This ping endpoint supplies none of that backend's
//! memory, callback, power or readiness authority.
use super::rtkit::Endpoint;
use alloc::vec::Vec;

pub mod native;

pub const ENDPOINT: u8 = 0x20;

const CLASS_SHIFT: u32 = 52;
const KIND_SHIFT: u32 = 48;
const POWER_MANAGEMENT: u64 = 2;
const PING: u64 = 0;
const PING_CONFIRM: u64 = 1;
const BODY: u64 = (1 << KIND_SHIFT) - 1;

/// The PMP's `PMPEndpoint1`.
#[derive(Debug, Default)]
pub struct Pmp {
    pings: u64,
}

impl Pmp {
    /// Pings the AP sent.
    pub fn pings(&self) -> u64 {
        self.pings
    }
}

impl Endpoint for Pmp {
    // This endpoint owns no AP allocation, queued callback or DMA. `pings`
    // is a lifetime diagnostic counter, not volatile protocol state.
    fn check_reset(&self) -> Result<(), &'static str> {
        Ok(())
    }
    fn reset(&mut self) -> Result<(), &'static str> {
        Ok(())
    }
    fn start(&mut self, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        Ok(())
    }

    fn receive(&mut self, payload: u64, outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        let class = payload >> CLASS_SHIFT & 0xf;
        let kind = payload >> KIND_SHIFT & 0xf;
        if payload >> 56 != 0 {
            return Err("PMP message bits above the class are not modeled");
        }
        match (class, kind) {
            (POWER_MANAGEMENT, PING) => {
                self.pings += 1;
                outbox.push(
                    POWER_MANAGEMENT << CLASS_SHIFT | PING_CONFIRM << KIND_SHIFT | payload & BODY,
                );
                Ok(())
            }
            _ => Err("PMP endpoint message other than the ping is not modeled"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ping_is_confirmed_and_other_messages_refuse() {
        let mut pmp = Pmp::default();
        let mut outbox = Vec::new();
        pmp.start(&mut outbox).unwrap();
        assert!(outbox.is_empty());
        // pingGated: class 2 kind 0, the AP's time in the low 32 bits.
        pmp.receive(0x0020_0000_1234_5678, &mut outbox).unwrap();
        assert_eq!(outbox, [0x0021_0000_1234_5678]);
        assert_eq!(pmp.pings(), 1);
        // A registry set request, a memory reply and a high-byte field.
        for payload in [
            0x0036_0000_0000_0001,
            0x0011_0000_0000_1000,
            0x0120_0000_0000_0000,
        ] {
            assert!(pmp.receive(payload, &mut Vec::new()).is_err());
        }
    }
}

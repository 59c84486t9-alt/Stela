// SPDX-License-Identifier: GPL-2.0-only
//! UAC3 power-domain controls adapted from Linux sound/usb/power.c. A SET ACK
//! alone is insufficient: wait for the specified recovery and observe CUR again.
use super::{Control, Error};
use crate::{block::BlockError, usb::xhci::setup};

const D0: u8 = 0;
const D1: u8 = 1;
const D2: u8 = 2;
const POWER_CONTROL: u16 = 2 << 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowerDomain {
    pub id: u8,
    /// Recovery times in the standard 50-microsecond units.
    pub recovery_d1: u16,
    pub recovery_d2: u16,
}
impl PowerDomain {
    fn current<C: Control>(self, io: &mut C, interface: u8) -> Result<u8, Error> {
        let reply = io.control(
            setup(
                0xa1,
                1,
                POWER_CONTROL,
                u16::from(self.id) << 8 | u16::from(interface),
                1,
            ),
            &[],
        )?;
        if reply.len() != 1 {
            return Err(Error::ControlLength);
        }
        if reply[0] > D2 {
            return Err(Error::PowerState);
        }
        Ok(reply[0])
    }
    fn set<C: Control>(self, io: &mut C, interface: u8, state: u8) -> Result<(), Error> {
        let previous = self.current(io, interface)?;
        if previous == state {
            return Ok(());
        }
        let reply = io.control(
            setup(
                0x21,
                1,
                POWER_CONTROL,
                u16::from(self.id) << 8 | u16::from(interface),
                1,
            ),
            &[state],
        )?;
        if !reply.is_empty() {
            return Err(Error::ControlLength);
        }
        let delay = if state == D0 {
            match previous {
                D1 => u64::from(self.recovery_d1) * 50,
                D2 => u64::from(self.recovery_d2) * 50,
                _ => return Err(Error::PowerState),
            }
        } else {
            0
        };
        let start = io.now_us();
        let mut spins = 0u32;
        while io.now_us().wrapping_sub(start) < delay {
            io.relax();
            spins += 1;
            // A broken/stopped platform clock must not hang driver teardown.
            if spins == 10_000_000 {
                return Err(Error::Transport(BlockError::Timeout));
            }
        }
        if self.current(io, interface)? != state {
            return Err(Error::ControlReadback);
        }
        Ok(())
    }
    pub(super) fn ensure_awake<C: Control>(self, io: &mut C, interface: u8) -> Result<(), Error> {
        if self.current(io, interface)? != D0 {
            return Err(Error::PowerState);
        }
        Ok(())
    }
    pub(super) fn awake<C: Control>(self, io: &mut C, interface: u8) -> Result<(), Error> {
        self.set(io, interface, D0)
    }
    pub(super) fn idle<C: Control>(self, io: &mut C, interface: u8) -> Result<(), Error> {
        self.set(io, interface, D1)
    }
}

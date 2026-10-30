// SPDX-License-Identifier: GPL-2.0-only
//! UAC3 power-domain controls adapted from Linux sound/usb/power.c. A SET ACK
//! alone is insufficient: wait for the specified recovery and observe CUR again.
use super::{Control, Error};
use crate::{block::BlockError, usb::descriptor::setup};

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
        let mut previous = start;
        let mut stalled = 0u32;
        while previous.wrapping_sub(start) < delay {
            io.relax();
            let current = io.now_us();
            // Bound a stopped timer, not the duration of a valid recovery.
            // Descriptor recovery may be seconds; a fast CPU can perform many
            // polls per microsecond without violating that recovery interval.
            if current == previous {
                stalled += 1;
                if stalled == 10_000_000 {
                    return Err(Error::Transport(BlockError::Timeout));
                }
            } else {
                stalled = 0;
            }
            previous = current;
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    struct FastPoll {
        cycles: u64,
        state: u8,
        stopped: bool,
    }
    impl Control for FastPoll {
        fn now_us(&self) -> u64 {
            self.cycles / 40
        }
        fn relax(&mut self) {
            if !self.stopped {
                self.cycles += 1;
            }
        }
        fn control(&mut self, r: [u8; 8], out: &[u8]) -> Result<Vec<u8>, BlockError> {
            assert_eq!(r, setup(r[0], 1, 2 << 8, 10 << 8, 1));
            if r[0] == 0x21 {
                self.state = out[0];
                Ok(Vec::new())
            } else {
                Ok(alloc::vec![self.state])
            }
        }
    }
    #[test]
    fn progressing_recovery_timer_is_not_limited_by_cpu_poll_count() {
        let domain = PowerDomain {
            id: 10,
            recovery_d1: 600,
            recovery_d2: 6000,
        };
        let mut io = FastPoll {
            cycles: 0,
            state: 2,
            stopped: false,
        };
        domain.awake(&mut io, 0).unwrap();
        assert_eq!(io.now_us(), 300_000);
        assert_eq!(io.cycles, 12_000_000);
        let mut io = FastPoll {
            cycles: 0,
            state: 2,
            stopped: true,
        };
        assert_eq!(
            domain.awake(&mut io, 0),
            Err(Error::Transport(BlockError::Timeout))
        );
    }
}

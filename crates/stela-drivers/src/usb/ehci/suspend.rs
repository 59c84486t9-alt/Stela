// SPDX-License-Identifier: GPL-2.0-only
// Root selective suspend/resume follows Linux ehci-hub.c, David Brownell.
//! Explicit held-D0 root link transitions after complete engine retirement.
use super::*;

const WAKE: u32 = 7 << 20;
// include/linux/usb.h USB_RESUME_TIMEOUT is 40ms at the pin; the older
// ehci-hub.c "20 msec" comment does not describe its macro value.
const RESUME_SIGNAL_US: u64 = 40_000;
const RESUME_RECOVERY_US: u64 = 10_000;
const RESUME_CLEAR_US: u64 = 2_000;

impl Controller {
    /// Suspend this exact configured, addressed root with no active transfer.
    /// Device remote wake is disabled through real EP0 requests, then both
    /// schedules stop and the original requester path drains. Public identities
    /// retire before PORT_SUSPEND is written. PCI D0 and all addresses/mappings
    /// remain owned; platform sleep and reset-on-resume are unsupported.
    pub fn suspend_port(&mut self, id: &DeviceId) -> Result<SuspendedPort, Error> {
        let index = self.identity(id)?;
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        let device = self.ports[index].as_ref().expect("validated");
        if device.address == 0 || device.configuration_value == 0 {
            return Err(Error::Invalid);
        }
        let generation = self
            .next_generation
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        let wake = (|| {
            let status = self.control_internal(id, [0x80, 0, 0, 0, 0, 0, 2, 0], &[], 2)?;
            if status.len() != 2 {
                return Err(Error::Invalid);
            }
            let status = u16::from_le_bytes([status[0], status[1]]);
            if status & !3 != 0 {
                return Err(Error::Invalid);
            }
            if status & 2 != 0 {
                self.control_internal(id, [0, 1, 1, 0, 0, 0, 0, 0], &[], 0)?;
                let actual = self.control_internal(id, [0x80, 0, 0, 0, 0, 0, 2, 0], &[], 2)?;
                if actual.len() != 2 || u16::from_le_bytes([actual[0], actual[1]]) != status & !2 {
                    return Err(Error::Invalid);
                }
            }
            self.live(id)?;
            self.schedule_off()
        })();
        self.guard(wake)?;
        let actual = self.read(self.port_at(index));
        let actual = self.guard(actual)?;
        let stable = self.suspend_link(actual, actual, false, false);
        self.guard(stable)?;
        self.next_generation = generation;
        let device = self.ports[index].as_mut().expect("retained");
        device.generation = generation;
        device.suspended = true;
        let transition = (|| {
            self.write(
                self.port_at(index),
                actual & !(PORT_CHANGES | WAKE) | PORT_SUSPEND,
            )?;
            self.wait_suspend_link(index, actual, true, false)?;
            // Let the link settle before its private owner is returned.
            self.hw().delay_us(5_000)?;
            let settled = self.read(self.port_at(index))?;
            self.suspend_link(actual, settled, true, false)?;
            self.health()
        })();
        self.guard(transition)?;
        Ok(SuspendedPort {
            owner: self.owner.clone(),
            generation,
            port: id.port,
        })
    }

    /// Resume only the capability's original suspended root. Actual
    /// 40ms resume signaling and cleared link/status acknowledgements precede
    /// a new public generation. No USB address, configuration or toggle is
    /// guessed or reset; old handles remain permanently stale.
    pub fn resume_port(&mut self, owner: &SuspendedPort) -> Result<DeviceId, Error> {
        if !Rc::ptr_eq(&self.owner, &owner.owner) {
            return Err(Error::Stale);
        }
        let index = usize::from(owner.port).checked_sub(1).ok_or(Error::Stale)?;
        if self
            .ports
            .get(index)
            .and_then(Option::as_ref)
            .is_none_or(|device| device.generation != owner.generation || !device.suspended)
        {
            return Err(Error::Stale);
        }
        self.ready()?;
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        let generation = self
            .next_generation
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        let result = (|| {
            self.schedule_off()?;
            let before = self.read(self.port_at(index))?;
            self.suspend_link(before, before, true, false)?;
            self.write(
                self.port_at(index),
                before & !(PORT_CHANGES | WAKE) | PORT_RESUME,
            )?;
            self.wait_suspend_link(index, before, true, true)?;
            self.hw().delay_us(RESUME_SIGNAL_US)?;
            let signaled = self.read(self.port_at(index))?;
            self.suspend_link(before, signaled, true, true)?;
            self.write(
                self.port_at(index),
                signaled & !(PORT_CHANGES | PORT_SUSPEND | PORT_RESUME | WAKE),
            )?;
            self.wait_suspend_link(index, before, false, false)?;
            self.hw().delay_us(RESUME_RECOVERY_US)?;
            let settled = self.read(self.port_at(index))?;
            self.suspend_link(before, settled, false, false)?;
            self.health()
        })();
        self.guard(result)?;
        self.next_generation = generation;
        let device = self.ports[index].as_mut().expect("retained");
        device.generation = generation;
        device.suspended = false;
        Ok(DeviceId {
            owner: self.owner.clone(),
            generation,
            port: owner.port,
        })
    }
    fn suspend_link(
        &self,
        before: u32,
        actual: u32,
        suspended: bool,
        resuming: bool,
    ) -> Result<(), Error> {
        if actual == u32::MAX
            || actual & (CONNECT | ENABLE | OWNER | OVERCURRENT | PORT_RESET | PORT_CHANGES)
                != CONNECT | ENABLE
            || (before ^ actual) & POWER != 0
            || self.power_control && actual & POWER == 0
            || (actual & PORT_SUSPEND != 0) != suspended
            || (actual & PORT_RESUME != 0) != resuming
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    fn wait_suspend_link(
        &mut self,
        index: usize,
        before: u32,
        suspended: bool,
        resuming: bool,
    ) -> Result<(), Error> {
        let start = self.hw().now_us();
        let timeout = if !suspended && !resuming {
            RESUME_CLEAR_US
        } else {
            TRANSITION_US
        };
        loop {
            self.health()?;
            let actual = self.read(self.port_at(index))?;
            // The same physical connection/power epoch must survive even
            // while the requested suspend/resume bits are still transitioning.
            if actual & (CONNECT | ENABLE | OWNER | OVERCURRENT | PORT_RESET | PORT_CHANGES)
                != CONNECT | ENABLE
                || (before ^ actual) & POWER != 0
                || self.power_control && actual & POWER == 0
            {
                return Err(Error::Stale);
            }
            if self
                .suspend_link(before, actual, suspended, resuming)
                .is_ok()
            {
                return Ok(());
            }
            if self.hw().now_us().wrapping_sub(start) >= timeout {
                return Err(Error::Timeout);
            }
            self.hw().pause();
        }
    }
}

// SPDX-License-Identifier: GPL-2.0-or-later
// Smart Battery System transactions, following Linux drivers/acpi/sbs.c.
// Copyright (c) 2007 Alexey Starikovskiy
// Copyright (c) 2005-2007 Vladimir Lebedev
// Copyright (c) 2005 Rich Townsend
//! Smart Battery/manager/charger protocol over an owned native SMBus host.
//!
//! Raw values keep SBS units, specification scaling, signed current and exact
//! identity block lengths. Charging policy and native EC-SMBus discovery are
//! separate. A failed selector/alarm write cannot be retried through this owner.
use crate::bus::smbus::{self, Address, Block, Bus, Transaction};

const MANAGER: u8 = 0x0a;
const BATTERY: u8 = 0x0b;
const CHARGER: u8 = 0x09;
const SELECT: u8 = 0x01;
const SYSTEM_INFO: u8 = 0x04;
const MODE: u8 = 0x03;
const SERIAL: u8 = 0x1c;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Topology {
    /// Firmware/platform discovery established a single direct battery.
    Single,
    /// Firmware/platform discovery established an SBS manager/selector.
    Managed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bus {
        address: u8,
        command: u8,
        error: smbus::Error,
    },
    UnsupportedSlot(u8),
    NotPresent,
    Changed,
    Readback,
    EmptyBlock(u8),
    NeedsReset,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityUnit {
    MilliampHours,
    TenMilliwattHours,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Information {
    pub alarm_capacity: u16,
    pub mode: u16,
    pub full_charge_capacity: u16,
    pub cycle_count: u16,
    pub design_capacity: u16,
    pub design_voltage: u16,
    pub specification: u16,
    pub serial: u16,
    pub manufacturer: Block,
    pub model: Block,
    pub chemistry: Block,
}
impl Information {
    pub fn capacity_unit(&self) -> CapacityUnit {
        if self.mode & 0x8000 == 0 {
            CapacityUnit::MilliampHours
        } else {
            CapacityUnit::TenMilliwattHours
        }
    }
    pub fn voltage_exponent(&self) -> u8 {
        ((self.specification >> 8) & 15) as u8
    }
    pub fn current_exponent(&self) -> u8 {
        ((self.specification >> 12) & 15) as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    /// SBS 0.1 kelvin units, not an invented Celsius conversion.
    pub temperature: u16,
    pub voltage: u16,
    /// Signed current, keeping charging/discharging direction.
    pub current: i16,
    pub average_current: i16,
    pub remaining_capacity: u16,
    pub relative_charge: u16,
    pub status: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub slot: u8,
    pub information: Information,
    pub state: State,
}

pub struct Sbs<B> {
    bus: B,
    topology: Topology,
    supported: u8,
    pec: bool,
    quarantined: bool,
    snapshot: Option<Snapshot>,
}
impl<B: Bus> Sbs<B> {
    /// # Safety
    /// Own the native host and firmware arbitration for the complete sequence,
    /// not only each individual transaction. No competing firmware/driver may
    /// change battery selection, unit mode or alarm during a public operation.
    /// Topology must come from platform/firmware discovery; absence of a
    /// responding manager does not authorize silently falling back to Single.
    pub unsafe fn claim(bus: B, topology: Topology, pec: bool) -> Result<Self, Error> {
        let mut this = Self {
            bus,
            topology,
            supported: 1,
            pec,
            quarantined: false,
            snapshot: None,
        };
        if topology == Topology::Managed {
            this.supported = (this.word(MANAGER, SYSTEM_INFO)? & 15) as u8;
        }
        Ok(this)
    }

    pub fn supported_slots(&self) -> u8 {
        self.supported
    }
    pub fn needs_reset(&self) -> bool {
        self.quarantined
    }
    pub fn snapshot(&self) -> Option<&Snapshot> {
        self.snapshot.as_ref()
    }

    /// Reads fresh information/state, then revalidates selector presence and
    /// unit/serial identity before publishing one coherent observation.
    pub fn refresh(&mut self, slot: u8) -> Result<Option<&Snapshot>, Error> {
        self.snapshot = None;
        self.ready()?;
        if !self.select(slot)? {
            return Ok(None);
        }
        let information = Information {
            alarm_capacity: self.word(BATTERY, SELECT)?,
            mode: self.word(BATTERY, MODE)?,
            full_charge_capacity: self.word(BATTERY, 0x10)?,
            cycle_count: self.word(BATTERY, 0x17)?,
            design_capacity: self.word(BATTERY, 0x18)?,
            design_voltage: self.word(BATTERY, 0x19)?,
            specification: self.word(BATTERY, 0x1a)?,
            serial: self.word(BATTERY, SERIAL)?,
            manufacturer: self.block(0x20)?,
            model: self.block(0x21)?,
            chemistry: self.block(0x22)?,
        };
        let state = State {
            temperature: self.word(BATTERY, 0x08)?,
            voltage: self.word(BATTERY, 0x09)?,
            current: self.word(BATTERY, 0x0a)? as i16,
            average_current: self.word(BATTERY, 0x0b)? as i16,
            remaining_capacity: self.word(BATTERY, 0x0f)?,
            relative_charge: self.word(BATTERY, 0x0e)?,
            status: self.word(BATTERY, 0x16)?,
        };
        self.validate(slot, information.mode, information.serial)?;
        self.snapshot = Some(Snapshot {
            slot,
            information,
            state,
        });
        Ok(self.snapshot.as_ref())
    }

    /// Writes native capacity units only after fresh identity validation, and
    /// acknowledges the alarm only after readback and revalidation.
    pub fn set_alarm(&mut self, capacity: u16) -> Result<(), Error> {
        self.ready()?;
        let old = self.snapshot.take().ok_or(Error::NotPresent)?;
        if !self.select(old.slot)? {
            return Err(Error::NotPresent);
        }
        self.validate(old.slot, old.information.mode, old.information.serial)?;
        self.write(BATTERY, SELECT, capacity)?;
        let result = (|| {
            if self.word(BATTERY, SELECT)? != capacity {
                return Err(Error::Readback);
            }
            self.validate(old.slot, old.information.mode, old.information.serial)
        })();
        if let Err(error) = result {
            self.quarantined = true;
            return Err(error);
        }
        let mut old = old;
        old.information.alarm_capacity = capacity;
        self.snapshot = Some(old);
        Ok(())
    }

    /// None means the charger status does not implement the mandatory
    /// bit or returned all ones, as checked by the Linux SBS driver.
    pub fn charger_online(&mut self) -> Result<Option<bool>, Error> {
        self.ready()?;
        let value = self.word(CHARGER, 0x13)?;
        Ok((value != u16::MAX && value & 0x10 != 0).then_some(value & 0x8000 != 0))
    }

    fn ready(&self) -> Result<(), Error> {
        if self.quarantined {
            Err(Error::NeedsReset)
        } else {
            Ok(())
        }
    }
    fn slot(&self, slot: u8) -> Result<(), Error> {
        if slot >= 4 || self.supported & (1 << slot) == 0 {
            Err(Error::UnsupportedSlot(slot))
        } else {
            Ok(())
        }
    }
    fn select(&mut self, slot: u8) -> Result<bool, Error> {
        self.slot(slot)?;
        if self.topology == Topology::Single {
            return Ok(true);
        }
        let current = self.word(MANAGER, SELECT)?;
        if current & (1 << slot) == 0 {
            return Ok(false);
        }
        let selected = 1 << (slot + 12);
        if current & 0xf000 != selected {
            // Source's Smart Battery Selector mask is required, not a blind
            // preservation of arbitrary firmware selection/request flags.
            self.write(MANAGER, SELECT, selected | 0x0fff)?;
        }
        self.validate_selection(slot)?;
        Ok(true)
    }
    fn validate_selection(&mut self, slot: u8) -> Result<(), Error> {
        if self.topology == Topology::Managed {
            let state = self.word(MANAGER, SELECT)?;
            if state & (1 << slot) == 0 || state & 0xf000 != 1 << (slot + 12) {
                return Err(Error::Changed);
            }
        }
        Ok(())
    }
    fn validate(&mut self, slot: u8, mode: u16, serial: u16) -> Result<(), Error> {
        self.validate_selection(slot)?;
        if self.word(BATTERY, MODE)? != mode || self.word(BATTERY, SERIAL)? != serial {
            return Err(Error::Changed);
        }
        self.validate_selection(slot)
    }
    fn word(&mut self, address: u8, command: u8) -> Result<u16, Error> {
        let mut value = 0;
        self.bus
            .transaction(
                Address::new(address).unwrap(),
                Transaction::ReadWord {
                    command,
                    data: &mut value,
                },
                self.pec,
            )
            .map_err(|error| Error::Bus {
                address,
                command,
                error,
            })?;
        Ok(value)
    }
    fn block(&mut self, command: u8) -> Result<Block, Error> {
        let mut value = Block::default();
        self.bus
            .transaction(
                Address::new(BATTERY).unwrap(),
                Transaction::ReadBlock {
                    command,
                    data: &mut value,
                },
                self.pec,
            )
            .map_err(|error| Error::Bus {
                address: BATTERY,
                command,
                error,
            })?;
        if value.as_slice().is_empty() {
            return Err(Error::EmptyBlock(command));
        }
        Ok(value)
    }
    fn write(&mut self, address: u8, command: u8, data: u16) -> Result<(), Error> {
        if let Err(error) = self.bus.transaction(
            Address::new(address).unwrap(),
            Transaction::WriteWord { command, data },
            self.pec,
        ) {
            self.quarantined = true;
            return Err(Error::Bus {
                address,
                command,
                error,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

// SPDX-License-Identifier: GPL-2.0-or-later
// ACPI AC adapter state, following Linux drivers/acpi/ac.c.
// Copyright (C) 2001, 2002 Andy Grover and Paul Diefenbaugh
//! Native ACPI AC adapters (ACPI0003): whether mains power is online, from
//! `_PSR` as Linux's `acpi_ac_get_state` reads it.
use super::acpi::{self, Handle, Value};

/// ACPICA's AE_TYPE: a method returned something other than an integer.
const TYPE: acpi::Error = acpi::Error(0x0008);

/// One AC adapter; every refresh evaluates `_PSR` anew.
pub struct AcAdapter<'a> {
    handle: Handle<'a>,
    online: Option<bool>,
}

impl<'a> AcAdapter<'a> {
    /// Use a handle from the session's ACPI0003 device discovery that has
    /// `_PSR`.
    pub fn attach(handle: Handle<'a>) -> Result<Self, acpi::Error> {
        handle.child("_PSR")?;
        Ok(Self {
            handle,
            online: None,
        })
    }

    /// Whether the adapter supplies power, from `_PSR`.
    pub fn refresh(&mut self) -> Result<bool, acpi::Error> {
        let online = state(self.handle.evaluate(Some("_PSR"), &[])?)?;
        self.online = Some(online);
        Ok(online)
    }

    /// The last [`Self::refresh`]'s answer.
    pub fn online(&self) -> Option<bool> {
        self.online
    }
}

/// `_PSR`'s answer: nonzero is online.
fn state(value: Option<Value<'_>>) -> Result<bool, acpi::Error> {
    match value {
        Some(Value::Integer(state)) => Ok(state != 0),
        _ => Err(TYPE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonzero_power_source_state_is_online_and_others_are_malformed() {
        assert_eq!(state(Some(Value::Integer(1))), Ok(true));
        assert_eq!(state(Some(Value::Integer(0))), Ok(false));
        assert_eq!(state(Some(Value::Buffer(alloc::vec![1]))), Err(TYPE));
        assert_eq!(state(None), Err(TYPE));
    }
}

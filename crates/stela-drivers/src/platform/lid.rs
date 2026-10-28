// SPDX-License-Identifier: GPL-2.0-or-later
// ACPI lid state, following Linux drivers/acpi/button.c.
// Copyright (C) 2001, 2002 Andy Grover and Paul Diefenbaugh
//! The native ACPI lid switch (PNP0C0D): whether the lid is open, from
//! `_LID` as Linux's `acpi_lid_evaluate_state` reads it.
use super::acpi::{self, Handle, Value};

/// ACPICA's AE_TYPE: a method returned something other than an integer.
const TYPE: acpi::Error = acpi::Error(0x0008);

/// The lid; every refresh evaluates `_LID` anew.
pub struct Lid<'a> {
    handle: Handle<'a>,
    open: Option<bool>,
}

impl<'a> Lid<'a> {
    /// Use a handle from the session's PNP0C0D device discovery that has
    /// `_LID`.
    pub fn attach(handle: Handle<'a>) -> Result<Self, acpi::Error> {
        handle.child("_LID")?;
        Ok(Self { handle, open: None })
    }

    /// Whether the lid is open, from `_LID`.
    pub fn refresh(&mut self) -> Result<bool, acpi::Error> {
        let open = state(self.handle.evaluate(Some("_LID"), &[])?)?;
        self.open = Some(open);
        Ok(open)
    }

    /// The last [`Self::refresh`]'s answer.
    pub fn open(&self) -> Option<bool> {
        self.open
    }
}

/// `_LID`'s answer: nonzero is open.
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
    fn nonzero_lid_state_is_open_and_others_are_malformed() {
        assert_eq!(state(Some(Value::Integer(1))), Ok(true));
        assert_eq!(state(Some(Value::Integer(0))), Ok(false));
        assert_eq!(state(Some(Value::String(alloc::vec![b'1']))), Err(TYPE));
        assert_eq!(state(None), Err(TYPE));
    }
}

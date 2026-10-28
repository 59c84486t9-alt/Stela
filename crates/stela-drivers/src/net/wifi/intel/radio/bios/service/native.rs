// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Stela contributors
//! The platform service of one attached Intel Wi-Fi function after
//! ExitBootServices: its ACPI companion's methods through the mount's ACPICA
//! session, as iwlwifi's `iwl_acpi_get_object` and `iwl_acpi_get_dsm_object`
//! evaluate them at `ACPI_HANDLE(dev)`; the EFI variables boot captured
//! before ExitBootServices, as `iwl_uefi_get_variable` reads them; and the
//! SMBIOS identity boot captured, for the DMI matches of `iwl_sar_*` quirks.
use super::{BiosIo, DmiIdentity, IoError, Object, Request};
use crate::{
    firmware::{
        Provider,
        smbios::{self, Observation as Field},
    },
    net::wifi::intel::platform::{self, Observation, Observations, Variable},
    platform::acpi::{self, Handle, Value},
};
use alloc::{string::String, vec::Vec};

/// Intel's Wi-Fi `_DSM` GUID f21202bf-8f78-4dc6-a5b3-1f738e285ade in its
/// ACPI buffer byte order.
const DSM_GUID: [u8; 16] = [
    0xbf, 0x02, 0x12, 0xf2, 0x78, 0x8f, 0xc6, 0x4d, 0xa5, 0xb3, 0x1f, 0x73, 0x8e, 0x28, 0x5a, 0xde,
];

/// The reads of one Intel Wi-Fi function.
pub struct NativeBios {
    /// The function's ACPI companion; `None` when the namespace has none,
    /// which iwlwifi reads as every method absent.
    companion: Option<Handle<'static>>,
    /// Whether an ACPI namespace serves the companion at all.
    namespace: bool,
    firmware: &'static dyn Provider,
    observations: Observations,
}

impl NativeBios {
    /// # Safety
    /// `companion` is the ACPI device whose `_ADR` names this exact function
    /// under its bridges, from a session that stays live while the radio
    /// runs. `firmware` and `observations` are the boot's captured catalog
    /// and the observations boot made while reading these variables.
    pub unsafe fn new(
        session: Option<&'static acpi::Session>,
        companion: Option<Handle<'static>>,
        firmware: &'static dyn Provider,
        observations: Observations,
    ) -> Self {
        Self {
            companion,
            namespace: session.is_some_and(acpi::Session::namespace_available),
            firmware,
            observations,
        }
    }
}

/// The method `iwl_acpi_get_object` evaluates for a request, `None` for
/// `_DSM`.
fn method(request: Request) -> Result<Option<&'static str>, IoError> {
    Ok(Some(match request {
        Request::Glai => "GLAI",
        Request::WideBandwidth => "WBEM",
        Request::ExternalClock => "ECKV",
        Request::Country => "WRDD",
        Request::PowerTable(Variable::Wrds) => "WRDS",
        Request::PowerTable(Variable::Ewrd) => "EWRD",
        Request::PowerTable(Variable::Wgds) => "WGDS",
        Request::PowerTable(Variable::Ppag) => "PPAG",
        Request::PowerTable(Variable::Wtas) => "WTAS",
        Request::PowerTable(_) => return Err(IoError::Unavailable),
        Request::Dsm(_) => return Ok(None),
    }))
}

fn status(error: acpi::Error) -> IoError {
    if error == acpi::NOT_FOUND {
        IoError::NotFound
    } else if error == acpi::LIMIT {
        IoError::BoundExceeded
    } else {
        IoError::Failed(u64::from(error.0))
    }
}

/// An evaluated object as the BIOS parsers take it. Strings and references
/// carry nothing iwlwifi reads.
fn object(value: Value<'_>) -> Object {
    match value {
        Value::Integer(value) => Object::Integer(value),
        Value::Buffer(bytes) => Object::Buffer(bytes),
        Value::Package(items) => Object::Package(items.into_iter().map(object).collect()),
        Value::String(_) | Value::Reference(_) | Value::Uninitialized => Object::Other,
    }
}

/// An SMBIOS string without its terminating NUL.
fn text(field: Field<'_>) -> Option<String> {
    match field {
        Field::Value(bytes) => {
            Some(String::from_utf8_lossy(bytes.strip_suffix(&[0]).unwrap_or(bytes)).into_owned())
        }
        Field::Absent | Field::NotObserved => None,
    }
}

// SAFETY: the companion and session are the function's own and stay live
// (`new`'s contract); variables come only from the boot's capture of their
// exact GUID and name, and SMBIOS from its capture of the entry and table.
unsafe impl BiosIo for NativeBios {
    fn evaluate(&mut self, request: Request) -> Result<Object, IoError> {
        if !self.namespace {
            return Err(IoError::Unavailable);
        }
        let Some(companion) = self.companion else {
            return Err(IoError::NotFound);
        };
        let result = match (method(request)?, request) {
            (Some(name), _) => companion.evaluate(Some(name), &[]),
            (None, Request::Dsm(function)) => companion.dsm(&DSM_GUID, 0, u64::from(function)),
            (None, _) => return Err(IoError::Unavailable),
        };
        match result {
            Ok(Some(value)) => Ok(object(value)),
            Ok(None) => Ok(Object::Other),
            Err(error) => Err(status(error)),
        }
    }

    fn variable(&mut self, variable: Variable) -> Result<Vec<u8>, IoError> {
        let observation = self.observations.get(variable);
        match platform::load_radio_image(variable, observation, self.firmware) {
            Ok(image) => Ok(image.bytes().to_vec()),
            Err(_) => Err(match observation {
                Observation::NotCaptured => IoError::Unavailable,
                Observation::Absent { status, .. } if status == platform::NOT_FOUND => {
                    IoError::NotFound
                }
                Observation::Absent { status, .. } | Observation::Failed { status, .. } => {
                    IoError::Failed(status)
                }
                Observation::BoundExceeded { .. } => IoError::BoundExceeded,
                // The capture and the catalog disagree.
                Observation::Present { .. } => IoError::Failed(0),
            }),
        }
    }

    fn dmi_identity(&mut self) -> Result<DmiIdentity, IoError> {
        let snapshot = smbios::load(self.firmware).map_err(|_| IoError::Unavailable)?;
        Ok(DmiIdentity {
            system_vendor: text(snapshot.identity.system_vendor),
            board_vendor: text(snapshot.identity.board_vendor),
        })
    }
}

#[cfg(test)]
mod tests;

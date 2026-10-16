//! Validate the identification fields the fixed control profile relies on.
//! Other fields are not interpreted and enable nothing.
use crate::system::{identification::Register, identification_snapshot::Snapshot};
use anyhow::{Result, ensure};

const ID_FIELD_MASK: u64 = 0xf;

struct RequiredField {
    register: Register,
    name: &'static str,
    shift: u32,
    value: u64,
}

// SysReg fields as of June 2026: PA40, ASID8, 4K and 16K granules, little
// endian only, and no address-authentication algorithm, matching the
// constants of declared_profile. entry_profile checks PAN, SSBS and ExS.
const FIXED_CONTROL_FIELDS: &[RequiredField] = &[
    RequiredField {
        register: Register::IdAa64Mmfr0El1,
        name: "PARange",
        shift: 0,
        value: 2,
    },
    RequiredField {
        register: Register::IdAa64Mmfr0El1,
        name: "ASIDBits",
        shift: 4,
        value: 0,
    },
    RequiredField {
        register: Register::IdAa64Mmfr0El1,
        name: "BigEnd",
        shift: 8,
        value: 0,
    },
    RequiredField {
        register: Register::IdAa64Mmfr0El1,
        name: "BigEndEL0",
        shift: 16,
        value: 0,
    },
    RequiredField {
        register: Register::IdAa64Mmfr0El1,
        name: "TGran16",
        shift: 20,
        value: 1,
    },
    RequiredField {
        register: Register::IdAa64Mmfr0El1,
        name: "TGran64",
        shift: 24,
        value: 15,
    },
    RequiredField {
        register: Register::IdAa64Mmfr0El1,
        name: "TGran4",
        shift: 28,
        value: 0,
    },
    RequiredField {
        register: Register::IdAa64Isar1El1,
        name: "APA",
        shift: 4,
        value: 0,
    },
    RequiredField {
        register: Register::IdAa64Isar1El1,
        name: "API",
        shift: 8,
        value: 0,
    },
    RequiredField {
        register: Register::IdAa64Isar2El1,
        name: "APA3",
        shift: 12,
        value: 0,
    },
];

pub(super) fn check(identification: &Snapshot) -> Result<()> {
    for field in FIXED_CONTROL_FIELDS {
        let actual = (identification.read(field.register)? >> field.shift) & ID_FIELD_MASK;
        ensure!(
            actual == field.value,
            "fixed EL1 control profile requires {:?}.{}={}, actual={}",
            field.register,
            field.name,
            field.value,
            actual
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;

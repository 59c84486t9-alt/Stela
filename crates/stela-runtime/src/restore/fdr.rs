//! Explicit diagnostic import through restored's original FDR memory store.
//! Imported signatures are opaque: only Apple's consumer decides their trust.
//! A commit is acknowledged only after the host's durable writer succeeds.
use super::{
    Error, Result,
    plist::{self, Limits, Value},
};
use alloc::{string::String, vec::Vec};

pub const FILE: &str = "fdr-diagnostic.plist";
pub const STATE_FILE: &str = "fdr-state.bin";
pub const MAX_BYTES: usize = 1024 * 1024;

pub struct Diagnostic {
    ecid: u64,
    chip: u64,
    board: u64,
    build: String,
    model: String,
    records: Value,
}

impl Diagnostic {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let value = plist::decode(
            bytes,
            Limits {
                bytes: MAX_BYTES,
                ..Limits::default()
            },
        )?;
        if value.required("DiagnosticVersion")?.uint()? != 1 {
            return Err(Error::Invalid("FDR diagnostic version"));
        }
        let ecid = value.required("ECID")?.bits()?;
        if ecid == 0 {
            return Err(Error::Invalid("FDR diagnostic ECID"));
        }
        let records = value.required("FDRMemoryStoreData")?.clone();
        let Value::Dict(entries) = &records else {
            return Err(Error::Invalid("FDR memory-store dictionary"));
        };
        if entries.len() > 128 {
            return Err(Error::Limit("FDR diagnostic records"));
        }
        for (key, value) in entries {
            if key.is_empty() || key.len() > 512 || value.data()?.is_empty() {
                return Err(Error::Invalid("FDR diagnostic record"));
            }
        }
        Ok(Self {
            ecid,
            chip: value.required("ChipID")?.uint()?,
            board: value.required("BoardID")?.uint()?,
            build: value.required("Build")?.string()?.into(),
            model: value.required("Model")?.string()?.into(),
            records,
        })
    }

    pub fn check(&self, hardware: &Value, build: &str, model: &str) -> Result<()> {
        if hardware.required("UniqueChipID")?.bits()? != self.ecid
            || hardware.required("ChipID")?.uint()? != self.chip
            || hardware.required("BoardID")?.uint()? != self.board
            || build != self.build
            || model != self.model
        {
            return Err(Error::Invalid("FDR diagnostic machine/build mismatch"));
        }
        Ok(())
    }

    pub fn reply(&self) -> Value {
        Value::dict([("FDRMemoryStoreData", self.records.clone())])
    }

    /// Replace opaque records without changing the machine/build binding.
    pub fn with_records(&self, records: Value) -> Result<Vec<u8>> {
        let value = Value::dict([
            ("DiagnosticVersion", Value::Integer(1)),
            ("ECID", Value::Integer(self.ecid)),
            ("ChipID", Value::Integer(self.chip)),
            ("BoardID", Value::Integer(self.board)),
            ("Build", Value::String(self.build.clone())),
            ("Model", Value::String(self.model.clone())),
            ("FDRMemoryStoreData", records),
        ]);
        let bytes = plist::encode_binary(
            &value,
            Limits {
                bytes: MAX_BYTES,
                ..Limits::default()
            },
        )?;
        Self::decode(&bytes)?;
        Ok(bytes)
    }

    pub fn same_identity(&self, other: &Self) -> bool {
        self.ecid == other.ecid
            && self.chip == other.chip
            && self.board == other.board
            && self.build == other.build
            && self.model == other.model
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn input() -> Value {
        Value::dict([
            ("DiagnosticVersion", Value::Integer(1)),
            ("ECID", Value::Integer(42)),
            ("ChipID", Value::Integer(8)),
            ("BoardID", Value::Integer(9)),
            ("Build", Value::from("test-build")),
            ("Model", Value::from("test-model")),
            (
                "FDRMemoryStoreData",
                Value::dict([("appv-own", Value::Data(vec![1, 2, 3]))]),
            ),
        ])
    }

    #[test]
    fn opaque_import_preserves_wire_bytes_and_requires_matching_machine() {
        let value = input();
        let bytes = plist::encode_binary(&value, Limits::default()).unwrap();
        let diagnostic = Diagnostic::decode(&bytes).unwrap();
        assert_eq!(
            diagnostic.reply().required("FDRMemoryStoreData").unwrap(),
            value.required("FDRMemoryStoreData").unwrap()
        );
        let hardware = Value::dict([
            ("UniqueChipID", Value::Integer(42)),
            ("ChipID", Value::Integer(8)),
            ("BoardID", Value::Integer(9)),
        ]);
        diagnostic
            .check(&hardware, "test-build", "test-model")
            .unwrap();
        assert!(
            diagnostic
                .check(&hardware, "different", "test-model")
                .is_err()
        );
        let mut other = hardware.clone();
        let Value::Dict(entries) = &mut other else {
            unreachable!()
        };
        entries.insert("UniqueChipID".into(), Value::Integer(43));
        assert!(
            diagnostic
                .check(&other, "test-build", "test-model")
                .is_err()
        );
    }

    #[test]
    fn malformed_store_is_refused() {
        for records in [
            Value::dict([("", Value::Data(vec![1]))]),
            Value::dict([("appv-own", Value::from("not-data"))]),
        ] {
            let mut value = input();
            let Value::Dict(entries) = &mut value else {
                unreachable!()
            };
            entries.insert("FDRMemoryStoreData".into(), records);
            let bytes = plist::encode_binary(&value, Limits::default()).unwrap();
            assert!(Diagnostic::decode(&bytes).is_err());
        }
    }
}

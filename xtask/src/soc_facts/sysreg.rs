//! The census of IMPLEMENTATION DEFINED System register and System
//! instruction accesses in one image: every MRS, MSR (register), SYS and
//! SYSL whose encoding Arm reserves for implementations (op0 3 with CRn 11
//! or 15 for registers, and op0 1 with CRn 11 or 15 for instructions;
//! Arm ARM D23.3.2 and the `MRS_RS`, `MSR_SR`, `SYS_CR` and
//! `SYSL_RC_systeminstrs` forms of the pinned A64 checklist).
//!
//! Each row is one encoding and direction with its word count and first
//! site (fileset entry, virtual address, file offset); deciding what a
//! register does stays with the engine's IMPDEF table and its evidence.
use super::{
    a64::{self, Insn},
    macho,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// The CRn values Arm leaves IMPLEMENTATION DEFINED.
const IMPDEF_CRN: [u8; 2] = [11, 15];
const REGISTER_OP0: u8 = 3;
const INSTRUCTION_OP0: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Encoding {
    pub op0: u8,
    pub op1: u8,
    pub crn: u8,
    pub crm: u8,
    pub op2: u8,
}

impl Encoding {
    pub fn name(&self) -> String {
        format!(
            "S{}_{}_C{}_C{}_{}",
            self.op0, self.op1, self.crn, self.crm, self.op2
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Direction {
    /// MRS or SYSL.
    Read,
    /// MSR or SYS.
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub count: usize,
    pub entry: Option<String>,
    pub address: u64,
    pub offset: u64,
}

/// The IMPDEF access of `insn`, if it is one.
pub fn impdef(insn: &Insn) -> Option<(Encoding, Direction)> {
    let (op0, op1, crn, crm, op2, read) = match *insn {
        Insn::System {
            read,
            op0,
            op1,
            crn,
            crm,
            op2,
            ..
        } => (op0, op1, crn, crm, op2, read),
        Insn::SystemInstruction {
            read,
            op1,
            crn,
            crm,
            op2,
            ..
        } => (INSTRUCTION_OP0, op1, crn, crm, op2, read),
        _ => return None,
    };
    if !matches!(op0, REGISTER_OP0 | INSTRUCTION_OP0) || !IMPDEF_CRN.contains(&crn) {
        return None;
    }
    let direction = if read {
        Direction::Read
    } else {
        Direction::Write
    };
    Some((
        Encoding {
            op0,
            op1,
            crn,
            crm,
            op2,
        },
        direction,
    ))
}

/// The census of `data`, whose code is `image`'s executable segments; a
/// fileset's rows name the entry whose header precedes their first site.
pub fn census(image: &macho::Image, data: &[u8]) -> BTreeMap<(Encoding, Direction), Row> {
    let mut owners: Vec<(u64, String)> = image
        .entries
        .iter()
        .map(|entry| (entry.offset, entry.name.clone()))
        .collect();
    owners.sort();
    let owner = |offset: u64| {
        let index = owners.partition_point(|(start, _)| *start <= offset);
        index.checked_sub(1).map(|index| owners[index].1.clone())
    };
    let mut rows = BTreeMap::new();
    for (address, offset, word) in macho::words(image, data) {
        let Some(key) = impdef(&a64::decode(address, word)) else {
            continue;
        };
        rows.entry(key)
            .and_modify(|row: &mut Row| row.count += 1)
            .or_insert_with(|| Row {
                count: 1,
                entry: None,
                address,
                offset,
            });
    }
    if !owners.is_empty() {
        for row in rows.values_mut() {
            row.entry = owner(row.offset);
        }
    }
    rows
}

/// The columns of each [`json`] row.
pub const COLUMNS: [&str; 6] = [
    "encoding",
    "direction",
    "count",
    "first entry",
    "first address",
    "first file offset",
];

/// A census as JSON rows in [`COLUMNS`] order.
pub fn json(rows: &BTreeMap<(Encoding, Direction), Row>) -> Value {
    Value::Array(
        rows.iter()
            .map(|((encoding, direction), row)| {
                json!([
                    encoding.name(),
                    match direction {
                        Direction::Read => "read",
                        Direction::Write => "write",
                    },
                    row.count,
                    row.entry,
                    format!("{:#x}", row.address),
                    format!("{:#x}", row.offset),
                ])
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_crn_11_and_15_of_op0_1_and_3_are_implementation_defined() {
        // msr S3_4_C15_C0_5, x8
        let (encoding, direction) = impdef(&a64::decode(0, 0xd51cf0a8)).unwrap();
        assert_eq!(encoding.name(), "S3_4_C15_C0_5");
        assert_eq!(direction, Direction::Write);
        // mrs x8, MPIDR_EL1 is architectural.
        assert_eq!(impdef(&a64::decode(0, 0xd53800a8)), None);
        // sys #0, C11, C0, #0, x0 (op0 1) is an IMPDEF instruction.
        let (encoding, _) = impdef(&a64::decode(0, 0xd508b000)).unwrap();
        assert_eq!(encoding.name(), "S1_0_C11_C0_0");
    }
}

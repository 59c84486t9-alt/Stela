//! NAND tunable tables the restore updater sends over the private tunnel.
//!
//! `nvmefwupdater --sendtunabletables` (26A434 ramdisk, U 0x100000d84 and
//! 0x100001838..0x100001cb8) reads the `/arm-io/ans` `tunable-table-bundle`
//! name, opens `/usr/standalone/firmware/storagetunables/<name>.tar.gz` and
//! maps each member's file name to a tunnel request type through
//! `file_to_tunnel_dictionary.plist` (`FilenameToTunnelOpcode`). Selector 14,
//! `AppleNVMeUpdateUC::TunableTableDownload` (0x3dca4b0), copies a table
//! into a kernel buffer, and `AppleANS2NVMeController::SendANS2Table`
//! (0x3dfbefc) sends it with tunnel selector 1: a zeroed request buffer
//! with the type at +12 (0x3dfbfc0), and the table at the start of a
//! zeroed tunnel buffer (0x3dfc028) whose 16 KiB-rounded size travels at
//! command +60. No table length is sent, so the controller receives the
//! whole buffer.
//!
//! Emulated die: Stela's choice. The tables configure NAND firmware the
//! die does not run, and the die has no analog trim for them to set, so it
//! records each accepted table's identity (the transferred buffer's
//! length, CRC32C and SHA-256) and changes nothing else. It accepts the
//! five legacy kinds, whose file names the updater also hard-codes
//! (U 0x100010080..0x1000100a8: `PBPM.bin`, `PB.bin`, `TT.bin`,
//! `LowQD.bin`, `BDR_AF.bin`). The `_V5` and `_BCM` kinds refuse by name:
//! J473AP's bundle carries none of them.
use super::bfh::{Identity, identity};
use crate::Result;
use stela_contracts::refuse;

/// Legacy request types from the dictionary's `FilenameToTunnelOpcode`.
pub(super) const KINDS: [(u32, &str); 5] = [
    (108, "PBPM"),
    (109, "PB"),
    (110, "TT"),
    (153, "LowQD"),
    (205, "BDR_AF"),
];

/// Request types of the dictionary's `_V5` and `_BCM` file names.
const V5_KINDS: [u32; 8] = [329, 330, 331, 332, 343, 344, 345, 346];

/// Whether a tunnel request type is a tunable table: `Some(Ok(name))` for
/// an accepted kind, `Some(Err(..))` for a refused one and `None` for any
/// other request.
pub(super) fn classify(kind: u32) -> Option<Result<&'static str>> {
    if let Some(&(_, name)) = KINDS.iter().find(|&&(id, _)| id == kind) {
        return Some(Ok(name));
    }
    V5_KINDS.contains(&kind).then_some(Err(refuse!(
        "ANS V5 or BCM tunable-table tunnel kind is not modeled: J473AP's bundle carries only \
         legacy tables"
    )))
}

/// The last accepted table of each kind.
#[derive(Default)]
pub(super) struct Tables(alloc::vec::Vec<(u32, Identity)>);

impl Tables {
    /// Record `data` as the current table of `kind`, replacing an earlier one.
    pub fn record(&mut self, kind: u32, data: &[u8]) {
        let entry = (kind, identity(data));
        match self.0.iter_mut().find(|(id, _)| *id == kind) {
            Some(slot) => *slot = entry,
            None => self.0.push(entry),
        }
    }
    #[cfg(test)]
    pub fn recorded(&self) -> &[(u32, Identity)] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_kinds_are_accepted_v5_kinds_refuse_and_records_replace() {
        assert_eq!(classify(110), Some(Ok("TT")));
        assert_eq!(classify(205), Some(Ok("BDR_AF")));
        assert!(matches!(classify(332), Some(Err(_))));
        assert!(matches!(classify(346), Some(Err(_))));
        // The private requests the die already serves are not tables.
        for other in [6, 0x0d, 0x38, 0xba, 0x120] {
            assert_eq!(classify(other), None);
        }
        let mut tables = Tables::default();
        tables.record(110, &[1; 16]);
        tables.record(153, &[2; 16]);
        tables.record(110, &[3; 32]);
        let recorded = tables.recorded();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0], (110, identity(&[3; 32])));
        assert_eq!(recorded[1].1.bytes, 16);
    }
}

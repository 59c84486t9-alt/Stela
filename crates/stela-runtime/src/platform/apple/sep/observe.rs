//! Opt-in observation of the SEP application services whose request and
//! reply contracts are not recovered: `sks` (AppleKeyStore), `pnon`
//! (BootPolicy) and `scrd` (AppleCredentialManager).
//!
//! These contracts are learned by watching what the unchanged kernel sends
//! to Stela's own SEP model, not by recovering sepOS. With observation on,
//! the SEP also advertises these services, so their kernel clients bind and
//! register OOL buffers. Each request is then recorded in the SEP's
//! [`Journal`] (the frame and a bounded prefix of its OOL input) and refused
//! by name, with no reply: the boot stops at that request with the evidence
//! in the log. Observation never answers a request; it is a diagnostic mode,
//! off by default, and a run with it on qualifies nothing beyond what it logs.
//!
//! The capacities are Stela's broad diagnostic choice, one to 32 SEP pages
//! each way, not recovered limits: a client whose registration falls
//! outside them is refused by length, which the journal also records.
use super::endpoint::Service;
use alloc::{collections::VecDeque, format, string::String};

/// Stela's catalog IDs for the observed services, after the xART pair.
pub const KEYSTORE_ID: u8 = 0x12;
pub const BOOT_POLICY_ID: u8 = 0x13;
pub const CREDENTIALS_ID: u8 = 0x14;
const CAPACITIES: [u8; 4] = [1, 0x20, 1, 0x20];
/// The OOL input prefix each recorded request logs: one 4 KiB page, enough
/// for a whole LocalPolicy-sized request, since every observed request
/// stops the boot and so costs a full restore run.
pub const INPUT_PREFIX: usize = 4096;
/// Lines the journal keeps before the host drains it; older ones are counted.
const JOURNAL_LINES: usize = 512;

pub fn services() -> [Service; 3] {
    [
        Service {
            id: KEYSTORE_ID,
            name: u32::from_be_bytes(*b"sks\0"),
            capacities: CAPACITIES,
        },
        Service {
            id: BOOT_POLICY_ID,
            name: u32::from_be_bytes(*b"pnon"),
            capacities: CAPACITIES,
        },
        Service {
            id: CREDENTIALS_ID,
            name: u32::from_be_bytes(*b"scrd"),
            capacities: CAPACITIES,
        },
    ]
}

/// The observed service's name, if `id` is one.
pub fn name(id: u8) -> Option<&'static str> {
    match id {
        KEYSTORE_ID => Some("sks"),
        BOOT_POLICY_ID => Some("pnon"),
        CREDENTIALS_ID => Some("scrd"),
        _ => None,
    }
}

/// The refusal that ends an observed request.
pub fn refusal(id: u8) -> &'static str {
    match id {
        KEYSTORE_ID => "SEP sks request recorded (--sep-observe); its contract is not recovered",
        BOOT_POLICY_ID => {
            "SEP pnon request recorded (--sep-observe); its contract is not recovered"
        }
        CREDENTIALS_ID => {
            "SEP scrd request recorded (--sep-observe); its contract is not recovered"
        }
        _ => "SEP application service is not modeled",
    }
}

/// What the SEP observed, as text lines for the boot log. Bounded: when the
/// host does not drain it, the oldest lines are dropped and counted.
#[derive(Default)]
pub struct Journal {
    lines: VecDeque<String>,
    dropped: usize,
}

impl Journal {
    pub fn record(&mut self, line: String) {
        if self.lines.len() == JOURNAL_LINES {
            self.lines.pop_front();
            self.dropped += 1;
        }
        self.lines.push_back(line);
    }

    /// The recorded lines, oldest first, preceded by a count of any dropped.
    pub fn drain(&mut self) -> impl Iterator<Item = String> + '_ {
        let dropped = core::mem::take(&mut self.dropped);
        (dropped != 0)
            .then(|| format!("journal dropped {dropped} older lines"))
            .into_iter()
            .chain(self.lines.drain(..))
    }
}

/// `bytes` as lowercase hexadecimal, for a journal line.
pub fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn the_observed_catalog_is_valid_and_disjoint_from_xart() {
        let mut all = super::super::xart::services().to_vec();
        all.extend(services());
        assert!(super::super::endpoint::Catalog::new(all).is_ok());
        for service in services() {
            assert!(name(service.id).is_some());
            assert!(service.accepts(true, 0x14000, 0x4000));
            assert!(!service.accepts(true, 0x84000, 0x4000));
            assert!(refusal(service.id).contains(name(service.id).unwrap()));
        }
        assert_eq!(name(0x11), None);
    }

    #[test]
    fn the_journal_is_bounded_and_drains_in_order() {
        let mut journal = Journal::default();
        for n in 0..JOURNAL_LINES + 2 {
            journal.record(format!("{n}"));
        }
        let lines: Vec<String> = journal.drain().collect();
        assert_eq!(lines[0], "journal dropped 2 older lines");
        assert_eq!(lines[1], "2");
        assert_eq!(lines.len(), JOURNAL_LINES + 1);
        assert_eq!(journal.drain().count(), 0);
    }
}

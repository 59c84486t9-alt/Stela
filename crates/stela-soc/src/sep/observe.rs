//! Opt-in journal of the SEP's keystore (`sks`), BootPolicy (`pnon`) and
//! credential manager (`scrd`) traffic.
//!
//! With observation on (`--sep-observe`), each request to one of these
//! services is recorded in the SEP's [`Journal`]: the frame and a bounded
//! prefix of its OOL input, read by the SEP model, not by recovering sepOS.
//! `sks` and `pnon` are native services ([`super::keystore`],
//! [`super::boot_policy`]) and are answered as usual after the record; the
//! journal shows the bodies of the commands they refuse. `scrd`'s contract
//! is not recovered: observation alone advertises it, so its kernel client
//! binds and registers OOL buffers, and each request is recorded and never
//! answered: the kernel client times out on its own and the run goes on to
//! record the requests that follow (docs/design/runtime.md "Unsupported
//! operations" names this diagnostic exception). Observation is
//! off by default, and a run with it on checks nothing beyond its log.
//!
//! The `scrd` capacities are Stela's broad diagnostic choice, one to 32 SEP
//! pages each way, not recovered limits: a client whose registration falls
//! outside them is refused by length.
use super::{boot_policy, endpoint::Service, keystore};
use alloc::{collections::VecDeque, format, string::String};

/// Stela's catalog ID for `scrd`, after the native services.
pub const CREDENTIALS_ID: u8 = 0x14;
const CAPACITIES: [u8; 4] = [1, 0x20, 1, 0x20];
/// The OOL input prefix each recorded request logs: one 4 KiB page, enough
/// for a whole LocalPolicy-sized request, since each observation costs a
/// full boot run.
pub const INPUT_PREFIX: usize = 4096;
/// Lines the journal keeps before the host drains it; older ones are counted.
const JOURNAL_LINES: usize = 512;

/// The services only observation advertises.
pub fn services() -> [Service; 1] {
    [Service {
        id: CREDENTIALS_ID,
        name: u32::from_be_bytes(*b"scrd"),
        capacities: CAPACITIES,
    }]
}

/// The journaled service's name, if `id` is one.
pub fn name(id: u8) -> Option<&'static str> {
    match id {
        keystore::ID => Some("sks"),
        boot_policy::ID => Some("pnon"),
        CREDENTIALS_ID => Some("scrd"),
        _ => None,
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
    fn the_observed_catalog_is_valid_and_disjoint_from_the_native_services() {
        let mut all = super::super::xart::services().to_vec();
        all.extend([keystore::service(), boot_policy::service()]);
        all.extend(services());
        assert!(super::super::endpoint::Catalog::new(all).is_ok());
        let [scrd] = services();
        assert_eq!(name(scrd.id), Some("scrd"));
        assert!(scrd.accepts(true, 0x14000, 0x4000));
        assert!(!scrd.accepts(true, 0x84000, 0x4000));
        assert_eq!(
            (name(keystore::ID), name(boot_policy::ID)),
            (Some("sks"), Some("pnon"))
        );
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

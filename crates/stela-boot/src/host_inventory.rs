//! What the boot learns of the PC on the way, for the guest's `StelaHost`
//! registry dictionary: each owner records its facts once, and the engine
//! writes them into the StelaGPU gate nodes' `stela-host` property
//! (`stela_loader::stela_gpu::encode_host`). Only model-level facts: no
//! serial numbers, addresses or other identifiers of the machine or person.
//!
//! The engine runs from a relocated copy of the image, whose statics start
//! afresh, so the loader's facts (CPU, RAM, firmware, SMBIOS) cross in the
//! handoff ([`save`], [`restore`]) as the status history does.
use alloc::{string::String, vec::Vec};
use core::cell::RefCell;
use stela_loader::stela_gpu::HostValue;

/// One processor runs the mount, and every access is a `try_borrow_mut`: a
/// fact recorded while the list is in use is dropped rather than re-entered.
struct Global(RefCell<Vec<(String, HostValue)>>);
// SAFETY: see `Global`.
unsafe impl Sync for Global {}

static ENTRIES: Global = Global(RefCell::new(Vec::new()));

/// Records `key`, replacing an earlier value.
pub fn record(key: impl Into<String>, value: HostValue) {
    let key = key.into();
    if let Ok(mut entries) = ENTRIES.0.try_borrow_mut() {
        match entries.iter_mut().find(|(known, _)| *known == key) {
            Some(entry) => entry.1 = value,
            None => entries.push((key, value)),
        }
    }
}

pub fn text(key: impl Into<String>, value: impl Into<String>) {
    record(key, HostValue::Text(value.into()));
}

pub fn number(key: impl Into<String>, value: u64) {
    record(key, HostValue::Number(value));
}

/// Every fact recorded so far, in recording order.
pub fn entries() -> Vec<(String, HostValue)> {
    ENTRIES
        .0
        .try_borrow()
        .map(|entries| entries.clone())
        .unwrap_or_default()
}

/// The handoff's room for the loader's facts.
pub const HANDOFF_BYTES: usize = 2048;

/// Writes the facts so far into `into` as a host record, whole lines only,
/// answering its length; facts past the room are left out.
pub fn save(into: &mut [u8; HANDOFF_BYTES]) -> usize {
    let Ok(record) = stela_loader::stela_gpu::encode_host(&entries()) else {
        return 0;
    };
    let mut bytes = record.len().min(HANDOFF_BYTES);
    while bytes > 0 && bytes < record.len() && record[bytes - 1] != b'\n' {
        bytes -= 1;
    }
    into[..bytes].copy_from_slice(&record[..bytes]);
    bytes
}

/// Records the facts a loader [`save`]d, keeping any recorded since.
pub fn restore(saved: &[u8]) {
    let Ok(restored) = stela_loader::stela_gpu::decode_host(saved) else {
        return;
    };
    for (key, value) in restored {
        let known = ENTRIES
            .0
            .try_borrow()
            .is_ok_and(|entries| entries.iter().any(|(entry, _)| *entry == key));
        if !known {
            record(key, value);
        }
    }
}

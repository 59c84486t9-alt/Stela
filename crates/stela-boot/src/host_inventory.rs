//! What the boot learns of the PC on the way, for the guest's `StelaHost`
//! registry dictionary: each owner records its facts once, and the engine
//! writes them into the StelaGPU gate nodes' `stela-host` property
//! (`stela_loader::stela_gpu::encode_host`). Only model-level facts: no
//! serial numbers, addresses or other identifiers of the machine or person.
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
#[cfg_attr(
    not(feature = "nvk"),
    expect(dead_code, reason = "only the StelaGPU gate nodes carry the record")
)]
pub fn entries() -> Vec<(String, HostValue)> {
    ENTRIES
        .0
        .try_borrow()
        .map(|entries| entries.clone())
        .unwrap_or_default()
}

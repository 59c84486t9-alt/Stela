//! Actual compile-time bytes; the shared launcher separately binds all three crates.
use std::collections::BTreeMap;

macro_rules! compiled_sources {
    ($($path:literal),* $(,)?) => {
        BTreeMap::from([$(($path, stela_core::sha256(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"), "/../../", $path
        ))))),*])
    };
}

pub(super) fn compiled_sources() -> BTreeMap<&'static str, String> {
    compiled_sources!(
        "Cargo.toml",
        "Cargo.lock",
        "crates/stela-core/src/lib.rs",
        "crates/stela-compiler/src/lib.rs",
        "crates/stela-compiler/src/block.rs",
        "crates/stela-compiler/src/block/system.rs",
        "crates/stela-compiler/src/aarch64/system/synchronization.rs",
        "crates/stela-compiler/src/x86_64/block.rs",
        "crates/stela-runtime/src/lib.rs",
        "crates/stela-runtime/src/blocks.rs",
        "crates/stela-runtime/src/execution.rs",
        "crates/stela-runtime/src/system/access.rs",
        "crates/stela-runtime/src/system/events.rs",
        "crates/stela-runtime/src/system/execution.rs",
        "crates/stela-runtime/src/system/pstate.rs",
        "crates/stela-runtime/src/system/state.rs",
        "crates/stela-runtime/src/system/exception.rs",
        "crates/stela-runtime/src/system/profile.rs",
        "crates/stela-runtime/src/system/execution/tests.rs",
        "crates/stela-runtime/src/system/execution/tests/event_corpus.rs",
        "crates/stela-runtime/src/system/execution/tests/event_corpus/backend.rs",
        "crates/stela-runtime/src/system/execution/tests/event_corpus/provenance.rs",
        "crates/stela-runtime/src/system/execution/tests/event_corpus/source_inventory.rs",
    )
}

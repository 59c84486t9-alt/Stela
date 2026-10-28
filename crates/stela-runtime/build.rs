//! Fingerprint the runtime sources: with the compiler's own fingerprint they
//! make the persistent translation store's translator id
//! (`translations::translator_id`).
//!
//! The whole engine and its shared contracts, formats and cryptography are
//! fingerprinted. What the engine gives the compiler for a block depends on
//! the dispatch loop, guest memory layout, block
//! translation, PAuth services, the CPU model and the store format, which
//! span most of the crate; a hand-maintained file list or ABI version
//! constant goes stale silently when one of them changes, while a whole-crate
//! digest at worst discards translations that were still valid.
fn main() {
    // `host_memory`: guest memory on the host's POSIX mappings, which hosted
    // execution runs on. A std build elsewhere (Windows, for setup) has none
    // and refuses such requests, as the UEFI build does without boot RAM.
    println!("cargo::rustc-check-cfg=cfg(host_memory)");
    if std::env::var_os("CARGO_FEATURE_STD").is_some()
        && std::env::var_os("CARGO_CFG_UNIX").is_some()
    {
        println!("cargo::rustc-cfg=host_memory");
    }
    stela_fingerprint::emit(
        "STELA_ENGINE_SOURCE_SHA256",
        &[
            "Cargo.toml",
            "build.rs",
            "src",
            "../stela-contracts/Cargo.toml",
            "../stela-contracts/src",
            "../stela-formats/Cargo.toml",
            "../stela-formats/src",
            "../stela-crypto/Cargo.toml",
            "../stela-crypto/src",
        ],
    );
}

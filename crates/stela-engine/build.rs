//! Fingerprint what decides the code a block translation holds: with the
//! compiler's own fingerprint it makes the persistent translation store's
//! translator id (`translations::translator_id`,
//! `docs/design/runtime.md#persistent-translation-store`).
//!
//! A stored entry is the compiler's output for its admitted input bytes, PC
//! and entry context. The context describes every preparation input
//! (`Preparation::context`), and the admitted input is compared byte for
//! byte before reuse, so chip admission checks itself. What else decides a
//! block is fingerprinted here: block preparation (`prepare.rs` and the
//! constants of `block_inputs.rs`), the record format, proof and relocation
//! (`translations`, `stored.rs`), and the chip's access checks that end a
//! block (Contracts' `chip` and `cpu_features`). The rest of the engine, the
//! other crates and the lock files are not inputs: rebuilding them leaves
//! the store warm. Unit-test modules are left out. A test in
//! `translations/tests.rs` checks that these files name no other engine
//! module.
fn main() {
    // `host_memory`: POSIX mappings for generic native-code validation.
    // A std build elsewhere (Windows, for setup) has none
    // and refuses such requests, as the UEFI build does without boot RAM.
    println!("cargo::rustc-check-cfg=cfg(host_memory)");
    if std::env::var_os("CARGO_FEATURE_STD").is_some()
        && std::env::var_os("CARGO_CFG_UNIX").is_some()
    {
        println!("cargo::rustc-cfg=host_memory");
    }
    stela_fingerprint::emit_with(
        "STELA_ENGINE_SOURCE_SHA256",
        &TRANSLATION_INPUTS,
        &stela_fingerprint::Options {
            skip_test_modules: true,
            locked: &[],
        },
    );
    println!(
        "cargo:rustc-env=STELA_ENGINE_TRANSLATION_INPUTS={}",
        TRANSLATION_INPUTS.join(" ")
    );
}

/// The engine's and Contracts' translation inputs, relative to this crate.
const TRANSLATION_INPUTS: [&str; 9] = [
    "build.rs",
    "src/machine/engine/block_inputs.rs",
    "src/machine/engine/prepare.rs",
    "src/machine/engine/stored.rs",
    "src/translations.rs",
    "src/translations",
    "../stela-contracts/src/chip.rs",
    "../stela-contracts/src/chip",
    "../stela-contracts/src/cpu_features.rs",
];

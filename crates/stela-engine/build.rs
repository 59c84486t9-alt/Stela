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
    // `host_memory`: POSIX mappings for generic native-code validation.
    // A std build elsewhere (Windows, for setup) has none
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
            "../stela-driver-core/Cargo.toml",
            "../stela-driver-core/src",
            "../stela-contracts/Cargo.toml",
            "../stela-contracts/src",
            "../stela-formats/Cargo.toml",
            "../stela-formats/src",
            "../stela-crypto/Cargo.toml",
            "../stela-crypto/src",
            "../stela-soc-data/Cargo.toml",
            "../stela-soc-data/src",
            "../stela-runtime/Cargo.toml",
            "../stela-runtime/src",
            "../stela-tls/Cargo.toml",
            "../stela-tls/build.rs",
            "../stela-tls/src",
            "../stela-tls/include",
            "../stela-tls/stela_alloc.h",
            "../stela-tls/stela_mbed_kx.c",
            "../stela-tls/stela_mbed_kx.h",
            "../stela-tls/stela_mbedcrypto_config.h",
            "../../third_party/mbedtls",
            "../../third_party/smoltcp/Cargo.toml",
            "../../third_party/smoltcp/build.rs",
            "../../third_party/smoltcp/src",
            "../../Cargo.toml",
            "../../Cargo.lock",
            "../stela-boot/Cargo.toml",
            "../stela-boot/Cargo.lock",
            "../../.cargo/config.toml",
        ],
    );
}

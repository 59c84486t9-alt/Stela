//! Fingerprint the compiler sources so cached native code is bound to them:
//! every non-test source, and the locked version of the one registry
//! package whose code computes emitted values (`rustc_apfloat`, with its
//! dependencies) in either workspace's lock file. Serde only derives
//! (de)serialization, which no emitted code depends on.
fn main() {
    stela_fingerprint::emit_with(
        "STELA_COMPILER_SOURCE_SHA256",
        &["Cargo.toml", "build.rs", "src"],
        &stela_fingerprint::Options {
            skip_test_modules: true,
            locked: &[
                ("../../Cargo.lock", &["rustc_apfloat"]),
                ("../stela-boot/Cargo.lock", &["rustc_apfloat"]),
            ],
        },
    );
}

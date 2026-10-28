//! Fingerprint the compiler sources so cached native code is bound to them.
fn main() {
    stela_fingerprint::emit(
        "STELA_COMPILER_SOURCE_SHA256",
        &["Cargo.toml", "build.rs", "src"],
    );
}

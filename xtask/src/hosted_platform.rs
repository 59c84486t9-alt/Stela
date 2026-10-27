//! Host requirements of the real Darwin process and fault-recovery adapters.
pub fn require(operation: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        cfg!(all(target_os = "macos", target_arch = "x86_64")),
        "{operation} requires an Intel Mac (macOS on x86_64); this host is {} on {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    Ok(())
}

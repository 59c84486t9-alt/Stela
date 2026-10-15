//! Preserve the entire native caller MXCSR across preparation, callbacks and cleanup.
pub(crate) struct HostFloatingEnvironment {
    #[cfg(target_arch = "x86_64")]
    mxcsr: u32,
}
impl HostFloatingEnvironment {
    pub(crate) fn capture() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            let mut mxcsr = 0;
            // SAFETY: MXCSR is present on every admitted x86-64 host. The valid
            // writable scalar lives for this instruction and no flags change.
            unsafe {
                std::arch::asm!("stmxcsr [{address}]", address = in(reg) &mut mxcsr, options(nostack, preserves_flags));
            }
            Self { mxcsr }
        }
        #[cfg(not(target_arch = "x86_64"))]
        Self {}
    }
}
impl Drop for HostFloatingEnvironment {
    fn drop(&mut self) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: This exact full value was read from the current caller's
        // hardware MXCSR; reserved bits cannot have been synthesized here.
        unsafe {
            std::arch::asm!("ldmxcsr [{address}]", address = in(reg) &self.mxcsr, options(nostack, preserves_flags));
        }
    }
}

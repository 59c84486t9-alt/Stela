//! Host CPU admission for each independently owned execution boundary.
pub(crate) mod system;
pub(crate) fn admitted(target: stela_compiler::TargetCpu) -> bool {
    #[cfg(feature = "std")]
    {
        target.supported()
    }
    #[cfg(not(feature = "std"))]
    {
        crate::platform::boot::admitted(target)
    }
}

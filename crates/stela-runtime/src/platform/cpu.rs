//! Plain compiler target metadata cannot qualify the actual boot CPU/controls.
//! The concrete loader CPU admission owner remains an explicit mount dependency.
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

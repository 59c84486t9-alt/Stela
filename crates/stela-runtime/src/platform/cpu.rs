//! Boot CPU feature admission (provided by the loader).
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

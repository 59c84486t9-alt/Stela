//! Plain compiler target metadata cannot qualify the actual boot CPU/controls.
//! The concrete loader CPU admission owner remains an explicit mount dependency.
pub(crate) fn admitted(target: stela_compiler::TargetCpu) -> bool {
    #[cfg(feature = "std")]
    {
        target.supported()
    }
    #[cfg(not(feature = "std"))]
    {
        let _ = target;
        // No freestanding platform has supplied the actual CPU/control owner.
        // Refuse every target, including baseline, until that owner is mounted.
        false
    }
}

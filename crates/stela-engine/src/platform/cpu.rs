//! Host CPU admission for each independently owned execution boundary.
pub(crate) mod system;
#[cfg(feature = "std")]
pub(crate) fn admitted(target: stela_compiler::TargetCpu) -> bool {
    target.supported()
}
/// The freestanding build admits no host execution boundary.
#[cfg(not(feature = "std"))]
pub(crate) fn admitted(_target: stela_compiler::TargetCpu) -> bool {
    false
}

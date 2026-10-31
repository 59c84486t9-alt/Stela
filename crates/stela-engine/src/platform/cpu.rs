//! Host CPU admission for each independently owned execution boundary.
pub(crate) mod system;
#[cfg(all(feature = "std", not(test)))]
pub(crate) fn admitted(target: stela_compiler::TargetCpu) -> bool {
    target.supported()
}
/// Tests also run blocks on the instructions the host's SIGILL models provide.
#[cfg(all(feature = "std", test))]
pub(crate) fn admitted(target: stela_compiler::TargetCpu) -> bool {
    stela_compiler::x86_64::modeled::host().supports(target)
}
/// The freestanding build admits no host execution boundary.
#[cfg(not(feature = "std"))]
pub(crate) fn admitted(_target: stela_compiler::TargetCpu) -> bool {
    false
}

//! Executable mappings for translated native code, one implementation per host.

#[cfg(all(target_arch = "x86_64", target_os = "none", not(feature = "std")))]
mod freestanding;
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
mod hosted;
#[cfg(not(any(
    all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")),
    all(target_arch = "x86_64", target_os = "none", not(feature = "std"))
)))]
mod unsupported;

#[cfg(all(target_arch = "x86_64", target_os = "none", not(feature = "std")))]
pub use freestanding::*;
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
pub use hosted::*;
#[cfg(not(any(
    all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")),
    all(target_arch = "x86_64", target_os = "none", not(feature = "std"))
)))]
pub use unsupported::*;

use super::*;

#[cfg(target_arch = "x86_64")]
mod basic_pauth;
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
mod clock_dispatch;
mod numerical_validation;
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
mod resident;
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
mod system_boundary;
mod trap_validation;

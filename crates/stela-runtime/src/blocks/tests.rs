#[cfg(target_arch = "x86_64")]
use super::services::complete_pauth;
use super::*;
use stela_compiler::{
    GuestState,
    block::{
        ClockOperation, PointerAuthentication, PointerAuthenticationKey,
        PointerAuthenticationModifier, decode_clock_instruction, decode_pointer_authentication,
        decode_trap,
    },
};

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

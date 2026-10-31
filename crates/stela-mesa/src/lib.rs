//! NVK, NIR and NAK, linked into `stela.efi` (`docs/design/metal-device.md`).
//!
//! The C is the archive `cargo xtask gpu nvk` builds; the Rust is NAK and NIL
//! as dependencies of this crate. Nothing but the driver's loader entry is
//! called from Rust: Mesa reaches its host through `compat/libc`.
#![no_std]

extern crate nak;
extern crate nil;

use core::ffi::{c_char, c_void};

unsafe extern "system" {
    /// The Vulkan loader-ICD entry of NVK.
    pub fn vk_icdGetInstanceProcAddr(instance: *mut c_void, name: *const c_char) -> *const c_void;
}

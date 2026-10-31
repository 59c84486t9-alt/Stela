//! NVK, NIR and NAK, linked into `stela.efi` (`docs/design/metal-device.md`).
//!
//! The C is the archive `cargo xtask gpu nvk` builds; the Rust is NAK and NIL
//! as dependencies of this crate. Nothing but the driver's loader entry and the
//! start of the C is called from here: Mesa reaches its host through
//! `compat/libc`, and the Metal compiler is `metal::compiler`'s.
#![no_std]

extern crate nak;
extern crate nil;

use core::ffi::{c_char, c_void};

unsafe extern "system" {
    /// The Vulkan loader-ICD entry of NVK.
    pub fn vk_icdGetInstanceProcAddr(instance: *mut c_void, name: *const c_char) -> *const c_void;
}

unsafe extern "C" {
    /// Runs the image's C and C++ static constructors, before anything else
    /// of theirs.
    pub fn stela_constructors();
}

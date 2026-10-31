//! The build script's registry generator: build scripts have no test harness.
#![allow(dead_code, reason = "the build script uses what these tests do not")]

#[path = "../build/inputs.rs"]
mod inputs;
#[path = "../build/linux_registry.rs"]
mod linux_registry;

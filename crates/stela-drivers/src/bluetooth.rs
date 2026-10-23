// SPDX-License-Identifier: MIT
//! Physical Bluetooth transports independent of the USB bus and guest frontend.
pub(crate) mod hci;
pub mod intel;
pub mod intel_pcie;

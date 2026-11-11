// SPDX-License-Identifier: GPL-2.0-or-later
//! Physical Bluetooth transports independent of the USB bus and guest frontend.
pub mod bcm4377;
pub(crate) mod hci;
pub mod intel;
pub mod intel_pcie;

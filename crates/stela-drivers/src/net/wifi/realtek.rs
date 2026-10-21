// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
// Copyright(c) 2019-2020 Realtek Corporation
//! Native Realtek PCIe Wi-Fi firmware primitives for Stela's macOS backend.
//! Pinned rtw88/rtw89 are hardware references, not a Linux kernel interface.
//! Staging does not grant PCI/DMA ownership or establish a working radio.
pub mod firmware;
pub mod identity;

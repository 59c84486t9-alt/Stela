// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
// Copyright(c) 2019-2020 Realtek Corporation
//! Native Realtek PCIe Wi-Fi firmware primitives for Stela's macOS backend.
//! Pinned rtw88/rtw89 are hardware references, not a Linux kernel interface.
//! Staging does not grant PCI/DMA ownership or establish a working radio.
pub mod beacon;
pub mod download;
pub mod efuse;
pub mod features;
pub mod fifo;
pub mod firmware;
pub mod firmware_control;
pub mod hci;
pub mod identity;
pub mod interrupt;
pub mod io;
pub mod phy_tables;
pub mod power;
pub mod receive;
pub mod registers;
pub mod rf;
pub mod transmit;

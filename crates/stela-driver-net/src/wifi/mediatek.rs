// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! MediaTek MT7921/MT7922/MT7925 native Wi-Fi primitives, adapted from
//! Linux mt76 at a804c5742bff224d4cb4d25dd383554d598be32b.
//!
//! Exact identity, bounded firmware parsing and download are separate from
//! PCI ownership, WFDMA transport, radio initialization and client association.
//! These primitives do not publish an Ethernet link or claim a ready radio.
pub mod acpi;
pub mod bootstrap;
pub mod control;
pub mod download;
pub mod firmware;
pub mod identity;
pub mod mailbox;
pub mod mcu;
pub mod regd;
pub mod registers;
pub mod reorder;
pub mod ring;
pub mod rx;
pub mod tx_free;
pub mod txp;
pub mod txwi;

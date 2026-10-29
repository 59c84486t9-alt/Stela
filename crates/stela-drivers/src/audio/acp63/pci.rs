// SPDX-License-Identifier: GPL-2.0-only
//! ACP63 PCI/UC adapter; revision63 and exact class048000 are required.
//! Copyright (C) 2022, 2023, 2025 Advanced Micro Devices, Inc.
pub use super::super::acp_pdm::pci::AttachFailure;
pub type NativeRegisters = super::super::acp_pdm::pci::NativeRegisters<super::PinkSardine>;

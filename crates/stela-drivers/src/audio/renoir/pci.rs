// SPDX-License-Identifier: GPL-2.0-only
//! Renoir PCI/UC adapter; revision01 and exact class048000 are required.
//! Copyright (C) 2020 Advanced Micro Devices, Inc.
pub use super::super::acp_pdm::pci::AttachFailure;
pub type NativeRegisters = super::super::acp_pdm::pci::NativeRegisters<super::Renoir>;

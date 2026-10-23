// SPDX-License-Identifier: GPL-2.0-only
//! Actual retained PCI function/UC BAR adapter for ACP70/71/72 class048000.
pub use super::super::acp_pdm::pci::AttachFailure;
pub type NativeRegisters = super::super::acp_pdm::pci::NativeRegisters<super::Ps70>;

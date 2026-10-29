// SPDX-License-Identifier: GPL-2.0-only
//! ACP6x native PCI/UC resource owner; behavior lives in the shared adapter.
//! Copyright (C) 2021 Advanced Micro Devices, Inc. All rights reserved.
pub use super::super::acp_pdm::pci::AttachFailure;
pub type NativeRegisters = super::super::acp_pdm::pci::NativeRegisters<super::YellowCarp>;

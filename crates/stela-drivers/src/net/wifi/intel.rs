// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2008-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
//! Intel Wi-Fi transport and firmware support adapted from pinned iwlwifi.
//!
//! Parsing firmware does not authenticate it or make a radio operational.
//! DMA, ALIVE/NVM/calibration, station association and key installation must
//! complete before a native Wi-Fi backend can provide an Ethernet link.
pub mod context;
pub mod firmware;
pub mod identity;

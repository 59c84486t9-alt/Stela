// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2018 Intel Corporation
//! Native PC Thunderbolt/USB4 NHI control transport.
//!
//! These are physical host-controller protocols, independent of the emulated
//! Apple CIO/USB-C devices. NHI ownership, a real device DMA domain and power
//! resources must be established by the native platform before ring takeover.
//! Config-channel traffic alone grants neither tunnel authorization nor a
//! working connection manager. No PCI ID is admitted by this initial core.
pub mod channel;
pub mod config;
pub mod domain;
pub mod ring;
pub mod topology;

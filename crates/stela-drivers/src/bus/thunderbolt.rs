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
pub mod adapter;
pub mod channel;
pub mod config;
pub mod controller;
pub mod displayport;
pub mod domain;
pub mod drom;
pub mod hop;
pub mod icm;
pub mod link;
pub mod operations;
pub mod path;
pub mod pcie;
pub mod power;
pub mod ring;
pub mod router;
pub mod topology;
pub mod usb3;

/// `timeout` milliseconds after `now`, no later than `limit`: a stage's
/// deadline within its job. None when the clock would overflow.
pub(crate) fn stage_deadline(now: u64, timeout: u64, limit: u64) -> Option<u64> {
    now.checked_add(timeout).map(|deadline| deadline.min(limit))
}

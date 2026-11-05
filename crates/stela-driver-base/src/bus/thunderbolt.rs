// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2018 Intel Corporation
//! Native PC Thunderbolt/USB4 NHI control transport.
//!
//! These are physical host-controller protocols, independent of the emulated
//! Apple CIO/USB-C devices. NHI ownership, a real device DMA domain and power
//! resources must be established by the native platform before ring takeover.
//! Hosts whose firmware runs the connection manager are served by [`icm`];
//! the others by the software one in [`manager`].
pub mod channel;
pub mod cold;
pub mod config;
pub mod controller;
pub mod drom;
pub mod icm;
pub mod manager;
pub mod ring;

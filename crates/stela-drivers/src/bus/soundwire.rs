// SPDX-License-Identifier: GPL-2.0-only
//! SoundWire controller protocols. Actual link resources, frame clocks, reset,
//! firmware arbitration, discovery and audio streams require their original
//! platform owner; a command engine or controller identity grants none of them.
//! Source attribution and finite evidence limits: `soundwire/THIRD_PARTY.md`.
pub mod amd;
pub mod cadence;

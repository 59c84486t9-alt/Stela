// SPDX-License-Identifier: GPL-2.0-only
//! Explicit controller reset boundaries. DMA remains allocated for the boot;
//! software reservations are released only after all engines acknowledge stop.
//! Probe retry adapts Linux sound/hda/controllers/intel.c and
//! sound/hda/common/controller.c at a804c5742bff224d4cb4d25dd383554d598be32b.
//! Copyright(c) 2004 Intel Corporation
//! Copyright (c) 2004 Takashi Iwai <tiwai@suse.de>
//!                     PeiSen Hou <pshou@realtek.com.tw>
use super::{Controller, Registers};
use crate::{Error, bus::i2c::Timer};

impl<R: Registers, T: Timer> Controller<R, T> {
    /// Stop all streams/command engines, then reset and restart command DMA.
    /// All stream IDs, codec graphs and routes from the old generation become
    /// invalid, even if descriptor indices/tags or codec node numbers recur.
    /// On failed quiescence, buffers/reservations remain pinned and ordinary
    /// operations fail with NeedsReset. A later explicit attempt may recover.
    /// This does not restore PCI/ACPI power, ownership, or codec/OEM routes.
    pub fn reinitialize(&mut self) -> Result<(), Error> {
        let generation = self
            .token
            .generation
            .checked_add(1)
            .ok_or(Error::NeedsReset)?;
        let shutdown = self.shutdown();
        self.lifecycle_failed = true;
        if let Err(error) = shutdown
            && !self.stopped
        {
            return Err(error);
        }
        // A failed codec amplifier-off readback can still leave every DMA RUN
        // acknowledged off (stopped=true). Reset is its recovery boundary;
        // that codec failure never licenses reuse without this reset.
        // Invalidate public handles now, but keep the original reservations
        // until link/ring reset and kept GPU cleanup both succeed.
        self.token.generation = generation;
        self.corb_wp = 0;
        self.rirb_rp = 0;
        self.codec_mask = 0;
        // A new generation starts from a fresh command transport and codecs.
        self.outstanding = [0; 15];
        self.single_command = false;
        self.allow_bus_reset = false;
        self.response_reset = false;
        self.writes = super::cache::Writes::default();
        self.discovery_ready = false;
        if let Err(error) = self.initialize() {
            let _ = self.shutdown();
            return Err(error);
        }
        // CRST disabled codec unsolicited state and the controller
        // gate; old tags/events cannot authorize the new reset generation.
        self.unsolicited = super::unsolicited::State::new();
        // New command epoch is live only after link/ring reset. Failed
        // HDMI teardown keeps original owners and requires another reset.
        self.command_poisoned = false;
        self.lifecycle_failed = false;
        self.stopped = false;
        if let Err(error) = self.retire_hdmi_after_reset() {
            self.lifecycle_failed = true;
            self.routing_failed = true;
            return Err(error);
        }
        for stream in &mut self.streams {
            *stream = None;
        }
        self.routes.clear();
        self.codec_controls.clear();
        self.converter_bindings.clear();
        self.realtek_codecs.clear();
        self.conexant_codecs.clear();
        self.sigmatel_codecs.clear();
        self.cirrus_codecs.clear();
        self.command_poisoned = false;
        self.routing_failed = false;
        self.lifecycle_failed = false;
        self.stopped = false;
        Ok(())
    }
}

/// Discovery budget selected from the controller identity. Retry is an
/// explicit pre-stream operation, never a hidden recovery of live DMA/routes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProbePolicy {
    #[default]
    Once,
    /// Total attempts (1..=60), with a delay (1..=1_000_000us) before each retry.
    /// AMD's source-backed policy uses 60 attempts spaced 1_000_000us apart.
    Retry { attempts: u8, delay_us: u32 },
}
impl ProbePolicy {
    pub(super) fn budget(self) -> Result<(u8, u32), Error> {
        match self {
            Self::Once => Ok((1, 0)),
            Self::Retry { attempts, delay_us }
                if (1..=60).contains(&attempts) && (1..=1_000_000).contains(&delay_us) =>
            {
                Ok((attempts, delay_us))
            }
            _ => Err(Error::InvalidConfiguration),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodecFailure {
    /// One-based attempt and the codec address that failed enumeration.
    pub attempt: u8,
    pub address: u8,
    pub error: Error,
}

/// Only graphs from the final, usable reset generation are returned. Failures
/// from earlier attempts and rejected codecs remain visible to the caller.
#[derive(Clone, Debug)]
pub struct CodecDiscovery {
    pub attempts: u8,
    pub codecs: alloc::vec::Vec<super::CodecGraph>,
    pub failures: alloc::vec::Vec<CodecFailure>,
}

#[derive(Clone, Debug)]
pub struct DiscoveryFailure {
    /// Completed discovery attempts; 0 for preflight or an initial refusal.
    pub attempts: u8,
    /// Final discovery or reset/quiescence error. No empty successful result.
    pub error: Error,
    pub failures: alloc::vec::Vec<CodecFailure>,
}

impl<R: Registers, T: Timer> Controller<R, T> {
    /// Enumerate the advertised codecs before any stream has been allocated.
    /// At least one standard audio graph and a healthy command transport are
    /// required. Codec-specific failures are held even on partial success.
    /// Each retry delays, then fully reinitializes the link and command rings;
    /// timed-out/ambiguous responses are never followed by another unsafe verb.
    /// This adapts the bounded retry in Linux intel.c::azx_probe_continue and
    /// common/controller.c::azx_codec_configure; vendor/OEM codec configuration
    /// and analog route success remain separate explicit operations.
    pub fn discover_codecs(&mut self) -> Result<CodecDiscovery, DiscoveryFailure> {
        let mut failures = alloc::vec::Vec::new();
        let preflight = (|| {
            let budget = self.config.probe_policy.budget()?;
            if self.lifecycle_failed || self.command_poisoned || self.routing_failed {
                return Err(Error::NeedsReset);
            }
            if self.stopped {
                return Err(Error::Shutdown);
            }
            if self.streams.iter().any(Option::is_some)
                || !self.routes.is_empty()
                || !self.codec_controls.is_empty()
            {
                return Err(Error::StreamsAllocated);
            }
            Ok(budget)
        })();
        let (limit, delay_us) = preflight.map_err(|error| DiscoveryFailure {
            attempts: 0,
            error,
            failures: alloc::vec::Vec::new(),
        })?;
        self.discovery_ready = false;
        for attempt in 1..=limit {
            let mut codecs = alloc::vec::Vec::new();
            let mut error = Error::CodecAbsent;
            for address in 0..15 {
                if self.codec_mask & (1 << address) == 0 {
                    continue;
                }
                // azx_probe_codecs: a slot whose vendor ID never answers is
                // disabled, and the chip reset back to sanity.
                if let Err(fault) = self.probe_codec(address) {
                    error = fault;
                    failures.push(CodecFailure {
                        attempt,
                        address,
                        error: fault,
                    });
                    self.codec_mask &= !(1 << address);
                    if self.codec_mask == 0 || self.command_poisoned {
                        break;
                    }
                    if let Err(error) = self.reset_chip() {
                        return Err(DiscoveryFailure {
                            attempts: attempt,
                            error,
                            failures,
                        });
                    }
                    continue;
                }
                match self.enumerate_codec(address) {
                    Ok(graph) => codecs.push(graph),
                    Err(fault) => {
                        error = fault;
                        failures.push(CodecFailure {
                            attempt,
                            address,
                            error: fault,
                        });
                    }
                }
                if self.command_poisoned {
                    break;
                }
            }
            if !codecs.is_empty() && !self.command_poisoned {
                self.discovery_ready = true;
                return Ok(CodecDiscovery {
                    attempts: attempt,
                    codecs,
                    failures,
                });
            }
            if attempt == limit {
                return Err(DiscoveryFailure {
                    attempts: attempt,
                    error,
                    failures,
                });
            }
            self.delay(u64::from(delay_us));
            if let Err(error) = self.reinitialize() {
                return Err(DiscoveryFailure {
                    attempts: attempt,
                    error,
                    failures,
                });
            }
        }
        unreachable!("validated discovery budget is nonzero")
    }
}

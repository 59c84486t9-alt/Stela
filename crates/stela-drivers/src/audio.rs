// SPDX-License-Identifier: GPL-2.0-only
//! Native host audio primitives. The HDA backend provides command transport,
//! codec graphs and cyclic PCM DMA; AMD ACP profiles supply direct PDM capture.
pub mod acp63;
pub mod acp6x;
pub mod acp70;
pub mod acp_i2s;
mod acp_pdm;
pub mod hda;
pub mod intel_dsp;
pub mod renoir;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Playback,
    Capture,
}

/// Interleaved little-endian integer PCM. 8-bit samples are unsigned; 20/24-bit
/// samples occupy 32-bit containers, as in Linux's HDA PCM interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcmFormat {
    pub rate: u32,
    pub bits: u8,
    pub channels: u8,
}

impl PcmFormat {
    pub fn frame_bytes(self) -> Result<usize, Error> {
        self.encode()?;
        Ok(usize::from(self.channels) * usize::from(self.bits.div_ceil(8).next_power_of_two()))
    }

    /// One nonempty HDA link packet contains MULT PCM frames. Fractional rates
    /// change packet cadence, not packet size (32k sends two blocks every third
    /// link frame; 176.4k sends four blocks in each nonempty cadence frame).
    pub fn packet_bytes(self) -> Result<usize, Error> {
        let multiplier = usize::from(((self.encode()? >> 11) & 7) + 1);
        Ok(self.frame_bytes()? * multiplier)
    }

    /// SDxFMT / converter format encoding. Only standard discrete PCM rates
    /// are accepted; arbitrary clock ratios and non-PCM formats are explicit.
    pub fn encode(self) -> Result<u16, Error> {
        let rate = match self.rate {
            8_000 => 5 << 8,
            11_025 => (1 << 14) | (3 << 8),
            16_000 => 2 << 8,
            22_050 => (1 << 14) | (1 << 8),
            32_000 => (1 << 11) | (2 << 8),
            44_100 => 1 << 14,
            48_000 => 0,
            88_200 => (1 << 14) | (1 << 11),
            96_000 => 1 << 11,
            176_400 => (1 << 14) | (3 << 11),
            192_000 => 3 << 11,
            _ => return Err(Error::InvalidFormat),
        };
        let bits = match self.bits {
            8 => 0,
            16 => 1,
            20 => 2,
            24 => 3,
            32 => 4,
            _ => return Err(Error::InvalidFormat),
        };
        if !(1..=16).contains(&self.channels) {
            return Err(Error::InvalidFormat);
        }
        Ok(rate | (bits << 4) | u16::from(self.channels - 1))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    LinkResetEnter,
    LinkResetExit,
    CommandStop,
    CommandStart,
    CorbResetEnter,
    CorbResetExit,
    RirbReset,
    Verb,
    StreamStop,
    StreamResetEnter,
    StreamResetExit,
    StreamStart,
    CodecPower,
    DisplayAudio,
    CodecDepop,
    CodecHeadsetDetection,
    LinkPowerDown,
    LinkPowerUp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidConfiguration,
    PciResetControl {
        offset: u16,
    },
    RegisterUnavailable {
        offset: usize,
    },
    UnsupportedVersion {
        major: u8,
        minor: u8,
    },
    UnsupportedRingSize,
    InvalidExtendedCapability {
        offset: usize,
    },
    UnsupportedExtendedCapability {
        id: u16,
        version: u8,
    },
    ProcessingOwned {
        offset: usize,
    },
    UnsupportedLink {
        offset: usize,
    },
    LinkPowerUncertain {
        offset: usize,
    },
    LinkClockRejected {
        offset: usize,
    },
    UnsupportedTopology,
    InvalidVerb,
    CodecAbsent,
    InvalidCodecGraph,
    InvalidHdmiPort,
    InvalidEld,
    InvalidChannelMap,
    SinkUnavailable,
    SinkChanged,
    PlaybackUnderrun,
    InvalidConnectionList,
    InvalidFormat,
    InvalidBuffer,
    LinkBandwidth {
        required_words: u16,
        available_words: u16,
    },
    NoDmaMemory,
    DmaAddress,
    NoStream,
    StreamsAllocated,
    NeedsDiscovery,
    InvalidStream,
    StreamRunning,
    StreamStopped,
    Timeout(Phase),
    CorbMemory,
    RirbOverrun,
    UnexpectedResponse {
        codec: u8,
    },
    InvalidRingPointer,
    StreamDma {
        status: u8,
    },
    InvalidPosition(u32),
    ConverterRejected,
    CoefficientRejected {
        node: u8,
        index: u16,
    },
    InvalidPinControl,
    InvalidJackNotification,
    JackNotificationTagsExhausted,
    RouteRejected,
    RouteInUse,
    /// A command timeout makes later replies ambiguous. A full controller
    /// reset/platform reinitialization is required before further commands.
    NeedsReset,
    Shutdown,
}

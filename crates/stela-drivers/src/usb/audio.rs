// SPDX-License-Identifier: GPL-2.0-or-later
//! USB Audio Class 2 PCM, with descriptor-selected clocks and endpoints.
//! Mixer adaptation retains Copyright (c) 2002 Takashi Iwai; original audio.c
//! contributions by Alan Cox and Thomas Sailer. UAC2 layout reference retains
//! Copyright (c) 2010 Daniel Mack. See stela-drivers/THIRD_PARTY.md.
//! Control/rate/feedback sequencing adapts Linux sound/usb/{clock,format,
//! endpoint,pcm,mixer}.c at a804c5742bff224d4cb4d25dd383554d598be32b.
//! No codec node, interface, clock, alternate, channel or sample rate is inferred
//! from the product name. The supported ASUS/Realtek USB2 identity selects the
//! standard UAC2 parser; its actual descriptors must satisfy that contract.
use super::xhci::{Endpoint, Interface};
use crate::{audio::Direction, block::BlockError};

mod control;
mod descriptors;
mod native;
mod packet;
pub use native::{Native, UsbAudio};
mod stream;
pub use control::{Control, RateRange, ResolvedClock};
pub use descriptors::{Binding, Entity, Format, Graph, Sync};

pub const CLASS: u8 = 1;
pub const CONTROL_SUBCLASS: u8 = 1;
pub const STREAMING_SUBCLASS: u8 = 2;
pub const UAC2: u8 = 0x20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Descriptor(&'static str),
    Unsupported(&'static str),
    Transport(BlockError),
    ControlLength,
    ControlReadback,
    ClockInvalid,
    RateUnsupported,
    Format,
    Busy,
    NotRunning,
    Feedback,
    Underrun,
    Overrun,
    Packet(&'static str),
    Poisoned,
}
impl From<BlockError> for Error {
    fn from(error: BlockError) -> Self {
        Self::Transport(error)
    }
}

/// A terminal isochronous packet completion releases its buffer even when the
/// packet failed. Transport errors do not grant ownership back to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketStatus {
    Success,
    Short,
    MissedService,
    Transaction,
    Babble,
    Bandwidth,
    BufferOverrun,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub bytes: usize,
    pub status: PacketStatus,
}

/// Actual control/isochronous ownership boundary, also used by stateful tests.
/// `deconfigure` must acknowledge endpoint stop, drain and context removal
/// before returning success. Implementations retain all DMA on any uncertainty.
pub trait Transport: Control {
    type Ticket;
    fn configure(&mut self, owner: Direction, endpoints: &[Endpoint]) -> Result<(), BlockError>;
    fn deconfigure(&mut self, owner: Direction, endpoints: &[Endpoint]) -> Result<(), BlockError>;
    fn submit(
        &mut self,
        endpoint: &Endpoint,
        physical: u64,
        bytes: usize,
    ) -> Result<Self::Ticket, BlockError>;
    fn completed(&mut self, ticket: &Self::Ticket) -> Option<Result<Completion, BlockError>>;
}

/// This PC's source-selected standard USB2 profile. The Linux donor has no
/// 0b05:1be1-specific audio/implicit-feedback quirk: class descriptors decide
/// behavior. The bcdDevice bound records the saved inventory, not a new quirk.
pub fn supported_identity(descriptor: &[u8; 18], speed: u8) -> bool {
    u16::from_le_bytes([descriptor[8], descriptor[9]]) == 0x0b05
        && u16::from_le_bytes([descriptor[10], descriptor[11]]) == 0x1be1
        && u16::from_le_bytes([descriptor[12], descriptor[13]]) == 2
        && u16::from_le_bytes([descriptor[2], descriptor[3]]) == 0x0200
        && descriptor[4..7] == [0xef, 2, 1]
        && speed == 3
}

pub(super) fn plan(
    interface: &Interface,
    all: &[Interface],
    configuration: &[u8],
    speed: u8,
) -> Result<Binding, Error> {
    Binding::parse(interface, all, configuration, speed)
}

pub use stream::{AudioDevice, Progress};

#[cfg(test)]
pub(crate) use stream::tests::configuration as test_configuration;

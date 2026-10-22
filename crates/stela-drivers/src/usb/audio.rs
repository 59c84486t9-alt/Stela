// SPDX-License-Identifier: GPL-2.0-or-later
//! USB Audio Class 2 PCM, with descriptor-selected clocks and endpoints.
//! Mixer adaptation retains Copyright (c) 2002 Takashi Iwai; original audio.c
//! contributions by Alan Cox and Thomas Sailer. UAC2 layout reference retains
//! Copyright (c) 2010 Daniel Mack. See stela-drivers/THIRD_PARTY.md.
//! Control/rate/feedback sequencing adapts Linux sound/usb/{clock,format,
//! endpoint,pcm,mixer}.c at a804c5742bff224d4cb4d25dd383554d598be32b.
//! Like snd-usb-audio, any UAC2 audio control interface binds by class; its
//! descriptors alone decide clocks, alternates, channels and sample rates.
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
    /// Observe that every proposed DCI is unowned, before SET_INTERFACE or any
    /// cleanup plan is staged. Callers serialize this observation with mutation.
    fn preflight(&mut self, endpoints: &[Endpoint]) -> Result<(), BlockError>;
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

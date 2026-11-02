//! Owning attachment refusals; diagnostics do not release the physical graph.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalCause {
    Transport(Error),
    Descriptor(ParseError),
}

/// The same device, including its bus, interrupt, clock and minimum provider.
/// Dropping this carrier retains those owners; it proves no platform detach.
pub struct Refusal<B, I, T> {
    pub error: RefusalCause,
    device: ManuallyDrop<Device<B, I, T>>,
}
impl<B, I, T> Refusal<B, I, T> {
    pub(super) fn transport(device: ManuallyDrop<Device<B, I, T>>, error: Error) -> Self {
        Self {
            device,
            error: RefusalCause::Transport(error),
        }
    }
    pub(super) fn descriptor(device: ManuallyDrop<Device<B, I, T>>, error: ParseError) -> Self {
        Self {
            device,
            error: RefusalCause::Descriptor(error),
        }
    }
    pub fn device(&self) -> &Device<B, I, T> {
        &self.device
    }
}
impl<B, I, T> core::fmt::Debug for Refusal<B, I, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Refusal")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

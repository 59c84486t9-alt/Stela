//! Actual controller construction custody before Self exists.
use super::Controller;
use crate::bus::dma::DmaBuffer;
use alloc::boxed::Box;

pub type ConstructionFailure<R, T> = crate::Refusal<Construction<R, T>, crate::Error>;
/// Failed construction keeps the same register/timer, partial DMA and core
/// graph. There is no retry or physical-owner reconstruction from metadata.
pub struct Construction<R, T> {
    pub(super) registers: Option<R>,
    pub(super) timer: Option<T>,
    pub allocation_error: Option<stela_driver_base::block::BlockError>,
    pub(super) corb: Option<DmaBuffer>,
    pub(super) rirb: Option<DmaBuffer>,
    pub(super) controller: Option<Box<Controller<R, T>>>,
}
impl<R, T> Construction<R, T> {
    pub(super) fn new(registers: R, timer: T) -> Self {
        Self {
            registers: Some(registers),
            timer: Some(timer),
            allocation_error: None,
            corb: None,
            rirb: None,
            controller: None,
        }
    }
}
impl<R, T> Drop for Construction<R, T> {
    fn drop(&mut self) {
        core::mem::forget(self.registers.take());
        core::mem::forget(self.timer.take());
        // allocation_error contains reason metadata only and owns no provider,
        // pin, mapping or destructor; the physical graph stays retained below.
        core::mem::forget(self.corb.take());
        core::mem::forget(self.rirb.take());
        core::mem::forget(self.controller.take());
    }
}

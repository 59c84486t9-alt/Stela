// SPDX-License-Identifier: GPL-2.0-only
//! Native NHI cold ownership before any private-domain/ring allocation.
//! HRR/controller initialization is not inherited NHI engine/IRQ completion.
use super::controller::{self, Profile};
use crate::{
    block::BlockError,
    bus::{
        mmio::owned::{self, Mapping},
        pci::{
            CapabilityError, ConfigSpace, Function,
            owned::OwnedConfig,
            requester::{
                ClaimError,
                preparation::{self, BoundRequester, PreparingRequester},
            },
        },
    },
};
use alloc::{boxed::Box, sync::Arc};
use core::{any::Any, mem::ManuallyDrop};
mod registers;
mod reset;
pub use registers::MappedRegisters;
pub use reset::{check_flr, reset};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Config(crate::bus::pci::ConfigError),
    Claim(ClaimError),
    Capability(CapabilityError),
    Controller(controller::Error),
    Mapping(owned::Error),
    Reset(BlockError),
    Preparation(preparation::Error),
    Identity,
    ForeignOwner,
    Registers,
    ResetRequired,
    ResetQuirk,
}
pub struct Inputs {
    pub requester: PreparingRequester,
    pub mapping: Mapping,
}
struct Resources {
    requester: Option<PreparingRequester>,
    mapping: Option<Mapping>,
    registers: Option<Arc<MappedRegisters>>,
}
struct Kept(Option<Box<Resources>>);
impl Drop for Kept {
    fn drop(&mut self) {
        core::mem::forget(self.0.take());
    }
}
pub struct Cold {
    kept: Kept,
}
pub struct Failure {
    pub error: Error,
    _retained: ManuallyDrop<Box<dyn Any>>,
}
pub struct Ready {
    bound: ManuallyDrop<BoundRequester>,
    registers: ManuallyDrop<Arc<MappedRegisters>>,
}
impl Ready {
    /// # Safety
    /// Transfer both actual owners into the same native NHI lifetime before
    /// any BME/ring/CM publication, preserving original source/IRQ/root leases.
    pub unsafe fn into_parts(
        self,
    ) -> (
        Function<OwnedConfig>,
        preparation::Attachment,
        Arc<MappedRegisters>,
    ) {
        let bound = ManuallyDrop::into_inner(self.bound);
        (
            bound.requester.into_function(),
            bound.attachment,
            ManuallyDrop::into_inner(self.registers),
        )
    }
}
impl Cold {
    /// # Safety
    /// This is the original exclusive first NHI preparation. The mapping is
    /// its actual whole BAR0 grant from the same native source, with D0/shared
    /// power held, prior firmware/config writers and IRQ/work users excluded.
    /// Old DMA backing stays owned by the actual original path or consumed
    /// global-retirement+same-config seal. Peer/bypass users are independently
    /// handled. No Stela IRQ, CM or ring producer exists; software/firmware CM
    /// policy remains separate from this function-local reset. IMR policy is
    /// resolved before native attachment. No mask is an IRQ join.
    pub unsafe fn new(inputs: Inputs) -> Self {
        Self {
            kept: Kept(Some(Box::new(Resources {
                requester: Some(inputs.requester),
                mapping: Some(inputs.mapping),
                registers: None,
            }))),
        }
    }
    #[expect(
        clippy::result_large_err,
        reason = "cold refusal returns the complete original requester and BAR graph without allocating"
    )]
    pub fn quiesce_and_bind(
        mut self,
        timer: &(impl crate::bus::pci::power::Timer + ?Sized),
    ) -> Result<Ready, Failure> {
        let result = (|| {
            let kept = self.kept.0.as_deref_mut().expect("original NHI");
            let function = kept
                .requester
                .as_mut()
                .expect("original requester")
                .function_mut();
            check_flr(function, timer)?;
            let retained = function.config().retain_epoch().map_err(Error::Mapping)?;
            let mut bar_words = [0u32; 6];
            for (index, saved) in bar_words.iter_mut().enumerate() {
                *saved = function.config().read32(0x10 + 4 * index as u16)?;
            }
            if bar_words.contains(&u32::MAX) {
                return Err(Error::Identity);
            }
            kept.registers = Some(Arc::new(MappedRegisters::new(
                kept.mapping.take().expect("original BAR0"),
                retained,
                bar_words,
            )));
            kept.registers
                .as_ref()
                .expect("original registers")
                .check(function)?;
            reset(function, timer)?;
            let registers = kept.registers.as_ref().expect("original registers");
            registers.check(function)?;
            registers.reset_rings()
        })();
        if let Err(error) = result {
            return Err(Failure {
                error,
                _retained: ManuallyDrop::new(Box::new(self.kept)),
            });
        }
        let kept = self.kept.0.as_deref_mut().expect("original NHI");
        let registers = ManuallyDrop::new(kept.registers.take().expect("original registers"));
        let requester = kept.requester.take().expect("original requester");
        // SAFETY: actual supported FLR discarded original function jobs,
        // containment/actual reset ring indices were rechecked, no producer can
        // restart, and original BAR/source/control/backing owners remain kept.
        let receipt = unsafe { requester.acknowledge_quiescence() };
        match receipt.finalize() {
            Ok(bound) => Ok(Ready {
                bound: ManuallyDrop::new(bound),
                registers,
            }),
            Err(failure) => Err(Failure {
                error: Error::Preparation(failure.error),
                _retained: ManuallyDrop::new(Box::new((failure, registers))),
            }),
        }
    }
}

#[cfg(test)]
mod tests;

impl From<crate::bus::pci::ConfigError> for Error {
    fn from(error: crate::bus::pci::ConfigError) -> Self {
        Self::Config(error)
    }
}

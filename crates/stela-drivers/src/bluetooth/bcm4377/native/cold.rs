// SPDX-License-Identifier: MIT AND GPL-2.0-only
//! Broadcom FLR/D0 preparation under the original requester and root owner.
use super::{Configuration, Error, Registers, Time, config};
use crate::{
    bluetooth::bcm4377::{Chip, PciIdentity},
    bus::pci::{
        ConfigSpace, Function, native_aspm,
        requester::preparation::{self, Attachment, PreparingRequester},
    },
};
use alloc::boxed::Box;
use core::{any::Any, mem::ManuallyDrop};

/// Original requester/root ownership, or an explicit configuration/root model.
/// # Safety
/// `function_mut` exposes only the original exclusive configuration epoch.
/// Finalization consumes its current-epoch quiescence receipt, drains that same
/// original root, rechecks canonical PCI containment and binds once. Failure,
/// abandonment and unwind retain all uncertain configuration/root/backing.
/// Former firmware, IRQ/work, competing reset writers and bypass are excluded
/// independently; no Stela IRQ/work/submission exists in this phase.
pub(crate) unsafe trait Preparation: 'static {
    type Config: Configuration;
    fn function_mut(&mut self) -> &mut Function<Self::Config>;
    /// # Safety
    /// Vendor FLR and its quiet/config-ready observations completed for this
    /// original function. BME/MSI/INTx are gated, prior users are excluded and
    /// the caller keeps all original BARs/topology/backing through completion.
    unsafe fn finalize(self) -> Result<Finalized<Self::Config>, FinalizeFailure>;
}
pub(crate) struct Finalized<C: Configuration> {
    pub function: Function<C>,
    pub attachment: Attachment,
}
pub(crate) struct FinalizeFailure {
    pub error: preparation::Error,
    pub retained: ManuallyDrop<Box<dyn Any>>,
}
// SAFETY: PreparingRequester owns the original configuration seal and Root;
// its consumed receipt enforces root drain/revalidation before private binding.
unsafe impl Preparation for PreparingRequester {
    type Config = crate::bus::pci::owned::OwnedConfig;
    fn function_mut(&mut self) -> &mut Function<Self::Config> {
        self.function_mut()
    }
    unsafe fn finalize(self) -> Result<Finalized<Self::Config>, FinalizeFailure> {
        // SAFETY: the driver-owned cold sequence establishes this trait's
        // quiescence contract, with original BARs and backing retained.
        let receipt = unsafe { self.acknowledge_quiescence() };
        match receipt.finalize() {
            Ok(bound) => Ok(Finalized {
                function: bound.requester.into_function(),
                attachment: bound.attachment,
            }),
            Err(failure) => Err(FinalizeFailure {
                error: failure.error,
                retained: ManuallyDrop::new(Box::new(failure)),
            }),
        }
    }
}
pub(crate) struct Inputs<P: Preparation, R: Registers, T: Time> {
    pub requester: P,
    pub topology: native_aspm::Topology<P::Config>,
    pub registers: R,
    pub clock: T,
}
struct Resources<P: Preparation, R: Registers, T: Time> {
    inputs: Inputs<P, R, T>,
    layout: config::Layout,
    chip: Chip,
}
struct Owner<P: Preparation, R: Registers, T: Time>(Option<Box<Resources<P, R, T>>>);
impl<P: Preparation, R: Registers, T: Time> Drop for Owner<P, R, T> {
    fn drop(&mut self) {
        core::mem::forget(self.0.take());
    }
}
pub(crate) struct Cold<P: Preparation, R: Registers, T: Time> {
    owner: Owner<P, R, T>,
}
pub(crate) struct Bound<C: Configuration, R: Registers, T: Time> {
    pub function: Function<C>,
    pub attachment: Attachment,
    pub topology: native_aspm::Topology<C>,
    pub registers: R,
    pub clock: T,
}
pub(crate) struct Failure {
    pub error: Error,
    _retained: ManuallyDrop<Box<dyn Any>>,
}
impl<P: Preparation, R: Registers, T: Time> Cold<P, R, T> {
    /// # Safety
    /// Inputs retain the same exclusive original requester/reset/root/backing
    /// epoch. UC BARs match its assigned windows. Prior firmware, IRQ/work and
    /// bypass are excluded, and the qualified clock advances on this context.
    /// No new domain, DMA allocation, route or worker has been admitted.
    pub(crate) unsafe fn new(
        mut inputs: Inputs<P, R, T>,
    ) -> Result<Self, (Error, Inputs<P, R, T>)> {
        let checked = (|| {
            let function = inputs.requester.function_mut();
            let class = function.config().read32(8);
            let subsystem = function.config().read32(0x2c);
            let chip = Chip::select(PciIdentity {
                address: function.address,
                vendor: function.vendor,
                device: function.device,
                subsystem_vendor: subsystem as u16,
                subsystem_device: (subsystem >> 16) as u16,
                revision: class as u8,
                class: class >> 8,
            })
            .map_err(|_| Error::Requirement("supported original Broadcom cold identity"))?;
            let layout = config::Layout::discover(function)?;
            inputs.topology.validate(function).map_err(Error::Aspm)?;
            if chip == Chip::Bcm4377 {
                inputs
                    .topology
                    .validate_link(function)
                    .map_err(Error::Aspm)?;
            }
            let spans = inputs.registers.spans();
            for (slot, span, bytes) in [
                (0, spans[0], chip.otp_offset() as u64 + 0xe0),
                (2, spans[1], u64::from(chip.bar2(0x20049c)) + 4),
            ] {
                if layout.bar(slot)?.0 != span.start() || span.bytes() < bytes {
                    return Err(Error::Requirement(
                        "same complete original Broadcom cold BARs",
                    ));
                }
            }
            if spans[0].start() < spans[1].end() && spans[1].start() < spans[0].end() {
                return Err(Error::Requirement(
                    "nonoverlapping original Broadcom cold BARs",
                ));
            }
            Ok((chip, layout))
        })();
        match checked {
            Ok((chip, layout)) => Ok(Self {
                owner: Owner(Some(Box::new(Resources {
                    inputs,
                    layout,
                    chip,
                }))),
            }),
            Err(error) => Err((error, inputs)),
        }
    }
    pub(crate) fn quiesce_and_bind(mut self) -> Result<Bound<P::Config, R, T>, Box<Failure>> {
        let result = (|| {
            let r = self.owner.0.as_mut().unwrap();
            let function = r.inputs.requester.function_mut();
            if r.chip == Chip::Bcm4377 {
                r.inputs.topology.disable(function).map_err(Error::Aspm)?;
            }
            // The source FLR/D0/BAR restore runs once, while the original root
            // still owns inherited traffic; no new domain/allocation exists.
            r.layout.prepare(function.config(), &r.inputs.clock)?;
            if r.chip == Chip::Bcm4377 {
                r.inputs.topology.disable(function).map_err(Error::Aspm)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            return Err(Box::new(Failure {
                error,
                _retained: ManuallyDrop::new(Box::new(self.owner)),
            }));
        }
        let Resources {
            inputs:
                Inputs {
                    requester,
                    topology,
                    registers,
                    clock,
                },
            ..
        } = *self.owner.0.take().unwrap();
        let companions = ManuallyDrop::new((topology, registers, clock));
        // SAFETY: same original function acknowledged FLR/config-ready with
        // BME/MSI off; prior users excluded and every companion remains held.
        match unsafe { requester.finalize() } {
            Ok(Finalized {
                function,
                attachment,
            }) => {
                let (topology, registers, clock) = ManuallyDrop::into_inner(companions);
                Ok(Bound {
                    function,
                    attachment,
                    topology,
                    registers,
                    clock,
                })
            }
            Err(failure) => Err(Box::new(Failure {
                error: Error::Preparation(failure.error),
                _retained: ManuallyDrop::new(Box::new((failure.retained, companions))),
            })),
        }
    }
}

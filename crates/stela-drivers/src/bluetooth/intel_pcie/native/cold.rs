// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2024 Intel Corporation
//! BT function reset while the original requester/root and BAR remain owned.
use super::super::{DEVICE_IDS, Error, Result, Snapshot, registers::*, reset};
use super::{Error as NativeError, Registers};
use crate::{
    Clock,
    bus::pci::{
        ConfigSpace, regs,
        requester::{
            StoppedRequester,
            preparation::{self, Attachment, PreparingRequester},
        },
    },
};
use alloc::boxed::Box;
use core::mem::ManuallyDrop;

pub struct Inputs<R: Registers> {
    pub requester: PreparingRequester,
    pub registers: R,
    pub clock: Clock,
}
struct Resources<R: Registers> {
    inputs: Inputs<R>,
    snapshot: Snapshot,
}
struct Owner<R: Registers>(Option<Box<Resources<R>>>);
impl<R: Registers> Drop for Owner<R> {
    fn drop(&mut self) {
        core::mem::forget(self.0.take());
    }
}
/// No private domain, allocation or IRQ registration exists in this phase.
pub struct Cold<R: Registers> {
    owner: Owner<R>,
}
pub struct Bound<R: Registers> {
    pub requester: StoppedRequester,
    pub registers: R,
    pub attachment: Attachment,
}
/// Failed cold preparation never releases the original root/BAR graph.
pub struct Failure<R: Registers> {
    pub error: Error,
    _cold: Option<Owner<R>>,
    _root: Option<preparation::Failure>,
    _registers: Option<ManuallyDrop<R>>,
}

impl<R: Registers> Cold<R> {
    /// # Safety
    /// The original preparation and complete UC BAR0 belong to this same
    /// exclusively owned function/reset epoch, in PCI D0. Prior firmware,
    /// IRQ/work and competing configuration/reset/routing owners are excluded;
    /// the original root and all inherited DMA backing remain held. `clock`
    /// is the original provider's qualified timer in that processor/root
    /// context. This grants no new DMA or IRQ admission.
    pub unsafe fn new(mut inputs: Inputs<R>) -> core::result::Result<Self, (Error, Inputs<R>)> {
        let valid = (|| {
            inputs
                .clock
                .check_duration(120_000_000)
                .map_err(|_| NativeError::Requirement("qualified native BT cold-reset clock"))?;
            let function = inputs.requester.function_mut();
            if function.vendor != 0x8086
                || !DEVICE_IDS.contains(&function.device)
                || function.config().read32(0)
                    != u32::from(function.vendor) | u32::from(function.device) << 16
            {
                return Err(NativeError::Requirement(
                    "original Intel BT function identity",
                ));
            }
            let command = function.config().read16(regs::COMMAND);
            if command == u16::MAX || command & regs::COMMAND_MASTER != 0 {
                return Err(NativeError::Requirement(
                    "cold BT requester bus mastering gated",
                ));
            }
            let bar = function.config().read32(0x10);
            if bar == u32::MAX || bar & 1 != 0 || matches!(bar & 6, 2 | 6) {
                return Err(NativeError::Requirement("cold BT memory BAR0 format"));
            }
            let upper = if bar & 6 == 4 {
                u64::from(function.config().read32(0x14)) << 32
            } else {
                0
            };
            if inputs.registers.full_bar().start() != u64::from(bar & !15) | upper {
                return Err(NativeError::Requirement("same original BT BAR0 mapping"));
            }
            Ok(())
        })();
        match valid {
            Ok(()) => Ok(Self {
                owner: Owner(Some(Box::new(Resources {
                    inputs,
                    snapshot: Snapshot::default(),
                }))),
            }),
            Err(error) => Err((error.into(), inputs)),
        }
    }

    /// Acknowledge the vendor disconnect/reset before asking the original
    /// root to drain and bind. Failures keep the original resource graph.
    pub fn quiesce_and_bind(mut self) -> core::result::Result<Bound<R>, Box<Failure<R>>> {
        let result = (|| {
            let r = self.owner.0.as_mut().expect("original cold BT owner");
            let function = r.inputs.requester.function_mut();
            let command = function.config().read16(regs::COMMAND);
            if command == u16::MAX || command & regs::COMMAND_MASTER != 0 {
                return Err(NativeError::Requirement("cold BT bus mastering still gated").into());
            }
            function.config().write16(
                regs::COMMAND,
                command | regs::COMMAND_MEMORY | regs::COMMAND_INTX_DISABLE,
            );
            let observed = function.config().read16(regs::COMMAND);
            if observed & 0x406 != 0x402 {
                return Err(NativeError::Readback {
                    offset: regs::COMMAND.into(),
                    observed: observed.into(),
                }
                .into());
            }
            for offset in [FH_MASK, HW_MASK] {
                r.inputs.registers.write32(offset, u32::MAX)?;
                let observed = r.inputs.registers.read32(offset)?;
                if observed != u32::MAX {
                    return Err(NativeError::Readback { offset, observed }.into());
                }
            }
            let mut io = Control {
                registers: &mut r.inputs.registers,
                clock: r.inputs.clock,
            };
            reset::reset(&mut io, &mut r.snapshot)?;
            if r.snapshot.function == u32::MAX
                || r.snapshot.function & (ENABLE | MAC_INIT | FUNC_INIT) != 0
            {
                return Err(NativeError::Requirement("cold BT reset function disabled").into());
            }
            for offset in [FH_CAUSE, HW_CAUSE] {
                let observed = r.inputs.registers.read32(offset)?;
                if observed != 0 {
                    return Err(NativeError::Readback { offset, observed }.into());
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            return Err(Box::new(Failure {
                error,
                _cold: Some(self.owner),
                _root: None,
                _registers: None,
            }));
        }
        let Resources {
            inputs:
                Inputs {
                    requester,
                    registers,
                    ..
                },
            ..
        } = *self.owner.0.take().expect("original cold BT owner");
        let registers = ManuallyDrop::new(registers);
        // SAFETY: the same vendor function acknowledged disconnect/reset,
        // BME stays clear, and the producer excludes old IRQ/work/bypass and
        // competing writers. Registers/backing stay kept through root completion.
        let receipt = unsafe { requester.acknowledge_quiescence() };
        match receipt.finalize() {
            Ok(preparation::BoundRequester {
                requester,
                attachment,
            }) => Ok(Bound {
                requester,
                registers: ManuallyDrop::into_inner(registers),
                attachment,
            }),
            Err(failure) => Err(Box::new(Failure {
                error: Error::Preparation(failure.error),
                _cold: None,
                _root: Some(failure),
                _registers: Some(registers),
            })),
        }
    }
}
struct Control<'a, R: Registers> {
    registers: &'a mut R,
    clock: Clock,
}
// SAFETY: borrowed from this original exclusively owned cold BAR/config/root
// attempt, with the producer's checked clock and backing retained throughout.
unsafe impl<R: Registers> reset::Io for Control<'_, R> {
    fn read(&mut self, offset: usize) -> Result<u32> {
        self.registers.read32(offset).map_err(Into::into)
    }
    fn write(&mut self, offset: usize, value: u32) -> Result<()> {
        self.registers.write32(offset, value).map_err(Into::into)
    }
    fn delay(&mut self, microseconds: u64) -> Result<()> {
        self.clock
            .try_delay(microseconds)
            .map_err(|_| NativeError::Requirement("qualified BT cold-reset delay").into())
    }
}

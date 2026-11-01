// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2024 Intel Corporation
//! One native BT transport retains its allocator and unique requester control.
use super::super::{Error, Result, Transport};
use super::{BarAccess, Error as NativeError, NativePlatform, RetirableRegisters};
use crate::{
    block::BlockError,
    bus::{
        dma::DomainAllocator,
        pci::{
            owned::{ConfigRetention, OwnedConfig},
            requester::preparation::Attachment,
        },
    },
};
use alloc::boxed::Box;
use core::ops::Deref;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaOperation {
    Drain,
    Detach,
}

pub struct Inputs<B: BarAccess + 'static, R: RetirableRegisters> {
    pub platform: NativePlatform<OwnedConfig, B, R>,
    pub allocator: DomainAllocator<'static>,
    pub attachment: Box<dyn Attachment>,
    pub retention: ConfigRetention,
}
struct Allocations {
    allocator: DomainAllocator<'static>,
    attachment: Box<dyn Attachment>,
    retention: Option<ConfigRetention>,
}
struct AllocationOwner(Option<Box<Allocations>>);
impl Drop for AllocationOwner {
    fn drop(&mut self) {
        core::mem::forget(self.0.take());
    }
}
impl AllocationOwner {
    fn get(&mut self) -> &mut Allocations {
        self.0.as_deref_mut().expect("original BT allocation owner")
    }
    fn release(&mut self) {
        drop(self.0.take());
    }
}
struct Resources<B: BarAccess + 'static, R: RetirableRegisters> {
    transport: Transport<NativePlatform<OwnedConfig, B, R>>,
    allocations: AllocationOwner,
}

/// A failed constructor retains partial allocations and the original binding.
/// NativePlatform's failed Drop independently keeps its configuration/BAR/IRQ
/// graph; no failed constructor can certify release or authorize shared reset.
pub struct Failure {
    pub error: Error,
    _allocations: AllocationOwner,
}

/// The owning driver keeps this entire original graph until close acknowledges
/// device, payload, translation and configuration/BAR retirement. Drop on any
/// incomplete/failed path retains it; an engine stop is insufficient release.
pub struct OwnedTransport<B: BarAccess + 'static, R: RetirableRegisters> {
    resources: Option<Box<Resources<B, R>>>,
    completed: bool,
    failure: Option<Error>,
}
impl<B: BarAccess + 'static, R: RetirableRegisters> Drop for OwnedTransport<B, R> {
    fn drop(&mut self) {
        if !self.completed {
            core::mem::forget(self.resources.take());
        }
    }
}
impl<B: BarAccess + 'static, R: RetirableRegisters> Deref for OwnedTransport<B, R> {
    type Target = Transport<NativePlatform<OwnedConfig, B, R>>;
    fn deref(&self) -> &Self::Target {
        &self.resources.as_ref().unwrap().transport
    }
}
impl<B: BarAccess + 'static, R: RetirableRegisters> OwnedTransport<B, R> {
    fn transport_mut(&mut self) -> &mut Transport<NativePlatform<OwnedConfig, B, R>> {
        &mut self.resources.as_deref_mut().unwrap().transport
    }
    pub fn start(&mut self) -> Result<()> {
        self.transport_mut().start()
    }
    pub fn poll(&mut self) -> Result<alloc::vec::Vec<super::super::Packet>> {
        self.transport_mut().poll()
    }
    pub fn send(
        &mut self,
        kind: super::super::Kind,
        bytes: &[u8],
    ) -> Result<super::super::TxReceipt> {
        self.transport_mut().send(kind, bytes)
    }
    pub fn enter_d0(&mut self) -> Result<super::super::Snapshot> {
        self.transport_mut().enter_d0()
    }
    pub fn initialize_firmware(
        &mut self,
        provider: &dyn crate::firmware::Provider,
        platform: crate::bluetooth::intel::PlatformInputs,
    ) -> core::result::Result<super::super::firmware::Report, super::super::firmware::Error> {
        super::super::firmware::initialize(self.transport_mut(), provider, platform)
    }
    /// # Safety
    /// All inputs belong to the same exclusively owned function/root/reset
    /// epoch. The cold driver receipt and original-root drain completed before
    /// binding; `retention` seals that exact configuration. The allocator uses
    /// this attachment's coherent domain and kept pages. Prior IRQ/work/bypass
    /// exclusions and the original processor/root context remain held.
    pub unsafe fn new(inputs: Inputs<B, R>) -> core::result::Result<Self, Failure> {
        let Inputs {
            platform,
            allocator,
            attachment,
            retention,
        } = inputs;
        let mut allocations = AllocationOwner(Some(Box::new(Allocations {
            allocator,
            attachment,
            retention: Some(retention),
        })));
        let transport = match Transport::new(platform, &mut allocations.get().allocator) {
            Ok(transport) => transport,
            Err(error) => {
                return Err(Failure {
                    error,
                    _allocations: allocations,
                });
            }
        };
        Ok(Self {
            resources: Some(Box::new(Resources {
                transport,
                allocations,
            })),
            completed: false,
            failure: None,
        })
    }

    /// Stop admission/engines and IRQs, drain the original bound path, release
    /// buffers and translations, detach the requester, then retire PCI/BARs.
    /// Every failure is sticky and retains this graph; no failed close permits
    /// shared reset or reprobe. Repeated acknowledged close has no new effects.
    pub fn close(&mut self) -> Result<()> {
        if self.completed {
            return Ok(());
        }
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        let result: Result<()> = (|| {
            let Resources {
                transport,
                allocations,
            } = self.resources.as_deref_mut().unwrap();
            transport.close()?;
            let allocation = allocations.get();
            transport
                .platform
                .stop_requester(allocation.retention.as_ref().unwrap())?;
            let domain = allocation.attachment.domain();
            // SAFETY: this same transport acknowledged engine/BME/IRQ/work
            // retirement, with all target buffers and original owners still held.
            unsafe { domain.drain_posted_writes() }.map_err(|source| NativeError::Dma {
                operation: DmaOperation::Drain,
                source,
            })?;
            // The core exposes no buffer references; all active calls/packet
            // users stopped. Closed/failed states cannot access these buffers.
            drop(transport.memory.take());
            // SAFETY: full device/payload/IRQ/work/CPU drain; dropping the
            // private core buffers left only the allocator's own mapping leases.
            unsafe { allocation.allocator.retire() }
                .map_err(|error| Error::Dma(BlockError::Dma(error)))?;
            // SAFETY: every mapping is gone and the original function cannot
            // resume. The same config/BAR/root owners remain through detach.
            unsafe { allocation.attachment.detach() }.map_err(|source| NativeError::Dma {
                operation: DmaOperation::Detach,
                source,
            })?;
            // The seal was checked before DMA retirement; release its view so
            // configuration mapping retirement can complete after detach.
            allocation.retention.take();
            // SAFETY: all device/DMA/IRQ/work/CPU users and views are retired;
            // no reset/reassignment can intervene in this serialized owner.
            unsafe { transport.platform.retire_resources() }?;
            allocations.release();
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.completed = true;
                Ok(())
            }
            Err(error) => {
                self.failure = Some(error.clone());
                Err(error)
            }
        }
    }
}

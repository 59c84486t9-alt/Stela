// SPDX-License-Identifier: GPL-2.0-only
//! Original native UC mapping and platform/device resource retention.
use super::{Description, IoError, Registers};
use crate::bus::mmio::owned::{CacheAttribute, Mapping, Protection};
use core::mem::ManuallyDrop;

pub struct NativeFailure<P> {
    pub error: IoError,
    _inputs: ManuallyDrop<(Mapping, P)>,
}
impl<P> core::fmt::Debug for NativeFailure<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativeFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
pub struct NativeRetireFailure<P> {
    pub error: crate::bus::mmio::owned::Error,
    _owner: NativeRegisters<P>,
}
impl<P> core::fmt::Debug for NativeRetireFailure<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativeRetireFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

pub struct NativeRegisters<P> {
    mapping: ManuallyDrop<Mapping>,
    platform: ManuallyDrop<P>,
    description: Description,
    bytes: usize,
}
impl<P: 'static> NativeRegisters<P> {
    /// # Safety
    /// `platform` keeps the original unique physical LPSS SSP PCI/ACPI device,
    /// clock/power/reset epoch, board pins and native CS/firmware arbitration.
    /// `mapping` is its complete exclusive register resource. Reset/remap
    /// and the enabled SSP input clock have been established by that real owner;
    /// Description is observed from those same resources, not guessed from IDs.
    /// Prior DMA, IRQ and deferred users are stopped/drained and cannot restart.
    /// No other owner can reset, revoke or relocate this epoch; deliberate leak
    /// keeps all grants. A short-lived external guard is insufficient.
    pub unsafe fn claim(
        mapping: Mapping,
        platform: P,
        description: Description,
    ) -> Result<Self, NativeFailure<P>> {
        let inputs = ManuallyDrop::new((mapping, platform));
        let checked = (|| {
            let mapping = &inputs.0;
            let bytes = mapping.bytes().map_err(IoError::Mmio)?;
            if bytes < description.profile.register_bytes() {
                return Err(IoError::InvalidRegister {
                    offset: description.profile.register_bytes() - 4,
                });
            }
            let attribute = mapping.attribute().map_err(IoError::Mmio)?;
            let protection = mapping.protection().map_err(IoError::Mmio)?;
            if attribute != CacheAttribute::Uncached || protection != Protection::ReadWrite {
                return Err(IoError::MappingAttributes {
                    attribute,
                    protection,
                });
            }
            if mapping.address(0, 4).map_err(IoError::Mmio)?.as_ptr() as usize & 3 != 0 {
                return Err(IoError::InvalidRegister { offset: 0 });
            }
            Ok(bytes)
        })();
        let bytes = match checked {
            Ok(bytes) => bytes,
            Err(error) => {
                return Err(NativeFailure {
                    error,
                    _inputs: inputs,
                });
            }
        };
        let (mapping, platform) = ManuallyDrop::into_inner(inputs);
        Ok(Self {
            mapping: ManuallyDrop::new(mapping),
            platform: ManuallyDrop::new(platform),
            description,
            bytes,
        })
    }
    /// # Safety
    /// The original Controller successfully released and all register users,
    /// callbacks and posted writes are drained. No extracted pointer may be
    /// accessed again. Failure retains the exact mapping/platform and original
    /// unmap cause; it grants neither retry nor native unmap completion.
    pub unsafe fn retire(mut self) -> Result<P, NativeRetireFailure<P>> {
        // SAFETY: caller supplies the original successful controller/user drain.
        if let Err(error) = unsafe { self.mapping.retire() } {
            return Err(NativeRetireFailure {
                error,
                _owner: self,
            });
        }
        drop(ManuallyDrop::into_inner(self.mapping));
        Ok(ManuallyDrop::into_inner(self.platform))
    }
}
// SAFETY: claim binds immutable device/clock/pin ownership to its
// original aligned UC mapping. Every DWORD checks bounds and ordered volatility;
// failed accesses may follow effects. The controller serializes all users.
unsafe impl<P: 'static> Registers for NativeRegisters<P> {
    fn description(&self) -> Description {
        self.description
    }
    fn bytes(&self) -> usize {
        self.bytes
    }
    fn read32(&mut self, offset: usize) -> Result<u32, IoError> {
        self.mapping.read32(offset).map_err(IoError::Mmio)
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), IoError> {
        self.mapping.write32(offset, value).map_err(IoError::Mmio)
    }
}

#[cfg(test)]
mod tests;

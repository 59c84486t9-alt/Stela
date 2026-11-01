// SPDX-License-Identifier: GPL-2.0-only
//! Original-root register access before Tigon3's vendor stop receipt.
use super::*;
use crate::bus::pci::{
    owned::OwnedConfig,
    requester::preparation::{self, Attachment, BoundRequester, PreparingRequester},
};
use alloc::boxed::Box;
use core::mem::ManuallyDrop;

struct Resources {
    requester: PreparingRequester,
    mac: Window,
    ape: Window,
    owner: ManuallyDrop<Arc<dyn core::any::Any>>,
}

/// Cold registers keep the original requester/root and BAR owners together.
/// No private DMA domain or engine-stop permission is implied.
pub struct Cold {
    resources: Option<Resources>,
    function: u8,
}
impl Drop for Cold {
    fn drop(&mut self) {
        core::mem::forget(self.resources.take());
    }
}

pub struct Bound {
    pub registers: Mmio<OwnedConfig>,
    pub attachment: Box<dyn Attachment>,
}

/// Failed finalization keeps the original root and BAR graph indefinitely.
pub struct BindFailure {
    pub error: preparation::Error,
    _root: preparation::Failure,
    _windows: ManuallyDrop<(Window, Window, Arc<dyn core::any::Any>)>,
}

impl Cold {
    /// # Safety
    /// The original requester and both complete UC windows name the same
    /// exclusively owned, powered function. `owner` keeps both windows and
    /// all inherited DMA backing. Prior firmware/IRQ/work and competing PCI
    /// owners are excluded throughout preparation. No new DMA may be started.
    pub unsafe fn from_owned_windows(
        mut requester: PreparingRequester,
        mac: NonNull<u8>,
        mac_bytes: usize,
        ape: NonNull<u8>,
        ape_bytes: usize,
        owner: Arc<dyn core::any::Any>,
    ) -> Result<Self, (Error, PreparingRequester, Arc<dyn core::any::Any>)> {
        let windows = (|| {
            Ok((
                Window::new(mac, mac_bytes, 0x8000)?,
                Window::new(ape, ape_bytes, 0x8440)?,
            ))
        })();
        match windows {
            Ok((mac, ape)) => {
                let function = requester.function_mut().address.function;
                Ok(Self {
                    resources: Some(Resources {
                        requester,
                        mac,
                        ape,
                        owner: ManuallyDrop::new(owner),
                    }),
                    function,
                })
            }
            Err(error) => Err((error, requester, owner)),
        }
    }

    fn r(&mut self) -> &mut Resources {
        self.resources.as_mut().expect("original cold Tigon3 owner")
    }

    /// Consume the vendor stop through the original remapper's drain and
    /// attach a private domain before any new packet allocation/publication.
    /// # Safety
    /// The owning driver has acknowledged engine/BME stop for this exact
    /// register owner; `Hardware::quiesce_cold` supplies native preparation.
    /// Prior IRQ/work exclusion still holds. No reset,
    /// routing/configuration writer, bypass or peer DMA can change the epoch.
    pub unsafe fn bind(mut self) -> Result<Bound, BindFailure> {
        let Resources {
            requester,
            mac,
            ape,
            owner,
        } = self.resources.take().expect("original cold Tigon3 owner");
        // SAFETY: the caller supplies this owner's acknowledged vendor stop
        // and IRQ/work exclusion. Finalization performs the original-root drain.
        let receipt = unsafe { requester.acknowledge_quiescence() };
        match receipt.finalize() {
            Ok(BoundRequester {
                requester,
                attachment,
            }) => Ok(Bound {
                registers: Mmio {
                    function: requester.into_function(),
                    mac,
                    ape,
                    _owner: ManuallyDrop::into_inner(owner),
                },
                attachment,
            }),
            Err(failure) => Err(BindFailure {
                error: failure.error,
                _root: failure,
                _windows: ManuallyDrop::new((mac, ape, ManuallyDrop::into_inner(owner))),
            }),
        }
    }
}

// SAFETY: construction binds the original function/root and checked UC
// windows. Configuration writes preserve native widths and never replace the
// owner; Drop retains the entire graph without asserting quiescence.
unsafe impl Registers for Cold {
    fn function_number(&self) -> u8 {
        self.function
    }
    fn config_read32(&mut self, at: u16) -> Result<u32, Error> {
        if at & 3 != 0 || at > 4092 {
            return Err(Error::Bounds);
        }
        let value = self.r().requester.function_mut().config().read32(at);
        if value == u32::MAX {
            Err(Error::Removed)
        } else {
            Ok(value)
        }
    }
    fn config_write32(&mut self, at: u16, value: u32) -> Result<(), Error> {
        if at & 3 != 0 || at > 4092 {
            return Err(Error::Bounds);
        }
        self.r()
            .requester
            .function_mut()
            .config()
            .write32(at, value);
        self.config_read32(0)?;
        Ok(())
    }
    fn config_write16(&mut self, at: u16, value: u16) -> Result<(), Error> {
        if at & 1 != 0 || at > 4094 {
            return Err(Error::Bounds);
        }
        self.r()
            .requester
            .function_mut()
            .config()
            .write16(at, value);
        self.config_read32(0)?;
        Ok(())
    }
    fn read32(&mut self, at: u32) -> Result<u32, Error> {
        self.r().mac.read(at)
    }
    fn write32(&mut self, at: u32, value: u32) -> Result<(), Error> {
        self.r().mac.write(at, value)
    }
    fn ape_read32(&mut self, at: u32) -> Result<u32, Error> {
        self.r().ape.read(at)
    }
    fn ape_write32(&mut self, at: u32, value: u32) -> Result<(), Error> {
        self.r().ape.write(at, value)
    }
}

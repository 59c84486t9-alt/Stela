// SPDX-License-Identifier: GPL-2.0-only
//! Native IRQ-registry source composition for a single parent vector.
//! Each child contributes its real device source and IRQ handler. No completion
//! is inferred from a VMD mask, a BDF, or a caller-set software stopped flag.
use super::*;
use crate::bus::irq::{Handler, IrqError, MsiMessage, Route, RouteRequest, Source};
use crate::bus::pci::regs;
use alloc::{boxed::Box, rc::Rc, sync::Arc};
use core::cell::RefCell;

pub struct ChildSource {
    pub source: Box<dyn Source>,
    pub handler: Arc<dyn Handler>,
}
/// Original parent register/resource owner becomes available only after
/// child quiescence, native CPU/callback drain and successful host retirement.
/// Final mapping retirement remains the native MMIO permission's responsibility.
pub struct RetiredHandle<R>(Rc<RefCell<Option<R>>>);

/// A started parent source, the fanout its children share and the handle
/// that returns its host.
pub type Started<S, R> = (S, Arc<remap::Fanout>, RetiredHandle<R>);
/// A refused start: the cause, and the host and children it was given.
pub type Refused<R> = (Error, Host<R>, Vec<ChildSource>);
impl<R> RetiredHandle<R> {
    /// # Safety
    /// The native IRQ registration built from this source has completed
    /// `retire()` successfully, including its final CPU pending/inflight check.
    /// A source synchronize callback alone is not terminal registry retirement.
    pub unsafe fn take_after_retirement(&mut self) -> Option<R> {
        self.0.borrow_mut().take()
    }
}

pub struct ParentSource<R: Registers> {
    host: Option<Host<R>>,
    children: Option<Vec<Box<dyn Source>>>,
    returned: Rc<RefCell<Option<R>>>,
    programmed: Option<u16>,
    retired: bool,
}
impl<R: Registers> ParentSource<R> {
    /// Build a real native Source plus its exact immutable fanout. The one
    /// parent vector is profile.first_vector; client vector zero remains masked.
    ///
    /// # Safety
    /// Every child source owns a real inactive device route within this exact
    /// VMD hierarchy and implements real device/DMA/work/posted-write stop and
    /// drain. Its handler acknowledges that source's causes. No child
    /// has another CPU registration or independent callback path. This owner is
    /// the sole host/table/config writer; child sources may access only their
    /// own function/register grants. Child DMA alias
    /// and resource permissions must exist independently; this wrapper grants
    /// none. The owning native CPU/process context remains fixed until retire.
    #[expect(
        clippy::result_large_err,
        reason = "failure returns the original host and every child source without allocating a replacement owner"
    )]
    pub unsafe fn new(
        host: Host<R>,
        children: Vec<ChildSource>,
    ) -> Result<Started<Self, R>, Refused<R>> {
        if children.is_empty()
            || children
                .iter()
                .any(|child| child.source.route() != RouteRequest::Msi)
        {
            return Err((Error::Address, host, children));
        }
        let handlers = children.iter().map(|child| child.handler.clone()).collect();
        let fanout = match remap::Fanout::new(handlers) {
            Ok(fanout) => Arc::new(fanout),
            Err(error) => return Err((error, host, children)),
        };
        let returned = Rc::new(RefCell::new(None));
        let handle = RetiredHandle(returned.clone());
        let sources = children.into_iter().map(|child| child.source).collect();
        Ok((
            Self {
                host: Some(host),
                children: Some(sources),
                returned,
                programmed: None,
                retired: false,
            },
            fanout,
            handle,
        ))
    }
    fn host(&mut self) -> Result<&mut Host<R>, IrqError> {
        self.host.as_mut().ok_or(IrqError::Unregistered)
    }
}
// SAFETY: unsafe construction transfers every child source owner. All
// effects delegate to those real sources and the parent MMIO engine;
// only the native registry can authorize CPU callback/message completion.
unsafe impl<R: Registers> Source for ParentSource<R> {
    fn mask(&mut self) -> Result<(), IrqError> {
        if self.retired {
            return Ok(());
        }
        for child in self.children.as_mut().ok_or(IrqError::Unregistered)? {
            child.mask()?;
        }
        if self.programmed.is_some() {
            self.host()?
                .mask_parent_vectors()
                .map_err(|_| IrqError::Mask)?;
        }
        Ok(())
    }
    fn quiesce(&mut self) -> Result<(), IrqError> {
        if self.retired {
            return Ok(());
        }
        for child in self.children.as_mut().ok_or(IrqError::Unregistered)? {
            child.mask()?;
            child.quiesce()?;
        }
        Ok(())
    }
    fn route(&self) -> RouteRequest {
        RouteRequest::Msi
    }
    unsafe fn program(&mut self, route: Route) -> Result<(), IrqError> {
        let Route::Msi(message) = route else {
            return Err(IrqError::Unsupported);
        };
        let host = self.host()?;
        let index = host.profile().first_vector;
        // SAFETY: registry owns this parent route and publishes the
        // immutable fanout before unmask; initial child routes are inactive.
        let end =
            unsafe { host.program_parent_vectors(&[message]) }.map_err(|_| IrqError::Route)?;
        self.programmed = Some(end);
        let message = MsiMessage {
            address: 0xfee0_0000 | u64::from(index) << 12,
            data: 0,
        };
        for child in self.children.as_mut().ok_or(IrqError::Unregistered)? {
            // SAFETY: this is the owned VMD route to the same parent
            // registry/callback, not an invented APIC target for the child.
            unsafe { child.program(Route::Msi(message)) }?;
        }
        Ok(())
    }
    unsafe fn unmask(&mut self) -> Result<(), IrqError> {
        let end = self.programmed.ok_or(IrqError::Route)?;
        // Host preparation never grants upstream bus mastering. Until
        // platform DMA/requester-domain attachment establishes it, do not
        // report an armed native interrupt path that cannot forward traffic.
        // This bit is only a prerequisite; new's unsafe domain
        // ownership contract remains independently required.
        let command = self
            .host()?
            .io()
            .parent_read(regs::COMMAND, 2)
            .map_err(|_| IrqError::FailedRead)?;
        if command == u32::from(u16::MAX) {
            return Err(IrqError::FailedRead);
        }
        if command & u32::from(regs::COMMAND_MASTER) == 0 {
            return Err(IrqError::Unsupported);
        }
        // SAFETY: exact programmed parent range with live registration.
        unsafe { self.host()?.unmask_parent_vectors(end) }.map_err(|_| IrqError::Route)?;
        for child in self.children.as_mut().ok_or(IrqError::Unregistered)? {
            // SAFETY: registry keeps the source/fanout/CPU route.
            unsafe { child.unmask() }?;
        }
        Ok(())
    }
    unsafe fn synchronize(&mut self) -> Result<(), IrqError> {
        if self.retired {
            return Ok(());
        }
        for child in self.children.as_mut().ok_or(IrqError::Unregistered)? {
            // SAFETY: parent CPU IRR/ISR/EOI and fanout callbacks drained;
            // every child source quiesced, including former IRQ work.
            unsafe { child.synchronize() }?;
        }
        let host = self.host.take().ok_or(IrqError::Unregistered)?;
        // SAFETY: child providers and native registry acknowledged all
        // child DMA/work, parent messages and CPU/fanout callbacks above.
        let registers = unsafe { host.retire() }.map_err(|_| IrqError::Drain)?;
        *self.returned.borrow_mut() = Some(registers);
        self.retired = true;
        self.programmed = None;
        Ok(())
    }
}
impl<R: Registers> Drop for ParentSource<R> {
    fn drop(&mut self) {
        if !self.retired {
            if let Some(host) = self.host.take() {
                core::mem::forget(host);
            }
            if let Some(children) = self.children.take() {
                core::mem::forget(children);
            }
        }
    }
}

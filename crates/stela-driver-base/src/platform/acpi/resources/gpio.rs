// SPDX-License-Identifier: GPL-2.0-only
//! Native GPIO OpRegion supplier, following gpiolib-acpi's line ownership.
//!
//! The first context member is ACPICA's connection-info ABI. ACPICA
//! serializes Connection updates; an OSL semaphore additionally serializes all
//! native line operations. CPU-affine namespace handles never enter callbacks.
use super::supplier::{DependencyPin, SupplierState};
use super::*;
use crate::platform::acpi::{self, Argument, Status};
use alloc::{boxed::Box, format, sync::Arc};
use core::{
    cell::UnsafeCell,
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};

pub(crate) mod sealed {
    pub trait Sealed {}
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Input,
    Output(bool),
    Preserve,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinePolicy {
    pub direction: Direction,
    pub debounce_us: u32,
}

/// First native-operation and first synchronization failures are independent
/// observations; they need not come from the same access. Line snapshots
/// and partial effects remain owned by the backend through failed cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failures {
    pub operation: Option<acpi::Error>,
    pub synchronization: Option<acpi::Error>,
}

/// Implemented only by native controller adapters keeping reservations
/// and mappings. An AML pin number cannot instantiate a backend.
pub trait NativeController: sealed::Sealed + Send + 'static {
    fn device_path(&self) -> &str;
    /// Match the original inspection/reservations, not just a path that
    /// can be reused after a namespace/session replacement.
    fn matches_device(&self, device: &DeviceResources<'_>) -> Result<(), Error>;
    /// Record a recoverable snapshot before any hardware effect. Partial failures
    /// keep the pin, snapshot and mapping until acknowledged release/shutdown.
    fn request(&mut self, pin: u16, policy: LinePolicy) -> Result<(), acpi::Error>;
    fn read(&mut self, pin: u16) -> Result<bool, acpi::Error>;
    fn write(&mut self, pin: u16, value: bool) -> Result<(), acpi::Error>;
    /// Release only after masked/synchronized native children and acknowledged
    /// restoration. Failure keeps the original snapshot and reservation.
    fn release(&mut self, pin: u16) -> Result<(), acpi::Error>;
    /// Drain native sources and retire original mappings. No new native
    /// access may begin after success. Failure keeps every uncertain owner.
    fn shutdown(&mut self) -> Result<(), acpi::Error>;
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ConnectionInfo {
    connection: *mut u8,
    length: u16,
    access_length: u8,
}
struct Claim {
    pin: u16,
    ready: bool,
}
struct State {
    controller: Box<dyn NativeController>,
    claims: Vec<Claim>,
    stopped: bool,
    dependencies: Vec<DependencyPin>,
}
#[repr(C)]
struct Context {
    // ACPICA evregion.c updates this prefix while holding its context mutex.
    info: UnsafeCell<ConnectionInfo>,
    enabled: AtomicBool,
    first_operation: AtomicU32,
    first_synchronization: AtomicU32,
    supplier: Arc<SupplierState>,
    semaphore: *mut c_void,
    state: UnsafeCell<State>,
}
const _: () = {
    assert!(core::mem::size_of::<ConnectionInfo>() == 16);
    assert!(core::mem::offset_of!(ConnectionInfo, length) == 8);
    assert!(core::mem::offset_of!(ConnectionInfo, access_length) == 10);
    assert!(core::mem::offset_of!(Context, info) == 0);
};
unsafe extern "C" {
    fn acpi_os_create_semaphore(max: u32, initial: u32, out: *mut *mut c_void) -> Status;
    fn acpi_os_delete_semaphore(semaphore: *mut c_void) -> Status;
    fn acpi_os_wait_semaphore(semaphore: *mut c_void, units: u32, milliseconds: u16) -> Status;
    fn acpi_os_signal_semaphore(semaphore: *mut c_void, units: u32) -> Status;
}
fn checked(status: Status) -> Result<(), acpi::Error> {
    if status == 0 {
        Ok(())
    } else {
        Err(acpi::Error(status))
    }
}
impl Context {
    fn acquire(&self) -> Result<(), acpi::Error> {
        // SAFETY: the original context keeps this real provider semaphore.
        let acquired = checked(unsafe { acpi_os_wait_semaphore(self.semaphore, 1, 1000) });
        if let Err(error) = acquired {
            let _ = self.first_synchronization.compare_exchange(
                0,
                error.0,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
        acquired
    }
    fn failures(&self) -> Failures {
        let failure = |status| {
            if status == 0 {
                None
            } else {
                Some(acpi::Error(status))
            }
        };
        Failures {
            operation: failure(self.first_operation.load(Ordering::Acquire)),
            synchronization: failure(self.first_synchronization.load(Ordering::Acquire)),
        }
    }
    fn outcome(
        &self,
        operation: Result<(), acpi::Error>,
        release: Result<(), acpi::Error>,
    ) -> Result<(), acpi::Error> {
        if let Err(error) = operation {
            let _ = self.first_operation.compare_exchange(
                0,
                error.0,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
        if let Err(error) = release {
            let _ = self.first_synchronization.compare_exchange(
                0,
                error.0,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            self.supplier.close_admission();
            self.enabled.store(false, Ordering::Release);
        }
        // Preserve the native operation's first error even when releasing its
        // real semaphore also fails. The synchronization status remains queryable.
        operation.and(release)
    }
    fn finish_backend(&self, release_dependencies: bool) -> Result<(), acpi::Error> {
        // Admission closes before this wait. Previously admitted operations
        // recheck enabled after acquiring the same native semaphore.
        debug_assert!(!self.enabled.load(Ordering::Acquire));
        // SAFETY: callback storage keeps the original OSL semaphore/provider.
        self.acquire()?;
        // SAFETY: this call holds the native state semaphore and admission closed.
        let state = unsafe { &mut *self.state.get() };
        let result = (|| {
            while let Some(claim) = state.claims.last() {
                state.controller.release(claim.pin)?;
                state.claims.pop();
            }
            if !state.stopped {
                state.controller.shutdown()?;
                state.stopped = true;
            }
            Ok(())
        })();
        // SAFETY: the native semaphore unit was acquired above.
        let released = checked(unsafe { acpi_os_signal_semaphore(self.semaphore, 1) });
        self.outcome(result, released)?;
        // No new native-state access can begin while disabled. Release
        // suppliers only after restoration, shutdown and synchronization ACKs.
        if release_dependencies {
            state.dependencies.clear();
        }
        Ok(())
    }
    fn with_state(
        &self,
        operation: impl FnOnce(&mut State) -> Result<(), acpi::Error>,
    ) -> Result<(), acpi::Error> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(acpi::SUPPORT);
        }
        // SAFETY: the core keeps this original OSL semaphore through callbacks.
        self.acquire()?;
        let result = if self.enabled.load(Ordering::Acquire) {
            // SAFETY: all native state accesses hold this semaphore.
            operation(unsafe { &mut *self.state.get() })
        } else {
            Err(acpi::SUPPORT)
        };
        // SAFETY: this call owns exactly the acquired semaphore unit.
        let released = checked(unsafe { acpi_os_signal_semaphore(self.semaphore, 1) });
        self.outcome(result, released)
    }
}
fn policy(gpio: &Gpio) -> LinePolicy {
    let direction = match gpio.kind {
        GpioKind::Interrupt { .. } | GpioKind::Io(IoRestriction::Input) => Direction::Input,
        GpioKind::Io(IoRestriction::Output) if gpio.pull == 1 => Direction::Output(true),
        GpioKind::Io(IoRestriction::Output) if gpio.pull == 2 => Direction::Output(false),
        _ => Direction::Preserve,
    };
    LinePolicy {
        direction,
        debounce_us: u32::from(gpio.debounce) * 10,
    }
}
fn claim(state: &mut State, gpio: &Gpio, pin: u16) -> Result<(), acpi::Error> {
    if let Some(prior) = state.claims.iter().find(|claim| claim.pin == pin) {
        return if prior.ready {
            Ok(())
        } else {
            Err(acpi::SUPPORT)
        };
    }
    state.claims.try_reserve(1).map_err(|_| acpi::Error(4))?;
    state.claims.push(Claim { pin, ready: false });
    state.controller.request(pin, policy(gpio))?;
    state.claims.last_mut().expect("inserted claim").ready = true;
    Ok(())
}

pub type Supplier<'a> = Dependency<'a>;

// Before callback registration, every refusal must still retire an already
// constructed native backend. Failed retirement pins its dependencies/provider.
struct Uninstalled<'a> {
    handle: Handle<'a>,
    controller: Option<Box<dyn NativeController>>,
    dependencies: Vec<DependencyPin>,
}
impl Drop for Uninstalled<'_> {
    fn drop(&mut self) {
        if let Some(mut controller) = self.controller.take()
            && controller.shutdown().is_err()
        {
            self.handle
                .ec_resource_quarantine()
                .store(true, Ordering::Release);
            core::mem::forget(controller);
            core::mem::forget(core::mem::take(&mut self.dependencies));
        }
    }
}

pub struct Binding<'a> {
    device: DeviceResources<'a>,
    context: *mut Context,
    installed: bool,
}
impl<'a> Binding<'a> {
    /// Install a real GPIO address-space handler before firmware `_REG` clients
    /// run. The sealed backend already owns this exact controller's resources.
    /// The caller keeps every `_DEP` supplier receipt.
    pub fn install(
        device: DeviceResources<'a>,
        controller: Box<dyn NativeController>,
        suppliers: &[Supplier<'a>],
    ) -> Result<Self, Error> {
        let mut owner = Uninstalled {
            handle: device.handle(),
            controller: Some(controller),
            dependencies: suppliers.iter().map(Dependency::native_pin).collect(),
        };
        device.revalidate()?;
        if owner
            .controller
            .as_ref()
            .expect("uninstalled backend")
            .device_path()
            != device.path()
        {
            return Err(Error::ResourceChanged);
        }
        owner
            .controller
            .as_ref()
            .expect("uninstalled backend")
            .matches_device(&device)?;
        if device.dependencies().iter().any(|dependency| {
            !suppliers
                .iter()
                .any(|supplier| supplier.handle() == *dependency)
        }) {
            return Err(Error::Unassigned);
        }
        let mut semaphore = ptr::null_mut();
        // SAFETY: this live namespace session owns the native OSL provider.
        checked(unsafe { acpi_os_create_semaphore(1, 1, &mut semaphore) })?;
        let context = Box::into_raw(Box::new(Context {
            info: UnsafeCell::new(ConnectionInfo {
                connection: ptr::null_mut(),
                length: 0,
                access_length: 0,
            }),
            enabled: AtomicBool::new(true),
            first_operation: AtomicU32::new(0),
            first_synchronization: AtomicU32::new(0),
            supplier: SupplierState::new(),
            semaphore,
            state: UnsafeCell::new(State {
                controller: owner.controller.take().expect("uninstalled backend"),
                claims: Vec::new(),
                stopped: false,
                dependencies: core::mem::take(&mut owner.dependencies),
            }),
        }));
        // SAFETY: the core keeps the exact callback storage through termination.
        if let Err(error) = unsafe {
            device
                .handle()
                .retain_ec_context(before_termination, retire, None, context.cast())
        } {
            // No callback can use this unregistered context, but its original
            // backend must still acknowledge shutdown before dependency release.
            // SAFETY: this function uniquely owns the unregistered allocation.
            let native = unsafe { &*context };
            native.enabled.store(false, Ordering::Release);
            // No core lifecycle owns this context. Supplier pins survive until
            // the original semaphore acknowledges deletion as well.
            let cleanup = native.finish_backend(false);
            let status = match cleanup {
                // SAFETY: no handler/finalizer received this semaphore/context.
                Ok(()) => unsafe { acpi_os_delete_semaphore(semaphore) },
                Err(error) => error.0,
            };
            if status == 0 {
                // SAFETY: unregistered context is uniquely owned here.
                unsafe { drop(Box::from_raw(context)) };
            } else {
                device
                    .handle()
                    .ec_resource_quarantine()
                    .store(true, Ordering::Release);
            }
            return Err(if status == 0 {
                Error::Acpi(error)
            } else {
                Error::Retirement {
                    primary: Some(error),
                    cleanup: acpi::Error(status),
                }
            });
        }
        let mut binding = Self {
            device,
            context,
            installed: false,
        };
        // SAFETY: core-registered context and sealed native backend own real I/O.
        match unsafe {
            binding
                .device
                .handle()
                .install_region(8, region, setup, context.cast())
        } {
            Ok(()) => {
                binding.installed = true;
                // ACPICA may suppress a _REG AML error after native effects.
                // Preserve the installed handler and diagnostics, but publish a
                // supplier only after acknowledged, error-free initialization.
                let native = binding.context();
                let healthy = native.with_state(|state| {
                    let failures = native.failures();
                    if let Some(error) = failures.operation.or(failures.synchronization) {
                        return Err(error);
                    }
                    if state.claims.iter().any(|claim| !claim.ready) {
                        Err(acpi::SUPPORT)
                    } else {
                        native.supplier.connected().map_err(|_| acpi::SUPPORT)
                    }
                });
                if healthy.is_err() {
                    native.supplier.close_admission();
                }
                Ok(binding)
            }
            Err(error) => {
                // Install can have succeeded before a namespace invalidation;
                // callbacks and native owners stay core-kept in either case.
                binding.context().enabled.store(false, Ordering::Release);
                Err(error.into())
            }
        }
    }
    fn context(&self) -> &Context {
        // SAFETY: Binding borrows the session keeping this core context.
        unsafe { &*self.context }
    }
    pub fn handle(&self) -> Handle<'a> {
        self.device.handle()
    }
    pub fn failures(&self) -> Failures {
        self.context().failures()
    }
    pub fn supplier(&self) -> Result<Supplier<'a>, Error> {
        self.device.revalidate()?;
        let failures = self.failures();
        if let Some(error) = failures.operation.or(failures.synchronization) {
            return Err(Error::Acpi(error));
        }
        if !self.installed || !self.context().enabled.load(Ordering::Acquire) {
            return Err(Error::Unassigned);
        }
        Dependency::acquire(self.device.handle(), &self.context().supplier)
    }
    /// Missing `_AEI` means no firmware event resources. Native parent IRQ,
    /// wake and deferred-work registration are required separately for admission.
    pub fn event_resources(&self) -> Result<Vec<Descriptor>, Error> {
        match evaluate(self.device.handle(), "_AEI") {
            Err(Error::Acpi(acpi::Error(5))) => Ok(Vec::new()),
            other => other,
        }
    }
    pub fn remove(&mut self) -> Result<(), Error> {
        self.context().supplier.close_admission();
        if self.context().supplier.consumers() != 0 {
            return Err(Error::Conflict);
        }
        // `_REG(DISCONNECT)` can access the original live lines during removal.
        let result = if self.installed {
            // SAFETY: installed callback/context remain held by the core.
            unsafe { self.device.handle().remove_region(8, region) }
        } else {
            Ok(())
        };
        self.context().enabled.store(false, Ordering::Release);
        self.installed = false;
        match (result, self.context().finish_backend(true)) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(Error::Acpi(error)),
            (result, Err(cleanup)) => Err(Error::Retirement {
                primary: result.err(),
                cleanup,
            }),
        }
    }
}
impl Drop for Binding<'_> {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

unsafe extern "C" fn setup(
    _: *mut c_void,
    action: u32,
    context: *mut c_void,
    out: *mut *mut c_void,
) -> Status {
    if context.is_null() || out.is_null() || action > 1 {
        return acpi::BAD_PARAMETER.0;
    }
    // SAFETY: ACPICA region context output and core-kept stable storage.
    unsafe {
        out.write(if action == 0 {
            context
        } else {
            ptr::null_mut()
        })
    };
    0
}
unsafe extern "C" fn region(
    function: u32,
    address: u64,
    width: u32,
    value: *mut u64,
    handler: *mut c_void,
    region_context: *mut c_void,
) -> Status {
    #[cfg(test)]
    {
        *tests::LAST_ACCESS.lock().unwrap() = (function, address, width);
    }
    if handler.is_null()
        || region_context != handler
        || value.is_null()
        || function > 1
        || width == 0
    {
        return acpi::BAD_PARAMETER.0;
    }
    // Pinned ACPICA exserial.c accepts only Integer writes and passes the
    // source integer's address, even for a wider GPIO field. Never overread it.
    if function == 1 && width > 64 {
        return acpi::SUPPORT.0;
    }
    // SAFETY: setup returns this original core-kept Context pointer only.
    let context = unsafe { &*handler.cast::<Context>() };
    // SAFETY: ACPICA's context mutex serializes its Connection prefix updates.
    let info = unsafe { *context.info.get() };
    if info.connection.is_null() || info.length == 0 {
        return acpi::BAD_PARAMETER.0;
    }
    // SAFETY: evregion.c keeps the field Connection buffer through call.
    let raw = unsafe { core::slice::from_raw_parts(info.connection, usize::from(info.length)) };
    let gpio = match parse_gpio_connection(raw) {
        Ok(gpio) => gpio,
        Err(_) => return acpi::BAD_PARAMETER.0,
    };
    let Ok(start) = usize::try_from(address) else {
        return acpi::BAD_PARAMETER.0;
    };
    if start >= gpio.pins.len()
        || (function == 1 && matches!(gpio.kind, GpioKind::Io(IoRestriction::Input)))
    {
        return acpi::BAD_PARAMETER.0;
    }
    let count = (width as usize).min(gpio.pins.len() - start);
    // exfield.c allocates ceil(width/8) bytes for reads and exserial.c supplies
    // an eight-byte Integer for writes. Byte access avoids rounded u64
    // overrun on non-multiple-of-64 Buffer fields.
    let bytes = (width as usize).div_ceil(8);
    // SAFETY: the unchanged ACPICA caller supplies at least this field
    // allocation; writes were restricted above to the source Integer's size.
    let value = unsafe { core::slice::from_raw_parts_mut(value.cast::<u8>(), bytes) };
    context
        .with_state(|state| {
            for (bit, pin) in gpio.pins[start..start + count].iter().copied().enumerate() {
                claim(state, &gpio, pin)?;
                let mask = 1 << (bit % 8);
                if function == 1 {
                    state.controller.write(pin, value[bit / 8] & mask != 0)?;
                } else if state.controller.read(pin)? {
                    value[bit / 8] |= mask;
                } else {
                    value[bit / 8] &= !mask;
                }
            }
            Ok(())
        })
        .map_or_else(|error| error.0, |()| 0)
}
unsafe extern "C" fn before_termination(raw: *mut c_void) -> Status {
    // SAFETY: provider quiescence has ended all callback/work access; this exact
    // core-kept context is still live before interpreter/provider teardown.
    let context = unsafe { &*raw.cast::<Context>() };
    context.supplier.close_admission();
    context.enabled.store(false, Ordering::Release);
    if context.supplier.consumers() != 0 {
        return acpi::SUPPORT.0;
    }
    // Suppliers were registered before consumers, so the core's LIFO callbacks
    // retire dependent native effects first while the supplier is still live.
    context
        .finish_backend(true)
        .map_or_else(|error| error.0, |()| 0)
}
unsafe extern "C" fn retire(raw: *mut c_void) -> Status {
    // SAFETY: successful core termination ended callbacks; provider remains live.
    let context = unsafe { &mut *raw.cast::<Context>() };
    let state = context.state.get_mut();
    if !state.stopped || !state.claims.is_empty() || !state.dependencies.is_empty() {
        return acpi::SUPPORT.0;
    }
    // SAFETY: no callbacks or direct controller accesses remain after termination.
    let status = unsafe { acpi_os_delete_semaphore(context.semaphore) };
    if status == 0 {
        // SAFETY: the core owns this exact Box; finalizer runs only once on success.
        unsafe { drop(Box::from_raw(raw.cast::<Context>())) };
    }
    status
}

/// Resolve the firmware method Linux selects for a particular `_AEI` resource.
/// This descriptor alone does not register an interrupt or enable wake.
pub fn event_method<'a>(
    provider: Handle<'a>,
    gpio: &Gpio,
) -> Result<Option<EventMethod<'a>>, Error> {
    let GpioKind::Interrupt { trigger, .. } = gpio.kind else {
        return Ok(None);
    };
    let Some(pin) = gpio.pins.first().copied() else {
        return Err(Error::Malformed);
    };
    if pin <= 255 {
        let name = format!(
            "_{}{:02X}",
            if trigger == Trigger::Edge { 'E' } else { 'L' },
            pin
        );
        match provider.child(&name) {
            Ok(method) => return Ok(Some(EventMethod { method, pin: None })),
            Err(acpi::Error(5)) => {}
            Err(error) => return Err(error.into()),
        }
    }
    match provider.child("_EVT") {
        Ok(method) => Ok(Some(EventMethod {
            method,
            pin: Some(pin),
        })),
        Err(acpi::Error(5)) => Ok(None),
        Err(error) => Err(error.into()),
    }
}
pub struct EventMethod<'a> {
    method: Handle<'a>,
    pin: Option<u16>,
}
impl EventMethod<'_> {
    /// Process-context AML dispatch after a real native IRQ receipt, never from
    /// the hard interrupt handler. Preserves the method's failure.
    pub fn evaluate(&self) -> Result<(), acpi::Error> {
        let argument = self.pin.map(|pin| Argument::Integer(u64::from(pin)));
        self.method.evaluate(None, argument.as_slice()).map(|_| ())
    }
}

#[cfg(test)]
mod tests;

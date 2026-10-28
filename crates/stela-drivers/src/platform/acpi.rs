//! Native x86 firmware AML via pinned ACPICA, separate from the ARM guest ACPI.
//!
//! The platform supplies owned OSL services. There is no implicit identity map,
//! interrupt routing, EC driver, scheduler, allocator, or permissive I/O fallback.
//! See [`Services`] and `acpi/README.md` before installing a provider.
pub mod resources;
use alloc::{boxed::Box, ffi::CString, string::String, sync::Arc, vec::Vec};
use core::{
    cell::{Cell, RefCell},
    ffi::{CStr, c_char, c_void},
    marker::PhantomData,
    ptr,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

pub type Status = u32;
pub type Interrupt = unsafe extern "C" fn(*mut c_void) -> u32;
pub type Work = unsafe extern "C" fn(*mut c_void);
pub type Notify = unsafe extern "C" fn(*mut c_void, u32, *mut c_void);
pub type Region = unsafe extern "C" fn(u32, u64, u32, *mut u64, *mut c_void, *mut c_void) -> Status;
pub type RegionSetup =
    unsafe extern "C" fn(*mut c_void, u32, *mut c_void, *mut *mut c_void) -> Status;

/// Exact ACPICA status, without collapsing firmware errors into generic success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(pub Status);
pub const SUPPORT: Error = Error(0x000f);
pub const NOT_FOUND: Error = Error(0x0005);
pub const BAD_PARAMETER: Error = Error(0x1001);
pub const ALREADY_EXISTS: Error = Error(0x0007);
pub const LIMIT: Error = Error(0x0010);
fn checked(status: Status) -> Result<(), Error> {
    if status == 0 {
        Ok(())
    } else {
        Err(Error(status))
    }
}

/// Hardware capabilities attested by the native provider, required as a set.
/// SCI includes correct FADT routing, shared level interrupts, mask/synchronize;
/// work includes genuinely deferred IRQ-safe enqueue and draining; regions includes
/// owned EC/GPIO/serial-bus handlers installed before dependent firmware methods;
/// allocation includes all OSL allocations from interrupt/deferred contexts.
pub const CAP_SCI: u64 = 1;
pub const CAP_DEFERRED_WORK: u64 = 2;
pub const CAP_REGIONS: u64 = 4;
pub const CAP_IRQ_ALLOC: u64 = 8;
pub const FULL_CAPABILITIES: u64 = CAP_SCI | CAP_DEFERRED_WORK | CAP_REGIONS | CAP_IRQ_ALLOC;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PciId {
    pub segment: u16,
    pub bus: u16,
    pub device: u16,
    pub function: u16,
}

/// Owned C-ABI native service provider. All functions are mandatory.
///
/// # Safety
/// Transfer `context` ownership to [`Session::start`]. All callbacks and context
/// must remain valid until `destroy`; failed quiescence intentionally retains them
/// permanently. Each callback must implement the corresponding ACPICA OSL contract
/// (including timeout units, IRQ flags, locking, memory attributes, map leases,
/// unique nonzero thread IDs, 100 ns monotonic timer and callback draining).
/// `allocate` returns at least 16-byte aligned storage, `free` accepts its pointers.
/// `map` owns each exact address/length lease until matching `unmap`, including
/// overlapping/repeated table mappings; firmware RAM and MMIO require appropriate
/// cache attributes and lifetime after ExitBootServices. Lock acquisition disables
/// local interrupts and restores their previous flags on release. Callbacks must
/// not panic/unwind. Unsupported fallible operations return a real failure status;
/// mandatory void operations must actually complete, never silently do nothing.
/// Semaphore timeout is milliseconds (`0` polls, `0xffff` waits forever), sleep
/// is milliseconds and stall is microseconds; I/O widths are bits. `execute`
/// queues work, including from SCI, without running it inline, preserving required
/// ordering (in particular FIFO Notify), with no drain deadlock on worker context.
/// `quiesce` closes this instance's work admission (new execute calls fail), masks
/// and synchronizes SCI and region callbacks, then drains all admitted work,
/// leaving all providers valid for ACPICA's remove/free calls during termination.
/// Native table deletion must occur outside active AML frames/interpreter callbacks.
/// Pre-delete quiescence excludes its current callback while synchronizing all other
/// producers/work. Failed pre-delete quiescence invokes nonreturning `fatal`.
/// `destroy` runs only after successful termination. Hardware capability bits must
/// attest real installed services, never aspirational support.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Services {
    pub context: *mut c_void,
    pub root: u64,
    pub capabilities: u64,
    pub allocate: unsafe extern "C" fn(*mut c_void, u64) -> *mut c_void,
    pub free: unsafe extern "C" fn(*mut c_void, *mut c_void),
    pub map: unsafe extern "C" fn(*mut c_void, u64, u64) -> *mut c_void,
    pub unmap: unsafe extern "C" fn(*mut c_void, *mut c_void, u64),
    pub create_lock: unsafe extern "C" fn(*mut c_void, *mut *mut c_void) -> Status,
    pub delete_lock: unsafe extern "C" fn(*mut c_void, *mut c_void),
    pub acquire_lock: unsafe extern "C" fn(*mut c_void, *mut c_void) -> u64,
    pub release_lock: unsafe extern "C" fn(*mut c_void, *mut c_void, u64),
    pub create_semaphore: unsafe extern "C" fn(*mut c_void, u32, u32, *mut *mut c_void) -> Status,
    pub delete_semaphore: unsafe extern "C" fn(*mut c_void, *mut c_void) -> Status,
    pub wait_semaphore: unsafe extern "C" fn(*mut c_void, *mut c_void, u32, u16) -> Status,
    pub signal_semaphore: unsafe extern "C" fn(*mut c_void, *mut c_void, u32) -> Status,
    pub install_interrupt: unsafe extern "C" fn(*mut c_void, u32, Interrupt, *mut c_void) -> Status,
    pub remove_interrupt: unsafe extern "C" fn(*mut c_void, u32, Interrupt) -> Status,
    pub thread_id: unsafe extern "C" fn(*mut c_void) -> u64,
    pub execute: unsafe extern "C" fn(*mut c_void, u32, Work, *mut c_void) -> Status,
    pub drain_work: unsafe extern "C" fn(*mut c_void),
    pub sleep: unsafe extern "C" fn(*mut c_void, u64),
    pub stall: unsafe extern "C" fn(*mut c_void, u32),
    pub read_port: unsafe extern "C" fn(*mut c_void, u64, *mut u32, u32) -> Status,
    pub write_port: unsafe extern "C" fn(*mut c_void, u64, u32, u32) -> Status,
    pub read_memory: unsafe extern "C" fn(*mut c_void, u64, *mut u64, u32) -> Status,
    pub write_memory: unsafe extern "C" fn(*mut c_void, u64, u64, u32) -> Status,
    pub read_pci: unsafe extern "C" fn(*mut c_void, *mut PciId, u32, *mut u64, u32) -> Status,
    pub write_pci: unsafe extern "C" fn(*mut c_void, *mut PciId, u32, u64, u32) -> Status,
    pub timer: unsafe extern "C" fn(*mut c_void) -> u64,
    pub signal: unsafe extern "C" fn(*mut c_void, u32, *mut c_void) -> Status,
    pub log: unsafe extern "C" fn(*mut c_void, *const c_char, u64),
    pub flush_cache: unsafe extern "C" fn(*mut c_void),
    pub quiesce: unsafe extern "C" fn(*mut c_void) -> Status,
    pub destroy: unsafe extern "C" fn(*mut c_void),
    /// Mandatory fail-closed kernel fatal path; called when pre-delete callback
    /// quiescence fails. It must never return, unwind, or fabricate completion.
    pub fatal: unsafe extern "C" fn(*mut c_void, Status) -> !,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawObject {
    kind: u32,
    length: u32,
    payload: u64,
    extra: u64,
}
#[repr(C)]
struct RawBuffer {
    length: u64,
    pointer: *mut c_void,
}
unsafe extern "C" {
    fn stela_acpi_start(services: *const Services, hardware: u8) -> Status;
    fn stela_acpi_stop() -> Status;
    fn stela_acpi_enable_hardware() -> Status;
    fn stela_acpi_guard_enter(out: *mut *mut c_void, epoch: *mut u64) -> Status;
    fn stela_acpi_guard_leave(guard: *mut c_void);
    fn stela_acpi_namespace_valid() -> u8;
    fn stela_acpi_bind_node(candidate: *mut c_void, epoch: u64) -> Status;
    fn stela_acpi_retain_context(
        before_termination: unsafe extern "C" fn(*mut c_void) -> Status,
        retire: unsafe extern "C" fn(*mut c_void) -> Status,
        activate: Option<unsafe extern "C" fn(*mut c_void) -> Status>,
        context: *mut c_void,
    ) -> Status;
    fn stela_acpi_evaluate(
        handle: *mut c_void,
        path: *const c_char,
        args: *mut RawObject,
        count: u32,
        result: *mut RawBuffer,
    ) -> Status;
    fn stela_acpi_walk(
        hid: *const c_char,
        callback: unsafe extern "C" fn(*mut c_void, u32, *mut c_void, *mut *mut c_void) -> Status,
        context: *mut c_void,
    ) -> Status;
    fn acpi_get_name(handle: *mut c_void, kind: u32, buffer: *mut RawBuffer) -> Status;
    fn acpi_get_handle(parent: *mut c_void, path: *const c_char, out: *mut *mut c_void) -> Status;
    fn acpi_os_free(pointer: *mut c_void);
    fn acpi_acquire_global_lock(timeout_ms: u16, token: *mut u32) -> Status;
    fn acpi_release_global_lock(token: u32) -> Status;
    fn acpi_install_notify_handler(
        handle: *mut c_void,
        kind: u32,
        callback: Notify,
        context: *mut c_void,
    ) -> Status;
    fn acpi_remove_notify_handler(handle: *mut c_void, kind: u32, callback: Notify) -> Status;
    fn acpi_os_wait_events_complete();
    fn acpi_get_sleep_type_data(state: u8, a: *mut u8, b: *mut u8) -> Status;
    fn acpi_enter_sleep_state_prep(state: u8) -> Status;
    fn acpi_install_address_space_handler(
        handle: *mut c_void,
        space: u32,
        handler: Region,
        setup: RegionSetup,
        context: *mut c_void,
    ) -> Status;
    fn acpi_remove_address_space_handler(
        handle: *mut c_void,
        space: u32,
        handler: Region,
    ) -> Status;
    fn acpi_install_address_space_handler_no_reg(
        handle: *mut c_void,
        space: u8,
        handler: Region,
        setup: RegionSetup,
        context: *mut c_void,
    ) -> Status;
    #[cfg(test)]
    fn stela_acpi_layout(field: u32) -> u64;
}
const _: () = {
    assert!(size_of::<Services>() == 280);
    assert!(core::mem::offset_of!(Services, fatal) == 272);
    assert!(core::mem::offset_of!(Services, destroy) == 264);
    assert!(size_of::<RawObject>() == 24);
    assert!(size_of::<RawBuffer>() == 16);
    assert!(size_of::<PciId>() == 8);
};
static RESERVED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    InterpreterOnly,
    Hardware,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HardwareState {
    InterpreterOnly,
    ActivationFailed,
    Enabled,
}

/// The single ACPICA instance. This BSP-owned facade is neither Send nor Sync;
/// the provider synchronizes asynchronous ACPICA callbacks separately.
/// Handles borrow it, and cannot survive termination.
pub struct Session {
    active: bool,
    hardware: Cell<HardwareState>,
    ec_global_locks: Arc<AtomicUsize>,
    ec_resource_quarantine: Arc<AtomicBool>,
    notifications: RefCell<Vec<*mut NotifyContext>>,
    _local: PhantomData<*mut ()>,
}
impl Session {
    /// Initialize real firmware tables and namespace. InterpreterOnly skips ACPI
    /// mode/event/FACS/device `_INI` activation; explicit AML can still access I/O
    /// and therefore must only be evaluated with appropriate provider ownership.
    ///
    /// # Safety
    /// All [`Services`] contracts must hold, including physical firmware table
    /// validity and exclusive system ownership of this interpreter. Ownership of
    /// `context` transfers even on initialization failure (except ALREADY_EXISTS).
    pub unsafe fn start(services: Services, mode: Mode) -> Result<Self, Error> {
        if RESERVED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ALREADY_EXISTS);
        }
        if services.root == 0
            || (mode == Mode::Hardware
                && services.capabilities & FULL_CAPABILITIES != FULL_CAPABILITIES)
        {
            // SAFETY: ownership transferred by caller; no C state was initialized.
            unsafe { (services.destroy)(services.context) };
            RESERVED.store(false, Ordering::Release);
            return Err(if services.root == 0 {
                BAD_PARAMETER
            } else {
                SUPPORT
            });
        }
        // SAFETY: reserved singleton and provider contract promised by caller.
        let status = unsafe { stela_acpi_start(&services, u8::from(mode == Mode::Hardware)) };
        if status != 0 {
            // SAFETY: all callbacks remain valid, including on partial init.
            if unsafe { stela_acpi_stop() } == 0 {
                RESERVED.store(false, Ordering::Release);
            }
            return Err(Error(status));
        }
        Ok(Self {
            active: true,
            hardware: Cell::new(if mode == Mode::Hardware {
                HardwareState::Enabled
            } else {
                HardwareState::InterpreterOnly
            }),
            ec_global_locks: Arc::new(AtomicUsize::new(0)),
            ec_resource_quarantine: Arc::new(AtomicBool::new(false)),
            notifications: RefCell::new(Vec::new()),
            _local: PhantomData,
        })
    }
    /// After native EC/GPIO/serial handlers are installed, activate real SCI/GPE
    /// events and firmware `_INI`/`_REG` methods. Missing services remain errors.
    /// A failure may have partially enabled hardware; shut down the session before
    /// retrying. The provider's original capability attestation must still hold.
    pub fn enable_hardware(&self) -> Result<(), Error> {
        let guard = self.guard()?;
        match self.hardware.get() {
            HardwareState::Enabled => return guard.check(),
            HardwareState::ActivationFailed => return Err(SUPPORT),
            HardwareState::InterpreterOnly => {}
        }
        // C marks activation attempted before enabling hardware. That flag is
        // deliberately not a success witness: even a partial attempt requires
        // global shutdown before retry. Publish success only after both checks.
        self.hardware.set(HardwareState::ActivationFailed);
        // SAFETY: the live session owns ACPICA and the native provider.
        checked(unsafe { stela_acpi_enable_hardware() })?;
        guard.check()?;
        self.hardware.set(HardwareState::Enabled);
        Ok(())
    }
    /// True only after this provider's actual C activation succeeded, while its
    /// original namespace remains valid. No caller can manufacture this witness.
    pub fn hardware_enabled(&self) -> bool {
        self.active && self.hardware.get() == HardwareState::Enabled && self.namespace_available()
    }
    /// Real ACPICA/FACS arbitration for an EC whose observed `_GLK` requires it.
    /// The EC retains this owner and its namespace lease through byte access.
    pub fn ec_global_lock(&self) -> EcGlobalLock<'_> {
        EcGlobalLock {
            session: self,
            held: None,
        }
    }

    pub fn root(&self) -> Handle<'_> {
        Handle {
            session: self,
            raw: usize::MAX as *mut c_void,
        }
    }
    pub fn handle(&self, path: &str) -> Result<Handle<'_>, Error> {
        self.root().child(path)
    }
    /// ACPICA's device walk matches `_HID` and `_CID` and filters absent devices
    /// using real `_STA`; a missing method follows ACPICA's specification default.
    pub fn devices(&self, hid: &str) -> Result<Vec<Handle<'_>>, Error> {
        let hid = CString::new(hid).map_err(|_| BAD_PARAMETER)?;
        self.walk(hid.as_ptr())
    }
    /// Every present device in the namespace: ACPICA's device walk without
    /// an ID, which filters by `_STA` alone.
    pub fn all_devices(&self) -> Result<Vec<Handle<'_>>, Error> {
        self.walk(ptr::null())
    }
    /// A copy of the firmware's first `signature` table, or `None` when it
    /// has none, read through AcpiGetTable and released with AcpiPutTable.
    pub fn table(&self, signature: &[u8; 4]) -> Result<Option<Vec<u8>>, Error> {
        unsafe extern "C" {
            fn acpi_get_table(signature: *const c_char, instance: u32, out: *mut *mut u8)
            -> Status;
            fn acpi_put_table(table: *mut u8);
        }
        let _guard = self.guard()?;
        let name = [signature[0], signature[1], signature[2], signature[3], 0];
        let mut table = ptr::null_mut();
        // SAFETY: a NUL-terminated signature and an out pointer ACPICA fills
        // while the namespace guard is held.
        let status = unsafe { acpi_get_table(name.as_ptr().cast(), 1, &mut table) };
        if status == NOT_FOUND.0 {
            return Ok(None);
        }
        checked(status)?;
        // SAFETY: ACPICA maps the whole table, whose header gives its length
        // at byte 4, until acpi_put_table releases it.
        let bytes = unsafe {
            let length = u32::from_le_bytes(ptr::read_unaligned(table.add(4).cast::<[u8; 4]>()));
            core::slice::from_raw_parts(table, length as usize).to_vec()
        };
        // SAFETY: the table acpi_get_table returned, released once.
        unsafe { acpi_put_table(table) };
        Ok(Some(bytes))
    }
    fn walk(&self, hid: *const c_char) -> Result<Vec<Handle<'_>>, Error> {
        let guard = self.guard()?;
        let mut raw = Vec::<*mut c_void>::new();
        unsafe extern "C" fn collect(
            handle: *mut c_void,
            _: u32,
            context: *mut c_void,
            _: *mut *mut c_void,
        ) -> Status {
            // SAFETY: synchronous acpi_get_devices call owns this Vec.
            unsafe { &mut *context.cast::<Vec<*mut c_void>>() }.push(handle);
            0
        }
        // SAFETY: all callback storage lives through this synchronous walk.
        checked(unsafe {
            stela_acpi_walk(hid, collect, (&mut raw as *mut Vec<*mut c_void>).cast())
        })?;
        guard.check()?;
        raw.into_iter()
            .map(|raw| {
                guard.bind(raw)?;
                Ok(Handle { session: self, raw })
            })
            .collect()
    }
    /// SLP_TYPa and SLP_TYPb of sleep `state`, as ACPICA evaluates `\_Sx`.
    pub fn sleep_types(&self, state: u8) -> Result<(u8, u8), Error> {
        let guard = self.guard()?;
        let (mut a, mut b) = (0, 0);
        // SAFETY: the live session owns ACPICA; both outputs are writable.
        checked(unsafe { acpi_get_sleep_type_data(state, &mut a, &mut b) })?;
        guard.check()?;
        Ok((a, b))
    }
    /// Prepare to enter sleep `state` as Linux's `acpi_sleep_prepare` does with
    /// `acpi_enter_sleep_state_prep`: `\_PTS` and the `\_SST` indicator. Entering
    /// the state, its PM1 or sleep-control writes, stays the caller's.
    pub fn prepare_sleep(&self, state: u8) -> Result<(), Error> {
        let guard = self.guard()?;
        // SAFETY: the live session owns ACPICA.
        checked(unsafe { acpi_enter_sleep_state_prep(state) })?;
        guard.check()
    }
    /// False after native table deletion. The whole facade then returns AE_SUPPORT;
    /// native driver rebinding into a changed namespace is not implemented.
    pub fn namespace_available(&self) -> bool {
        // SAFETY: this live session owns the global native interpreter.
        unsafe { stela_acpi_namespace_valid() != 0 }
    }
    fn guard(&self) -> Result<NamespaceGuard<'_>, Error> {
        let mut raw = ptr::null_mut();
        let mut epoch = 0;
        // SAFETY: borrowed session retains C/provider state through guard drop.
        checked(unsafe { stela_acpi_guard_enter(&mut raw, &mut epoch) })?;
        Ok(NamespaceGuard {
            raw,
            epoch,
            session: self,
        })
    }
    fn release_notification(&self, context: *mut NotifyContext) {
        let mut contexts = self.notifications.borrow_mut();
        let index = contexts
            .iter()
            .position(|p| *p == context)
            .expect("owned notification");
        contexts.swap_remove(index);
        // SAFETY: handler removal and work draining completed before this call.
        unsafe {
            drop(Box::from_raw(context));
        }
    }
    /// Quiesce callbacks before freeing ACPICA state. A failure quarantines the
    /// interpreter/provider permanently and prevents another session being opened.
    pub fn shutdown(mut self) -> Result<(), Error> {
        self.close()
    }
    fn close(&mut self) -> Result<(), Error> {
        if !self.active {
            return Ok(());
        }
        if self.ec_global_locks.load(Ordering::Acquire) != 0
            || self.ec_resource_quarantine.load(Ordering::Acquire)
        {
            // An unreleased FACS mutex or an unregistered native resource with
            // failed retirement still references this provider. Retain both.
            return Err(SUPPORT);
        }
        self.active = false;
        self.hardware.set(HardwareState::ActivationFailed);
        // SAFETY: this session owns the globally reserved instance.
        let result = checked(unsafe { stela_acpi_stop() });
        if result.is_ok() {
            // The core/provider are stopped; includes callbacks retained after
            // unload or failed Notify removal. Failed quiescence leaks them safely.
            for context in self.notifications.get_mut().drain(..) {
                // SAFETY: the core is stopped, so no callback can still use the context.
                unsafe {
                    drop(Box::from_raw(context));
                }
            }
            RESERVED.store(false, Ordering::Release);
        }
        result
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

struct NamespaceGuard<'a> {
    raw: *mut c_void,
    epoch: u64,
    session: &'a Session,
}
impl NamespaceGuard<'_> {
    fn check(&self) -> Result<(), Error> {
        if self.session.namespace_available() {
            Ok(())
        } else {
            Err(SUPPORT)
        }
    }
    fn bind(&self, candidate: *mut c_void) -> Result<(), Error> {
        self.check()?;
        // SAFETY: actual namespace read lease protects the locked tree walk;
        // candidate itself is compared only and never dereferenced speculatively.
        checked(unsafe { stela_acpi_bind_node(candidate, self.epoch) })?;
        self.check()
    }
}
impl Drop for NamespaceGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: this guard entered the namespace lease that it now leaves.
        unsafe {
            stela_acpi_guard_leave(self.raw);
        }
    }
}

/// An EC firmware lock, backed by ACPICA's actual global-lock API.
/// Failed release retains its token/namespace lease; it never retries implicitly.
pub struct EcGlobalLock<'a> {
    session: &'a Session,
    held: Option<(u32, NamespaceGuard<'a>)>,
}

impl super::ec::FirmwareLock for EcGlobalLock<'_> {
    fn acquire(&mut self, timeout_us: u64) -> Result<(), super::ec::LockError> {
        if self.held.is_some() {
            return Err(super::ec::LockError);
        }
        // ACPICA uses milliseconds; 0xffff means forever and is not bounded.
        let milliseconds = timeout_us.div_ceil(1_000);
        if milliseconds == 0 || milliseconds >= u64::from(u16::MAX) {
            return Err(super::ec::LockError);
        }
        let guard = self.session.guard().map_err(|_| super::ec::LockError)?;
        let mut token = 0;
        // SAFETY: the session and actual namespace read lease retain ACPICA;
        // only the real API creates this FACS/global-mutex ownership token.
        checked(unsafe { acpi_acquire_global_lock(milliseconds as u16, &mut token) })
            .map_err(|_| super::ec::LockError)?;
        self.held = Some((token, guard));
        // Native service callbacks can nest; count the current ownership after
        // the real acquisition instead of overwriting a pre-call snapshot.
        self.session
            .ec_global_locks
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .map_err(|_| super::ec::LockError)?;
        if self.held.as_ref().unwrap().1.check().is_err() {
            // A native callback may have invalidated namespace admission while
            // acquisition waited. Release actual firmware ownership, never
            // authorize EC I/O from the stale namespace observation.
            self.release()?;
            return Err(super::ec::LockError);
        }
        Ok(())
    }

    fn release(&mut self) -> Result<(), super::ec::LockError> {
        let Some((token, _guard)) = self.held.as_ref() else {
            return Err(super::ec::LockError);
        };
        // SAFETY: token belongs to this live session and is still acquired.
        // Cleanup remains necessary even if namespace admission was invalidated.
        checked(unsafe { acpi_release_global_lock(*token) }).map_err(|_| super::ec::LockError)?;
        self.held = None;
        self.session.ec_global_locks.fetch_sub(1, Ordering::AcqRel);
        Ok(())
    }
}

impl Drop for EcGlobalLock<'_> {
    fn drop(&mut self) {
        if let Some((_token, guard)) = self.held.take() {
            // An uncertain/unreleased firmware lock cannot silently free its
            // namespace owner. Ec reports and quarantines release failures.
            core::mem::forget(guard);
        }
    }
}

#[derive(Clone, Copy)]
pub struct Handle<'a> {
    session: &'a Session,
    raw: *mut c_void,
}
impl core::fmt::Debug for Handle<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("AcpiHandle").field(&self.raw).finish()
    }
}
impl PartialEq for Handle<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.session, other.session) && self.raw == other.raw
    }
}
impl Eq for Handle<'_> {}
/// Exact ACPICA external object type code, including values unknown here.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectType(u32);
impl ObjectType {
    pub const INTEGER: Self = Self(1);
    pub const DEVICE: Self = Self(6);
    pub const POWER: Self = Self(11);

    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> u32 {
        self.0
    }
}
/// Namespace reference and its external ACPICA ActualType. The handle still
/// borrows its single Session; this metadata grants no independent ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reference<'a> {
    pub handle: Handle<'a>,
    pub actual_type: ObjectType,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    Integer(u64),
    String(Vec<u8>),
    Buffer(Vec<u8>),
    Package(Vec<Value<'a>>),
    Reference(Reference<'a>),
    Uninitialized,
}
pub enum Argument<'a> {
    Integer(u64),
    String(&'a CStr),
    Buffer(&'a [u8]),
    Package(&'a [Argument<'a>]),
    Reference(Reference<'a>),
}
struct Arguments {
    objects: Vec<RawObject>,
    children: Vec<Arguments>,
}
impl Arguments {
    fn new(args: &[Argument<'_>], session: &Session, depth: u32) -> Result<Self, Error> {
        if depth > 32 || args.len() > 65536 {
            return Err(LIMIT);
        }
        let mut result = Self {
            objects: Vec::with_capacity(args.len()),
            children: Vec::new(),
        };
        for arg in args {
            let (kind, length, payload) = match arg {
                Argument::Integer(n) => (1, 0, *n),
                Argument::String(text) => (
                    2,
                    u32::try_from(text.to_bytes().len()).map_err(|_| LIMIT)?,
                    text.as_ptr() as u64,
                ),
                Argument::Buffer(bytes) => (
                    3,
                    u32::try_from(bytes.len()).map_err(|_| LIMIT)?,
                    bytes.as_ptr() as u64,
                ),
                Argument::Package(items) => {
                    let child = Self::new(items, session, depth + 1)?;
                    let entry = (4, child.objects.len() as u32, child.objects.as_ptr() as u64);
                    result.children.push(child);
                    entry
                }
                Argument::Reference(reference) => {
                    if !ptr::eq(session, reference.handle.session) {
                        return Err(BAD_PARAMETER);
                    }
                    (
                        0x14,
                        reference.actual_type.raw(),
                        reference.handle.raw as u64,
                    )
                }
            };
            result.objects.push(RawObject {
                kind,
                length,
                payload,
                extra: 0,
            });
        }
        Ok(result)
    }
}
impl<'a> Handle<'a> {
    pub(crate) fn ec_scope(self, root: bool) -> Self {
        if root { self.session.root() } else { self }
    }
    pub(crate) fn ec_lock_count(self) -> Arc<AtomicUsize> {
        self.session.ec_global_locks.clone()
    }
    pub(crate) fn ec_resource_quarantine(self) -> Arc<AtomicBool> {
        self.session.ec_resource_quarantine.clone()
    }
    /// Retain callback storage through actual core termination, including failed
    /// removal. The finalizer runs before the original OSL provider is destroyed.
    ///
    /// # Safety
    /// A successful call transfers ownership of context to the core finalizer.
    /// before_termination runs after real provider quiescence, closes native
    /// admission and must refuse while ownership still requires the live core.
    /// The finalizer must not enter AML or unwind, and must retire provider
    /// resources before freeing its storage. Failed calls transfer no ownership.
    /// An optional activation callback runs after actual FACS/SCI/GLK setup
    /// and before device _INI. It must be idempotent after explicit attachment,
    /// retain its namespace identity and propagate any activation failure.
    /// Activation must not register more retained contexts or borrow a movable
    /// Rust Session address.
    pub(crate) unsafe fn retain_ec_context(
        self,
        before_termination: unsafe extern "C" fn(*mut c_void) -> Status,
        retire: unsafe extern "C" fn(*mut c_void) -> Status,
        activate: Option<unsafe extern "C" fn(*mut c_void) -> Status>,
        context: *mut c_void,
    ) -> Result<(), Error> {
        let guard = self.session.guard()?;
        guard.bind(self.raw)?;
        // SAFETY: caller transfers the retained context on actual C success.
        checked(unsafe { stela_acpi_retain_context(before_termination, retire, activate, context) })
    }
    pub(crate) fn ec_activation_target(self) -> Result<*mut c_void, Error> {
        let guard = self.session.guard()?;
        guard.bind(self.raw)?;
        Ok(self.raw)
    }
    /// Match Linux EC setup: root handler coverage must not connect unrelated
    /// devices' _REG methods. The actual EC subtree is connected separately.
    pub(crate) unsafe fn install_ec_region(
        self,
        handler: Region,
        setup: RegionSetup,
        context: *mut c_void,
    ) -> Result<(), Error> {
        let guard = self.session.guard()?;
        guard.bind(self.raw)?;
        // SAFETY: live namespace lease validates the exact scope; caller retains
        // the callback/context until removal or actual core termination.
        checked(unsafe {
            acpi_install_address_space_handler_no_reg(self.raw, 3, handler, setup, context)
        })?;
        guard.check()
    }
    /// Read the owning provider's successful activation and namespace witness.
    pub fn hardware_active(self) -> bool {
        self.session.hardware_enabled()
    }
    /// Resolve a retained namespace handle to its actual absolute ACPI path.
    pub fn path(self) -> Result<String, Error> {
        let guard = self.session.guard()?;
        let mut result = RawBuffer {
            length: u64::MAX,
            pointer: ptr::null_mut(),
        };
        // SAFETY: handle belongs to this live session; ACPICA owns the result.
        let status = unsafe { acpi_get_name(self.raw, 0, &mut result) };
        struct Free(*mut c_void);
        impl Drop for Free {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: ACPICA allocated this result buffer for the caller to free once.
                    unsafe { acpi_os_free(self.0) };
                }
            }
        }
        let _free = Free(result.pointer);
        checked(status)?;
        guard.check()?;
        if result.pointer.is_null() {
            return Err(BAD_PARAMETER);
        }
        let length = usize::try_from(result.length).map_err(|_| LIMIT)?;
        if length > 65536 {
            return Err(LIMIT);
        }
        // SAFETY: successful ACPICA output owns exactly buffer.length bytes.
        let bytes = unsafe { core::slice::from_raw_parts(result.pointer.cast::<u8>(), length) };
        let text = CStr::from_bytes_until_nul(bytes).map_err(|_| BAD_PARAMETER)?;
        String::from_utf8(text.to_bytes().to_vec()).map_err(|_| BAD_PARAMETER)
    }

    pub fn child(self, path: &str) -> Result<Self, Error> {
        let guard = self.session.guard()?;
        let path = CString::new(path).map_err(|_| BAD_PARAMETER)?;
        let mut raw = ptr::null_mut();
        // SAFETY: handles belong to the live borrowed instance, output is writable.
        checked(unsafe { acpi_get_handle(self.raw, path.as_ptr(), &mut raw) })?;
        guard.bind(raw)?;
        Ok(Self {
            session: self.session,
            raw,
        })
    }
    pub fn evaluate(
        self,
        path: Option<&str>,
        args: &[Argument<'_>],
    ) -> Result<Option<Value<'a>>, Error> {
        let guard = self.session.guard()?;
        let path = path
            .map(CString::new)
            .transpose()
            .map_err(|_| BAD_PARAMETER)?;
        let mut args = Arguments::new(args, self.session, 0)?;
        let mut result = RawBuffer {
            length: u64::MAX,
            pointer: ptr::null_mut(),
        };
        // SAFETY: arguments and all nested buffers are retained during evaluation.
        let status = unsafe {
            stela_acpi_evaluate(
                self.raw,
                path.as_ref().map_or(ptr::null(), |p| p.as_ptr()),
                args.objects.as_mut_ptr(),
                args.objects.len() as u32,
                &mut result,
            )
        };
        struct Free(*mut c_void);
        impl Drop for Free {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: ACPICA allocated this result buffer for the caller to free once.
                    unsafe { acpi_os_free(self.0) };
                }
            }
        }
        let _free = Free(result.pointer);
        checked(status)?;
        guard.check()?;
        if result.pointer.is_null() {
            return Ok(None);
        }
        let start = result.pointer as usize;
        let end = start
            .checked_add(usize::try_from(result.length).map_err(|_| LIMIT)?)
            .ok_or(LIMIT)?;
        // SAFETY: successful ACPICA result is an owned external-object allocation.
        unsafe {
            read_value(
                result.pointer.cast(),
                start,
                end,
                self.session,
                &guard,
                &mut 65536,
                0,
            )
            .map(Some)
        }
    }
    /// Evaluate the specification UCSI `_DSM` with an empty package Arg3.
    pub fn dsm(
        self,
        uuid: &[u8; 16],
        revision: u64,
        function: u64,
    ) -> Result<Option<Value<'a>>, Error> {
        self.evaluate(
            Some("_DSM"),
            &[
                Argument::Buffer(uuid),
                Argument::Integer(revision),
                Argument::Integer(function),
                Argument::Package(&[]),
            ],
        )
    }
    /// Install a true ACPICA device Notify callback. Callback work must be short,
    /// nonblocking and enqueue driver work; the provider supplies deferred dispatch.
    pub fn notify(
        self,
        callback: impl Fn(u32) + Send + Sync + 'static,
    ) -> Result<Notification<'a>, Error> {
        let guard = self.session.guard()?;
        let context = Box::new(NotifyContext {
            enabled: AtomicBool::new(true),
            callback: Box::new(callback),
        });
        let context = Box::into_raw(context);
        // SAFETY: owned stable context is retained until removal and drain.
        let status =
            unsafe { acpi_install_notify_handler(self.raw, 2, notify_trampoline, context.cast()) };
        if status != 0 {
            // SAFETY: installation failed, so this is the only reference to the box.
            unsafe {
                drop(Box::from_raw(context));
            }
            return Err(Error(status));
        }
        self.session.notifications.borrow_mut().push(context);
        if let Err(error) = guard.check() {
            // SAFETY: the context was just registered with this session, which keeps it.
            unsafe { &*context }.enabled.store(false, Ordering::Release);
            return Err(error);
        }
        Ok(Notification {
            handle: self,
            context: Some(context),
        })
    }
    /// Install an owned native region implementation (e.g. EmbeddedControl 3).
    ///
    /// # Safety
    /// Context/callbacks must remain valid until removal and event drain; implement
    /// ACPICA region setup/activation/deactivation, ownership and actual I/O. This
    /// never silently substitutes zeros for an unsupported EC/GPIO/serial region.
    pub unsafe fn install_region(
        self,
        space: u32,
        handler: Region,
        setup: RegionSetup,
        context: *mut c_void,
    ) -> Result<(), Error> {
        let guard = self.session.guard()?;
        // SAFETY: covered by this function's own safety contract.
        checked(unsafe {
            acpi_install_address_space_handler(self.raw, space, handler, setup, context)
        })?;
        guard.check()
    }
    /// # Safety
    /// Must match an installed handler and retain its context through this call;
    /// provider must synchronize external region callbacks before freeing context.
    pub unsafe fn remove_region(self, space: u32, handler: Region) -> Result<(), Error> {
        let guard = self.session.guard()?;
        // SAFETY: covered by this function's own safety contract.
        checked(unsafe { acpi_remove_address_space_handler(self.raw, space, handler) })?;
        // SAFETY: called from process context with no namespace lock held by this thread.
        unsafe { acpi_os_wait_events_complete() };
        guard.check()
    }
}
struct NotifyContext {
    enabled: AtomicBool,
    callback: Box<dyn Fn(u32) + Send + Sync>,
}
unsafe extern "C" fn notify_trampoline(_: *mut c_void, value: u32, context: *mut c_void) {
    // SAFETY: registration owns context through handler removal + draining.
    let context = unsafe { &*context.cast::<NotifyContext>() };
    // UNLOAD invalidates clients before deletion; context storage is still owned
    // through quiescence/core termination even when the node itself is gone.
    // SAFETY: ACPICA calls this trampoline only inside the live core.
    if context.enabled.load(Ordering::Acquire) && unsafe { stela_acpi_namespace_valid() != 0 } {
        (context.callback)(value);
    }
}
pub struct Notification<'a> {
    handle: Handle<'a>,
    context: Option<*mut NotifyContext>,
}
impl Notification<'_> {
    pub fn remove(mut self) -> Result<(), Error> {
        self.close()
    }
    // Test an actual ACPICA removal error after another native actor removed
    // the registration. The Rust owner deliberately remains outstanding.
    #[cfg(test)]
    pub(crate) fn remove_from_core_without_retiring_for_test(&self) -> Result<(), Error> {
        let guard = self.handle.session.guard()?;
        // SAFETY: the actual live node and callback belong to this registration.
        checked(unsafe { acpi_remove_notify_handler(self.handle.raw, 2, notify_trampoline) })?;
        // SAFETY: test process context; drain the real provider work queue.
        unsafe { acpi_os_wait_events_complete() };
        guard.check()
    }
    fn close(&mut self) -> Result<(), Error> {
        let Some(context) = self.context.take() else {
            return Ok(());
        };
        let result = (|| {
            let guard = self.handle.session.guard()?;
            // Only a live namespace lease may pass this node into ACPICA.
            // SAFETY: the namespace guard keeps this node live.
            checked(unsafe { acpi_remove_notify_handler(self.handle.raw, 2, notify_trampoline) })?;
            // SAFETY: called from process context with no namespace lock held by this thread.
            unsafe {
                acpi_os_wait_events_complete();
            }
            guard.check()
        })();
        if result.is_ok() {
            self.handle.session.release_notification(context);
        } else {
            // Keep callback storage in Session until successful global teardown;
            // neither stale removal nor an error may free a still registered box.
            // SAFETY: the session keeps every registered context until global teardown.
            unsafe { &*context }.enabled.store(false, Ordering::Release);
        }
        result
    }
}
impl Drop for Notification<'_> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

unsafe fn read_value<'a>(
    object: *const RawObject,
    start: usize,
    end: usize,
    session: &'a Session,
    guard: &NamespaceGuard<'_>,
    budget: &mut usize,
    depth: u32,
) -> Result<Value<'a>, Error> {
    if depth > 32 || *budget == 0 {
        return Err(LIMIT);
    }
    *budget -= 1;
    fn range(p: usize, bytes: usize, start: usize, end: usize) -> Result<(), Error> {
        if p < start || p.checked_add(bytes).is_none_or(|n| n > end) {
            Err(BAD_PARAMETER)
        } else {
            Ok(())
        }
    }
    range(object as usize, size_of::<RawObject>(), start, end)?;
    // ACPICA packs the external buffer; unaligned reads avoid platform assumptions.
    // SAFETY: `range` checked the object lies in the result buffer.
    let raw = unsafe { object.read_unaligned() };
    match raw.kind {
        0 => Ok(Value::Uninitialized),
        1 => Ok(Value::Integer(raw.payload)),
        2 | 3 => {
            let n = raw.length as usize;
            let bytes = if n == 0 {
                Vec::new()
            } else {
                range(raw.payload as usize, n, start, end)?;
                // SAFETY: `range` checked these bytes lie in the result buffer.
                unsafe { core::slice::from_raw_parts(raw.payload as *const u8, n) }.to_vec()
            };
            Ok(if raw.kind == 2 {
                Value::String(bytes)
            } else {
                Value::Buffer(bytes)
            })
        }
        4 => {
            let count = raw.length as usize;
            if count > *budget {
                return Err(LIMIT);
            }
            if count != 0 {
                range(
                    raw.payload as usize,
                    count.checked_mul(size_of::<RawObject>()).ok_or(LIMIT)?,
                    start,
                    end,
                )?;
            }
            let mut values = Vec::with_capacity(count);
            for n in 0..count {
                // SAFETY: `range` checked the whole element array lies in the result buffer.
                values.push(unsafe {
                    read_value(
                        (raw.payload as *const RawObject).add(n),
                        start,
                        end,
                        session,
                        guard,
                        budget,
                        depth + 1,
                    )
                }?);
            }
            Ok(Value::Package(values))
        }
        0x14 => {
            guard.bind(raw.payload as *mut c_void)?;
            Ok(Value::Reference(Reference {
                handle: Handle {
                    session,
                    raw: raw.payload as *mut c_void,
                },
                actual_type: ObjectType::from_raw(raw.length),
            }))
        }
        _ => Err(SUPPORT),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    mod references;
    include!("acpi/battery_tests.rs");
    include!("ec/native_tests.rs");
    include!("battery/native_tests.rs");
    include!("ec/binding_native_tests.rs");
    extern crate std;
    use super::*;
    use std::{
        alloc::{Layout, alloc, dealloc},
        collections::{BTreeMap, VecDeque},
        sync::{
            Arc, Mutex,
            atomic::{AtomicU32, AtomicU64, AtomicUsize},
        },
        time::{Duration, Instant},
    };

    pub(crate) static TEST_SERIAL: Mutex<()> = Mutex::new(());

    struct Semaphore {
        units: AtomicU32,
        max: u32,
    }
    #[derive(Default)]
    struct Counts {
        allocations: AtomicUsize,
        mappings: AtomicUsize,
        destroyed: AtomicBool,
        memory: AtomicU64,
        port_writes: AtomicUsize,
        ledger: Mutex<BTreeMap<usize, usize>>,
    }
    struct TestPlatform {
        tables: Vec<(u64, Vec<u8>)>,
        leases: Mutex<BTreeMap<(usize, u64), usize>>,
        work: Mutex<VecDeque<(Work, usize)>>,
        counts: Arc<Counts>,
        origin: Instant,
        quiescing: AtomicBool,
        fail_quiesce: AtomicBool,
    }
    unsafe fn platform<'a>(p: *mut c_void) -> &'a TestPlatform {
        unsafe { &*p.cast::<TestPlatform>() }
    }
    unsafe extern "C" fn allocate(p: *mut c_void, bytes: u64) -> *mut c_void {
        let Ok(bytes) = usize::try_from(bytes) else {
            return ptr::null_mut();
        };
        let Some(total) = bytes.checked_add(16) else {
            return ptr::null_mut();
        };
        let Ok(layout) = Layout::from_size_align(total, 16) else {
            return ptr::null_mut();
        };
        let raw = unsafe { alloc(layout) };
        if raw.is_null() {
            return ptr::null_mut();
        }
        unsafe {
            raw.cast::<usize>().write(total);
        }
        unsafe { platform(p) }
            .counts
            .allocations
            .fetch_add(1, Ordering::SeqCst);
        let result = unsafe { raw.add(16).cast() };
        unsafe { platform(p) }
            .counts
            .ledger
            .lock()
            .unwrap()
            .insert(result as usize, bytes);
        result
    }
    unsafe extern "C" fn free(p: *mut c_void, allocation: *mut c_void) {
        unsafe { platform(p) }
            .counts
            .ledger
            .lock()
            .unwrap()
            .remove(&(allocation as usize))
            .unwrap();
        let raw = unsafe { allocation.cast::<u8>().sub(16) };
        let total = unsafe { raw.cast::<usize>().read() };
        unsafe { dealloc(raw, Layout::from_size_align(total, 16).unwrap()) };
        unsafe { platform(p) }
            .counts
            .allocations
            .fetch_sub(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn map(p: *mut c_void, address: u64, length: u64) -> *mut c_void {
        let platform = unsafe { platform(p) };
        let Some(end) = address.checked_add(length) else {
            return ptr::null_mut();
        };
        let mapped = if address >= 0x9000 && end <= 0x9008 {
            unsafe {
                platform
                    .counts
                    .memory
                    .as_ptr()
                    .cast::<u8>()
                    .add((address - 0x9000) as usize)
            }
            .cast()
        } else {
            let Some((base, bytes)) = platform
                .tables
                .iter()
                .find(|(base, bytes)| *base <= address && end <= *base + bytes.len() as u64)
            else {
                return ptr::null_mut();
            };
            (unsafe { bytes.as_ptr().add((address - base) as usize) }) as *mut c_void
        };
        *platform
            .leases
            .lock()
            .unwrap()
            .entry((mapped as usize, length))
            .or_default() += 1;
        platform.counts.mappings.fetch_add(1, Ordering::SeqCst);
        mapped
    }
    unsafe extern "C" fn unmap(p: *mut c_void, pointer: *mut c_void, length: u64) {
        let platform = unsafe { platform(p) };
        let mut leases = platform.leases.lock().unwrap();
        let entry = leases
            .get_mut(&(pointer as usize, length))
            .expect("exact mapping lease");
        *entry -= 1;
        if *entry == 0 {
            leases.remove(&(pointer as usize, length));
        }
        platform.counts.mappings.fetch_sub(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn create_lock(_: *mut c_void, out: *mut *mut c_void) -> Status {
        unsafe { out.write(Box::into_raw(Box::new(AtomicBool::new(false))).cast()) };
        0
    }
    unsafe extern "C" fn delete_lock(_: *mut c_void, lock: *mut c_void) {
        unsafe {
            drop(Box::from_raw(lock.cast::<AtomicBool>()));
        }
    }
    unsafe extern "C" fn acquire_lock(_: *mut c_void, lock: *mut c_void) -> u64 {
        let lock = unsafe { &*lock.cast::<AtomicBool>() };
        while lock
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        0 // Hosted fixture has no hardware interrupts; never advertises SCI capability.
    }
    unsafe extern "C" fn release_lock(_: *mut c_void, lock: *mut c_void, flags: u64) {
        assert_eq!(flags, 0);
        unsafe { &*lock.cast::<AtomicBool>() }.store(false, Ordering::Release);
    }
    unsafe extern "C" fn create_semaphore(
        _: *mut c_void,
        max: u32,
        initial: u32,
        out: *mut *mut c_void,
    ) -> Status {
        if initial > max || max == 0 {
            return BAD_PARAMETER.0;
        }
        unsafe {
            out.write(
                Box::into_raw(Box::new(Semaphore {
                    units: AtomicU32::new(initial),
                    max,
                }))
                .cast(),
            )
        };
        0
    }
    unsafe extern "C" fn delete_semaphore(_: *mut c_void, s: *mut c_void) -> Status {
        unsafe {
            drop(Box::from_raw(s.cast::<Semaphore>()));
        }
        0
    }
    unsafe extern "C" fn wait_semaphore(
        _: *mut c_void,
        s: *mut c_void,
        units: u32,
        timeout: u16,
    ) -> Status {
        let s = unsafe { &*s.cast::<Semaphore>() };
        let start = Instant::now();
        if units == 0 || units > s.max {
            return BAD_PARAMETER.0;
        }
        loop {
            let current = s.units.load(Ordering::Acquire);
            if current >= units
                && s.units
                    .compare_exchange_weak(
                        current,
                        current - units,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            {
                return 0;
            }
            if timeout != u16::MAX && start.elapsed() >= Duration::from_millis(u64::from(timeout)) {
                return 0x11;
            }
            std::thread::yield_now();
        }
    }
    unsafe extern "C" fn signal_semaphore(_: *mut c_void, s: *mut c_void, units: u32) -> Status {
        let s = unsafe { &*s.cast::<Semaphore>() };
        let mut current = s.units.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(units).filter(|n| *n <= s.max) else {
                return LIMIT.0;
            };
            match s
                .units
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return 0,
                Err(n) => current = n,
            }
        }
    }
    unsafe extern "C" fn install_interrupt(
        _: *mut c_void,
        _: u32,
        _: Interrupt,
        _: *mut c_void,
    ) -> Status {
        SUPPORT.0
    }
    unsafe extern "C" fn remove_interrupt(_: *mut c_void, _: u32, _: Interrupt) -> Status {
        SUPPORT.0
    }
    unsafe extern "C" fn thread_id(_: *mut c_void) -> u64 {
        std::thread_local! { static ID: u64 = { static NEXT: AtomicUsize = AtomicUsize::new(1); NEXT.fetch_add(1,Ordering::Relaxed) as u64 }; }
        ID.with(|id| *id)
    }
    unsafe extern "C" fn execute(
        p: *mut c_void,
        _: u32,
        callback: Work,
        context: *mut c_void,
    ) -> Status {
        if unsafe { platform(p) }.quiescing.load(Ordering::Acquire) {
            return 6;
        }
        unsafe { platform(p) }
            .work
            .lock()
            .unwrap()
            .push_back((callback, context as usize));
        0
    }
    unsafe extern "C" fn drain_work(p: *mut c_void) {
        loop {
            let next = unsafe { platform(p) }.work.lock().unwrap().pop_front();
            let Some((callback, context)) = next else {
                return;
            };
            unsafe { callback(context as *mut c_void) };
        }
    }
    unsafe extern "C" fn sleep(_: *mut c_void, ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }
    unsafe extern "C" fn stall(_: *mut c_void, us: u32) {
        let start = Instant::now();
        while start.elapsed() < Duration::from_micros(us.into()) {
            core::hint::spin_loop();
        }
    }
    unsafe extern "C" fn read_port(_: *mut c_void, _: u64, _: *mut u32, _: u32) -> Status {
        SUPPORT.0
    }
    unsafe extern "C" fn write_port(p: *mut c_void, _: u64, _: u32, _: u32) -> Status {
        unsafe { platform(p) }
            .counts
            .port_writes
            .fetch_add(1, Ordering::SeqCst);
        SUPPORT.0
    }
    unsafe extern "C" fn read_memory(
        p: *mut c_void,
        address: u64,
        value: *mut u64,
        width: u32,
    ) -> Status {
        if address != 0x9000 || width != 32 {
            return SUPPORT.0;
        }
        unsafe { value.write(platform(p).counts.memory.load(Ordering::Acquire)) };
        0
    }
    unsafe extern "C" fn write_memory(
        p: *mut c_void,
        address: u64,
        value: u64,
        width: u32,
    ) -> Status {
        if address != 0x9000 || width != 32 {
            return SUPPORT.0;
        }
        unsafe { platform(p) }
            .counts
            .memory
            .store(value, Ordering::Release);
        0
    }
    unsafe extern "C" fn read_pci(
        _: *mut c_void,
        _: *mut PciId,
        _: u32,
        _: *mut u64,
        _: u32,
    ) -> Status {
        SUPPORT.0
    }
    unsafe extern "C" fn write_pci(
        _: *mut c_void,
        _: *mut PciId,
        _: u32,
        _: u64,
        _: u32,
    ) -> Status {
        SUPPORT.0
    }
    unsafe extern "C" fn timer(p: *mut c_void) -> u64 {
        unsafe { platform(p) }.origin.elapsed().as_nanos() as u64 / 100
    }
    unsafe extern "C" fn signal(_: *mut c_void, _: u32, _: *mut c_void) -> Status {
        SUPPORT.0
    }
    unsafe extern "C" fn log(_: *mut c_void, text: *const c_char, length: u64) {
        let bytes = unsafe { core::slice::from_raw_parts(text.cast::<u8>(), length as usize) };
        std::eprint!("{}", std::string::String::from_utf8_lossy(bytes));
    }
    unsafe extern "C" fn flush_cache(_: *mut c_void) {
        panic!("no hardware cache flush permitted by fixture");
    }
    unsafe extern "C" fn quiesce(p: *mut c_void) -> Status {
        if unsafe { platform(p) }.fail_quiesce.load(Ordering::Acquire) {
            return SUPPORT.0;
        }
        unsafe { platform(p) }
            .quiescing
            .store(true, Ordering::Release);
        unsafe { drain_work(p) };
        0
    }
    unsafe extern "C" fn destroy(p: *mut c_void) {
        let p = unsafe { Box::from_raw(p.cast::<TestPlatform>()) };
        p.counts.destroyed.store(true, Ordering::SeqCst);
    }

    unsafe extern "C" fn fatal(_: *mut c_void, status: Status) -> ! {
        std::eprintln!("native ACPI pre-delete quiescence fatal: {status:#x}");
        std::process::exit(86)
    }
    fn checksum(bytes: &mut [u8], offset: usize) {
        bytes[offset] = 0;
        bytes[offset] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)));
    }
    fn table(signature: &[u8; 4], length: usize, revision: u8) -> Vec<u8> {
        let mut bytes = vec![0; length];
        bytes[..4].copy_from_slice(signature);
        bytes[4..8].copy_from_slice(&(length as u32).to_le_bytes());
        bytes[8] = revision;
        bytes[10..16].copy_from_slice(b"STELA ");
        bytes[16..24].copy_from_slice(b"AMLTEST ");
        bytes
    }
    fn fixture() -> (Services, Arc<Counts>) {
        fixture_dsdt(include_bytes!("acpi/fixtures/namespace.aml").to_vec())
    }
    fn fixture_dsdt(dsdt: Vec<u8>) -> (Services, Arc<Counts>) {
        let counts = Arc::new(Counts::default());
        let mut rsdp = vec![0; 36];
        rsdp[..8].copy_from_slice(b"RSD PTR ");
        rsdp[9..15].copy_from_slice(b"STELA ");
        rsdp[15] = 2;
        rsdp[20..24].copy_from_slice(&36u32.to_le_bytes());
        rsdp[24..32].copy_from_slice(&0x2000u64.to_le_bytes());
        checksum(&mut rsdp[..20], 8);
        checksum(&mut rsdp, 32);
        let mut xsdt = table(b"XSDT", 44, 1);
        xsdt[36..44].copy_from_slice(&0x3000u64.to_le_bytes());
        checksum(&mut xsdt, 9);
        let mut fadt = table(b"FACP", 276, 6);
        fadt[56..60].copy_from_slice(&0x1000u32.to_le_bytes());
        fadt[64..68].copy_from_slice(&0x1004u32.to_le_bytes());
        fadt[88] = 4;
        fadt[89] = 2;
        fadt[46..48].copy_from_slice(&9u16.to_le_bytes());
        fadt[140..148].copy_from_slice(&0x4000u64.to_le_bytes());
        checksum(&mut fadt, 9);
        let context = Box::into_raw(Box::new(TestPlatform {
            tables: vec![
                (0x1000, rsdp),
                (0x2000, xsdt),
                (0x3000, fadt),
                (0x4000, dsdt),
            ],
            leases: Mutex::new(BTreeMap::new()),
            work: Mutex::new(VecDeque::new()),
            counts: counts.clone(),
            origin: Instant::now(),
            quiescing: AtomicBool::new(false),
            fail_quiesce: AtomicBool::new(false),
        }))
        .cast();
        (
            Services {
                context,
                root: 0x1000,
                capabilities: 0,
                allocate,
                free,
                map,
                unmap,
                create_lock,
                delete_lock,
                acquire_lock,
                release_lock,
                create_semaphore,
                delete_semaphore,
                wait_semaphore,
                signal_semaphore,
                install_interrupt,
                remove_interrupt,
                thread_id,
                execute,
                drain_work,
                sleep,
                stall,
                read_port,
                write_port,
                read_memory,
                write_memory,
                read_pci,
                write_pci,
                timer,
                signal,
                log,
                flush_cache,
                quiesce,
                destroy,
                fatal,
            },
            counts,
        )
    }

    /// Reuse the actual ACPICA fixture with a reduced-hardware FADT. Hardware
    /// mode then genuinely executes C activation and AML _INI without inventing
    /// legacy SCI/PM hardware. Extra AML methods are part of the real DSDT.
    pub(crate) fn reduced_hardware_fixture(extra_aml: &[u8]) -> Services {
        let mut dsdt = include_bytes!("acpi/fixtures/namespace.aml").to_vec();
        dsdt.extend_from_slice(extra_aml);
        let length = dsdt.len() as u32;
        dsdt[4..8].copy_from_slice(&length.to_le_bytes());
        checksum(&mut dsdt, 9);
        let (mut services, _) = fixture_dsdt(dsdt);
        // SAFETY: fixture owns this unpublished provider; ACPICA has not started.
        let provider = unsafe { &mut *services.context.cast::<TestPlatform>() };
        let fadt = &mut provider
            .tables
            .iter_mut()
            .find(|(p, _)| *p == 0x3000)
            .unwrap()
            .1;
        fadt[112..116].copy_from_slice(&(1u32 << 20).to_le_bytes());
        checksum(fadt, 9);
        services.capabilities = FULL_CAPABILITIES;
        services
    }

    #[test]
    fn failed_actual_hardware_activation_never_publishes_success_or_retries() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (mut provider, counts) = fixture();
        // The real legacy-hardware C path is entered; the existing provider
        // rejects actual legacy PM I/O. C has already marked its attempt, which
        // must never be interpreted as successful activation by Rust clients.
        provider.capabilities = FULL_CAPABILITIES;
        // SAFETY: actual test provider owns all services; singleton serialized.
        let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
        assert!(session.enable_hardware().is_err());
        assert!(!session.hardware_enabled());
        assert!(!session.root().hardware_active());
        let writes = counts.port_writes.load(Ordering::SeqCst);
        assert_eq!(session.enable_hardware(), Err(SUPPORT));
        assert_eq!(counts.port_writes.load(Ordering::SeqCst), writes);
        session.shutdown().unwrap();
        assert!(counts.destroyed.load(Ordering::SeqCst));
    }

    #[test]
    fn sleep_preparation_evaluates_s5_and_runs_pts() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let mut dsdt = include_bytes!("acpi/fixtures/namespace.aml").to_vec();
        // Name (PTSV, Zero)
        dsdt.extend_from_slice(&[0x08, b'P', b'T', b'S', b'V', 0x00]);
        // Name (_S5, Package () { 5, 7, Zero, Zero })
        dsdt.extend_from_slice(&[
            0x08, b'_', b'S', b'5', b'_', 0x12, 8, 4, 0x0a, 5, 0x0a, 7, 0, 0,
        ]);
        // Method (_PTS, 1) { Store (Arg0, PTSV) }
        dsdt.extend_from_slice(&[0x14, 12, b'_', b'P', b'T', b'S', 1, 0x70, 0x68]);
        dsdt.extend_from_slice(b"PTSV");
        let length = dsdt.len() as u32;
        dsdt[4..8].copy_from_slice(&length.to_le_bytes());
        checksum(&mut dsdt, 9);
        let (provider, counts) = fixture_dsdt(dsdt);
        // SAFETY: actual test provider owns all services; singleton serialized.
        let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
        let prepared = || {
            session
                .handle("\\PTSV")
                .unwrap()
                .evaluate(None, &[])
                .unwrap()
        };
        assert_eq!(session.sleep_types(5), Ok((5, 7)));
        assert_eq!(prepared(), Some(Value::Integer(0)));
        session.prepare_sleep(5).unwrap();
        assert_eq!(prepared(), Some(Value::Integer(5)));
        // No \_S3: AE_NOT_FOUND, and no _PTS for a state the firmware lacks.
        assert_eq!(session.sleep_types(3), Err(Error(0x0005)));
        assert_eq!(session.prepare_sleep(3), Err(Error(0x0005)));
        assert_eq!(prepared(), Some(Value::Integer(5)));
        assert_eq!(counts.port_writes.load(Ordering::SeqCst), 0);
        session.shutdown().unwrap();
    }

    #[test]
    fn successful_hardware_witness_is_revoked_by_actual_namespace_unload() {
        let _serial = TEST_SERIAL.lock().unwrap();
        // SAFETY: reduced-hardware provider enters actual C activation without
        // inventing legacy hardware; singleton serialized for this whole test.
        let session =
            unsafe { Session::start(reduced_hardware_fixture(&[]), Mode::Hardware) }.unwrap();
        assert!(session.hardware_enabled());
        let root = session.root();
        assert!(root.hardware_active());
        // A minimal SSDT: Scope (\_SB) { Device (DYN1) { Name (TEST, 42) } }.
        // Keep these actual table bytes alive until ACPICA terminates.
        let mut ssdt = table(b"SSDT", 36, 2);
        ssdt.extend_from_slice(&[0x10, 20, b'\\', b'_', b'S', b'B', b'_', 0x5b, 0x82, 12]);
        ssdt.extend_from_slice(b"DYN1");
        ssdt.push(0x08);
        ssdt.extend_from_slice(b"TEST");
        ssdt.extend_from_slice(&[0x0a, 42]);
        let length = ssdt.len() as u32;
        ssdt[4..8].copy_from_slice(&length.to_le_bytes());
        checksum(&mut ssdt, 9);
        unsafe extern "C" {
            fn acpi_load_table(table: *mut c_void, index: *mut u32) -> Status;
            fn acpi_unload_parent_table(handle: *mut c_void) -> Status;
        }
        let mut index = 0;
        // SAFETY: actual complete owned SSDT, retained through global teardown.
        assert_eq!(
            unsafe { acpi_load_table(ssdt.as_mut_ptr().cast(), &mut index) },
            0
        );
        let dynamic = session.handle("\\_SB.DYN1").unwrap();
        assert_eq!(
            dynamic.evaluate(Some("TEST"), &[]).unwrap(),
            Some(Value::Integer(42))
        );
        // SAFETY: supported native unload from process context; real provider
        // quiesces callbacks before C deletes the loaded SSDT namespace nodes.
        assert_eq!(unsafe { acpi_unload_parent_table(dynamic.raw) }, 0);
        assert!(!session.namespace_available());
        assert!(!session.hardware_enabled());
        assert!(!root.hardware_active());
        assert_eq!(session.enable_hardware(), Err(SUPPORT));
        session.shutdown().unwrap();
    }

    #[test]
    fn actual_acpica_abi_namespace_dsm_regions_failures_notify_and_cleanup() {
        let _serial = TEST_SERIAL.lock().unwrap();
        if std::env::var_os("STELA_ACPI_EC_LOCK_CHILD").is_some() {
            use super::super::ec::FirmwareLock;
            let (provider, counts) = fixture();
            let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
            let mut lock = session.ec_global_lock();
            lock.acquire(1_000).unwrap();
            drop(lock); // an unreleased owner must never permit core destruction
            assert_eq!(session.shutdown(), Err(SUPPORT));
            assert!(!counts.destroyed.load(Ordering::SeqCst));
            assert!(counts.allocations.load(Ordering::SeqCst) > 0);
            return;
        }
        if std::env::var_os("STELA_ACPI_QUARANTINE_CHILD").is_some() {
            unsafe extern "C" fn reject_quiescence(_: *mut c_void) -> Status {
                SUPPORT.0
            }
            let (mut provider, counts) = fixture();
            provider.quiesce = reject_quiescence;
            let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
            let observed = Arc::new(AtomicU32::new(0));
            let target = observed.clone();
            let handle = session.handle("\\_SB.UCSI").unwrap();
            let notification = handle
                .notify(move |value| {
                    target.store(value, Ordering::SeqCst);
                })
                .unwrap();
            handle
                .evaluate(Some("FIRE"), &[Argument::Integer(0x80)])
                .unwrap();
            core::mem::forget(notification); // retained callback tests quarantine, not normal removal
            assert_eq!(session.shutdown(), Err(SUPPORT));
            unsafe { (provider.drain_work)(provider.context) };
            assert_eq!(
                observed.load(Ordering::SeqCst),
                0x80,
                "quarantined callback remains alive"
            );
            assert!(!counts.destroyed.load(Ordering::SeqCst));
            assert!(counts.allocations.load(Ordering::SeqCst) > 0);
            assert!(counts.mappings.load(Ordering::SeqCst) > 0);
            let (other, other_counts) = fixture();
            assert!(matches!(
                unsafe { Session::start(other, Mode::InterpreterOnly) },
                Err(ALREADY_EXISTS)
            ));
            assert!(!other_counts.destroyed.load(Ordering::SeqCst));
            unsafe { (other.destroy)(other.context) }; // reservation rejection never transfers ownership
            return;
        }
        unsafe extern "C" {
            fn stela_acpi_global_acquire(lock: *mut u32) -> u8;
            fn stela_acpi_global_release(lock: *mut u32) -> u8;
        }
        let mut lock = 0x10u32;
        assert_eq!(unsafe { stela_acpi_global_acquire(&mut lock) }, 1);
        assert_eq!(lock, 0x12);
        assert_eq!(unsafe { stela_acpi_global_acquire(&mut lock) }, 0);
        assert_eq!(lock, 0x13);
        assert_eq!(unsafe { stela_acpi_global_release(&mut lock) }, 1);
        assert_eq!(lock, 0x10);
        assert_eq!(unsafe { stela_acpi_global_release(&mut lock) }, 0);
        assert_eq!(lock, 0x10);
        let expected = [
            size_of::<Services>(),
            size_of::<RawObject>(),
            size_of::<RawBuffer>(),
            size_of::<PciId>(),
            8,
            8,
            core::mem::offset_of!(Services, destroy),
            core::mem::offset_of!(RawBuffer, pointer),
            8,
            core::mem::offset_of!(Services, fatal),
            core::mem::offset_of!(RawObject, length),
            core::mem::offset_of!(RawObject, payload),
            size_of::<ObjectType>(),
        ];
        for (field, expected) in expected.into_iter().enumerate() {
            assert_eq!(
                unsafe { stela_acpi_layout(field as u32) },
                expected as u64,
                "ABI field {field}"
            );
        }
        // Actual partial initialization failures must reclaim the transferred provider.
        unsafe extern "C" fn reject_lock(_: *mut c_void, _: *mut *mut c_void) -> Status {
            4
        }
        let (mut provider, counts) = fixture();
        provider.create_lock = reject_lock;
        assert!(matches!(
            unsafe { Session::start(provider, Mode::InterpreterOnly) },
            Err(Error(4))
        ));
        assert!(counts.destroyed.load(Ordering::SeqCst));
        let (mut provider, counts) = fixture();
        provider.root = 0xdead;
        assert!(unsafe { Session::start(provider, Mode::InterpreterOnly) }.is_err());
        assert!(counts.destroyed.load(Ordering::SeqCst));
        assert_eq!(counts.allocations.load(Ordering::SeqCst), 0);
        assert_eq!(counts.mappings.load(Ordering::SeqCst), 0);
        // Real hardware activation must be rejected before touching SCI or mode regs.
        let (provider, counts) = fixture();
        assert!(matches!(
            unsafe { Session::start(provider, Mode::Hardware) },
            Err(SUPPORT)
        ));
        assert!(counts.destroyed.load(Ordering::SeqCst));
        assert_eq!(counts.port_writes.load(Ordering::SeqCst), 0);
        let (provider, counts) = fixture();
        let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
        assert!(!session.hardware_enabled());
        assert!(!session.root().hardware_active());
        assert_eq!(session.enable_hardware(), Err(SUPPORT));
        assert!(!session.hardware_enabled());
        assert_eq!(session.enable_hardware(), Err(SUPPORT));
        assert!(!session.root().hardware_active());
        assert_eq!(counts.port_writes.load(Ordering::SeqCst), 0);
        assert_eq!(session.devices("PNP0CA0").unwrap().len(), 1);
        assert_eq!(session.devices("STLA0002").unwrap().len(), 1);
        assert!(session.devices("NONE0001").unwrap().is_empty());
        {
            use super::super::ec::FirmwareLock;
            let mut lock = session.ec_global_lock();
            assert!(lock.acquire(0).is_err());
            assert!(lock.acquire(u64::from(u16::MAX) * 1_000).is_err());
            lock.acquire(1_000).unwrap();
            assert!(lock.acquire(1_000).is_err());
            lock.release().unwrap();
            assert!(lock.release().is_err());
            lock.acquire(1_000).unwrap();
            lock.release().unwrap();
        }
        let ucsi = session.handle("\\_SB.UCSI").unwrap();
        assert_eq!(ucsi.path().unwrap(), "\\_SB_.UCSI");
        assert_eq!(
            ucsi.evaluate(Some("INIC"), &[]).unwrap(),
            Some(Value::Integer(0)),
            "interpreter-only mode must not run firmware _INI"
        );
        assert_eq!(
            ucsi.evaluate(Some("_STA"), &[]).unwrap(),
            Some(Value::Integer(15))
        );
        assert_eq!(
            ucsi.evaluate(Some("BARD"), &[]),
            Err(Error(4)),
            "unmapped AML memory must not return fabricated data"
        );
        assert!(
            ucsi.evaluate(Some("ECRD"), &[]).is_err(),
            "EC cannot work before a real handler is installed"
        );
        unsafe extern "C" fn region_setup(
            _: *mut c_void,
            action: u32,
            context: *mut c_void,
            out: *mut *mut c_void,
        ) -> Status {
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
            _: *mut c_void,
            context: *mut c_void,
        ) -> Status {
            if function != 0 || address != 0 || width != 8 || context.is_null() {
                return SUPPORT.0;
            }
            unsafe { value.write(0xab) };
            0
        }
        let region_context = Box::into_raw(Box::new(1u8)).cast();
        unsafe {
            session
                .root()
                .install_region(3, region, region_setup, region_context)
        }
        .unwrap();
        assert_eq!(
            ucsi.evaluate(Some("ECRD"), &[]).unwrap(),
            Some(Value::Integer(0xab))
        );
        unsafe { session.root().remove_region(3, region) }.unwrap();
        unsafe {
            drop(Box::from_raw(region_context.cast::<u8>()));
        }
        let deps = ucsi.evaluate(Some("_DEP"), &[]).unwrap().unwrap();
        assert_eq!(
            deps,
            Value::Package(vec![Value::Reference(Reference {
                handle: session.handle("\\_SB.EC00").unwrap(),
                actual_type: ObjectType::DEVICE,
            })])
        );
        let crs = ucsi.evaluate(Some("_CRS"), &[]).unwrap().unwrap();
        assert!(
            matches!(crs,Value::Buffer(ref bytes) if bytes[0]==0x86 && bytes[4..8]==0x9000u32.to_le_bytes() && bytes[8..12]==0x210u32.to_le_bytes())
        );
        let uuid = [
            0xc2, 0x98, 0x83, 0x6f, 0xa4, 0x7c, 0xe4, 0x11, 0xad, 0x36, 0x63, 0x10, 0x42, 0xb5,
            0x00, 0x8f,
        ];
        assert_eq!(ucsi.dsm(&uuid, 1, 0).unwrap(), Some(Value::Buffer(vec![7])));
        assert_eq!(ucsi.dsm(&uuid, 1, 1).unwrap(), Some(Value::Integer(1)));
        assert_eq!(counts.memory.load(Ordering::SeqCst), 0x11223344);
        assert_eq!(
            ucsi.dsm(&uuid, 1, 2).unwrap(),
            Some(Value::Integer(0x11223344))
        );
        assert_eq!(
            ucsi.dsm(&[0; 16], 1, 0).unwrap(),
            Some(Value::Buffer(vec![0]))
        );
        assert_eq!(
            ucsi.evaluate(Some("FAIL"), &[Argument::Integer(0)]),
            Err(Error(0x300c))
        );
        assert_eq!(
            ucsi.evaluate(Some("FAIL"), &[Argument::Integer(1)])
                .unwrap(),
            Some(Value::Integer(1))
        );
        assert!(ucsi.evaluate(Some("MISSING"), &[]).is_err());
        assert_eq!(
            ucsi.evaluate(Some("PACK"), &[]).unwrap(),
            Some(Value::Package(vec![
                Value::Integer(42),
                Value::String(b"firmware".to_vec()),
                Value::Buffer(vec![1, 2, 3]),
                Value::Package(vec![Value::Integer(7), Value::Integer(8)])
            ]))
        );
        let notified = Arc::new(AtomicU32::new(0));
        let target = notified.clone();
        let notification = ucsi
            .notify(move |value| {
                target.store(value, Ordering::SeqCst);
            })
            .unwrap();
        assert_eq!(
            ucsi.evaluate(Some("FIRE"), &[Argument::Integer(0x80)])
                .unwrap(),
            None
        );
        ucsi.evaluate(Some("FIRE"), &[Argument::Integer(0x81)])
            .unwrap();
        assert_eq!(
            notified.load(Ordering::SeqCst),
            0,
            "Notify must actually be deferred"
        );
        unsafe { acpi_os_wait_events_complete() };
        assert_eq!(
            notified.load(Ordering::SeqCst),
            0x81,
            "Notify dispatch preserves FIFO order"
        );
        notification.remove().unwrap();
        ucsi.evaluate(Some("FIRE"), &[Argument::Integer(0x80)])
            .unwrap();
        unsafe { acpi_os_wait_events_complete() };
        session.shutdown().unwrap();
        assert!(counts.destroyed.load(Ordering::SeqCst));
        assert_eq!(counts.allocations.load(Ordering::SeqCst), 0);
        assert_eq!(counts.mappings.load(Ordering::SeqCst), 0);
        let status=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","platform::acpi::tests::actual_acpica_abi_namespace_dsm_regions_failures_notify_and_cleanup"]).env("STELA_ACPI_QUARANTINE_CHILD","1").status().unwrap();
        assert!(
            status.success(),
            "failed quiescence must retain all callback-owned state"
        );
        let lock_child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "platform::acpi::tests::actual_acpica_abi_namespace_dsm_regions_failures_notify_and_cleanup"])
            .env("STELA_ACPI_EC_LOCK_CHILD", "1").status().unwrap();
        assert!(
            lock_child.success(),
            "unreleased EC firmware owner must quarantine ACPICA"
        );
        // Reopening proves successful cleanup releases the singleton reservation.
        let (provider, counts) = fixture();
        unsafe { Session::start(provider, Mode::InterpreterOnly) }
            .unwrap()
            .shutdown()
            .unwrap();
        assert!(counts.destroyed.load(Ordering::SeqCst));
    }

    #[test]
    fn native_table_unload_invalidates_handles_references_and_notifications() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (provider, counts) =
            fixture_dsdt(include_bytes!("acpi/fixtures/dynamic-host.aml").to_vec());
        let fatal_child = std::env::var_os("STELA_ACPI_UNLOAD_FATAL_CHILD").is_some();
        let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
        assert!(matches!(
            session.root().evaluate(
                Some("LDTB"),
                &[Argument::Buffer(include_bytes!(
                    "acpi/fixtures/dynamic.aml"
                ))]
            ),
            Ok(Some(Value::Integer(1)))
        ));
        let device = session.handle("\\_SB.DYN0").unwrap();
        assert!(matches!(
            device.evaluate(Some("TEST"), &[]),
            Ok(Some(Value::Integer(0x1234)))
        ));
        let reference = device.evaluate(Some("REFR"), &[]).unwrap().unwrap();
        let Value::Package(mut references) = reference else {
            panic!("actual AML package must retain its namespace name reference")
        };
        let Value::Reference(reference) = references.pop().unwrap() else {
            panic!("package name must return a namespace reference")
        };
        assert_eq!(reference.handle.path().unwrap(), device.path().unwrap());
        assert_eq!(reference.actual_type, ObjectType::DEVICE);
        // Current ACPICA Load/LoadTable return integers, not old DDB handles.
        // Real AML Unload rejects these inputs; do not invent an operable handle
        // or claim those unsupported operations exercised native deletion.
        for method in ["SELF", "NEST"] {
            assert_eq!(
                device.evaluate(Some(method), &[]).err(),
                Some(Error(0x3003))
            );
            assert!(session.namespace_available());
            assert!(matches!(
                device.evaluate(Some("TEST"), &[]),
                Ok(Some(Value::Integer(0x1234)))
            ));
        }
        let observed = Arc::new(AtomicU32::new(0));
        let target = observed.clone();
        let notification = device
            .notify(move |value| {
                target.store(value, Ordering::SeqCst);
            })
            .unwrap();
        device
            .evaluate(Some("FIRE"), &[Argument::Integer(0x80)])
            .unwrap();
        if fatal_child {
            // Swap only the actual provider callback used inside C's immutable
            // transferred vtable through a fixture flag; no production bypass.
            unsafe { platform(provider.context) }
                .fail_quiesce
                .store(true, Ordering::Release);
        }
        unsafe extern "C" {
            fn acpi_unload_parent_table(handle: *mut c_void) -> Status;
        }
        // SAFETY: actual loaded SSDT node, interpreter idle on this owner thread;
        // the provider drains all other callbacks before real namespace deletion.
        // This uses ACPICA's supported native table API, not a fabricated AML DDB.
        assert_eq!(unsafe { acpi_unload_parent_table(device.raw) }, 0);
        assert!(!session.namespace_available());
        // Force ACPICA's node caches back to the sanitizer allocator. Stale raw
        // dereferences now read freed storage rather than merely recycled nodes.
        unsafe extern "C" {
            fn acpi_purge_cached_objects() -> Status;
        }
        assert_eq!(unsafe { acpi_purge_cached_objects() }, 0);
        assert_eq!(device.path(), Err(SUPPORT));
        assert_eq!(device.child("TEST").err(), Some(SUPPORT));
        assert_eq!(device.evaluate(Some("TEST"), &[]).err(), Some(SUPPORT));
        assert_eq!(reference.handle.path(), Err(SUPPORT));
        assert_eq!(device.dsm(&[0; 16], 1, 1).err(), Some(SUPPORT));
        assert_eq!(device.notify(|_| {}).err(), Some(SUPPORT));
        assert_eq!(session.devices("STLA0003").err(), Some(SUPPORT));
        assert_eq!(notification.remove(), Err(SUPPORT));
        assert_eq!(
            observed.load(Ordering::SeqCst),
            0,
            "invalid clients are not called during pre-delete drain"
        );
        assert_eq!(
            Arc::strong_count(&observed),
            2,
            "stale removal retains callback until termination"
        );
        // Raw oracle calls are deliberately test-only: prove the real native
        // table API deleted the node. Unsupported AML did not execute its Store.
        let mut gone = ptr::null_mut();
        let name = CString::new("\\_SB.DYN0").unwrap();
        assert_ne!(
            unsafe { acpi_get_handle(usize::MAX as *mut c_void, name.as_ptr(), &mut gone) },
            0
        );
        let name = CString::new("\\UNLD").unwrap();
        let mut result = RawBuffer {
            length: u64::MAX,
            pointer: ptr::null_mut(),
        };
        assert_eq!(
            unsafe {
                stela_acpi_evaluate(
                    usize::MAX as *mut c_void,
                    name.as_ptr(),
                    ptr::null_mut(),
                    0,
                    &mut result,
                )
            },
            0
        );
        let raw = unsafe { result.pointer.cast::<RawObject>().read_unaligned() };
        assert_eq!((raw.kind, raw.payload), (1, 0));
        unsafe { acpi_os_free(result.pointer) };
        session.shutdown().unwrap();
        assert_eq!(Arc::strong_count(&observed), 1);
        assert!(counts.destroyed.load(Ordering::SeqCst));
        assert_eq!(counts.allocations.load(Ordering::SeqCst), 0);
        assert_eq!(counts.mappings.load(Ordering::SeqCst), 0);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "platform::acpi::tests::native_table_unload_invalidates_handles_references_and_notifications", "--nocapture"])
            .env("STELA_ACPI_UNLOAD_FATAL_CHILD", "1").status().unwrap();
        assert_eq!(
            status.code(),
            Some(86),
            "pre-delete quiescence failure must not return to namespace deletion"
        );
    }

    /// Actual captured QEMU/firmware inputs remain ignored; this generic evaluator
    /// records their hash and real method results without production path exceptions.
    #[test]
    #[ignore = "requires STELA_ACPI_DSDT, optional STELA_ACPI_METHOD and STELA_ACPI_QUERIES"]
    fn evaluate_captured_firmware_with_real_acpica() {
        let _serial = TEST_SERIAL.lock().unwrap();
        use sha2::{Digest, Sha256};
        let path = std::env::var("STELA_ACPI_DSDT").expect("captured ignored DSDT path");
        let dsdt = std::fs::read(path).unwrap();
        assert!(dsdt.len() >= 36 && dsdt.len() <= 16 * 1024 * 1024);
        assert_eq!(&dsdt[..4], b"DSDT");
        assert_eq!(
            u32::from_le_bytes(dsdt[4..8].try_into().unwrap()) as usize,
            dsdt.len()
        );
        assert_eq!(dsdt.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)), 0);
        std::println!(
            "DSDT sha256={:x} bytes={}",
            Sha256::digest(&dsdt),
            dsdt.len()
        );
        let (provider, counts) = fixture_dsdt(dsdt);
        let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
        if let Ok(method) = std::env::var("STELA_ACPI_METHOD") {
            let value = std::env::var("STELA_ACPI_INTEGER")
                .unwrap_or_else(|_| "1".into())
                .parse::<u64>()
                .unwrap();
            let result = session
                .handle(&method)
                .unwrap()
                .evaluate(None, &[Argument::Integer(value)])
                .unwrap();
            std::println!("{method}({value}) => {result:?}");
        }
        fn describe(value: &Value<'_>) -> std::string::String {
            match value {
                Value::Reference(reference) => std::format!(
                    "Reference({},{:?})",
                    reference.handle.path().unwrap(),
                    reference.actual_type
                ),
                Value::Package(items) => std::format!(
                    "Package[{}]",
                    items.iter().map(describe).collect::<Vec<_>>().join(", ")
                ),
                other => std::format!("{other:?}"),
            }
        }
        for query in std::env::var("STELA_ACPI_QUERIES")
            .expect("comma-separated actual method/resource paths")
            .split(',')
        {
            let result = session.handle(query).unwrap().evaluate(None, &[]).unwrap();
            std::println!(
                "{query} => {}",
                result
                    .as_ref()
                    .map(describe)
                    .unwrap_or_else(|| "NoResult".into())
            );
        }
        session.shutdown().unwrap();
        assert!(counts.destroyed.load(Ordering::SeqCst));
        assert_eq!(counts.allocations.load(Ordering::SeqCst), 0);
        assert_eq!(counts.mappings.load(Ordering::SeqCst), 0);
    }
}

//! The owner of a Linux environment: the table of `stela_linux_services` Linux
//! code calls back through (`compat/linux/stela/linux.h`), over a [`Platform`].
//!
//! This is the whole boundary. A platform answers in Rust types and negative
//! errnos; the table's trampolines are the only code here that sees the C ABI,
//! and nothing else in this crate needs to know how a service reaches hardware.
use alloc::boxed::Box;
use core::{
    ffi::{CStr, c_char, c_int, c_uint, c_void},
    pin::Pin,
    ptr, slice,
};

/// A negative Linux errno.
pub type Errno = i32;

/// What Linux code needs of the machine it runs on. Each method's contract is
/// its entry in `stela_linux_services`.
pub trait Platform {
    /// Monotonic nanoseconds.
    fn now_ns(&self) -> i64;
    /// Wait at least `minimum` and preferably at most `maximum` microseconds.
    /// An `atomic` wait must not sleep.
    fn delay_us(&self, minimum: u64, maximum: u64, atomic: bool);
    /// A firmware image by Linux's name, stable until the owner exits.
    fn firmware(&self, name: &CStr) -> Result<&[u8], Errno>;
    /// One formatted kernel message at its printk level.
    fn log(&self, level: i32, message: &CStr);
    /// A `WARN` that fired, with its condition when Linux records one.
    fn warn(&self, file: &CStr, line: i32, condition: Option<&CStr>);
    /// An operation Stela does not provide; the caller continues degraded.
    fn unsupported(&self, operation: &CStr);
    /// Bytes from an already seeded generator. Must not sleep or allocate.
    fn random_bytes(&self, bytes: &mut [u8]);
    /// Start a task running `stela_linux_workers_run`, never inline.
    fn start_worker(&self) -> Result<(), Errno>;
    /// Power the machine off.
    fn shutdown(&self, force: bool);
    /// Map page-aligned device memory uncached.
    fn map_device(&self, physical: u64, size: usize) -> Option<*mut c_void>;
    /// # Safety
    /// `address` came from [`Self::map_device`] and nothing uses it any more.
    unsafe fn unmap_device(&self, address: *mut c_void);
    /// Map `physical` pages contiguously, write-back.
    fn map_pages(&self, physical: &[u64]) -> Option<*mut c_void>;
    /// # Safety
    /// `address` came from [`Self::map_pages`] for `count` pages and nothing
    /// uses it any more.
    unsafe fn unmap_pages(&self, address: *mut c_void, count: usize);
    /// Route `irq` to the service, which calls `stela_linux_irq_run`.
    fn irq_enable(&self, irq: u32) -> Result<(), Errno>;
    /// Mask `irq`, returning once no new firing can reach the service.
    fn irq_disable(&self, irq: u32);
    /// # Safety
    /// `to` is writable for `size` bytes; `from` is an address in the running
    /// client. Returns the bytes left uncopied at a fault.
    unsafe fn copy_from_user(&self, to: *mut u8, from: *const u8, size: usize) -> usize;
    /// # Safety
    /// `from` is readable for `size` bytes; `to` is an address in the running
    /// client. Returns the bytes left uncopied at a fault.
    unsafe fn copy_to_user(&self, to: *mut u8, from: *const u8, size: usize) -> usize;
    /// Install one page in client `space`. `prot` holds x86 page table bits.
    fn map_user(&self, space: *mut c_void, address: u64, pfn: u64, prot: u64) -> Result<(), Errno>;
    /// Remove a client's pages.
    fn unmap_user(&self, space: *mut c_void, address: u64, size: usize);
}

/// `struct stela_linux_services`, in that header's order.
#[repr(C)]
struct Services {
    now_ns: unsafe extern "C" fn(*mut c_void) -> i64,
    delay_us: unsafe extern "C" fn(*mut c_void, u64, u64, bool),
    firmware: unsafe extern "C" fn(*mut c_void, *const c_char, *mut *const u8, *mut usize) -> c_int,
    log: unsafe extern "C" fn(*mut c_void, c_int, *const c_char),
    warn: unsafe extern "C" fn(*mut c_void, *const c_char, c_int, *const c_char),
    unsupported: unsafe extern "C" fn(*mut c_void, *const c_char),
    random_bytes: unsafe extern "C" fn(*mut c_void, *mut c_void, usize),
    start_worker: unsafe extern "C" fn(*mut c_void) -> c_int,
    shutdown: unsafe extern "C" fn(*mut c_void, bool),
    map_device: unsafe extern "C" fn(*mut c_void, u64, usize) -> *mut c_void,
    unmap_device: unsafe extern "C" fn(*mut c_void, *mut c_void),
    map_pages: unsafe extern "C" fn(*mut c_void, *const u64, usize) -> *mut c_void,
    unmap_pages: unsafe extern "C" fn(*mut c_void, *mut c_void, usize),
    irq_enable: unsafe extern "C" fn(*mut c_void, c_uint) -> c_int,
    irq_disable: unsafe extern "C" fn(*mut c_void, c_uint),
    copy_from_user: unsafe extern "C" fn(*mut c_void, *mut c_void, *const c_void, u64) -> u64,
    copy_to_user: unsafe extern "C" fn(*mut c_void, *mut c_void, *const c_void, u64) -> u64,
    map_user: unsafe extern "C" fn(*mut c_void, *mut c_void, u64, u64, u64) -> c_int,
    unmap_user: unsafe extern "C" fn(*mut c_void, *mut c_void, u64, usize),
}

const _: () = assert!(size_of::<Services>() == 152);

/// `struct stela_linux_owner`.
#[repr(C)]
pub struct RawOwner {
    services: *const Services,
    context: *mut c_void,
}

const _: () = assert!(size_of::<RawOwner>() == 16);

/// # Safety
/// `context` is the `P` an [`Owner`] gave Linux, alive while Linux runs.
unsafe fn platform<'a, P: Platform>(context: *mut c_void) -> &'a P {
    // SAFETY: the caller's contract.
    unsafe { &*context.cast::<P>() }
}

/// # Safety
/// `text` is Linux's, NUL-terminated and live for the call.
unsafe fn text<'a>(text: *const c_char) -> &'a CStr {
    // SAFETY: the caller's contract.
    unsafe { CStr::from_ptr(text) }
}

fn status(result: Result<(), Errno>) -> c_int {
    result.err().unwrap_or(0)
}

/// The trampolines' safety is that of the table: Linux calls each with the
/// context [`Owner::new`] gave it and the arguments `linux.h` documents.
mod trampolines {
    use super::*;

    pub unsafe extern "C" fn now_ns<P: Platform>(context: *mut c_void) -> i64 {
        // SAFETY: see the module.
        unsafe { platform::<P>(context) }.now_ns()
    }

    pub unsafe extern "C" fn delay_us<P: Platform>(
        context: *mut c_void,
        minimum: u64,
        maximum: u64,
        atomic: bool,
    ) {
        // SAFETY: see the module.
        unsafe { platform::<P>(context) }.delay_us(minimum, maximum, atomic);
    }

    pub unsafe extern "C" fn firmware<P: Platform>(
        context: *mut c_void,
        name: *const c_char,
        data: *mut *const u8,
        size: *mut usize,
    ) -> c_int {
        // SAFETY: see the module.
        match unsafe { platform::<P>(context).firmware(text(name)) } {
            Ok(image) => {
                // SAFETY: both are the caller's writable out-parameters.
                unsafe {
                    data.write(image.as_ptr());
                    size.write(image.len());
                }
                0
            }
            Err(errno) => errno,
        }
    }

    pub unsafe extern "C" fn log<P: Platform>(
        context: *mut c_void,
        level: c_int,
        message: *const c_char,
    ) {
        // SAFETY: see the module.
        unsafe { platform::<P>(context).log(level, text(message)) };
    }

    pub unsafe extern "C" fn warn<P: Platform>(
        context: *mut c_void,
        file: *const c_char,
        line: c_int,
        condition: *const c_char,
    ) {
        // SAFETY: see the module; a condition is optional.
        unsafe {
            let condition = (!condition.is_null()).then(|| text(condition));
            platform::<P>(context).warn(text(file), line, condition);
        }
    }

    pub unsafe extern "C" fn unsupported<P: Platform>(
        context: *mut c_void,
        operation: *const c_char,
    ) {
        // SAFETY: see the module.
        unsafe { platform::<P>(context).unsupported(text(operation)) };
    }

    pub unsafe extern "C" fn random_bytes<P: Platform>(
        context: *mut c_void,
        bytes: *mut c_void,
        size: usize,
    ) {
        // SAFETY: see the module; `bytes` is writable for `size`.
        unsafe {
            platform::<P>(context).random_bytes(slice::from_raw_parts_mut(bytes.cast(), size));
        }
    }

    pub unsafe extern "C" fn start_worker<P: Platform>(context: *mut c_void) -> c_int {
        // SAFETY: see the module.
        status(unsafe { platform::<P>(context) }.start_worker())
    }

    pub unsafe extern "C" fn shutdown<P: Platform>(context: *mut c_void, force: bool) {
        // SAFETY: see the module.
        unsafe { platform::<P>(context) }.shutdown(force);
    }

    pub unsafe extern "C" fn map_device<P: Platform>(
        context: *mut c_void,
        physical: u64,
        size: usize,
    ) -> *mut c_void {
        // SAFETY: see the module.
        unsafe { platform::<P>(context) }
            .map_device(physical, size)
            .unwrap_or(ptr::null_mut())
    }

    pub unsafe extern "C" fn unmap_device<P: Platform>(context: *mut c_void, address: *mut c_void) {
        // SAFETY: see the module; Linux passes what map_device returned.
        unsafe { platform::<P>(context).unmap_device(address) };
    }

    pub unsafe extern "C" fn map_pages<P: Platform>(
        context: *mut c_void,
        physical: *const u64,
        count: usize,
    ) -> *mut c_void {
        // SAFETY: see the module; `physical` holds `count` addresses.
        unsafe {
            platform::<P>(context)
                .map_pages(slice::from_raw_parts(physical, count))
                .unwrap_or(ptr::null_mut())
        }
    }

    pub unsafe extern "C" fn unmap_pages<P: Platform>(
        context: *mut c_void,
        address: *mut c_void,
        count: usize,
    ) {
        // SAFETY: see the module; Linux passes what map_pages returned.
        unsafe { platform::<P>(context).unmap_pages(address, count) };
    }

    pub unsafe extern "C" fn irq_enable<P: Platform>(context: *mut c_void, irq: c_uint) -> c_int {
        // SAFETY: see the module.
        status(unsafe { platform::<P>(context) }.irq_enable(irq))
    }

    pub unsafe extern "C" fn irq_disable<P: Platform>(context: *mut c_void, irq: c_uint) {
        // SAFETY: see the module.
        unsafe { platform::<P>(context) }.irq_disable(irq);
    }

    pub unsafe extern "C" fn copy_from_user<P: Platform>(
        context: *mut c_void,
        to: *mut c_void,
        from: *const c_void,
        size: u64,
    ) -> u64 {
        // SAFETY: see the module.
        let left =
            unsafe { platform::<P>(context).copy_from_user(to.cast(), from.cast(), size as usize) };
        left as u64
    }

    pub unsafe extern "C" fn copy_to_user<P: Platform>(
        context: *mut c_void,
        to: *mut c_void,
        from: *const c_void,
        size: u64,
    ) -> u64 {
        // SAFETY: see the module.
        let left =
            unsafe { platform::<P>(context).copy_to_user(to.cast(), from.cast(), size as usize) };
        left as u64
    }

    pub unsafe extern "C" fn map_user<P: Platform>(
        context: *mut c_void,
        space: *mut c_void,
        address: u64,
        pfn: u64,
        prot: u64,
    ) -> c_int {
        // SAFETY: see the module.
        status(unsafe { platform::<P>(context) }.map_user(space, address, pfn, prot))
    }

    pub unsafe extern "C" fn unmap_user<P: Platform>(
        context: *mut c_void,
        space: *mut c_void,
        address: u64,
        size: usize,
    ) {
        // SAFETY: see the module.
        unsafe { platform::<P>(context) }.unmap_user(space, address, size);
    }
}

/// A platform and the table Linux reaches it through. Pinned, because Linux
/// keeps the addresses of both.
pub struct Owner<P: Platform> {
    services: Services,
    raw: RawOwner,
    platform: P,
    _pin: core::marker::PhantomPinned,
}

impl<P: Platform> Owner<P> {
    pub fn new(platform: P) -> Pin<Box<Self>> {
        use trampolines as t;
        let mut owner = Box::new(Self {
            services: Services {
                now_ns: t::now_ns::<P>,
                delay_us: t::delay_us::<P>,
                firmware: t::firmware::<P>,
                log: t::log::<P>,
                warn: t::warn::<P>,
                unsupported: t::unsupported::<P>,
                random_bytes: t::random_bytes::<P>,
                start_worker: t::start_worker::<P>,
                shutdown: t::shutdown::<P>,
                map_device: t::map_device::<P>,
                unmap_device: t::unmap_device::<P>,
                map_pages: t::map_pages::<P>,
                unmap_pages: t::unmap_pages::<P>,
                irq_enable: t::irq_enable::<P>,
                irq_disable: t::irq_disable::<P>,
                copy_from_user: t::copy_from_user::<P>,
                copy_to_user: t::copy_to_user::<P>,
                map_user: t::map_user::<P>,
                unmap_user: t::unmap_user::<P>,
            },
            raw: RawOwner {
                services: ptr::null(),
                context: ptr::null_mut(),
            },
            platform,
            _pin: core::marker::PhantomPinned,
        });
        owner.raw.services = &raw const owner.services;
        owner.raw.context = (&raw mut owner.platform).cast();
        Box::into_pin(owner)
    }

    /// What `stela_linux_enter` takes.
    pub fn raw(&self) -> *const RawOwner {
        &raw const self.raw
    }

    pub fn platform(&self) -> &P {
        &self.platform
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::{Cell, RefCell};
    use std::{string::String, vec::Vec};
    extern crate std;

    const ENOENT: Errno = -2;
    static IMAGE: [u8; 3] = [1, 2, 3];

    #[derive(Default)]
    struct Fake {
        events: RefCell<Vec<String>>,
        workers: Cell<u32>,
    }

    impl Fake {
        fn note(&self, event: String) {
            self.events.borrow_mut().push(event);
        }
    }

    impl Platform for Fake {
        fn now_ns(&self) -> i64 {
            42
        }
        fn delay_us(&self, minimum: u64, maximum: u64, atomic: bool) {
            self.note(std::format!("delay {minimum} {maximum} {atomic}"));
        }
        fn firmware(&self, name: &CStr) -> Result<&[u8], Errno> {
            if name == c"nvidia/gsp.bin" {
                Ok(&IMAGE)
            } else {
                Err(ENOENT)
            }
        }
        fn log(&self, level: i32, message: &CStr) {
            self.note(std::format!("log {level} {}", message.to_str().unwrap()));
        }
        fn warn(&self, file: &CStr, line: i32, condition: Option<&CStr>) {
            self.note(std::format!("warn {file:?} {line} {condition:?}"));
        }
        fn unsupported(&self, operation: &CStr) {
            self.note(std::format!("unsupported {operation:?}"));
        }
        fn random_bytes(&self, bytes: &mut [u8]) {
            bytes.fill(7);
        }
        fn start_worker(&self) -> Result<(), Errno> {
            self.workers.set(self.workers.get() + 1);
            if self.workers.get() > 1 {
                Err(-11)
            } else {
                Ok(())
            }
        }
        fn shutdown(&self, force: bool) {
            self.note(std::format!("shutdown {force}"));
        }
        fn map_device(&self, physical: u64, size: usize) -> Option<*mut c_void> {
            (size != 0).then_some(physical as *mut c_void)
        }
        unsafe fn unmap_device(&self, address: *mut c_void) {
            self.note(std::format!("unmap device {:#x}", address as usize));
        }
        fn map_pages(&self, physical: &[u64]) -> Option<*mut c_void> {
            physical.first().map(|&page| page as *mut c_void)
        }
        unsafe fn unmap_pages(&self, address: *mut c_void, count: usize) {
            self.note(std::format!("unmap pages {:#x} {count}", address as usize));
        }
        fn irq_enable(&self, irq: u32) -> Result<(), Errno> {
            if irq == 0 { Err(-22) } else { Ok(()) }
        }
        fn irq_disable(&self, irq: u32) {
            self.note(std::format!("irq off {irq}"));
        }
        unsafe fn copy_from_user(&self, to: *mut u8, from: *const u8, size: usize) -> usize {
            // SAFETY: the tests pass valid buffers.
            unsafe { ptr::copy_nonoverlapping(from, to, size) };
            0
        }
        unsafe fn copy_to_user(&self, _: *mut u8, _: *const u8, size: usize) -> usize {
            size
        }
        fn map_user(&self, _: *mut c_void, _: u64, pfn: u64, _: u64) -> Result<(), Errno> {
            if pfn == 0 { Err(-14) } else { Ok(()) }
        }
        fn unmap_user(&self, space: *mut c_void, address: u64, size: usize) {
            self.note(std::format!(
                "unmap user {:#x} {address:#x} {size}",
                space as usize
            ));
        }
    }

    #[test]
    fn each_service_reaches_the_platform_through_the_c_table() {
        let owner = Owner::new(Fake::default());
        // SAFETY: the raw owner stays valid while `owner` lives, and each call
        // follows its `linux.h` contract with live local buffers.
        unsafe {
            let raw = &*owner.raw();
            let (s, context) = (&*raw.services, raw.context);
            assert_eq!((s.now_ns)(context), 42);
            (s.delay_us)(context, 1, 2, true);

            let (mut data, mut size) = (ptr::null(), 0);
            assert_eq!(
                (s.firmware)(context, c"nvidia/gsp.bin".as_ptr(), &mut data, &mut size),
                0
            );
            assert_eq!(slice::from_raw_parts(data, size), IMAGE);
            assert_eq!(
                (s.firmware)(context, c"none".as_ptr(), &mut data, &mut size),
                ENOENT
            );

            (s.log)(context, 4, c"hello".as_ptr());
            (s.warn)(context, c"a.c".as_ptr(), 9, ptr::null());
            (s.warn)(context, c"a.c".as_ptr(), 9, c"x".as_ptr());
            (s.unsupported)(context, c"swap".as_ptr());
            let mut bytes = [0u8; 4];
            (s.random_bytes)(context, bytes.as_mut_ptr().cast(), 4);
            assert_eq!(bytes, [7; 4]);
            assert_eq!((s.start_worker)(context), 0);
            assert_eq!((s.start_worker)(context), -11);
            (s.shutdown)(context, false);

            assert_eq!((s.map_device)(context, 0x1000, 0), ptr::null_mut());
            let device = (s.map_device)(context, 0x1000, 4096);
            assert_eq!(device as usize, 0x1000);
            (s.unmap_device)(context, device);
            assert_eq!((s.map_pages)(context, [].as_ptr(), 0), ptr::null_mut());
            let pages = (s.map_pages)(context, [0x2000u64, 0x9000].as_ptr(), 2);
            assert_eq!(pages as usize, 0x2000);
            (s.unmap_pages)(context, pages, 2);

            assert_eq!((s.irq_enable)(context, 0), -22);
            assert_eq!((s.irq_enable)(context, 5), 0);
            (s.irq_disable)(context, 5);

            let source = [1u8, 2];
            let mut target = [0u8; 2];
            assert_eq!(
                (s.copy_from_user)(
                    context,
                    target.as_mut_ptr().cast(),
                    source.as_ptr().cast(),
                    2
                ),
                0
            );
            assert_eq!(target, source);
            assert_eq!(
                (s.copy_to_user)(
                    context,
                    target.as_mut_ptr().cast(),
                    source.as_ptr().cast(),
                    2
                ),
                2
            );
            assert_eq!((s.map_user)(context, 8 as *mut c_void, 0x4000, 0, 0), -14);
            assert_eq!((s.map_user)(context, 8 as *mut c_void, 0x4000, 1, 0), 0);
            (s.unmap_user)(context, 8 as *mut c_void, 0x4000, 4096);
        }
        assert_eq!(
            *owner.platform().events.borrow(),
            [
                "delay 1 2 true",
                "log 4 hello",
                "warn \"a.c\" 9 None",
                "warn \"a.c\" 9 Some(\"x\")",
                "unsupported \"swap\"",
                "shutdown false",
                "unmap device 0x1000",
                "unmap pages 0x2000 2",
                "irq off 5",
                "unmap user 0x8 0x4000 4096",
            ]
        );
    }
}

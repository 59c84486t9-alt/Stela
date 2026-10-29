mod battery;
mod battery_native;
mod ec_binding;
mod ec_native;
mod references;
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
    preflight_status: AtomicU32,
    flush_status: AtomicU32,
    flush_calls: AtomicUsize,
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
    // SAFETY: callers pass the provider context, a live `TestPlatform` until `destroy`.
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
    // SAFETY: `layout` has a nonzero size.
    let raw = unsafe { alloc(layout) };
    if raw.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `raw` is a fresh 16-aligned block of at least 16 bytes.
    unsafe {
        raw.cast::<usize>().write(total);
    }
    // SAFETY: ACPICA passes back the provider context, a live `TestPlatform` until `destroy`.
    unsafe { platform(p) }
        .counts
        .allocations
        .fetch_add(1, Ordering::SeqCst);
    // SAFETY: the block spans `16 + bytes` bytes.
    let result = unsafe { raw.add(16).cast() };
    // SAFETY: ACPICA passes back the provider context, a live `TestPlatform` until `destroy`.
    unsafe { platform(p) }
        .counts
        .ledger
        .lock()
        .unwrap()
        .insert(result as usize, bytes);
    result
}
unsafe extern "C" fn free(p: *mut c_void, allocation: *mut c_void) {
    // SAFETY: ACPICA passes back the provider context, a live `TestPlatform` until `destroy`.
    unsafe { platform(p) }
        .counts
        .ledger
        .lock()
        .unwrap()
        .remove(&(allocation as usize))
        .unwrap();
    // SAFETY: `allocation` came from `allocate`, 16 bytes past its block's start.
    let raw = unsafe { allocation.cast::<u8>().sub(16) };
    // SAFETY: `allocate` stored the block's size in its first word.
    let total = unsafe { raw.cast::<usize>().read() };
    // SAFETY: `raw` came from `alloc` with this size and alignment and is freed once.
    unsafe { dealloc(raw, Layout::from_size_align(total, 16).unwrap()) };
    // SAFETY: ACPICA passes back the provider context, a live `TestPlatform` until `destroy`.
    unsafe { platform(p) }
        .counts
        .allocations
        .fetch_sub(1, Ordering::SeqCst);
}
unsafe extern "C" fn map(p: *mut c_void, address: u64, length: u64) -> *mut c_void {
    // SAFETY: ACPICA passes back the provider context, a live `TestPlatform` until `destroy`.
    let platform = unsafe { platform(p) };
    let Some(end) = address.checked_add(length) else {
        return ptr::null_mut();
    };
    let mapped = if address >= 0x9000 && end <= 0x9008 {
        // SAFETY: the address check keeps the offset within the eight-byte memory word.
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
        // SAFETY: the table lookup keeps the mapped range within `bytes`.
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
    // SAFETY: ACPICA passes back the provider context, a live `TestPlatform` until `destroy`.
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
    // SAFETY: ACPICA passes a valid out pointer.
    unsafe { out.write(Box::into_raw(Box::new(AtomicBool::new(false))).cast()) };
    0
}
unsafe extern "C" fn delete_lock(_: *mut c_void, lock: *mut c_void) {
    // SAFETY: `lock` came from `create_lock` and ACPICA deletes it once.
    unsafe {
        drop(Box::from_raw(lock.cast::<AtomicBool>()));
    }
}
unsafe extern "C" fn acquire_lock(_: *mut c_void, lock: *mut c_void) -> u64 {
    // SAFETY: `lock` came from `create_lock` and lives until `delete_lock`.
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
    // SAFETY: `lock` came from `create_lock` and lives until `delete_lock`.
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
    // SAFETY: ACPICA passes a valid out pointer.
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
    // SAFETY: `s` came from `create_semaphore` and ACPICA deletes it once.
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
    // SAFETY: `s` came from `create_semaphore` and lives until `delete_semaphore`.
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
    // SAFETY: `s` came from `create_semaphore` and lives until `delete_semaphore`.
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
    // SAFETY: ACPICA passes back the provider context, a live `TestPlatform` until `destroy`.
    if unsafe { platform(p) }.quiescing.load(Ordering::Acquire) {
        return 6;
    }
    // SAFETY: ACPICA passes back the provider context, a live `TestPlatform` until `destroy`.
    unsafe { platform(p) }
        .work
        .lock()
        .unwrap()
        .push_back((callback, context as usize));
    0
}
unsafe extern "C" fn drain_work(p: *mut c_void) -> Status {
    // SAFETY: this fixture keeps its TestPlatform until core shutdown.
    let state = unsafe { platform(p) };
    state.counts.flush_calls.fetch_add(1, Ordering::SeqCst);
    let failure = state.counts.flush_status.load(Ordering::Acquire);
    if failure != 0 {
        return failure;
    }
    loop {
        // SAFETY: ACPICA passes back the provider context, a live `TestPlatform` until
        // `destroy`.
        let next = unsafe { platform(p) }.work.lock().unwrap().pop_front();
        let Some((callback, context)) = next else {
            return 0;
        };
        // SAFETY: ACPICA queued this callback with its own context.
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
    // SAFETY: ACPICA passes back the provider context, a live `TestPlatform` until `destroy`.
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
    // SAFETY: ACPICA passes a valid out pointer and the provider context, a live
    // `TestPlatform`.
    unsafe { value.write(platform(p).counts.memory.load(Ordering::Acquire)) };
    0
}
unsafe extern "C" fn write_memory(p: *mut c_void, address: u64, value: u64, width: u32) -> Status {
    if address != 0x9000 || width != 32 {
        return SUPPORT.0;
    }
    // SAFETY: ACPICA passes back the provider context, a live `TestPlatform` until `destroy`.
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
unsafe extern "C" fn write_pci(_: *mut c_void, _: *mut PciId, _: u32, _: u64, _: u32) -> Status {
    SUPPORT.0
}
unsafe extern "C" fn timer(p: *mut c_void) -> u64 {
    // SAFETY: ACPICA passes back the provider context, a live `TestPlatform` until `destroy`.
    unsafe { platform(p) }.origin.elapsed().as_nanos() as u64 / 100
}
unsafe extern "C" fn signal(_: *mut c_void, _: u32, _: *mut c_void) -> Status {
    SUPPORT.0
}
unsafe extern "C" fn log(_: *mut c_void, text: *const c_char, length: u64) {
    // SAFETY: ACPICA passes `length` valid bytes at `text`.
    let bytes = unsafe { core::slice::from_raw_parts(text.cast::<u8>(), length as usize) };
    std::eprint!("{}", std::string::String::from_utf8_lossy(bytes));
}
unsafe extern "C" fn flush_cache(_: *mut c_void) {
    panic!("no hardware cache flush permitted by fixture");
}
unsafe extern "C" fn quiesce(p: *mut c_void) -> Status {
    // SAFETY: ACPICA passes back the provider context, a live `TestPlatform` until `destroy`.
    if unsafe { platform(p) }.fail_quiesce.load(Ordering::Acquire) {
        return SUPPORT.0;
    }
    // SAFETY: ACPICA passes back the provider context, a live `TestPlatform` until `destroy`.
    unsafe { platform(p) }
        .quiescing
        .store(true, Ordering::Release);
    // SAFETY: `p` is this provider's context.
    unsafe { drain_work(p) }
}
unsafe extern "C" fn preflight_wait_events(p: *mut c_void) -> Status {
    // SAFETY: the singleton fixture owns this live provider context.
    unsafe { platform(p) }
        .counts
        .preflight_status
        .load(Ordering::Acquire)
}
unsafe extern "C" fn destroy(p: *mut c_void) {
    // SAFETY: `p` is the boxed `TestPlatform` the fixture leaked into the provider; ACPICA
    // destroys it once.
    let p = unsafe { Box::from_raw(p.cast::<TestPlatform>()) };
    p.counts.destroyed.store(true, Ordering::SeqCst);
}

unsafe extern "C" fn fatal(_: *mut c_void, status: Status) -> ! {
    std::eprintln!("native ACPI callback completion fatal: {status:#x}");
    // SAFETY: this fatal callback is entered by the same live singleton's C
    // bridge after it poisons namespace access, before any provider teardown.
    assert_eq!(unsafe { stela_acpi_namespace_valid() }, 0);
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
    fixture_dsdt(include_bytes!("fixtures/namespace.aml").to_vec())
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
            abi_version: SERVICES_ABI_VERSION,
            abi_bytes: SERVICES_ABI_BYTES,
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
            preflight_wait_events,
        },
        counts,
    )
}

/// Reuse the ACPICA fixture with a reduced-hardware FADT. Hardware
/// mode then executes C activation and AML _INI without inventing
/// legacy SCI/PM hardware. Extra AML methods are part of the real DSDT.
pub(crate) fn reduced_hardware_fixture(extra_aml: &[u8]) -> Services {
    let mut dsdt = include_bytes!("fixtures/namespace.aml").to_vec();
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
    // rejects legacy PM I/O. C has already marked its attempt, which
    // must never be interpreted as successful activation by Rust clients.
    provider.capabilities = FULL_CAPABILITIES;
    // SAFETY: test provider owns all services; singleton serialized.
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
    let mut dsdt = include_bytes!("fixtures/namespace.aml").to_vec();
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
    // SAFETY: test provider owns all services; singleton serialized.
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
fn wake_gpes_follow_prw_and_every_notification_reaches_the_global_handler() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let mut dsdt = include_bytes!("fixtures/namespace.aml").to_vec();
    // Scope (\_SB) { Device (WAK1) { Name (_PRW, Package () { 0x0D, 4 }) } }
    dsdt.extend_from_slice(&[0x10, 25, b'\\', b'_', b'S', b'B', b'_', 0x5b, 0x82, 17]);
    dsdt.extend_from_slice(b"WAK1");
    dsdt.extend_from_slice(&[
        0x08, b'_', b'P', b'R', b'W', 0x12, 6, 2, 0x0a, 0x0d, 0x0a, 4,
    ]);
    let length = dsdt.len() as u32;
    dsdt[4..8].copy_from_slice(&length.to_le_bytes());
    checksum(&mut dsdt, 9);
    let (provider, _) = fixture_dsdt(dsdt);
    // SAFETY: test provider owns all services; singleton serialized.
    let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
    let wake = session.handle("\\_SB.WAK1").unwrap();
    assert!(session.all_devices().unwrap().contains(&wake));
    assert_eq!(
        wake.wake_gpe(),
        Ok(Some(Gpe {
            block: None,
            number: 0x0d
        }))
    );
    let ucsi = session.handle("\\_SB.UCSI").unwrap();
    assert_eq!(ucsi.wake_gpe(), Ok(None));
    // GPE blocks and fixed events exist only once hardware is activated.
    static FLAG: AtomicBool = AtomicBool::new(false);
    assert_eq!(session.update_all_gpes(), Err(SUPPORT));
    assert_eq!(session.flag_gpe(0x0d, true, &FLAG), Err(SUPPORT));
    assert_eq!(
        session.flag_fixed_event(EVENT_POWER_BUTTON, &FLAG),
        Err(SUPPORT)
    );
    assert_eq!(
        session.setup_wake_gpe(
            wake,
            Gpe {
                block: None,
                number: 0x0d
            },
            false
        ),
        Err(SUPPORT)
    );
    // System and device notifications alike, with the object's path.
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let target = seen.clone();
    let all = session
        .notify_all(move |path, value| target.lock().unwrap().push((path, value)))
        .unwrap();
    for value in [0x80, 0x01] {
        ucsi.evaluate(Some("FIRE"), &[Argument::Integer(value)])
            .unwrap();
    }
    // SAFETY: test process context; drains the provider's work queue.
    unsafe { acpi_os_wait_events_complete() };
    let path = Some(String::from("\\_SB_.UCSI"));
    assert_eq!(*seen.lock().unwrap(), [(path.clone(), 0x80), (path, 0x01)]);
    all.remove().unwrap();
    session.shutdown().unwrap();
}

#[test]
fn service_abi_rejects_wrong_version_or_extent_before_provider_publication() {
    let _serial = TEST_SERIAL.lock().unwrap();
    for (version, bytes) in [
        (SERVICES_ABI_VERSION - 1, SERVICES_ABI_BYTES),
        (SERVICES_ABI_VERSION, SERVICES_ABI_BYTES - 8),
    ] {
        let (mut provider, counts) = fixture();
        provider.abi_version = version;
        provider.abi_bytes = bytes;
        assert!(matches!(
            // SAFETY: complete fixture allocation is valid even with mismatched
            // format metadata; Rust must retire it without entering C.
            unsafe { Session::start(provider, Mode::InterpreterOnly) },
            Err(BAD_PARAMETER)
        ));
        assert!(counts.destroyed.load(Ordering::Acquire));
        assert_eq!(counts.allocations.load(Ordering::Acquire), 0);
        assert_eq!(counts.mappings.load(Ordering::Acquire), 0);
        let (mut provider, counts) = fixture();
        provider.abi_version = version;
        provider.abi_bytes = bytes;
        // SAFETY: complete current-sized table checks the C format boundary
        // directly; rejection must leave ownership with this fixture caller.
        assert_eq!(unsafe { stela_acpi_start(&provider, 0) }, BAD_PARAMETER.0);
        assert!(!counts.destroyed.load(Ordering::Acquire));
        // SAFETY: rejected C start did not take this provider allocation.
        unsafe { (provider.destroy)(provider.context) };
    }
}

#[test]
fn removal_preflight_retains_real_region_and_notification_on_refusal() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let (provider, counts) = fixture();
    // SAFETY: serialized fixture keeps firmware and real ACPICA services.
    let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
    let handle = session.handle("\\_SB.UCSI").unwrap();
    unsafe extern "C" fn setup(
        _: *mut c_void,
        action: u32,
        context: *mut c_void,
        output: *mut *mut c_void,
    ) -> Status {
        // SAFETY: ACPICA passes a writable context slot; this test keeps its
        // exact u8 allocation live until handler removal succeeds.
        unsafe {
            output.write(if action == 0 {
                context
            } else {
                ptr::null_mut()
            })
        };
        0
    }
    unsafe extern "C" fn read(
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
        // SAFETY: setup published the exact u8 allocation and C
        // provides the output slot for this screened 8-bit read.
        unsafe { value.write(u64::from(*context.cast::<u8>())) };
        0
    }
    let context = Box::into_raw(Box::new(0xabu8));
    // SAFETY: callbacks are static and this owned context survives refusal.
    unsafe {
        session
            .root()
            .install_region(3, read, setup, context.cast())
    }
    .unwrap();
    let observed = Arc::new(AtomicU32::new(0));
    let retained = observed.clone();
    let notification = handle
        .notify(move |value| {
            retained.store(value, Ordering::Release);
        })
        .unwrap();
    let flushes = counts.flush_calls.load(Ordering::Acquire);
    counts.preflight_status.store(SUPPORT.0, Ordering::Release);
    assert_eq!(
        // SAFETY: registration; failed preflight must not remove it.
        unsafe { session.root().remove_region(3, read) },
        Err(SUPPORT)
    );
    assert_eq!(
        handle.evaluate(Some("ECRD"), &[]),
        Ok(Some(Value::Integer(0xab)))
    );
    assert_eq!(notification.remove(), Err(SUPPORT));
    assert_eq!(handle.notify(|_| {}).err(), Some(ALREADY_EXISTS));
    assert_eq!(Arc::strong_count(&observed), 2);
    assert_eq!(counts.flush_calls.load(Ordering::Acquire), flushes);
    assert!(session.namespace_available());
    counts.preflight_status.store(0, Ordering::Release);
    // SAFETY: same still-registered handler/context, now eligible for removal.
    unsafe { session.root().remove_region(3, read) }.unwrap();
    // SAFETY: successful removal and completion exclude all borrowers.
    unsafe { drop(Box::from_raw(context)) };
    session.shutdown().unwrap();
    assert_eq!(Arc::strong_count(&observed), 1);
    assert!(counts.destroyed.load(Ordering::Acquire));
    assert_eq!(counts.allocations.load(Ordering::Acquire), 0);
}

#[test]
fn failed_void_event_completion_stops_before_c_returns() {
    if std::env::var_os("STELA_ACPI_VOID_FLUSH_CHILD").is_some() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (provider, counts) = fixture();
        // SAFETY: isolated child owns the singleton and valid fixture table.
        let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
        let notification = session
            .handle("\\_SB.UCSI")
            .unwrap()
            .notify(|_| {})
            .unwrap();
        counts.flush_status.store(SUPPORT.0, Ordering::Release);
        // Real ACPICA Notify removal enters its internal void OSL completion
        // call. The bridge must stop there, before returning to this Rust frame.
        let _unexpected = notification.remove();
        std::eprintln!("FAILED VOID COMPLETION RETURNED");
        std::process::exit(87);
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "platform::acpi::tests::failed_void_event_completion_stops_before_c_returns",
            "--nocapture",
        ])
        .env("STELA_ACPI_VOID_FLUSH_CHILD", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(86));
    let stderr = std::string::String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("native ACPI callback completion fatal: 0xf"),
        "{stderr}"
    );
    assert!(!stderr.contains("FAILED VOID COMPLETION RETURNED"));
}

#[test]
fn wake_gpe_checks_interpreted_sleep_packages() {
    let _serial = TEST_SERIAL.lock().unwrap();
    for (count, elements, accepted) in [
        (1, &[0x0a, 0x0d][..], false),
        (2, &[0x0a, 0x0d, 0x0a, 6][..], false),
        // ACPICA repairs an invalid numeric string to zero for this
        // predefined object, as on Linux. Validate its interpreted value.
        (2, &[0x0a, 0x0d, 0x0d, b'x', 0][..], true),
        (2, &[0x0a, 0x0d, 0x0d, b'6', 0][..], false),
    ] {
        let mut package = alloc::vec![0x12, (elements.len() + 2) as u8, count];
        package.extend_from_slice(elements);
        let mut name = alloc::vec![0x08, b'_', b'P', b'R', b'W'];
        name.extend(package);
        let mut device = alloc::vec![0x5b, 0x82, (name.len() + 5) as u8];
        device.extend_from_slice(b"WAK1");
        device.extend(name);
        let mut dsdt = include_bytes!("fixtures/namespace.aml").to_vec();
        dsdt.extend_from_slice(&[0x10, (device.len() + 6) as u8, b'\\']);
        dsdt.extend_from_slice(b"_SB_");
        dsdt.extend(device);
        let length = dsdt.len() as u32;
        dsdt[4..8].copy_from_slice(&length.to_le_bytes());
        checksum(&mut dsdt, 9);
        let (provider, _) = fixture_dsdt(dsdt);
        // SAFETY: the serialized fixture owns the singleton's services.
        let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
        let gpe = session.handle("\\_SB.WAK1").unwrap().wake_gpe();
        if accepted {
            assert_eq!(
                gpe,
                Ok(Some(Gpe {
                    block: None,
                    number: 13
                }))
            );
        } else {
            assert_eq!(gpe, Err(BAD_PARAMETER));
        }
        session.shutdown().unwrap();
    }
}

#[test]
fn activated_events_take_only_gpes_acpica_has() {
    let _serial = TEST_SERIAL.lock().unwrap();
    // SAFETY: reduced-hardware provider enters C activation without
    // inventing legacy hardware; singleton serialized for this whole test.
    let session = unsafe { Session::start(reduced_hardware_fixture(&[]), Mode::Hardware) }.unwrap();
    session.update_all_gpes().unwrap();
    // Without GPE blocks, ACPICA has no GPE 0x0D to take.
    static FLAG: AtomicBool = AtomicBool::new(false);
    assert_eq!(session.flag_gpe(0x0d, true, &FLAG), Err(BAD_PARAMETER));
    assert!(!FLAG.load(Ordering::Acquire));
    session.shutdown().unwrap();
}

#[test]
fn successful_hardware_witness_is_revoked_by_actual_namespace_unload() {
    let _serial = TEST_SERIAL.lock().unwrap();
    // SAFETY: reduced-hardware provider enters C activation without
    // inventing legacy hardware; singleton serialized for this whole test.
    let session = unsafe { Session::start(reduced_hardware_fixture(&[]), Mode::Hardware) }.unwrap();
    assert!(session.hardware_enabled());
    let root = session.root();
    assert!(root.hardware_active());
    // A minimal SSDT: Scope (\_SB) { Device (DYN1) { Name (TEST, 42) } }.
    // Keep these table bytes alive until ACPICA terminates.
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
    assert_eq!(
        // SAFETY: complete owned SSDT, kept through global teardown.
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
        // SAFETY: the fixture provider's tables and callbacks are valid, and the serial lock
        // keeps this the only interpreter.
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
        // SAFETY: the fixture provider's tables and callbacks are valid, and the serial lock
        // keeps this the only interpreter.
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
        core::mem::forget(notification); // callback tests quarantine, not normal removal
        assert_eq!(session.shutdown(), Err(SUPPORT));
        // SAFETY: the quarantined provider context stays alive, and its callbacks are still
        // valid.
        assert_eq!(unsafe { (provider.drain_work)(provider.context) }, 0);
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
            // SAFETY: the fixture provider's tables and callbacks are valid, and the serial
            // lock keeps this the only interpreter.
            unsafe { Session::start(other, Mode::InterpreterOnly) },
            Err(ALREADY_EXISTS)
        ));
        assert!(!other_counts.destroyed.load(Ordering::SeqCst));
        // SAFETY: the refused start never took `other`, so its context is destroyed once here.
        unsafe { (other.destroy)(other.context) }; // reservation rejection never transfers ownership
        return;
    }
    unsafe extern "C" {
        fn stela_acpi_global_acquire(lock: *mut u32) -> u8;
        fn stela_acpi_global_release(lock: *mut u32) -> u8;
    }
    let mut lock = 0x10u32;
    // SAFETY: `lock` is a local FACS global-lock word.
    assert_eq!(unsafe { stela_acpi_global_acquire(&mut lock) }, 1);
    assert_eq!(lock, 0x12);
    // SAFETY: `lock` is a local FACS global-lock word.
    assert_eq!(unsafe { stela_acpi_global_acquire(&mut lock) }, 0);
    assert_eq!(lock, 0x13);
    // SAFETY: `lock` is a local FACS global-lock word.
    assert_eq!(unsafe { stela_acpi_global_release(&mut lock) }, 1);
    assert_eq!(lock, 0x10);
    // SAFETY: `lock` is a local FACS global-lock word.
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
        core::mem::offset_of!(Services, preflight_wait_events),
        core::mem::offset_of!(Services, context),
        size_of::<u32>(),
    ];
    for (field, expected) in expected.into_iter().enumerate() {
        assert_eq!(
            // SAFETY: reads a constant ABI layout value.
            unsafe { stela_acpi_layout(field as u32) },
            expected as u64,
            "ABI field {field}"
        );
    }
    // Partial initialization failures must reclaim the transferred provider.
    unsafe extern "C" fn reject_lock(_: *mut c_void, _: *mut *mut c_void) -> Status {
        4
    }
    let (mut provider, counts) = fixture();
    provider.create_lock = reject_lock;
    assert!(matches!(
        // SAFETY: the fixture provider's tables and callbacks are valid, and the serial lock
        // keeps this the only interpreter.
        unsafe { Session::start(provider, Mode::InterpreterOnly) },
        Err(Error(4))
    ));
    assert!(counts.destroyed.load(Ordering::SeqCst));
    let (mut provider, counts) = fixture();
    provider.root = 0xdead;
    // SAFETY: the fixture provider's tables and callbacks are valid, and the serial lock keeps
    // this the only interpreter.
    assert!(unsafe { Session::start(provider, Mode::InterpreterOnly) }.is_err());
    assert!(counts.destroyed.load(Ordering::SeqCst));
    assert_eq!(counts.allocations.load(Ordering::SeqCst), 0);
    assert_eq!(counts.mappings.load(Ordering::SeqCst), 0);
    // Real hardware activation must be rejected before touching SCI or mode regs.
    let (provider, counts) = fixture();
    assert!(matches!(
        // SAFETY: the fixture provider's tables and callbacks are valid, and the serial lock
        // keeps this the only interpreter.
        unsafe { Session::start(provider, Mode::Hardware) },
        Err(SUPPORT)
    ));
    assert!(counts.destroyed.load(Ordering::SeqCst));
    assert_eq!(counts.port_writes.load(Ordering::SeqCst), 0);
    let (provider, counts) = fixture();
    // SAFETY: the fixture provider's tables and callbacks are valid, and the serial lock keeps
    // this the only interpreter.
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
        // SAFETY: ACPICA passes a valid out pointer.
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
        // SAFETY: ACPICA passes a valid out pointer.
        unsafe { value.write(0xab) };
        0
    }
    let region_context = Box::into_raw(Box::new(1u8)).cast();
    // SAFETY: `region_context` lives until after `remove_region`, and both callbacks implement
    // the region contract.
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
    // SAFETY: this handler was installed above and its context is still alive.
    unsafe { session.root().remove_region(3, region) }.unwrap();
    // SAFETY: the region was removed, so nothing else holds `region_context`.
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
        0xc2, 0x98, 0x83, 0x6f, 0xa4, 0x7c, 0xe4, 0x11, 0xad, 0x36, 0x63, 0x10, 0x42, 0xb5, 0x00,
        0x8f,
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
    // SAFETY: the session is live and this thread holds no ACPICA lock.
    unsafe { acpi_os_wait_events_complete() };
    assert_eq!(
        notified.load(Ordering::SeqCst),
        0x81,
        "Notify dispatch preserves FIFO order"
    );
    notification.remove().unwrap();
    ucsi.evaluate(Some("FIRE"), &[Argument::Integer(0x80)])
        .unwrap();
    // SAFETY: the session is live and this thread holds no ACPICA lock.
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
    // SAFETY: the fixture provider's tables and callbacks are valid, and the serial lock keeps
    // this the only interpreter.
    unsafe { Session::start(provider, Mode::InterpreterOnly) }
        .unwrap()
        .shutdown()
        .unwrap();
    assert!(counts.destroyed.load(Ordering::SeqCst));
}

#[test]
fn native_table_unload_invalidates_handles_references_and_notifications() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let (provider, counts) = fixture_dsdt(include_bytes!("fixtures/dynamic-host.aml").to_vec());
    let fatal_child = std::env::var_os("STELA_ACPI_UNLOAD_FATAL_CHILD").is_some();
    // SAFETY: the fixture provider's tables and callbacks are valid, and the serial lock keeps
    // this the only interpreter.
    let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
    assert!(matches!(
        session.root().evaluate(
            Some("LDTB"),
            &[Argument::Buffer(include_bytes!("fixtures/dynamic.aml"))]
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
        // Swap only the provider callback used inside C's immutable
        // transferred vtable through a fixture flag; no production bypass.
        // SAFETY: ACPICA passes back the provider context, a live `TestPlatform` until
        // `destroy`.
        unsafe { platform(provider.context) }
            .fail_quiesce
            .store(true, Ordering::Release);
    }
    unsafe extern "C" {
        fn acpi_unload_parent_table(handle: *mut c_void) -> Status;
    }
    // SAFETY: loaded SSDT node, interpreter idle on this owner thread;
    // the provider drains all other callbacks before real namespace deletion.
    // This uses ACPICA's supported native table API, not an invented AML DDB.
    assert_eq!(unsafe { acpi_unload_parent_table(device.raw) }, 0);
    assert!(!session.namespace_available());
    // Force ACPICA's node caches back to the sanitizer allocator. Stale raw
    // dereferences now read freed storage rather than recycled nodes.
    unsafe extern "C" {
        fn acpi_purge_cached_objects() -> Status;
    }
    // SAFETY: the interpreter is idle on this thread.
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
    // Raw oracle calls are test-only: prove the real native
    // table API deleted the node. Unsupported AML did not execute its Store.
    let mut gone = ptr::null_mut();
    let name = CString::new("\\_SB.DYN0").unwrap();
    assert_ne!(
        // SAFETY: `name` and `gone` are live locals, and the interpreter is idle on this
        // thread.
        unsafe { acpi_get_handle(usize::MAX as *mut c_void, name.as_ptr(), &mut gone) },
        0
    );
    let name = CString::new("\\UNLD").unwrap();
    let mut result = RawBuffer {
        length: u64::MAX,
        pointer: ptr::null_mut(),
    };
    assert_eq!(
        // SAFETY: `name` and `result` are live locals, and the interpreter is idle on this
        // thread.
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
    // SAFETY: a successful evaluation returns one allocated `RawObject` at `pointer`.
    let raw = unsafe { result.pointer.cast::<RawObject>().read_unaligned() };
    assert_eq!((raw.kind, raw.payload), (1, 0));
    // SAFETY: ACPICA allocated `pointer` for this result, freed once.
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

/// Captured QEMU/firmware inputs remain ignored; this generic evaluator
/// records their hash and real method results without production path exceptions.
#[test]
#[ignore = "oracle: STELA_ACPI_DSDT, STELA_ACPI_QUERIES"]
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
    // SAFETY: the fixture provider's tables and callbacks are valid, and the serial lock keeps
    // this the only interpreter.
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

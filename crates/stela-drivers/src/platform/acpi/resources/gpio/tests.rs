extern crate std;
use super::*;
use crate::platform::acpi::{
    Mode, Session, Value,
    tests::{TEST_SERIAL, reduced_hardware_fixture},
};
use alloc::vec;
use std::sync::Mutex;

pub(super) static LAST_ACCESS: Mutex<(u32, u64, u32)> = Mutex::new((u32::MAX, 0, 0));

fn pkg(op: &[u8], body: &[u8]) -> Vec<u8> {
    let mut bytes = op.to_vec();
    let length = body.len() + if body.len() + 1 < 64 { 1 } else { 2 };
    assert!(length < 4096);
    if length < 64 {
        bytes.push(length as u8);
    } else {
        bytes.extend([0x40 | (length as u8 & 15), (length >> 4) as u8]);
    }
    bytes.extend(body);
    bytes
}
fn name(id: &[u8; 4], value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![8];
    bytes.extend(id);
    bytes.extend(value);
    bytes
}
fn method(id: &[u8; 4], flags: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = id.to_vec();
    bytes.push(flags);
    bytes.extend(body);
    pkg(&[0x14], &bytes)
}
fn buffer(bytes: &[u8]) -> Vec<u8> {
    let mut body = vec![0x0b];
    body.extend((bytes.len() as u16).to_le_bytes());
    body.extend(bytes);
    pkg(&[0x11], &body)
}
fn fixture() -> Vec<u8> {
    fixture_for(b"STLA0001", 0xfd00_0123)
}
fn fixture_for(hid: &[u8], memory_base: u32) -> Vec<u8> {
    let mut resource = vec![0x86, 9, 0, 1];
    resource.extend_from_slice(&memory_base.to_le_bytes());
    resource.extend_from_slice(&0x400u32.to_le_bytes());
    resource.extend_from_slice(&[0x79, 0]);
    fixture_with_resources(hid, &resource)
}
fn fixture_with_resources(hid: &[u8], resource: &[u8]) -> Vec<u8> {
    fixture_with_reg(hid, resource, None)
}
fn fixture_with_reg(hid: &[u8], resource: &[u8], reg: Option<&[u8]>) -> Vec<u8> {
    let mut device = b"GPO0".to_vec();
    let mut identifier = vec![0x0d];
    identifier.extend_from_slice(hid);
    identifier.push(0);
    device.extend(name(b"_HID", &identifier));
    device.extend(name(b"_CRS", &buffer(resource)));
    let pins = 80;
    let source_at: u16 = 23 + pins * 2;
    let length = source_at + 6 - 3;
    let mut connection = vec![0x8c];
    connection.extend(length.to_le_bytes());
    connection.extend([1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 23, 0, 0]);
    connection.extend(source_at.to_le_bytes());
    connection.extend([0, 0, 0, 0]);
    for pin in 0u16..pins {
        connection.extend(pin.to_le_bytes());
    }
    connection.extend(b"GPO0\0");
    // The actual source string has 5 bytes; fix the descriptor body length.
    let body_len = (connection.len() - 3) as u16;
    connection[1..3].copy_from_slice(&body_len.to_le_bytes());
    device.extend(name(b"CON0", &buffer(&connection)));
    // Nine bytes contain all 66 declared bits, including N065 at byte offset8.
    device.extend(b"\x5b\x80GPOR\x08\x00\x0a\x09");
    // Connection(CON0), single bit at index zero, then index one.
    device.extend(pkg(b"\x5b\x81", b"GPOR\x01\x02CON0F000\x01F001\x01"));
    device.extend(method(b"RD00", 0, b"\xa4F000"));
    device.extend(method(b"RD01", 0, b"\xa4F001"));
    device.extend(method(b"WR01", 1, b"\x70\x68F001\xa4\x00"));
    // Fresh Connection index zero, then a 65-bit field with an actual 9-byte
    // ACPICA Buffer result. PkgLength(65) = 0x41,0x04 (not a package size).
    device.extend(pkg(b"\x5b\x81", b"GPOR\x01\x02CON0WIDE\x41\x04"));
    device.extend(method(b"RD65", 0, b"\xa4WIDE"));
    device.extend(method(b"WR65", 1, b"\x70\x68WIDE\xa4\x00"));
    let mut fields = b"GPOR\x01\x02CON0".to_vec();
    for index in 0..66 {
        fields.extend(format!("N{index:03}").as_bytes());
        fields.push(1);
    }
    device.extend(pkg(b"\x5b\x81", &fields));
    device.extend(method(b"RD66", 0, b"\xa4N065"));
    device.extend(name(b"CNTR", &[0]));
    device.extend(method(b"_E01", 0, b"\x75CNTR\xa4\x00"));
    device.extend(method(b"_EVT", 1, b"\x70\x68CNTR\xa4\x00"));
    if let Some(body) = reg {
        device.extend(method(b"_REG", 2, body));
    }
    let mut aml = pkg(b"\x5b\x82", &device);
    for (id, resource) in [(b"NOST", false), (b"NODE", true)] {
        let mut device = id.to_vec();
        device.extend(name(b"_HID", b"\x0dSTLA0001\0"));
        if resource {
            device.extend(name(b"_CRS", &buffer(&[0x79, 0])));
            device.extend(method(b"_DEP", 0, &[]));
        } else {
            device.extend(method(b"_STA", 0, &[]));
        }
        aml.extend(pkg(b"\x5b\x82", &device));
    }
    aml
}
#[derive(Default)]
struct Model {
    values: [u64; 2],
    claims: Vec<u16>,
    policies: Vec<LinePolicy>,
    writes: Vec<(u16, bool)>,
    released: Vec<u16>,
    stopped: bool,
    fail_request: bool,
    fail_release: bool,
    fail_write: bool,
}
struct Backend(Arc<Mutex<Model>>, super::super::memory::DeviceIdentity);
impl sealed::Sealed for Backend {}
impl NativeController for Backend {
    fn device_path(&self) -> &str {
        "\\GPO0"
    }
    fn matches_device(&self, device: &DeviceResources<'_>) -> Result<(), Error> {
        if self.1.same(&device.identity()) {
            Ok(())
        } else {
            Err(Error::ResourceChanged)
        }
    }
    fn request(&mut self, pin: u16, policy: LinePolicy) -> Result<(), acpi::Error> {
        let mut model = self.0.lock().unwrap();
        assert!(!model.claims.contains(&pin));
        model.claims.push(pin);
        model.policies.push(policy);
        if model.fail_request {
            Err(acpi::Error(1))
        } else {
            Ok(())
        }
    }
    fn read(&mut self, pin: u16) -> Result<bool, acpi::Error> {
        let model = self.0.lock().unwrap();
        assert!(model.claims.contains(&pin));
        Ok(model.values[pin as usize / 64] & (1 << (pin % 64)) != 0)
    }
    fn write(&mut self, pin: u16, value: bool) -> Result<(), acpi::Error> {
        let mut model = self.0.lock().unwrap();
        assert!(model.claims.contains(&pin));
        model.writes.push((pin, value));
        if model.fail_write {
            Err(acpi::Error(1))
        } else {
            Ok(())
        }
    }
    fn release(&mut self, pin: u16) -> Result<(), acpi::Error> {
        let mut model = self.0.lock().unwrap();
        if model.fail_release {
            return Err(acpi::Error(1));
        }
        let at = model.claims.iter().position(|p| *p == pin).unwrap();
        model.claims.remove(at);
        model.released.push(pin);
        Ok(())
    }
    fn shutdown(&mut self) -> Result<(), acpi::Error> {
        let mut model = self.0.lock().unwrap();
        assert!(model.claims.is_empty());
        model.stopped = true;
        Ok(())
    }
}
#[test]
fn actual_acpica_connection_nonzero_index_wide_reads_and_integer_only_writes() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let provider = reduced_hardware_fixture(&fixture());
    // SAFETY: actual authored OSL services and native singleton are serialized.
    let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
    let handle = session.handle("\\GPO0").unwrap();
    assert!(matches!(
        DeviceResources::inspect(session.handle("\\NOST").unwrap()),
        Err(Error::InvalidObject("_STA"))
    ));
    assert!(matches!(
        DeviceResources::inspect(session.handle("\\NODE").unwrap()),
        Err(Error::InvalidObject("_DEP"))
    ));
    let device = DeviceResources::inspect(handle).unwrap();
    assert!(device.matches_hid("STLA0001").unwrap());
    assert!(!device.matches_hid("PNP0C09").unwrap());
    let model = Arc::new(Mutex::new(Model {
        values: [2, 3],
        ..Model::default()
    }));
    let backend = Backend(model.clone(), device.identity());
    let mut binding = Binding::install(device, Box::new(backend), &[]).unwrap();
    assert_eq!(
        handle.evaluate(Some("RD00"), &[]).unwrap(),
        Some(Value::Integer(0))
    );
    // Real ACPICA supplies address=1,width=1 and a field-relative value buffer.
    assert_eq!(
        handle.evaluate(Some("RD01"), &[]).unwrap(),
        Some(Value::Integer(1))
    );
    assert_eq!(*LAST_ACCESS.lock().unwrap(), (0, 1, 1));
    assert_eq!(
        handle.evaluate(Some("RD66"), &[]).unwrap(),
        Some(Value::Integer(1))
    );
    assert_eq!(*LAST_ACCESS.lock().unwrap(), (0, 65, 1));
    handle
        .evaluate(Some("WR01"), &[Argument::Integer(1)])
        .unwrap();
    assert_eq!(model.lock().unwrap().writes, [(1, true)]);
    assert_eq!(
        handle.evaluate(Some("RD65"), &[]).unwrap(),
        Some(Value::Buffer(vec![2, 0, 0, 0, 0, 0, 0, 0, 1]))
    );
    let writes = model.lock().unwrap().writes.len();
    assert_eq!(
        handle.evaluate(Some("WR65"), &[Argument::Integer(u64::MAX)]),
        Err(acpi::SUPPORT)
    );
    assert_eq!(model.lock().unwrap().writes.len(), writes);
    let supplier = binding.supplier().unwrap();
    assert!(matches!(binding.remove(), Err(Error::Conflict)));
    drop(supplier);
    binding.remove().unwrap();
    assert!(handle.evaluate(Some("RD01"), &[]).is_err());
    drop(binding);
    session.shutdown().unwrap();
    let model = model.lock().unwrap();
    assert!(model.stopped && model.claims.is_empty());
    assert_eq!(model.released.len(), 66);
}
#[test]
fn failed_first_request_is_not_replayed_and_claim_retires_after_handler_callbacks_end() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let provider = reduced_hardware_fixture(&fixture());
    // SAFETY: actual authored OSL provider under the native singleton test lock.
    let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
    let handle = session.handle("\\GPO0").unwrap();
    let model = Arc::new(Mutex::new(Model {
        fail_request: true,
        ..Model::default()
    }));
    let device = DeviceResources::inspect(handle).unwrap();
    let backend = Backend(model.clone(), device.identity());
    let binding = Binding::install(device, Box::new(backend), &[]).unwrap();
    assert!(handle.evaluate(Some("RD00"), &[]).is_err());
    assert!(handle.evaluate(Some("RD00"), &[]).is_err());
    assert_eq!(model.lock().unwrap().claims, [0]);
    drop(binding);
    assert!(model.lock().unwrap().stopped);
    assert_eq!(model.lock().unwrap().released, [0]);
    assert_eq!(
        Arc::strong_count(&model),
        2,
        "core retains callback storage"
    );
    session.shutdown().unwrap();
    assert_eq!(Arc::strong_count(&model), 1);
}
#[test]
fn actual_aei_method_resolution_follows_edge_level_then_evt_with_native_arguments() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let provider = reduced_hardware_fixture(&fixture());
    // SAFETY: actual provider and native singleton test lock remain retained.
    let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
    let handle = session.handle("\\GPO0").unwrap();
    let gpio = Gpio {
        consumer: true,
        kind: GpioKind::Interrupt {
            trigger: Trigger::Edge,
            polarity: Polarity::High,
        },
        shared: false,
        wake: false,
        pull: 0,
        drive_strength: 0,
        debounce: 0,
        pins: vec![1],
        source: Source {
            index: 0,
            path: String::from("GPO0"),
        },
        vendor: Vec::new(),
    };
    event_method(handle, &gpio)
        .unwrap()
        .unwrap()
        .evaluate()
        .unwrap();
    assert_eq!(
        handle.evaluate(Some("CNTR"), &[]).unwrap(),
        Some(Value::Integer(1))
    );
    let gpio = Gpio {
        pins: vec![300],
        ..gpio
    };
    event_method(handle, &gpio)
        .unwrap()
        .unwrap()
        .evaluate()
        .unwrap();
    assert_eq!(
        handle.evaluate(Some("CNTR"), &[]).unwrap(),
        Some(Value::Integer(300))
    );
    session.shutdown().unwrap();
}

#[test]
fn identical_namespace_path_does_not_replace_original_backend_inspection() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let provider = reduced_hardware_fixture(&fixture());
    // SAFETY: actual authored provider and native singleton remain serialized.
    let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
    let handle = session.handle("\\GPO0").unwrap();
    let original = DeviceResources::inspect(handle).unwrap();
    let replacement = DeviceResources::inspect(handle).unwrap();
    let model = Arc::new(Mutex::new(Model::default()));
    let backend = Backend(model.clone(), original.identity());
    assert!(matches!(
        Binding::install(replacement, Box::new(backend), &[]),
        Err(Error::ResourceChanged)
    ));
    let observed = model.lock().unwrap();
    assert!(observed.claims.is_empty() && observed.writes.is_empty() && observed.stopped);
    drop(observed);
    drop(original);
    session.shutdown().unwrap();
}

type Signal = unsafe extern "C" fn(*mut core::ffi::c_void, *mut core::ffi::c_void, u32) -> u32;
static ORIGINAL_SIGNAL: Mutex<Option<Signal>> = Mutex::new(None);
static NATIVE_SEMAPHORE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static FAIL_SIGNAL_ONCE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
unsafe extern "C" fn signal_then_report_failure(
    context: *mut core::ffi::c_void,
    semaphore: *mut core::ffi::c_void,
    units: u32,
) -> u32 {
    let original = ORIGINAL_SIGNAL
        .lock()
        .unwrap()
        .expect("retained original provider callback");
    // SAFETY: forwards the unchanged actual provider context and semaphore.
    let status = unsafe { original(context, semaphore, units) };
    if status == 0
        && semaphore as usize == NATIVE_SEMAPHORE.load(Ordering::Acquire)
        && FAIL_SIGNAL_ONCE.swap(false, Ordering::AcqRel)
    {
        acpi::LIMIT.0
    } else {
        status
    }
}

#[test]
fn native_write_failure_and_semaphore_release_failure_remain_separate() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let mut provider = reduced_hardware_fixture(&fixture());
    *ORIGINAL_SIGNAL.lock().unwrap() = Some(provider.signal_semaphore);
    provider.signal_semaphore = signal_then_report_failure;
    // SAFETY: actual provider callback forwarding and native singleton are owned.
    let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
    let handle = session.handle("\\GPO0").unwrap();
    let device = DeviceResources::inspect(handle).unwrap();
    let model = Arc::new(Mutex::new(Model {
        fail_write: true,
        ..Model::default()
    }));
    let backend = Backend(model.clone(), device.identity());
    let mut binding = Binding::install(device, Box::new(backend), &[]).unwrap();
    NATIVE_SEMAPHORE.store(binding.context().semaphore as usize, Ordering::Release);
    FAIL_SIGNAL_ONCE.store(true, Ordering::Release);
    assert_eq!(
        handle.evaluate(Some("WR01"), &[Argument::Integer(1)]),
        Err(acpi::Error(1))
    );
    assert_eq!(model.lock().unwrap().writes, [(1, true)]);
    assert_eq!(
        binding.failures(),
        Failures {
            operation: Some(acpi::Error(1)),
            synchronization: Some(acpi::LIMIT)
        }
    );
    assert!(handle.evaluate(Some("RD01"), &[]).is_err());
    assert!(matches!(
        binding.context().supplier.connected(),
        Err(Error::Unassigned)
    ));
    assert!(matches!(
        Dependency::acquire(handle, &binding.context().supplier),
        Err(Error::Unassigned)
    ));
    binding.remove().unwrap();
    drop(binding);
    session.shutdown().unwrap();
    assert!(model.lock().unwrap().stopped);
    NATIVE_SEMAPHORE.store(0, Ordering::Release);
    *ORIGINAL_SIGNAL.lock().unwrap() = None;
}

#[test]
fn suppressed_reg_write_failure_keeps_installed_handler_without_supplier_publication() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let resource = [0x86, 9, 0, 1, 0x23, 1, 0, 0xfd, 0, 4, 0, 0, 0x79, 0];
    // If(Arg1) { Store(One,F001) }: only the real _REG(CONNECT) accesses GPIO.
    let reg = pkg(&[0xa0], b"\x69\x70\x01F001");
    let provider = reduced_hardware_fixture(&fixture_with_reg(b"STLA0001", &resource, Some(&reg)));
    // SAFETY: the original native OSL fixture/singleton is serialized.
    let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
    let handle = session.handle("\\GPO0").unwrap();
    let device = DeviceResources::inspect(handle).unwrap();
    let model = Arc::new(Mutex::new(Model {
        fail_write: true,
        ..Model::default()
    }));
    let backend = Backend(model.clone(), device.identity());
    let mut binding = Binding::install(device, Box::new(backend), &[]).unwrap();
    assert!(
        binding.installed,
        "actual successful handler installation is retained"
    );
    assert_eq!(model.lock().unwrap().writes, [(1, true)]);
    assert_eq!(binding.failures().operation, Some(acpi::Error(1)));
    assert_eq!(binding.failures().synchronization, None);
    assert!(matches!(
        binding.supplier(),
        Err(Error::Acpi(acpi::Error(1)))
    ));
    assert!(matches!(
        binding.context().supplier.connected(),
        Err(Error::Unassigned)
    ));
    binding.remove().unwrap();
    drop(binding);
    session.shutdown().unwrap();
    let model = model.lock().unwrap();
    assert_eq!(model.released, [1]);
    assert!(model.stopped);
}

type Wait = unsafe extern "C" fn(*mut core::ffi::c_void, *mut core::ffi::c_void, u32, u16) -> u32;
static ORIGINAL_WAIT: Mutex<Option<Wait>> = Mutex::new(None);
static FAIL_WAIT_ONCE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
unsafe extern "C" fn refuse_once_before_wait(
    context: *mut core::ffi::c_void,
    semaphore: *mut core::ffi::c_void,
    units: u32,
    timeout: u16,
) -> u32 {
    if semaphore as usize == NATIVE_SEMAPHORE.load(Ordering::Acquire)
        && FAIL_WAIT_ONCE.swap(false, Ordering::AcqRel)
    {
        return 0x11;
    }
    let original = ORIGINAL_WAIT
        .lock()
        .unwrap()
        .expect("retained original provider wait callback");
    // SAFETY: unchanged original context, semaphore and ABI arguments.
    unsafe { original(context, semaphore, units, timeout) }
}

#[test]
fn native_wait_refusal_is_retained_without_claims_or_invented_operation_error() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let mut provider = reduced_hardware_fixture(&fixture());
    *ORIGINAL_WAIT.lock().unwrap() = Some(provider.wait_semaphore);
    provider.wait_semaphore = refuse_once_before_wait;
    // SAFETY: real forwarded OSL provider and native singleton are serialized.
    let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
    let handle = session.handle("\\GPO0").unwrap();
    let device = DeviceResources::inspect(handle).unwrap();
    let model = Arc::new(Mutex::new(Model::default()));
    let backend = Backend(model.clone(), device.identity());
    let mut binding = Binding::install(device, Box::new(backend), &[]).unwrap();
    NATIVE_SEMAPHORE.store(binding.context().semaphore as usize, Ordering::Release);
    FAIL_WAIT_ONCE.store(true, Ordering::Release);
    assert_eq!(handle.evaluate(Some("RD01"), &[]), Err(acpi::Error(0x11)));
    assert!(model.lock().unwrap().claims.is_empty());
    assert_eq!(
        binding.failures(),
        Failures {
            operation: None,
            synchronization: Some(acpi::Error(0x11))
        }
    );
    assert_eq!(
        handle.evaluate(Some("RD01"), &[]).unwrap(),
        Some(Value::Integer(0))
    );
    binding.remove().unwrap();
    drop(binding);
    session.shutdown().unwrap();
    NATIVE_SEMAPHORE.store(0, Ordering::Release);
    *ORIGINAL_WAIT.lock().unwrap() = None;
}

#[repr(align(4096))]
struct NativePage(core::cell::UnsafeCell<[u8; 4096]>);

#[test]
fn actual_namespace_dependent_memory_cannot_construct_a_native_device() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let mut resource = vec![0x31, 0, 0x86, 9, 0, 1];
    resource.extend_from_slice(&0xfd00_0100u32.to_le_bytes());
    resource.extend_from_slice(&0x400u32.to_le_bytes());
    resource.extend_from_slice(&[0x38, 0x79, 0]);
    let provider = reduced_hardware_fixture(&fixture_with_resources(b"AMD0030", &resource));
    // SAFETY: the actual native OSL fixture and singleton are serialized.
    let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
    let handle = session.handle("\\GPO0").unwrap();
    assert_eq!(
        handle.evaluate(Some("_CRS"), &[]).unwrap(),
        Some(Value::Buffer(resource))
    );
    // No DeviceResources owner exists for the native factory/broker to consume;
    // no native mapping authority or backend can be created by this template.
    assert!(matches!(
        DeviceResources::inspect(handle),
        Err(Error::DependentFunctions)
    ));
    session.shutdown().unwrap();
}

#[derive(Default)]
struct NativeMappingState {
    page: Option<Box<NativePage>>,
    token: u64,
    maps: usize,
    unmaps: usize,
    restored_control: u32,
}
struct NativeMappingModel {
    owner: std::thread::ThreadId,
    state: Mutex<NativeMappingState>,
}
struct NativeRoot(Arc<NativeMappingModel>);
const NATIVE_BASE: u64 = 0xfd00_0000;
fn native_span() -> crate::bus::mmio::owned::PhysicalSpan {
    crate::bus::mmio::owned::PhysicalSpan::new(NATIVE_BASE, 4096).unwrap()
}
// SAFETY: this test root represents one exclusive page in the simulated native
// machine. Its model lives through all child resources and mapping retirement.
unsafe impl crate::bus::mmio::owned::ResourceBacking for NativeRoot {
    fn physical_span(&self) -> crate::bus::mmio::owned::PhysicalSpan {
        native_span()
    }
    fn kind(&self) -> crate::bus::mmio::owned::ResourceKind {
        crate::bus::mmio::owned::ResourceKind::Registers
    }
}
// SAFETY: one simulated native CPU, actual aligned owned RAM and unique mapping
// token. The production mapping authority still performs all reservation/cache
// checks; this model does not establish physical PAT/MTRR or hardware operation.
unsafe impl crate::bus::mmio::owned::MappingPlatform for NativeMappingModel {
    fn check_context(
        &self,
        address: crate::bus::mmio::owned::AddressSpace,
    ) -> Result<(), crate::bus::mmio::owned::Error> {
        if self.owner != std::thread::current().id() || address.identity != 1 {
            return Err(crate::bus::mmio::owned::Error::Unavailable);
        }
        Ok(())
    }
    unsafe fn map(
        &self,
        resource: &crate::bus::mmio::owned::Resource,
        request: crate::bus::mmio::owned::MapRequest,
    ) -> Result<crate::bus::mmio::owned::InstalledMapping, crate::bus::mmio::owned::MapFailure>
    {
        use crate::bus::mmio::owned::{Error as MmioError, MapFailure};
        let parent = super::super::reservation_parent(resource)
            .ok_or(MapFailure::Unchanged(MmioError::OutsideResource))?;
        let backing = parent
            .backing()
            .downcast_ref::<NativeRoot>()
            .ok_or(MapFailure::Unchanged(MmioError::OutsideResource))?;
        if !core::ptr::eq(backing.0.as_ref(), self) || request.physical != native_span() {
            return Err(MapFailure::Unchanged(MmioError::OutsideResource));
        }
        let mut state = self.state.lock().unwrap();
        assert!(state.page.is_none());
        let page = Box::new(NativePage(core::cell::UnsafeCell::new([0; 4096])));
        let pointer = page.0.get().cast::<u8>();
        // SAFETY: bounded aligned word in this original test page, before any
        // mapping consumer is published. Set the independent pin1 input sample.
        unsafe { pointer.add(0x104).cast::<u32>().write(1 << 16) };
        state.token = request.id;
        state.maps += 1;
        state.page = Some(page);
        Ok(crate::bus::mmio::owned::InstalledMapping {
            token: request.id,
            cpu_base: core::ptr::NonNull::new(pointer).unwrap(),
            physical: request.physical,
            attribute: request.attribute,
            protection: request.protection,
        })
    }
    unsafe fn unmap(
        &self,
        request: crate::bus::mmio::owned::MapRequest,
        mapping: crate::bus::mmio::owned::InstalledMapping,
    ) -> Result<(), crate::bus::mmio::owned::Error> {
        let mut state = self.state.lock().unwrap();
        assert_eq!(request.id, state.token);
        assert_eq!(mapping.token, state.token);
        let page = state.page.as_ref().unwrap();
        assert_eq!(page.0.get().cast::<u8>(), mapping.cpu_base.as_ptr());
        // SAFETY: the production owner stopped/drained consumers before its
        // actual mapping-retirement call; this original page is still retained.
        state.restored_control = unsafe {
            page.0
                .get()
                .cast::<u8>()
                .add(0x104)
                .cast::<u32>()
                .read_volatile()
        };
        state.page.take();
        state.unmaps += 1;
        Ok(())
    }
}

#[test]
#[ignore = "requires a fresh process for the production native MMIO authority singleton"]
fn actual_native_amd_factory_opregion_retirement_and_fresh_rebind() {
    use crate::bus::gpio::native::Device;
    use crate::bus::mmio::owned::{AddressSpace, Authority, Resource as MmioResource};
    let _serial = TEST_SERIAL.lock().unwrap();
    let provider = reduced_hardware_fixture(&fixture_for(b"AMD0030", NATIVE_BASE as u32 + 0x100));
    // SAFETY: actual native OSL fixture and singleton are serialized.
    let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
    let handle = session.handle("\\GPO0").unwrap();
    let model = Arc::new(NativeMappingModel {
        owner: std::thread::current().id(),
        state: Mutex::new(NativeMappingState::default()),
    });
    let root = MmioResource::new(Box::new(NativeRoot(model.clone())));
    // SAFETY: this is the only resource suballocator for the simulated native
    // machine; it retains the original root and all actual page coverage.
    let broker = unsafe { MemoryBroker::new(vec![root]) }.unwrap();
    // SAFETY: fresh process, exclusive simulated CPU/address space, no aliases;
    // the original model implements actual owned page map/unmap effects.
    let authority = unsafe {
        Authority::activate(
            model.clone(),
            AddressSpace {
                identity: 1,
                physical_bits: 48,
                virtual_bits: 48,
            },
            Vec::new(),
        )
    }
    .unwrap();
    for cycle in 1..=2 {
        let device = DeviceResources::inspect(handle).unwrap();
        assert!(matches!(
            Device::attach(&device, "AMDI0033", &broker, &authority),
            Err(crate::bus::gpio::native::Error::Unsupported)
        ));
        let native = Device::attach(&device, "AMD0030", &broker, &authority).unwrap();
        let mut binding = Binding::install(device, Box::new(native), &[]).unwrap();
        assert_eq!(
            handle.evaluate(Some("RD01"), &[]).unwrap(),
            Some(Value::Integer(1))
        );
        handle
            .evaluate(Some("WR01"), &[Argument::Integer(1)])
            .unwrap();
        {
            let state = model.state.lock().unwrap();
            let page = state.page.as_ref().unwrap();
            // SAFETY: AML returned; the native semaphore ended actual access.
            let control = unsafe {
                page.0
                    .get()
                    .cast::<u8>()
                    .add(0x104)
                    .cast::<u32>()
                    .read_volatile()
            };
            assert_ne!(control & (1 << 22), 0);
            assert_eq!(control & (1 << 23), 0, "Preserve never enables an output");
        }
        binding.remove().unwrap();
        drop(binding);
        let state = model.state.lock().unwrap();
        assert_eq!(state.maps, cycle);
        assert_eq!(state.unmaps, cycle);
        assert_eq!(state.restored_control & !(1 << 16), 0);
    }
    session.shutdown().unwrap();
}

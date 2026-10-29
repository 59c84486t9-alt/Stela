// SPDX-License-Identifier: GPL-2.0-only
//! ACPICA namespace/Notify ownership around an independent RAM PPM peer.
//! The private DSM seam models firmware protocol effects, not ACPI activation.
extern crate std;

use super::*;
use crate::platform::acpi::{Argument, Mode, ObjectType, Reference, tests::TEST_SERIAL};
use alloc::{collections::VecDeque, rc::Rc};
use core::{
    cell::{Cell, RefCell, UnsafeCell},
    ffi::c_void,
};

#[repr(C, align(8))]
struct Ram([u8; 528]);
struct Peer {
    ram: Box<UnsafeCell<Ram>>,
    mapping_live: bool,
    mapping_drops: usize,
    dependency_drops: usize,
    dependency_reads: usize,
    cci: u32,
    controls: Vec<u64>,
    events: VecDeque<Result<[u8; 16], ()>>,
    connector_acks: usize,
    notifications: u64,
}
impl Peer {
    fn new() -> Rc<RefCell<Self>> {
        let peer = Self {
            ram: Box::new(UnsafeCell::new(Ram([0; 528]))),
            mapping_live: true,
            mapping_drops: 0,
            dependency_drops: 0,
            dependency_reads: 0,
            cci: 0,
            controls: Vec::new(),
            events: VecDeque::new(),
            connector_acks: 0,
            notifications: 0,
        };
        peer.write(0, &0x0120u16.to_le_bytes());
        Rc::new(RefCell::new(peer))
    }
    fn base(&self) -> NonNull<u8> {
        NonNull::new(self.ram.get().cast::<u8>()).unwrap()
    }
    fn write(&self, offset: usize, bytes: &[u8]) {
        assert!(offset + bytes.len() <= 528);
        for (index, byte) in bytes.iter().enumerate() {
            // SAFETY: serialized model effects use only raw pointers into this
            // stable UnsafeCell RAM; the live mapping uses no Rust references.
            unsafe {
                self.base()
                    .as_ptr()
                    .add(offset + index)
                    .write_volatile(*byte)
            };
        }
    }
    fn control(&self) -> u64 {
        // SAFETY: aligned, live scalar in the exclusively serialized peer RAM.
        unsafe { u64::from_le(self.base().as_ptr().add(8).cast::<u64>().read_volatile()) }
    }
    fn connector(&self) -> u32 {
        if self.events.is_empty() { 0 } else { 2 }
    }
    fn command(&mut self, control: u64) -> Result<(), TransportError> {
        self.controls.push(control);
        let mut payload = Vec::new();
        match control as u8 {
            1 => {
                self.events.clear();
                self.cci = 1 << 27;
                self.notifications = 0;
                return Ok(());
            }
            4 => {
                assert_ne!(control & (1 << 17), 0, "real command ACK required");
                if control & (1 << 16) != 0 {
                    assert!(self.events.pop_front().unwrap().is_ok());
                    self.connector_acks += 1;
                }
                self.cci = (1 << 29) | self.connector();
                return Ok(());
            }
            5 => self.notifications = control >> 16,
            6 => {
                payload.resize(16, 0);
                payload[4] = 1; // capability: exactly one connector
            }
            7 => {
                assert_eq!((control >> 16) & 0x7f, 1);
                payload.extend_from_slice(&[0x03, 0x00]);
            }
            0x12 => {
                assert_eq!((control >> 16) & 0x7f, 1);
                match self.events.front() {
                    Some(Ok(status)) => payload.extend_from_slice(status),
                    Some(Err(())) => return Err(TransportError::Io(0xdead)),
                    None => payload.resize(16, 0),
                }
            }
            other => panic!("unexpected raw PPM command {other:#x}"),
        }
        self.write(16, &payload);
        self.cci = (1 << 31) | ((payload.len() as u32) << 8) | self.connector();
        Ok(())
    }
}
struct Firmware(Rc<RefCell<Peer>>);
impl Dsm for Firmware {
    fn evaluate(
        &mut self,
        uuid: [u8; 16],
        revision: u64,
        function: u64,
    ) -> Result<(), TransportError> {
        assert_eq!(uuid, DSM_UUID);
        assert_eq!(revision, 1);
        let mut peer = self.0.borrow_mut();
        assert!(
            peer.mapping_live,
            "DSM must not outlive its original mapping"
        );
        match function {
            1 => {
                let control = peer.control();
                peer.command(control)
            }
            2 => {
                // Refresh publishes peer CCI into shared RAM. An ACK is
                // observed once, then firmware returns to its idle event latch.
                let cci = peer.cci;
                peer.write(4, &cci.to_le_bytes());
                if cci & (1 << 29) != 0 {
                    peer.cci = peer.connector();
                }
                Ok(())
            }
            _ => panic!("unexpected DSM function"),
        }
    }
}
struct OwnedMapping(Rc<RefCell<Peer>>, MemoryResource);
// SAFETY: the test mapping keeps the stable, aligned and serialized RAM peer;
// only raw volatile accesses share bytes with the independently acting firmware.
unsafe impl Mapping for OwnedMapping {
    fn resource(&self) -> MemoryResource {
        self.1
    }
    fn base(&self) -> NonNull<u8> {
        self.0.borrow().base()
    }
}
impl Drop for OwnedMapping {
    fn drop(&mut self) {
        let mut peer = self.0.borrow_mut();
        peer.mapping_live = false;
        peer.mapping_drops += 1;
    }
}
struct RegionContext {
    peer: Rc<RefCell<Peer>>,
    value: Cell<u8>,
}
unsafe extern "C" fn region(
    function: u32,
    address: u64,
    width: u32,
    value: *mut u64,
    context: *mut c_void,
    _: *mut c_void,
) -> acpi::Status {
    if address != 0 || width != 8 || value.is_null() {
        return acpi::BAD_PARAMETER.0;
    }
    // SAFETY: OwnedDependency keeps this exact region context until
    // ACPICA handler removal and deferred-work drain have completed.
    let context = unsafe { &*context.cast::<RegionContext>() };
    match function {
        0 => {
            context.peer.borrow_mut().dependency_reads += 1;
            // SAFETY: ACPICA provides a writable result for this callback.
            unsafe { value.write(u64::from(context.value.get())) };
        }
        1 => {
            // SAFETY: ACPICA provides the input value for this write callback.
            context.value.set(unsafe { value.read() } as u8);
        }
        _ => return acpi::BAD_PARAMETER.0,
    }
    0
}
unsafe extern "C" fn region_setup(
    _: *mut c_void,
    action: u32,
    context: *mut c_void,
    out: *mut *mut c_void,
) -> acpi::Status {
    // SAFETY: ACPICA supplies a writable region-context output. The
    // handler owner keeps context alive throughout activation/deactivation.
    unsafe {
        out.write(if action == 0 {
            context
        } else {
            core::ptr::null_mut()
        })
    };
    0
}
struct OwnedDependency<'a> {
    handle: Handle<'a>,
    context: Option<Box<RegionContext>>,
}
impl<'a> OwnedDependency<'a> {
    fn install(handle: Handle<'a>, peer: Rc<RefCell<Peer>>) -> Self {
        let mut context = Box::new(RegionContext {
            peer,
            value: Cell::new(0x5a),
        });
        // SAFETY: this owner keeps the installed stateful native EC
        // region handler through removal/draining; all test access is serialized.
        unsafe {
            handle.install_region(
                3,
                region,
                region_setup,
                (&mut *context as *mut RegionContext).cast(),
            )
        }
        .unwrap();
        assert_eq!(
            handle.evaluate(Some("READ"), &[]).unwrap(),
            Some(Value::Integer(0x5a))
        );
        Self {
            handle,
            context: Some(context),
        }
    }
}
// SAFETY: keeps the real ACPICA-installed stateful EC service on the exact
// _DEP node. Its callback is exercised through AML, not a caller flag.
unsafe impl<'a> Dependency<'a> for OwnedDependency<'a> {
    fn handle(&self) -> Handle<'a> {
        self.handle
    }
}
impl Drop for OwnedDependency<'_> {
    fn drop(&mut self) {
        let context = self.context.take().unwrap();
        // SAFETY: matches the registration; context stays live
        // through the synchronous handler removal and callback drain.
        if unsafe { self.handle.remove_region(3, region) }.is_ok() {
            context.peer.borrow_mut().dependency_drops += 1;
        } else {
            core::mem::forget(context);
        }
    }
}
#[derive(Default)]
struct Time(Cell<u64>);
impl Timer for Time {
    fn now_us(&self) -> u64 {
        self.0.get()
    }
    fn delay_us(&self, us: u64) {
        self.0.set(self.0.get() + us);
    }
}
type Bound<'a> = Attachment<'a, OwnedMapping, OwnedDependency<'a>, Time>;

fn bind<'a>(session: &'a Session, peer: Rc<RefCell<Peer>>) -> Bound<'a> {
    let device = discover(session).unwrap().pop().unwrap().unwrap();
    let mapping = OwnedMapping(peer.clone(), device.resource());
    let dependencies = device
        .dependencies()
        .iter()
        .map(|h| OwnedDependency::install(*h, peer.clone()))
        .collect();
    let aml = Aml {
        handle: device.handle,
        peer: Some(Box::new(Firmware(peer))),
    };
    Attachment::bind_with_aml(device, mapping, dependencies, Time::default(), aml).unwrap()
}

// Encode ordinary AML methods which mutate the _STA/_CRS/_DEP namespace
// objects; no test-side Device fields are overwritten to simulate revalidation.
fn namespace_mutators() -> Vec<u8> {
    let mut body = b"\\._SB_UCSI".to_vec(); // RootChar, DualNamePrefix, two NameSegs
    for (method, name) in [(b"SSTA", b"_STA"), (b"SCRS", b"_CRS"), (b"SDEP", b"_DEP")] {
        let mut terms = method.to_vec();
        terms.push(1); // one argument
        terms.extend_from_slice(&[0x70, 0x68]); // StoreOp, Arg0Op
        terms.extend_from_slice(name);
        body.extend_from_slice(&[0x14, (terms.len() + 1) as u8]);
        body.extend_from_slice(&terms);
    }
    assert!(body.len() + 1 < 64);
    let mut result = vec![0x10, (body.len() + 1) as u8]; // ScopeOp, PkgLength
    result.extend_from_slice(&body);
    // _DEP requires namespace-name references, as in Package () { EC00 }.
    // An external Argument::Reference is imported by ACPICA as RefOf; storing
    // that argument into _DEP cannot turn it into the required name reference.
    // Keep these packages in AML so CDEP/RDEP change/restore nodes:
    // Method (CDEP, 0) { Store (Package () { \_SB.HIDE }, _DEP) }
    // Method (RDEP, 0) { Store (Package () { \_SB.EC00 }, _DEP) }
    let mut named_dependencies = b"\\._SB_UCSI".to_vec();
    for (method, target) in [(b"CDEP", b"\\._SB_HIDE"), (b"RDEP", b"\\._SB_EC00")] {
        let mut terms = method.to_vec();
        terms.extend_from_slice(&[0, 0x70]); // zero arguments, StoreOp
        terms.extend_from_slice(&[0x12, 12, 1]); // PackageOp, PkgLength, one element
        terms.extend_from_slice(target);
        terms.extend_from_slice(b"_DEP");
        named_dependencies.extend_from_slice(&[0x14, (terms.len() + 1) as u8]);
        named_dependencies.extend_from_slice(&terms);
    }
    assert!(named_dependencies.len() + 1 < 64);
    result.extend_from_slice(&[0x10, (named_dependencies.len() + 1) as u8]);
    result.extend_from_slice(&named_dependencies);
    // Scope (\_SB.EC00): an EmbeddedControl region and READ method.
    // OperationRegion (ECMD, EmbeddedControl, 0, 16)
    let mut ec = b"\\._SB_EC00".to_vec();
    ec.extend_from_slice(&[0x5b, 0x80]);
    ec.extend_from_slice(b"ECMD");
    ec.extend_from_slice(&[3, 0, 0x0a, 16]);
    // Field (ECMD, ByteAcc, NoLock, Preserve) { ECBY, 8 }
    ec.extend_from_slice(&[0x5b, 0x81, 11]);
    ec.extend_from_slice(b"ECMD");
    ec.push(1);
    ec.extend_from_slice(b"ECBY");
    ec.push(8);
    // Method (READ, 0) { Return (ECBY) }
    ec.extend_from_slice(&[0x14, 11]);
    ec.extend_from_slice(b"READ");
    ec.extend_from_slice(&[0, 0xa4]);
    ec.extend_from_slice(b"ECBY");
    assert!(ec.len() + 1 < 64);
    result.extend_from_slice(&[0x10, (ec.len() + 1) as u8]);
    result.extend_from_slice(&ec);
    result
}
fn provider() -> acpi::Services {
    acpi::tests::reduced_hardware_fixture(&namespace_mutators())
}
fn fire(session: &Session) {
    session
        .handle("\\_SB.UCSI")
        .unwrap()
        .evaluate(Some("FIRE"), &[Argument::Integer(0x80)])
        .unwrap();
    // Drain the real ACPICA deferred-work provider, not a direct closure call.
    unsafe extern "C" {
        fn acpi_os_wait_events_complete();
    }
    // SAFETY: serialized process context outside an active AML frame.
    unsafe { acpi_os_wait_events_complete() };
}
fn set_resource(session: &Session, physical: u32) {
    let mut resource = vec![0x86, 9, 0, 1, 0, 0, 0, 0, 0x10, 2, 0, 0, 0x79, 0];
    resource[4..8].copy_from_slice(&physical.to_le_bytes());
    session
        .handle("\\_SB.UCSI")
        .unwrap()
        .evaluate(Some("SCRS"), &[Argument::Buffer(&resource)])
        .unwrap();
}

#[test]
fn activation_bind_start_notify_suspend_resume_and_retire() {
    let _serial = TEST_SERIAL.lock().unwrap();
    // SAFETY: fixture owns all ACPICA services; test holds singleton lock.
    let session = unsafe { Session::start(provider(), Mode::InterpreterOnly) }.unwrap();
    assert!(!session.hardware_enabled());
    assert!(matches!(discover(&session), Err(Error::HardwareInactive)));
    session.enable_hardware().unwrap();
    assert!(session.hardware_enabled());
    assert!(session.handle("\\_SB.UCSI").unwrap().hardware_active());
    assert_eq!(
        session
            .handle("\\_SB.UCSI")
            .unwrap()
            .evaluate(Some("INIC"), &[])
            .unwrap(),
        Some(Value::Integer(1))
    );
    session.enable_hardware().unwrap(); // no second C activation / _INI replay
    assert_eq!(
        session
            .handle("\\_SB.UCSI")
            .unwrap()
            .evaluate(Some("INIC"), &[])
            .unwrap(),
        Some(Value::Integer(1))
    );
    let peer = Peer::new();
    let mut attachment = bind(&session, peer.clone());
    assert_eq!(attachment.state(), State::Bound);
    assert!(peer.borrow().controls.is_empty());
    assert_eq!(peer.borrow().dependency_reads, 1);
    attachment.start().unwrap();
    assert_eq!(attachment.state(), State::Running);
    assert!(attachment.controller().initialized());
    assert_ne!(peer.borrow().notifications, 0);
    fire(&session);
    assert!(attachment.needs_service());
    assert!(attachment.service(1).unwrap().changes.is_empty());
    attachment.suspend().unwrap();
    assert_eq!(attachment.state(), State::Suspended);
    assert_eq!(peer.borrow().notifications, 0);
    assert!(!attachment.controller().initialized());
    attachment.start().unwrap();
    attachment.detach().unwrap();
    assert_eq!(attachment.state(), State::Retired);
    assert_eq!(peer.borrow().mapping_drops, 1);
    assert_eq!(peer.borrow().dependency_drops, 1);
    attachment.detach().unwrap();
    drop(attachment);
    session.shutdown().unwrap();
}

#[test]
fn resource_changes_refuse_commands_and_retirement() {
    let _serial = TEST_SERIAL.lock().unwrap();
    // SAFETY: fixture owns all ACPICA services; serialized singleton.
    let session = unsafe { Session::start(provider(), Mode::Hardware) }.unwrap();
    assert!(session.hardware_enabled());
    let peer = Peer::new();
    let mut attachment = bind(&session, peer.clone());
    let handle = session.handle("\\_SB.UCSI").unwrap();
    let ec = session.handle("\\_SB.EC00").unwrap();
    assert_eq!(attachment.device.dependencies(), &[ec]);
    assert_eq!(
        handle.evaluate(Some("_DEP"), &[]).unwrap(),
        Some(Value::Package(vec![Value::Reference(Reference {
            handle: ec,
            actual_type: ObjectType::DEVICE
        })]))
    );
    handle
        .evaluate(Some("SSTA"), &[Argument::Integer(0)])
        .unwrap();
    assert_eq!(attachment.start(), Err(Error::DeviceUnavailable(0)));
    assert!(peer.borrow().controls.is_empty());
    handle
        .evaluate(Some("SSTA"), &[Argument::Integer(15)])
        .unwrap();
    set_resource(&session, 0xa000);
    assert_eq!(attachment.start(), Err(Error::ResourcesChanged));
    assert!(peer.borrow().controls.is_empty());
    set_resource(&session, 0x9000);
    attachment.start().unwrap();
    let before = peer.borrow().controls.len();
    handle
        .evaluate(Some("SDEP"), &[Argument::Package(&[])])
        .unwrap();
    assert_eq!(
        handle.evaluate(Some("_DEP"), &[]).unwrap(),
        Some(Value::Package(vec![]))
    );
    assert_eq!(attachment.detach(), Err(Error::ResourcesChanged));
    assert_eq!(peer.borrow().controls.len(), before);
    assert_eq!(peer.borrow().mapping_drops, 0);
    assert_eq!(peer.borrow().dependency_drops, 0);
    // A different well-formed firmware dependency must also refuse retirement;
    // a valid namespace reference alone supplies no replacement native owner.
    handle.evaluate(Some("CDEP"), &[]).unwrap();
    assert_eq!(
        handle.evaluate(Some("_DEP"), &[]).unwrap(),
        Some(Value::Package(vec![Value::Reference(Reference {
            handle: session.handle("\\_SB.HIDE").unwrap(),
            actual_type: ObjectType::DEVICE,
        })]))
    );
    assert_eq!(attachment.detach(), Err(Error::ResourcesChanged));
    assert_eq!(peer.borrow().controls.len(), before);
    assert_eq!(peer.borrow().mapping_drops, 0);
    assert_eq!(peer.borrow().dependency_drops, 0);
    handle.evaluate(Some("RDEP"), &[]).unwrap();
    assert_eq!(
        handle.evaluate(Some("_DEP"), &[]).unwrap(),
        Some(Value::Package(vec![Value::Reference(Reference {
            handle: ec,
            actual_type: ObjectType::DEVICE
        })]))
    );
    attachment.detach().unwrap();
    assert_eq!(peer.borrow().mapping_drops, 1);
    assert_eq!(peer.borrow().dependency_drops, 1);
    drop(attachment);
    session.shutdown().unwrap();
}

#[test]
fn acknowledged_first_event_survives_later_service_failure() {
    let _serial = TEST_SERIAL.lock().unwrap();
    // SAFETY: fixture owns all ACPICA services; serialized singleton.
    let session = unsafe { Session::start(provider(), Mode::Hardware) }.unwrap();
    let peer = Peer::new();
    let mut attachment = bind(&session, peer.clone());
    attachment.start().unwrap();
    let mut status = [0; 16];
    status[0] = 0x40;
    status[2] = 0x08;
    {
        let mut hardware = peer.borrow_mut();
        hardware.events.extend([Ok(status), Err(())]);
        hardware.cci = 2;
    }
    fire(&session);
    let report = attachment.service(2).unwrap();
    assert_eq!(report.changes.len(), 1);
    assert_eq!(report.changes[0].status.raw(), &status);
    assert!(matches!(
        report.error,
        Some(Error::Ucsi(UcsiError::Transport { .. }))
    ));
    assert_eq!(peer.borrow().connector_acks, 1);
    assert_eq!(peer.borrow().events.len(), 1);
    assert_eq!(attachment.state(), State::Faulted);
    assert!(attachment.needs_service());
    assert_eq!(peer.borrow().mapping_drops, 0);
    attachment.detach().unwrap();
    drop(attachment);
    session.shutdown().unwrap();
}

#[test]
fn failed_notify_removal_permanently_quarantines_detach_and_drop() {
    let _serial = TEST_SERIAL.lock().unwrap();
    // SAFETY: fixture owns all ACPICA services; serialized singleton.
    for running in [false, true] {
        // SAFETY: independent fixture/C core for each quarantined owner.
        let session = unsafe { Session::start(provider(), Mode::Hardware) }.unwrap();
        let peer = Peer::new();
        let mut attachment = bind(&session, peer.clone());
        if running {
            attachment.start().unwrap();
        }
        attachment
            .notification
            .as_ref()
            .unwrap()
            .remove_from_core_without_retiring_for_test()
            .unwrap();
        let first = attachment.detach().unwrap_err();
        assert!(matches!(first, Error::NotificationRemovalUncertain(_)));
        assert_eq!(attachment.state(), State::Quarantined);
        let before = peer.borrow().controls.len();
        assert_eq!(attachment.detach(), Err(first));
        assert_eq!(peer.borrow().controls.len(), before);
        assert!(attachment.start().is_err());
        drop(attachment);
        assert!(peer.borrow().mapping_live);
        assert_eq!(peer.borrow().mapping_drops, 0);
        assert_eq!(peer.borrow().dependency_drops, 0);
        session.shutdown().unwrap();
    }
    // A failed removal first encountered by Drop must also keep owners when
    // Bound or Suspended, which otherwise permit ordinary resource release.
    for suspended in [false, true] {
        // SAFETY: independent fixture/C core for each quarantined owner.
        let session = unsafe { Session::start(provider(), Mode::Hardware) }.unwrap();
        let peer = Peer::new();
        let mut attachment = bind(&session, peer.clone());
        if suspended {
            attachment.start().unwrap();
            attachment.suspend().unwrap();
        }
        attachment
            .notification
            .as_ref()
            .unwrap()
            .remove_from_core_without_retiring_for_test()
            .unwrap();
        drop(attachment);
        assert!(peer.borrow().mapping_live);
        assert_eq!(peer.borrow().mapping_drops, 0);
        assert_eq!(peer.borrow().dependency_drops, 0);
        session.shutdown().unwrap();
    }
}

// SPDX-License-Identifier: MIT
// Included by acpi::tests to exercise actual native AML and EC operation regions.
#[test]
fn native_ec_discovery_consumed_queries_and_reentrant_operation_regions() {
    use crate::platform::ec::{
        self,
        discovery::native::{Device, DiscoveryError},
    };
    use core::sync::atomic::AtomicU64;
    use std::sync::{Arc, Mutex};
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
    fn method(id: &[u8; 4], instructions: &[u8]) -> Vec<u8> {
        let mut body = id.to_vec();
        body.push(8); // serialized, no arguments
        body.extend(instructions);
        pkg(&[0x14], &body)
    }
    // The byte peripheral obeys the EC's command/input/output grammar. Its
    // immediate IBF consumption is allowed by the protocol, not a driver echo.
    struct Registers {
        ram: u8,
        command: u8,
        address: Option<u8>,
        output: Option<u8>,
        queries: std::collections::VecDeque<u8>,
        log: Vec<u8>,
    }
    impl ec::Registers for Registers {
        fn status(&mut self) -> Result<u8, ec::IoError> {
            Ok(if self.output.is_some() { 1 } else { 0 }
                | if self.queries.is_empty() { 0 } else { 0x20 })
        }
        fn command(&mut self, value: u8) -> Result<(), ec::IoError> {
            assert!(self.output.is_none());
            self.log.push(value);
            self.command = value;
            self.address = None;
            if value == 0x84 {
                self.output = Some(self.queries.pop_front().unwrap_or(0));
            } else {
                assert!(matches!(value, 0x80 | 0x81));
            }
            Ok(())
        }
        fn read_data(&mut self) -> Result<u8, ec::IoError> {
            Ok(self.output.take().expect("actual pending output"))
        }
        fn write_data(&mut self, value: u8) -> Result<(), ec::IoError> {
            if self.address.is_none() {
                assert_eq!(value, 0);
                self.address = Some(value);
                if self.command == 0x80 {
                    self.output = Some(self.ram);
                }
            } else {
                assert_eq!(self.command, 0x81);
                self.ram = value;
            }
            Ok(())
        }
    }
    struct Time(AtomicU64);
    impl crate::bus::i2c::Timer for Time {
        fn now_us(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
        fn relax(&self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    type Controller = ec::Ec<Registers, Time, ec::NoGlobalLock>;
    unsafe extern "C" fn setup(
        _: *mut c_void,
        action: u32,
        context: *mut c_void,
        out: *mut *mut c_void,
    ) -> Status {
        // SAFETY: ACPICA supplies a live region-context output; the boxed
        // controller below survives native handler removal and work drain.
        unsafe {
            out.write(if action == 0 {
                context
            } else {
                ptr::null_mut()
            });
        }
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
        if context.is_null() || value.is_null() {
            return BAD_PARAMETER.0;
        }
        // SAFETY: setup returned the retained exact controller context.
        let controller = unsafe { &*context.cast::<Mutex<Controller>>() };
        let mut controller = controller.lock().unwrap();
        match function {
            0 => match controller.read_region(address, width) {
                Ok(data) => {
                    unsafe {
                        value.write(data);
                    }
                    0
                }
                Err(_) => SUPPORT.0,
            },
            1 => match controller.write_region(address, width, unsafe { value.read() }) {
                Ok(()) => 0,
                Err(_) => SUPPORT.0,
            },
            _ => BAD_PARAMETER.0,
        }
    }

    let _serial = TEST_SERIAL.lock().unwrap();
    let mut device = b"EC00".to_vec();
    device.extend(name(b"_HID", b"\x0dPNP0C09\0"));
    let resources = [
        0x47, 1, 0x62, 0, 0x62, 0, 1, 1, 0x47, 1, 0x66, 0, 0x66, 0, 1, 1, 0x79, 0,
    ];
    let mut buffer = vec![0x0a, resources.len() as u8];
    buffer.extend(resources);
    device.extend(name(b"_CRS", &pkg(&[0x11], &buffer)));
    device.extend(name(b"_GLK", &[0]));
    device.extend(name(b"_GPE", &[0x0a, 0x17]));
    device.extend(name(b"CNT0", &[0]));
    // OperationRegion(ECRG, EmbeddedControl, Zero, One)
    device.extend(b"\x5b\x80ECRG\x03\x00\x01");
    device.extend(pkg(b"\x5b\x81", b"ECRG\x01BYTE\x08"));
    device.extend(method(b"_QAB", b"\x70\x0a\x5aBYTE\x75CNT0\xa4\x00"));
    // Real effects precede an AML divide-by-zero exception.
    device.extend(method(
        b"_QAC",
        b"\x70\x0a\xa5BYTE\x75CNT0\x78\x01\x00\x00\x00\xa4\x00",
    ));
    let mut aml = pkg(b"\x5b\x82", &device);
    for (id, failing_method) in [
        (b"ENON", None),
        (b"EGLK", Some(b"_GLK")),
        (b"EGPE", Some(b"_GPE")),
    ] {
        let mut other = id.to_vec();
        other.extend(name(b"_HID", b"\x0dPNP0C09\0"));
        other.extend(name(b"_CRS", &pkg(&[0x11], &buffer)));
        if let Some(failing_method) = failing_method {
            if failing_method == b"_GPE" {
                other.extend(name(b"_GLK", &[1]));
            }
            // Existing firmware AML fails AE_NOT_FOUND resolving NOEX.
            // Resolving the _GLK/_GPE child itself must still succeed.
            other.extend(method(failing_method, b"\xa4NOEX"));
        }
        aml.extend(pkg(b"\x5b\x82", &other));
    }
    let mut dsdt = table(b"DSDT", 36 + aml.len(), 2);
    dsdt[36..].copy_from_slice(&aml);
    checksum(&mut dsdt, 9);
    let (provider, counts) = fixture_dsdt(dsdt);
    let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
    let handles = session.devices("PNP0C09").unwrap();
    assert_eq!(handles.len(), 4);
    let absent = Device::discover(session.handle("\\ENON").unwrap()).unwrap();
    assert!(!absent.global_lock);
    assert_eq!(absent.gpe, None);
    for (path, name) in [("\\EGLK", "_GLK"), ("\\EGPE", "_GPE")] {
        let device = session.handle(path).unwrap();
        assert_eq!(
            device.child(name).unwrap().evaluate(None, &[]),
            Err(Error(5))
        );
        assert_eq!(
            Device::discover(device),
            Err(DiscoveryError::Firmware(name, Error(5)))
        );
    }
    let handle = session.handle("\\EC00").unwrap();
    let found = Device::discover(handle).unwrap();
    assert_eq!(found.ports.data, 0x62);
    assert_eq!(found.ports.command, 0x66);
    assert!(!found.global_lock);
    assert_eq!(found.gpe, Some(0x17));
    let registers = Registers {
        ram: 0,
        command: 0,
        address: None,
        output: None,
        queries: [0xab, 0xac, 0xad].into(),
        log: Vec::new(),
    };
    let controller = Arc::new(Mutex::new(
        ec::Ec::new(
            registers,
            Time(AtomicU64::new(0)),
            // SAFETY: authored `_GLK` is zero and this model has no competing owner.
            unsafe { ec::NoGlobalLock::exclusively_owned() },
            ec::Config {
                polling_guard_us: 0,
                ..ec::Config::default()
            },
        )
        .unwrap(),
    ));
    // SAFETY: actual callbacks execute the EC core, whose sole boxed owner is
    // retained until explicit removal below; no other handler accesses it.
    unsafe { handle.install_region(3, region, setup, Arc::as_ptr(&controller).cast_mut().cast()) }
        .unwrap();
    for (value, success) in [(0xab, true), (0xac, false), (0xad, false)] {
        // Deliberately end the owner guard before AML. A handler-issued EC
        // transaction would otherwise deadlock on its same native controller.
        let receipt = controller.lock().unwrap().poll_query().unwrap().unwrap();
        assert_eq!(receipt.value(), value);
        let result = receipt.evaluate(handle);
        assert_eq!(result.is_ok(), success);
        if let Err(error) = result {
            assert_eq!(error.query, value);
        }
    }
    assert!(controller.lock().unwrap().poll_query().unwrap().is_none());
    assert_eq!(
        handle.evaluate(Some("CNT0"), &[]).unwrap(),
        Some(Value::Integer(2))
    );
    // Direct native region read proves the second method's effect survived its
    // exception; evaluating its old consumed event was never automatically retried.
    let mut value = 0;
    assert_eq!(
        unsafe {
            region(
                0,
                0,
                8,
                &mut value,
                ptr::null_mut(),
                Arc::as_ptr(&controller).cast_mut().cast(),
            )
        },
        0
    );
    assert_eq!(value, 0xa5);
    unsafe { handle.remove_region(3, region) }.unwrap();
    drop(controller);
    session.shutdown().unwrap();
    assert!(counts.destroyed.load(Ordering::SeqCst));
    assert_eq!(counts.allocations.load(Ordering::SeqCst), 0);
    assert_eq!(counts.mappings.load(Ordering::SeqCst), 0);
}

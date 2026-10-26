// SPDX-License-Identifier: MIT
// Included by acpi::tests: actual native AML, never a synthetic Handle backend.
#[test]
fn native_battery_linux_status_default_information_fallback_and_trip_failures() {
    use crate::platform::battery::{Battery, Error as BatteryError, Method};
    fn pkg(opcode: &[u8], body: &[u8]) -> Vec<u8> {
        let mut bytes = opcode.to_vec();
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
    fn method(id: &[u8; 4], arguments: u8, code: &[u8]) -> Vec<u8> {
        let mut body = id.to_vec();
        body.push(arguments | 8);
        body.extend(code);
        pkg(&[0x14], &body)
    }
    fn information() -> Vec<u8> {
        let mut body = vec![13];
        for number in [1u32, 5000, 4500, 1, 12000, 500, 200, 1, 2] {
            body.push(0x0c);
            body.extend(number.to_le_bytes());
        }
        for text in [b"Battery".as_slice(), b"serial", b"LION", b"OEM"] {
            body.push(0x0d);
            body.extend(text);
            body.push(0);
        }
        pkg(&[0x12], &body)
    }
    let _serial = TEST_SERIAL.lock().unwrap();
    let mut aml = Vec::new();
    for id in [
        b"BNUL", b"BSTA", b"BEVL", b"BBIF", b"BBIX", b"BERR", b"BFAL",
    ] {
        let mut device = id.to_vec();
        device.extend(name(b"_HID", b"\x0dPNP0C0A\0"));
        for counter in [b"BCNT", b"SCNT", b"XCNT", b"ALRM"] {
            device.extend(name(counter, &[0]));
        }
        device.extend(name(b"BIFV", &information()));
        let mut state = vec![4];
        for value in [1u32, 100, 3000, 12000] {
            state.push(0x0c);
            state.extend(value.to_le_bytes());
        }
        device.extend(name(b"BSTV", &pkg(&[0x12], &state)));
        device.extend(method(b"_BST", 0, b"\x75SCNT\xa4BSTV"));
        device.extend(method(
            b"_BIF",
            0,
            if matches!(id, b"BERR" | b"BFAL") {
                b"\x75BCNT\xa4NOEX"
            } else {
                b"\x75BCNT\xa4BIFV"
            },
        ));
        if id == b"BSTA" {
            device.extend(method(b"_STA", 0, b"\x75XCNT\xa4NOEX"));
        } else if id == b"BEVL" {
            device.extend(method(b"_STA", 0, b"\x75XCNT\xa4\x78\x01\x00\x00\x00"));
        } else if id != b"BNUL" {
            device.extend(name(b"_STA", &[0x0a, 0x1f]));
        }
        if matches!(id, b"BBIX" | b"BFAL") {
            device.extend(method(b"_BIX", 0, b"\x75XCNT\xa4NOEX"));
            // Actual alarm side effect followed by AE_NOT_FOUND during AML.
            device.extend(method(b"_BTP", 1, b"\x70\x68ALRM\xa4NOEX"));
        }
        aml.extend(pkg(&[0x5b, 0x82], &device));
    }
    let mut dsdt = table(b"DSDT", 36 + aml.len(), 2);
    dsdt[36..].copy_from_slice(&aml);
    checksum(&mut dsdt, 9);
    let (provider, counts) = fixture_dsdt(dsdt);
    let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
    fn get<'a>(handle: Handle<'a>, name: &str) -> Value<'a> {
        handle.evaluate(Some(name), &[]).unwrap().unwrap()
    }

    let absent = session.handle("\\BNUL").unwrap();
    assert_eq!(absent.child("_STA"), Err(Error(5)));
    let mut battery = Battery::attach(absent).unwrap();
    assert_eq!(battery.refresh(), Ok(None));
    assert_eq!(battery.status_fallback(), Some(Error(5)));
    assert_eq!(battery.information_fallback(), None);
    assert_eq!(get(absent, "BCNT"), Value::Integer(0));
    assert_eq!(get(absent, "SCNT"), Value::Integer(0));
    assert_eq!(battery.set_trip(1), Err(BatteryError::TripUnsupported));

    let failed_status = session.handle("\\BSTA").unwrap();
    assert!(failed_status.child("_STA").is_ok());
    let mut battery = Battery::attach(failed_status).unwrap();
    // Match Linux's AE_NOT_FOUND default even when existing AML executed and
    // failed. The default 0x0f has no battery-present bit, so no data is invented.
    assert_eq!(battery.refresh(), Ok(None));
    assert_eq!(battery.status_fallback(), Some(Error(5)));
    assert_eq!(get(failed_status, "XCNT"), Value::Integer(1));
    assert_eq!(get(failed_status, "BCNT"), Value::Integer(0));
    assert_eq!(get(failed_status, "SCNT"), Value::Integer(0));
    assert!(battery.snapshot().is_none());

    let failed_execution = session.handle("\\BEVL").unwrap();
    let failure = failed_execution.evaluate(Some("_STA"), &[]).unwrap_err();
    assert_ne!(failure, Error(5));
    let mut battery = Battery::attach(failed_execution).unwrap();
    assert_eq!(
        battery.refresh(),
        Err(BatteryError::Firmware(Method::Status, failure))
    );
    assert_eq!(battery.status_fallback(), None);
    assert_eq!(get(failed_execution, "XCNT"), Value::Integer(2));
    assert_eq!(get(failed_execution, "BCNT"), Value::Integer(0));
    assert_eq!(get(failed_execution, "SCNT"), Value::Integer(0));

    let legacy = session.handle("\\BBIF").unwrap();
    assert_eq!(legacy.child("_BIX"), Err(Error(5)));
    assert_eq!(legacy.child("_BTP"), Err(Error(5)));
    let mut battery = Battery::attach(legacy).unwrap();
    assert!(
        battery
            .refresh()
            .unwrap()
            .unwrap()
            .information
            .extended
            .is_none()
    );
    assert_eq!(battery.information_fallback(), None);
    assert_eq!(battery.status_fallback(), None);
    assert_eq!(battery.set_trip(500), Err(BatteryError::TripUnsupported));
    assert_eq!(get(legacy, "BCNT"), Value::Integer(1));

    let extended = session.handle("\\BBIX").unwrap();
    let mut battery = Battery::attach(extended).unwrap();
    assert_eq!(get(extended, "XCNT"), Value::Integer(0)); // presence tests do not execute
    assert_eq!(get(extended, "ALRM"), Value::Integer(0));
    let snapshot = battery.refresh().unwrap().unwrap();
    assert!(snapshot.information.extended.is_none());
    assert_eq!(snapshot.information.design_capacity, Some(5000));
    assert_eq!(battery.information_fallback(), Some(Error(5)));
    assert_eq!(get(extended, "XCNT"), Value::Integer(1));
    assert_eq!(get(extended, "BCNT"), Value::Integer(1));
    assert_eq!(
        battery.set_trip(600),
        Err(BatteryError::Firmware(Method::Trip, Error(5)))
    );
    assert_eq!(get(extended, "ALRM"), Value::Integer(600));
    assert_eq!(battery.acknowledged_trip(), None);
    assert!(battery.snapshot().is_none());
    assert_eq!(battery.information_fallback(), Some(Error(5)));

    let failed_info = session.handle("\\BERR").unwrap();
    let mut battery = Battery::attach(failed_info).unwrap();
    assert_eq!(
        battery.refresh(),
        Err(BatteryError::Firmware(Method::Information, Error(5)))
    );
    assert_eq!(battery.information_fallback(), None);
    assert!(battery.snapshot().is_none());
    assert_eq!(get(failed_info, "BCNT"), Value::Integer(1));
    assert_eq!(get(failed_info, "SCNT"), Value::Integer(0));
    let failed_both = session.handle("\\BFAL").unwrap();
    let mut battery = Battery::attach(failed_both).unwrap();
    assert_eq!(
        battery.refresh(),
        Err(BatteryError::Firmware(Method::Information, Error(5)))
    );
    assert_eq!(battery.information_fallback(), Some(Error(5)));
    assert!(battery.snapshot().is_none());
    assert_eq!(get(failed_both, "XCNT"), Value::Integer(1));
    assert_eq!(get(failed_both, "BCNT"), Value::Integer(1));
    assert_eq!(get(failed_both, "SCNT"), Value::Integer(0));
    session.shutdown().unwrap();
    assert!(counts.destroyed.load(Ordering::SeqCst));
    assert_eq!(counts.allocations.load(Ordering::SeqCst), 0);
    assert_eq!(counts.mappings.load(Ordering::SeqCst), 0);
}

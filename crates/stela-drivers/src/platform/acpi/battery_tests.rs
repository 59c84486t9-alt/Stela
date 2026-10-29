// SPDX-License-Identifier: MIT
// Authored AML protocol fixture, evaluated by the real native ACPICA interpreter.
#[test]
fn native_control_method_battery_refresh_alarm_fallback_and_removal() {
    use crate::platform::battery::{Battery, Error as BatteryError, Method, Unit};
    fn integer(value: u32) -> Vec<u8> {
        let mut bytes = vec![0x0c]; // DWordConst
        bytes.extend(value.to_le_bytes());
        bytes
    }
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
    fn name(name: &[u8; 4], value: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x08]; // Name
        bytes.extend(name);
        bytes.extend(value);
        bytes
    }
    fn method(name: &[u8; 4], arguments: u8, instructions: &[u8]) -> Vec<u8> {
        let mut body = name.to_vec();
        body.push(arguments | 8); // serialized
        body.extend(instructions);
        pkg(&[0x14], &body)
    }
    fn info(extended: bool) -> Vec<u8> {
        let mut numbers = vec![1, 5000, 4500, 1, 12000, 500, 200];
        if extended {
            numbers.insert(0, 0);
            numbers.extend([42, 95000, 1000, 100, 500, 50]);
        }
        numbers.extend([1, 2]);
        let mut body = vec![if extended { 20 } else { 13 }];
        for value in numbers { body.extend(integer(value)); }
        for text in [b"Battery".as_slice(), b"serial", b"LION", b"OEM"] {
            body.push(0x0d); // String
            body.extend(text);
            body.push(0);
        }
        pkg(&[0x12], &body)
    }
    let _serial = TEST_SERIAL.lock().unwrap();
    let mut device = b"BAT0".to_vec();
    device.extend(name(b"_HID", b"\x0dPNP0C0A\0"));
    for (field, value) in [(b"STAT", 0x1f), (b"FALL", 0), (b"RACE", 0),
        (b"ALRM", 0), (b"BCNT", 0), (b"SCNT", 0)] {
        device.extend(name(field, &integer(value)));
    }
    device.extend(name(b"BIXV", &info(true)));
    device.extend(name(b"BIFV", &info(false)));
    let mut state = vec![4];
    for value in [1, 0xff9c, 3000, 12000] { state.extend(integer(value)); }
    device.extend(name(b"BSTV", &pkg(&[0x12], &state)));
    device.extend(method(b"_STA", 0, b"\xa4STAT")); // Return(STAT)
    let mut bix = pkg(&[0xa0], b"FALL\xa4\x78\x01\x00\x00\x00");
    bix.extend(b"\xa4BIXV");
    device.extend(method(b"_BIX", 0, &bix));
    device.extend(method(b"_BIF", 0, b"\x75BCNT\xa4BIFV"));
    let mut bst = b"\x75SCNT".to_vec();
    bst.extend(pkg(&[0xa0], b"RACE\x70\x0a\x0fSTAT"));
    bst.extend(b"\xa4BSTV");
    device.extend(method(b"_BST", 0, &bst));
    let mut trip = b"\x70\x68ALRM".to_vec(); // Store(Arg0, ALRM)
    trip.extend(pkg(&[0xa0], b"FALL\xa4\x78\x01\x00\x00\x00"));
    trip.extend([0xa4, 0]);
    device.extend(method(b"_BTP", 1, &trip));
    for (setter, field) in [(b"SSTA", b"STAT"), (b"SFAL", b"FALL"),
        (b"SRAC", b"RACE"), (b"MBIX", b"BIXV")] {
        let mut code = vec![if setter == b"MBIX" { 0x9d } else { 0x70 }, 0x68];
        code.extend(field);
        code.extend([0xa4, 0]);
        device.extend(method(setter, 1, &code));
    }
    let aml = pkg(&[0x5b, 0x82], &device);
    let mut dsdt = table(b"DSDT", 36 + aml.len(), 2);
    dsdt[36..].copy_from_slice(&aml);
    checksum(&mut dsdt, 9);
    let (provider, counts) = fixture_dsdt(dsdt);
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
    let handles = session.devices("PNP0C0A").unwrap();
    assert_eq!(handles.len(), 1);
    let handle = handles[0];
    let set = |method: &str, value: u64| {
        handle.evaluate(Some(method), &[Argument::Integer(value)]).unwrap();
    };
    let get = |field: &str| handle.evaluate(Some(field), &[]).unwrap().unwrap();
    let mut battery = Battery::attach(handle).unwrap();
    let snapshot = battery.refresh().unwrap().unwrap();
    assert_eq!(snapshot.information.unit, Unit::Charge);
    assert_eq!(snapshot.information.extended.as_ref().unwrap().cycle_count, Some(42));
    assert_eq!(snapshot.state.rate, Some(100));
    battery.set_trip(500).unwrap();
    assert_eq!(battery.acknowledged_trip(), Some(500));
    assert_eq!(get("ALRM"), Value::Integer(500));
    set("SFAL", 1);
    assert!(matches!(battery.set_trip(600), Err(BatteryError::Firmware(Method::Trip, _))));
    assert_eq!(get("ALRM"), Value::Integer(600)); // error follows actual AML effect
    assert_eq!(battery.acknowledged_trip(), None);
    assert!(battery.refresh().unwrap().unwrap().information.extended.is_none());
    assert_eq!(get("BCNT"), Value::Integer(1));
    set("SFAL", 0);
    set("MBIX", 0);
    assert_eq!(battery.refresh(), Err(BatteryError::Malformed(Method::ExtendedInformation)));
    assert!(battery.snapshot().is_none());
    assert_eq!(get("BCNT"), Value::Integer(1)); // malformed BIX is not fallback
    set("SFAL", 1); // restores working BIF fallback
    set("SRAC", 1);
    assert_eq!(battery.refresh(), Err(BatteryError::PresenceChanged));
    assert!(battery.snapshot().is_none());
    let reads = get("SCNT");
    assert_eq!(battery.refresh(), Ok(None));
    assert_eq!(get("SCNT"), reads); // absent battery issues no state read
    assert_eq!(battery.set_trip(0), Err(BatteryError::NotPresent));
    session.shutdown().unwrap();
    assert!(counts.destroyed.load(Ordering::SeqCst));
    assert_eq!(counts.allocations.load(Ordering::SeqCst), 0);
    assert_eq!(counts.mappings.load(Ordering::SeqCst), 0);
}

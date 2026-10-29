//! External reference metadata from real ACPICA and bounded wire inputs.
use super::*;

fn reference_fixture() -> (Services, Arc<Counts>) {
    let mut dsdt = include_bytes!("../fixtures/namespace.aml").to_vec();
    // PowerResource(PR00, 0, 0) {}; Name(PREF, Package(){ PR00 });
    // Method(ECHO, 1) { Return(Arg0) }; TYPE returns ObjectType(Arg0).
    // These are ordinary AML namespace objects,
    // not a substituted interpreter or firmware result.
    dsdt.extend_from_slice(&[
        0x5b, 0x84, 8, b'P', b'R', b'0', b'0', 0, 0, 0, 0x08, b'P', b'R', b'E', b'F', 0x12, 6, 1,
        b'P', b'R', b'0', b'0', 0x14, 8, b'E', b'C', b'H', b'O', 1, 0xa4, 0x68,
    ]);
    dsdt.extend_from_slice(&[0x14, 9, b'T', b'Y', b'P', b'E', 1, 0xa4, 0x8e, 0x68]);
    // Name(CNT0, Zero); Method(RUN0, 1) { Store(Arg0, CNT0); Return(PR00) }
    dsdt.extend_from_slice(&[
        0x08, b'C', b'N', b'T', b'0', 0, 0x14, 17, b'R', b'U', b'N', b'0', 1, 0x70, 0x68, b'C',
        b'N', b'T', b'0', 0xa4, b'P', b'R', b'0', b'0',
    ]);
    let length = dsdt.len() as u32;
    dsdt[4..8].copy_from_slice(&length.to_le_bytes());
    checksum(&mut dsdt, 9);
    fixture_dsdt(dsdt)
}

#[test]
fn device_and_power_references_keep_actual_type_through_arguments() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let (services, counts) = reference_fixture();
    // SAFETY: this serialized fixture transfers its complete provider
    // to the one real ACPICA Session, which outlives all handles/results below.
    let session = unsafe { Session::start(services, Mode::InterpreterOnly) }.unwrap();
    let Some(Value::Package(dependencies)) = session
        .handle("\\_SB.UCSI")
        .unwrap()
        .evaluate(Some("_DEP"), &[])
        .unwrap()
    else {
        panic!("actual _DEP package")
    };
    let Value::Reference(device) = dependencies[0] else {
        panic!("actual Device reference")
    };
    assert_eq!(device.actual_type, ObjectType::DEVICE);
    assert_eq!(device.handle, session.handle("\\_SB.EC00").unwrap());
    let Some(Value::Package(resources)) = session
        .handle("\\PREF")
        .unwrap()
        .evaluate(None, &[])
        .unwrap()
    else {
        panic!("actual power resource package")
    };
    let Value::Reference(power) = resources[0] else {
        panic!("actual PowerResource reference")
    };
    assert_eq!(power.actual_type, ObjectType::POWER);
    assert_eq!(power.handle, session.handle("\\PR00").unwrap());
    for (reference, echo_error) in [(device, Error(8)), (power, SUPPORT)] {
        let arguments = Arguments::new(&[Argument::Reference(reference)], &session, 0).unwrap();
        assert_eq!(arguments.objects[0].kind, 0x14);
        assert_eq!(arguments.objects[0].length, reference.actual_type.raw());
        assert_eq!(arguments.objects[0].payload, reference.handle.raw as u64);
        assert_eq!(
            session
                .handle("\\TYPE")
                .unwrap()
                .evaluate(None, &[Argument::Reference(reference)])
                .unwrap(),
            Some(Value::Integer(u64::from(reference.actual_type.raw())))
        );
        // ACPICA cannot export the Device RefOf (AE_TYPE). A concrete returned
        // PowerResource remains explicitly unsupported by this facade (SUPPORT).
        // Preserve both boundaries rather than inventing a successful handle.
        assert_eq!(
            session
                .handle("\\ECHO")
                .unwrap()
                .evaluate(None, &[Argument::Reference(reference)])
                .err(),
            Some(echo_error)
        );
    }
    drop(session);
    assert!(counts.destroyed.load(Ordering::SeqCst));
    assert_eq!(counts.allocations.load(Ordering::SeqCst), 0);
    assert_eq!(counts.mappings.load(Ordering::SeqCst), 0);
}

#[test]
fn wire_reference_metadata_retains_unrecognized_codes() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let (services, _) = reference_fixture();
    // SAFETY: the fixture owns all callbacks and mappings through this real Session.
    let session = unsafe { Session::start(services, Mode::InterpreterOnly) }.unwrap();
    let handle = session.handle("\\PR00").unwrap();
    let guard = session.guard().unwrap();
    // A modeled external type code, around a validated namespace node.
    // This proves lossless wire conversion, not that ACPICA emits unknown types.
    let raw = RawObject {
        kind: 0x14,
        length: 0xfedc_ba98,
        payload: handle.raw as u64,
        extra: 0,
    };
    let start = core::ptr::addr_of!(raw) as usize;
    let mut budget = 1;
    // SAFETY: the live RawObject is wholly inside the supplied byte range;
    // its handle belongs to this guarded Session and no deletion/evaluation runs.
    let value = unsafe {
        read_value(
            &raw,
            start,
            start + size_of::<RawObject>(),
            &session,
            &guard,
            &mut budget,
            0,
        )
    }
    .unwrap();
    let Value::Reference(reference) = value else {
        panic!("external reference")
    };
    assert_eq!(reference.handle, handle);
    assert_eq!(reference.actual_type.raw(), 0xfedc_ba98);
    let arguments = Arguments::new(&[Argument::Reference(reference)], &session, 0).unwrap();
    assert_eq!(arguments.objects[0].length, 0xfedc_ba98);
    assert_eq!(budget, 0);
}

#[test]
fn null_output_executes_side_effects_without_converting_returned_power_resource() {
    let _serial = TEST_SERIAL.lock().unwrap();
    let (services, counts) = reference_fixture();
    // SAFETY: this serialized provider keeps the real tables, OSL callbacks
    // and allocations through every guarded invocation and Session shutdown.
    let session = unsafe { Session::start(services, Mode::InterpreterOnly) }.unwrap();
    let root = session.root();
    assert_eq!(root.invoke(Some("RUN0"), &[Argument::Integer(9)]), Ok(()));
    assert_eq!(
        root.evaluate(Some("CNT0"), &[]),
        Ok(Some(Value::Integer(9)))
    );
    assert_eq!(
        root.evaluate(Some("RUN0"), &[Argument::Integer(7)]),
        Err(SUPPORT)
    );
    assert_eq!(
        root.evaluate(Some("CNT0"), &[]),
        Ok(Some(Value::Integer(7)))
    );
    // The method-handle form uses the same guarded discard boundary.
    assert_eq!(
        session
            .handle("\\RUN0")
            .unwrap()
            .invoke(None, &[Argument::Integer(11)]),
        Ok(())
    );
    assert_eq!(
        root.evaluate(Some("CNT0"), &[]),
        Ok(Some(Value::Integer(11)))
    );
    assert_eq!(root.invoke(Some("MISS"), &[]), Err(NOT_FOUND));
    assert_eq!(
        root.evaluate(Some("CNT0"), &[]),
        Ok(Some(Value::Integer(11)))
    );
    drop(session);
    assert!(counts.destroyed.load(Ordering::SeqCst));
    assert_eq!(counts.allocations.load(Ordering::SeqCst), 0);
    assert_eq!(counts.mappings.load(Ordering::SeqCst), 0);
}

#[cfg(all(unix, target_arch = "x86_64"))]
mod roles;

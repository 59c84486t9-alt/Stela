use super::*;
fn s(counter: u64, sleep_ticks: u64) -> Snapshot {
    Snapshot {
        counter,
        sleep_ticks,
    }
}
#[test]
fn arithmetic_and_explicit_counter_profile() -> Result<()> {
    for sample in [s(0, 0), s(100, 20), s(u64::MAX, u64::MAX)] {
        let bytes = fields(sample);
        let offset = u64::from_le_bytes(bytes[..8].try_into()?);
        assert_eq!(sample.counter.wrapping_add(offset), sample.awake_ticks()?);
        assert_eq!(bytes[USER_TIMEBASE - FIELD_START], 1);
        assert_eq!(bytes[CONT_HWCLOCK - FIELD_START], 1);
        assert_eq!(
            u64::from_le_bytes(bytes[16..24].try_into()?),
            sample.sleep_ticks
        );
        assert_eq!(&bytes[32..40], &[0; 8]);
    }
    assert!(s(9, 10).awake_ticks().is_err());
    Ok(())
}
#[test]
fn replay_validation_and_exhaustion() -> Result<()> {
    for samples in [
        vec![],
        vec![s(9, 10)],
        vec![s(10, 1), s(9, 1)],
        vec![s(10, 1), s(11, 0)],
        vec![s(10, 1), s(11, 3)],
    ] {
        assert!(ReplaySource::new(samples).is_err());
    }
    let mut source = ReplaySource::new(vec![s(10, 1), s(10, 1), s(15, 4)])?;
    assert_eq!(source.sample()?, s(10, 1));
    assert_eq!(source.sample()?, s(10, 1));
    assert_eq!(source.sample()?, s(15, 4));
    assert!(source.sample().is_err());
    Ok(())
}
#[test]
fn readonly_publication_updates_are_coherent_and_failures_preserve_it() -> Result<()> {
    let _clock_guard = TEST_CONTEXT_LOCK.lock().unwrap();
    struct UncheckedSource(VecDeque<Snapshot>);
    impl ClockSource for UncheckedSource {
        fn sample(&mut self) -> Result<Snapshot> {
            Ok(self.0.pop_front().unwrap())
        }
        fn source_id(&self) -> &'static str {
            "invalid-test-source"
        }
    }
    let mut context = Context::new(
        91,
        Box::new(UncheckedSource([s(100, 20), s(130, 40), s(125, 40)].into())),
    )?;
    assert_eq!(context.address_space(), 91);
    assert_eq!(context.frequency(), FREQUENCY);
    assert_eq!(context.region().guest_address, GUEST_BASE);
    assert!(!context.region().writable);
    assert!(!context.region().executable);
    assert!(context.region().readable);
    assert_eq!(
        context.snapshot_bytes(FIELD_START, FIELD_END - FIELD_START)?,
        fields(s(100, 20))
    );
    assert_eq!(context.read_counter()?, 130);
    assert_eq!(context.snapshot(), s(130, 40));
    assert_eq!(
        context.snapshot_bytes(FIELD_START, FIELD_END - FIELD_START)?,
        fields(s(130, 40))
    );
    assert_eq!(context.events().len(), 2);
    assert_eq!(
        context.events()[1],
        CounterEvent {
            sequence: 1,
            snapshot: s(130, 40)
        }
    );
    let before = context.snapshot_bytes(0, GUEST_BYTES)?;
    assert!(context.read_counter().is_err());
    assert_eq!(context.snapshot_bytes(0, GUEST_BYTES)?, before);
    assert_eq!(context.events().len(), 2);
    assert!(context.snapshot_bytes(GUEST_BYTES, 1).is_err());
    assert!(Context::new(92, Box::new(ReplaySource::new(vec![s(1, 0)])?)).is_err());
    assert_eq!(context.snapshot_bytes(0, GUEST_BYTES)?, before);
    drop(context);
    let replacement = Context::new(92, Box::new(ReplaySource::new(vec![s(1, 0)])?))?;
    assert_eq!(replacement.snapshot(), s(1, 0));
    Ok(())
}
#[test]
fn clock_samples_preserve_explicit_legacy_configuration() -> Result<()> {
    let _clock_guard = TEST_CONTEXT_LOCK.lock().unwrap();
    let configuration = legacy::Configuration {
        kdebug: Some(legacy::KdebugState::Disabled),
        dyld_flags: Some(legacy::DyldFlags {
            value: 0xfedcba9876543210,
            thread_protection: legacy::ThreadProtection::Disabled,
        }),
    };
    let mut context = Context::new_with_commpage(
        93,
        Box::new(ReplaySource::new(vec![s(100, 20), s(130, 40)])?),
        configuration,
    )?;
    assert_eq!(context.legacy_configuration(), configuration);
    let before = context.snapshot_bytes(0, GUEST_BYTES)?;
    assert_eq!(context.read_counter()?, 130);
    let after = context.snapshot_bytes(0, GUEST_BYTES)?;
    let mut expected = before;
    expected[FIELD_START..FIELD_END].copy_from_slice(&fields(s(130, 40)));
    assert_eq!(after, expected);
    let kdebug = &after[legacy::KDEBUG_ENABLE..legacy::KDEBUG_ENABLE + size_of::<u32>()];
    assert_eq!(u32::from_le_bytes(kdebug.try_into()?), 0);
    assert!(context.read_counter().is_err());
    assert_eq!(context.snapshot_bytes(0, GUEST_BYTES)?, after);
    assert_eq!(context.legacy_configuration(), configuration);
    drop(context);
    let clock_only = Context::new(94, Box::new(ReplaySource::new(vec![s(1, 0)])?))?;
    assert_eq!(
        clock_only.legacy_configuration(),
        legacy::Configuration::default()
    );
    Ok(())
}

#[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
#[test]
fn native_clock_does_not_guess_another_host_contract() {
    assert!(NativeDarwinSource::new().is_err());
}

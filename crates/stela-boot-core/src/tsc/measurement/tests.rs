use super::*;
#[test]
fn five_real_bracket_windows_keep_raw_evidence_and_intersect_exact_bounds() {
    let mut reads = 0u64;
    let calibration = calibrate_hpet::<Error>(1_000_000, || {
        let n = reads;
        reads += 1;
        Ok(Sample {
            tsc_before: n * 3_000_000,
            reference: n * 1_000_000,
            tsc_after: n * 3_000_000 + 10,
        })
    })
    .unwrap();
    assert_eq!(reads, 10);
    assert_eq!(calibration.windows().len(), 5);
    assert_eq!(calibration.windows()[4].end.reference, 9_000_000);
    assert_eq!(calibration.rate_window().minimum_hz(), 2_999_990_000);
    assert_eq!(calibration.rate_window().maximum_hz(), 3_000_010_000);
}
#[test]
fn stopped_reference_tsc_and_disturbed_brackets_never_wait_on_themselves() {
    let mut reads = 0;
    let result = calibrate_hpet::<Error>(1_000_000, || {
        reads += 1;
        Ok(Sample {
            tsc_before: reads,
            reference: 0,
            tsc_after: reads,
        })
    });
    assert_eq!(result.unwrap_err(), Error::NoProgress);
    assert_eq!(reads, MAX_POLLS as u64 + 1);
    let mut reads = 0;
    let result = calibrate_hpet::<Error>(1_000_000, || {
        reads += 1;
        Ok(Sample {
            tsc_before: 1,
            reference: reads * 1_000_000,
            tsc_after: 1,
        })
    });
    assert_eq!(result.unwrap_err(), Error::NoProgress);
    assert_eq!(reads, 2);
    let mut reads = 0;
    let result = calibrate_hpet::<Error>(1_000_000, || {
        reads += 1;
        Ok(Sample {
            tsc_before: 0,
            reference: 0,
            tsc_after: MAX_READ_CYCLES,
        })
    });
    assert_eq!(result.unwrap_err(), Error::Disturbed);
    assert_eq!(reads, RETRIES);
}
#[test]
fn changed_rate_backwards_reference_and_source_failure_stop_without_partial_evidence() {
    let mut reads = 0u64;
    let result = calibrate_hpet::<Error>(1_000_000, || {
        let n = reads;
        reads += 1;
        let t = match n {
            0 => 0,
            1 => 3_000_000,
            2 => 6_000_000,
            _ => 8_000_000,
        };
        Ok(Sample {
            tsc_before: t,
            reference: n * 1_000_000,
            tsc_after: t,
        })
    });
    assert_eq!(result.unwrap_err(), Error::InconsistentRate);
    assert_eq!(reads, 4);
    let mut reads = 0;
    let result = calibrate_hpet::<Error>(1_000_000, || {
        reads += 1;
        Ok(Sample {
            tsc_before: reads,
            reference: 10 - reads,
            tsc_after: reads,
        })
    });
    assert_eq!(result.unwrap_err(), Error::Backwards);
    assert_eq!(reads, 2);
    let mut reads = 0;
    let result = calibrate_hpet::<Error>(1_000_000, || {
        reads += 1;
        Err(Error::MissingMsr(0x3b))
    });
    assert_eq!(result.unwrap_err(), Error::MissingMsr(0x3b));
    assert_eq!(reads, 1);
    let mut reads = 0;
    let result = calibrate_hpet::<Error>(0, || {
        reads += 1;
        unreachable!()
    });
    assert_eq!(result.unwrap_err(), Error::InvalidRate);
    assert_eq!(reads, 0);
}

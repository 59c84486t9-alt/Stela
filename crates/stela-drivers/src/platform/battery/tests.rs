use super::*;
use alloc::vec;

fn information(extended: bool, revision: u32) -> Value<'static> {
    let mut numbers = vec![0, 50_000, 45_000, 1, 12_000, 5_000, 2_000];
    if extended {
        numbers.insert(0, revision);
        numbers.extend([42, 95_000, 1_000, 100, 500, 50]);
    }
    numbers.extend([1, 2]);
    let mut values: Vec<_> = numbers
        .into_iter()
        .map(|n| Value::Integer(n.into()))
        .collect();
    values.extend([
        Value::String(b"Battery model".to_vec()),
        Value::Buffer(b"serial\0ignored".to_vec()),
        Value::Integer(u64::from_le_bytes(*b"LION\0\0\0\0")),
        Value::String(b"OEM".to_vec()),
    ]);
    if extended && revision == 1 {
        values.push(Value::Integer(1));
    }
    Value::Package(values)
}

#[test]
fn information_layouts_preserve_native_units_and_extension_fields() {
    for extended in [false, true] {
        for revision in 0..=1 {
            let info = parse_information(information(extended, revision), extended).unwrap();
            assert_eq!(info.unit, Unit::Energy);
            assert_eq!(info.design_capacity, Some(50_000));
            assert_eq!(info.design_voltage_mv, Some(12_000));
            assert_eq!(info.low_granularity, Some(1));
            assert_eq!(info.high_granularity, Some(2));
            assert_eq!(info.model, b"Battery model");
            assert_eq!(info.serial, b"serial");
            assert_eq!(info.chemistry, b"LION");
            assert_eq!(info.oem, b"OEM");
            if extended {
                let extension = info.extended.unwrap();
                assert_eq!(extension.cycle_count, Some(42));
                assert_eq!(extension.accuracy, Some(95_000));
                assert_eq!(extension.swapping_capability, (revision == 1).then_some(1));
            } else {
                assert!(info.extended.is_none());
            }
        }
    }
}

#[test]
fn malformed_firmware_is_not_coerced_into_a_charge_reading() {
    for extended in [false, true] {
        let Value::Package(values) = information(extended, 0) else {
            unreachable!()
        };
        for length in 0..values.len() {
            assert!(
                parse_information(Value::Package(values[..length].to_vec()), extended).is_err()
            );
        }
        for index in 0..if extended { 16 } else { 9 } {
            let mut invalid = values.clone();
            invalid[index] = Value::Buffer(vec![0]);
            assert!(parse_information(Value::Package(invalid), extended).is_err());
        }
    }
    assert_eq!(
        parse_information(information(true, 2), true),
        Err(Error::UnsupportedRevision(2))
    );
    let Value::Package(mut missing) = information(true, 1) else {
        unreachable!()
    };
    missing.pop();
    assert_eq!(
        parse_information(Value::Package(missing), true),
        Err(Error::Malformed(Method::ExtendedInformation))
    );
}

#[test]
fn unknown_values_remain_unknown_and_state_flags_are_not_policy() {
    let state = parse_state(Value::Package(vec![
        Value::Integer(7),
        Value::Integer(UNKNOWN.into()),
        Value::Integer(UNKNOWN.into()),
        Value::Integer(UNKNOWN.into()),
    ]))
    .unwrap();
    assert_eq!(state.charging(), Some(true));
    assert_eq!(state.discharging(), Some(true));
    assert_eq!(state.critical(), Some(true));
    assert_eq!(
        State {
            flags: UNKNOWN,
            ..state
        }
        .charging(),
        None
    );
    assert_eq!(state.rate, None);
    assert_eq!(state.remaining_capacity, None);
    assert_eq!(state.voltage_mv, None);
    assert!(parse_state(Value::Package(vec![Value::Integer(0); 3])).is_err());
    assert!(parse_state(Value::Package(vec![Value::Integer(u64::MAX); 4])).is_err());
}

#[test]
fn identity_bounds_preserve_raw_bytes_without_utf8_or_termination_assumptions() {
    assert_eq!(
        text(Value::String(vec![0xff; 100]), Method::Information).unwrap(),
        vec![0xff; 31]
    );
    assert_eq!(
        text(Value::Buffer(vec![]), Method::Information).unwrap(),
        b""
    );
}

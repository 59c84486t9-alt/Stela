use super::*;
use alloc::vec;

fn large(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
fn template(mut raw: Vec<u8>) -> Vec<u8> {
    raw.extend_from_slice(&[0x79, 0]);
    raw
}
fn gpio_raw(kind: u8, flags: u8, pins: &[u16]) -> Vec<u8> {
    let source_at = 23 + pins.len() * 2;
    let mut payload = vec![1, kind, 1, 0, flags, 0, 2, 0x34, 0x12, 0x78, 0x56, 23, 0, 7];
    payload.extend_from_slice(&(source_at as u16).to_le_bytes());
    payload.extend_from_slice(&[0, 0, 0, 0]);
    for pin in pins {
        payload.extend_from_slice(&pin.to_le_bytes());
    }
    payload.extend_from_slice(b"\\_SB.GPO0\0");
    large(0x8c, &payload)
}
#[test]
fn real_fixed_memory_and_irq_wire_flags_are_preserved() {
    let mut bytes = vec![0x86, 9, 0, 1];
    bytes.extend_from_slice(&0xfed8_0000u32.to_le_bytes());
    bytes.extend_from_slice(&0x1000u32.to_le_bytes());
    bytes.extend_from_slice(&[0x89, 6, 0, 0x1d, 1, 22, 0, 0, 0]);
    let resources = parse(&template(bytes)).unwrap();
    assert_eq!(resources.len(), 2);
    let Resource::Address(memory) = &resources[0].resource else {
        panic!()
    };
    assert_eq!(
        (memory.minimum, memory.maximum, memory.length),
        (0xfed8_0000, 0xfed8_0fff, 0x1000)
    );
    let Resource::Interrupt(irq) = &resources[1].resource else {
        panic!()
    };
    assert_eq!(
        (irq.trigger, irq.polarity, irq.shared, irq.wake),
        (Trigger::Level, Polarity::Low, true, true)
    );
    assert_eq!(irq.pins, [22]);
}
#[test]
fn unresolved_dependent_functions_never_publish_interior_assignments() {
    let mut memory = vec![0x86, 9, 0, 1];
    memory.extend_from_slice(&0xfed8_0000u32.to_le_bytes());
    memory.extend_from_slice(&0x1000u32.to_le_bytes());
    for start in [vec![0x30], vec![0x31, 0], vec![0x31, 5]] {
        let mut alternatives = start;
        alternatives.extend_from_slice(&memory);
        alternatives.push(0x38);
        assert_eq!(
            parse(&template(alternatives)),
            Err(Error::DependentFunctions)
        );
    }
    assert_eq!(parse(&template(vec![0x38])), Err(Error::DependentFunctions));
    // Opaque vendor data does not select or delimit resource alternatives.
    let mut vendor = vec![0x71, 0xab];
    vendor.extend_from_slice(&memory);
    assert_eq!(parse(&template(vendor)).unwrap().len(), 2);
}
#[test]
fn gpio_connection_decode_keeps_order_units_and_bounds() {
    let raw = gpio_raw(0, 0x1b, &[31, 2, 255]);
    let gpio = parse_gpio_connection(&raw).unwrap();
    assert_eq!(gpio.pins, [31, 2, 255]);
    assert_eq!(gpio.source.path, "\\_SB.GPO0");
    assert_eq!(gpio.source.index, 7);
    assert_eq!(gpio.drive_strength, 0x1234);
    assert_eq!(gpio.debounce, 0x5678);
    assert_eq!(
        gpio.kind,
        GpioKind::Interrupt {
            trigger: Trigger::Edge,
            polarity: Polarity::Low
        }
    );
    assert!(gpio.shared && gpio.wake);
    for i in 0..raw.len() {
        assert!(parse_gpio_connection(&raw[..i]).is_err());
    }
    for offset in [14, 17, 19, 21] {
        let mut malformed = raw.clone();
        malformed[offset..offset + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(parse_gpio_connection(&malformed).is_err());
    }
}
#[test]
fn malformed_checksum_trailing_data_unknown_tags_and_revisions_are_explicit() {
    let mut checked = vec![0x71, 0xab, 0x79, 0];
    checked[3] = 0u8.wrapping_sub(checked[..3].iter().fold(0u8, |sum, b| sum.wrapping_add(*b)));
    assert!(matches!(
        parse(&checked).unwrap()[0].resource,
        Resource::Unsupported { tag: 0x71, .. }
    ));
    checked[1] ^= 1;
    assert_eq!(parse(&checked), Err(Error::Checksum));
    assert_eq!(parse(&[0x79, 0, 0]), Err(Error::Malformed));
    assert_eq!(parse(&[]), Err(Error::MissingEnd));
    assert_eq!(parse(&[0x86, 9, 0]), Err(Error::Truncated));
    let mut raw = gpio_raw(1, 1, &[5]);
    raw[3] = 2;
    assert_eq!(
        parse_gpio_connection(&raw),
        Err(Error::Unsupported {
            tag: 0x8c,
            revision: 2
        })
    );
}
#[test]
fn serial_bus_source_ordinal_address_mode_and_spi_signals_are_preserved() {
    let mut payload = vec![2, 3, 1, 6, 1, 0, 1, 8, 0];
    payload.extend_from_slice(&400_000u32.to_le_bytes());
    payload.extend_from_slice(&0x2aau16.to_le_bytes());
    payload.extend_from_slice(&[0xde, 0xad]);
    payload.extend_from_slice(b"I2C0\0");
    let mut raw = large(0x8e, &payload);
    let mut spi = vec![1, 2, 2, 2, 3, 0, 1, 9, 0];
    spi.extend_from_slice(&12_000_000u32.to_le_bytes());
    spi.extend_from_slice(&[16, 1, 0, 4, 0]);
    spi.extend_from_slice(b"^SPI0\0");
    raw.extend_from_slice(&large(0x8e, &spi));
    let resources = parse(&template(raw)).unwrap();
    let Resource::Serial(i2c) = &resources[0].resource else {
        panic!()
    };
    assert_eq!(
        i2c.kind,
        SerialKind::I2c {
            address: 0x2aa,
            ten_bit: true
        }
    );
    assert_eq!(i2c.vendor, [0xde, 0xad]);
    assert!(i2c.consumer && i2c.shared && i2c.controller_initiated);
    let Resource::Serial(spi) = &resources[1].resource else {
        panic!()
    };
    assert_eq!(
        spi.kind,
        SerialKind::Spi {
            selection: 4,
            three_wire: true,
            active_high: true,
            bits: 16,
            clock_phase: 1,
            clock_polarity: 0
        }
    );
    assert_eq!(resources[1].ordinal, 1);
    assert_eq!(spi.source.path, "^SPI0");
}

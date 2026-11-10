use super::Mmio;

fn window(registers: &mut [u32; 2]) -> Mmio {
    // SAFETY: the window is this test's own buffer.
    unsafe { Mmio::new(registers.as_mut_ptr() as u64, size_of_val(registers)) }
}

#[test]
fn an_access_ending_at_the_window_end_reaches_its_register() {
    let mut registers = [0, 0x1234_5678];
    let mmio = window(&mut registers);
    assert_eq!(mmio.read32(mmio.len() - 4), 0x1234_5678);
    mmio.write8(mmio.len() - 1, 0xab);
    assert_eq!(mmio.read8(mmio.len() - 1), 0xab);
}

#[test]
#[should_panic(expected = "outside a 0x8-byte register window")]
fn an_access_crossing_the_window_end_panics() {
    let mut registers = [0; 2];
    let mmio = window(&mut registers);
    mmio.read32(mmio.len() - 3);
}

#[test]
#[should_panic(expected = "outside a 0x8-byte register window")]
fn an_offset_that_overflows_panics() {
    let mut registers = [0; 2];
    let mmio = window(&mut registers);
    mmio.write32(usize::MAX - 1, 0);
}

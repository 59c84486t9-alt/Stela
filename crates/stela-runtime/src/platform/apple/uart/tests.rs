use super::*;
use alloc::vec::Vec;
use stela_contracts::interrupt::InterruptLatch;

#[derive(Default)]
struct Console {
    bytes: Vec<u8>,
    busy: bool,
}
impl ConsoleSink for Console {
    fn transmit(&mut self, byte: u8) -> Result<(), ConsoleBusy> {
        if self.busy {
            return Err(ConsoleBusy);
        }
        self.bytes.push(byte);
        Ok(())
    }
}
const IRQ: AicInput = AicInput::new(0, 739);
fn uart() -> S5lUart<Console> {
    S5lUart::new(Console::default(), Some(IRQ))
}

fn lifecycle(uart: &mut S5lUart<Console>, state: LifecycleState, latch: &mut InterruptLatch) {
    uart.check_lifecycle(state).unwrap();
    uart.set_lifecycle(state, &mut Access::new(0, 0, latch));
}

#[test]
fn kept_pauses_preserve_fifo_and_irq_without_transmitting_while_gated() {
    let mut uart = uart();
    let mut latch = InterruptLatch::new();
    write(&mut uart, &mut latch, UCON, 5 | UCON_TXTHRESH_ENABLE);
    write(&mut uart, &mut latch, UTXH, u32::from(b'a'));
    assert!(latch.is_asserted(Wire::Aic(IRQ)));
    uart.console().busy = true;
    write(&mut uart, &mut latch, UTXH, u32::from(b'b'));
    let active = uart.lifecycle;
    for paused in [
        LifecycleState {
            clocked: false,
            ..active
        },
        LifecycleState {
            powered: false,
            retention: true,
            ..active
        },
        LifecycleState {
            quiesced: true,
            ..active
        },
    ] {
        lifecycle(&mut uart, paused, &mut latch);
        uart.console().busy = false;
        uart.flush(&mut Access::new(0, 0, &mut latch));
        assert_eq!(uart.console().bytes, b"a");
        assert_eq!(uart.tx.front(), Some(&b'b'));
        assert!(!latch.is_asserted(Wire::Aic(IRQ)));
        assert_eq!(uart.receive(b"rx", &mut Access::new(0, 0, &mut latch)), 0);
        uart.console().busy = true;
        lifecycle(&mut uart, active, &mut latch);
        assert!(latch.is_asserted(Wire::Aic(IRQ)));
    }
    uart.console().busy = false;
    uart.flush(&mut Access::new(0, 0, &mut latch));
    assert_eq!(uart.console().bytes, b"ab");
}

#[test]
fn destructive_edges_keep_the_console_but_require_explicit_register_initialization() {
    for reset in [false, true] {
        let mut uart = uart();
        let mut latch = InterruptLatch::new();
        write(&mut uart, &mut latch, UTXH, u32::from(b'a'));
        uart.console().busy = true;
        write(&mut uart, &mut latch, UTXH, u32::from(b'b'));
        assert_eq!(uart.receive(b"rx", &mut Access::new(0, 0, &mut latch)), 2);
        let active = uart.lifecycle;
        lifecycle(
            &mut uart,
            LifecycleState {
                powered: reset,
                reset,
                ..active
            },
            &mut latch,
        );
        assert!(
            uart.read(UTRSTAT, Width::Word, &mut Access::new(0, 0, &mut latch))
                .is_err()
        );
        lifecycle(&mut uart, active, &mut latch);
        assert!(uart.tx.is_empty() && uart.rx.is_empty());
        assert_eq!(uart.console().bytes, b"a");
        assert!(
            uart.read(UCON, Width::Word, &mut Access::new(0, 0, &mut latch))
                .is_err()
        );
        assert!(
            uart.write(
                UTXH,
                Width::Word,
                u64::from(b'c'),
                &mut Access::new(0, 0, &mut latch)
            )
            .is_err()
        );
        write(&mut uart, &mut latch, ULCON, 3);
        write(&mut uart, &mut latch, UCON, 5);
        write(&mut uart, &mut latch, UFCON, UFCON_FIFO_ENABLE);
        uart.console().busy = false;
        write(&mut uart, &mut latch, UTXH, u32::from(b'd'));
        assert_eq!(uart.console().bytes, b"ad");
        assert_eq!(read(&mut uart, &mut latch, UCON), 5);
        assert!(
            uart.read(UMCON, Width::Word, &mut Access::new(0, 0, &mut latch))
                .is_err()
        );
        assert!(
            uart.read(UBRDIV, Width::Word, &mut Access::new(0, 0, &mut latch))
                .is_err()
        );
    }
}
fn write(uart: &mut S5lUart<Console>, latch: &mut InterruptLatch, offset: u64, value: u32) {
    uart.write(
        offset,
        Width::Word,
        value.into(),
        &mut Access::new(0, 0, latch),
    )
    .unwrap();
}
fn read(uart: &mut S5lUart<Console>, latch: &mut InterruptLatch, offset: u64) -> u32 {
    uart.read(offset, Width::Word, &mut Access::new(0, 0, latch))
        .unwrap() as u32
}

/// XNU `apple_uart_init` followed by `apple_uart_transmit_data`, polling
/// `apple_uart_transmit_ready` as `serial_putc` does.
#[test]
fn xnu_init_then_polled_transmit() {
    let mut latch = InterruptLatch::new();
    let mut uart = uart();
    write(&mut uart, &mut latch, UCON, 1 << 10 | 1 << 2 | 1);
    write(&mut uart, &mut latch, ULCON, 3);
    // 24 MHz NCLK at 115200 baud: XNU's search keeps sample rate 16 and
    // rounds the divisor 12.02 down to 12 (0.16% error).
    write(&mut uart, &mut latch, UBRDIV, 12);
    write(
        &mut uart,
        &mut latch,
        UFCON,
        UFCON_FIFO_ENABLE | UFCON_RX_RESET | UFCON_TX_RESET,
    );
    assert_eq!(read(&mut uart, &mut latch, UFCON), UFCON_FIFO_ENABLE);
    for &byte in b"Darwin\n" {
        assert_eq!(read(&mut uart, &mut latch, UFSTAT) & UFSTAT_TX_FULL, 0);
        write(&mut uart, &mut latch, UTXH, byte.into());
    }
    assert_eq!(uart.console().bytes, b"Darwin\n");
    assert_eq!(read(&mut uart, &mut latch, UBRDIV), 12);
    let utrstat = read(&mut uart, &mut latch, UTRSTAT);
    assert_eq!(
        utrstat & 0b111,
        UTRSTAT_TX_BUFFER_EMPTY | UTRSTAT_TRANSMITTER_EMPTY
    );
    assert!(
        !latch.is_asserted(Wire::Aic(IRQ)),
        "TX interrupt was never enabled"
    );
}

/// XNU `apple_uart_enable_irq` and `apple_uart_ack_irq`: the TX threshold
/// edge raises the AIC input until the guest clears UTRSTAT bit 5.
#[test]
fn xnu_transmit_interrupt_and_acknowledge() {
    let mut latch = InterruptLatch::new();
    let mut uart = uart();
    let ufcon = read(&mut uart, &mut latch, UFCON);
    write(
        &mut uart,
        &mut latch,
        UFCON,
        ufcon & !(0b11 << UFCON_TX_TRIGGER_SHIFT),
    );
    let ucon = read(&mut uart, &mut latch, UCON);
    write(&mut uart, &mut latch, UCON, ucon | UCON_TXTHRESH_ENABLE);
    assert!(
        !latch.is_asserted(Wire::Aic(IRQ)),
        "edge-triggered: no TX IRQ while idle"
    );
    write(&mut uart, &mut latch, UTXH, u32::from(b'x'));
    assert!(latch.is_asserted(Wire::Aic(IRQ)));
    assert_ne!(read(&mut uart, &mut latch, UTRSTAT) & UTRSTAT_TXTHRESH, 0);
    write(&mut uart, &mut latch, UTRSTAT, UTRSTAT_TXTHRESH);
    assert!(!latch.is_asserted(Wire::Aic(IRQ)));
    assert_eq!(latch.take_aic_inputs(), vec![(IRQ, true), (IRQ, false)]);
}

/// Linux `apple_s5l_serial_startup` and `apple_serial_handle_irq` receive.
#[test]
fn linux_receive_interrupt_sequence() {
    let mut latch = InterruptLatch::new();
    let mut uart = uart();
    write(&mut uart, &mut latch, UTRSTAT, UTRSTAT_CLEARABLE);
    let ufcon = read(&mut uart, &mut latch, UFCON);
    write(
        &mut uart,
        &mut latch,
        UFCON,
        ufcon | UFCON_RX_RESET | 1 << UFCON_RX_TRIGGER_SHIFT,
    );
    let ucon = read(&mut uart, &mut latch, UCON);
    write(
        &mut uart,
        &mut latch,
        UCON,
        ucon | UCON_RX_TIMEOUT_ENABLE
            | UCON_RXTHRESH_ENABLE
            | UCON_RXTO_ENABLE
            | UCON_RXTO_LEGACY_ENABLE,
    );
    assert_eq!(uart.receive(b"ls\r", &mut Access::new(0, 0, &mut latch)), 3);
    assert!(latch.is_asserted(Wire::Aic(IRQ)));
    let pending = read(&mut uart, &mut latch, UTRSTAT);
    assert_eq!(
        pending & (UTRSTAT_RXTO | UTRSTAT_RXTO_LEGACY),
        UTRSTAT_RXTO | UTRSTAT_RXTO_LEGACY
    );
    assert_eq!(
        pending & UTRSTAT_RXTHRESH,
        0,
        "3 bytes are below the 8-byte trigger"
    );
    write(
        &mut uart,
        &mut latch,
        UTRSTAT,
        UTRSTAT_RXTHRESH | UTRSTAT_RXTO | UTRSTAT_RXTO_LEGACY,
    );
    assert!(!latch.is_asserted(Wire::Aic(IRQ)));
    assert_eq!(read(&mut uart, &mut latch, UFSTAT), 3);
    let received: Vec<u8> = (0..3)
        .map(|_| read(&mut uart, &mut latch, URXH) as u8)
        .collect();
    assert_eq!(received, b"ls\r");
    assert_eq!(read(&mut uart, &mut latch, UTRSTAT) & UTRSTAT_RX_READY, 0);
    assert!(
        uart.read(URXH, Width::Word, &mut Access::new(0, 0, &mut latch))
            .is_err()
    );
}

#[test]
fn full_fifos_are_reported_not_dropped() {
    let mut latch = InterruptLatch::new();
    let mut uart = uart();
    uart.console().busy = true;
    for byte in 0..16 {
        write(&mut uart, &mut latch, UTXH, byte);
    }
    assert_eq!(read(&mut uart, &mut latch, UFSTAT), UFSTAT_TX_FULL);
    assert!(
        uart.write(UTXH, Width::Word, 16, &mut Access::new(0, 0, &mut latch))
            .is_err()
    );
    uart.console().busy = false;
    uart.flush(&mut Access::new(0, 0, &mut latch));
    assert_eq!(uart.console().bytes, (0..16).collect::<Vec<u8>>());
    assert_eq!(
        uart.receive(&[0; 20], &mut Access::new(0, 0, &mut latch)),
        16
    );
    assert_eq!(read(&mut uart, &mut latch, UFSTAT), UFSTAT_RX_FULL);
}

#[test]
fn unmodeled_registers_and_fields_are_refused() {
    let mut latch = InterruptLatch::new();
    let mut uart = uart();
    let mut access = Access::new(0, 0, &mut latch);
    for offset in [UVER, UABRCNT, UTXOFFSET, 0x40, UBRDIV] {
        assert!(
            uart.read(offset, Width::Word, &mut access).is_err(),
            "{offset:#x}"
        );
    }
    assert!(
        uart.write(UCON, Width::Word, 1 << 5 | 5, &mut access)
            .is_err(),
        "loopback"
    );
    assert!(
        uart.write(UCON, Width::Word, 3 << 2 | 1, &mut access)
            .is_err(),
        "DMA"
    );
    assert!(
        uart.write(ULCON, Width::Word, 2, &mut access).is_err(),
        "7-bit words"
    );
    assert!(
        uart.write(UFCON, Width::Word, 0, &mut access).is_err(),
        "non-FIFO mode"
    );
    assert!(uart.read(UTRSTAT, Width::Byte, &mut access).is_err());
}

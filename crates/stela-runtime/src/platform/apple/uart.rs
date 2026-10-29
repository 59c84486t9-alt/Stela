//! The Apple S5L UART (`apple,s5l-uart`; ADT `uart-1,samsung`), the serial
//! console XNU uses with `serial=3`.
//!
//! Register layout and field names are documented by XNU
//! `pexpert/pexpert/arm/apple_uart_regs.h` and exercised by
//! `pexpert/arm/pe_serial.c` (`apple_uart_init`, `apple_uart_enable_irq`,
//! `apple_uart_ack_irq`, `apple_uart_transmit_ready`); Linux
//! `drivers/tty/serial/samsung_tty.c` (`TYPE_APPLE_S5L`) and
//! `include/linux/serial_s3c.h` document the same UFSTAT counts and the
//! UCON enable / UTRSTAT status pairs (bits 9/9, 11/3, 12/4, 13/5). Linux also
//! documents that "the Apple version only has edge triggered TX IRQs".
//!
//! Inferred, not documented: the TX threshold status latches when the TX FIFO
//! level falls from above the UFCON trigger level to at or below it; the RX
//! threshold status latches when the RX level rises to the trigger level, with
//! the S3C2410 RX levels 4/8/12/16; the RX timeout statuses latch at the end of
//! each host receive burst; the UFCON FIFO reset bits self-clear; the reset
//! state is the 8N1, FIFO-enabled, polled console left by the boot firmware.
//! Transmitted bytes go to the host [`ConsoleSink`] immediately; bytes it cannot
//! take stay in the 16-byte TX FIFO and are reported as FIFO occupancy.
use alloc::collections::VecDeque;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction, stela_contracts::bus::Lifecycle,
    stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::bus::Width, stela_contracts::bus::refuse,
};
use {stela_contracts::interrupt::AicInput, stela_contracts::interrupt::Wire};

const NAME: &str = "s5l-uart";
const FIFO_BYTES: usize = 16;

const ULCON: u64 = 0x00;
const UCON: u64 = 0x04;
const UFCON: u64 = 0x08;
const UMCON: u64 = 0x0c;
const UTRSTAT: u64 = 0x10;
const UERSTAT: u64 = 0x14;
const UFSTAT: u64 = 0x18;
const UMSTAT: u64 = 0x1c;
const UTXH: u64 = 0x20;
const URXH: u64 = 0x24;
const UBRDIV: u64 = 0x28;
const UABRCNT: u64 = 0x2c;
const UTXOFFSET: u64 = 0x34;
const URXOFFSET: u64 = 0x38;
const UVER: u64 = 0x3c;

const ULCON_WORD_LENGTH: u32 = 0b11;
const ULCON_WORD_LENGTH_8_BITS: u32 = 0b11;
/// Word length, stop bits, parity and tolerant mode: framing on the wire,
/// with no effect on a byte-stream console.
const ULCON_FRAMING: u32 = 0b1011_1111;

const UCON_RECEIVE_MODE: u32 = 0b11;
const UCON_TRANSMIT_MODE_SHIFT: u32 = 2;
const UCON_MODE_INTERRUPT_OR_POLLING: u32 = 1;
const UCON_RX_TIMEOUT_ENABLE: u32 = 1 << 7;
const UCON_RXTO_ENABLE: u32 = 1 << 9;
const UCON_RXTO_LEGACY_ENABLE: u32 = 1 << 11;
const UCON_RXTHRESH_ENABLE: u32 = 1 << 12;
const UCON_TXTHRESH_ENABLE: u32 = 1 << 13;
const UCON_ERROR_ENABLE: u32 = 1 << 14;
/// Fields whose effect the model implements, or which have none here: the
/// modes, timeout and interrupt enables, NCLK/PCLK selection, the auto-baud
/// interrupt enable (auto-baud never runs) and the DMA request options (DMA
/// mode is refused).
const UCON_SUPPORTED: u32 = 0b1111
    | UCON_RX_TIMEOUT_ENABLE
    | UCON_RXTO_ENABLE
    | 1 << 10
    | UCON_RXTO_LEGACY_ENABLE
    | UCON_RXTHRESH_ENABLE
    | UCON_TXTHRESH_ENABLE
    | UCON_ERROR_ENABLE
    | 1 << 16
    | 1 << 18
    | 1 << 21;

const UFCON_FIFO_ENABLE: u32 = 1;
const UFCON_RX_RESET: u32 = 1 << 1;
const UFCON_TX_RESET: u32 = 1 << 2;
#[cfg(test)]
const UFCON_RX_TRIGGER_SHIFT: u32 = 4;
const UFCON_TX_TRIGGER_SHIFT: u32 = 6;
const UFCON_STORED: u32 = UFCON_FIFO_ENABLE | 0b11_1111 << 4;

/// RTS level and auto flow control fields (Linux `S3C2410_UMCOM_*`,
/// `S3C2412_UMCON_AFC_*`); the host console is always ready.
const UMCON_SUPPORTED: u32 = 1 | 0b1111 << 4;
const UMSTAT_CTS: u32 = 1;

const UTRSTAT_RX_READY: u32 = 1;
const UTRSTAT_TX_BUFFER_EMPTY: u32 = 1 << 1;
const UTRSTAT_TRANSMITTER_EMPTY: u32 = 1 << 2;
const UTRSTAT_RXTO_LEGACY: u32 = 1 << 3;
const UTRSTAT_RXTHRESH: u32 = 1 << 4;
const UTRSTAT_TXTHRESH: u32 = 1 << 5;
const UTRSTAT_RXTO: u32 = 1 << 9;
/// Linux `APPLE_S5L_UTRSTAT_ALL_FLAGS`: write-one-to-clear statuses.
const UTRSTAT_CLEARABLE: u32 = 0b111_1111 << 3;
const UTRSTAT_READ_ONLY: u32 = 0b111;

const UFSTAT_TX_COUNT_SHIFT: u32 = 4;
const UFSTAT_RX_FULL: u32 = 1 << 8;
const UFSTAT_TX_FULL: u32 = 1 << 9;

const UBRDIV_FIELDS: u32 = 0xf_ffff;
const CONFIGURATION: u16 = 0xf; // ULCON, UCON, UFCON, UMCON.
const TRANSFER_CONFIGURATION: u16 = 0x7; // Framing, modes and FIFOs; CTS is always ready.

/// The host side of the console: COM1 and the firmware framebuffer in
/// `stela.efi`.
pub trait ConsoleSink {
    /// Accepts one transmitted byte, or reports that it cannot take it now.
    fn transmit(&mut self, byte: u8) -> Result<(), ConsoleBusy>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsoleBusy;

pub struct S5lUart<C> {
    console: C,
    irq: Option<AicInput>,
    irq_level: bool,
    ulcon: u32,
    ucon: u32,
    ufcon: u32,
    umcon: u32,
    ubrdiv: Option<u32>,
    status: u32,
    tx: VecDeque<u8>,
    rx: VecDeque<u8>,
    lifecycle: LifecycleState,
    configuration: u16,
}
impl<C: ConsoleSink> S5lUart<C> {
    /// `irq` is the node's DeviceTree `interrupts` AIC input, if it has one.
    pub fn new(console: C, irq: Option<AicInput>) -> Self {
        Self {
            console,
            irq,
            irq_level: false,
            ulcon: ULCON_WORD_LENGTH_8_BITS,
            ucon: UCON_MODE_INTERRUPT_OR_POLLING
                | UCON_MODE_INTERRUPT_OR_POLLING << UCON_TRANSMIT_MODE_SHIFT,
            ufcon: UFCON_FIFO_ENABLE,
            umcon: 0,
            ubrdiv: None,
            status: 0,
            tx: VecDeque::with_capacity(FIFO_BYTES),
            rx: VecDeque::with_capacity(FIFO_BYTES),
            lifecycle: LifecycleState {
                powered: true,
                clocked: true,
                quiesced: false,
                reset: false,
                retention: false,
            },
            configuration: CONFIGURATION,
        }
    }
    #[cfg(test)]
    pub fn console(&mut self) -> &mut C {
        &mut self.console
    }
    /// Delivers host input. Returns how many bytes fit in the RX FIFO; the
    /// caller keeps the rest. The end of the call is the end of the burst.
    #[cfg(test)]
    pub fn receive(&mut self, bytes: &[u8], access: &mut Access<'_>) -> usize {
        if !self.active() || self.configuration & TRANSFER_CONFIGURATION != TRANSFER_CONFIGURATION {
            return 0;
        }
        let accepted = bytes.len().min(FIFO_BYTES - self.rx.len());
        let trigger = [4, 8, 12, 16][field(self.ufcon, UFCON_RX_TRIGGER_SHIFT)];
        for &byte in &bytes[..accepted] {
            self.rx.push_back(byte);
            if self.rx.len() == trigger {
                self.status |= UTRSTAT_RXTHRESH;
            }
        }
        if !self.rx.is_empty() && self.ucon & UCON_RX_TIMEOUT_ENABLE != 0 {
            self.status |= UTRSTAT_RXTO | UTRSTAT_RXTO_LEGACY;
        }
        self.update_irq(access);
        accepted
    }
    /// Retries bytes the console refused earlier.
    pub fn flush(&mut self, access: &mut Access<'_>) {
        let before = self.tx.len();
        self.drain_tx(before);
        self.update_irq(access);
    }

    fn drain_tx(&mut self, peak: usize) {
        if !self.active() || self.configuration & TRANSFER_CONFIGURATION != TRANSFER_CONFIGURATION {
            return;
        }
        while let Some(&byte) = self.tx.front() {
            if self.console.transmit(byte).is_err() {
                break;
            }
            self.tx.pop_front();
        }
        let trigger = [0, 4, 8, 12][field(self.ufcon, UFCON_TX_TRIGGER_SHIFT)];
        if peak > trigger && self.tx.len() <= trigger {
            self.status |= UTRSTAT_TXTHRESH;
        }
    }
    fn utrstat(&self) -> u32 {
        let mut value = self.status;
        if !self.rx.is_empty() {
            value |= UTRSTAT_RX_READY;
        }
        if self.tx.is_empty() {
            value |= UTRSTAT_TX_BUFFER_EMPTY | UTRSTAT_TRANSMITTER_EMPTY;
        }
        value
    }
    fn ufstat(&self) -> u32 {
        let count = |len: usize| (len % FIFO_BYTES) as u32;
        let mut value = count(self.rx.len()) | count(self.tx.len()) << UFSTAT_TX_COUNT_SHIFT;
        if self.rx.len() == FIFO_BYTES {
            value |= UFSTAT_RX_FULL;
        }
        if self.tx.len() == FIFO_BYTES {
            value |= UFSTAT_TX_FULL;
        }
        value
    }
    fn enabled_status(&self) -> u32 {
        [
            (UCON_RXTO_ENABLE, UTRSTAT_RXTO),
            (UCON_RXTO_LEGACY_ENABLE, UTRSTAT_RXTO_LEGACY),
            (UCON_RXTHRESH_ENABLE, UTRSTAT_RXTHRESH),
            (UCON_TXTHRESH_ENABLE, UTRSTAT_TXTHRESH),
        ]
        .into_iter()
        .filter(|(enable, _)| self.ucon & enable != 0)
        .fold(0, |mask, (_, status)| mask | status)
    }
    fn update_irq(&mut self, access: &mut Access<'_>) {
        let level = self.active() && self.status & self.enabled_status() != 0;
        if level != self.irq_level {
            self.irq_level = level;
            if let Some(irq) = self.irq {
                access.interrupts.set_level(Wire::Aic(irq), level);
            }
        }
    }
    fn write_register(&mut self, offset: u64, value: u32) -> Result<(), &'static str> {
        match offset {
            ULCON => {
                if value & !ULCON_FRAMING != 0 {
                    return Err("ULCON infra-red, inverted or reserved mode is not modeled");
                }
                if value & ULCON_WORD_LENGTH != ULCON_WORD_LENGTH_8_BITS {
                    return Err("ULCON word lengths other than 8 bits are not modeled");
                }
                self.ulcon = value;
            }
            UCON => {
                if value & !UCON_SUPPORTED != 0 {
                    return Err(
                        "UCON break, loopback, auto-baud, transmit stop, software reset or reserved field is not modeled",
                    );
                }
                let rx_mode = value & UCON_RECEIVE_MODE;
                let tx_mode = value >> UCON_TRANSMIT_MODE_SHIFT & UCON_RECEIVE_MODE;
                if rx_mode > UCON_MODE_INTERRUPT_OR_POLLING
                    || tx_mode > UCON_MODE_INTERRUPT_OR_POLLING
                {
                    return Err("UCON DMA or undefined transfer mode is not modeled");
                }
                self.ucon = value;
            }
            UFCON => {
                if value & !(UFCON_STORED | UFCON_RX_RESET | UFCON_TX_RESET) != 0 {
                    return Err("UFCON reserved field is not modeled");
                }
                if value & UFCON_FIFO_ENABLE == 0 {
                    return Err("UFCON non-FIFO mode is not modeled");
                }
                if value & UFCON_RX_RESET != 0 {
                    self.rx.clear();
                }
                if value & UFCON_TX_RESET != 0 {
                    self.tx.clear();
                }
                self.ufcon = value & UFCON_STORED;
            }
            UMCON => {
                if value & !UMCON_SUPPORTED != 0 {
                    return Err("UMCON reserved field is not modeled");
                }
                self.umcon = value;
            }
            UTRSTAT => {
                if value & !(UTRSTAT_CLEARABLE | UTRSTAT_READ_ONLY) != 0 {
                    return Err("UTRSTAT reserved field is not modeled");
                }
                self.status &= !(value & UTRSTAT_CLEARABLE);
            }
            UTXH => {
                if self.configuration & TRANSFER_CONFIGURATION != TRANSFER_CONFIGURATION {
                    return Err(
                        "UART framing/FIFO configuration after power loss or reset is unknown",
                    );
                }
                if field(self.ucon, UCON_TRANSMIT_MODE_SHIFT)
                    != UCON_MODE_INTERRUPT_OR_POLLING as usize
                {
                    return Err("UTXH written while UCON transmit mode is disabled");
                }
                if self.tx.len() == FIFO_BYTES {
                    return Err("UTXH written while the transmit FIFO is full");
                }
                self.tx.push_back(value as u8);
                let peak = self.tx.len();
                self.drain_tx(peak);
            }
            UBRDIV => {
                if value & !UBRDIV_FIELDS != 0 {
                    return Err("UBRDIV reserved field is not modeled");
                }
                self.ubrdiv = Some(value);
            }
            UERSTAT | UFSTAT | UMSTAT | URXH => return Err("read-only register"),
            UABRCNT => return Err("UABRCNT auto-baud count is not modeled"),
            UTXOFFSET | URXOFFSET => return Err("UTXOFFSET/URXOFFSET are not modeled"),
            UVER => return Err("UVER version value is not known"),
            _ => return Err("unknown S5L UART register"),
        }
        if offset <= UMCON {
            self.configuration |= 1 << (offset / 4);
        }
        Ok(())
    }
    fn read_register(&mut self, offset: u64) -> Result<u32, &'static str> {
        if offset <= UMCON && self.configuration & (1 << (offset / 4)) == 0 {
            return Err("UART configuration reset value has not been qualified");
        }
        Ok(match offset {
            ULCON => self.ulcon,
            UCON => self.ucon,
            UFCON => self.ufcon,
            UMCON => self.umcon,
            UTRSTAT => self.utrstat(),
            // The console never reports overrun, parity, frame or break.
            UERSTAT => 0,
            UFSTAT => self.ufstat(),
            UMSTAT => UMSTAT_CTS,
            URXH => u32::from(
                self.rx
                    .pop_front()
                    .ok_or("URXH read while the receive FIFO is empty")?,
            ),
            UBRDIV => self
                .ubrdiv
                .ok_or("UBRDIV read before the guest programmed it")?,
            UTXH => return Err("write-only register"),
            UABRCNT => return Err("UABRCNT auto-baud count is not modeled"),
            UTXOFFSET | URXOFFSET => return Err("UTXOFFSET/URXOFFSET are not modeled"),
            UVER => return Err("UVER version value is not known"),
            _ => return Err("unknown S5L UART register"),
        })
    }

    fn mmio_ready(&self) -> Result<(), &'static str> {
        if !self.lifecycle.powered {
            return Err("UART power domain is off");
        }
        if !self.lifecycle.clocked {
            return Err("UART clock is gated");
        }
        if self.lifecycle.reset {
            return Err("UART physical reset is asserted");
        }
        Ok(())
    }

    fn active(&self) -> bool {
        self.mmio_ready().is_ok() && !self.lifecycle.quiesced
    }
}

impl<C: ConsoleSink> Lifecycle for S5lUart<C> {
    fn check_lifecycle(&self, _: LifecycleState) -> Result<(), &'static str> {
        Ok(())
    }

    fn set_lifecycle(&mut self, proposed: LifecycleState, access: &mut Access<'_>) {
        if self.lifecycle.powered && !proposed.powered && !proposed.retention
            || !self.lifecycle.reset && proposed.reset
        {
            // The external console and already transmitted bytes survive.
            // Configuration values after physical reset are not inferred
            // from the boot firmware's configured handoff.
            self.configuration = 0;
            self.ubrdiv = None;
            self.status = 0;
            self.tx.clear();
            self.rx.clear();
        }
        self.lifecycle = proposed;
        self.flush(access);
    }
}

fn field(register: u32, shift: u32) -> usize {
    (register >> shift & 0b11) as usize
}

impl<C: ConsoleSink + 'static> MmioDevice for S5lUart<C> {
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        Some(self)
    }
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(
        &mut self,
        offset: u64,
        width: Width,
        access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        if width != Width::Word {
            return Err(refuse(
                NAME,
                offset,
                width,
                Direction::Read,
                "S5L UART registers are 32-bit",
            ));
        }
        self.mmio_ready()
            .map_err(|reason| refuse(NAME, offset, width, Direction::Read, reason))?;
        let value = self
            .read_register(offset)
            .map_err(|reason| refuse(NAME, offset, width, Direction::Read, reason))?;
        self.update_irq(access);
        Ok(u64::from(value))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        if width != Width::Word {
            return Err(refuse(
                NAME,
                offset,
                width,
                Direction::Write,
                "S5L UART registers are 32-bit",
            ));
        }
        self.mmio_ready()
            .map_err(|reason| refuse(NAME, offset, width, Direction::Write, reason))?;
        self.write_register(offset, value as u32)
            .map_err(|reason| refuse(NAME, offset, width, Direction::Write, reason))?;
        self.update_irq(access);
        Ok(())
    }
    fn advance(&mut self, access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        if !self.tx.is_empty() {
            self.flush(access);
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
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
    fn retained_pauses_preserve_fifo_and_irq_without_transmitting_while_gated() {
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
}

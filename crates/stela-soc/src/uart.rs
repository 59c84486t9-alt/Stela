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
use crate::Result;
use alloc::collections::VecDeque;
use stela_contracts::refuse;
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
    /// Takes one pending host byte; an empty source must return immediately.
    fn poll(&mut self) -> Option<u8> {
        None
    }
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
    fn receive(&mut self, bytes: &[u8], access: &mut Access<'_>) -> usize {
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

    fn poll_input(&mut self, access: &mut Access<'_>) {
        if !self.active()
            || self.configuration & TRANSFER_CONFIGURATION != TRANSFER_CONFIGURATION
            || self.ucon & UCON_RECEIVE_MODE == 0
        {
            return;
        }
        let mut bytes = [0; FIFO_BYTES];
        let mut count = 0;
        while count < FIFO_BYTES - self.rx.len() {
            let Some(byte) = self.console.poll() else {
                break;
            };
            bytes[count] = byte;
            count += 1;
        }
        if count != 0 {
            self.receive(&bytes[..count], access);
        }
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
    fn write_register(&mut self, offset: u64, value: u32) -> Result<()> {
        match offset {
            ULCON => {
                if value & !ULCON_FRAMING != 0 {
                    return Err(refuse!(
                        "ULCON infra-red, inverted or reserved mode is not modeled"
                    ));
                }
                if value & ULCON_WORD_LENGTH != ULCON_WORD_LENGTH_8_BITS {
                    return Err(refuse!(
                        "ULCON word lengths other than 8 bits are not modeled"
                    ));
                }
                self.ulcon = value;
            }
            UCON => {
                if value & !UCON_SUPPORTED != 0 {
                    return Err(refuse!(
                        "UCON break, loopback, auto-baud, transmit stop, software reset or reserved field is not modeled"
                    ));
                }
                let rx_mode = value & UCON_RECEIVE_MODE;
                let tx_mode = value >> UCON_TRANSMIT_MODE_SHIFT & UCON_RECEIVE_MODE;
                if rx_mode > UCON_MODE_INTERRUPT_OR_POLLING
                    || tx_mode > UCON_MODE_INTERRUPT_OR_POLLING
                {
                    return Err(refuse!(
                        "UCON DMA or undefined transfer mode is not modeled"
                    ));
                }
                self.ucon = value;
            }
            UFCON => {
                if value & !(UFCON_STORED | UFCON_RX_RESET | UFCON_TX_RESET) != 0 {
                    return Err(refuse!("UFCON reserved field is not modeled"));
                }
                if value & UFCON_FIFO_ENABLE == 0 {
                    return Err(refuse!("UFCON non-FIFO mode is not modeled"));
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
                    return Err(refuse!("UMCON reserved field is not modeled"));
                }
                self.umcon = value;
            }
            UTRSTAT => {
                if value & !(UTRSTAT_CLEARABLE | UTRSTAT_READ_ONLY) != 0 {
                    return Err(refuse!("UTRSTAT reserved field is not modeled"));
                }
                self.status &= !(value & UTRSTAT_CLEARABLE);
            }
            UTXH => {
                if self.configuration & TRANSFER_CONFIGURATION != TRANSFER_CONFIGURATION {
                    return Err(refuse!(
                        "UART framing/FIFO configuration after power loss or reset is unknown"
                    ));
                }
                if field(self.ucon, UCON_TRANSMIT_MODE_SHIFT)
                    != UCON_MODE_INTERRUPT_OR_POLLING as usize
                {
                    return Err(refuse!("UTXH written while UCON transmit mode is disabled"));
                }
                if self.tx.len() == FIFO_BYTES {
                    return Err(refuse!("UTXH written while the transmit FIFO is full"));
                }
                self.tx.push_back(value as u8);
                let peak = self.tx.len();
                self.drain_tx(peak);
            }
            UBRDIV => {
                if value & !UBRDIV_FIELDS != 0 {
                    return Err(refuse!("UBRDIV reserved field is not modeled"));
                }
                self.ubrdiv = Some(value);
            }
            UERSTAT | UFSTAT | UMSTAT | URXH => return Err(refuse!("read-only register")),
            UABRCNT => return Err(refuse!("UABRCNT auto-baud count is not modeled")),
            UTXOFFSET | URXOFFSET => return Err(refuse!("UTXOFFSET/URXOFFSET are not modeled")),
            UVER => return Err(refuse!("UVER version value is not known")),
            _ => return Err(refuse!("unknown S5L UART register")),
        }
        if offset <= UMCON {
            self.configuration |= 1 << (offset / 4);
        }
        Ok(())
    }
    fn read_register(&mut self, offset: u64) -> Result<u32> {
        if offset <= UMCON && self.configuration & (1 << (offset / 4)) == 0 {
            return Err(refuse!(
                "UART configuration reset value has not been qualified"
            ));
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
                    .ok_or(refuse!("URXH read while the receive FIFO is empty"))?,
            ),
            UBRDIV => self
                .ubrdiv
                .ok_or(refuse!("UBRDIV read before the guest programmed it"))?,
            UTXH => return Err(refuse!("write-only register")),
            UABRCNT => return Err(refuse!("UABRCNT auto-baud count is not modeled")),
            UTXOFFSET | URXOFFSET => return Err(refuse!("UTXOFFSET/URXOFFSET are not modeled")),
            UVER => return Err(refuse!("UVER version value is not known")),
            _ => return Err(refuse!("unknown S5L UART register")),
        })
    }

    fn mmio_ready(&self) -> Result<()> {
        if !self.lifecycle.powered {
            return Err(refuse!("UART power domain is off"));
        }
        if !self.lifecycle.clocked {
            return Err(refuse!("UART clock is gated"));
        }
        if self.lifecycle.reset {
            return Err(refuse!("UART physical reset is asserted"));
        }
        Ok(())
    }

    fn active(&self) -> bool {
        self.mmio_ready().is_ok() && !self.lifecycle.quiesced
    }
}

impl<C: ConsoleSink> Lifecycle for S5lUart<C> {
    fn check_lifecycle(&self, _: LifecycleState) -> Result<()> {
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
        self.poll_input(access);
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
        self.poll_input(access);
        if !self.tx.is_empty() {
            self.flush(access);
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests;

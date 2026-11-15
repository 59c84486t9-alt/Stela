//! Apple `spi-1,spimc`, version 1, byte PIO.
//!
//! Sources: m1n1 `proxyclient/m1n1/hw/spi.py` (v1 STATUS.TX_COMPLETE
//! is bit 22, unlike later Linux controllers), Linux `drivers/spi/spi-apple.c`
//! (FIFO depth 16 and register fields), and 26A434 kernel
//! `AppleSPIMCController::_executeSPICommandPIO` file 0x2dbde3c,
//! `_interruptActionSubr` 0x2dbf68c, `_setInternalCS` 0x2dc00cc,
//! `_getTxFIFOCount` 0x2dc02b8 and `_getRxFIFOCount` 0x2dc0348.
//! The shifter runs eagerly on accesses until a FIFO stalls: no host I/O or
//! transfer-time guarantee. The boot stage leaves it stopped, CS inactive,
//! FIFOs/counts/configuration zero (Stela boot-chain choices). Only byte,
//! MSB-first PIO is supported; DMA and wider words refuse.
//!
//! Linux `spi-apple.c` (the same M1-family controller) also names SHIFTCFG
//! 0x150 and DELAY_PRE/POST 0x160/0x168, which 26A434
//! `AppleSPIMCController::_configureHardwareDelay` (file 0x2dbcf34) uses: its
//! software-delay branch clears SHIFTCFG.OVERRIDE_CS (bit 24) and both delay
//! enables by RMW. The boot stage leaves all three zero (Linux's own init
//! state). Delays only change timing, which the eager shifter never
//! guarantees, so their words are held. Only OVERRIDE_CS may change in
//! SHIFTCFG, and only while an external GPIO drives the chip select, since
//! the internal CS output is then disconnected from the attached device.
use crate::Result;
use crate::aic::ClaimStamp;
use alloc::vec::Vec;
use stela_contracts::Refusal;
use stela_contracts::refuse;
use {
    super::nor::Nor, stela_contracts::bus::Access, stela_contracts::bus::Direction,
    stela_contracts::bus::Lifecycle, stela_contracts::bus::LifecycleState,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError, stela_contracts::bus::Width,
    stela_contracts::bus::refuse, stela_contracts::interrupt::AicInput,
    stela_contracts::interrupt::Wire, stela_soc_data::nor::Image,
};

const NAME: &str = "Apple SPI v1";
const CTRL: u64 = 0x00;
const CFG: u64 = 0x04;
const STATUS: u64 = 0x08;
const PIN: u64 = 0x0c;
const TXDATA: u64 = 0x10;
const RXDATA: u64 = 0x20;
const CLKDIV: u64 = 0x30;
const RXCNT: u64 = 0x34;
const DELAY: u64 = 0x38;
const TXCNT: u64 = 0x4c;
const FIFOSTAT: u64 = 0x10c;
const SHIFTCFG: u64 = 0x150;
const DELAY_PRE: u64 = 0x160;
const DELAY_POST: u64 = 0x168;
const OVERRIDE_CS: u32 = 1 << 24;
const RUN: u32 = 1;
const TX_RESET: u32 = 1 << 2;
const RX_RESET: u32 = 1 << 3;
const CS_HIGH: u32 = 1 << 1;
const FIFO_DEPTH: usize = 16;
const RX_COMPLETE: u32 = 1;
const THRESHOLD: u32 = 1 << 1;
const TX_COMPLETE: u32 = 1 << 22;
const MODE: u32 = 3 << 5;
const IRQ_MODE: u32 = 1 << 5;
const IE_RX_COMPLETE: u32 = 1 << 7;
const IE_THRESHOLD: u32 = 1 << 8;
const IE_TX_COMPLETE: u32 = 1 << 21;
const FIFO_THRESHOLD: u32 = 3 << 17;
const CONFIG_MASK: u32 = 6 | MODE | IE_RX_COMPLETE | IE_THRESHOLD | IE_TX_COMPLETE | FIFO_THRESHOLD;
const TRANSFER_CONFIGURATION: u8 = 3; // CTRL and CFG.
/// SHIFTCFG and DELAY_PRE/POST: a power cycle or reset restores the boot
/// stage's zero words, which `_configureHardwareDelay` read-modify-writes
/// after power-up (file 0x2dbcf34) without writing them first.
const RESET_CONFIGURATION: u8 = 0xe0;

fn configuration_bit(offset: u64) -> u8 {
    match offset {
        CTRL => 1,
        CFG => 2,
        PIN => 4,
        CLKDIV => 8,
        DELAY => 16,
        SHIFTCFG => 32,
        DELAY_PRE => 64,
        DELAY_POST => 128,
        _ => 0,
    }
}

/// A byte FIFO of [`FIFO_DEPTH`]: a copy of its value, not of the heap,
/// is what a refused transfer restores.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Fifo {
    bytes: [u8; FIFO_DEPTH],
    start: usize,
    len: usize,
}

impl Fifo {
    fn len(&self) -> usize {
        self.len
    }
    fn is_empty(&self) -> bool {
        self.len == 0
    }
    fn front(&self) -> Option<u8> {
        (self.len != 0).then(|| self.bytes[self.start])
    }
    fn pop_front(&mut self) -> Option<u8> {
        let byte = self.front()?;
        self.start = (self.start + 1) % FIFO_DEPTH;
        self.len -= 1;
        Some(byte)
    }
    /// Callers check for room first.
    fn push_back(&mut self, byte: u8) {
        assert!(self.len < FIFO_DEPTH, "SPI FIFO overflow");
        self.bytes[(self.start + self.len) % FIFO_DEPTH] = byte;
        self.len += 1;
    }
    fn push_front(&mut self, byte: u8) {
        assert!(self.len < FIFO_DEPTH, "SPI FIFO overflow");
        self.start = (self.start + FIFO_DEPTH - 1) % FIFO_DEPTH;
        self.bytes[self.start] = byte;
        self.len += 1;
    }
    fn clear(&mut self) {
        *self = Self::default();
    }
}

/// What the controller did since the host last asked ([`Spi::take_activity`]),
/// on every PE: the guest's NVRAM sync runs through it inside XNU's 30 s
/// halt/restart timer, so the host logs where a slow sync spent its time.
/// Times are system counter ticks (`counter::FREQUENCY_HZ`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Activity {
    /// Register accesses, refused ones included.
    pub accesses: u64,
    /// NOR commands: chip select falling edges.
    pub commands: u64,
    /// Bytes the shifter moved.
    pub bytes: u64,
    /// Times the interrupt line rose.
    pub interrupts: u64,
    /// Ticks the line stayed high until an access or power change lowered
    /// it, summed, and the longest of them.
    pub interrupt_ticks: u64,
    pub longest_interrupt_ticks: u64,
    /// Ticks from each command's first register access to its last one
    /// before chip select rose, summed.
    pub selected_ticks: u64,
    /// Rises during a register access, the rest during an advance or a
    /// power change.
    pub raised_in_access: u64,
    /// Rises a CPU's AIC event read claimed before the driver's next
    /// register access ([`Spi::watch_claims`]): ticks from the rise to the
    /// claim (the host's delivery and the guest's own IRQ masking) and
    /// from the claim to that access (the guest's handler, its work loop's
    /// wake and scheduling), summed and the longest; the claims by CPU
    /// (CPUs past the array in its last entry), and those by the CPU whose
    /// access raised the line.
    pub claimed: u64,
    pub claim_ticks: u64,
    pub longest_claim_ticks: u64,
    pub answer_ticks: u64,
    pub longest_answer_ticks: u64,
    pub claims_by_cpu: [u32; CLAIM_CPUS],
    pub claimed_by_raiser: u64,
    /// Rises the line fell from with no claim since (the driver polled or
    /// answered before taking the IRQ), and their ticks from rise to fall.
    pub unclaimed: u64,
    pub unclaimed_ticks: u64,
    /// Calls on a board shared between PEs that accessed this controller
    /// ([`Spi::touched`]), the host counter ticks they waited for the
    /// board's lock and held it, summed, and the longest hold: the part of
    /// each access spent on the board, apart from the guest's own code and
    /// its exits between accesses.
    pub locked: u64,
    pub lock_waited_ticks: u64,
    pub lock_held_ticks: u64,
    pub longest_lock_held_ticks: u64,
}

/// Set by each register access of a [`Spi`] that has one; the board's lock
/// release clears it ([`Spi::touched`]).
pub type TouchStamp = alloc::rc::Rc<core::cell::Cell<bool>>;

/// CPUs [`Activity::claims_by_cpu`] counts apart.
pub const CLAIM_CPUS: usize = 32;

pub struct Spi {
    nor: Nor,
    irq: AicInput,
    activity: Activity,
    /// When the interrupt line last rose, while it stays high.
    raised: Option<u64>,
    /// The CPU whose access raised it, and whether the driver's first
    /// access after a claim of it was counted.
    raiser: usize,
    answered: bool,
    /// The AIC's last claim of this controller's input, when wired.
    claims: Option<ClaimStamp>,
    /// Marked at each register access, when wired ([`Spi::touched`]).
    touch: Option<TouchStamp>,
    /// The current command's first and latest register access.
    selected: Option<(u64, u64)>,
    control: u32,
    config: u32,
    pin: u32,
    divider: u32,
    delay: u32,
    shift: u32,
    cs_delays: [u32; 2],
    status: u32,
    tx_count: u32,
    rx_count: u32,
    tx: Fifo,
    rx: Fifo,
    /// External CS wiring disables the internal PIN output's connection.
    external_cs: bool,
    lifecycle: LifecycleState,
    configuration: u8,
}
impl Spi {
    pub fn new(image: Image, irq: AicInput, external_cs: bool) -> Self {
        Self {
            nor: Nor::new(image),
            irq,
            activity: Activity::default(),
            raised: None,
            raiser: usize::MAX,
            answered: false,
            claims: None,
            touch: None,
            selected: None,
            control: 0,
            config: 0,
            pin: CS_HIGH,
            divider: 0,
            delay: 0,
            shift: 0,
            cs_delays: [0; 2],
            status: 0,
            tx_count: 0,
            rx_count: 0,
            tx: Fifo::default(),
            rx: Fifo::default(),
            external_cs,
            lifecycle: LifecycleState {
                powered: true,
                clocked: true,
                quiesced: false,
                reset: false,
                retention: false,
            },
            configuration: u8::MAX,
        }
    }
    /// The NOR image as programs and erases left it.
    pub fn image(&self) -> &Image {
        self.nor.image()
    }
    /// The NOR sectors changed since the last call (`Nor::take_dirty`).
    pub fn take_dirty(&mut self) -> Vec<(usize, Vec<u8>)> {
        self.nor.take_dirty()
    }
    /// Board wiring, independent of command/transfer boundaries. External
    /// GPIO's output is active low, just as PIN.CS is for internal selection.
    pub(crate) fn check_cs(&self, high: bool) -> Result<()> {
        self.nor.check_select(!high)
    }
    pub fn set_cs(&mut self, high: bool) -> Result<()> {
        let was = self.nor.selected();
        self.nor.select(!high)?;
        match (was, self.nor.selected()) {
            (false, true) => {
                self.activity.commands += 1;
                self.selected = None;
            }
            (true, false) => self.deselected(),
            _ => (),
        }
        Ok(())
    }
    /// Close the current command's span at chip select rising.
    fn deselected(&mut self) {
        if let Some((first, last)) = self.selected.take() {
            self.activity.selected_ticks += last.saturating_sub(first);
        }
    }
    /// The activity since the last call ([`Activity`]).
    pub fn take_activity(&mut self) -> Activity {
        core::mem::take(&mut self.activity)
    }
    /// This controller's AIC input.
    pub fn irq(&self) -> AicInput {
        self.irq
    }
    /// Split each interrupt wait at the AIC's claim of the line, which the
    /// AIC writes to `claims` ([`crate::aic::Aic2::watch_claims`]).
    pub fn watch_claims(&mut self, claims: ClaimStamp) {
        self.claims = Some(claims);
    }
    /// Mark `touch` at each register access, which the board's owner reads
    /// at each release of its lock to count that call's lock time here
    /// ([`Self::locked`]).
    pub fn touched(&mut self, touch: TouchStamp) {
        self.touch = Some(touch);
    }
    /// Count one call that accessed this controller: it waited `waited`
    /// host counter ticks for the board's lock and held it `held`.
    pub fn locked(&mut self, waited: u64, held: u64) {
        let activity = &mut self.activity;
        activity.locked += 1;
        activity.lock_waited_ticks += waited;
        activity.lock_held_ticks += held;
        activity.longest_lock_held_ticks = activity.longest_lock_held_ticks.max(held);
    }
    /// The claim of the line since it last rose at `raised`, if any.
    fn claim_since(&self, raised: u64) -> Option<(u64, usize)> {
        self.claims
            .as_ref()
            .and_then(|claims| claims.get())
            .filter(|&(at, _)| at >= raised)
    }
    /// Count a register access at `now`, within the current command's
    /// span while the die is selected, and the driver's first access after
    /// a claim of a raised line.
    fn accessed(&mut self, now: u64) {
        if let Some(raised) = self.raised
            && !self.answered
            && let Some((claimed, cpu)) = self.claim_since(raised)
        {
            self.answered = true;
            let activity = &mut self.activity;
            let (claim, answer) = (claimed - raised, now.saturating_sub(claimed));
            activity.claimed += 1;
            activity.claim_ticks += claim;
            activity.longest_claim_ticks = activity.longest_claim_ticks.max(claim);
            activity.answer_ticks += answer;
            activity.longest_answer_ticks = activity.longest_answer_ticks.max(answer);
            activity.claims_by_cpu[cpu.min(CLAIM_CPUS - 1)] += 1;
            activity.claimed_by_raiser += u64::from(cpu == self.raiser);
        }
        self.activity.accesses += 1;
        if let Some(touch) = &self.touch {
            touch.set(true);
        }
        if self.nor.selected() {
            let first = self.selected.map_or(now, |(first, _)| first);
            self.selected = Some((first, now));
        }
    }
    fn error(
        offset: u64,
        width: Width,
        direction: Direction,
        reason: impl Into<Refusal>,
    ) -> MmioError {
        refuse(NAME, offset, width, direction, reason)
    }
    fn threshold(&self) -> bool {
        let threshold = match (self.config & FIFO_THRESHOLD) >> 17 {
            0 => 8,
            1 => 4,
            2 => 1,
            _ => return false,
        };
        self.config & MODE == IRQ_MODE
            && (self.rx.len() >= threshold
                || self.tx_count != 0 && FIFO_DEPTH - self.tx.len() >= threshold)
    }
    fn status(&self) -> u32 {
        self.status | if self.threshold() { THRESHOLD } else { 0 }
    }
    fn interrupt(&mut self, access: &mut Access<'_>, in_access: bool) {
        let status = self.status();
        let enabled = (status & RX_COMPLETE != 0 && self.config & IE_RX_COMPLETE != 0)
            || (status & THRESHOLD != 0 && self.config & IE_THRESHOLD != 0)
            || (status & TX_COMPLETE != 0 && self.config & IE_TX_COMPLETE != 0);
        let level = self.active() && enabled;
        match (self.raised, level) {
            (None, true) => {
                self.raised = Some(access.now);
                self.raiser = access.cpu;
                self.answered = false;
                self.activity.interrupts += 1;
                self.activity.raised_in_access += u64::from(in_access);
            }
            (Some(raised), false) => {
                let ticks = access.now.saturating_sub(raised);
                self.raised = None;
                if !self.answered && self.claim_since(raised).is_none() {
                    self.activity.unclaimed += 1;
                    self.activity.unclaimed_ticks += ticks;
                }
                self.activity.interrupt_ticks += ticks;
                self.activity.longest_interrupt_ticks =
                    self.activity.longest_interrupt_ticks.max(ticks);
            }
            _ => (),
        }
        access.interrupts.set_level(Wire::Aic(self.irq), level);
    }

    fn mmio_ready(&self) -> Result<()> {
        if !self.lifecycle.powered {
            return Err(refuse!("SPI power domain is off"));
        }
        if !self.lifecycle.clocked {
            return Err(refuse!("SPI clock is gated"));
        }
        if self.lifecycle.reset {
            return Err(refuse!("SPI physical reset is asserted"));
        }
        Ok(())
    }

    fn active(&self) -> bool {
        self.mmio_ready().is_ok() && !self.lifecycle.quiesced
    }
    fn pump(&mut self) -> Result<()> {
        // An idle controller moves nothing: skip the rollback copies that
        // every device advance would otherwise take.
        if !self.active() || self.control & RUN == 0 {
            return Ok(());
        }
        let checkpoint = self.nor.checkpoint();
        let (tx, rx, tx_count, rx_count, status, bytes) = (
            self.tx,
            self.rx,
            self.tx_count,
            self.rx_count,
            self.status,
            self.activity.bytes,
        );
        if let Err(error) = self.pump_inner() {
            self.nor.restore(checkpoint);
            self.tx = tx;
            self.rx = rx;
            self.tx_count = tx_count;
            self.rx_count = rx_count;
            self.status = status;
            self.activity.bytes = bytes;
            return Err(error);
        }
        Ok(())
    }
    fn pump_inner(&mut self) -> Result<()> {
        if !self.active() || self.control & RUN == 0 {
            return Ok(());
        }
        if self.configuration & TRANSFER_CONFIGURATION != TRANSFER_CONFIGURATION {
            return Err(refuse!(
                "SPI control and transfer configuration require initialization"
            ));
        }
        while self.tx_count != 0 || self.rx_count != 0 {
            if self.rx_count != 0 && self.rx.len() == FIFO_DEPTH {
                break;
            }
            let byte = if self.tx_count != 0 {
                let Some(byte) = self.tx.front() else {
                    break;
                };
                byte
            } else {
                0xff
            };
            let incoming = self.nor.shift(byte)?;
            self.activity.bytes += 1;
            if self.tx_count != 0 {
                self.tx.pop_front();
                self.tx_count -= 1;
                if self.tx_count == 0 {
                    self.status |= TX_COMPLETE;
                }
            }
            if self.rx_count != 0 {
                self.rx.push_back(incoming);
                self.rx_count -= 1;
                if self.rx_count == 0 {
                    self.status |= RX_COMPLETE;
                }
            }
        }
        Ok(())
    }
}

impl Lifecycle for Spi {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<()> {
        if (self.lifecycle.powered && !proposed.powered && !proposed.retention
            || !self.lifecycle.reset && proposed.reset)
            && !self.external_cs
        {
            self.nor.check_select(false)?;
        }
        Ok(())
    }

    fn set_lifecycle(&mut self, proposed: LifecycleState, access: &mut Access<'_>) {
        if self.lifecycle.powered && !proposed.powered && !proposed.retention
            || !self.lifecycle.reset && proposed.reset
        {
            if !self.external_cs {
                // Internal CS rising may commit an accepted NOR
                // program prefix. Its preflight ran before PMGR completion.
                self.nor.select(false).expect("checked internal SPI CS");
                self.deselected();
            }
            // External GPIO CS and the flash die are separate hardware:
            // keep their transaction, image, WEL and dirty sectors.
            self.control = 0;
            self.status = 0;
            self.tx_count = 0;
            self.rx_count = 0;
            self.tx.clear();
            self.rx.clear();
            self.shift = 0;
            self.cs_delays = [0; 2];
            self.configuration = RESET_CONFIGURATION;
        }
        self.lifecycle = proposed;
        self.interrupt(access, false);
    }
}

impl MmioDevice for Spi {
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
        self.accessed(access.now);
        let error = |reason: Refusal| Self::error(offset, width, Direction::Read, reason);
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(error(refuse!(
                "SPI registers require aligned 32-bit accesses"
            )));
        }
        self.mmio_ready().map_err(error)?;
        let bit = configuration_bit(offset);
        if bit != 0 && self.configuration & bit == 0 {
            return Err(error(refuse!(
                "SPI configuration reset value has not been qualified"
            )));
        }
        let value = match offset {
            CTRL => self.control,
            CFG => self.config,
            STATUS => self.status(),
            PIN => self.pin,
            CLKDIV => self.divider,
            DELAY => self.delay,
            SHIFTCFG => self.shift,
            DELAY_PRE => self.cs_delays[0],
            DELAY_POST => self.cs_delays[1],
            TXCNT => self.tx_count,
            RXCNT => self.rx_count,
            FIFOSTAT => {
                ((self.tx.len() as u32) << 8)
                    | ((self.rx.len() as u32) << 24)
                    | if self.tx.len() == FIFO_DEPTH {
                        1 << 4
                    } else {
                        0
                    }
                    | if self.rx.is_empty() { 1 << 20 } else { 0 }
            }
            RXDATA => {
                let byte = self
                    .rx
                    .front()
                    .ok_or_else(|| error(refuse!("SPI RX FIFO underflow")))?;
                // Consume only after validating the next shift. The incoming
                // command byte is validated by TXDATA, before it is queued.
                self.rx.pop_front();
                if let Err(reason) = self.pump() {
                    self.rx.push_front(byte);
                    return Err(error(reason));
                }
                u32::from(byte)
            }
            _ => return Err(error(refuse!("unmodeled SPI register"))),
        };
        self.interrupt(access, true);
        Ok(u64::from(value))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        self.accessed(access.now);
        let error = |reason: Refusal| Self::error(offset, width, Direction::Write, reason);
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(error(refuse!(
                "SPI registers require aligned 32-bit accesses"
            )));
        }
        self.mmio_ready().map_err(error)?;
        let value = value as u32;
        let saved = (
            self.control,
            self.tx_count,
            self.rx_count,
            self.status,
            self.config,
            self.divider,
            self.delay,
            self.tx,
            self.rx,
            self.configuration,
        );
        match offset {
            CTRL => {
                if value & !(RUN | RX_RESET | TX_RESET) != 0 {
                    return Err(error(refuse!("unmodeled SPI control bits")));
                }
                if value & TX_RESET != 0 {
                    self.tx.clear();
                }
                if value & RX_RESET != 0 {
                    self.rx.clear();
                }
                self.control = value & RUN;
            }
            CFG => {
                if value & !CONFIG_MASK != 0 || !matches!(value & MODE, 0 | IRQ_MODE) {
                    return Err(error(refuse!(
                        "SPI DMA, LSB-first, wide words or unknown configuration"
                    )));
                }
                self.config = value;
            }
            STATUS => self.status &= !value, // v1 W1C, including inactive error flags.
            PIN => {
                if value & !3 != 0 {
                    return Err(error(refuse!("unmodeled SPI pin bits")));
                }
                if !self.external_cs {
                    self.set_cs(value & CS_HIGH != 0).map_err(error)?;
                }
                self.pin = value;
            }
            TXDATA => {
                if value > 0xff {
                    return Err(error(refuse!("SPI byte FIFO write exceeds 8 bits")));
                }
                if self.tx.len() == FIFO_DEPTH {
                    return Err(error(refuse!("SPI TX FIFO overflow")));
                }
                self.tx.push_back(value as u8);
            }
            CLKDIV => {
                if value > 0x7ff {
                    return Err(error(refuse!("SPI divider exceeds 11 bits")));
                }
                self.divider = value;
            }
            DELAY => {
                if value > 0xffff {
                    return Err(error(refuse!("SPI delay exceeds 16 bits")));
                }
                self.delay = value;
            }
            SHIFTCFG => {
                if (value ^ self.shift) & !OVERRIDE_CS != 0 {
                    return Err(error(refuse!("SPI shifter configuration is not modeled")));
                }
                if value & OVERRIDE_CS != 0 && !self.external_cs {
                    return Err(error(refuse!(
                        "shifter-driven internal SPI chip select is not modeled"
                    )));
                }
                self.shift = value;
            }
            DELAY_PRE => self.cs_delays[0] = value,
            DELAY_POST => self.cs_delays[1] = value,
            TXCNT => {
                self.tx_count = value;
                self.status &= !TX_COMPLETE;
            }
            RXCNT => {
                self.rx_count = value;
                self.status &= !RX_COMPLETE;
            }
            _ => return Err(error(refuse!("unmodeled or read-only SPI register"))),
        }
        self.configuration |= configuration_bit(offset);
        if matches!(offset, CTRL | TXDATA | TXCNT | RXCNT)
            && let Err(reason) = self.pump()
        {
            (
                self.control,
                self.tx_count,
                self.rx_count,
                self.status,
                self.config,
                self.divider,
                self.delay,
                self.tx,
                self.rx,
                self.configuration,
            ) = saved;
            return Err(error(reason));
        }
        self.interrupt(access, true);
        Ok(())
    }

    fn advance(&mut self, access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        self.pump()
            .map_err(|reason| Self::error(CTRL, Width::Word, Direction::Write, reason))?;
        self.interrupt(access, false);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_contracts::interrupt::InterruptLatch;
    fn write(spi: &mut Spi, offset: u64, value: u32, access: &mut Access<'_>) {
        spi.write(offset, Width::Word, u64::from(value), access)
            .unwrap();
    }

    #[test]
    fn the_fifo_keeps_order_across_its_wrap_and_a_copy_restores_it() {
        let mut fifo = Fifo::default();
        for byte in 0..FIFO_DEPTH as u8 {
            fifo.push_back(byte);
        }
        assert_eq!(fifo.len(), FIFO_DEPTH);
        let full = fifo;
        for byte in 0..10 {
            assert_eq!(fifo.pop_front(), Some(byte));
        }
        // The next pushes wrap past the end of the storage.
        for byte in 100..109 {
            fifo.push_back(byte);
        }
        fifo.push_front(9);
        let order: alloc::vec::Vec<_> = core::iter::from_fn(|| fifo.pop_front()).collect();
        let expected: alloc::vec::Vec<u8> = (9..FIFO_DEPTH as u8).chain(100..109).collect();
        assert_eq!(order, expected);
        assert!(fifo.is_empty() && fifo.front().is_none());
        fifo = full;
        assert_eq!((fifo.len(), fifo.front()), (FIFO_DEPTH, Some(0)));
    }

    #[test]
    fn kept_pauses_preserve_queued_shifts_and_pending_interrupts() {
        let irq = AicInput::new(0, 749);
        let mut spi = Spi::new(Image::fresh(), irq, false);
        let mut latch = InterruptLatch::new();
        write(&mut spi, PIN, 0, &mut Access::new(0, 0, &mut latch));
        write(
            &mut spi,
            CFG,
            IRQ_MODE | IE_TX_COMPLETE,
            &mut Access::new(0, 0, &mut latch),
        );
        let active = spi.lifecycle;
        let paused = LifecycleState {
            quiesced: true,
            ..active
        };
        spi.check_lifecycle(paused).unwrap();
        spi.set_lifecycle(paused, &mut Access::new(0, 0, &mut latch));
        write(&mut spi, TXCNT, 1, &mut Access::new(0, 0, &mut latch));
        write(&mut spi, TXDATA, 0x06, &mut Access::new(0, 0, &mut latch));
        write(&mut spi, CTRL, RUN, &mut Access::new(0, 0, &mut latch));
        assert_eq!((spi.tx_count, spi.tx.front()), (1, Some(0x06)));
        assert_eq!(spi.status, 0);
        spi.advance(&mut Access::new(0, 0, &mut latch)).unwrap();
        assert_eq!(spi.tx_count, 1);
        spi.set_lifecycle(active, &mut Access::new(0, 0, &mut latch));
        spi.advance(&mut Access::new(0, 0, &mut latch)).unwrap();
        assert!(spi.tx.is_empty());
        assert!(latch.is_asserted(Wire::Aic(irq)));
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
        ] {
            spi.check_lifecycle(paused).unwrap();
            spi.set_lifecycle(paused, &mut Access::new(0, 0, &mut latch));
            assert!(!latch.is_asserted(Wire::Aic(irq)));
            assert!(
                spi.read(STATUS, Width::Word, &mut Access::new(0, 0, &mut latch))
                    .is_err()
            );
            spi.set_lifecycle(active, &mut Access::new(0, 0, &mut latch));
            assert!(latch.is_asserted(Wire::Aic(irq)));
        }
        write(&mut spi, PIN, CS_HIGH, &mut Access::new(0, 0, &mut latch));
        spi.nor.select(true).unwrap();
        spi.nor.shift(0x05).unwrap();
        assert_eq!(
            spi.nor.shift(0xff).unwrap() & 2,
            2,
            "WREN committed at the actual CS edge"
        );
    }

    #[test]
    fn destructive_preflight_keeps_incomplete_internal_cs_transactions_unchanged() {
        let irq = AicInput::new(0, 749);
        let mut spi = Spi::new(Image::fresh(), irq, false);
        spi.nor.select(true).unwrap();
        spi.nor.shift(0x02).unwrap();
        let active = spi.lifecycle;
        for proposed in [
            LifecycleState {
                reset: true,
                ..active
            },
            LifecycleState {
                powered: false,
                ..active
            },
        ] {
            assert_eq!(
                spi.check_lifecycle(proposed),
                Err(refuse!("incomplete NOR command at CS rising"))
            );
            assert_eq!(spi.lifecycle, active);
            assert!(spi.nor.selected());
            assert!(spi.take_dirty().is_empty());
        }
    }

    #[test]
    fn destructive_edges_preserve_the_die_and_only_cs_edges_commit_programs() {
        for external_cs in [false, true] {
            for reset in [false, true] {
                let irq = AicInput::new(0, 749);
                let mut spi = Spi::new(Image::fresh(), irq, external_cs);
                spi.nor.select(true).unwrap();
                spi.nor.shift(0x06).unwrap();
                spi.nor.select(false).unwrap();
                spi.nor.select(true).unwrap();
                for byte in [0x02, 0, 0, 0x20, 0xa5] {
                    spi.nor.shift(byte).unwrap();
                }
                let mut latch = InterruptLatch::new();
                let mut a = Access::new(0, 0, &mut latch);
                let active = spi.lifecycle;
                let down = LifecycleState {
                    powered: reset,
                    reset,
                    ..active
                };
                spi.check_lifecycle(down).unwrap();
                spi.set_lifecycle(down, &mut a);
                assert_eq!(spi.nor.selected(), external_cs);
                assert_eq!(
                    spi.image().bytes()[0x20],
                    if external_cs { 0xff } else { 0xa5 }
                );
                if external_cs {
                    assert!(spi.take_dirty().is_empty());
                    spi.set_cs(true).unwrap();
                }
                assert_eq!(spi.image().bytes()[0x20], 0xa5);
                assert_eq!(spi.take_dirty().len(), 1);
                spi.set_lifecycle(down, &mut a);
                assert!(
                    spi.take_dirty().is_empty(),
                    "held reset cannot replay the CS edge"
                );
                assert!(spi.read(CTRL, Width::Word, &mut a).is_err());
                spi.set_lifecycle(active, &mut a);
                assert!(spi.read(CTRL, Width::Word, &mut a).is_err());
                write(&mut spi, CTRL, 0, &mut a);
                assert_eq!(spi.read(CTRL, Width::Word, &mut a), Ok(0));
                assert!(spi.read(CFG, Width::Word, &mut a).is_err());
                assert_eq!(spi.read(DELAY_PRE, Width::Word, &mut a), Ok(0));
            }
        }
    }
    #[test]
    fn long_read_stalls_at_fifo_capacity_and_interrupt_clears_after_drain() {
        use stela_soc_data::nor::CAPACITY;
        let image = Image::from_bytes((0..CAPACITY).map(|i| i as u8).collect()).unwrap();
        let irq = AicInput::new(0, 749);
        let mut spi = Spi::new(image, irq, false);
        let mut latch = InterruptLatch::new();
        {
            let mut a = Access::new(0, 0, &mut latch);
            write(&mut spi, PIN, 0, &mut a);
            write(&mut spi, RXCNT, 4, &mut a);
            write(&mut spi, TXCNT, 4, &mut a);
            for b in [3, 0, 0, 0] {
                write(&mut spi, TXDATA, b, &mut a);
            }
            write(&mut spi, CTRL, RUN, &mut a);
            for _ in 0..4 {
                spi.read(RXDATA, Width::Word, &mut a).unwrap();
            }
            write(&mut spi, CTRL, TX_RESET | RX_RESET, &mut a);
            write(&mut spi, RXCNT, 300, &mut a);
            write(&mut spi, TXCNT, 300, &mut a);
            write(
                &mut spi,
                CFG,
                IRQ_MODE | IE_RX_COMPLETE | IE_THRESHOLD | 2 << 17,
                &mut a,
            );
            for _ in 0..FIFO_DEPTH {
                write(&mut spi, TXDATA, 0xff, &mut a);
            }
            write(&mut spi, CTRL, RUN, &mut a);
            assert_eq!(spi.rx.len(), FIFO_DEPTH);
            assert_eq!(spi.rx_count, 284);
            let mut sent = FIFO_DEPTH;
            for i in 0..300 {
                while sent < 300 && spi.tx.len() < FIFO_DEPTH {
                    write(&mut spi, TXDATA, 0xff, &mut a);
                    sent += 1;
                }
                assert_eq!(
                    spi.read(RXDATA, Width::Word, &mut a),
                    Ok(u64::from(i as u8))
                );
                assert!(spi.rx.len() <= FIFO_DEPTH);
            }
            assert_eq!((spi.rx_count, spi.tx_count), (0, 0));
        }
        assert!(latch.is_asserted(Wire::Aic(irq)));
        let mut a = Access::new(0, 0, &mut latch);
        write(&mut spi, STATUS, RX_COMPLETE | TX_COMPLETE, &mut a);
        assert!(!latch.is_asserted(Wire::Aic(irq)));
    }

    #[test]
    fn unsupported_nor_byte_does_not_start_or_consume_a_transfer() {
        let mut spi = Spi::new(Image::fresh(), AicInput::new(0, 749), false);
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        write(&mut spi, PIN, 0, &mut a);
        write(&mut spi, TXCNT, 1, &mut a);
        write(&mut spi, TXDATA, 0x5a, &mut a);
        assert!(spi.write(CTRL, Width::Word, 1, &mut a).is_err());
        assert_eq!((spi.control, spi.tx_count), (0, 1));
        assert_eq!(spi.tx.front(), Some(0x5a));
        write(&mut spi, CTRL, TX_RESET, &mut a);
        write(&mut spi, TXDATA, 0x06, &mut a);
        write(&mut spi, CTRL, RUN, &mut a);
        write(&mut spi, PIN, CS_HIGH, &mut a);
        assert_eq!(spi.nor.shift(0), Ok(0xff));
    }

    #[test]
    fn kernel_pio_jedec_sequence_and_w1c_interrupt() {
        let irq = AicInput::new(0, 749);
        let mut spi = Spi::new(Image::fresh(), irq, false);
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        write(&mut spi, PIN, 0, &mut a);
        write(&mut spi, CTRL, TX_RESET | RX_RESET, &mut a);
        write(&mut spi, RXCNT, 4, &mut a);
        write(&mut spi, TXCNT, 4, &mut a);
        write(&mut spi, CFG, IRQ_MODE | IE_RX_COMPLETE | 2 << 17, &mut a);
        for byte in [0x9f, 0xff, 0xff, 0xff] {
            write(&mut spi, TXDATA, byte, &mut a);
        }
        write(&mut spi, CTRL, RUN, &mut a);
        assert_eq!(
            spi.read(STATUS, Width::Word, &mut a).unwrap() & (1 | 1 << 22),
            1 | 1 << 22
        );

        let bytes: alloc::vec::Vec<_> = (0..4)
            .map(|_| spi.read(RXDATA, Width::Word, &mut a).unwrap())
            .collect();
        assert_eq!(bytes, [0xff, 0xef, 0x60, 0x17]);
        write(&mut spi, PIN, CS_HIGH, &mut a);
        write(&mut spi, STATUS, 0x400023, &mut a);
        assert_eq!(spi.read(STATUS, Width::Word, &mut a), Ok(0));
        assert!(!latch.is_asserted(Wire::Aic(irq)));
    }
    #[test]
    fn activity_counts_commands_bytes_interrupt_waits_and_command_spans() {
        let irq = AicInput::new(0, 749);
        let mut spi = Spi::new(Image::fresh(), irq, false);
        let mut latch = InterruptLatch::new();
        let at = |spi: &mut Spi, latch: &mut InterruptLatch, now: u64, offset: u64, value: u32| {
            write(spi, offset, value, &mut Access::new(0, now, latch));
        };
        at(&mut spi, &mut latch, 0, PIN, 0);
        at(&mut spi, &mut latch, 24, CFG, IRQ_MODE | IE_TX_COMPLETE);
        at(&mut spi, &mut latch, 48, TXCNT, 1);
        at(&mut spi, &mut latch, 60, TXDATA, 0x06);
        at(&mut spi, &mut latch, 72, CTRL, RUN);
        at(&mut spi, &mut latch, 72 + 2400, STATUS, TX_COMPLETE);
        at(&mut spi, &mut latch, 3000, PIN, CS_HIGH);
        // A refused shift moves no byte: the opcode is not a NOR command.
        at(&mut spi, &mut latch, 4000, PIN, 0);
        at(&mut spi, &mut latch, 4024, CTRL, TX_RESET);
        at(&mut spi, &mut latch, 4048, TXCNT, 1);
        at(&mut spi, &mut latch, 4060, TXDATA, 0x5a);
        assert!(
            spi.write(
                CTRL,
                Width::Word,
                u64::from(RUN),
                &mut Access::new(0, 4072, &mut latch)
            )
            .is_err()
        );
        assert_eq!(
            spi.take_activity(),
            Activity {
                accesses: 12,
                commands: 2,
                bytes: 1,
                interrupts: 1,
                interrupt_ticks: 2400,
                longest_interrupt_ticks: 2400,
                selected_ticks: 3000 - 24,
                raised_in_access: 1,
                // No AIC watches this controller: the wait is unsplit.
                unclaimed: 1,
                unclaimed_ticks: 2400,
                ..Activity::default()
            }
        );
        assert!(spi.nor.selected());
        assert_eq!(spi.take_activity(), Activity::default());
    }

    /// A wait splits at the AIC's claim: rise to claim, and claim to the
    /// driver's next register access, with the claiming CPU counted; a
    /// claim before the rise, or none, leaves the wait unclaimed.
    #[test]
    fn activity_splits_each_interrupt_wait_at_the_aic_claim() {
        let irq = AicInput::new(0, 749);
        let mut spi = Spi::new(Image::fresh(), irq, false);
        let claims = ClaimStamp::default();
        spi.watch_claims(claims.clone());
        let mut latch = InterruptLatch::new();
        let at = |spi: &mut Spi,
                  latch: &mut InterruptLatch,
                  cpu: usize,
                  now: u64,
                  offset: u64,
                  value: u32| {
            write(spi, offset, value, &mut Access::new(cpu, now, latch));
        };
        at(&mut spi, &mut latch, 3, 0, PIN, 0);
        at(&mut spi, &mut latch, 3, 10, CFG, IRQ_MODE | IE_TX_COMPLETE);
        // A claim from before the rise is not this one's.
        claims.set(Some((5, 1)));
        at(&mut spi, &mut latch, 3, 20, TXCNT, 1);
        at(&mut spi, &mut latch, 3, 30, TXDATA, 0x06);
        at(&mut spi, &mut latch, 3, 40, CTRL, RUN);
        assert!(latch.is_asserted(Wire::Aic(irq)));
        // CPU 0 claims it at 1040; the driver reads STATUS on CPU 5 at
        // 3040 and clears it at 3100.
        claims.set(Some((1040, 0)));
        assert_eq!(
            spi.read(STATUS, Width::Word, &mut Access::new(5, 3040, &mut latch)),
            Ok(u64::from(TX_COMPLETE))
        );
        at(&mut spi, &mut latch, 5, 3100, STATUS, TX_COMPLETE);
        assert!(!latch.is_asserted(Wire::Aic(irq)));
        // The second rise, by CPU 5, which claims it itself at once.
        at(&mut spi, &mut latch, 5, 3980, PIN, CS_HIGH);
        at(&mut spi, &mut latch, 5, 3990, PIN, 0);
        at(&mut spi, &mut latch, 5, 4000, TXCNT, 1);
        at(&mut spi, &mut latch, 5, 4010, TXDATA, 0x06);
        claims.set(Some((4010, 5)));
        at(&mut spi, &mut latch, 5, 4020, STATUS, TX_COMPLETE);
        // A third the driver clears before any claim.
        at(&mut spi, &mut latch, 5, 4980, PIN, CS_HIGH);
        at(&mut spi, &mut latch, 5, 4990, PIN, 0);
        at(&mut spi, &mut latch, 5, 5000, TXCNT, 1);
        at(&mut spi, &mut latch, 5, 5010, TXDATA, 0x06);
        at(&mut spi, &mut latch, 5, 5500, STATUS, TX_COMPLETE);
        let activity = spi.take_activity();
        let mut claims_by_cpu = [0; CLAIM_CPUS];
        claims_by_cpu[0] = 1;
        claims_by_cpu[5] = 1;
        assert_eq!(
            (
                activity.interrupts,
                activity.raised_in_access,
                activity.claimed,
                activity.claim_ticks,
                activity.longest_claim_ticks,
                activity.answer_ticks,
                activity.longest_answer_ticks,
                activity.claims_by_cpu,
                activity.claimed_by_raiser,
                activity.unclaimed,
                activity.unclaimed_ticks,
                activity.interrupt_ticks,
            ),
            (
                3,
                3,
                2,
                1000,
                1000,
                2000 + 10,
                2000,
                claims_by_cpu,
                1,
                1,
                490,
                3060 + 10 + 490
            )
        );
    }

    #[test]
    fn unknown_modes_and_fifo_errors_refuse() {
        let mut spi = Spi::new(Image::fresh(), AicInput::new(0, 1), false);
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        assert!(spi.write(CFG, Width::Word, 2 << 5, &mut a).is_err());
        assert!(spi.read(RXDATA, Width::Word, &mut a).is_err());
        for _ in 0..FIFO_DEPTH {
            write(&mut spi, TXDATA, 0xff, &mut a);
        }
        assert!(spi.write(TXDATA, Width::Word, 0xff, &mut a).is_err());
        assert_eq!(spi.tx.len(), FIFO_DEPTH);
        assert!(spi.read(0x134, Width::Word, &mut a).is_err());
        assert!(spi.write(CTRL, Width::Double, 1, &mut a).is_err());
    }
    #[test]
    fn shifter_cs_override_and_delays_are_kept_configuration() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut external = Spi::new(Image::fresh(), AicInput::new(0, 1), true);
        assert_eq!(external.read(SHIFTCFG, Width::Word, &mut access), Ok(0));
        external
            .write(SHIFTCFG, Width::Word, OVERRIDE_CS.into(), &mut access)
            .unwrap();
        external
            .write(SHIFTCFG, Width::Word, 0, &mut access)
            .unwrap();
        assert!(
            external
                .write(SHIFTCFG, Width::Word, 1, &mut access)
                .is_err()
        );
        external
            .write(DELAY_PRE, Width::Word, 0x823 | 9 << 16, &mut access)
            .unwrap();
        assert_eq!(
            external.read(DELAY_PRE, Width::Word, &mut access),
            Ok(0x823 | 9 << 16)
        );
        external
            .write(DELAY_POST, Width::Word, 0, &mut access)
            .unwrap();
        let mut internal = Spi::new(Image::fresh(), AicInput::new(0, 1), false);
        assert!(
            internal
                .write(SHIFTCFG, Width::Word, OVERRIDE_CS.into(), &mut access)
                .is_err()
        );
        assert_eq!(internal.read(SHIFTCFG, Width::Word, &mut access), Ok(0));
    }
}

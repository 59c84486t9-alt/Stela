//! The System Management Controller's key endpoint, native at its RTKit
//! boundary: AppleSMCKeysEndpoint's protocol on application endpoint 0x20,
//! a shared SRAM page for values that do not fit a message, a table of
//! typed keys, the system-event commands that restart and power off the
//! machine, and the notifications the SMC sends on its own.
//!
//! Evidence (26A434 J473AP kernel; unslid VAs, or KC file offsets where
//! marked "file"): AppleSMCKeysEndpoint builds a request as type (byte 0),
//! the caller's low nibble and a rolling 4-bit ID in the high nibble of
//! byte 1 (`_sendKeyMsgAndWaitForResponse` 0xfffffe0009da61c8), the size in
//! byte 2 and the key in bytes 4..7 as the 32-bit value whose bytes, most
//! significant first, spell it (`_readKeyWithSMC` 0xfffffe0009da6344: READ
//! 0x10, size 1..=120). A reply echoes byte 1, carries the result in byte 0
//! and the size in byte 2, and holds up to four value bytes in bytes 4..7;
//! a longer value is in the shared page (`_readKeyGated` 0xfffffe0009da6500,
//! result 0x87 when the reply is longer than asked). INITIALIZE (0x17) is
//! answered with the shared page's physical address, which must lie in the
//! nub's region-base..region-size (`_keyEndpointHandler`
//! 0xfffffe0009da5320, check at 0xfffffe0009da5a20). `#KEY` holds the key
//! count most significant byte first (`_smcInitKeyTableCache`
//! 0xfffffe0009da5d20). The other message types, the key information layout
//! (size, type code, flags) and the result codes are those Linux's Apple
//! SMC driver (`include/linux/mfd/macsmc.h`, the `macsmc` RTKit transport)
//! documents for the same protocol: WRITE 0x11 takes its value from the
//! shared page, GET_KEY_BY_INDEX 0x12 answers the key at an index of the
//! lexicographically sorted table, GET_KEY_INFO 0x13 writes six bytes to the
//! shared page, RW 0x20 writes then reads.
//!
//! Notifications. A message of type 0x18 from the SMC carries an event in
//! bytes 4..7: its class in byte 7, a subclass in byte 6 and two data
//! bytes (`_keyEndpointHandler` file 0x2da1410..0x2da1588 queues it,
//! `AppleSMC::_processUpstreamNotification` file 0x2da95e8 dispatches on
//! byte 7: 0x70 system state, 0x71 power state, 0x72 HID, 0x73 battery
//! authentication, 0x74 gas-gauge update, 0x75 system control, 0x76
//! thermal, 0x77 core analytics). The SMC sends them once the AP has set
//! the `NTAP` flag (`AppleSMC::_smcInitNotifications` file 0x2da83c0, Linux
//! macsmc). `AppleSMCPMU::_smcNotifyCallout` (file 0x2d9eaf8) turns HID
//! subclass 1 into a button event, byte 5 the button and byte 4 its state;
//! button 1 is the Consumer page's Power usage (0x0c/0x30, the jump table
//! at file 0x2d9f580), dispatched through `smc-pmu`'s `function-pmu_button`
//! to AppleM68Buttons. Linux `macsmc-input` reads the same event
//! (0x7201, button 1 power). `/buttons` `function-button_hold` reads
//! `bHLD` (`btnR`, `AppleSMCEmbeddedFunction::callFunction` file
//! 0x2d97994), the power button's current state.
//!
//! System events. `MBSE` takes a four-character command written as the
//! 32-bit value of its code, little-endian in the shared page:
//! - `offw`, `rest` and `slpw` announce a power-off, restart or sleep
//!   (`AppleSMCPMU::handleSystemPowerStateChange` file 0x2d9c24c, on
//!   kIOMessageSystemWillPowerOff/WillRestart/CapabilityChange), `waka` a
//!   wake (`AppleSMCPMU::callPlatformFunction` file 0x2d9dcec), `panb` a
//!   panic (`AppleSMC::callPlatformFunction` file 0x2daae84) and `pane` its
//!   end (`AppleDialogSPMIPMU::_handlePEHaltRestart` file 0x2dd01dc). They
//!   are notices: the SMC records them and nothing else changes.
//! - `phra` restarts the machine: the Dialog PMU's restart handler on a PMU
//!   with `info-has_phra` writes it through `smc-pmu`'s
//!   `function-external_standby` (`keyW MBSE`) and panics "SMCFW failed to
//!   handle restart request" if the machine is still running a second later
//!   (`_handlePEHaltRestart` .cold.2, file 0x2ddbd48); `sysr` is the same
//!   for a PMU with `info-has_sysrst` (.cold.1, file 0x2ddbc88).
//! - `susp` powers the machine off to standby: `_shutdownGated` (file
//!   0x2dd7178, "smc go stdby") writes it as the last step of
//!   `PEHaltRestart(kPEHaltCPU)` and panics "SMCFW failed to handle
//!   suspend/lpem request" a second later. `lpem` (low-power emergency
//!   mode, on battery systems) refuses: the board has no battery.
//!
//! AppleSMCPMU only takes the system-event path when `MBSE` reports a
//! 4-byte value (`AppleSMCPMU::start` file 0x2d9bfd8). Any other command
//! refuses, since its effect on the machine is unknown.
//!
//! `NESN` carries a notification from the AP to the SMC as class,
//! subclass and two data bytes. In a panic the AP writes `70 8a 00 00`
//! polled (`_sendNotifyDirect` file 0x2da4f48) and then waits up to 45 s
//! for the SMC's system-state notification 0x0a, "panic done"
//! (`AppleSMC::callPlatformFunction` file 0x2dab0bc,
//! `_sysStateNotifyHandler` file 0x2da8c58); the SMC answers at once. Other
//! notifications refuse.
//!
//! Boot records. `MBSW` is the 64-bit set of wake sources the AP claims at
//! start (`AppleSMCPMU::_claimSystemBootEvents` file 0x2d9c680) and `MESS`
//! the one-byte cause of the last shutdown (`_claimSystemShutdownEvents`
//! file 0x2d9c8a8; code 0 is "unknown"). A machine Stela starts was woken
//! by none of the sources and has no recorded shutdown, so both read zero.
//! `MEST`, the time of that shutdown, is absent: the driver then claims the
//! shutdown event without a time.
//!
//! The table holds those keys, `#KEY`, the `NTAP` notification-enable
//! flag, and the PMU GPIO keys the DeviceTree's `pKW4` platform functions
//! on `smc-pmu` name (on J473AP `gP09` DP-to-HDMI reset, `gP0d` Wi-Fi/BT
//! regulator, `gP0f` NFC, `gP10` HDMI CEC, `gP15`/`gP16` HDMI power, `gP18`
//! USB-A controller power and the CIO supply toggle `pmVC`). A GPIO key
//! latches the 32-bit command last written and reads it back; other models
//! read the latch for the pin's level. Any other key answers KEY_NOT_FOUND,
//! as an SMC without it does; a key is added only with its established
//! size and meaning, never a guessed value. The type codes of `MBSE`,
//! `NESN`, `MBSW` and `MESS` are inferred from their sizes; no client
//! reads them.
use super::asc::TransitionRequest;
use super::bus::{Access, Direction, MmioDevice, MmioError, Transition, Width, refuse};
use super::rtkit::Endpoint;
use alloc::{
    collections::{BTreeMap, VecDeque},
    rc::Rc,
    vec,
    vec::Vec,
};
use core::cell::RefCell;

pub const ENDPOINT: u8 = 0x20;
/// The shared page: one 16 KiB kernel page at the start of the region.
pub const SRAM_BYTES: u64 = 0x4000;
const NAME: &str = "smc";

const READ: u8 = 0x10;
const WRITE: u8 = 0x11;
const KEY_BY_INDEX: u8 = 0x12;
const KEY_INFO: u8 = 0x13;
const INITIALIZE: u8 = 0x17;
const NOTIFICATION: u8 = 0x18;
const READ_WRITE: u8 = 0x20;

const SUCCESS: u8 = 0;
const KEY_NOT_FOUND: u8 = 0x84;
const NOT_READABLE: u8 = 0x85;
const NOT_WRITABLE: u8 = 0x86;
const SIZE_MISMATCH: u8 = 0x87;
const BAD_ARGUMENT: u8 = 0x89;
const INDEX_RANGE: u8 = 0xb8;

const KEY_COUNT: u32 = code(b"#KEY");
const NOTIFICATIONS: u32 = code(b"NTAP");
const SYSTEM_EVENT: u32 = code(b"MBSE");
const NOTIFY_SMC: u32 = code(b"NESN");
const BUTTON_HELD: u32 = code(b"bHLD");
const WAKE_SOURCES: u32 = code(b"MBSW");
const SHUTDOWN_CAUSE: u32 = code(b"MESS");

/// `MBSE` commands (see the module comment).
const WILL_POWER_OFF: u32 = code(b"offw");
const WILL_RESTART: u32 = code(b"rest");
const WILL_SLEEP: u32 = code(b"slpw");
const WAKE: u32 = code(b"waka");
const PANIC_BEGIN: u32 = code(b"panb");
const PANIC_END: u32 = code(b"pane");
const RESTART: u32 = code(b"phra");
const SYSTEM_RESET: u32 = code(b"sysr");
const STANDBY: u32 = code(b"susp");
const LOW_POWER_EMERGENCY: u32 = code(b"lpem");

/// Notification classes and subclasses, in the event's top two bytes.
const SYSTEM_STATE: u8 = 0x70;
const HID: u8 = 0x72;
const HID_BUTTON: u8 = 0x01;
const POWER_BUTTON: u8 = 0x01;
const PANIC_DONE: u8 = 0x0a;
/// The AP's own panic notification, `NESN` subclass 0x8a.
const AP_PANIC: u8 = 0x8a;

pub const READABLE: u8 = 0x80;
pub const WRITABLE: u8 = 0x40;
pub const FUNCTION: u8 = 0x10;
const MAX_VALUE: usize = 120;

/// The 32-bit form of a four-character key or type code.
pub const fn code(name: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*name)
}

/// One notification event: class, subclass and two data bytes.
const fn event(class: u8, subclass: u8, first: u8, second: u8) -> u32 {
    u32::from_be_bytes([class, subclass, first, second])
}

/// The shared page, mapped at the nub's region base and read by the SMC.
#[derive(Clone)]
pub struct Sram(Rc<RefCell<Vec<u8>>>);

impl Default for Sram {
    fn default() -> Self {
        Self(Rc::new(RefCell::new(vec![0; SRAM_BYTES as usize])))
    }
}

impl Sram {
    pub fn read(&self, offset: u64, bytes: usize) -> Option<u64> {
        let page = self.0.borrow();
        let start = usize::try_from(offset).ok()?;
        let slice = page.get(start..start.checked_add(bytes)?)?;
        let mut word = [0u8; 8];
        word[..bytes].copy_from_slice(slice);
        Some(u64::from_le_bytes(word))
    }

    pub fn write(&self, offset: u64, bytes: usize, value: u64) -> Option<()> {
        let mut page = self.0.borrow_mut();
        let start = usize::try_from(offset).ok()?;
        let slice = page.get_mut(start..start.checked_add(bytes)?)?;
        slice.copy_from_slice(&value.to_le_bytes()[..bytes]);
        Some(())
    }

    fn get(&self, bytes: usize) -> Vec<u8> {
        self.0.borrow()[..bytes].to_vec()
    }

    fn put(&self, data: &[u8]) {
        self.0.borrow_mut()[..data.len()].copy_from_slice(data);
    }
}

/// One key: its type code, flags and current value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub kind: u32,
    pub flags: u8,
    pub value: Vec<u8>,
}

impl Key {
    /// A PMU GPIO key: a 32-bit command latch, readable and writable.
    pub fn gpio() -> Self {
        Self {
            kind: code(b"ui32"),
            flags: READABLE | WRITABLE | FUNCTION,
            value: vec![0; 4],
        }
    }

    fn new(kind: &[u8; 4], flags: u8, bytes: usize) -> Self {
        Self {
            kind: code(kind),
            flags,
            value: vec![0; bytes],
        }
    }
}

/// The SMC's own keys, with their initial values (see the module comment).
fn own_keys() -> [(u32, Key); 6] {
    [
        // The notification enable: AppleSMC::_smcInitNotifications and
        // Linux macsmc write the one-byte flag 1.
        (NOTIFICATIONS, Key::new(b"flag", READABLE | WRITABLE, 1)),
        (SYSTEM_EVENT, Key::new(b"ui32", WRITABLE, 4)),
        (NOTIFY_SMC, Key::new(b"ui32", WRITABLE, 4)),
        (BUTTON_HELD, Key::new(b"flag", READABLE, 1)),
        (WAKE_SOURCES, Key::new(b"ui64", READABLE, 8)),
        (SHUTDOWN_CAUSE, Key::new(b"ui8 ", READABLE, 1)),
    ]
}

pub struct Smc {
    sram: Sram,
    sram_address: u64,
    keys: BTreeMap<u32, Key>,
    /// Board events waiting for the AP to enable notifications.
    events: VecDeque<u32>,
    /// The last notice `MBSE` received.
    notice: Option<u32>,
    transition: Option<TransitionRequest>,
}

impl Smc {
    /// An SMC whose shared page is at physical `sram_address`, holding
    /// `keys` besides its own.
    pub fn new(sram: Sram, sram_address: u64, keys: Vec<(u32, Key)>) -> Result<Self, &'static str> {
        let mut table: BTreeMap<u32, Key> = own_keys().into_iter().collect();
        for (name, key) in keys {
            if name == KEY_COUNT || own_keys().iter().any(|(own, _)| *own == name) {
                return Err("a board key duplicates one of the SMC's own keys");
            }
            if key.value.is_empty() || key.value.len() > MAX_VALUE {
                return Err("SMC key value size outside 1..=120");
            }
            if table.insert(name, key).is_some() {
                return Err("SMC key provided twice");
            }
        }
        let count = u32::try_from(table.len() + 1).map_err(|_| "too many SMC keys")?;
        table.insert(
            KEY_COUNT,
            Key {
                kind: code(b"ui32"),
                flags: READABLE,
                value: count.to_be_bytes().to_vec(),
            },
        );
        Ok(Self {
            sram,
            sram_address,
            keys: table,
            events: VecDeque::new(),
            notice: None,
            transition: None,
        })
    }

    /// Whether the AP has enabled unsolicited notifications.
    pub fn notifications_enabled(&self) -> bool {
        self.value(NOTIFICATIONS) == Some(&[1])
    }

    /// Key `name`'s current value.
    pub fn value(&self, name: u32) -> Option<&[u8]> {
        self.keys.get(&name).map(|key| key.value.as_slice())
    }

    /// The last power notice the AP gave (`offw`, `rest`, `slpw`, `waka`,
    /// `panb` or `pane`).
    pub fn notice(&self) -> Option<u32> {
        self.notice
    }

    /// The power button went down or up: `bHLD` follows it and the AP is
    /// sent the HID button event.
    pub fn power_button(&mut self, pressed: bool) {
        let state = u8::from(pressed);
        self.keys
            .get_mut(&BUTTON_HELD)
            .expect("bHLD is one of the SMC's own keys")
            .value = vec![state];
        self.events
            .push_back(event(HID, HID_BUTTON, POWER_BUTTON, state));
    }

    fn reply(request: u64, result: u8, size: usize, data: u32) -> u64 {
        u64::from(result) | (request & 0xff00) | (size as u64) << 16 | u64::from(data) << 32
    }

    fn notification(event: u32) -> u64 {
        u64::from(NOTIFICATION) | u64::from(event) << 32
    }

    /// The reply to a read of `size` bytes of `name`.
    fn read(&self, request: u64, name: u32, size: usize) -> u64 {
        let Some(key) = self.keys.get(&name) else {
            return Self::reply(request, KEY_NOT_FOUND, 0, 0);
        };
        if key.flags & READABLE == 0 {
            return Self::reply(request, NOT_READABLE, 0, 0);
        }
        if size < key.value.len() {
            return Self::reply(request, SIZE_MISMATCH, 0, 0);
        }
        let length = key.value.len();
        if length <= 4 {
            let mut inline = [0u8; 4];
            inline[..length].copy_from_slice(&key.value);
            Self::reply(request, SUCCESS, length, u32::from_le_bytes(inline))
        } else {
            self.sram.put(&key.value);
            Self::reply(request, SUCCESS, length, 0)
        }
    }

    /// Writes `size` bytes from the shared page to `name` and carries out
    /// what the key commands; notifications the write causes go to
    /// `answers`, after the reply.
    fn write(
        &mut self,
        name: u32,
        size: usize,
        answers: &mut Vec<u64>,
    ) -> Result<u8, &'static str> {
        let Some(key) = self.keys.get_mut(&name) else {
            return Ok(KEY_NOT_FOUND);
        };
        if key.flags & WRITABLE == 0 {
            return Ok(NOT_WRITABLE);
        }
        if size != key.value.len() {
            return Ok(SIZE_MISMATCH);
        }
        let value = self.sram.get(size);
        match name {
            SYSTEM_EVENT => self.system_event(u32::from_le_bytes(
                value[..].try_into().expect("MBSE is four bytes"),
            ))?,
            NOTIFY_SMC => answers.push(Self::notification(Self::notified(&value)?)),
            _ => {}
        }
        self.keys.get_mut(&name).expect("key looked up").value = value;
        Ok(SUCCESS)
    }

    fn system_event(&mut self, command: u32) -> Result<(), &'static str> {
        let transition = |transition, reason| TransitionRequest {
            device: NAME,
            transition,
            reason,
        };
        match command {
            WILL_POWER_OFF | WILL_RESTART | WILL_SLEEP | WAKE | PANIC_BEGIN | PANIC_END => {
                self.notice = Some(command);
            }
            RESTART | SYSTEM_RESET => {
                self.transition = Some(transition(
                    Transition::Restart,
                    "MBSE restart command: system restart",
                ));
            }
            STANDBY => {
                self.transition = Some(transition(
                    Transition::PowerOff,
                    "MBSE standby command: system power-off",
                ));
            }
            LOW_POWER_EMERGENCY => {
                return Err("SMC low-power emergency mode needs a battery the board does not have");
            }
            _ => return Err("SMC MBSE command is not modeled"),
        }
        Ok(())
    }

    /// The SMC's answer to an AP notification written to `NESN`.
    fn notified(value: &[u8]) -> Result<u32, &'static str> {
        match value {
            [SYSTEM_STATE, AP_PANIC, 0, 0] => Ok(event(SYSTEM_STATE, PANIC_DONE, 0, 0)),
            _ => Err("SMC NESN notification is not modeled"),
        }
    }
}

impl Endpoint for Smc {
    fn start(&mut self, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        Ok(())
    }

    fn receive(&mut self, payload: u64, outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        let kind = payload as u8;
        let size = usize::from((payload >> 16) as u8);
        let write_size = usize::from((payload >> 24) as u8);
        let name = (payload >> 32) as u32;
        let mut answers = Vec::new();
        let reply = match kind {
            INITIALIZE => self.sram_address,
            READ if (1..=MAX_VALUE).contains(&size) => self.read(payload, name, size),
            WRITE if (1..=MAX_VALUE).contains(&size) => {
                Self::reply(payload, self.write(name, size, &mut answers)?, 0, 0)
            }
            READ_WRITE if (1..=MAX_VALUE).contains(&write_size) => {
                match self.write(name, write_size, &mut answers)? {
                    SUCCESS => self.read(payload, name, size),
                    result => Self::reply(payload, result, 0, 0),
                }
            }
            READ | WRITE | READ_WRITE => Self::reply(payload, BAD_ARGUMENT, 0, 0),
            KEY_BY_INDEX => match self.keys.keys().nth(name as usize) {
                Some(&key) => Self::reply(payload, SUCCESS, 4, key),
                None => Self::reply(payload, INDEX_RANGE, 0, 0),
            },
            KEY_INFO => match self.keys.get(&name) {
                Some(key) => {
                    let mut info = [0u8; 6];
                    info[0] = key.value.len() as u8;
                    info[1..5].copy_from_slice(&key.kind.to_le_bytes());
                    info[5] = key.flags;
                    self.sram.put(&info);
                    Self::reply(payload, SUCCESS, info.len(), 0)
                }
                None => Self::reply(payload, KEY_NOT_FOUND, 0, 0),
            },
            _ => return Err("SMC key endpoint message type is not modeled"),
        };
        outbox.push(reply);
        outbox.extend(answers);
        Ok(())
    }

    fn poll(&mut self, outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        if self.notifications_enabled() {
            outbox.extend(self.events.drain(..).map(Self::notification));
        }
        Ok(())
    }

    fn take_transition(&mut self) -> Option<TransitionRequest> {
        self.transition.take()
    }
}

/// The shared page as a bus device.
pub struct SramWindow(pub Sram);

impl MmioDevice for SramWindow {
    fn name(&self) -> &'static str {
        "smc-sram"
    }

    fn read(
        &mut self,
        offset: u64,
        width: Width,
        _access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        self.0
            .read(offset, width.bytes() as usize)
            .ok_or_else(|| outside(offset, width, Direction::Read))
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        self.0
            .write(offset, width.bytes() as usize, value)
            .ok_or_else(|| outside(offset, width, Direction::Write))
    }
}

fn outside(offset: u64, width: Width, direction: Direction) -> MmioError {
    refuse(
        "smc-sram",
        offset,
        width,
        direction,
        "outside the shared page",
    )
}

/// The SMC hardware watchdog bank (`reg[timers-reg-index]`, 0x14 bytes).
/// AppleSMC::start maps it (0xfffffe0009dab7dc) and
/// `_disableSmcHwWatchdog` (0xfffffe0009daf1e0) clears control bit 0 at
/// 0xc with a read-modify-write before a panic or sleep; no other access
/// exists. The native SMC never arms it, so control reads 0 and only a
/// disarmed value is accepted. Arming, and the other words, would need the
/// watchdog's expiry semantics and refuse.
pub struct Watchdog;

pub const WATCHDOG_BYTES: u64 = 0x14;
const WATCHDOG_CONTROL: u64 = 0xc;

impl MmioDevice for Watchdog {
    fn name(&self) -> &'static str {
        "smc-watchdog"
    }

    fn read(
        &mut self,
        offset: u64,
        width: Width,
        _access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        match (offset, width) {
            (WATCHDOG_CONTROL, Width::Word) => Ok(0),
            _ => Err(refuse(
                "smc-watchdog",
                offset,
                width,
                Direction::Read,
                "only the 32-bit control word is modeled",
            )),
        }
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        match (offset, width, value) {
            (WATCHDOG_CONTROL, Width::Word, 0) => Ok(()),
            _ => Err(refuse(
                "smc-watchdog",
                offset,
                width,
                Direction::Write,
                "only disarming the control word is modeled",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x2_3fe0_0000;
    /// The keys the J473AP DeviceTree's `pKW4` functions name.
    const J473_GPIO_KEYS: [&[u8; 4]; 8] = [
        b"gP09", b"gP0d", b"gP0f", b"gP10", b"gP15", b"gP16", b"gP18", b"pmVC",
    ];

    fn request(kind: u8, id: u8, size: u8, write_size: u8, key: u32) -> u64 {
        u64::from(kind)
            | u64::from(id) << 12
            | u64::from(size) << 16
            | u64::from(write_size) << 24
            | u64::from(key) << 32
    }

    fn smc() -> (Smc, Sram) {
        let sram = Sram::default();
        let keys = J473_GPIO_KEYS
            .iter()
            .map(|name| (code(name), Key::gpio()))
            .collect();
        (Smc::new(sram.clone(), BASE, keys).unwrap(), sram)
    }

    fn send(smc: &mut Smc, payload: u64) -> u64 {
        let mut outbox = Vec::new();
        smc.receive(payload, &mut outbox).unwrap();
        assert_eq!(outbox.len(), 1);
        outbox[0]
    }

    #[test]
    fn initialize_names_the_shared_page_and_key_count_reads_big_endian() {
        let (mut smc, _) = smc();
        assert_eq!(send(&mut smc, u64::from(INITIALIZE)), BASE);
        let reply = send(&mut smc, request(READ, 3, 4, 0, code(b"#KEY")));
        assert_eq!(reply & 0xff, u64::from(SUCCESS));
        assert_eq!(reply >> 12 & 0xf, 3);
        assert_eq!(reply >> 16 & 0xff, 4);
        assert_eq!((reply >> 32) as u32, u32::from_be(15));
        // Unknown keys, short reads and bad sizes answer SMC errors.
        assert_eq!(
            send(&mut smc, request(READ, 0, 4, 0, code(b"RGEN"))) & 0xff,
            u64::from(KEY_NOT_FOUND)
        );
        assert_eq!(
            send(&mut smc, request(READ, 0, 2, 0, code(b"#KEY"))) & 0xff,
            u64::from(SIZE_MISMATCH)
        );
        assert_eq!(
            send(&mut smc, request(READ, 0, 121, 0, code(b"#KEY"))) & 0xff,
            u64::from(BAD_ARGUMENT)
        );
        assert!(smc.receive(0x55, &mut Vec::new()).is_err());
    }

    #[test]
    fn keys_enumerate_sorted_with_their_information() {
        let (mut smc, sram) = smc();
        let first = send(&mut smc, request(KEY_BY_INDEX, 0, 0, 0, 0));
        assert_eq!((first >> 32) as u32, code(b"#KEY"));
        let second = send(&mut smc, request(KEY_BY_INDEX, 0, 0, 0, 1));
        assert_eq!((second >> 32) as u32, code(b"MBSE"));
        let third = send(&mut smc, request(KEY_BY_INDEX, 0, 0, 0, 7));
        assert_eq!((third >> 32) as u32, code(b"gP09"));
        assert_eq!(
            send(&mut smc, request(KEY_BY_INDEX, 0, 0, 0, 15)) & 0xff,
            u64::from(INDEX_RANGE)
        );
        send(&mut smc, request(KEY_INFO, 0, 0, 0, code(b"gP16")));
        assert_eq!(sram.get(6), [4, b'2', b'3', b'i', b'u', 0xd0]);
    }

    #[test]
    fn the_ap_enables_notifications_with_the_ntap_flag() {
        let (mut smc, sram) = smc();
        assert!(!smc.notifications_enabled());
        sram.put(&[1]);
        let reply = send(&mut smc, request(WRITE, 0, 1, 0, code(b"NTAP")));
        assert_eq!(reply & 0xff, u64::from(SUCCESS));
        assert!(smc.notifications_enabled());
        assert!(Smc::new(Sram::default(), BASE, vec![(code(b"NTAP"), Key::gpio())]).is_err());
    }

    #[test]
    fn gpio_keys_latch_writes_from_the_shared_page() {
        let (mut smc, sram) = smc();
        sram.put(&0x0100_8000u32.to_le_bytes());
        let reply = send(&mut smc, request(WRITE, 5, 4, 0, code(b"gP16")));
        assert_eq!((reply & 0xff, reply >> 12 & 0xf), (u64::from(SUCCESS), 5));
        assert_eq!(smc.value(code(b"gP16")), Some(&[0, 0x80, 0, 1][..]));
        let read = send(&mut smc, request(READ, 0, 4, 0, code(b"gP16")));
        assert_eq!((read >> 32) as u32, 0x0100_8000);
        assert_eq!(
            send(&mut smc, request(WRITE, 0, 4, 0, code(b"#KEY"))) & 0xff,
            u64::from(NOT_WRITABLE)
        );
        assert_eq!(
            send(&mut smc, request(WRITE, 0, 2, 0, code(b"gP16"))) & 0xff,
            u64::from(SIZE_MISMATCH)
        );
        // RW writes then reads back.
        sram.put(&7u32.to_le_bytes());
        let both = send(&mut smc, request(READ_WRITE, 0, 4, 4, code(b"gP09")));
        assert_eq!((both >> 32) as u32, 7);
        assert_eq!(sram.read(0, 4), Some(7));
        assert!(sram.read(SRAM_BYTES - 2, 4).is_none());
    }

    fn write_key(smc: &mut Smc, sram: &Sram, name: &[u8; 4], value: &[u8]) -> Vec<u64> {
        sram.put(value);
        let mut outbox = Vec::new();
        smc.receive(
            request(WRITE, 2, value.len() as u8, 0, code(name)),
            &mut outbox,
        )
        .unwrap();
        outbox
    }

    #[test]
    fn system_event_notices_are_recorded_and_commands_request_transitions() {
        let (mut smc, sram) = smc();
        // AppleSMCPMU takes the system-event path only for a 4-byte MBSE.
        send(&mut smc, request(KEY_INFO, 0, 0, 0, code(b"MBSE")));
        assert_eq!(sram.get(1), [4]);
        for notice in [b"offw", b"rest", b"slpw", b"waka", b"panb", b"pane"] {
            let reply = write_key(&mut smc, &sram, b"MBSE", &code(notice).to_le_bytes());
            assert_eq!(reply, [request(SUCCESS, 2, 0, 0, 0) & 0xffff]);
            assert_eq!(smc.notice(), Some(code(notice)));
            assert!(smc.take_transition().is_none());
        }
        write_key(&mut smc, &sram, b"MBSE", &code(b"phra").to_le_bytes());
        let restart = smc.take_transition().unwrap();
        assert_eq!(
            (restart.device, restart.transition),
            ("smc", Transition::Restart)
        );
        assert!(smc.take_transition().is_none());
        write_key(&mut smc, &sram, b"MBSE", &code(b"sysr").to_le_bytes());
        assert_eq!(
            smc.take_transition().unwrap().transition,
            Transition::Restart
        );
        write_key(&mut smc, &sram, b"MBSE", &code(b"susp").to_le_bytes());
        assert_eq!(
            smc.take_transition().unwrap().transition,
            Transition::PowerOff
        );
        // Low-power emergency mode and unknown commands refuse.
        for command in [b"lpem", b"zzzz"] {
            sram.put(&code(command).to_le_bytes());
            assert!(
                smc.receive(request(WRITE, 0, 4, 0, code(b"MBSE")), &mut Vec::new())
                    .is_err()
            );
        }
        assert_eq!(
            send(&mut smc, request(READ, 0, 4, 0, code(b"MBSE"))) & 0xff,
            u64::from(NOT_READABLE)
        );
    }

    #[test]
    fn an_ap_panic_notification_is_answered_with_panic_done() {
        let (mut smc, sram) = smc();
        let outbox = write_key(&mut smc, &sram, b"NESN", &[0x70, 0x8a, 0, 0]);
        assert_eq!(outbox.len(), 2);
        assert_eq!(outbox[0] & 0xff, u64::from(SUCCESS));
        assert_eq!(outbox[1], 0x18 | 0x700a_0000 << 32);
        sram.put(&[0x75, 1, 0, 0]);
        assert!(
            smc.receive(request(WRITE, 0, 4, 0, code(b"NESN")), &mut Vec::new())
                .is_err()
        );
    }

    #[test]
    fn the_power_button_is_held_in_bhld_and_notified_once_enabled() {
        let (mut smc, sram) = smc();
        smc.power_button(true);
        let held = send(&mut smc, request(READ, 0, 1, 0, code(b"bHLD")));
        assert_eq!((held >> 16 & 0xff, held >> 32), (1, 1));
        // Nothing is sent before the AP sets NTAP; the event waits.
        let mut outbox = Vec::new();
        smc.poll(&mut outbox).unwrap();
        assert!(outbox.is_empty());
        write_key(&mut smc, &sram, b"NTAP", &[1]);
        smc.poll(&mut outbox).unwrap();
        assert_eq!(outbox, [0x18 | 0x7201_0101 << 32]);
        smc.power_button(false);
        outbox.clear();
        smc.poll(&mut outbox).unwrap();
        assert_eq!(outbox, [0x18 | 0x7201_0100 << 32]);
        let released = send(&mut smc, request(READ, 0, 1, 0, code(b"bHLD")));
        assert_eq!(released >> 32, 0);
    }

    #[test]
    fn boot_records_report_no_wake_source_and_an_unknown_shutdown() {
        let (mut smc, sram) = smc();
        sram.put(&[0xff; 8]);
        let wake = send(&mut smc, request(READ, 0, 8, 0, code(b"MBSW")));
        assert_eq!((wake & 0xff, wake >> 16 & 0xff), (u64::from(SUCCESS), 8));
        assert_eq!(sram.get(8), [0; 8]);
        let cause = send(&mut smc, request(READ, 0, 1, 0, code(b"MESS")));
        assert_eq!((cause & 0xff, cause >> 16 & 0xff, cause >> 32), (0, 1, 0));
        assert_eq!(
            send(&mut smc, request(READ, 0, 8, 0, code(b"MEST"))) & 0xff,
            u64::from(KEY_NOT_FOUND)
        );
        assert_eq!(
            send(&mut smc, request(WRITE, 0, 1, 0, code(b"MESS"))) & 0xff,
            u64::from(NOT_WRITABLE)
        );
    }

    #[test]
    fn the_watchdog_reads_disarmed_and_refuses_arming() {
        let mut sink = super::super::interrupt::InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        let mut watchdog = Watchdog;
        let control = watchdog
            .read(WATCHDOG_CONTROL, Width::Word, &mut access)
            .unwrap();
        assert_eq!(control, 0);
        // `_disableSmcHwWatchdog`'s read-modify-write.
        watchdog
            .write(WATCHDOG_CONTROL, Width::Word, control & !1, &mut access)
            .unwrap();
        assert!(
            watchdog
                .write(WATCHDOG_CONTROL, Width::Word, 1, &mut access)
                .is_err()
        );
        assert!(watchdog.read(0, Width::Word, &mut access).is_err());
    }
}

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
//! shared page, RW 0x20 writes then reads. Returned key names and the SRAM
//! type field carry the FourCC's ASCII bytes in order: consumers decode a
//! big-endian word (_getKeyFromIndexGated 0xfffffe0009da7d28 and
//! _getKeyInfoGated 0xfffffe0009da82dc; Linux macsmc's swab32/BE32). This
//! field order is independent of each key value's own encoding.
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
//! - `slpa` puts the SoC to sleep and `hiba` into hibernation: the key
//!   endpoint writes one itself when its power state drops to 0
//!   (`AppleSMCKeysEndpoint::_powerStateActionGated` file 0x2da492c,
//!   `hiba` when the root domain's `IOHibernateState` is 1, hibernating)
//!   and then holds every other key command until its power state rises
//!   again. `slpa` makes the sleep pending: the SoC sleeps once every PE
//!   has powered down (`machine::apple`'s SoC sleep), and only a modeled
//!   wake source wakes it ([`Smc::wake`]). `waka` with the sleep still
//!   pending cancels it. `hiba` refuses: waking from hibernation needs the
//!   boot stage to restore the hibernation image, which Stela's does not.
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
//! Wake. On its platform wake action AppleSMCPMU raises the key endpoint's
//! power state, which reads `MBSE` (4 bytes) and unquiesces; then it reads
//! `MBSW` and claims each set bit as a wake event named by `smc-pmu`'s
//! `event_name-bitN` (`nameWakeReason` file 0x2da12ec), and writes `waka`
//! (`AppleSMCPMU::callPlatformFunction` file 0x2d9d838..0x2d9de20). A wake
//! sets `MBSW` to the bit of its source as those names give it (`pwrbtn`,
//! `rtc`; none when the tree names none). `MBSE` stays write-only: its
//! read fails with NOT_READABLE, which the endpoint logs as its result
//! before unquiescing, and AppleSMCPMU, without `smc-pmu-debug-wake`, goes
//! on to `MBSW` either way. The power button press that wakes the SoC is
//! its wake source and not also a button event, nor is its release
//! (inferred: otherwise one press would both wake the machine and ask it
//! to shut down).
//!
//! Port controller lock. `D1Vn` is the SMC's lock on the 4CC command
//! interface of the RID-0 USB-C port controller. `AppleHPM::atomic4CC`
//! (file 0x27cce78..0x27cd91c) takes it around every 4CC command except the
//! `aUFC`/`sUFC`/`mUFC`/`pUFC` firmware-update ones: it reads the byte
//! (`AppleHPMARM::get4ccLockStatus` file 0x27c2378, 1 = held), writes 1
//! (`set4ccLock` file 0x27c2434), reads it again until it holds (two 5 ms
//! retries, then it goes ahead regardless), issues the command and writes
//! 0. The emulated SMC never issues 4CC commands of its own, so the lock
//! is always free for the AP: the byte reads back what the AP last wrote.
//! Values other than 0 and 1 refuse. Ports with another RID never take it
//! (`get4ccLockStatus` returns at once for a nonzero RID).
//!
//! ADC sensors. `aDC#` is the number of PMU ADC channels the SMC exports
//! as `AppleARMPMUSensor`s: `AppleSMC::start` (file 0x2da7c80..0x2da7d58)
//! reads it (4 bytes) and creates one sensor per index from the `aDC?`
//! keys. The emulated SMC measures no ADC channels, so it reads 0 and
//! AppleSMC creates none.
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
//! `NESN`, `MBSW`, `MESS`, `D1Vn` and `aDC#` are inferred from their sizes
//! and uses; no client reads them. The 26A434 J473AP census of every key
//! the kernel's SMC clients and the restore ramdisk use, with the reason
//! each absent key stays absent, is in docs/research/desktop-requirements.md
//! (SMC key census).
//!
//! A source-declared primary RTC helper can additionally bind CLKM to the
//! PMU oscillator. Its recovered six-byte hex_ / attributes0x94 key
//! profile and original/native evidence are in docs/research/smc-rtc-t6000.md.
//! Missing counter publication refuses before SRAM/reply effects; this path
//! owns no second calendar offset and makes no Apple reset-epoch assumption.
mod rtc;
use crate::Result;
use rtc::RtcBinding;
use stela_contracts::refuse;
use stela_soc_data::smc::RtcKeyProfile;

use super::asc::TransitionRequest;
use super::rtkit::Endpoint;
use alloc::{
    collections::{BTreeMap, VecDeque},
    rc::Rc,
    vec,
    vec::Vec,
};
use core::cell::RefCell;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError,
    stela_contracts::bus::Transition, stela_contracts::bus::Width, stela_contracts::bus::refuse,
};

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
const PORT_CONTROLLER_LOCK: u32 = code(b"D1Vn");
const ADC_SENSOR_COUNT: u32 = code(b"aDC#");

/// `D1Vn` values (see the module comment).
const LOCK_RELEASED: u8 = 0;
const LOCK_HELD: u8 = 1;

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
const SLEEP: u32 = code(b"slpa");
const HIBERNATE: u32 = code(b"hiba");

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
const WRITE_LOG_LIMIT: usize = 64;

/// A diagnostic observation of a write at the key endpoint. The raw reply
/// is held even when it is zero; an error means no reply was emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteLog {
    pub request: u64,
    /// The four-byte system-event command, when this write targets MBSE.
    pub system_event: Option<u32>,
    pub reply: Result<u64>,
    /// Older observations lost to the bounded queue before this entry.
    pub dropped_before: usize,
}

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
fn own_keys() -> [(u32, Key); 8] {
    [
        // The notification enable: AppleSMC::_smcInitNotifications and
        // Linux macsmc write the one-byte flag 1.
        (NOTIFICATIONS, Key::new(b"flag", READABLE | WRITABLE, 1)),
        (SYSTEM_EVENT, Key::new(b"ui32", WRITABLE, 4)),
        (NOTIFY_SMC, Key::new(b"ui32", WRITABLE, 4)),
        (BUTTON_HELD, Key::new(b"flag", READABLE, 1)),
        (WAKE_SOURCES, Key::new(b"ui64", READABLE, 8)),
        (SHUTDOWN_CAUSE, Key::new(b"ui8 ", READABLE, 1)),
        // Released until the AP takes it.
        (
            PORT_CONTROLLER_LOCK,
            Key::new(b"flag", READABLE | WRITABLE, 1),
        ),
        // No ADC channels.
        (ADC_SENSOR_COUNT, Key::new(b"ui32", READABLE, 4)),
    ]
}

use stela_soc_data::smc::WakeBits;

/// What woke the SoC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeSource {
    PowerButton,
    /// The PMU's RTC alarm.
    Rtc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sleep {
    Awake,
    /// `slpa` received; the SoC sleeps once every PE is down.
    Pending,
    Asleep,
}

pub struct Smc {
    sram: Sram,
    sram_address: u64,
    keys: BTreeMap<u32, Key>,
    rtc: Option<RtcBinding>,
    /// Board events waiting for the AP to enable notifications.
    events: VecDeque<u32>,
    /// The last notice `MBSE` received.
    notice: Option<u32>,
    transition: Option<TransitionRequest>,
    sleep: Sleep,
    wake_bits: WakeBits,
    /// The power button woke the SoC; its release is not reported.
    waking_press: bool,
    write_log: VecDeque<WriteLog>,
    dropped_writes: usize,
}

impl Smc {
    /// An SMC whose shared page is at physical `sram_address`, holding
    /// `keys` besides its own.
    pub fn new(sram: Sram, sram_address: u64, keys: Vec<(u32, Key)>) -> Result<Self> {
        let mut table: BTreeMap<u32, Key> = own_keys().into_iter().collect();
        for (name, key) in keys {
            if name == KEY_COUNT || own_keys().iter().any(|(own, _)| *own == name) {
                return Err(refuse!("a board key duplicates one of the SMC's own keys"));
            }
            if key.value.is_empty() || key.value.len() > MAX_VALUE {
                return Err(refuse!("SMC key value size outside 1..=120"));
            }
            if table.insert(name, key).is_some() {
                return Err(refuse!("SMC key provided twice"));
            }
        }
        let count = u32::try_from(table.len() + 1).map_err(|_| refuse!("too many SMC keys"))?;
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
            rtc: None,
            events: VecDeque::new(),
            notice: None,
            transition: None,
            sleep: Sleep::Awake,
            wake_bits: WakeBits::default(),
            waking_press: false,
            write_log: VecDeque::new(),
            dropped_writes: 0,
        })
    }

    /// The `MBSW` bits the board's DeviceTree names for its wake sources.
    pub fn with_wake_bits(mut self, bits: WakeBits) -> Self {
        self.wake_bits = bits;
        self
    }

    /// The AP asked for sleep (`slpa`) and has not yet gone down.
    pub fn sleep_pending(&self) -> bool {
        self.sleep == Sleep::Pending
    }

    /// Every PE is down after `slpa`: the SoC sleeps.
    pub fn enter_sleep(&mut self) {
        debug_assert_eq!(self.sleep, Sleep::Pending);
        self.sleep = Sleep::Asleep;
    }

    pub fn asleep(&self) -> bool {
        self.sleep == Sleep::Asleep
    }

    /// Bind the primary PMU oscillator. No key/value exists before this
    /// join, and a missing counter publication cannot return an initial zero.
    pub fn bind_rtc(&mut self, clock: super::pmu::RtcClock, profile: RtcKeyProfile) -> Result<()> {
        self.check_bind_rtc()?;
        let count = u32::try_from(self.keys.len() + 1).map_err(|_| refuse!("too many SMC keys"))?;
        self.keys
            .get_mut(&KEY_COUNT)
            .expect("key count owner")
            .value = count.to_be_bytes().to_vec();
        self.rtc = Some(RtcBinding { clock, profile });
        Ok(())
    }

    /// Board construction preflight, before publishing a PMU/controller owner.
    pub fn check_bind_rtc(&self) -> Result<()> {
        if self.rtc.is_some() || self.keys.contains_key(&rtc::KEY) {
            return Err(refuse!(
                "SMC RTC key has duplicate or conflicting ownership"
            ));
        }
        u32::try_from(self.keys.len() + 1).map_err(|_| refuse!("too many SMC keys"))?;
        Ok(())
    }

    fn key_info(&self, name: u32) -> Option<(usize, u32, u8)> {
        if name == rtc::KEY
            && let Some(rtc) = &self.rtc
        {
            return Some(rtc.info());
        }
        self.keys
            .get(&name)
            .map(|key| (key.value.len(), key.kind, key.flags))
    }
    fn key_by_index(&self, index: usize) -> Option<u32> {
        let index = if self.rtc.is_some() {
            let position = self.keys.range(..rtc::KEY).count();
            if index == position {
                return Some(rtc::KEY);
            }
            if index > position { index - 1 } else { index }
        } else {
            index
        };
        self.keys.keys().nth(index).copied()
    }

    /// The SoC wakes from `source`, which `MBSW` then reports.
    pub fn wake(&mut self, source: WakeSource) {
        debug_assert_eq!(self.sleep, Sleep::Asleep);
        self.sleep = Sleep::Awake;
        let bit = match source {
            WakeSource::PowerButton => {
                self.waking_press = true;
                self.wake_bits.power_button
            }
            WakeSource::Rtc => self.wake_bits.rtc,
        };
        let sources = bit.map_or(0, |bit| 1u64 << bit);
        self.keys
            .get_mut(&WAKE_SOURCES)
            .expect("MBSW is one of the SMC's own keys")
            .value = sources.to_le_bytes().to_vec();
    }

    /// Whether the AP has enabled unsolicited notifications.
    pub fn notifications_enabled(&self) -> bool {
        self.value(NOTIFICATIONS) == Some(&[1])
    }

    /// A stored key's current bytes. Dynamic RTC values are available only
    /// through the checked key protocol, never as a stale borrowed buffer.
    pub fn value(&self, name: u32) -> Option<&[u8]> {
        self.keys.get(&name).map(|key| key.value.as_slice())
    }

    /// The last power notice the AP gave (`offw`, `rest`, `slpw`, `waka`,
    /// `panb` or `pane`).
    #[cfg(test)]
    pub fn notice(&self) -> Option<u32> {
        self.notice
    }

    /// Drains one bounded protocol observation without altering its reply.
    pub fn take_log(&mut self) -> Option<WriteLog> {
        let mut log = self.write_log.pop_front()?;
        log.dropped_before = core::mem::take(&mut self.dropped_writes);
        Some(log)
    }

    /// The power button went down or up: `bHLD` follows it and the AP is
    /// sent the HID button event. While the SoC sleeps nothing is sent, and
    /// a press answers true: it would wake the SoC ([`Smc::wake`]). The
    /// release of a press that woke it is not sent either.
    pub fn power_button(&mut self, pressed: bool) -> bool {
        let state = u8::from(pressed);
        self.keys
            .get_mut(&BUTTON_HELD)
            .expect("bHLD is one of the SMC's own keys")
            .value = vec![state];
        if self.asleep() {
            return pressed;
        }
        if !pressed && core::mem::take(&mut self.waking_press) {
            return false;
        }
        self.events
            .push_back(event(HID, HID_BUTTON, POWER_BUTTON, state));
        false
    }

    fn reply(request: u64, result: u8, size: usize, data: u32) -> u64 {
        u64::from(result) | (request & 0xff00) | (size as u64) << 16 | u64::from(data) << 32
    }

    fn notification(event: u32) -> u64 {
        u64::from(NOTIFICATION) | u64::from(event) << 32
    }

    /// The reply to a read of `size` bytes of `name`.
    fn read(&self, request: u64, name: u32, size: usize) -> Result<u64> {
        if name == rtc::KEY
            && let Some(rtc) = &self.rtc
        {
            let (bytes, _, _) = rtc.info();
            if size < bytes {
                return Ok(Self::reply(request, SIZE_MISMATCH, 0, 0));
            }
            let value = rtc.value()?;
            self.sram.put(&value);
            return Ok(Self::reply(request, SUCCESS, bytes, 0));
        }
        let Some(key) = self.keys.get(&name) else {
            return Ok(Self::reply(request, KEY_NOT_FOUND, 0, 0));
        };
        if key.flags & READABLE == 0 {
            return Ok(Self::reply(request, NOT_READABLE, 0, 0));
        }
        if size < key.value.len() {
            return Ok(Self::reply(request, SIZE_MISMATCH, 0, 0));
        }
        let length = key.value.len();
        if length <= 4 {
            let mut inline = [0u8; 4];
            inline[..length].copy_from_slice(&key.value);
            Ok(Self::reply(
                request,
                SUCCESS,
                length,
                u32::from_le_bytes(inline),
            ))
        } else {
            self.sram.put(&key.value);
            Ok(Self::reply(request, SUCCESS, length, 0))
        }
    }

    /// Writes `size` bytes from the shared page to `name` and carries out
    /// what the key commands; notifications the write causes go to
    /// `answers`, after the reply.
    fn write(&mut self, name: u32, size: usize, answers: &mut Vec<u64>) -> Result<u8> {
        if name == rtc::KEY && self.rtc.is_some() {
            return Ok(NOT_WRITABLE);
        }
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
            PORT_CONTROLLER_LOCK if !matches!(value[..], [LOCK_RELEASED | LOCK_HELD]) => {
                return Err(refuse!(
                    "SMC D1Vn takes 0 (release) or 1 (take) for the port controller's 4CC lock"
                ));
            }
            _ => {}
        }
        self.keys.get_mut(&name).expect("key looked up").value = value;
        Ok(SUCCESS)
    }

    fn system_event(&mut self, command: u32) -> Result<()> {
        let transition = |transition, reason| TransitionRequest {
            device: NAME,
            transition,
            reason,
        };
        match command {
            WILL_POWER_OFF | WILL_RESTART | WILL_SLEEP | PANIC_BEGIN | PANIC_END => {
                self.notice = Some(command);
            }
            WAKE => {
                self.notice = Some(command);
                if self.sleep == Sleep::Pending {
                    self.sleep = Sleep::Awake;
                }
            }
            SLEEP => self.sleep = Sleep::Pending,
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
                return Err(refuse!(
                    "SMC low-power emergency mode needs a battery the board does not have"
                ));
            }
            HIBERNATE => {
                return Err(refuse!(
                    "SMC hibernation needs the boot stage to restore the hibernation image, which Stela's does not"
                ));
            }
            _ => return Err(refuse!("SMC MBSE command is not modeled")),
        }
        Ok(())
    }

    /// The SMC's answer to an AP notification written to `NESN`.
    fn notified(value: &[u8]) -> Result<u32> {
        match value {
            [SYSTEM_STATE, AP_PANIC, 0, 0] => Ok(event(SYSTEM_STATE, PANIC_DONE, 0, 0)),
            _ => Err(refuse!("SMC NESN notification is not modeled")),
        }
    }
}

impl Endpoint for Smc {
    fn start(&mut self, _outbox: &mut Vec<u64>) -> Result<()> {
        Ok(())
    }

    fn receive(&mut self, payload: u64, outbox: &mut Vec<u64>) -> Result<()> {
        let kind = payload as u8;
        let size = usize::from((payload >> 16) as u8);
        let write_size = usize::from((payload >> 24) as u8);
        let name = (payload >> 32) as u32;
        let mut answers = Vec::new();
        let system_event = (name == SYSTEM_EVENT
            && matches!((kind, size, write_size), (WRITE, 4, _) | (READ_WRITE, _, 4)))
        .then(|| u32::from_le_bytes(self.sram.get(4).try_into().expect("four-byte command")));
        let result = (|| {
            let reply = match kind {
                INITIALIZE => self.sram_address,
                READ if (1..=MAX_VALUE).contains(&size) => self.read(payload, name, size)?,
                WRITE if (1..=MAX_VALUE).contains(&size) => {
                    Self::reply(payload, self.write(name, size, &mut answers)?, 0, 0)
                }
                READ_WRITE if (1..=MAX_VALUE).contains(&write_size) => {
                    match self.write(name, write_size, &mut answers)? {
                        SUCCESS => self.read(payload, name, size)?,
                        result => Self::reply(payload, result, 0, 0),
                    }
                }
                READ | WRITE | READ_WRITE => Self::reply(payload, BAD_ARGUMENT, 0, 0),
                KEY_BY_INDEX => match self.key_by_index(name as usize) {
                    Some(key) => Self::reply(payload, SUCCESS, 4, key.swap_bytes()),
                    None => Self::reply(payload, INDEX_RANGE, 0, 0),
                },
                KEY_INFO => match self.key_info(name) {
                    Some((bytes, kind, flags)) => {
                        let mut info = [0u8; 6];
                        info[0] = bytes as u8;
                        info[1..5].copy_from_slice(&kind.to_be_bytes());
                        info[5] = flags;
                        self.sram.put(&info);
                        Self::reply(payload, SUCCESS, info.len(), 0)
                    }
                    None => Self::reply(payload, KEY_NOT_FOUND, 0, 0),
                },
                _ => return Err(refuse!("SMC key endpoint message type is not modeled")),
            };
            Ok(reply)
        })();
        if matches!(kind, WRITE | READ_WRITE) {
            if self.write_log.len() == WRITE_LOG_LIMIT {
                self.write_log.pop_front();
                self.dropped_writes = self.dropped_writes.saturating_add(1);
            }
            self.write_log.push_back(WriteLog {
                request: payload,
                system_event,
                reply: result.clone(),
                dropped_before: 0,
            });
        }
        let reply = result?;
        outbox.push(reply);
        outbox.extend(answers);
        Ok(())
    }

    fn poll(&mut self, outbox: &mut Vec<u64>) -> Result<()> {
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
mod tests;

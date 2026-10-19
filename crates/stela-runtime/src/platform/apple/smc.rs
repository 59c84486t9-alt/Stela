//! The System Management Controller's key endpoint, native at its RTKit
//! boundary: AppleSMCKeysEndpoint's protocol on application endpoint 0x20,
//! a shared SRAM page for values that do not fit a message, and a table of
//! typed keys.
//!
//! Evidence (26A434 J473AP kernel, unslid VAs): AppleSMCKeysEndpoint builds
//! a request as type (byte 0), the caller's low nibble and a rolling 4-bit
//! ID in the high nibble of byte 1 (`_sendKeyMsgAndWaitForResponse`
//! 0xfffffe0009da61c8), the size in byte 2 and the key in bytes 4..7 as
//! the 32-bit value whose bytes, most significant first, spell it
//! (`_readKeyWithSMC` 0xfffffe0009da6344: READ 0x10, size 1..=120). A
//! reply echoes byte 1, carries the result in byte 0 and the size in byte
//! 2, and holds up to four value bytes in bytes 4..7; a longer value is in
//! the shared page (`_readKeyGated` 0xfffffe0009da6500, result 0x87 when
//! the reply is longer than asked). INITIALIZE (0x17) is answered with the
//! shared page's physical address, which must lie in the nub's
//! region-base..region-size (`_keyEndpointHandler` 0xfffffe0009da5320,
//! check at 0xfffffe0009da5a20). Type 0x18 is an unsolicited notification
//! from the SMC. `#KEY` holds the key count most significant byte first
//! (`_smcInitKeyTableCache` 0xfffffe0009da5d20). The other message types,
//! the key information layout (size, type code, flags) and the result codes
//! are those Linux's Apple SMC driver (`include/linux/mfd/macsmc.h`, the
//! `macsmc` RTKit transport) documents for the same protocol: WRITE 0x11
//! takes its value from the shared page, GET_KEY_BY_INDEX 0x12 answers the
//! key at an index of the lexicographically sorted table, GET_KEY_INFO 0x13
//! writes six bytes to the shared page, RW 0x20 writes then reads.
//!
//! The table holds the keys whose meaning a DeviceTree or kernel client
//! establishes: `#KEY`, and the PMU GPIO keys the DeviceTree's `pKW4`
//! platform functions on `smc-pmu` name (on J473AP `gP09` DP-to-HDMI
//! reset, `gP0d` Wi-Fi/BT regulator, `gP0f` NFC, `gP10` HDMI CEC,
//! `gP15`/`gP16` HDMI power, `gP18` USB-A controller power and the CIO
//! supply toggle `pmVC`). A GPIO
//! key latches the 32-bit command last written and reads it back; other
//! models read the latch for the pin's level. Any other key answers
//! KEY_NOT_FOUND, as an SMC without it does; a key is added only with its
//! established type, size and meaning, never a guessed value.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use super::rtkit::Endpoint;
use alloc::{collections::BTreeMap, rc::Rc, vec, vec::Vec};
use core::cell::RefCell;

pub const ENDPOINT: u8 = 0x20;
/// The shared page: one 16 KiB kernel page at the start of the region.
pub const SRAM_BYTES: u64 = 0x4000;

const READ: u8 = 0x10;
const WRITE: u8 = 0x11;
const KEY_BY_INDEX: u8 = 0x12;
const KEY_INFO: u8 = 0x13;
const INITIALIZE: u8 = 0x17;
const READ_WRITE: u8 = 0x20;

const SUCCESS: u8 = 0;
const KEY_NOT_FOUND: u8 = 0x84;
const NOT_READABLE: u8 = 0x85;
const NOT_WRITABLE: u8 = 0x86;
const SIZE_MISMATCH: u8 = 0x87;
const BAD_ARGUMENT: u8 = 0x89;
const INDEX_RANGE: u8 = 0xb8;

pub const READABLE: u8 = 0x80;
pub const WRITABLE: u8 = 0x40;
pub const FUNCTION: u8 = 0x10;
const MAX_VALUE: usize = 120;

/// The 32-bit form of a four-character key or type code.
pub const fn code(name: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*name)
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
}

pub struct Smc {
    sram: Sram,
    sram_address: u64,
    keys: BTreeMap<u32, Key>,
}

impl Smc {
    /// An SMC whose shared page is at physical `sram_address`, holding
    /// `keys` besides `#KEY`.
    pub fn new(sram: Sram, sram_address: u64, keys: Vec<(u32, Key)>) -> Result<Self, &'static str> {
        let mut table = BTreeMap::new();
        for (name, key) in keys {
            if name == code(b"#KEY") {
                return Err("#KEY is the SMC's own count");
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
            code(b"#KEY"),
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
        })
    }

    /// Key `name`'s current value.
    pub fn value(&self, name: u32) -> Option<&[u8]> {
        self.keys.get(&name).map(|key| key.value.as_slice())
    }

    fn reply(request: u64, result: u8, size: usize, data: u32) -> u64 {
        u64::from(result) | (request & 0xff00) | (size as u64) << 16 | u64::from(data) << 32
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

    /// Writes `size` bytes from the shared page to `name`.
    fn write(&mut self, name: u32, size: usize) -> u8 {
        let Some(key) = self.keys.get_mut(&name) else {
            return KEY_NOT_FOUND;
        };
        if key.flags & WRITABLE == 0 {
            return NOT_WRITABLE;
        }
        if size != key.value.len() {
            return SIZE_MISMATCH;
        }
        key.value = self.sram.get(size);
        SUCCESS
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
        let reply = match kind {
            INITIALIZE => self.sram_address,
            READ if (1..=MAX_VALUE).contains(&size) => self.read(payload, name, size),
            WRITE if (1..=MAX_VALUE).contains(&size) => {
                Self::reply(payload, self.write(name, size), 0, 0)
            }
            READ_WRITE if (1..=MAX_VALUE).contains(&write_size) => {
                match self.write(name, write_size) {
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
        Ok(())
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
        assert_eq!((reply >> 32) as u32, u32::from_be(9));
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
        assert_eq!((second >> 32) as u32, code(b"gP09"));
        assert_eq!(
            send(&mut smc, request(KEY_BY_INDEX, 0, 0, 0, 9)) & 0xff,
            u64::from(INDEX_RANGE)
        );
        send(&mut smc, request(KEY_INFO, 0, 0, 0, code(b"gP16")));
        assert_eq!(sram.get(6), [4, b'2', b'3', b'i', b'u', 0xd0]);
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

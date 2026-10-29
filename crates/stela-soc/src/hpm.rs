//! Bounded CD321x/TPS6598x-family I2C register protocol; not yet advertised.
//!
//! Linux `drivers/usb/typec/tipd/{core.c,tps6598x.h}` at a0ff06b3 defines
//! length prefixes, status, power/data status and the CD321x event bits.
//! Original `AppleHPMARMI2C::writeIECSReg` (26A434 KC file 0x277a8bc)
//! prepends length; `readRegs(u8,u8*,u64*)` (0x277a780) strips it.
//! `AppleHPMDeviceHAL::{getStatus,getDataStatus,getPDStatus}` select
//! 0x1a/0x5f/0x40 at 0x27c77f0/0x27c7388/0x27c7a70. Their parsers
//! (0x27c7874/0x27c740c) agree with the public USB2 and role fields.
//! `getAndClearInterrupts` (0x27c83ec) reads event then writes its clear
//! register: reading events does not acknowledge them.
//!
//! The class-10 startup research (`docs/research/hpm.md`) gives the registers AppleTCControllerType10 reads and their lengths: the
//! identity, UID (0x05), revision (0x2c), boot flags (0x2d), the firmware
//! configuration records such as 0x29 and TX Identity 0x47, power state (0x20), data control (0x50), Apple CF/VID status (0x5e)
//! and 5-byte data status. Event and mask banks keep the public 11-byte TPS
//! layout; the driver reads 9 and masks 8, with Apple's bit map (0 AppLoaded,
//! 1 plug, 8 status, 10 data status, 11 PD status). Masks preserve events and
//! clears are W1C. A 4CC written to CMD1 completes before the write returns:
//! CMD1 reads zero again, the documented completion. `SSPS` (active power
//! states 0 and 2), `USBd`, `USBw` and `ABRT` record their effect; sleep and
//! every other command refuse rather than fake a firmware effect. The bus
//! manager's summary at address 0x6b is `Summary`.

use crate::Result;
use alloc::vec::Vec;
use stela_contracts::refuse;

use super::{
    gpio::OpenDrain,
    i2c::{I2cTarget, TargetError},
    typec::{DataRole, Orientation, Port, Snapshot},
};

const VENDOR: u8 = 0x00;
const DEVICE: u8 = 0x01;
const MODE: u8 = 0x03;
const UID: u8 = 0x05;
const COMMAND: u8 = 0x08;
const DATA: u8 = 0x09;
const VERSION: u8 = 0x0f;
const COMMAND2: u8 = 0x10;
const POWER_STATE: u8 = 0x20;
const REVISION: u8 = 0x2c;
const BOOT_FLAGS: u8 = 0x2d;
const DATA_CONTROL: u8 = 0x50;
const APPLE_STATUS: u8 = 0x5e;
const EVENT1: u8 = 0x14;
const EVENT2: u8 = 0x15;
const MASK1: u8 = 0x16;
const MASK2: u8 = 0x17;
const CLEAR1: u8 = 0x18;
const CLEAR2: u8 = 0x19;
const STATUS: u8 = 0x1a;
const POWER: u8 = 0x3f;
const PD: u8 = 0x40;
const DATA_STATUS: u8 = 0x5f;
const BANK_BYTES: usize = 11;
const MAX_DATA: usize = 64;
const APPLE_STATUS_BYTES: usize = 18;
/// Configured registers wider than the leading bytes their record stores.
const REGISTER_WIDTHS: [(u8, usize); 1] = [(0x47, 49)];
/// Active with a cable and active unplugged; 3 is sleep.
const ACTIVE_POWER_STATES: [u8; 2] = [0, 2];
const PLUG_EVENT: u16 = 1 << 1;
const STATUS_EVENT: u16 = 1 << 8;
const POWER_EVENT: u16 = 1 << 9;
const DATA_EVENT: u16 = 1 << 10;
const PLUG: u32 = 1;
const CONNECTED_NO_RA: u32 = 6 << 1;
const FLIPPED: u32 = 1 << 4;
const SOURCE: u32 = 1 << 5;
const DFP: u32 = 1 << 6;
const POWER_VIN: u32 = 1 << 18;
const VBUS_5V: u32 = 1 << 20;
const HOST_NO_PD: u32 = 2 << 22;
const DATA_CONNECTED: u32 = 1;
const DATA_FLIPPED: u32 = 1 << 1;
const DATA_USB2: u32 = 1 << 4;
const DATA_UFP: u32 = 1 << 7;

/// Firmware identity and application configuration are an emulated-die
/// choice, not a guest-build selector. The ramdisk's USB-C_HPM,47.bin
/// (SHA-256 6db2150525133690452ce0ff05f498ba158509a35918927d931511dbf7784b41)
/// has its header at 0x4000: format 0xace00002, device 0x00cd3218 at
/// header+0x30 and version 0x00216300 at +0x34. These field meanings are
/// inferred by comparison with the IDs `publishHPMDevices` accepts at KC
/// 0x277a4ac..0x277a514, and agree with the names the restore ramdisk's
/// `libUSBCfwflasher.dylib` logs for them (aceDeviceID, aceFWVersion,
/// appConfigOffset).
///
/// Its `-[iecsUpdater getAceHeaderOffset:...]` (file 0x1188..0x12d4) finds
/// the header from the image's first word: an ACE format word there puts the
/// header at 0; otherwise that word is a region offset, or, when it is 0 or
/// all ones, the word at 0x1000 is; the header is that region plus the word
/// at 0xffc (0x1ffc for the region at 0x1000). The M2 and later
/// images keep 0 there, so their header is the region at 0x4000; the
/// full-flash M1-family images (USB-C_HPM,27..35) keep 0x66000, putting it
/// at 0x6a000 after the region's other contents.
///
/// Header+0x48 and +0x4c hold the application configuration's offset from
/// the header and its size (0x800, 0x1fd). The configuration starts with
/// version 1 and the same size, a board tag ("J473") and, at +0x18, the
/// offset of its register records (0x3a, after the board strings). Each
/// record is `[register][length - 1][length bytes]` with ascending
/// registers; the first non-ascending register ends the run. The layout is
/// inferred: record lengths equal the lengths the class-10 driver reads (0x29
/// is 63 bytes, 0x28 64 bytes), and 0x47 holds the PD TX Identity VDOs with
/// J473's product ID 0x7416. A record may store only a register's leading
/// bytes: TX Identity is 49 bytes (`getTCCPID`, KC 0x27c19e0, reads 49) but
/// its record keeps the 25 that carry VDOs, so the rest reads zero. Records seed the
/// registers the firmware loads from its configuration; registers that
/// carry live state (masks, power state) keep their modeled values.
/// Callers provide the input; no Apple firmware is embedded or executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Firmware {
    pub device: u32,
    pub version: u32,
    pub config: Vec<(u8, Vec<u8>)>,
}
impl Firmware {
    pub fn from_image(image: &[u8]) -> Result<Self> {
        let bytes = |offset: usize, len: usize| image.get(offset..offset.checked_add(len)?);
        let word = |offset: usize| {
            bytes(offset, 4).map(|v| u32::from_le_bytes(v.try_into().expect("four-byte field")))
        };
        let field =
            |offset: Option<usize>| offset.and_then(word).and_then(|v| usize::try_from(v).ok());
        let header = match word(0).ok_or(refuse!("HPM firmware has no header pointer"))? {
            0xace0_0001 | 0xace0_0002 => Some(0),
            0 | u32::MAX => field(Some(0x1000))
                .filter(|&region| region != 0 && region != u32::MAX as usize)
                .zip(field(Some(0x1ffc)))
                .and_then(|(region, offset)| region.checked_add(offset)),
            region => field(Some(0xffc))
                .and_then(|offset| usize::try_from(region).ok()?.checked_add(offset)),
        }
        .ok_or(refuse!("HPM firmware has no header pointer"))?;
        if word(header) != Some(0xace0_0002) {
            return Err(refuse!("unrecognized HPM firmware header format"));
        }
        let device = header
            .checked_add(0x30)
            .and_then(word)
            .ok_or(refuse!("truncated HPM device identity"))?;
        let version = header
            .checked_add(0x34)
            .and_then(word)
            .ok_or(refuse!("truncated HPM firmware version"))?;
        if !matches!(device, 0x00cd_3217 | 0x00cd_3218) || version == 0 || version == u32::MAX {
            return Err(refuse!(
                "unqualified HPM device identity or firmware version"
            ));
        }
        let start = field(header.checked_add(0x48))
            .and_then(|offset| header.checked_add(offset))
            .ok_or(refuse!("truncated HPM configuration offset"))?;
        let size =
            field(header.checked_add(0x4c)).ok_or(refuse!("truncated HPM configuration size"))?;
        let config =
            bytes(start, size).ok_or(refuse!("truncated HPM application configuration"))?;
        if config.len() < 0x1a
            || config[..2] != [1, 0]
            || usize::from(u16::from_le_bytes([config[2], config[3]])) != size
        {
            return Err(refuse!("unrecognized HPM application configuration"));
        }
        let mut offset = usize::from(u16::from_le_bytes([config[0x18], config[0x19]]));
        let mut records = Vec::new();
        while let Some(&[register, len]) = config.get(offset..offset + 2) {
            if records.last().is_some_and(|&(last, _)| register <= last) {
                break;
            }
            let data = config
                .get(offset + 2..offset + 3 + usize::from(len))
                .filter(|data| data.len() <= MAX_DATA)
                .ok_or(refuse!(
                    "HPM configuration record exceeds its configuration"
                ))?;
            records.push((register, data.to_vec()));
            offset += 3 + usize::from(len);
        }
        if records.is_empty() {
            return Err(refuse!(
                "HPM application configuration has no register records"
            ));
        }
        Ok(Self {
            device,
            version,
            config: records,
        })
    }
}

#[derive(Clone)]
pub struct Hpm {
    port: Port,
    firmware: Firmware,
    observed: Snapshot,
    events: [[u8; BANK_BYTES]; 2],
    masks: [[u8; BANK_BYTES]; 2],
    data: [u8; MAX_DATA],
    // One captured response serves a split register read, so its length and
    // data cannot belong to different connection generations.
    response: [u8; MAX_DATA + 1],
    cursor: usize,
    selected: bool,
    irq: Option<OpenDrain>,
    uid: [u8; 16],
    power_state: u8,
    usb_detection: bool,
    remote_wake: u8,
    data_control: [u8; 4],
}
impl Hpm {
    /// APP firmware is running at handoff, active (power state 0), with
    /// masks disabled, no events and the 4CC engine idle. Port electrical
    /// state is supplied independently by `Port`. This is Stela's
    /// boot-firmware handoff image, not captured iBoot state. Stela's die
    /// reports silicon revision 0, clear boot flags, its firmware's
    /// configuration records and a UID naming its bus address.
    pub fn new(port: Port, firmware: Firmware, address: u8) -> Self {
        let mut uid = *b"Stela HPM die   ";
        uid[15] = address;
        let observed = Snapshot {
            generation: 0,
            connection: None,
        };
        Self {
            port,
            firmware,
            observed,
            events: [[0; BANK_BYTES]; 2],
            masks: [[0; BANK_BYTES]; 2],
            data: [0; MAX_DATA],
            response: [0; MAX_DATA + 1],
            cursor: 0,
            selected: false,
            irq: None,
            uid,
            power_state: 0,
            usb_detection: false,
            remote_wake: 0,
            data_control: [0; 4],
        }
    }
    /// Drives the board's interrupt net from `interrupt_asserted`.
    pub fn with_interrupt(mut self, irq: OpenDrain) -> Self {
        self.irq = Some(irq);
        self
    }
    fn drive(&mut self) {
        let asserted = self.interrupt_asserted();
        if let Some(irq) = &self.irq {
            irq.pull_low(asserted);
        }
    }
    fn refresh(&mut self) {
        let next = self.port.snapshot();
        if next.generation == self.observed.generation {
            return;
        }
        let mut events = 0u16;
        for (changed, bit) in self
            .port
            .changes_since(self.observed.generation)
            .into_iter()
            .zip([PLUG_EVENT, STATUS_EVENT, POWER_EVENT, DATA_EVENT])
        {
            if changed {
                events |= bit;
            }
        }
        let bits = events.to_le_bytes();
        for bank in &mut self.events {
            for (byte, bits) in bank.iter_mut().zip(bits) {
                *byte |= bits;
            }
        }
        self.observed = next;
    }
    /// Active-low HPM interrupt output before board GPIO routing. Mask changes
    /// never erase latched events. Deassert only when no unacknowledged enabled
    /// bit remains in either bank.
    pub fn interrupt_asserted(&mut self) -> bool {
        self.refresh();
        self.events
            .iter()
            .zip(&self.masks)
            .any(|(events, masks)| events.iter().zip(masks).any(|(e, m)| e & m != 0))
    }
    fn register(&self, register: u8) -> Result<([u8; MAX_DATA], usize)> {
        let mut data = [0; MAX_DATA];
        let connection = self.observed.connection;
        let len = match register {
            VENDOR => {
                data[..4].copy_from_slice(&0x28u32.to_le_bytes());
                4
            }
            DEVICE => {
                data[..4].copy_from_slice(&self.firmware.device.to_le_bytes());
                4
            }
            MODE => {
                data[..4].copy_from_slice(b"APP ");
                4
            }
            VERSION => {
                data[..4].copy_from_slice(&self.firmware.version.to_le_bytes());
                4
            }
            UID => {
                data[..16].copy_from_slice(&self.uid);
                16
            }
            // Commands complete synchronously, so both command registers
            // are idle whenever software can read them.
            COMMAND | COMMAND2 => 4,
            POWER_STATE => {
                data[0] = self.power_state;
                1
            }
            BOOT_FLAGS => MAX_DATA,
            REVISION => 1,
            DATA_CONTROL => {
                data[..4].copy_from_slice(&self.data_control);
                4
            }
            APPLE_STATUS => APPLE_STATUS_BYTES,
            DATA => {
                data = self.data;
                MAX_DATA
            }
            EVENT1 | EVENT2 => {
                data[..BANK_BYTES].copy_from_slice(&self.events[(register - EVENT1) as usize]);
                BANK_BYTES
            }
            MASK1 | MASK2 => {
                data[..BANK_BYTES].copy_from_slice(&self.masks[(register - MASK1) as usize]);
                BANK_BYTES
            }
            STATUS => {
                let mut status = POWER_VIN;
                if let Some(c) = connection {
                    status |= PLUG | CONNECTED_NO_RA;
                    if c.orientation == Orientation::Flipped {
                        status |= FLIPPED;
                    }
                    if c.source {
                        status |= SOURCE;
                    }
                    if c.role == DataRole::Dfp {
                        status |= DFP;
                    }
                    if c.vbus {
                        status |= VBUS_5V;
                    }
                    if c.role == DataRole::Ufp {
                        status |= HOST_NO_PD;
                    }
                }
                data[..4].copy_from_slice(&status.to_le_bytes());
                4
            }
            POWER => {
                // Public SOURCESINK is 1=sink, opposite STATUS.PORTROLE.
                data[0] = connection.map_or(0, |c| u8::from(c.vbus) | (u8::from(!c.source) << 1));
                2
            }
            PD => 5, // No negotiated PD contract, alt mode or partner identity.
            DATA_STATUS => {
                let mut status = 0u32;
                if let Some(c) = connection {
                    status = DATA_CONNECTED | DATA_USB2;
                    if c.orientation == Orientation::Flipped {
                        status |= DATA_FLIPPED;
                    }
                    if c.role == DataRole::Ufp {
                        status |= DATA_UFP;
                    }
                }
                data[..4].copy_from_slice(&status.to_le_bytes());
                5
            }
            _ => {
                let (_, record) = self
                    .firmware
                    .config
                    .iter()
                    .find(|(r, _)| *r == register)
                    .ok_or(refuse!(
                        "unmodeled HPM register or write-only interrupt clear"
                    ))?;
                data[..record.len()].copy_from_slice(record);
                REGISTER_WIDTHS
                    .iter()
                    .find(|(r, _)| *r == register)
                    .map_or(record.len(), |&(_, width)| width.max(record.len()))
            }
        };
        Ok((data, len))
    }
    fn write_register(&mut self, register: u8, data: &[u8]) -> Result<()> {
        match register {
            MASK1 | MASK2 | CLEAR1 | CLEAR2 => {
                if data.is_empty() || data.len() > BANK_BYTES {
                    return Err(refuse!(
                        "HPM interrupt bank length is outside the public TPS6598x layout"
                    ));
                }
                if matches!(register, MASK1 | MASK2) {
                    self.masks[(register - MASK1) as usize][..data.len()].copy_from_slice(data);
                } else {
                    for (event, clear) in self.events[(register - CLEAR1) as usize]
                        .iter_mut()
                        .zip(data)
                    {
                        *event &= !clear;
                    }
                }
            }
            DATA => {
                if data.is_empty() || data.len() > MAX_DATA {
                    return Err(refuse!("invalid HPM command-data length"));
                }
                self.data[..data.len()].copy_from_slice(data);
            }
            DATA_CONTROL => {
                let control: [u8; 4] = data
                    .try_into()
                    .map_err(|_| refuse!("HPM data control is four bytes"))?;
                self.data_control = control;
            }
            COMMAND => {
                let command: [u8; 4] = data
                    .try_into()
                    .map_err(|_| refuse!("HPM 4CC command is four bytes"))?;
                self.execute(command)?;
            }
            _ => return Err(refuse!("unmodeled HPM write or read-only register")),
        }
        Ok(())
    }
    /// Runs one 4CC with its DATA1 argument to completion.
    fn execute(&mut self, command: [u8; 4]) -> Result<()> {
        let argument = self.data[0];
        match &command {
            b"SSPS" if ACTIVE_POWER_STATES.contains(&argument) => self.power_state = argument,
            b"SSPS" => return Err(refuse!("HPM sleep or unknown power state is not modeled")),
            b"USBd" if argument <= 1 => self.usb_detection = argument == 1,
            b"USBw" if [0, 1, 9, 0x11, 0x80].contains(&argument) => self.remote_wake = argument,
            b"ABRT" => {}
            _ => return Err(refuse!("unmodeled HPM 4CC command or argument")),
        }
        Ok(())
    }
    fn transfer_inner(&mut self, write: &[u8], read: &mut [u8], stop: bool) -> Result<()> {
        self.refresh();
        if write.len() > 1 {
            if !read.is_empty() || write.len() != usize::from(write[1]) + 2 {
                return Err(refuse!(
                    "HPM write length prefix does not match its transaction"
                ));
            }
            self.write_register(write[0], &write[2..])?;
            self.selected = false;
            return Ok(());
        }
        if let Some(&register) = write.first() {
            let (data, len) = self.register(register)?;
            self.response = [0; MAX_DATA + 1];
            self.response[0] = len as u8;
            self.response[1..=len].copy_from_slice(&data[..len]);
            self.cursor = 0;
            self.selected = true;
        }
        if !self.selected {
            return Err(refuse!("HPM read without an established register selector"));
        }
        let end = self
            .cursor
            .checked_add(read.len())
            .filter(|&end| end <= self.response.len())
            .ok_or(refuse!("HPM read exceeds the 64-byte register protocol"))?;
        // Fixed-size reads may clock beyond a register's data. The
        // public protocol defines a length followed by that many bytes only.
        if end > usize::from(self.response[0]) + 1 {
            return Err(refuse!("HPM read beyond the described register payload"));
        }
        read.copy_from_slice(&self.response[self.cursor..end]);
        self.cursor = end;
        if stop && !read.is_empty() {
            self.selected = false;
        }
        Ok(())
    }
}
impl I2cTarget for Hpm {
    fn transfer(&mut self, write: &[u8], read: &mut [u8], stop: bool) -> Result<(), TargetError> {
        // Preparation on a private copy keeps protocol/state effects atomic on
        // every refusal. Port is shared read-only by preparation.
        let mut next = self.clone();
        let mut data = [0; MAX_DATA + 1];
        let output = data
            .get_mut(..read.len())
            .ok_or(TargetError::Unsupported(refuse!(
                "HPM transfer exceeds the register protocol"
            )))?;
        next.transfer_inner(write, output, stop)
            .map_err(TargetError::Unsupported)?;
        read.copy_from_slice(output);
        *self = next;
        self.drive();
        Ok(())
    }
    fn abort(&mut self) {
        self.selected = false;
        self.cursor = 0;
    }
    fn advance(&mut self) {
        self.drive();
    }
}

/// The bus manager's interrupt summary, a target at its own I2C address.
/// `AppleHPMBusController`'s interrupt action reads raw register 0x10, four
/// wire bytes, and notifies die 0x38 + n for each set bit 2n + 1 of
/// `be16(wire[2..4]) ^ 0xfffe` (`docs/research/hpm.md`): odd bits are the
/// dies' active-low alerts, sampled from their open-drain interrupt outputs.
/// Reading does not acknowledge; a die deasserts when its events are
/// cleared. Stela's register is length-prefixed with three bytes whose
/// unconsumed bits read released (one), so idle reads `03 ff ff ff`.
pub struct Summary {
    dies: Vec<(u8, OpenDrain)>,
    response: Option<([u8; 4], usize)>,
}
const SUMMARY: u8 = 0x10;
impl Summary {
    pub fn new(dies: Vec<(u8, OpenDrain)>) -> Result<Self> {
        if dies
            .iter()
            .any(|&(address, _)| !(0x38..=0x3f).contains(&address))
        {
            return Err(refuse!("HPM summary covers only dies at 0x38..=0x3f"));
        }
        Ok(Self {
            dies,
            response: None,
        })
    }
    fn word(&self) -> u16 {
        self.dies
            .iter()
            .filter(|(_, alert)| alert.is_low())
            .fold(u16::MAX, |word, &(address, _)| {
                word & !(1 << (2 * (address - 0x38) + 1))
            })
    }
}
impl I2cTarget for Summary {
    fn transfer(&mut self, write: &[u8], read: &mut [u8], stop: bool) -> Result<(), TargetError> {
        let mut response = self.response;
        match write {
            [] => {}
            [SUMMARY] => {
                let [high, low] = self.word().to_be_bytes();
                response = Some(([3, 0xff, high, low], 0));
            }
            _ => {
                return Err(TargetError::Unsupported(refuse!(
                    "HPM bus manager has only its read-only summary register"
                )));
            }
        }
        if read.is_empty() {
            self.response = response;
            return Ok(());
        }
        let (bytes, cursor) = response.ok_or(TargetError::Unsupported(refuse!(
            "HPM summary read without its register selector"
        )))?;
        let end = cursor + read.len();
        if end > bytes.len() {
            return Err(TargetError::Unsupported(refuse!(
                "HPM summary read beyond its four bytes"
            )));
        }
        read.copy_from_slice(&bytes[cursor..end]);
        self.response = (!stop).then_some((bytes, end));
        Ok(())
    }
    fn abort(&mut self) {
        self.response = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typec::{Attached, Usb2Speed};
    const CONFIG: u8 = 0x29;
    const TX_IDENTITY: u8 = 0x47;
    fn identity() -> Firmware {
        let mut config = alloc::vec![0; 63];
        config[62] = 0x6e;
        Firmware {
            device: 0x00cd3218,
            version: 0x00216300,
            config: alloc::vec![(CONFIG, config), (TX_IDENTITY, alloc::vec![6, 0xac, 5])],
        }
    }
    fn host() -> Attached {
        Attached {
            orientation: Orientation::Normal,
            role: DataRole::Ufp,
            source: false,
            vbus: true,
            speed: Usb2Speed::High,
        }
    }
    fn read(hpm: &mut Hpm, reg: u8, len: usize) -> alloc::vec::Vec<u8> {
        let mut bytes = alloc::vec![0;len+1];
        hpm.transfer(&[reg], &mut bytes, true).unwrap();
        assert_eq!(bytes[0] as usize, len);
        bytes[1..].to_vec()
    }
    fn write(hpm: &mut Hpm, reg: u8, data: &[u8]) {
        let mut bytes = alloc::vec![reg, data.len() as u8];
        bytes.extend_from_slice(data);
        hpm.transfer(&bytes, &mut [], true).unwrap();
    }
    #[test]
    fn identity_and_records_are_derived_from_the_supplied_image() {
        let firmware = identity();
        let word = |image: &mut [u8], at: usize, v: u32| {
            image[at..at + 4].copy_from_slice(&v.to_le_bytes())
        };
        // An image whose header is at `at`.
        let place = |at: usize| {
            let mut image = alloc::vec![0; 0x3000];
            word(&mut image, at, 0xace00002);
            word(&mut image, at + 0x30, firmware.device);
            word(&mut image, at + 0x34, firmware.version);
            word(&mut image, at + 0x48, 0x80);
            word(&mut image, at + 0x4c, 0x70);
            image[at + 0x80..at + 0x84].copy_from_slice(&[1, 0, 0x70, 0]);
            image[at + 0x98] = 0x1a;
            let mut records = alloc::vec![CONFIG, 62];
            records.extend_from_slice(&firmware.config[0].1);
            records.extend_from_slice(&[TX_IDENTITY, 2, 6, 0xac, 5]);
            // A non-ascending register ends the run.
            records.extend_from_slice(&[0x01, 0, 0]);
            image[at + 0x9a..at + 0x9a + records.len()].copy_from_slice(&records);
            image
        };
        // The header is the region the first word names, plus the word at
        // 0xffc.
        let mut image = place(0x100);
        word(&mut image, 0, 0x100);
        assert_eq!(Firmware::from_image(&image), Ok(firmware.clone()));
        for end in [0, 3, 0x100, 0x103, 0x133, 0x137, 0x14b, 0x14f, 0x1ef, 0xfff] {
            assert!(Firmware::from_image(&image[..end]).is_err());
        }
        let mut long = image.clone();
        long[0x19b] = 0x70;
        assert!(Firmware::from_image(&long).is_err());
        let mut far = place(0x1100);
        word(&mut far, 0, 0x100);
        word(&mut far, 0xffc, 0x1000);
        assert_eq!(Firmware::from_image(&far), Ok(firmware.clone()));
        // An erased first word defers to the region word at 0x1000 and its
        // offset at 0x1ffc; a header first is at 0.
        let mut erased = place(0x2100);
        word(&mut erased, 0, u32::MAX);
        word(&mut erased, 0x1000, 0x100);
        word(&mut erased, 0x1ffc, 0x2000);
        assert_eq!(Firmware::from_image(&erased), Ok(firmware.clone()));
        assert_eq!(Firmware::from_image(&place(0)), Ok(firmware));
        word(&mut erased, 0x1000, 0);
        assert!(Firmware::from_image(&erased).is_err());
        word(&mut image, 0xffc, 4);
        assert!(Firmware::from_image(&image).is_err());
    }
    #[test]
    fn one_port_drives_orientation_roles_vbus_and_all_status_registers() {
        let port = Port::new();
        let mut h = Hpm::new(port.clone(), identity(), 0x38);
        assert_eq!(read(&mut h, MODE, 4), b"APP ");
        assert_eq!(read(&mut h, VERSION, 4), identity().version.to_le_bytes());
        assert_eq!(read(&mut h, DATA_STATUS, 5), [0; 5]);
        port.set_connection(Some(host())).unwrap();
        assert_eq!(read(&mut h, DATA_STATUS, 5), [0x91, 0, 0, 0, 0]);
        assert_eq!(read(&mut h, POWER, 2), [3, 0]);
        assert_eq!(read(&mut h, PD, 5), [0; 5]);
        let s = u32::from_le_bytes(read(&mut h, STATUS, 4).try_into().unwrap());
        assert_eq!(
            s & (PLUG | FLIPPED | DFP | SOURCE | VBUS_5V | HOST_NO_PD),
            PLUG | VBUS_5V | HOST_NO_PD
        );
        port.set_connection(Some(Attached {
            orientation: Orientation::Flipped,
            role: DataRole::Dfp,
            source: true,
            ..host()
        }))
        .unwrap();
        assert_eq!(read(&mut h, DATA_STATUS, 5), [0x13, 0, 0, 0, 0]);
        assert_eq!(read(&mut h, POWER, 2), [1, 0]);
        port.set_connection(None).unwrap();
        assert_eq!(read(&mut h, DATA_STATUS, 5), [0; 5]);
        assert_eq!(read(&mut h, POWER, 2), [0; 2]);
    }
    #[test]
    fn event_banks_persist_across_reads_masks_acknowledgements_and_cable_bounce() {
        let port = Port::new();
        let mut h = Hpm::new(port.clone(), identity(), 0x38);
        port.set_connection(Some(host())).unwrap();
        assert!(!h.interrupt_asserted());
        let events = read(&mut h, EVENT1, BANK_BYTES);
        assert_eq!(events[0] & 2, 2);
        write(&mut h, MASK1, &[2]);
        write(&mut h, MASK2, &[2]);
        assert!(h.interrupt_asserted());
        assert_eq!(read(&mut h, EVENT1, BANK_BYTES), events);
        write(&mut h, CLEAR1, &[2]);
        assert!(h.interrupt_asserted());
        write(&mut h, CLEAR2, &[2]);
        assert!(!h.interrupt_asserted());
        port.set_connection(None).unwrap();
        port.set_connection(Some(host())).unwrap();
        assert!(h.interrupt_asserted());
        write(&mut h, MASK1, &[0]);
        write(&mut h, MASK2, &[0]);
        assert!(!h.interrupt_asserted());
        assert_eq!(read(&mut h, EVENT1, BANK_BYTES)[0] & 2, 2);
    }
    #[test]
    fn dies_pull_their_shared_interrupt_net_until_every_event_is_cleared() {
        use crate::gpio::Net;
        let (net, port) = (Net::new(), Port::new());
        let mut a =
            Hpm::new(port.clone(), identity(), 0x38).with_interrupt(net.open_drain().unwrap());
        let mut b =
            Hpm::new(Port::new(), identity(), 0x3f).with_interrupt(net.open_drain().unwrap());
        write(&mut a, MASK1, &[2]);
        port.set_connection(Some(host())).unwrap();
        // A cable change is seen when the target advances, not only on access.
        assert!(net.level());
        a.advance();
        assert!(!net.level());
        b.advance();
        assert!(!net.level());
        write(&mut a, CLEAR1, &[2]);
        assert!(net.level());
    }
    #[test]
    fn split_response_is_coherent_and_bad_transactions_have_no_effect() {
        let port = Port::new();
        let mut h = Hpm::new(port.clone(), identity(), 0x38);
        let mut length = [0];
        h.transfer(&[STATUS], &mut length, false).unwrap();
        assert_eq!(length, [4]);
        port.set_connection(Some(host())).unwrap();
        let mut data = [0; 4];
        h.transfer(&[], &mut data, true).unwrap();
        assert_eq!(u32::from_le_bytes(data), POWER_VIN);
        for frame in [
            &[COMMAND, 4, b'G', b'A', b'I', b'D'][..],
            &[MASK1, 2, 1][..],
            &[DATA, 0][..],
            &[STATUS, 1, 0][..],
        ] {
            let before = h.data;
            assert!(h.transfer(frame, &mut [], true).is_err());
            assert_eq!(h.data, before);
        }
        let mut out = [0xa5; 6];
        assert!(h.transfer(&[STATUS], &mut out, true).is_err());
        assert_eq!(out, [0xa5; 6]);
        assert!(h.transfer(&[0xfe], &mut [0], true).is_err());
        h.abort();
        assert!(h.transfer(&[], &mut [0], true).is_err());
    }
    #[test]
    fn startup_metadata_has_the_lengths_the_class_10_driver_reads() {
        let mut h = Hpm::new(Port::new(), identity(), 0x3f);
        let uid = read(&mut h, UID, 16);
        assert_eq!((&uid[..14], uid[15]), (&b"Stela HPM die "[..], 0x3f));
        assert_eq!(read(&mut h, REVISION, 1), [0]);
        assert_eq!(read(&mut h, BOOT_FLAGS, 64), [0; 64]);
        assert_eq!(read(&mut h, CONFIG, 63)[62] & 0x60, 0x60);
        let identity = read(&mut h, TX_IDENTITY, 49);
        assert_eq!(
            (&identity[..3], &identity[3..]),
            (&[6, 0xac, 5][..], &[0; 46][..])
        );
        assert!(h.transfer(&[TX_IDENTITY], &mut [0; 51], true).is_err());
        assert_eq!(read(&mut h, APPLE_STATUS, 18), [0; 18]);
        assert_eq!(read(&mut h, COMMAND2, 4), [0; 4]);
        // A raw read may stop short of the payload.
        let mut raw = [0; 19];
        h.transfer(&[BOOT_FLAGS], &mut raw, true).unwrap();
        assert_eq!(raw[0], 64);
        write(&mut h, DATA_CONTROL, &[0, 0x20, 0, 0]);
        assert_eq!(read(&mut h, DATA_CONTROL, 4), [0, 0x20, 0, 0]);
    }
    #[test]
    fn commands_complete_synchronously_or_refuse_without_effect() {
        let mut h = Hpm::new(Port::new(), identity(), 0x38);
        assert_eq!(read(&mut h, POWER_STATE, 1), [0]);
        write(&mut h, DATA, &[2]);
        write(&mut h, COMMAND, b"SSPS");
        assert_eq!(read(&mut h, COMMAND, 4), [0; 4]);
        assert_eq!(read(&mut h, POWER_STATE, 1), [2]);
        write(&mut h, DATA, &[1]);
        write(&mut h, COMMAND, b"USBd");
        assert!(h.usb_detection);
        write(&mut h, COMMAND, b"ABRT");
        for (argument, command) in [(3, b"SSPS"), (2, b"USBd"), (0, b"GAID")] {
            write(&mut h, DATA, &[argument]);
            let frame = [&[COMMAND, 4][..], command].concat();
            assert!(h.transfer(&frame, &mut [], true).is_err());
        }
        assert_eq!(read(&mut h, POWER_STATE, 1), [2]);
        assert!(h.usb_detection);
    }
    #[test]
    fn the_manager_summary_reports_each_alerting_die_active_low() {
        use crate::gpio::Net;
        let net = Net::new();
        let (a, b) = (net.open_drain().unwrap(), net.open_drain().unwrap());
        let mut summary = Summary::new(alloc::vec![(0x38, a.clone()), (0x3f, b.clone())]).unwrap();
        let read = |summary: &mut Summary| {
            let mut wire = [0; 4];
            summary.transfer(&[SUMMARY], &mut [], true).unwrap();
            summary.transfer(&[], &mut wire, true).unwrap();
            // The consumer's view: odd bits of be16(wire[2..4]) ^ 0xfffe.
            (wire, u16::from_be_bytes([wire[2], wire[3]]) ^ 0xfffe)
        };
        assert_eq!(read(&mut summary), ([3, 0xff, 0xff, 0xff], 1));
        a.pull_low(true);
        assert_eq!(read(&mut summary).1, 1 | 1 << 1);
        b.pull_low(true);
        a.pull_low(false);
        assert_eq!(read(&mut summary).1, 1 | 1 << 15);
        assert!(summary.transfer(&[], &mut [0], true).is_err());
        assert!(summary.transfer(&[0x11], &mut [0], true).is_err());
        assert!(Summary::new(alloc::vec![(0x40, a)]).is_err());
    }
}

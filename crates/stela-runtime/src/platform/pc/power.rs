//! The host PC's ACPI fixed hardware for power: how the mount restarts and
//! powers off the machine when the guest does, and where it reads the
//! power button. Everything comes from the firmware's FADT and the DSDT's
//! `\_S5` object (ACPI 6.5 sections 4.8, 5.2.9 and 7.4.2); no chipset is
//! assumed.
//!
//! - Restart writes the FADT's RESET_VALUE to RESET_REG when the FADT sets
//!   RESET_REG_SUP (section 4.8.3.6). Only system I/O and PCI configuration
//!   space registers (segment 0, bus 0, as section 5.2.9 requires) are
//!   taken; a memory-space register is reported and left to the mount's
//!   architectural fallbacks.
//! - Power-off is the S5 soft-off sequence: SLP_TYPx from `\_S5` and SLP_EN
//!   written to PM1a_CNT and, when present, PM1b_CNT (section 7.4.2). The
//!   `\_PTS` and `\_GTS` control methods are AML the mount cannot run;
//!   firmware that needs them keeps the machine on and the mount says so.
//! - The fixed-feature power button sets PWRBTN_STS in PM1x_STS when
//!   PWRBTN_EN in PM1x_EN is set (section 4.8.4.1); a status bit is
//!   cleared by writing one. A FADT with PWR_BUTTON set has a
//!   control-method button instead, which needs AML and is not read.
//!
//! The PM1 blocks are system I/O ports. The extended (X_) FADT blocks are
//! preferred when present; one outside I/O space is refused. A
//! hardware-reduced platform has no PM1 blocks, so it has neither the
//! soft-off sequence nor the fixed button.
use super::acpi::{self, AcpiError};

const HEADER: usize = 36;

/// FADT field offsets (ACPI 6.5 table 5.9).
const DSDT: usize = 40;
const SMI_COMMAND: usize = 48;
const ACPI_ENABLE: usize = 52;
const PM1A_EVENT: usize = 56;
const PM1B_EVENT: usize = 60;
const PM1A_CONTROL: usize = 64;
const PM1B_CONTROL: usize = 68;
const PM1_EVENT_LENGTH: usize = 88;
const FLAGS: usize = 112;
const RESET_REGISTER: usize = 116;
const RESET_VALUE: usize = 128;
const X_DSDT: usize = 140;
const X_PM1A_EVENT: usize = 148;
const X_PM1B_EVENT: usize = 160;
const X_PM1A_CONTROL: usize = 172;
const X_PM1B_CONTROL: usize = 184;
const GAS_BYTES: usize = 12;

/// FADT flags.
const CONTROL_METHOD_POWER_BUTTON: u32 = 1 << 4;
const RESET_SUPPORTED: u32 = 1 << 10;
const HARDWARE_REDUCED: u32 = 1 << 20;

/// Generic Address Structure address spaces.
const SYSTEM_MEMORY: u8 = 0;
const SYSTEM_IO: u8 = 1;
const PCI_CONFIGURATION: u8 = 2;

/// PM1 status and enable bits (ACPI 6.5 tables 4.16, 4.17).
pub const POWER_BUTTON: u16 = 1 << 8;
/// PM1 control bits (ACPI 6.5 table 4.18).
pub const SCI_ENABLE: u16 = 1 << 0;
const SLEEP_TYPE_SHIFT: u16 = 10;
const SLEEP_TYPE: u16 = 0x7 << SLEEP_TYPE_SHIFT;
const SLEEP_ENABLE: u16 = 1 << 13;

/// AML opcodes `\_S5` is declared with (ACPI 6.5 section 20.2).
const NAME_OP: u8 = 0x08;
const PACKAGE_OP: u8 = 0x12;
const ROOT_CHAR: u8 = b'\\';
const ZERO_OP: u8 = 0x00;
const ONE_OP: u8 = 0x01;
const BYTE_PREFIX: u8 = 0x0a;
const WORD_PREFIX: u8 = 0x0b;
const DWORD_PREFIX: u8 = 0x0c;

/// Where the reset value is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetRegister {
    Io(u16),
    /// Segment 0, bus 0.
    PciConfiguration {
        device: u8,
        function: u8,
        offset: u8,
    },
}

/// One PM1 register block pair: its event block (status, then enable) and
/// control block, as I/O ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pm1 {
    pub event: u16,
    pub control: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HostPower {
    /// PM1a and PM1b; PM1a is required for any PM1 use.
    pub pm1: [Option<Pm1>; 2],
    /// Bytes of each event block: status is the first half, enable the
    /// second.
    pub pm1_event_bytes: u8,
    /// SLP_TYPa and SLP_TYPb of S5, from `\_S5`.
    pub soft_off: Option<(u8, u8)>,
    pub reset: Option<(ResetRegister, u8)>,
    /// Whether the power button is the fixed-feature one.
    pub fixed_power_button: bool,
    /// SMI_CMD and the ACPI_ENABLE value written to it to hand the fixed
    /// events to the OS, when the firmware starts in legacy mode.
    pub acpi_enable: Option<(u16, u8)>,
    /// What was found and refused, for the mount's report.
    pub refused: Option<&'static str>,
}

impl HostPower {
    /// PM1x_EN's port for an event block.
    pub fn enable_port(&self, pm1: Pm1) -> u16 {
        pm1.event + u16::from(self.pm1_event_bytes / 2)
    }

    /// The PM1 blocks present.
    pub fn blocks(&self) -> impl Iterator<Item = Pm1> + '_ {
        self.pm1.iter().flatten().copied()
    }
}

/// PM1x_CNT with S5's sleep type and SLP_EN set, from its current value.
pub fn sleep_control(current: u16, sleep_type: u8) -> u16 {
    current & !(SLEEP_TYPE | SLEEP_ENABLE)
        | (u16::from(sleep_type) << SLEEP_TYPE_SHIFT) & SLEEP_TYPE
        | SLEEP_ENABLE
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

/// A Generic Address Structure: its space and address.
fn gas(bytes: &[u8], offset: usize) -> Option<(u8, u64)> {
    let field = bytes.get(offset..offset + GAS_BYTES)?;
    Some((field[0], u64_at(field, 4)?))
}

/// An I/O port block: the X_ field when present, else the 32-bit one.
fn port(fadt: &[u8], legacy: usize, extended: usize) -> Result<Option<u16>, &'static str> {
    let address = match gas(fadt, extended) {
        Some((SYSTEM_IO, address)) if address != 0 => address,
        Some((_, address)) if address != 0 => {
            return Err("a PM1 block outside system I/O space");
        }
        _ => u64::from(u32_at(fadt, legacy).unwrap_or(0)),
    };
    match address {
        0 => Ok(None),
        address => u16::try_from(address)
            .map(Some)
            .map_err(|_| "a PM1 block above the I/O space"),
    }
}

fn reset_register(fadt: &[u8]) -> Result<Option<(ResetRegister, u8)>, &'static str> {
    if u32_at(fadt, FLAGS).unwrap_or(0) & RESET_SUPPORTED == 0 {
        return Ok(None);
    }
    let (Some((space, address)), Some(&value)) = (gas(fadt, RESET_REGISTER), fadt.get(RESET_VALUE))
    else {
        return Ok(None);
    };
    let register = match space {
        SYSTEM_IO => ResetRegister::Io(
            u16::try_from(address).map_err(|_| "a reset register above the I/O space")?,
        ),
        PCI_CONFIGURATION => ResetRegister::PciConfiguration {
            device: u8::try_from(address >> 32 & 0xffff)
                .ok()
                .filter(|device| *device < 32)
                .ok_or("a PCI reset register device above 31")?,
            function: u8::try_from(address >> 16 & 0xffff)
                .ok()
                .filter(|function| *function < 8)
                .ok_or("a PCI reset register function above 7")?,
            offset: u8::try_from(address & 0xffff)
                .map_err(|_| "a PCI reset register past configuration header space")?,
        },
        SYSTEM_MEMORY => return Err("a memory-space reset register"),
        _ => return Err("a reset register in an unmodeled address space"),
    };
    Ok(Some((register, value)))
}

/// The FADT's power hardware, and the DSDT's physical address.
pub fn fadt(table: &[u8]) -> Result<(HostPower, u64), AcpiError> {
    const BAD: AcpiError = AcpiError::BadTable(*b"FACP");
    if table.len() < RESET_REGISTER || &table[..4] != b"FACP" {
        return Err(BAD);
    }
    let flags = u32_at(table, FLAGS).ok_or(BAD)?;
    let mut power = HostPower::default();
    let mut refuse = |reason| {
        power.refused.get_or_insert(reason);
    };
    let dsdt = match u64_at(table, X_DSDT) {
        Some(address) if address != 0 => address,
        _ => u64::from(u32_at(table, DSDT).ok_or(BAD)?),
    };
    let mut reset = None;
    match reset_register(table) {
        Ok(found) => reset = found,
        Err(reason) => refuse(reason),
    }
    let mut pm1 = [None; 2];
    let mut event_bytes = 0;
    if flags & HARDWARE_REDUCED != 0 {
        refuse("a hardware-reduced platform: no PM1 blocks");
    } else {
        event_bytes = table[PM1_EVENT_LENGTH];
        let blocks = [
            (PM1A_EVENT, X_PM1A_EVENT, PM1A_CONTROL, X_PM1A_CONTROL),
            (PM1B_EVENT, X_PM1B_EVENT, PM1B_CONTROL, X_PM1B_CONTROL),
        ];
        for (slot, (event, x_event, control, x_control)) in pm1.iter_mut().zip(blocks) {
            match (port(table, event, x_event), port(table, control, x_control)) {
                (Ok(Some(event)), Ok(Some(control))) => *slot = Some(Pm1 { event, control }),
                (Ok(_), Ok(_)) => {}
                (Err(reason), _) | (_, Err(reason)) => refuse(reason),
            }
        }
        if pm1[0].is_none() {
            pm1 = [None; 2];
            refuse("no PM1a event and control blocks");
        } else if event_bytes < 4 || event_bytes % 2 != 0 {
            pm1 = [None; 2];
            refuse("a PM1 event block shorter than its status and enable registers");
        }
    }
    let smi = u32_at(table, SMI_COMMAND).unwrap_or(0);
    let enable = table[ACPI_ENABLE];
    let power = HostPower {
        pm1,
        pm1_event_bytes: event_bytes,
        reset,
        fixed_power_button: pm1[0].is_some() && flags & CONTROL_METHOD_POWER_BUTTON == 0,
        acpi_enable: u16::try_from(smi)
            .ok()
            .filter(|&port| port != 0 && enable != 0)
            .map(|port| (port, enable)),
        ..power
    };
    Ok((power, dsdt))
}

/// One AML integer constant at the start of `bytes`, and its length.
fn integer(bytes: &[u8]) -> Option<(u64, usize)> {
    match *bytes.first()? {
        ZERO_OP => Some((0, 1)),
        ONE_OP => Some((1, 1)),
        BYTE_PREFIX => Some((u64::from(*bytes.get(1)?), 2)),
        WORD_PREFIX => Some((
            u64::from(u16::from_le_bytes(bytes.get(1..3)?.try_into().ok()?)),
            3,
        )),
        DWORD_PREFIX => Some((u64::from(u32_at(bytes, 1)?), 5)),
        _ => None,
    }
}

/// SLP_TYPa and SLP_TYPb of `\_S5` in a DSDT, when it is a static package
/// (`Name (_S5, Package () { a, b, ... })`); an `_S5` method or any other
/// form needs an AML interpreter and gives `None`.
pub fn soft_off(dsdt: &[u8]) -> Option<(u8, u8)> {
    let body = dsdt.get(HEADER..)?;
    let at = body.windows(4).enumerate().find_map(|(at, name)| {
        let named = match at.checked_sub(1).map(|before| body[before]) {
            Some(NAME_OP) => true,
            Some(ROOT_CHAR) => at.checked_sub(2).map(|before| body[before]) == Some(NAME_OP),
            _ => false,
        };
        (name == b"_S5_" && named && body.get(at + 4) == Some(&PACKAGE_OP)).then_some(at + 5)
    })?;
    // PkgLength: bits 7:6 of the lead byte count the bytes that follow.
    let lead = *body.get(at)?;
    let mut cursor = at + 1 + usize::from(lead >> 6);
    let elements = *body.get(cursor)?;
    cursor += 1;
    let mut values = [0u8; 2];
    for value in values.iter_mut().take(usize::from(elements.min(2))) {
        let (number, length) = integer(body.get(cursor..)?)?;
        *value = u8::try_from(number).ok().filter(|&kind| kind <= 7)?;
        cursor += length;
    }
    match elements {
        0 => None,
        1 => Some((values[0], values[0])),
        _ => Some((values[0], values[1])),
    }
}

/// The host's power hardware from its ACPI tables.
///
/// # Safety
///
/// `rsdp` must be the firmware's RSDP, with every table it reaches mapped.
pub unsafe fn discover(rsdp: u64) -> Result<HostPower, AcpiError> {
    // SAFETY: the caller's contract.
    let (mut power, dsdt) = fadt(unsafe { acpi::find(rsdp, b"FACP")? })?;
    if power.pm1[0].is_some() {
        // SAFETY: the FADT's DSDT, under the caller's contract.
        match unsafe { acpi::table(dsdt) }.ok().and_then(soft_off) {
            Some(types) => power.soft_off = Some(types),
            None => {
                power
                    .refused
                    .get_or_insert("no static \\_S5 package in the DSDT");
            }
        }
    }
    Ok(power)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// A 276-byte FADT with QEMU q35's power hardware.
    fn q35() -> Vec<u8> {
        let mut table = vec![0u8; 276];
        table[..4].copy_from_slice(b"FACP");
        table[DSDT..DSDT + 4].copy_from_slice(&0x7fe0_0000u32.to_le_bytes());
        table[SMI_COMMAND..SMI_COMMAND + 4].copy_from_slice(&0xb2u32.to_le_bytes());
        table[ACPI_ENABLE] = 0x02;
        table[PM1A_EVENT..PM1A_EVENT + 4].copy_from_slice(&0x600u32.to_le_bytes());
        table[PM1A_CONTROL..PM1A_CONTROL + 4].copy_from_slice(&0x604u32.to_le_bytes());
        table[PM1_EVENT_LENGTH] = 4;
        table[FLAGS..FLAGS + 4].copy_from_slice(&(RESET_SUPPORTED | 1 << 5).to_le_bytes());
        table[RESET_REGISTER] = SYSTEM_IO;
        table[RESET_REGISTER + 4..RESET_REGISTER + 12].copy_from_slice(&0xcf9u64.to_le_bytes());
        table[RESET_VALUE] = 0x06;
        table
    }

    #[test]
    fn a_fadt_names_its_pm1_blocks_reset_register_and_button() {
        let (power, dsdt) = fadt(&q35()).unwrap();
        assert_eq!(dsdt, 0x7fe0_0000);
        let pm1a = Pm1 {
            event: 0x600,
            control: 0x604,
        };
        assert_eq!(power.pm1, [Some(pm1a), None]);
        assert_eq!(power.enable_port(pm1a), 0x602);
        assert_eq!(power.reset, Some((ResetRegister::Io(0xcf9), 6)));
        assert!(power.fixed_power_button);
        assert_eq!(power.acpi_enable, Some((0xb2, 2)));
        assert_eq!(power.refused, None);
    }

    #[test]
    fn extended_blocks_win_and_unsupported_forms_are_refused() {
        let mut table = q35();
        table[X_PM1A_EVENT] = SYSTEM_IO;
        table[X_PM1A_EVENT + 4..X_PM1A_EVENT + 12].copy_from_slice(&0x1800u64.to_le_bytes());
        table[X_PM1A_CONTROL] = SYSTEM_IO;
        table[X_PM1A_CONTROL + 4..X_PM1A_CONTROL + 12].copy_from_slice(&0x1804u64.to_le_bytes());
        table[RESET_REGISTER] = PCI_CONFIGURATION;
        table[RESET_REGISTER + 4..RESET_REGISTER + 12]
            .copy_from_slice(&(0x1f_u64 << 32 | 3 << 16 | 0xac).to_le_bytes());
        let (power, _) = fadt(&table).unwrap();
        assert_eq!(power.pm1[0].unwrap().event, 0x1800);
        assert_eq!(
            power.reset.unwrap().0,
            ResetRegister::PciConfiguration {
                device: 0x1f,
                function: 3,
                offset: 0xac
            }
        );
        table[RESET_REGISTER] = SYSTEM_MEMORY;
        table[X_PM1A_CONTROL] = SYSTEM_MEMORY;
        let (power, _) = fadt(&table).unwrap();
        assert_eq!(power.reset, None);
        assert_eq!(power.pm1, [None, None]);
        assert!(!power.fixed_power_button);
        assert_eq!(power.refused, Some("a memory-space reset register"));
        // A control-method button and a hardware-reduced platform.
        let mut table = q35();
        table[FLAGS] |= CONTROL_METHOD_POWER_BUTTON as u8;
        assert!(!fadt(&table).unwrap().0.fixed_power_button);
        table[FLAGS + 2] |= (HARDWARE_REDUCED >> 16) as u8;
        let (power, _) = fadt(&table).unwrap();
        assert_eq!(power.pm1, [None, None]);
        assert!(power.reset.is_some());
        assert!(fadt(&table[..100]).is_err());
    }

    fn dsdt(body: &[u8]) -> Vec<u8> {
        let mut table = vec![0u8; HEADER];
        table[..4].copy_from_slice(b"DSDT");
        table.extend_from_slice(body);
        table
    }

    #[test]
    fn s5_sleep_types_come_from_a_static_package() {
        // QEMU: Name (_S5, Package (0x04) { Zero, Zero, Zero, Zero }).
        let qemu = dsdt(&[
            0x10, 0x08, b'_', b'S', b'5', b'_', 0x12, 0x06, 0x04, 0, 0, 0, 0,
        ]);
        assert_eq!(soft_off(&qemu), Some((0, 0)));
        // A rooted name with byte constants and a two-byte PkgLength.
        let board = dsdt(&[
            0x08, b'\\', b'_', b'S', b'5', b'_', 0x12, 0x40, 0x01, 0x02, 0x0a, 0x07, 0x0a, 0x05,
        ]);
        assert_eq!(soft_off(&board), Some((7, 5)));
        let single = dsdt(&[0x08, b'_', b'S', b'5', b'_', 0x12, 0x03, 0x01, 0x01]);
        assert_eq!(soft_off(&single), Some((1, 1)));
        // A method, an out-of-range type and a bare string are not taken.
        let method = dsdt(&[0x14, 0x08, b'_', b'S', b'5', b'_', 0x00, 0xa4, 0x00]);
        assert_eq!(soft_off(&method), None);
        let wide = dsdt(&[0x08, b'_', b'S', b'5', b'_', 0x12, 0x04, 0x01, 0x0a, 0x09]);
        assert_eq!(soft_off(&wide), None);
        assert_eq!(soft_off(&dsdt(b"_S5_")), None);
    }

    #[test]
    fn sleep_control_sets_the_type_and_enable_and_keeps_other_bits() {
        assert_eq!(
            sleep_control(SCI_ENABLE | 0x1c00, 5),
            SCI_ENABLE | 5 << 10 | 1 << 13
        );
        assert_eq!(sleep_control(0, 0), 1 << 13);
    }
}

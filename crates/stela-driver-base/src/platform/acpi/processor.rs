//! Processor idle states, as Linux's ACPI processor driver reads them: the
//! OS's processor capabilities declared through `_OSC` or `_PDC`
//! (`acpi_early_processor_control_setup`), each declared processor's local
//! APIC from the MADT (`map_madt_entry`) and its `_CST` entries
//! (`acpi_processor_evaluate_cst`), and the states a CPU may
//! enter ([`admit`]): its fixed-hardware MWAIT hints probed against its own
//! CPUID as `acpi_processor_ffh_cstate_probe` probes them, then verified as
//! `acpi_processor_power_verify` verifies them.
use super::{Argument, Error, Handle, Session, Value};
use alloc::vec::Vec;
use core::fmt;

const MADT_HEADER: usize = 44;
const LOCAL_APIC: u8 = 0;
const LOCAL_X2APIC: u8 = 9;
const ENABLED: u32 = 1;
const FIXED_HARDWARE: u8 = 0x7f;
const SYSTEM_IO: u8 = 1;
/// `ACPI_PROC_CAP_*` bits: C1 by HLT, C1 with processor throttling and
/// C2/C3 on multiprocessors (together `ACPI_PROC_CAP_C_CAPABILITY_SMP`), and
/// C1 and C2/C3 entered by MWAIT.
const CAP_C1_HALT: u32 = 0x0002;
const CAP_SMP_C1PT: u32 = 0x0008;
const CAP_SMP_C2C3: u32 = 0x0010;
const CAP_C1_FFH: u32 = 0x0100;
const CAP_C2C3_FFH: u32 = 0x0200;
/// The Intel processor `_OSC` UUID, 4077A616-290C-47BE-9EBD-D87058713953.
const PROCESSOR_OSC: [u8; 16] = [
    0x16, 0xa6, 0x77, 0x40, 0x0c, 0x29, 0xbe, 0x47, 0x9e, 0xbd, 0xd8, 0x70, 0x58, 0x71, 0x39, 0x53,
];
const PDC_REVISION: u32 = 1;
/// `NATIVE_CSTATE_BEYOND_HALT`: the fixed-hardware class of an MWAIT hint.
const MWAIT_CLASS: u8 = 2;
/// CPUID leaf 5 ECX: MWAIT extensions, and interrupts as break events.
const MWAIT_EXTENSIONS: u32 = 1;
const MWAIT_INTERRUPT_BREAK: u32 = 2;
/// `ACPI_PROCESSOR_MAX_C2_LATENCY` and `ACPI_PROCESSOR_MAX_C3_LATENCY`.
const MAX_C2_LATENCY_US: u64 = 100;
const MAX_C3_LATENCY_US: u64 = 1000;
/// Linux `latency_factor`: a state's target residency is twice its exit
/// latency.
const LATENCY_FACTOR: u64 = 2;

/// The enabled local APIC MADT names for ACPI processor `id`: Processor
/// Local APIC entries match its ProcessorID, and x2APIC entries its `_UID`
/// when it is a device declaration, as `map_madt_entry` matches them.
pub fn apic_id(madt: &[u8], id: u32, device: bool) -> Option<u32> {
    let mut offset = MADT_HEADER;
    let end = madt
        .get(4..8)
        .map(|length| u32::from_le_bytes(length.try_into().unwrap()) as usize)?
        .min(madt.len());
    while offset + 2 <= end {
        let (kind, length) = (madt[offset], usize::from(madt[offset + 1]));
        if length < 2 || offset + length > end {
            return None;
        }
        let entry = &madt[offset..offset + length];
        let flags = |at: usize| {
            entry
                .get(at..at + 4)
                .map(|f| u32::from_le_bytes(f.try_into().unwrap()))
        };
        match kind {
            LOCAL_APIC if length >= 8 && u32::from(entry[2]) == id => {
                if flags(4)? & ENABLED != 0 {
                    return Some(u32::from(entry[3]));
                }
            }
            LOCAL_X2APIC if device && length >= 16 => {
                let uid = u32::from_le_bytes(entry[12..16].try_into().unwrap());
                if uid == id && flags(8)? & ENABLED != 0 {
                    return Some(u32::from_le_bytes(entry[4..8].try_into().unwrap()));
                }
            }
            _ => {}
        }
        offset += length;
    }
    None
}

/// The processor capabilities this OS declares, as Linux's
/// `arch_acpi_set_proc_cap_bits` sets the C-state ones: the MWAIT entries
/// only on a CPU with MWAIT. The P- and T-state bits Linux also sets are
/// left out, since this OS manages neither.
pub fn capabilities(mwait: bool) -> u32 {
    let halt = CAP_SMP_C2C3 | CAP_SMP_C1PT | CAP_C1_HALT;
    if mwait {
        halt | CAP_C1_FFH | CAP_C2C3_FFH
    } else {
        halt
    }
}

/// How the firmware learned the processor capabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Handshake {
    /// Every present processor accepted them through `_OSC`.
    Osc,
    /// `_OSC` failed on one, so each was given `_PDC`, which `accepted`
    /// of the `present` evaluated.
    Pdc { accepted: usize, present: usize },
}

/// The firmware's processor idle declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declaration {
    pub handshake: Handshake,
    pub processors: Vec<Declared>,
}

/// A present processor: its local APIC ID and its `_CST`, None without one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declared {
    pub apic: u32,
    pub cst: Option<Result<Vec<CState>, CstError>>,
}

impl Session {
    /// Declare `capabilities` to every present processor, as Linux's
    /// `acpi_early_processor_control_setup` does, `_OSC` first and `_PDC`
    /// to all when any `_OSC` fails, then read their `_CST`, which the
    /// tables either may load. A processor is present when the MADT gives
    /// it an enabled local APIC.
    pub fn processor_idle(&self, capabilities: u32) -> Result<Declaration, Error> {
        let madt = self.table(b"APIC")?.unwrap_or_default();
        let present: Vec<_> = self
            .processors()?
            .into_iter()
            .filter_map(|(handle, id, device)| Some((handle, apic_id(&madt, id, device)?)))
            .collect();
        let osc = present.iter().all(|(handle, _)| {
            matches!(handle.osc(&PROCESSOR_OSC, 1, &[0, capabilities]), Ok(Ok(_)))
        });
        let handshake = if osc {
            Handshake::Osc
        } else {
            let buffer: Vec<u8> = [PDC_REVISION, 1, capabilities]
                .iter()
                .flat_map(|dword| dword.to_le_bytes())
                .collect();
            let accepted = present
                .iter()
                .filter(|(handle, _)| {
                    handle.child("_PDC").is_ok()
                        && handle
                            .evaluate(Some("_PDC"), &[Argument::Buffer(&buffer)])
                            .is_ok()
                })
                .count();
            Handshake::Pdc {
                accepted,
                present: present.len(),
            }
        };
        let processors = present
            .into_iter()
            .map(|(handle, apic)| {
                Ok(Declared {
                    apic,
                    cst: handle.cst()?,
                })
            })
            .collect::<Result<_, Error>>()?;
        Ok(Declaration {
            handshake,
            processors,
        })
    }
}

/// How a `_CST` entry is entered: its Generic Register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    /// FIXED_HARDWARE: on x86, an MWAIT hint in `address` when `class`
    /// (the register's bit offset) is 2, native C-state beyond halt.
    FixedHardware {
        address: u64,
        vendor: u8,
        class: u8,
        access_size: u8,
    },
    /// SYSTEM_IO: a read of this port.
    SystemIo(u64),
}

/// One `_CST` idle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CState {
    /// ACPI C-state type: 1, 2 or 3 for C1–C3.
    pub kind: u64,
    pub latency_us: u64,
    pub power_mw: u64,
    pub entry: Entry,
}

/// Why a processor's `_CST` was refused whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CstError {
    /// Not a package of at least two elements.
    Invalid,
    /// Its count is not the number of states that follow it.
    Inconsistent,
}

/// The states of a `_CST` result, as `acpi_processor_evaluate_cst` keeps
/// them: entries that are not four-element packages of a register buffer
/// and three integers, or whose register is neither fixed hardware nor
/// system I/O, are skipped.
pub fn parse_cst(value: Value<'_>) -> Result<Vec<CState>, CstError> {
    let Value::Package(elements) = value else {
        return Err(CstError::Invalid);
    };
    if elements.len() < 2 {
        return Err(CstError::Invalid);
    }
    match elements[0] {
        Value::Integer(count) if count >= 1 && count == elements.len() as u64 - 1 => {}
        _ => return Err(CstError::Inconsistent),
    }
    let mut states = Vec::new();
    for element in &elements[1..] {
        let Value::Package(fields) = element else {
            continue;
        };
        let [
            Value::Buffer(register),
            Value::Integer(kind),
            Value::Integer(latency),
            Value::Integer(power),
        ] = fields.as_slice()
        else {
            continue;
        };
        // struct acpi_power_register: descriptor, length, space, bit width,
        // bit offset, access size, then the 64-bit address.
        let Some(address) = register.get(7..15) else {
            continue;
        };
        let address = u64::from_le_bytes(address.try_into().unwrap());
        let entry = match register[3] {
            FIXED_HARDWARE => Entry::FixedHardware {
                address,
                vendor: register[4],
                class: register[5],
                access_size: register[6],
            },
            SYSTEM_IO => Entry::SystemIo(address),
            _ => continue,
        };
        states.push(CState {
            kind: *kind,
            latency_us: *latency,
            power_mw: *power,
            entry,
        });
    }
    Ok(states)
}

/// The facts about the entering CPU that decide which states it may enter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cpu {
    /// Intel, AMD or Hygon: the vendors whose `_CST` MWAIT hints Linux uses.
    pub mwait_vendor: bool,
    pub intel: bool,
    /// CPUID leaf 5 ECX and EDX, when MONITOR/MWAIT and the leaf exist.
    pub mwait: Option<(u32, u32)>,
    /// CPUID.06H:EAX[2]: the APIC timer runs in every C-state. Deeper states
    /// would need a broadcast timer otherwise, which this boot has none of.
    pub always_running_timer: bool,
    /// CPUID.80000007H:EDX[8]: the TSC, which this boot keeps time with,
    /// runs in every C-state.
    pub nonstop_tsc: bool,
}

/// How an admitted state is entered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enter {
    Halt,
    /// MWAIT with this hint and interrupts as break events.
    Mwait(u32),
}

/// A state the CPU may enter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub kind: u64,
    pub latency_us: u64,
    /// Twice the exit latency, as Linux's `latency_factor` sets it.
    pub residency_us: u64,
    pub enter: Enter,
}

/// Why a declared state was left out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Its MWAIT hint names a substate this CPU lacks, or the CPU lacks
    /// MWAIT, interrupt break or a vendor `_CST` hints apply to.
    UnsupportedHint,
    /// System I/O entry, which this boot does not enter.
    IoPort,
    /// Not C1, C2 or C3.
    UnknownType,
    /// Exit latency past Linux's C2 or C3 ceiling.
    Latency,
    /// The APIC timer stops in it, and no broadcast timer wakes the CPU.
    TimerStops,
    /// The TSC may stop in it.
    TscStops,
    /// C3 whose entry needs the bus-master status check, which this boot
    /// does not make.
    BusMasterCheck,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedHint => "an MWAIT hint this CPU does not support",
            Self::IoPort => "a system I/O entry, which is not entered",
            Self::UnknownType => "not C1, C2 or C3",
            Self::Latency => "exit latency past the C2/C3 ceiling",
            Self::TimerStops => "the APIC timer stops in it",
            Self::TscStops => "the TSC may stop in it",
            Self::BusMasterCheck => "it needs the bus-master activity check",
        })
    }
}

/// The states `cpu` may enter of its `_CST` `states`, C1 first (HLT when
/// the table names none), and each one left out with why.
pub fn admit(states: &[CState], cpu: &Cpu) -> (Vec<Admitted>, Vec<(CState, Refusal)>) {
    let mut admitted = Vec::new();
    let mut refused = Vec::new();
    if states.first().is_none_or(|state| state.kind != 1) {
        admitted.push(Admitted {
            kind: 1,
            latency_us: 0,
            residency_us: 0,
            enter: Enter::Halt,
        });
    }
    for state in states {
        let (enter, bm_sts_skip) = match state.entry {
            Entry::FixedHardware {
                address,
                class,
                access_size,
                ..
            } => match probe(address, class, cpu) {
                Some(hint) => (Enter::Mwait(hint), cpu.intel && access_size & 2 == 0),
                None if state.kind == 1 => (Enter::Halt, false),
                None => {
                    refused.push((*state, Refusal::UnsupportedHint));
                    continue;
                }
            },
            Entry::SystemIo(_) => {
                refused.push((*state, Refusal::IoPort));
                continue;
            }
        };
        let refusal = match state.kind {
            1 => None,
            2 | 3
                if state.latency_us
                    > if state.kind == 2 {
                        MAX_C2_LATENCY_US
                    } else {
                        MAX_C3_LATENCY_US
                    } =>
            {
                Some(Refusal::Latency)
            }
            2 | 3 if !cpu.always_running_timer => Some(Refusal::TimerStops),
            2 | 3 if !cpu.nonstop_tsc => Some(Refusal::TscStops),
            3 if !bm_sts_skip => Some(Refusal::BusMasterCheck),
            2 | 3 => None,
            _ => Some(Refusal::UnknownType),
        };
        match refusal {
            Some(refusal) => refused.push((*state, refusal)),
            None => admitted.push(Admitted {
                kind: state.kind,
                latency_us: state.latency_us,
                residency_us: state.latency_us.saturating_mul(LATENCY_FACTOR),
                enter,
            }),
        }
    }
    (admitted, refused)
}

/// `acpi_processor_ffh_cstate_probe`: the MWAIT hint of a fixed-hardware
/// entry, when this CPU supports its substate and interrupt break.
fn probe(address: u64, class: u8, cpu: &Cpu) -> Option<u32> {
    let (ecx, edx) = cpu.mwait?;
    if !cpu.mwait_vendor || class != MWAIT_CLASS {
        return None;
    }
    let hint = address as u32;
    let kind = (((hint >> 4) & 0xf) + 1) & 0xf;
    let substates = edx.checked_shr(kind * 4).unwrap_or(0) & 0xf;
    (substates != 0 && ecx & MWAIT_EXTENSIONS != 0 && ecx & MWAIT_INTERRUPT_BREAK != 0)
        .then_some(hint)
}

/// The deepest of `states` whose target residency fits `budget_us`
/// microseconds (any when None), or the first.
pub fn select(states: &[Admitted], budget_us: Option<u64>) -> Option<&Admitted> {
    states
        .iter()
        .rev()
        .find(|state| budget_us.is_none_or(|budget| state.residency_us <= budget))
        .or(states.first())
}

impl<'a> Handle<'a> {
    /// This processor's `_CST` states; None when it has no `_CST`.
    pub fn cst(self) -> Result<Option<Result<Vec<CState>, CstError>>, Error> {
        if self.child("_CST").is_err() {
            return Ok(None);
        }
        Ok(Some(match self.evaluate(Some("_CST"), &[])? {
            Some(value) => parse_cst(value),
            None => Err(CstError::Invalid),
        }))
    }
}

#[cfg(test)]
mod tests;

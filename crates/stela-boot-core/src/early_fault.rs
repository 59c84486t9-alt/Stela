//! Early exception frames, not a recoverable AP/native-worker acknowledgement.
//! Intel SDM3A ch6 and AMD APM2 ch8 define the gate/frame/error-code layouts.
use core::sync::atomic::{AtomicU32, Ordering};

pub const EXCEPTIONS: usize = 32;
pub const STUB_BYTES: usize = 12;
pub const STACK_BYTES: usize = 512;
// #DF, #TS, #NP, #SS, #GP, #PF, #AC, #CP, #VC and #SX push CPU error codes.
pub const ERROR_MASK: u32 = (1 << 8) | (0x1f << 10) | (1 << 17) | (1 << 21) | (1 << 29) | (1 << 30);
pub const WRITING: u32 = 1;
pub const SEALED: u32 = 0x5354_464c;

#[repr(C, align(8))]
pub struct Record {
    seal: AtomicU32,
    vector: u32,
    mode: u32,
    reserved: u32,
    error: u64,
    pc: u64,
    address: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EarlyFault {
    pub mode: u8,
    pub vector: u8,
    pub error: Option<u64>,
    pub pc: u64,
    /// Only #PF defines the CR2 as this exception's address.
    pub address: Option<u64>,
}

/// A published record whose contents cannot describe a CPU exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    Frame { mode: u32, vector: u32 },
    Publication { seal: u32 },
}

impl core::fmt::Display for RecordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Frame { mode, vector } => write!(
                f,
                "early AP exception has mode {mode} and vector {vector}; expected mode 32 or 64 and vector below {EXCEPTIONS}"
            ),
            Self::Publication { seal } => {
                write!(
                    f,
                    "early AP exception has invalid publication value {seal:#x}"
                )
            }
        }
    }
}

impl core::error::Error for RecordError {}

pub fn gate32(handler: u32) -> [u8; 8] {
    let low = handler as u16;
    let high = (handler >> 16) as u16;
    [
        low as u8,
        (low >> 8) as u8,
        0x18,
        0,
        0,
        0x8e,
        high as u8,
        (high >> 8) as u8,
    ]
}
pub fn gate64(handler: u64) -> [u8; 16] {
    let mut gate = [0; 16];
    gate[..2].copy_from_slice(&(handler as u16).to_le_bytes());
    gate[2] = 0x08;
    gate[5] = 0x8e;
    gate[6..8].copy_from_slice(&((handler >> 16) as u16).to_le_bytes());
    gate[8..12].copy_from_slice(&((handler >> 32) as u32).to_le_bytes());
    gate
}
fn decode(
    mode: u32,
    vector: u32,
    error: u64,
    pc: u64,
    address: u64,
) -> Result<EarlyFault, RecordError> {
    if !matches!(mode, 32 | 64) || vector >= EXCEPTIONS as u32 {
        return Err(RecordError::Frame { mode, vector });
    }
    Ok(EarlyFault {
        mode: mode as u8,
        vector: vector as u8,
        error: (ERROR_MASK & (1 << vector) != 0).then_some(error),
        pc,
        address: (vector == 14).then_some(address),
    })
}
/// # Safety
/// The record is the aligned owned SIPI allocation, not arbitrary bytes.
/// The AP is the sole claimant; its assembly latches the first exception and
/// never changes payload after publishing SEALED, including later NMI entry.
pub unsafe fn read(record: *const Record) -> Result<Option<EarlyFault>, RecordError> {
    // SAFETY: the caller keeps an aligned live Record; its seal is atomic
    // while the AP may still be publishing the payload.
    let seal = unsafe { &(*record).seal }.load(Ordering::Acquire);
    match seal {
        0 | WRITING => Ok(None),
        SEALED => {
            // SAFETY: Acquire observes completed immutable publication. No Rust RAM
            // references cross concurrent AP writes while the seal is pending.
            let fault = unsafe {
                decode(
                    (&raw const (*record).mode).read_volatile(),
                    (&raw const (*record).vector).read_volatile(),
                    (&raw const (*record).error).read_volatile(),
                    (&raw const (*record).pc).read_volatile(),
                    (&raw const (*record).address).read_volatile(),
                )
            }?;
            Ok(Some(fault))
        }
        seal => Err(RecordError::Publication { seal }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(record: &Record) -> Result<Option<EarlyFault>, RecordError> {
        // SAFETY: every test record is aligned, live, and owned by this thread;
        // there is no AP or other writer, including after publishing SEALED.
        unsafe { read(record) }
    }

    #[test]
    fn exact_exception_error_slots_and_mode_gates_follow_cpu_frames() {
        assert_eq!(core::mem::size_of::<Record>(), 40);
        assert_eq!(core::mem::offset_of!(Record, vector), 4);
        assert_eq!(core::mem::offset_of!(Record, mode), 8);
        assert_eq!(core::mem::offset_of!(Record, error), 16);
        assert_eq!(core::mem::offset_of!(Record, pc), 24);
        assert_eq!(core::mem::offset_of!(Record, address), 32);
        let errors = [8, 10, 11, 12, 13, 14, 17, 21, 29, 30];
        for vector in 0..EXCEPTIONS as u32 {
            let fault = decode(32, vector, 0x45, 0x12345, 0x23456).unwrap();
            assert_eq!(fault.error, errors.contains(&vector).then_some(0x45));
            assert_eq!(fault.address, (vector == 14).then_some(0x23456));
        }
        assert_eq!(
            decode(16, 13, 0, 0, 0),
            Err(RecordError::Frame {
                mode: 16,
                vector: 13
            })
        );
        assert_eq!(
            decode(64, 32, 0, 0, 0),
            Err(RecordError::Frame {
                mode: 64,
                vector: 32
            })
        );
        let address = 0x98765432;
        let legacy = gate32(address);
        assert_eq!(&legacy[2..6], &[0x18, 0, 0, 0x8e]);
        assert_eq!(
            u32::from(u16::from_le_bytes(legacy[..2].try_into().unwrap()))
                | u32::from(u16::from_le_bytes(legacy[6..].try_into().unwrap())) << 16,
            address
        );
        let address = 0x123456789abc;
        let long = gate64(address);
        assert_eq!(&long[2..6], &[8, 0, 0, 0x8e]);
        assert_eq!(&long[12..], &[0; 4]);
        assert_eq!(
            u64::from(u16::from_le_bytes(long[..2].try_into().unwrap()))
                | u64::from(u16::from_le_bytes(long[6..8].try_into().unwrap())) << 16
                | u64::from(u32::from_le_bytes(long[8..12].try_into().unwrap())) << 32,
            address
        );
    }
    #[test]
    fn incomplete_records_never_become_actual_exception_evidence() {
        let mut record = Record {
            seal: AtomicU32::new(0),
            vector: 13,
            mode: 64,
            reserved: 0,
            error: 0x44,
            pc: 0xabcdef,
            address: 0x123456,
        };
        assert_eq!(observed(&record), Ok(None));
        record.seal.store(WRITING, Ordering::Release);
        assert_eq!(observed(&record), Ok(None));
        record.seal.store(SEALED, Ordering::Release);
        assert_eq!(
            observed(&record),
            Ok(Some(EarlyFault {
                mode: 64,
                vector: 13,
                error: Some(0x44),
                pc: 0xabcdef,
                address: None,
            }))
        );
        record.vector = 14;
        assert_eq!(observed(&record).unwrap().unwrap().address, Some(0x123456));
        record.seal.store(2, Ordering::Release);
        assert_eq!(observed(&record), Err(RecordError::Publication { seal: 2 }));
    }
}

// SPDX-License-Identifier: MIT
//! Owned pre-EBS UEFI observation for Intel's packed DSBR variable. Raw EFI
//! statuses are x86-64 values; only NOT_FOUND is classified as absent.
use super::{DsbrInput, PlatformInputs};

const UEFI_ERROR_BIT: u64 = 1 << 63;
const UEFI_NOT_FOUND: u64 = UEFI_ERROR_BIT | 14;
const UEFI_BUFFER_TOO_SMALL: u64 = UEFI_ERROR_BIT | 5;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DsbrCapture {
    pub observation: DsbrCaptureObservation,
}
/// Copy data only: no UEFI service pointer, provider borrow or heap allocation
/// survives the pre-EBS read. Invalid-size/error input never becomes Absent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DsbrCaptureObservation {
    #[default]
    NotCaptured,
    Present {
        bytes: [u8; 5],
        attributes: u32,
    },
    Absent {
        uefi_status: u64,
    },
    MalformedSize {
        uefi_status: u64,
        reported_bytes: u64,
    },
    UefiError {
        uefi_status: u64,
        required_bytes: Option<u64>,
    },
}
impl DsbrCapture {
    /// A successful GetVariable response. Short (or otherwise wrong-size)
    /// responses keep their exact size and SUCCESS status, not an absence.
    pub fn from_variable(bytes: &[u8], attributes: u32) -> Self {
        Self {
            observation: match bytes.try_into() {
                Ok(bytes) => DsbrCaptureObservation::Present { bytes, attributes },
                Err(_) => DsbrCaptureObservation::MalformedSize {
                    uefi_status: 0,
                    reported_bytes: bytes.len() as u64,
                },
            },
        }
    }
    /// Preserve the native x86-64 EFI_STATUS and returned required size.
    /// BUFFER_TOO_SMALL is a malformed fixed-size variable, never a request to
    /// allocate an arbitrary firmware-controlled buffer or retry a racing read.
    pub fn from_uefi_error(uefi_status: u64, required_bytes: Option<u64>) -> Self {
        Self {
            observation: match (uefi_status, required_bytes) {
                (UEFI_NOT_FOUND, _) => DsbrCaptureObservation::Absent { uefi_status },
                (UEFI_BUFFER_TOO_SMALL, Some(reported_bytes)) => {
                    DsbrCaptureObservation::MalformedSize {
                        uefi_status,
                        reported_bytes,
                    }
                }
                _ => DsbrCaptureObservation::UefiError {
                    uefi_status,
                    required_bytes,
                },
            },
        }
    }
    pub fn input(self) -> DsbrInput {
        match self.observation {
            DsbrCaptureObservation::Present { bytes, .. } => DsbrInput::decode(&bytes).unwrap(),
            DsbrCaptureObservation::Absent { .. } => DsbrInput::Absent,
            _ => DsbrInput::Unavailable,
        }
    }
    pub fn platform_inputs(self) -> PlatformInputs {
        PlatformInputs { dsbr: self.input() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_capture_preserves_all_five_bytes_attributes_and_override() {
        let capture = DsbrCapture::from_variable(&[7, 0xb1, 0xbe, 0xad, 0xde], 0x87);
        assert_eq!(
            capture.observation,
            DsbrCaptureObservation::Present {
                bytes: [7, 0xb1, 0xbe, 0xad, 0xde],
                attributes: 0x87,
            }
        );
        let copied = capture;
        assert_eq!(
            copied.input(),
            DsbrInput::Present {
                revision: 7,
                raw: 0xdead_beb1
            }
        );
        assert_eq!(copied.platform_inputs().dsbr.parameters(), [1, 11]);
    }
    #[test]
    fn only_actual_not_found_is_absent_and_all_uefi_errors_keep_raw_status() {
        let capture = DsbrCapture::from_uefi_error(UEFI_NOT_FOUND, None);
        assert_eq!(capture.input(), DsbrInput::Absent);
        assert_eq!(
            capture.observation,
            DsbrCaptureObservation::Absent {
                uefi_status: UEFI_NOT_FOUND
            }
        );
        for status in [
            UEFI_ERROR_BIT | 3,
            UEFI_ERROR_BIT | 7,
            UEFI_ERROR_BIT | 26,
            1,
            0x8123_4567_89ab_cdef,
        ] {
            let capture = DsbrCapture::from_uefi_error(status, Some(123));
            assert_eq!(capture.input(), DsbrInput::Unavailable);
            assert_eq!(
                capture.observation,
                DsbrCaptureObservation::UefiError {
                    uefi_status: status,
                    required_bytes: Some(123)
                }
            );
        }
        assert_eq!(DsbrCapture::default().input(), DsbrInput::Unavailable);
        assert_eq!(
            DsbrCapture::default().observation,
            DsbrCaptureObservation::NotCaptured
        );
    }
    #[test]
    fn short_success_and_oversized_variable_never_claim_absence_or_zero_override() {
        for len in [0, 1, 2, 3, 4, 6, 255] {
            let capture = DsbrCapture::from_variable(&vec![0; len], 0);
            assert_eq!(capture.input(), DsbrInput::Unavailable);
            assert_eq!(
                capture.observation,
                DsbrCaptureObservation::MalformedSize {
                    uefi_status: 0,
                    reported_bytes: len as u64
                }
            );
        }
        let capture = DsbrCapture::from_uefi_error(UEFI_BUFFER_TOO_SMALL, Some(0x1234_5678_9abc));
        assert_eq!(capture.input(), DsbrInput::Unavailable);
        assert_eq!(
            capture.observation,
            DsbrCaptureObservation::MalformedSize {
                uefi_status: UEFI_BUFFER_TOO_SMALL,
                reported_bytes: 0x1234_5678_9abc,
            }
        );
        let unavailable_size = DsbrCapture::from_uefi_error(UEFI_BUFFER_TOO_SMALL, None);
        assert!(matches!(
            unavailable_size.observation,
            DsbrCaptureObservation::UefiError {
                required_bytes: None,
                ..
            }
        ));
        assert_eq!(unavailable_size.input(), DsbrInput::Unavailable);
    }
}

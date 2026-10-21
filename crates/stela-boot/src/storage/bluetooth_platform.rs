//! Read-only pre-EBS Intel board override capture. One bounded GetVariable
//! reads exactly five bytes; no variable writes, allocation or retry occurs.
use stela_drivers::usb::bluetooth::intel::{DsbrCapture, DsbrCaptureObservation};
use uefi::{
    CStr16, cstr16, guid,
    runtime::{self, VariableAttributes, VariableVendor},
};

const NAME: &CStr16 = cstr16!("UefiCnvCommonDSBR");
const VENDOR: VariableVendor = VariableVendor(guid!("e65d8884-d4af-4b20-8d03-772ecc3da531"));
type VariableRead = uefi::Result<(usize, VariableAttributes), Option<usize>>;

pub(super) fn capture() -> DsbrCapture {
    capture_with(|name, vendor, bytes| {
        runtime::get_variable(name, vendor, bytes)
            .map(|(value, attributes)| (value.len(), attributes))
    })
}

fn capture_with(
    read: impl FnOnce(&CStr16, &VariableVendor, &mut [u8; 5]) -> VariableRead,
) -> DsbrCapture {
    let mut bytes = [0u8; 5];
    match read(NAME, &VENDOR, &mut bytes) {
        Ok((size, attributes)) => match bytes.get(..size) {
            Some(value) => DsbrCapture::from_variable(value, attributes.bits()),
            None => DsbrCapture {
                observation: DsbrCaptureObservation::MalformedSize {
                    uefi_status: 0,
                    reported_bytes: size as u64,
                },
            },
        },
        Err(error) => DsbrCapture::from_uefi_error(
            error.status().0 as u64,
            error.data().map(|bytes| bytes as u64),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_drivers::usb::bluetooth::intel::DsbrInput;
    use uefi::Status;

    #[test]
    fn pre_ebs_reader_uses_exact_variable_guid_and_one_fixed_buffer() {
        let mut calls = 0;
        let capture = capture_with(|name, vendor, bytes| {
            calls += 1;
            assert_eq!(name, cstr16!("UefiCnvCommonDSBR"));
            assert_eq!(
                *vendor,
                VariableVendor(guid!("e65d8884-d4af-4b20-8d03-772ecc3da531"))
            );
            assert_eq!(*bytes, [0; 5]);
            bytes.copy_from_slice(&[7, 0xb1, 0xbe, 0xad, 0xde]);
            Ok((5, VariableAttributes::from_bits_retain(0x87)))
        });
        assert_eq!(calls, 1);
        assert_eq!(
            capture.input(),
            DsbrInput::Present {
                revision: 7,
                raw: 0xdead_beb1
            }
        );
        assert_eq!(
            capture.observation,
            DsbrCaptureObservation::Present {
                bytes: [7, 0xb1, 0xbe, 0xad, 0xde],
                attributes: 0x87,
            }
        );
    }
    #[test]
    fn absence_size_and_exact_uefi_errors_survive_copy_without_a_service_borrow() {
        let mut calls = 0;
        let absent = capture_with(|_, _, _| {
            calls += 1;
            Err(uefi::Error::new(Status::NOT_FOUND, None))
        });
        assert_eq!(calls, 1);
        assert_eq!(absent.input(), DsbrInput::Absent);
        assert_eq!(
            absent.observation,
            DsbrCaptureObservation::Absent {
                uefi_status: Status::NOT_FOUND.0 as u64
            }
        );
        for size in [0, 1, 4, 6] {
            let capture = capture_with(|_, _, _| Ok((size, VariableAttributes::empty())));
            assert_eq!(capture.input(), DsbrInput::Unavailable);
            assert_eq!(
                capture.observation,
                DsbrCaptureObservation::MalformedSize {
                    uefi_status: 0,
                    reported_bytes: size as u64
                }
            );
        }
        for status in [
            Status::BUFFER_TOO_SMALL,
            Status::DEVICE_ERROR,
            Status::SECURITY_VIOLATION,
            Status::UNSUPPORTED,
        ] {
            let original = capture_with(|_, _, _| Err(uefi::Error::new(status, Some(123))));
            let copied = original;
            assert_eq!(copied.input(), DsbrInput::Unavailable);
            match copied.observation {
                DsbrCaptureObservation::MalformedSize {
                    uefi_status,
                    reported_bytes,
                } => {
                    assert_eq!(uefi_status, Status::BUFFER_TOO_SMALL.0 as u64);
                    assert_eq!(reported_bytes, 123);
                }
                DsbrCaptureObservation::UefiError {
                    uefi_status,
                    required_bytes,
                } => {
                    assert_eq!(uefi_status, status.0 as u64);
                    assert_eq!(required_bytes, Some(123));
                }
                _ => panic!("error must retain its precise unavailable diagnostic"),
            }
        }
    }
}

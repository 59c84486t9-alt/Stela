//! Read-only Intel Wi-Fi variable observations before ExitBootServices. Only
//! copied observations and immutable LOADER_DATA regions leave this module.
use crate::{handoff::Region, paging::PAGE};
use sha2::Digest;
use stela_crypto::Sha256;
use stela_drivers::net::wifi::intel::platform::{Observation, Stage, Variable};
use uefi::{
    CString16, Status, boot,
    runtime::{VariableAttributes, VariableVendor},
};

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub(super) struct Capture {
    pub observation: Observation,
    pub region: Region,
}

struct Read {
    status: u64,
    bytes: usize,
    attributes: u32,
}

pub(super) fn record(
    phase: &str,
    variable: Variable,
    observation: Observation,
    resource: Option<&stela_drivers::firmware::Resource<'_, &'static [u8]>>,
) -> serde_json::Value {
    let stage = |stage| match stage {
        Stage::Probe => "probe",
        Stage::Read => "read",
    };
    let observed = match observation {
        Observation::NotCaptured => serde_json::json!({"state":"not-captured"}),
        Observation::Absent {
            stage: at,
            status,
            reported_bytes,
        } => {
            serde_json::json!({"state":"absent","stage":stage(at),"status":status,"reported_bytes":reported_bytes})
        }
        Observation::Failed {
            stage: at,
            status,
            reported_bytes,
        } => {
            serde_json::json!({"state":"failed","stage":stage(at),"status":status,"reported_bytes":reported_bytes})
        }
        Observation::BoundExceeded {
            stage: at,
            status,
            reported_bytes,
        } => {
            serde_json::json!({"state":"bound-exceeded","stage":stage(at),"status":status,"reported_bytes":reported_bytes})
        }
        Observation::Present {
            attributes,
            bytes,
            sha256,
            probe_reported_bytes,
        } => {
            let digest: alloc::string::String =
                sha256.iter().map(|b| alloc::format!("{b:02x}")).collect();
            serde_json::json!({"state":"present","attributes":attributes,"bytes":bytes,"sha256":digest,"probe_reported_bytes":probe_reported_bytes})
        }
    };
    let target = variable.requirement().target;
    let provenance = resource.map(|resource| {
        let provenance = resource.provenance;
        serde_json::json!({"source":provenance.source,"revision":provenance.revision,
            "member":provenance.member,"license":provenance.license})
    });
    serde_json::json!({"phase":phase,"variable":variable.name(),"guid":variable.guid(),
        "name":variable.resource_name(),"target":{"driver":target.driver,"hardware":target.hardware,"revision":target.revision,"board":target.board},"observation":observed,"provenance":provenance})
}

/// Preserve the actual EFI status and DataSize on every outcome. The safe
/// convenience wrapper discards DataSize on errors other than BUFFER_TOO_SMALL
/// and slices its buffer before the caller can validate a returned size.
fn read(variable: Variable, buffer: &mut [u8]) -> Read {
    let name = CString16::try_from(variable.name()).expect("static variable name is UCS-2");
    let vendor = VariableVendor(
        variable
            .guid()
            .parse()
            .expect("static variable GUID is valid"),
    );
    let mut bytes = buffer.len();
    let mut attributes = VariableAttributes::empty();
    let table = uefi::table::system_table_raw().expect("UEFI entry initialized the system table");
    // SAFETY: called only before EBS while the runtime table remains identity
    // mapped. All output pointers and the exclusive data buffer are valid for
    // this one call. Empty size probes pass a null data pointer.
    let status = unsafe {
        let runtime = &*table.as_ref().runtime_services;
        (runtime.get_variable)(
            name.as_ptr().cast(),
            &vendor.0,
            &mut attributes,
            &mut bytes,
            if buffer.is_empty() {
                core::ptr::null_mut()
            } else {
                buffer.as_mut_ptr().cast()
            },
        )
    };
    Read {
        status: status.0 as u64,
        bytes,
        attributes: attributes.bits(),
    }
}

pub(super) fn capture(variable: Variable) -> Result<Capture, &'static str> {
    capture_with(variable, read, |bytes| {
        let page = boot::allocate_pages(
            boot::AllocateType::AnyPages,
            boot::MemoryType::LOADER_DATA,
            bytes.div_ceil(PAGE),
        )
        .map_err(|_| "firmware has no permanent Wi-Fi observation pages")?;
        // SAFETY: fresh exclusive reserved pages, never freed or given to the
        // guest allocator. The only mutation happens before publishing Capture.
        Ok(unsafe { core::slice::from_raw_parts_mut(page.as_ptr(), bytes) })
    })
}

fn capture_with(
    variable: Variable,
    mut read: impl FnMut(Variable, &mut [u8]) -> Read,
    allocate: impl FnOnce(usize) -> Result<&'static mut [u8], &'static str>,
) -> Result<Capture, &'static str> {
    let probe = read(variable, &mut []);
    let reported = Some(probe.bytes as u64);
    let failed = |stage, result: &Read| Capture {
        observation: Observation::from_error(stage, result.status, Some(result.bytes as u64)),
        region: Region::default(),
    };
    if probe.status == Status::SUCCESS.0 as u64 && probe.bytes == 0 {
        return Ok(Capture {
            observation: Observation::Present {
                attributes: probe.attributes,
                bytes: 0,
                sha256: Sha256::digest([]).into(),
                probe_reported_bytes: reported,
            },
            region: Region::default(),
        });
    }
    if probe.status != Status::BUFFER_TOO_SMALL.0 as u64 || probe.bytes == 0 {
        return Ok(failed(Stage::Probe, &probe));
    }
    let length = match variable.bounded_bytes(Stage::Probe, probe.status, probe.bytes as u64) {
        Ok(length) => length,
        Err(observation) => {
            return Ok(Capture {
                observation,
                region: Region::default(),
            });
        }
    };
    let buffer = allocate(length)?;
    if buffer.len() != length {
        return Err("Wi-Fi capture allocator returned a different buffer length");
    }
    let result = read(variable, buffer);
    if result.status != Status::SUCCESS.0 as u64 || result.bytes > length {
        return Ok(failed(Stage::Read, &result));
    }
    let bytes = &buffer[..result.bytes];
    Ok(Capture {
        observation: Observation::Present {
            attributes: result.attributes,
            bytes: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            probe_reported_bytes: reported,
        },
        region: Region {
            physical: buffer.as_ptr() as u64,
            bytes: result.bytes as u64,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, vec};
    use core::cell::Cell;
    use stela_drivers::net::wifi::intel::platform::MAX_VARIABLE_BYTES;

    fn reply(status: Status, bytes: usize) -> Read {
        Read {
            status: status.0 as u64,
            bytes,
            attributes: 0x87,
        }
    }

    #[test]
    fn each_radio_query_bound_refuses_before_allocation_and_preserves_required_size() {
        use stela_drivers::net::wifi::intel::platform::VARIABLE_DESCRIPTORS;
        for descriptor in &VARIABLE_DESCRIPTORS[3..] {
            let calls = Cell::new(0);
            let over = descriptor.maximum_bytes + 1;
            let capture = capture_with(
                descriptor.variable,
                |variable, buffer| {
                    assert_eq!(variable, descriptor.variable);
                    assert!(buffer.is_empty());
                    calls.set(calls.get() + 1);
                    reply(Status::BUFFER_TOO_SMALL, over)
                },
                |_| panic!("over-limit raw query must not allocate"),
            )
            .unwrap();
            assert_eq!(calls.get(), 1);
            assert_eq!(
                capture.observation,
                Observation::BoundExceeded {
                    stage: Stage::Probe,
                    status: Status::BUFFER_TOO_SMALL.0 as u64,
                    reported_bytes: over as u64,
                }
            );
            assert_eq!(capture.region.bytes, 0);
            assert_eq!(capture.region.physical, 0);
        }
    }

    #[test]
    fn query_then_one_permanent_read_retains_exact_variable_attrs_length_and_digest() {
        for variable in stela_drivers::net::wifi::intel::platform::VARIABLE_DESCRIPTORS
            .iter()
            .map(|descriptor| descriptor.variable)
        {
            let calls = Cell::new(0);
            let pointer = Cell::new(0);
            let capture = capture_with(
                variable,
                |observed, buffer| {
                    assert_eq!(observed, variable);
                    calls.set(calls.get() + 1);
                    if buffer.is_empty() {
                        return reply(Status::BUFFER_TOO_SMALL, 8);
                    }
                    assert_eq!(buffer.len(), 8);
                    assert_eq!(buffer.as_ptr() as u64, pointer.get());
                    buffer[..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
                    // Shrinkage is retained as the actual successful bytes, with
                    // the original query size attached and no retry.
                    reply(Status::SUCCESS, 6)
                },
                |bytes| {
                    let buffer = Box::leak(vec![0; bytes].into_boxed_slice());
                    pointer.set(buffer.as_ptr() as u64);
                    Ok(buffer)
                },
            )
            .unwrap();
            assert_eq!(calls.get(), 2);
            assert_eq!(capture.region.physical, pointer.get());
            assert_eq!(capture.region.bytes, 6);
            assert_eq!(
                capture.observation,
                Observation::Present {
                    attributes: 0x87,
                    bytes: 6,
                    sha256: Sha256::digest([1, 2, 3, 4, 5, 6]).into(),
                    probe_reported_bytes: Some(8),
                }
            );
        }
    }

    #[test]
    fn actual_empty_success_remains_present_without_allocation_or_retry() {
        let calls = Cell::new(0);
        let capture = capture_with(
            Variable::Step,
            |_, bytes| {
                calls.set(calls.get() + 1);
                assert!(bytes.is_empty());
                reply(Status::SUCCESS, 0)
            },
            |_| panic!("empty query success must not allocate"),
        )
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(capture.region.bytes, 0);
        assert_eq!(
            capture.observation,
            Observation::Present {
                attributes: 0x87,
                bytes: 0,
                sha256: Sha256::digest([]).into(),
                probe_reported_bytes: Some(0)
            }
        );
    }

    #[test]
    fn only_not_found_is_absence_and_probe_failures_keep_actual_status_and_size() {
        for status in [
            Status::NOT_FOUND,
            Status::DEVICE_ERROR,
            Status::SECURITY_VIOLATION,
            Status::UNSUPPORTED,
            Status::SUCCESS,
        ] {
            let capture = capture_with(
                Variable::OemPnvm,
                |_, _| reply(status, 123),
                |_| panic!("failed query must not allocate"),
            )
            .unwrap();
            assert_eq!(
                capture.observation,
                Observation::from_error(Stage::Probe, status.0 as u64, Some(123))
            );
            assert_eq!(capture.region.physical, 0);
        }
        for bytes in [0, MAX_VARIABLE_BYTES + 1, usize::MAX] {
            let capture = capture_with(
                Variable::Step,
                |_, _| reply(Status::BUFFER_TOO_SMALL, bytes),
                |_| panic!("invalid query size must not allocate"),
            )
            .unwrap();
            if bytes == 0 {
                assert_eq!(
                    capture.observation,
                    Observation::from_error(
                        Stage::Probe,
                        Status::BUFFER_TOO_SMALL.0 as u64,
                        Some(0)
                    )
                );
            } else {
                assert_eq!(
                    capture.observation,
                    Observation::BoundExceeded {
                        stage: Stage::Probe,
                        status: Status::BUFFER_TOO_SMALL.0 as u64,
                        reported_bytes: bytes as u64
                    }
                );
            }
        }
    }

    #[test]
    fn read_failures_growth_and_disappearance_preserve_status_and_never_retry() {
        for (status, bytes) in [
            (Status::NOT_FOUND, 19),
            (Status::DEVICE_ERROR, 17),
            (Status::BUFFER_TOO_SMALL, 9),
            (Status::SUCCESS, 9),
        ] {
            let calls = Cell::new(0);
            let capture = capture_with(
                Variable::ReducedPower,
                |_, buffer| {
                    calls.set(calls.get() + 1);
                    if buffer.is_empty() {
                        reply(Status::BUFFER_TOO_SMALL, 8)
                    } else {
                        reply(status, bytes)
                    }
                },
                |bytes| Ok(Box::leak(vec![0; bytes].into_boxed_slice())),
            )
            .unwrap();
            assert_eq!(calls.get(), 2);
            assert_eq!(
                capture.observation,
                Observation::from_error(Stage::Read, status.0 as u64, Some(bytes as u64))
            );
            assert_eq!(capture.region.physical, 0);
        }
    }

    #[test]
    fn actual_read_zero_success_and_allocation_failure_are_distinct() {
        let capture = capture_with(
            Variable::Step,
            |_, buffer| {
                if buffer.is_empty() {
                    reply(Status::BUFFER_TOO_SMALL, 6)
                } else {
                    reply(Status::SUCCESS, 0)
                }
            },
            |bytes| Ok(Box::leak(vec![0; bytes].into_boxed_slice())),
        )
        .unwrap();
        assert!(matches!(
            capture.observation,
            Observation::Present {
                bytes: 0,
                probe_reported_bytes: Some(6),
                ..
            }
        ));
        let error = capture_with(
            Variable::Step,
            |_, _| reply(Status::BUFFER_TOO_SMALL, 6),
            |_| Err("actual allocation failure"),
        )
        .err()
        .unwrap();
        assert_eq!(error, "actual allocation failure");
    }
}

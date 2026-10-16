use super::*;
use stela_compiler::{GuestAddress, context::memory::MemoryStatus};

fn fault() -> OwnedMemoryFault {
    OwnedMemoryFault {
        status: MemoryStatus::Permission,
        address: GuestAddress(1011),
        pc: GuestAddress(1012),
        completed_bytes: 1013,
    }
}

fn raw() -> RawMemoryObservation {
    RawMemoryObservation {
        status_code: u32::MAX,
        address: 2021,
        pc: 2022,
        completed_bytes: 2023,
    }
}

fn contains_fields(rendered: &str, fields: &[&str]) {
    for field in fields {
        assert!(rendered.contains(field), "missing {field}: {rendered}");
    }
}

#[test]
fn invocation_failure_diagnostics_retain_fault_raw_and_unqualified_carriers() {
    let value = NativeObservation::InvocationFailed {
        detail: "frame changed after call".into(),
        native_invoked: true,
        native_executed: false,
        original_fault: Some(fault()),
        raw_memory: Some(raw()),
        completed_bytes: 3031,
        observed_exit: Some((4041, 4042)),
        raw_returned_carrier: Some((5051, 5052)),
    };
    contains_fields(
        &format!("{value:?}"),
        &[
            "InvocationFailed",
            "frame changed after call",
            "native_invoked: true",
            "native_executed: false",
            "status: Permission",
            "address: GuestAddress(1011)",
            "pc: GuestAddress(1012)",
            "completed_bytes: 1013",
            "status_code: 4294967295",
            "address: 2021",
            "pc: 2022",
            "completed_bytes: 2023",
            "completed_bytes: 3031",
            "observed_exit: Some((4041, 4042))",
            "raw_returned_carrier: Some((5051, 5052))",
        ],
    );
}

#[test]
fn finalizer_and_blocked_stop_diagnostics_preserve_original_failure_details() {
    let value = NativeObservation::FinalizationFailed {
        status: MemoryStatus::Domain,
        native_executed: true,
        original_fault: Some(fault()),
        completed_bytes: 6061,
        observed_exit: None,
        native_invoked: Some(true),
        callback_failure: Some("original callback failure".into()),
        raw_memory: Some(raw()),
        raw_returned_carrier: Some((7071, 7072)),
    };
    contains_fields(
        &format!("{value:?}"),
        &[
            "FinalizationFailed",
            "status: Domain",
            "native_executed: true",
            "address: GuestAddress(1011)",
            "completed_bytes: 6061",
            "observed_exit: None",
            "native_invoked: Some(true)",
            "original callback failure",
            "status_code: 4294967295",
            "raw_returned_carrier: Some((7071, 7072))",
        ],
    );
    contains_fields(
        &format!("{:?}", OwnedStop::FaultPending(fault())),
        &["FaultPending", "address: GuestAddress(1011)"],
    );
    for (value, expected) in [
        (
            OwnedStop::EntryDeclined("source changed".into()),
            "EntryDeclined(\"source changed\")",
        ),
        (
            OwnedStop::HelperRefused("helper refused".into()),
            "HelperRefused(\"helper refused\")",
        ),
        (
            OwnedStop::Indeterminate("original unknown completion".into()),
            "Indeterminate(\"original unknown completion\")",
        ),
    ] {
        assert_eq!(format!("{value:?}"), expected);
    }
    let trap = stela_compiler::block::decode_trap(GuestAddress(8080), 0xd400_0061)
        .unwrap()
        .unwrap();
    contains_fields(
        &format!("{:?}", OwnedStop::TrapPending(trap)),
        &[
            "TrapPending",
            "kind: SupervisorCall",
            "immediate: 3",
            "instruction_pc: GuestAddress(8080)",
            "exception_return_pc: GuestAddress(8084)",
        ],
    );
}

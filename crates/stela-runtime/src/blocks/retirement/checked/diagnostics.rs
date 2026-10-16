//! Descriptive formatting of every retained failure observation.
//! Formatting borrows the original payloads and grants no execution authority.

use super::{NativeObservation, OwnedMemoryFault, OwnedStop, RawMemoryObservation};
use core::fmt;

impl fmt::Debug for OwnedStop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StopAddress => f.write_str("StopAddress"),
            Self::BudgetExhausted => f.write_str("BudgetExhausted"),
            Self::EntryDeclined(value) => f.debug_tuple("EntryDeclined").field(value).finish(),
            Self::Halted { instruction_pc } => f
                .debug_struct("Halted")
                .field("instruction_pc", instruction_pc)
                .finish(),
            Self::HelperRefused(value) => f.debug_tuple("HelperRefused").field(value).finish(),
            #[cfg(feature = "std")]
            Self::PointerAuthenticationFault { instruction, code } => f
                .debug_struct("PointerAuthenticationFault")
                .field("instruction", instruction)
                .field("code", code)
                .finish(),
            #[cfg(feature = "std")]
            Self::PointerAuthenticationPoisonedTransfer {
                instruction,
                target,
            } => f
                .debug_struct("PointerAuthenticationPoisonedTransfer")
                .field("instruction", instruction)
                .field("target", target)
                .finish(),
            Self::FaultPending(value) => f.debug_tuple("FaultPending").field(value).finish(),
            Self::TrapPending(value) => f.debug_tuple("TrapPending").field(value).finish(),
            Self::Indeterminate(value) => f.debug_tuple("Indeterminate").field(value).finish(),
        }
    }
}

impl fmt::Debug for OwnedMemoryFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedMemoryFault")
            .field("status", &self.status)
            .field("address", &self.address)
            .field("pc", &self.pc)
            .field("completed_bytes", &self.completed_bytes)
            .finish()
    }
}

impl fmt::Debug for RawMemoryObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawMemoryObservation")
            .field("status_code", &self.status_code)
            .field("address", &self.address)
            .field("pc", &self.pc)
            .field("completed_bytes", &self.completed_bytes)
            .finish()
    }
}

impl fmt::Debug for NativeObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Returned { next_pc, kind } => f
                .debug_struct("Returned")
                .field("next_pc", next_pc)
                .field("kind", kind)
                .finish(),
            Self::Fault(value) => f.debug_tuple("Fault").field(value).finish(),
            Self::CpuDeclined(value) => f.debug_tuple("CpuDeclined").field(value).finish(),
            Self::EntryDeclined(value) => f.debug_tuple("EntryDeclined").field(value).finish(),
            Self::FinalizationFailed {
                status,
                native_executed,
                original_fault,
                completed_bytes,
                observed_exit,
                native_invoked,
                callback_failure,
                raw_memory,
                raw_returned_carrier,
            } => f
                .debug_struct("FinalizationFailed")
                .field("status", status)
                .field("native_executed", native_executed)
                .field("original_fault", original_fault)
                .field("completed_bytes", completed_bytes)
                .field("observed_exit", observed_exit)
                .field("native_invoked", native_invoked)
                .field("callback_failure", callback_failure)
                .field("raw_memory", raw_memory)
                .field("raw_returned_carrier", raw_returned_carrier)
                .finish(),
            Self::InvocationFailed {
                detail,
                native_invoked,
                native_executed,
                original_fault,
                raw_memory,
                completed_bytes,
                observed_exit,
                raw_returned_carrier,
            } => f
                .debug_struct("InvocationFailed")
                .field("detail", detail)
                .field("native_invoked", native_invoked)
                .field("native_executed", native_executed)
                .field("original_fault", original_fault)
                .field("raw_memory", raw_memory)
                .field("completed_bytes", completed_bytes)
                .field("observed_exit", observed_exit)
                .field("raw_returned_carrier", raw_returned_carrier)
                .finish(),
            Self::UnqualifiedCallFailure(value) => f
                .debug_tuple("UnqualifiedCallFailure")
                .field(value)
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
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
}

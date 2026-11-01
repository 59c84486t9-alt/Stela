//! Bind exact faulting instructions to their source and register-state plan.
use crate::x86_64::asm::Code;
use crate::{
    GuestAddress,
    block::{FaultRecovery, RecoveryBinding, RetirementPoint},
};
use alloc::vec::Vec;

/// SP's number in a [`RecoveryBinding`].
const STACK_POINTER: u8 = 31;

/// Broad register locations do not imply a guest access. Split them at exact
/// typed emission sites; only those instructions can authorize guest projection.
pub(super) fn bind(
    code: &Code,
    source_map: &[(GuestAddress, usize)],
    source: &[crate::aarch64::Instruction],
    rows: Vec<FaultRecovery>,
) -> Vec<FaultRecovery> {
    let capacity = code
        .sites()
        .iter()
        .map(|marker| {
            rows.iter()
                .filter(|row| row.start < marker.end && marker.start < row.end)
                .count()
                .max(1)
        })
        .sum();
    let mut output = Vec::with_capacity(capacity);
    // Old broad rows prove register locations across the operand/check only.
    // Their frame commits do not prove a complete Before state. Missing
    // internal intervals terminate as host faults without architectural writes.
    for marker in code.sites() {
        let mut matched = false;
        for row in rows
            .iter()
            .filter(|row| row.start < marker.end && marker.start < row.end)
        {
            assert!(
                row.start <= marker.start && marker.end <= row.end,
                "a faulting instruction has one complete location plan"
            );
            matched = true;
            output.push(FaultRecovery {
                start: marker.start,
                end: marker.end,
                site: marker.site,
                ..row.clone()
            });
        }
        if !matched {
            let pc = marker
                .source
                .map(|index| source_map[index].0)
                .or_else(|| {
                    source_map
                        .iter()
                        .filter(|(_, at)| *at <= marker.start)
                        .max_by_key(|(_, at)| *at)
                        .map(|(pc, _)| *pc)
                })
                .expect("guest operand has source map");
            let index = source
                .iter()
                .position(|instruction| instruction.pc == pc)
                .unwrap_or(source.len());
            output.push(FaultRecovery {
                start: marker.start,
                end: marker.end,
                site: marker.site,
                bindings: marker
                    .stack
                    .map(|host| RecoveryBinding::gpr(STACK_POINTER, host))
                    .into_iter()
                    .collect(),
                retirement: RetirementPoint::before(
                    pc,
                    u16::try_from(index).expect("bounded instruction prefix"),
                )
                .expect("validated source PC"),
            });
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aarch64::{Instruction, Operation},
        block::{RecoverySite, RecoverySiteKind},
        x86_64::asm::{Gpr, Mem, Size},
    };
    #[test]
    fn exact_operand_sites_do_not_cover_address_frame_or_settlement_instructions() {
        let mut code = Code::new();
        code.asm()
            .mov_load(Size::Qword, Gpr::Rax, Mem::base(Gpr::Rdi, 0));
        code.asm().guest_check();
        code.asm()
            .lea(Size::Qword, Gpr::Rax, Mem::base_disp8(Gpr::Rax, 8));
        code.asm()
            .guest_access(|asm| asm.mov_load(Size::Qword, Gpr::Rcx, Mem::base(Gpr::Rax, 0)));
        code.asm()
            .mov_store(Size::Qword, Mem::base(Gpr::Rdi, 0), Gpr::Rcx);
        assert_eq!(
            &code[..],
            [
                0x48, 0x8b, 0x07, 0x0f, 0x0b, 0x48, 0x8d, 0x40, 0x08, 0x48, 0x8b, 0x08, 0x48, 0x89,
                0x0f
            ]
        );
        assert_eq!(code.instructions(), 5);
        let pc = GuestAddress(0x1000);
        let source = [Instruction {
            pc,
            operation: Operation::Nop,
        }];
        let row = FaultRecovery {
            start: 0,
            end: 15,
            bindings: alloc::vec![RecoveryBinding::gpr(0, 8)],
            retirement: RetirementPoint::before(pc, 0).unwrap(),
            site: RecoverySite::native_internal(),
        };
        let rows = bind(&code, &[(pc, 0)], &source, alloc::vec![row]);
        assert_eq!(rows.capacity(), rows.len());
        assert_eq!(
            rows.iter()
                .map(|row| (row.start, row.end, row.site.kind()))
                .collect::<Vec<_>>(),
            alloc::vec![
                (3, 5, RecoverySiteKind::GuestCheck),
                (9, 12, RecoverySiteKind::GuestAccess),
            ]
        );
        assert!(
            rows.iter()
                .all(|row| row.bindings == [RecoveryBinding::gpr(0, 8)])
        );
        for internal in [0, 2, 5, 8, 12, 14] {
            assert_eq!(
                FaultRecovery::site_at(&rows, internal).unwrap().kind(),
                RecoverySiteKind::NativeInternal
            );
            let mut state = crate::GuestState::default();
            let before = state.clone();
            assert_eq!(
                FaultRecovery::apply(
                    &rows,
                    internal,
                    crate::block::HostFaultSnapshot {
                        gprs: &crate::block::HostGprSnapshot::legacy([77; 16]),
                        spills: &crate::block::HostSpillSnapshot::new()
                    },
                    &mut state
                )
                .unwrap(),
                None
            );
            assert_eq!(state, before);
        }
        // Baseline code has an authoritative frame and needs no dirty bindings,
        // but its exact guest operations still require checked semantics.
        let baseline = bind(&code, &[(pc, 0)], &source, Vec::new());
        assert_eq!(baseline.capacity(), baseline.len());
        assert_eq!(
            baseline
                .iter()
                .map(|row| (row.start, row.end, row.site.kind()))
                .collect::<Vec<_>>(),
            alloc::vec![
                (3, 5, RecoverySiteKind::GuestCheck),
                (9, 12, RecoverySiteKind::GuestAccess)
            ]
        );
        assert!(baseline.iter().all(|row| row.bindings.is_empty()));
        assert_eq!(
            FaultRecovery::site_at(&baseline, 12).unwrap().kind(),
            RecoverySiteKind::NativeInternal
        );
    }
    #[test]
    fn exact_capacity_includes_overlapping_plans_and_frame_fallbacks() {
        let mut code = Code::new();
        for _ in 0..3 {
            code.asm().guest_check();
        }
        let pc = GuestAddress(0x1000);
        let source = [Instruction {
            pc,
            operation: Operation::Nop,
        }];
        let rows = [RecoveryBinding::gpr(0, 8), RecoveryBinding::gpr(1, 9)]
            .into_iter()
            .map(|binding| FaultRecovery {
                start: 0,
                end: 2,
                bindings: alloc::vec![binding],
                retirement: RetirementPoint::before(pc, 0).unwrap(),
                site: RecoverySite::native_internal(),
            })
            .collect();
        let result = bind(&code, &[(pc, 0)], &source, rows);
        assert_eq!(result.capacity(), 4);
        assert_eq!(
            result
                .iter()
                .map(|row| (row.start, row.end))
                .collect::<Vec<_>>(),
            alloc::vec![(0, 2), (0, 2), (2, 4), (4, 6)]
        );
        assert_eq!(result[0].bindings, [RecoveryBinding::gpr(0, 8)]);
        assert_eq!(result[1].bindings, [RecoveryBinding::gpr(1, 9)]);
        assert!(result[2..].iter().all(|row| row.bindings.is_empty()));
        assert!(
            result
                .iter()
                .all(|row| row.site.kind() == RecoverySiteKind::GuestCheck)
        );
        assert!(
            result
                .iter()
                .all(|row| row.retirement == RetirementPoint::before(pc, 0).unwrap())
        );
    }
}

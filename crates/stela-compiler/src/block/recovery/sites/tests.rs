fn template<'a>(
    block: &'a crate::block::CompiledBlock,
    rows: &'a [crate::block::UnqualifiedFaultRecovery],
) -> crate::block::RecoveryTemplate<'a> {
    crate::block::RecoveryTemplate {
        code: &block.native.x86_64_code,
        source_map: &block.native.source_map,
        source_bytes: block.source_bytes,
        direct_exits: &block.direct_exits,
        recovery: rows,
    }
}
use super::*;
use crate::{
    GuestAddress, Options, TargetCpu,
    block::{
        BlockProfile, CompilationPlan, FaultRecovery, Features, RecoveryQualificationError,
        RetirementPhase, UnqualifiedFaultRecovery,
    },
    x86_64::{MemoryChecks, RangeCheck},
};
use alloc::vec::Vec;

#[test]
fn translated_return_token_is_exact_before_and_descriptor_is_compiler_owned() {
    let source: Vec<_> = [0x91000400_u32, 0xf9400022, 0xf9000022, 0x14000000]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    for range in [RangeCheck::FIVE_LEVEL, RangeCheck::four_level(3)] {
        let options = Options::new(
            BlockProfile::new(Features::SYSTEM_MODE),
            TargetCpu::Baseline,
        )
        .with_memory_checks(
            MemoryChecks::system(false, false, true, false)
                .with_range(range)
                .with_translation(0x1122334455667788),
        );
        let plan = || CompilationPlan::new(&source, GuestAddress(0x1000), &options).unwrap();
        let block = plan().compile().unwrap();
        let rows: Vec<_> = block
            .fault_recovery
            .iter()
            .map(UnqualifiedFaultRecovery::from)
            .collect();
        let mut helpers = 0;
        for row in &block.fault_recovery {
            if row.site.kind() != RecoverySiteKind::TranslatedHelper {
                continue;
            }
            helpers += 1;
            assert_eq!(row.end, row.start + 1);
            assert_eq!(row.retirement.phase(), RetirementPhase::Before);
            let access = row.site.translated_access().unwrap();
            assert_eq!(access.bytes(), 8);
            assert!(!access.atomic());
            assert!(!access.unprivileged());
            assert_eq!(
                &block.native.x86_64_code[row.start - 2..row.start],
                &[0xff, 0xd0]
            );
            assert_eq!(
                &block.native.x86_64_code[row.start..row.start + 2],
                &[8, u8::from(access.write())]
            );
            assert_eq!(
                FaultRecovery::site_at(&block.fault_recovery, row.start - 1)
                    .unwrap()
                    .kind(),
                RecoverySiteKind::NativeInternal
            );
            assert_eq!(
                FaultRecovery::site_at(&block.fault_recovery, row.start + 1)
                    .unwrap()
                    .kind(),
                RecoverySiteKind::NativeInternal
            );
            assert_eq!(
                FaultRecovery::site_at(&block.fault_recovery, row.start).unwrap(),
                row.site
            );
            assert_eq!(
                row.retirement.instruction_pc(),
                GuestAddress(if access.write() { 0x1008 } else { 0x1004 })
            );
        }
        assert_eq!(helpers, 2);
        let qualified = plan().qualify_recovery(template(&block, &rows)).unwrap();
        assert_eq!(qualified.fault_recovery, block.fault_recovery);
        let index = rows
            .iter()
            .position(|row| row.site == RecoverySiteKind::TranslatedHelper)
            .unwrap();
        for start in [rows[index].start - 1, rows[index].start + 1] {
            let mut forged = rows.clone();
            forged[index].start = start;
            forged[index].end = start + 1;
            assert!(matches!(
                plan().qualify_recovery(template(&block, &forged)),
                Err(RecoveryQualificationError::RecoveryPlan)
            ));
        }
        let mut forged = rows.clone();
        forged[index].site = RecoverySiteKind::GuestCheck;
        assert!(matches!(
            plan().qualify_recovery(template(&block, &forged)),
            Err(RecoveryQualificationError::RecoveryPlan)
        ));
        // The live plan retains the actual descriptor, not just its portable tag.
        assert_ne!(
            RecoverySite::translated_helper(8, 0),
            RecoverySite::translated_helper(8, 1)
        );
    }
}

#[test]
fn translated_descriptor_fields_and_zero_instruction_count_survive_span_copy() {
    use crate::x86_64::asm::{Code, Gpr};
    for bytes in [1, 2, 4, 8, 16, 32, 64, 255] {
        for flags in 0..8 {
            let mut code = Code::new();
            code.asm().call_rm(Gpr::Rax);
            let at = code.checkpoint();
            code.asm().translated_helper_return(bytes, flags);
            let span = code.span_since(at);
            assert_eq!(span.instructions(), 0);
            assert_eq!(code.instructions(), 1);
            assert_eq!(&code[..], &[0xff, 0xd0, bytes, flags]);
            let access = code.sites()[0].site.translated_access().unwrap();
            assert_eq!(access.bytes(), bytes);
            assert_eq!(access.write(), flags & 1 != 0);
            assert_eq!(access.unprivileged(), flags & 2 != 0);
            assert_eq!(access.atomic(), flags & 4 != 0);
            let mut copy = Code::new();
            copy.append_span(&code, span);
            assert_eq!(&copy[..], &[bytes, flags]);
            assert_eq!(copy.instructions(), 0);
            assert_eq!((copy.sites()[0].start, copy.sites()[0].end), (0, 1));
            assert_eq!(copy.sites()[0].site, code.sites()[0].site);
        }
    }
}

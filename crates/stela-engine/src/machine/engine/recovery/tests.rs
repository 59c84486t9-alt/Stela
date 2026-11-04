use super::super::Fetched;
use super::super::tests::{BASE, machine, make_pending};

#[test]
fn legacy_first_fault_qualification_is_cached_and_reports_dispatcher_cost() {
    let program = [0x91000400u32, 0xf9400043, 0xd4000001];
    let input: Vec<u8> = program.into_iter().flat_map(u32::to_le_bytes).collect();
    let mut machine = machine(&program);
    let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
        panic!("actual emission");
    };
    make_pending(&mut machine, index, &input);
    let mut owner = machine.fault_recovery.remove(&index).unwrap();
    let started = std::time::Instant::now();
    let first = owner.qualify(BASE, None).unwrap().rows();
    let cold = started.elapsed();
    assert!(
        first
            .iter()
            .any(|row| row.site.kind() == stela_compiler::block::RecoverySiteKind::GuestAccess)
    );
    let started = std::time::Instant::now();
    for _ in 0..32 {
        assert_eq!(owner.qualify(BASE, None).unwrap().rows(), first);
    }
    let cached = started.elapsed();
    assert_eq!(
        owner.qualification_attempts, 1,
        "only the first actual fault re-emits the plan"
    );
    eprintln!(
        "dispatcher recovery qualification: source={} native={} cold_ns={} cached_average_ns={} (current host; no native guest entered)",
        input.len(),
        owner.code_bytes(),
        cold.as_nanos(),
        cached.as_nanos() / 32
    );
}

use super::super::{Prepared, prepare};
use super::{Emission, Template};
use alloc::{sync::Arc, vec::Vec};
use stela_compiler::block::{FaultRecovery, RecoveryBinding, UnqualifiedFaultRecovery};

fn store_window() -> (
    Arc<super::Preparation>,
    Vec<u8>,
    stela_compiler::block::CompiledBlock,
) {
    let preparation = Arc::new(prepare::test_preparation());
    let source: Vec<u8> = [0xf900_0041u32; 256]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let Prepared::Block {
        compiled, input, ..
    } = preparation.prepare(&source, BASE, source.len()).unwrap()
    else {
        panic!("actual store-window compilation");
    };
    assert_eq!(input, source.len());
    assert!(!compiled.fault_recovery.is_empty());
    (preparation, source, compiled)
}

#[test]
fn a_compiled_owner_keeps_only_its_packed_rows() {
    let (preparation, source, compiled) = store_window();
    let expected = compiled.fault_recovery.clone();
    let unpacked = expected.len() * core::mem::size_of::<FaultRecovery>()
        + expected
            .iter()
            .map(|row| row.bindings.len() * core::mem::size_of::<RecoveryBinding>())
            .sum::<usize>();
    let native_bytes = compiled.native.x86_64_code.len();
    let mut owner =
        Template::compiled(Arc::new(Emission::new(source, compiled, preparation))).installed();
    assert_eq!(
        owner.code_bytes(),
        native_bytes,
        "the code's image, not a copy"
    );
    assert_eq!(owner.qualify(BASE, None).unwrap().rows(), expected);
    assert!(
        owner.test_packed_bytes() * 3 < unpacked,
        "{} packed bytes of {unpacked}",
        owner.test_packed_bytes()
    );
}

#[test]
fn exact_lazy_qualification_replaces_portable_bank_with_only_minted_rows() {
    let (preparation, source, compiled) = store_window();
    let expected = compiled.fault_recovery.clone();
    let code_bytes = compiled.native.x86_64_code.len();
    let template = crate::translations::StoredBlock {
        native: compiled.native,
        source_bytes: compiled.source_bytes,
        direct_exits: compiled.direct_exits,
        fault_recovery: compiled
            .fault_recovery
            .iter()
            .map(UnqualifiedFaultRecovery::from)
            .collect(),
    };
    let mut owner = Template::stored(template, source, preparation, None).installed();
    assert_eq!(owner.code_bytes(), code_bytes);
    assert_eq!(owner.qualify(BASE, None).unwrap().rows(), expected);
    assert_eq!(owner.code_bytes(), code_bytes);
    assert_eq!(owner.qualification_attempts, 1);
    assert_eq!(owner.qualify(BASE, None).unwrap().rows(), expected);
    assert_eq!(owner.qualification_attempts, 1);
}

#[test]
fn fault_rows_survive_packing() {
    let program = [0x9100_0400u32, 0xf900_0020, 0xf940_0043, 0x9100_0c64].repeat(64);
    let mut description = prepare::test_preparation().description();
    description.checks = stela_compiler::x86_64::MemoryChecks::system(true, false, true, false);
    let preparation = Arc::new(super::Preparation::from_description(&description).unwrap());
    let source: Vec<u8> = program.into_iter().flat_map(u32::to_le_bytes).collect();
    let Prepared::Block {
        compiled, input, ..
    } = preparation.prepare(&source, BASE, source.len()).unwrap()
    else {
        panic!("actual load compilation");
    };
    assert_eq!(input, source.len());
    assert!(!compiled.fault_recovery.is_empty());
    let expected = compiled.fault_recovery.clone();
    let mut owner =
        Template::compiled(Arc::new(Emission::new(source, compiled, preparation))).installed();
    assert_eq!(owner.qualify(BASE, None).unwrap().rows(), expected);
}

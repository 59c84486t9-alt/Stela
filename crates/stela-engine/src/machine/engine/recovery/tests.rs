use super::super::Fetched;
use super::super::tests::{BASE, machine};

#[test]
fn legacy_first_fault_qualification_is_cached_and_reports_dispatcher_cost() {
    let mut machine = machine(&[0x91000400, 0xf9400043, 0xd4000001]);
    let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
        panic!("actual emission");
    };
    let mut owner = machine.fault_recovery.remove(&index).unwrap();
    owner.test_make_pending();
    let started = std::time::Instant::now();
    let first = owner.qualify(BASE).unwrap().to_vec();
    let cold = started.elapsed();
    assert!(
        first
            .iter()
            .any(|row| row.site.kind() == stela_compiler::block::RecoverySiteKind::GuestAccess)
    );
    let started = std::time::Instant::now();
    for _ in 0..32 {
        assert_eq!(owner.qualify(BASE).unwrap(), first);
    }
    let cached = started.elapsed();
    assert_eq!(
        owner.qualification_attempts, 1,
        "only the first actual fault re-emits the plan"
    );
    eprintln!(
        "dispatcher recovery qualification: source={} native={} cold_ns={} cached_average_ns={} (current host; no native guest entered)",
        owner.emission.input.len(),
        owner.native().x86_64_code.len(),
        cold.as_nanos(),
        cached.as_nanos() / 32
    );
}

use super::super::{Prepared, prepare};
use super::{CodeRecovery, Emission};
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
fn compiled_owner_moves_one_compact_minted_row_bank_without_binding_copies() {
    let (preparation, source, compiled) = store_window();
    let rows = compiled.fault_recovery.len();
    let capacity = compiled.fault_recovery.capacity();
    let binding_pointers: Vec<_> = compiled
        .fault_recovery
        .iter()
        .map(|row| row.bindings.as_ptr())
        .collect();
    let binding_bytes: usize = compiled
        .fault_recovery
        .iter()
        .map(|row| row.bindings.capacity() * core::mem::size_of::<RecoveryBinding>())
        .sum();
    let portable: Vec<_> = compiled
        .fault_recovery
        .iter()
        .map(UnqualifiedFaultRecovery::from)
        .collect();
    let portable_binding_bytes: usize = portable
        .iter()
        .map(|row| row.bindings.capacity() * core::mem::size_of::<RecoveryBinding>())
        .sum();
    let portable_bytes = portable.capacity() * core::mem::size_of::<UnqualifiedFaultRecovery>()
        + portable_binding_bytes;
    drop(portable);
    let native_pointer = compiled.native.x86_64_code.as_ptr();
    let map_pointer = compiled.native.source_map.as_ptr();
    let native_bytes = compiled.native.x86_64_code.len();
    let owner = CodeRecovery::compiled(Arc::new(Emission::new(source, compiled, preparation)));
    assert!(owner.pending.is_none(), "actual compiler-minted bank");
    let bank = &owner.emission.block.fault_recovery;
    assert_eq!(bank.len(), rows);
    assert_eq!(owner.native().x86_64_code.as_ptr(), native_pointer);
    assert_eq!(owner.native().source_map.as_ptr(), map_pointer);
    for (row, pointer) in bank.iter().zip(binding_pointers) {
        assert_eq!(row.bindings.as_ptr(), pointer);
    }
    let old_row_bytes =
        capacity * core::mem::size_of::<FaultRecovery>() + binding_bytes + portable_bytes;
    assert_eq!(bank.capacity(), bank.len());
    let retained_row_bytes = core::mem::size_of_val(bank.as_slice()) + binding_bytes;
    assert!(
        retained_row_bytes < old_row_bytes,
        "one exact-length bank replaces duplicate portable and capacity storage"
    );
    eprintln!(
        "recovery retained requested layout: native={native_bytes} rows={rows} old_row_capacity={capacity} old_row_bytes={old_row_bytes} retained_row_bytes={retained_row_bytes} (Vec/Box payload only; allocator headers, size classes and CPU caches excluded)"
    );
}

#[test]
fn exact_lazy_qualification_replaces_portable_bank_with_only_minted_rows() {
    let (preparation, source, compiled) = store_window();
    let expected = compiled.fault_recovery.clone();
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
    let mut owner = CodeRecovery::stored(template, source, preparation);
    assert!(owner.pending.is_some());
    assert_eq!(owner.qualify(BASE).unwrap(), expected);
    assert!(owner.pending.is_none());
    assert_eq!(owner.qualification_attempts, 1);
    assert_eq!(owner.qualify(BASE).unwrap(), expected);
    assert_eq!(owner.qualification_attempts, 1);
}

#[test]
fn dirty_guest_binding_buffers_move_with_the_compact_minted_bank() {
    // The complete system-mode region keeps dirty values across its stores
    // and loads; a short fallback can commit every value before the load.
    let program = [0x9100_0400u32, 0xf900_0020, 0xf940_0043, 0x9100_0c64].repeat(64);
    let mut description = prepare::test_preparation().description();
    description.checks = stela_compiler::x86_64::MemoryChecks::system(true, false, true, false);
    let preparation = Arc::new(super::Preparation::from_description(&description).unwrap());
    let source: Vec<u8> = program.into_iter().flat_map(u32::to_le_bytes).collect();
    let Prepared::Block {
        compiled, input, ..
    } = preparation.prepare(&source, BASE, source.len()).unwrap()
    else {
        panic!("actual dirty-register load compilation");
    };
    assert_eq!(input, source.len());
    assert!(
        compiled
            .fault_recovery
            .iter()
            .any(|row| !row.bindings.is_empty())
    );
    let pointers: Vec<_> = compiled
        .fault_recovery
        .iter()
        .map(|row| row.bindings.as_ptr())
        .collect();
    let expected = compiled.fault_recovery.clone();
    let owner = CodeRecovery::compiled(Arc::new(Emission::new(source, compiled, preparation)));
    assert!(owner.pending.is_none(), "minted bank");
    let rows = &owner.emission.block.fault_recovery;
    assert_eq!(rows, &expected);
    for (row, pointer) in rows.iter().zip(pointers) {
        assert_eq!(row.bindings.as_ptr(), pointer);
    }
}

//! Run original register-only fixtures through first-use native translation.
use anyhow::{Result, ensure};
use stela_compiler::{GuestAddress, GuestState};
use stela_runtime::{dispatch::LeafDispatcher, execution::ExecutableLeaf};

fn source(value: u32) -> Vec<u8> {
    [0xd2800000u32 | (value << 5), 0xd65f03c0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect()
}

fn main() -> Result<()> {
    let cache = std::path::PathBuf::from(".stela/cache/leaf-v1");
    let mut dispatcher = LeafDispatcher::new(1, cache);
    let entry = GuestAddress(0x100000);
    dispatcher.register(entry, source(42))?;
    let first = dispatcher.resolve(entry)?;
    let executable = ExecutableLeaf::load(&dispatcher, &first)?;
    let mut state = GuestState::default();
    // SAFETY: These original finite MOV/RET fixtures perform no memory accesses.
    unsafe { executable.execute(&dispatcher, &mut state)? };
    ensure!(state.x[0] == 42, "first native execution result differs");
    dispatcher.register(entry, source(43))?;
    let rejected = unsafe { executable.execute(&dispatcher, &mut state) }.is_err();
    ensure!(
        rejected && state.x[0] == 42,
        "stale translation was executed"
    );
    let replacement = dispatcher.resolve(entry)?;
    let updated = ExecutableLeaf::load(&dispatcher, &replacement)?;
    unsafe { updated.execute(&dispatcher, &mut state)? };
    ensure!(
        state.x[0] == 43,
        "replacement native execution result differs"
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "kind": "bounded_first_use_native_leaf_execution",
            "first_result": 42,
            "replacement_result": state.x[0],
            "first_cache_hit": first.prepared().cache_hit,
            "stale_execution_rejected": rejected,
            "compiler_source_sha256": first.identity().translation.compiler_source_sha256,
            "limits": "Original MOV/RET fixtures only; no arbitrary runtime dispatch, OS loading or guest fault delivery."
        }))?
    );
    Ok(())
}

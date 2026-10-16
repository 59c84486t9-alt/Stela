use super::*;
use crate::memory::{MemoryRegionSpec, host_page_size};

fn word(plan: &KernelArgsPlan, address: u64) -> u64 {
    let offset = (address - plan.payload_address) as usize;
    u64::from_le_bytes(plan.initial_bytes[offset..offset + 8].try_into().unwrap())
}
#[test]
fn explicit_json_arguments_default_missing_arrays_and_decline_unknown_fields() -> Result<()> {
    let args: ProcessArguments = serde_json::from_str(r#"{"argv":[[255,65]]}"#)?;
    assert_eq!(args.argv, [vec![255, 65]]);
    assert!(args.environment.is_empty() && args.apple.is_empty());
    assert_eq!(
        serde_json::from_str::<ProcessArguments>("{}")?,
        ProcessArguments::default()
    );
    assert!(serde_json::from_str::<ProcessArguments>(r#"{"env":[[65]]}"#).is_err());
    assert!(serde_json::from_str::<ProcessArguments>(r#"{"argv":[[256]]}"#).is_err());
    Ok(())
}
fn string(plan: &KernelArgsPlan, address: u64) -> &[u8] {
    let offset = (address - plan.payload_address) as usize;
    let bytes = &plan.initial_bytes[offset..];
    &bytes[..bytes.iter().position(|b| *b == 0).unwrap()]
}
#[test]
fn complete_guest_pointer_tables_preserve_bytes_and_path_first() -> Result<()> {
    let args = ProcessArguments {
        argv: vec![b"different-argv0".to_vec(), vec![0xff, 0xfe], vec![]],
        environment: vec![b"A=B".to_vec()],
        apple: vec![b"custom=value".to_vec()],
    };
    let p = plan_kernel_args(
        0x90000000000,
        0x10000,
        0x40000000000,
        b"/app/bin/main",
        &args,
    )?;
    assert_eq!(word(&p, p.raw_sp), 0x40000000000);
    assert_eq!(word(&p, p.argc_address), 3);
    assert_eq!(p.raw_sp % 16, 8);
    assert_eq!(p.aligned_sp % 16, 0);
    assert_eq!(p.argc_address, p.raw_sp + 8);
    assert_eq!(
        p.initial_bytes.len() as u64 + p.payload_address,
        p.stack_base + p.stack_bytes
    );
    for (start, expected) in [
        (p.argv_address, args.argv.as_slice()),
        (p.envp_address, args.environment.as_slice()),
    ] {
        for (i, bytes) in expected.iter().enumerate() {
            assert_eq!(string(&p, word(&p, start + i as u64 * 8)), bytes);
        }
        assert_eq!(word(&p, start + expected.len() as u64 * 8), 0);
    }
    assert_eq!(string(&p, word(&p, p.apple_address)), b"/app/bin/main");
    assert_eq!(string(&p, word(&p, p.apple_address + 8)), b"custom=value");
    assert_eq!(word(&p, p.apple_address + 16), 0);
    for span in &p.strings {
        assert_eq!(string(&p, span.address).len(), span.bytes);
    }
    Ok(())
}
#[test]
fn zero_arguments_and_unaligned_stack_top_have_explicit_null_arrays() -> Result<()> {
    for bytes in [4096, 4097, 4103, 4111] {
        let p = plan_kernel_args(0x100000, bytes, 0, b"x", &ProcessArguments::default())?;
        assert_eq!(p.argc, 0);
        assert_eq!(word(&p, p.argv_address), 0);
        assert_eq!(word(&p, p.envp_address), 0);
        assert_eq!(string(&p, word(&p, p.apple_address)), b"x");
        assert_eq!(word(&p, p.apple_address + 8), 0);
        assert_eq!(p.raw_sp % 16, 8);
        assert!(p.aligned_sp >= p.stack_base + MIN_WORKING_STACK_BYTES);
    }
    Ok(())
}
#[test]
fn nul_empty_path_overflow_small_stack_and_resource_limits_decline() {
    let empty = ProcessArguments::default();
    for (base, bytes, path) in [
        (u64::MAX - 5, 6, b"x".as_slice()),
        (0, 32, b"x"),
        (0, 4096, b""),
        (0, 4096, b"x\0y"),
    ] {
        assert!(plan_kernel_args(base, bytes, 0, path, &empty).is_err());
    }
    for kind in 0..3 {
        let mut args = ProcessArguments::default();
        [&mut args.argv, &mut args.environment, &mut args.apple][kind]
            .push(b"bad\0string".to_vec());
        assert!(plan_kernel_args(0, 0x10000, 0, b"x", &args).is_err());
    }
    let args = ProcessArguments {
        argv: vec![vec![]; MAX_ARGUMENT_STRINGS],
        ..Default::default()
    };
    assert!(plan_kernel_args(0, 0x1000000, 0, b"x", &args).is_err());
    let args = ProcessArguments {
        argv: vec![vec![1; MAX_ARGUMENT_STRING_BYTES + 1]],
        ..Default::default()
    };
    assert!(plan_kernel_args(0, 0x1000000, 0, b"x", &args).is_err());
    let args = ProcessArguments {
        argv: vec![vec![1; MAX_ARGUMENT_STRING_BYTES]; 16],
        ..Default::default()
    };
    assert!(plan_kernel_args(0, 0x1000000, 0, b"x", &args).is_err());
}
fn memory(readonly_last: bool) -> OwnedMemory {
    let page = host_page_size().unwrap();
    for _ in 0..32 {
        // SAFETY: temporary anonymous ownership, immediately released before
        // asking OwnedMemory for its independently checked exact-address map.
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page * 3,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(pointer, libc::MAP_FAILED);
        let base = pointer as usize as u64;
        assert_eq!(unsafe { libc::munmap(pointer, page * 3) }, 0);
        let specs = (0..3)
            .map(|i| MemoryRegionSpec {
                guest_address: base + (i * page) as u64,
                virtual_bytes: page as u64,
                initial_bytes: vec![0xa5; page],
                readable: true,
                writable: !(readonly_last && i == 2),
                executable: false,
            })
            .collect();
        if let Ok(memory) = OwnedMemory::map(specs) {
            return memory;
        }
    }
    panic!("could not allocate test stack");
}
#[test]
fn installation_writes_only_payload_and_preserves_disjoint_memory() -> Result<()> {
    let mut memory = memory(false);
    let page = host_page_size()? as u64;
    let base = memory.regions()[0].guest_address;
    let p = plan_kernel_args(
        base + page,
        page * 2,
        0x40000000000,
        b"/main",
        &ProcessArguments::default(),
    )?;
    p.install(&mut memory)?;
    assert_eq!(
        memory.read_snapshot(p.payload_address, p.initial_bytes.len())?,
        p.initial_bytes
    );
    assert_eq!(
        memory.read_snapshot(base, (p.payload_address - base) as usize)?,
        vec![0xa5; (p.payload_address - base) as usize]
    );
    Ok(())
}
#[test]
fn failed_installation_is_atomic_across_permissions_and_forged_span() -> Result<()> {
    let mut memory = memory(true);
    let page = host_page_size()? as u64;
    let base = memory.regions()[0].guest_address;
    let before = memory.read_snapshot(base, (page * 3) as usize)?;
    let args = ProcessArguments {
        argv: vec![vec![1; page as usize + 32]],
        ..Default::default()
    };
    let p = plan_kernel_args(base + page, page * 2, 0, b"x", &args)?;
    assert!(p.payload_address < base + page * 2);
    assert!(p.install(&mut memory).is_err());
    assert_eq!(memory.read_snapshot(base, before.len())?, before);
    let mut p = plan_kernel_args(base, page, 0, b"x", &ProcessArguments::default())?;
    p.payload_address = base - 1;
    assert!(p.install(&mut memory).is_err());
    assert_eq!(memory.read_snapshot(base, before.len())?, before);
    Ok(())
}

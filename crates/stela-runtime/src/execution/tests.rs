use super::*;
use stela_compiler::GuestAddress;

fn source(value: u32) -> Vec<u8> {
    [0xd2800000u32 | (value << 5), 0xd65f03c0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect()
}

#[test]
fn executes_first_resolved_native_leaf_and_rejects_replaced_or_removed_handles() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut dispatcher = LeafDispatcher::new(1, cache.path().into());
    let entry = GuestAddress(0x1000);
    dispatcher.register(entry, source(42))?;
    let first = dispatcher.resolve(entry)?;
    let executable = ExecutableLeaf::load(&dispatcher, &first)?;
    assert_eq!(
        executable.native_bytes(),
        first.prepared().manifest.native_bytes
    );
    assert_eq!(executable.resolved().identity(), first.identity());
    let mut state = GuestState::default();
    // SAFETY: register-only MOV/RET with no guest memory.
    unsafe { executable.execute(&dispatcher, &mut state)? };
    assert_eq!(state.x[0], 42);
    dispatcher.register(entry, source(43))?;
    assert!(ExecutableLeaf::load(&dispatcher, &first).is_err());
    state.x[0] = 777;
    assert!(unsafe { executable.execute(&dispatcher, &mut state) }.is_err());
    assert_eq!(state.x[0], 777);
    let replacement = ExecutableLeaf::load(&dispatcher, &dispatcher.resolve(entry)?)?;
    unsafe { replacement.execute(&dispatcher, &mut state)? };
    assert_eq!(state.x[0], 43);
    assert!(dispatcher.unregister(entry));
    state.x[0] = 888;
    assert!(unsafe { replacement.execute(&dispatcher, &mut state) }.is_err());
    assert_eq!(state.x[0], 888);
    dispatcher.register(entry, source(42))?;
    assert!(unsafe { executable.execute(&dispatcher, &mut state) }.is_err());
    let reloaded = ExecutableLeaf::load(&dispatcher, &dispatcher.resolve(entry)?)?;
    unsafe { reloaded.execute(&dispatcher, &mut state)? };
    assert_eq!(state.x[0], 42);
    Ok(())
}

#[test]
fn rejects_foreign_registry_and_changed_disk_bytes_but_owns_loaded_snapshot() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut dispatcher = LeafDispatcher::new(1, cache.path().into());
    let mut other = LeafDispatcher::new(1, cache.path().into());
    let entry = GuestAddress(0x1000);
    dispatcher.register(entry, source(42))?;
    other.register(entry, source(42))?;
    let resolved = dispatcher.resolve(entry)?;
    let executable = ExecutableLeaf::load(&dispatcher, &resolved)?;
    assert!(ExecutableLeaf::load(&other, &resolved).is_err());
    let mut state = GuestState::default();
    assert!(unsafe { executable.execute(&other, &mut state) }.is_err());
    std::fs::write(resolved.prepared().directory.join("native.bin"), b"corrupt")?;
    assert!(ExecutableLeaf::load(&dispatcher, &resolved).is_err());
    // Own RX bytes are independent of the now-corrupt disk artifact.
    unsafe { executable.execute(&dispatcher, &mut state)? };
    assert_eq!(state.x[0], 42);
    Ok(())
}

#[test]
fn registered_direct_ram_leaf_writes_owned_memory_without_state_aliasing() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut dispatcher = LeafDispatcher::new(1, cache.path().into());
    let entry = GuestAddress(0x2000);
    // STR X1,[X0]; LDR X2,[X0]; RET. Compiler semantics have their own
    // ARM-vs-native differential suite; this checks executor integration.
    let source = [0xf9000001u32, 0xf9400002, 0xd65f03c0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    dispatcher.register(entry, source)?;
    let executable = ExecutableLeaf::load(&dispatcher, &dispatcher.resolve(entry)?)?;
    let mut ram = vec![0u64; 2];
    let mut state = GuestState::default();
    state.x[0] = ram.as_mut_ptr() as u64;
    state.x[1] = 0xfedc_ba98_7654_3210;
    state.nzcv = 0xa000_0000;
    // SAFETY: the code makes one aligned in-bounds store and load to separately
    // owned RAM. No Rust reference to that RAM is held during the call, and it
    // aliases neither the state nor the mapping.
    unsafe { executable.execute(&dispatcher, &mut state)? };
    assert_eq!(ram, [0xfedc_ba98_7654_3210, 0]);
    assert_eq!(state.x[2], state.x[1]);
    assert_eq!(state.nzcv, 0xa000_0000);
    Ok(())
}

#[test]
fn unsupported_source_never_becomes_an_executable_object() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut dispatcher = LeafDispatcher::new(1, cache.path().into());
    dispatcher.register(GuestAddress(0x1000), vec![0, 0, 0, 0])?;
    assert!(dispatcher.resolve(GuestAddress(0x1000)).is_err());
    assert_eq!(std::fs::read_dir(cache.path())?.count(), 0);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn linux_mapping_is_read_execute_and_not_write() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut dispatcher = LeafDispatcher::new(1, cache.path().into());
    let entry = GuestAddress(0x1000);
    dispatcher.register(entry, source(42))?;
    let executable = ExecutableLeaf::load(&dispatcher, &dispatcher.resolve(entry)?)?;
    let address = executable.mapping.address();
    let maps = std::fs::read_to_string("/proc/self/maps")?;
    let permissions = maps.lines().find_map(|line| {
        let mut columns = line.split_whitespace();
        let (low, high) = columns.next()?.split_once('-')?;
        let low = usize::from_str_radix(low, 16).ok()?;
        let high = usize::from_str_radix(high, 16).ok()?;
        (low <= address && address < high).then(|| columns.next().unwrap().to_owned())
    });
    assert_eq!(permissions.as_deref(), Some("r-xp"));
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn macos_mapping_is_read_execute_and_not_write() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut dispatcher = LeafDispatcher::new(1, cache.path().into());
    let entry = GuestAddress(0x1000);
    dispatcher.register(entry, source(42))?;
    let executable = ExecutableLeaf::load(&dispatcher, &dispatcher.resolve(entry)?)?;
    let mut address = executable.mapping.address() as u64;
    let mut size = 0u64;
    // Installed Darwin SDK mach/vm_region.h: BASIC_INFO_64 flavor 9,
    // 4-byte packed structure occupies nine integer_t words. Only the
    // first word (current protection) is needed; do not reinterpret u64
    // members through potentially misaligned Rust references.
    let mut info = [0i32; 9];
    let mut count = 9u32;
    unsafe extern "C" {
        static mach_task_self_: u32;
        fn mach_vm_region(
            task: u32,
            address: *mut u64,
            size: *mut u64,
            flavor: i32,
            info: *mut i32,
            count: *mut u32,
            object: *mut u32,
        ) -> i32;
        fn mach_port_deallocate(task: u32, name: u32) -> i32;
    }
    let mut object = 0u32;
    // SAFETY: Query the current process with initialized output buffers and
    // the documented VM_REGION_BASIC_INFO_64 flavor/count.
    let result = unsafe {
        mach_vm_region(
            mach_task_self_,
            &mut address,
            &mut size,
            9,
            info.as_mut_ptr(),
            &mut count,
            &mut object,
        )
    };
    if object != 0 {
        unsafe { mach_port_deallocate(mach_task_self_, object) };
    }
    assert_eq!(result, libc::KERN_SUCCESS);
    assert_eq!(info[0], libc::VM_PROT_READ | libc::VM_PROT_EXECUTE);
    assert!(address <= executable.mapping.address() as u64);
    assert!(
        executable.mapping.address() as u64 + executable.native_bytes() as u64 <= address + size
    );
    Ok(())
}

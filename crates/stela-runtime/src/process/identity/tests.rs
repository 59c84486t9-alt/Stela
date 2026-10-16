use super::*;

#[test]
fn normal_process_profile_rejects_kernel_and_unallocated_ids() {
    for pid in [0, MAX_PROCESS_ID + 1, u32::MAX] {
        assert!(Context::new(1, pid).is_err());
    }
    for pid in [1, MAX_PROCESS_ID] {
        let process = Context::new(1, pid).unwrap();
        assert_eq!(process.pid(), pid);
    }
}

#[test]
fn declared_process_identity_preserves_independent_address_space_binding() {
    for address_space in [0, 1, u64::MAX] {
        let process = Context::new(address_space, MAX_PROCESS_ID).unwrap();
        assert_eq!(process.address_space(), address_space);
        assert_eq!(
            process.snapshot(),
            Snapshot {
                profile_id: PROFILE_ID,
                address_space,
                process_id: MAX_PROCESS_ID,
            }
        );
    }
}

use super::*;

#[test]
fn thread_register_exit_requires_exact_consumed_source_descriptor() {
    const MRS_TPIDRRO_EL0: u32 = 0xd53bd060;
    const ADD_X0_X0_ONE: u32 = 0x91000400;
    let base = GuestAddress(0x1000);
    let terminal = GuestAddress(base.0 + INSTRUCTION_BYTES as u64);
    for destination in 0..32 {
        let source: Vec<_> = [ADD_X0_X0_ONE, MRS_TPIDRRO_EL0 | destination]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let instruction =
            validate_thread_register_exit(base, terminal, source.len(), base.0, &source).unwrap();
        assert_eq!(instruction.destination, destination as u8);
        for (returned, count, region) in [
            (base, 8, base.0),
            (terminal, 0, base.0),
            (terminal, 6, base.0),
            (GuestAddress(0x1008), 12, base.0),
            (terminal, 8, 0x2000),
        ] {
            assert!(validate_thread_register_exit(base, returned, count, region, &source).is_err());
        }
    }
    assert!(
        validate_thread_register_exit(base, base, 4, base.0, &ADD_X0_X0_ONE.to_le_bytes()).is_err()
    );
    assert!(
        validate_thread_register_exit(GuestAddress(u64::MAX - 3), GuestAddress(0), 8, 0, &[])
            .is_err()
    );
}

#[test]
fn clock_exit_requires_exact_consumed_source_descriptor() {
    let base = GuestAddress(0x1000);
    let terminal = GuestAddress(0x1004);
    for word in [0xd5033fdf_u32, 0xd53be049, 0xd53be05f] {
        let source: Vec<_> = [0x91000400u32, word]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        assert_eq!(
            validate_clock_exit(base, terminal, 8, base.0, &source).unwrap(),
            decode_clock_instruction(terminal, word).unwrap().unwrap()
        );
        for (returned, count, region) in [
            (base, 8, base.0),
            (terminal, 0, base.0),
            (terminal, 6, base.0),
            (GuestAddress(0x1008), 12, base.0),
            (terminal, 8, 0x2000),
        ] {
            assert!(validate_clock_exit(base, returned, count, region, &source).is_err());
        }
    }
    assert!(validate_clock_exit(base, base, 4, base.0, &0xd503237fu32.to_le_bytes()).is_err());
}

#[test]
fn pauth_exit_requires_the_exact_consumed_immutable_helper_instruction() {
    let base = GuestAddress(0x1000);
    let terminal = GuestAddress(0x1004);
    let source: Vec<_> = [0x91000400u32, 0xd503237f]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    assert_eq!(
        validate_pauth_exit(base, terminal, 8, base.0, &source).unwrap(),
        decode_pointer_authentication(terminal, 0xd503237f)
            .unwrap()
            .unwrap()
    );
    for (returned, bytes, region) in [
        (base, 8, base.0),
        (terminal, 0, base.0),
        (terminal, 6, base.0),
        (GuestAddress(0x1008), 12, base.0),
        (terminal, 8, 0x2000),
    ] {
        assert!(validate_pauth_exit(base, returned, bytes, region, &source).is_err());
    }
    assert!(validate_pauth_exit(base, base, 4, base.0, &source).is_err());
}

#[test]
fn trap_exit_requires_the_exact_consumed_immutable_terminator() {
    let base = GuestAddress(0x1000);
    let terminal = GuestAddress(0x1004);
    let source: Vec<_> = [0x91000400u32, 0xd4001001]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect(); // ADD; SVC #0x80
    assert_eq!(
        validate_trap_exit(base, terminal, 8, base.0, &source).unwrap(),
        decode_trap(terminal, 0xd4001001).unwrap().unwrap()
    );
    assert!(validate_trap_exit(base, base, 8, base.0, &source).is_err());
    assert!(validate_trap_exit(base, terminal, 0, base.0, &source).is_err());
    assert!(validate_trap_exit(base, terminal, 6, base.0, &source).is_err());
    assert!(validate_trap_exit(base, GuestAddress(0x1008), 12, base.0, &source).is_err());
    assert!(validate_trap_exit(base, terminal, 8, 0x2000, &source).is_err());
    let ordinary: Vec<_> = [0x91000400u32, 0xd65f03c0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    assert!(validate_trap_exit(base, terminal, 8, base.0, &ordinary).is_err());
}

use super::*;
use stela_compiler::aarch64::scalable::MAX_VECTOR_BYTES;

fn length(bytes: usize) -> VectorLength {
    VectorLength::from_bytes(bytes).expect("architectural vector length")
}

#[test]
fn controls_and_disabled_state_do_not_allocate() -> Result<()> {
    let mut state = ScalableState::new(length(32), true);
    let mut registers = GuestState::default();
    registers.v[3] = [7, 9];
    registers.fpsr = u32::MAX;
    state.set_tpidr2_el0(123);
    state.set_fpmr(456);
    state.apply_mode(&mut registers, ScalableMode::new(false, false))?;
    assert_eq!(registers.v[3], [7, 9]);
    assert_eq!(registers.fpsr, u32::MAX);
    assert_eq!(state.tpidr2_el0(), 123);
    assert_eq!(state.fpmr(), 456);
    assert!(state.vectors.is_none());
    assert!(state.matrices.is_none());
    Ok(())
}

#[test]
fn transitions_reset_exact_state_and_preserve_independent_matrix() -> Result<()> {
    let mut state = ScalableState::new(length(32), true);
    let mut registers = GuestState {
        fpcr: 123,
        nzcv: 0xa000_0000,
        ..GuestState::default()
    };
    state.set_tpidr2_el0(999);
    state.apply_mode(&mut registers, ScalableMode::new(true, true))?;
    state.write_z(&mut registers, 31, &[0x45; 32])?;
    state.write_predicate(15, &[0x67; 4])?;
    state.write_ffr(&[0x89; 4])?;
    state.write_za(1023, &[0xab])?;
    state.write_zt0(63, &[0xcd])?;
    state.set_fpmr(123);
    registers.fpsr = u32::MAX;
    state.apply_mode(&mut registers, ScalableMode::new(true, true))?;
    assert_eq!(registers.v[31], [0x4545_4545_4545_4545; 2]);
    assert_eq!(registers.fpsr, u32::MAX);
    assert_eq!(state.fpmr(), 123);
    state.apply_mode(&mut registers, ScalableMode::new(false, true))?;
    assert_eq!(registers.v, [[0; 2]; VECTOR_REGISTER_COUNT as usize]);
    assert!(
        state
            .vectors
            .as_ref()
            .unwrap()
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(registers.fpsr, STREAMING_RESET_FPSR);
    assert_eq!(state.fpmr(), 0);
    assert_eq!(state.tpidr2_el0(), 999);
    assert_eq!(registers.fpcr, 123);
    assert_eq!(registers.nzcv, 0xa000_0000);
    let mut byte = [0];
    state.read_za(1023, &mut byte)?;
    assert_eq!(byte, [0xab]);
    state.read_zt0(63, &mut byte)?;
    assert_eq!(byte, [0xcd]);
    state.apply_mode(&mut registers, ScalableMode::new(false, false))?;
    assert!(state.read_za(0, &mut byte).is_err());
    state.apply_mode(&mut registers, ScalableMode::new(false, true))?;
    state.read_za(1023, &mut byte)?;
    assert_eq!(byte, [0]);
    state.read_zt0(63, &mut byte)?;
    assert_eq!(byte, [0]);
    Ok(())
}

#[test]
fn all_lengths_preserve_low_alias_and_bound_every_register_bank() -> Result<()> {
    for bytes in (VECTOR_CHUNK_BYTES..=MAX_VECTOR_BYTES).filter(|bytes| bytes.is_power_of_two()) {
        let mut state = ScalableState::new(length(bytes), true);
        let mut registers = GuestState::default();
        state.apply_mode(&mut registers, ScalableMode::new(true, true))?;
        let input: Vec<u8> = (0..bytes).map(|byte| byte as u8).collect();
        let mut output = vec![0; bytes];
        state.write_z(&mut registers, 31, &input)?;
        registers.v[31][0] = u64::MAX;
        state.read_z(&registers, 31, &mut output)?;
        assert_eq!(&output[..8], &[0xff; 8]);
        assert_eq!(&output[8..], &input[8..]);
        state.write_v(&mut registers, 31, [3, 4])?;
        state.read_z(&registers, 31, &mut output)?;
        assert!(output[VECTOR_CHUNK_BYTES..].iter().all(|byte| *byte == 0));
        assert!(state.write_z(&mut registers, 32, &input).is_err());
        assert!(
            state
                .write_z(&mut registers, 0, &input[..bytes - 1])
                .is_err()
        );
        assert!(state.write_predicate(16, &vec![0; bytes / 8]).is_err());
        assert!(state.write_ffr(&vec![0; bytes / 8 + 1]).is_err());
        assert!(state.write_za(bytes * bytes, &[1]).is_err());
        assert!(state.write_za(usize::MAX, &[1]).is_err());
        assert!(state.write_zt0(64, &[1]).is_err());
    }
    Ok(())
}

#[test]
fn clone_and_scoped_view_keep_storage_independent_and_stable() -> Result<()> {
    let mut state = ScalableState::new(length(32), true);
    let mut registers = GuestState::default();
    state.apply_mode(&mut registers, ScalableMode::new(true, true))?;
    state.write_za(0, &[7])?;
    let mut cloned = state.clone();
    cloned.write_za(0, &[9])?;
    let mut byte = [0];
    state.read_za(0, &mut byte)?;
    assert_eq!(byte, [7]);
    // SAFETY: only live bounded storage is accessed, and no pointers escape.
    unsafe {
        state.with_view(|view| {
            assert_eq!(view.svl_bytes, 32);
            assert_eq!(view.svcr, 3);
            *view.z_upper = 0x12;
            *view.predicates = 0x34;
            *view.ffr = 0x56;
            *view.za = 0x78;
            *view.zt0 = 0x9a;
            view.tpidr2_el0 = 111;
            view.fpmr = 222;
        });
    }
    let mut z = [0; 32];
    state.read_z(&registers, 0, &mut z)?;
    assert_eq!(z[16], 0x12);
    let mut predicate = [0; 4];
    state.read_predicate(0, &mut predicate)?;
    assert_eq!(predicate[0], 0x34);
    state.read_ffr(&mut predicate)?;
    assert_eq!(predicate[0], 0x56);
    state.read_za(0, &mut byte)?;
    assert_eq!(byte, [0x78]);
    state.read_zt0(0, &mut byte)?;
    assert_eq!(byte, [0x9a]);
    assert_eq!(state.tpidr2_el0(), 111);
    assert_eq!(state.fpmr(), 222);
    let without_sme2 = ScalableState::new(length(16), false);
    assert!(without_sme2.read_zt0(0, &mut byte).is_err());
    Ok(())
}

#[test]
fn za_scratch_reuses_high_water_capacity_on_success_error_and_unwind() -> Result<()> {
    for bytes in (VECTOR_CHUNK_BYTES..=MAX_VECTOR_BYTES).filter(|bytes| bytes.is_power_of_two()) {
        let mut state = ScalableState::new(length(bytes), true);
        let mut registers = GuestState::default();
        state.apply_mode(&mut registers, ScalableMode::new(true, true))?;
        state.set_tpidr2_el0(123);
        state.set_fpmr(456);
        let original = state.clone();
        let rows = bytes;
        let pointer = state.with_za_row_scratch(rows, |_, scratch| -> Result<_> {
            assert_eq!(scratch.len(), rows * bytes);
            assert!(scratch.iter().all(|byte| *byte == 0));
            scratch.fill(0xa5);
            Ok(scratch.as_ptr() as usize)
        })?;
        let capacity = state.za_scratch.as_ref().unwrap().capacity();
        assert_eq!(state.za_scratch.as_ref().unwrap().len(), rows * bytes);
        let error: Result<()> = state.with_za_row_scratch(1, |_, scratch| {
            assert_eq!(scratch.as_ptr() as usize, pointer);
            assert_eq!(scratch.len(), bytes);
            assert!(scratch.iter().all(|byte| *byte == 0xa5));
            scratch.fill(0x5a);
            Err(anyhow::anyhow!("directed evaluation error"))
        });
        assert!(error.is_err());
        assert_eq!(state.za_scratch.as_ref().unwrap().capacity(), capacity);
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<()> = state.with_za_row_scratch(rows, |_, scratch| {
                assert_eq!(scratch.as_ptr() as usize, pointer);
                assert!(scratch[..bytes].iter().all(|byte| *byte == 0x5a));
                assert!(scratch[bytes..].iter().all(|byte| *byte == 0xa5));
                panic!("directed evaluation unwind");
            });
        }));
        assert!(unwind.is_err());
        assert_eq!(state.za_scratch.as_ref().unwrap().capacity(), capacity);
        assert_eq!(state.vectors, original.vectors);
        assert_eq!(state.matrices, original.matrices);
        assert_eq!(state.mode, original.mode);
        assert_eq!(state.tpidr2_el0(), original.tpidr2_el0());
        assert_eq!(state.fpmr(), original.fpmr());
    }
    Ok(())
}

#[test]
fn za_scratch_bounds_reentrancy_and_clone_are_independent() -> Result<()> {
    let mut state = ScalableState::new(length(32), true);
    let maximum_rows = state.vector_length().bytes();
    for invalid in [0, maximum_rows + 1, usize::MAX] {
        let result: Result<()> =
            state.with_za_row_scratch(invalid, |_, _| panic!("invalid loan entered callback"));
        assert!(result.is_err());
        assert_eq!(state.za_scratch.as_ref().unwrap().capacity(), 0);
    }
    state.with_za_row_scratch(maximum_rows, |owner, scratch| -> Result<()> {
        let nested: Result<()> =
            owner.with_za_row_scratch(1, |_, _| panic!("nested loan entered callback"));
        assert!(nested.is_err());
        let mut cloned = owner.clone();
        assert_eq!(cloned.za_scratch.as_ref().unwrap().capacity(), 0);
        cloned.with_za_row_scratch(1, |_, independent| -> Result<()> {
            assert_ne!(scratch.as_ptr(), independent.as_ptr());
            independent.fill(0x5a);
            Ok(())
        })?;
        assert!(scratch.iter().all(|byte| *byte == 0));
        Ok(())
    })?;
    assert!(state.za_scratch.is_some());
    Ok(())
}

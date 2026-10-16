use super::*;

fn wide(
    kind: WideMove,
    width: Width,
    destination: Register,
    immediate: u16,
    shift: u8,
) -> Operation {
    Operation::MoveWide {
        kind,
        width,
        destination,
        immediate,
        shift,
    }
}

#[test]
fn known_wide_moves_keep_each_intermediate_value_and_width_effect() {
    let mut facts = ConstantRegisters::default();
    let destination = Register::X(12);
    let operations = [
        wide(WideMove::Not, Width::X64, destination, 0x1234, 32),
        wide(WideMove::Keep, Width::W32, destination, 0x89ab, 16),
        wide(WideMove::Keep, Width::X64, destination, 0xcdef, 48),
    ];
    let expected = [0xffff_edcb_ffff_ffff, 0x89ab_ffff, 0xcdef_0000_89ab_ffff];
    for (operation, value) in operations.iter().zip(expected) {
        assert_eq!(
            facts.step(operation),
            Some(ConstantWrite { destination, value })
        );
    }
}

#[test]
fn independent_interior_entry_does_not_inherit_a_predecessor_constant() {
    let mut facts = ConstantRegisters::default();
    assert_eq!(
        facts.step(&wide(WideMove::Keep, Width::X64, Register::X(0), 7, 16)),
        None
    );
    assert_eq!(facts.read(Register::X(0)), None);
}

#[test]
fn pc_relative_address_then_add_can_alias_or_write_sp_and_wrap() {
    for destination in [Register::X(0), Register::Sp] {
        let mut facts = ConstantRegisters::default();
        let source = Register::X(0);
        facts.step(&Operation::PcRelative(
            crate::aarch64::pc_relative::Operand {
                destination: source,
                address: u64::MAX - 15,
            },
        ));
        assert_eq!(
            facts.step(&Operation::AddSub {
                width: Width::X64,
                subtract: false,
                flags: false,
                destination,
                source,
                immediate: 32,
            }),
            Some(ConstantWrite {
                destination,
                value: 16
            })
        );
    }
}

#[test]
fn flags_and_unknown_operations_erase_facts_instead_of_dropping_effects() {
    let mut facts = ConstantRegisters::default();
    facts.step(&wide(WideMove::Zero, Width::X64, Register::X(0), 7, 0));
    assert_eq!(
        facts.step(&Operation::AddSub {
            width: Width::X64,
            subtract: false,
            flags: true,
            destination: Register::X(0),
            source: Register::X(0),
            immediate: 1,
        }),
        None
    );
    assert_eq!(facts.read(Register::X(0)), None);
}

#[test]
fn zero_register_never_acquires_a_fact() {
    let mut facts = ConstantRegisters::default();
    assert_eq!(
        facts.step(&wide(WideMove::Not, Width::X64, Register::Zero, 0, 0)),
        None
    );
    assert_eq!(facts.read(Register::Zero), Some(0));
}

use super::*;
use alloc::vec;

fn madt(entries: &[&[u8]]) -> Vec<u8> {
    let mut table = vec![0; MADT_HEADER];
    for entry in entries {
        table.extend_from_slice(entry);
    }
    let length = table.len() as u32;
    table[4..8].copy_from_slice(&length.to_le_bytes());
    table
}

#[test]
fn madt_maps_processor_ids_and_device_uids_to_enabled_apics() {
    let table = madt(&[
        // Processor Local APIC: ID 1 -> APIC 2, enabled; ID 3 disabled.
        &[0, 8, 1, 2, 1, 0, 0, 0],
        &[0, 8, 3, 6, 0, 0, 0, 0],
        // x2APIC 0x100, enabled, UID 9.
        &[9, 16, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0],
    ]);
    assert_eq!(apic_id(&table, 1, false), Some(2));
    assert_eq!(apic_id(&table, 1, true), Some(2));
    assert_eq!(apic_id(&table, 3, false), None);
    assert_eq!(apic_id(&table, 9, true), Some(0x100));
    // x2APIC entries name device declarations only.
    assert_eq!(apic_id(&table, 9, false), None);
    let truncated = madt(&[&[0, 8, 1, 2, 1, 0, 0, 0], &[0, 9, 4]]);
    assert_eq!(apic_id(&truncated, 4, false), None);
}

fn register(space: u8, class: u8, access: u8, address: u64) -> Value<'static> {
    let mut bytes = vec![0x82, 0x0c, 0, space, 1, class, access];
    bytes.extend_from_slice(&address.to_le_bytes());
    bytes.extend_from_slice(&[0x79, 0]);
    Value::Buffer(bytes)
}

fn state(register: Value<'static>, kind: u64, latency: u64) -> Value<'static> {
    Value::Package(vec![
        register,
        Value::Integer(kind),
        Value::Integer(latency),
        Value::Integer(1000),
    ])
}

fn declared(kind: u64, latency: u64, class: u8, access: u8, hint: u64) -> CState {
    CState {
        kind,
        latency_us: latency,
        power_mw: 0,
        entry: Entry::FixedHardware {
            address: hint,
            vendor: 1,
            class,
            access_size: access,
        },
    }
}

const SKYLAKE: Cpu = Cpu {
    mwait_vendor: true,
    intel: true,
    // Extensions and interrupt break; C0..C4 substates.
    mwait: Some((3, 0x0011_1120)),
    always_running_timer: true,
    nonstop_tsc: true,
};

#[test]
fn admission_probes_hints_and_verifies_states_as_linux_does() {
    let cst = [
        declared(1, 1, 2, 1, 0x00),
        declared(2, 80, 2, 3, 0x10),
        // C3 whose GAS access size asks for the bus-master check.
        declared(3, 150, 2, 3, 0x20),
        // C3 that skips it; a substate the CPU lacks.
        declared(3, 150, 2, 1, 0x20),
        declared(3, 200, 2, 1, 0x60),
    ];
    let (admitted, refused) = admit(&cst, &SKYLAKE);
    let entered: Vec<_> = admitted
        .iter()
        .map(|state| (state.kind, state.enter, state.residency_us))
        .collect();
    assert_eq!(
        entered,
        [
            (1, Enter::Mwait(0x00), 2),
            (2, Enter::Mwait(0x10), 160),
            (3, Enter::Mwait(0x20), 300),
        ]
    );
    let reasons: Vec<_> = refused.iter().map(|(_, refusal)| *refusal).collect();
    assert_eq!(reasons, [Refusal::BusMasterCheck, Refusal::UnsupportedHint]);
    assert_eq!(select(&admitted, Some(200)).unwrap().kind, 2);
    assert_eq!(select(&admitted, Some(1)).unwrap().kind, 1);
    assert_eq!(select(&admitted, None).unwrap().kind, 3);
}

#[test]
fn without_mwait_c1_halts_and_deeper_states_stay_out() {
    let cpu = Cpu {
        mwait: None,
        ..SKYLAKE
    };
    let cst = [declared(1, 1, 2, 1, 0), declared(2, 80, 2, 3, 0x10)];
    let (admitted, refused) = admit(&cst, &cpu);
    assert_eq!(admitted[0].enter, Enter::Halt);
    assert_eq!(admitted.len(), 1);
    assert_eq!(refused[0].1, Refusal::UnsupportedHint);
    // A timer that stops, or a TSC that may, keeps C2 out.
    for (cpu, refusal) in [
        (
            Cpu {
                always_running_timer: false,
                ..SKYLAKE
            },
            Refusal::TimerStops,
        ),
        (
            Cpu {
                nonstop_tsc: false,
                ..SKYLAKE
            },
            Refusal::TscStops,
        ),
    ] {
        assert_eq!(admit(&cst, &cpu).1[0].1, refusal);
    }
    // No C1 declared: HLT stands in; system I/O entries are refused.
    let (admitted, refused) = admit(
        &[CState {
            kind: 2,
            latency_us: 50,
            power_mw: 0,
            entry: Entry::SystemIo(0x414),
        }],
        &SKYLAKE,
    );
    assert_eq!(admitted[0].enter, Enter::Halt);
    assert_eq!(refused[0].1, Refusal::IoPort);
    assert_eq!(
        admit(&[declared(2, 101, 2, 3, 0x10)], &SKYLAKE).1[0].1,
        Refusal::Latency
    );
}

#[test]
fn cst_keeps_well_formed_entries_as_linux_does() {
    let cst = Value::Package(vec![
        Value::Integer(4),
        state(register(FIXED_HARDWARE, 1, 1, 0), 1, 1),
        state(register(FIXED_HARDWARE, 2, 3, 0x21), 2, 70),
        // An address space neither fixed hardware nor system I/O is skipped.
        state(register(2, 0, 0, 0), 3, 100),
        state(register(SYSTEM_IO, 0, 0, 0x414), 3, 200),
    ]);
    assert_eq!(
        parse_cst(cst),
        Ok(vec![
            CState {
                kind: 1,
                latency_us: 1,
                power_mw: 1000,
                entry: Entry::FixedHardware {
                    address: 0,
                    vendor: 1,
                    class: 1,
                    access_size: 1
                }
            },
            CState {
                kind: 2,
                latency_us: 70,
                power_mw: 1000,
                entry: Entry::FixedHardware {
                    address: 0x21,
                    vendor: 1,
                    class: 2,
                    access_size: 3
                }
            },
            CState {
                kind: 3,
                latency_us: 200,
                power_mw: 1000,
                entry: Entry::SystemIo(0x414)
            },
        ])
    );
    let short = Value::Package(vec![
        Value::Integer(1),
        Value::Package(vec![Value::Integer(1)]),
    ]);
    assert_eq!(parse_cst(short), Ok(vec![]));
    assert_eq!(
        parse_cst(Value::Package(vec![
            Value::Integer(2),
            state(register(SYSTEM_IO, 0, 0, 1), 2, 1)
        ])),
        Err(CstError::Inconsistent)
    );
    assert_eq!(parse_cst(Value::Integer(1)), Err(CstError::Invalid));
}

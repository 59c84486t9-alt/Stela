use super::*;

fn associated() -> (Station, Arc<AssociationContext>) {
    let mut station = Station::new(LOCAL).unwrap();
    let join = modern_join();
    let Action::Configure {
        ticket,
        context: Some(context),
        ..
    } = configuration(&mut station, join.clone(), beacon(&join)).unwrap()
    else {
        panic!("actual modern context");
    };
    station
        .complete_configuration(ticket, Completion::Accepted, 3)
        .unwrap();
    (station, context)
}

#[test]
fn software_qos_sequences_are_independent_modulo_4096_inputs() {
    let (mut station, context) = associated();
    for tid in 0..16 {
        assert_eq!(station.next_qos_sequence(&context, tid), Ok(0));
        for value in 0..4096 {
            assert_eq!(station.allocate_qos_sequence(&context, tid), Ok(value));
        }
        assert_eq!(station.next_qos_sequence(&context, tid), Ok(0));
        assert_eq!(station.allocate_qos_sequence(&context, tid), Ok(0));
        assert_eq!(station.next_qos_sequence(&context, tid), Ok(1));
    }
    assert!(station.next_qos_sequence(&context, 16).is_err());
    assert!(station.allocate_qos_sequence(&context, 16).is_err());
}

#[test]
fn preview_does_not_consume_and_allocation_never_rolls_back_without_air_proof() {
    let (mut station, context) = associated();
    assert_eq!(station.next_qos_sequence(&context, 3), Ok(0));
    assert_eq!(station.next_qos_sequence(&context, 3), Ok(0));
    assert_eq!(station.allocate_qos_sequence(&context, 3), Ok(0));
    // A caller may discard a prepared plan; no TX status is fabricated here.
    assert_eq!(station.allocate_qos_sequence(&context, 3), Ok(1));
    assert_eq!(station.next_qos_sequence(&context, 3), Ok(2));
    assert_eq!(station.next_qos_sequence(&context, 4), Ok(0));
}

#[test]
fn stale_private_context_and_configuration_phase_cannot_consume_sequences() {
    let (mut station, old) = associated();
    let (_, unrelated) = associated();
    assert_eq!(
        station.allocate_qos_sequence(&unrelated, 0),
        Err(Error::Stale)
    );
    assert_eq!(station.next_qos_sequence(&old, 0), Ok(0));
    station.disconnect().unwrap();
    assert!(station.allocate_qos_sequence(&old, 0).is_err());
    assert!(station.next_qos_sequence(&old, 0).is_err());
    let mut station = Station::new(LOCAL).unwrap();
    let join = modern_join();
    let Action::Configure {
        context: Some(context),
        ..
    } = configuration(&mut station, join.clone(), beacon(&join)).unwrap()
    else {
        panic!("actual modern context");
    };
    assert_eq!(
        station.allocate_qos_sequence(&context, 0),
        Err(Error::NotAssociated)
    );
}

#[test]
fn software_next_inputs_match_complete_unchanged_linux_helper() {
    use sha2::{Digest, Sha256};
    let (mut station, context) = associated();
    let mut trace = Sha256::new();
    for tid in 0..16 {
        for _ in 0..8194 {
            let input = station.allocate_qos_sequence(&context, tid).unwrap() << 4;
            let next = station.next_qos_sequence(&context, tid).unwrap() << 4;
            trace.update(input.to_le_bytes());
            trace.update(next.to_le_bytes());
        }
    }
    let actual: [u8; 32] = trace.finalize().into();
    assert_eq!(
        actual,
        [
            0x18, 0x9e, 0x48, 0x56, 0x56, 0xe1, 0x1b, 0xf8, 0x72, 0xf6, 0x44, 0xef, 0x17, 0x43,
            0x4c, 0xa3, 0xec, 0xf2, 0x47, 0x6f, 0x44, 0xbe, 0xce, 0x2e, 0x6a, 0xc1, 0x1f, 0xe9,
            0xd1, 0x0a, 0x40, 0x5e
        ]
    );
}

#[test]
fn only_actual_accepted_removal_resets_retired_peer_software_counters() {
    for outcome in [Completion::Accepted, Completion::Uncertain] {
        let (mut station, context) = associated();
        assert_eq!(station.allocate_qos_sequence(&context, 3), Ok(0));
        let Action::Remove { ticket, .. } = station.disconnect().unwrap() else {
            panic!("actual removal");
        };
        assert_eq!(station.qos_sequence[3], 1);
        station.complete_removal(ticket, outcome).unwrap();
        assert_eq!(
            station.qos_sequence[3],
            if outcome == Completion::Accepted {
                0
            } else {
                1
            }
        );
        assert!(station.next_qos_sequence(&context, 3).is_err());
    }
}

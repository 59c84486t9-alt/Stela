use super::*;
use crate::input::Input;

// Numbered keyboard: modifier byte, reserved byte and six array usages.
const KEYBOARD: &[u8] = &[
    5, 1, 9, 6, 0xa1, 1, 0x85, 1, 5, 7, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0, 0x25, 1, 0x75, 1, 0x95, 8,
    0x81, 2, 0x95, 1, 0x75, 8, 0x81, 1, 0x95, 6, 0x75, 8, 0x25, 0x65, 0x19, 0, 0x29, 0x65, 0x81, 0,
    0xc0,
];

fn malformed_projection() -> Vec<u8> {
    // This is still a valid wire-length inventory, but its Usage Maximum has
    // no Usage Minimum. The projection's precise parser failure must survive.
    let mut descriptor = vec![0x29, 1];
    descriptor.extend_from_slice(KEYBOARD);
    assert!(descriptor::parse(&descriptor).is_ok());
    assert!(Translator::describe(&descriptor).is_err());
    descriptor
}

#[test]
fn valid_client_continues_with_exact_bad_client_and_nonlegacy_diagnostics() {
    let mut f = prepared();
    let malformed = malformed_projection();
    let expected = Translator::describe(&malformed).err().unwrap();
    {
        let mut data = f.peer.state.lock().unwrap();
        data.descriptor = KEYBOARD.to_vec();
        data.extra_devices = vec![(8, malformed), (9, report_descriptor())];
    }
    f.driver.start().unwrap();
    assert_eq!(
        f.driver.devices().len(),
        3,
        "actual discovered protocol roster"
    );
    let mut input = IshInput::new(f.driver, "model".into()).unwrap();
    assert_eq!(
        input.client_refusals(),
        [
            ClientRefusal {
                device_id: 8,
                cause: ClientRefusalCause::Descriptor(expected)
            },
            ClientRefusal {
                device_id: 9,
                cause: ClientRefusalCause::NoLegacyProjection
            },
        ]
    );
    let bytes = [1, 0, 0, 4, 0, 0, 0, 0, 0];
    f.peer.push_client(hostif(0x85, 7, &bytes));
    let mut guest = Vec::new();
    input.poll(&mut guest).unwrap();
    assert_eq!(
        guest,
        [Input::Key {
            usage: 4,
            pressed: true
        }]
    );
    assert_eq!(input.last_report(), bytes);
    drop(input);
    assert_eq!(f.config_counts.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(f.bar_counts.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(f.peer.root_drops.load(Ordering::Relaxed), 0);
    assert_eq!(f.peer.domain_drops.load(Ordering::Relaxed), 0);
}

#[test]
fn refused_projection_retains_the_same_roster_descriptors_and_native_graph() {
    let mut f = prepared();
    let malformed = malformed_projection();
    let expected = Translator::describe(&malformed).err().unwrap();
    f.peer.state.lock().unwrap().extra_devices = vec![(8, malformed.clone())];
    f.driver.start().unwrap();
    let before = f.peer.state.lock().unwrap().events.len();
    let refusal = IshInput::new(f.driver, "model".into()).err().unwrap();
    assert_eq!(
        refusal.clients(),
        [
            ClientRefusal {
                device_id: 7,
                cause: ClientRefusalCause::NoLegacyProjection
            },
            ClientRefusal {
                device_id: 8,
                cause: ClientRefusalCause::Descriptor(expected)
            },
        ]
    );
    assert_eq!(refusal.native().devices()[1].report_descriptor, malformed);
    assert!(refusal.native().firmware().is_some());
    assert_eq!(
        f.peer.state.lock().unwrap().events.len(),
        before,
        "projection does no I/O"
    );
    drop(refusal);
    assert_eq!(f.peer.state.lock().unwrap().events.len(), before);
    assert_eq!(f.config_counts.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(f.bar_counts.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(f.peer.root_drops.load(Ordering::Relaxed), 0);
    assert_eq!(f.peer.domain_drops.load(Ordering::Relaxed), 0);
}

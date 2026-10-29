// SPDX-License-Identifier: GPL-2.0-only
//! codec graph behavior tests.
use super::*;

#[test]
fn connection_ranges_and_inherited_caps() {
    let mut fixture = Fixture::new();
    let model = graph_model();
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    assert_eq!(graph.vendor_id, 0x1234_5678);
    assert_eq!(graph.groups.len(), 1);
    assert_eq!(graph.widget(6).unwrap().connections, [2, 3, 4]);
    assert_eq!(graph.widget(7).unwrap().connections, [2, 3, 4]);
    assert_eq!(graph.widget(4).unwrap().connections, [2]);
    assert_eq!(graph.widget(2).unwrap().output_amplifier, Some(0x8000_5678));
    assert!(graph.widget(2).unwrap().pcm.supports(pcm()));
    assert_eq!(graph.widget(4).unwrap().pin_capabilities, Some(0x10));
    assert_eq!(graph.widget(2).unwrap().channels(), 2);
}

#[test]
fn malformed_connections_rejected() {
    for (node, parameter, value) in [(0, 4, (127 << 16) | 2), (1, 4, (1 << 16) | 6), (6, 0x0e, 1)] {
        let mut fixture = Fixture::new();
        let model = graph_model();
        model
            .borrow_mut()
            .parameters
            .insert((node, parameter), value);
        if node == 6 {
            model.borrow_mut().connection_words.insert((6, 0), 0x84);
        }
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        assert!(matches!(
            controller.enumerate_codec(0),
            Err(Error::InvalidCodecGraph | Error::InvalidConnectionList)
        ));
    }
}

#[test]
fn unencodable_connection_node_rejected() {
    let mut fixture = Fixture::new();
    let model = graph_model();
    model.borrow_mut().connection_words.insert((4, 0), 0x100); // long NID cannot be packed into verbs.
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    assert!(matches!(
        controller.enumerate_codec(0),
        Err(Error::InvalidConnectionList)
    ));
}

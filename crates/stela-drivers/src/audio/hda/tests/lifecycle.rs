// SPDX-License-Identifier: GPL-2.0-only
//! Codec power acknowledgement and transition tests.
use super::*;
#[test]
fn codec_power_acknowledgement() {
    let mut fixture = Fixture::new();
    let model = analog_model();
    {
        let mut m = model.borrow_mut();
        m.codec_power_model = true;
        m.power_delay = 1000;
    }
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    controller
        .verb(Verb::short(0, 1, 0x705, 3).unwrap())
        .unwrap();
    assert_eq!(
        controller
            .verb(Verb::short(0, 1, 0xf05, 0).unwrap())
            .unwrap(),
        3
    );
    let clock = model.borrow().clock.clone();
    clock.0.set(clock.now_us() + 2000);
    assert_eq!(
        controller
            .verb(Verb::short(0, 1, 0xf05, 0).unwrap())
            .unwrap(),
        0x33
    );
    controller
        .verb(Verb::short(0, 1, 0x705, 0).unwrap())
        .unwrap();
    assert_eq!(
        controller
            .verb(Verb::short(0, 1, 0xf05, 0).unwrap())
            .unwrap(),
        0x30
    );
    model.borrow_mut().power_stuck = true;
    clock.0.set(clock.now_us() + 2000);
    assert_eq!(
        controller
            .verb(Verb::short(0, 1, 0xf05, 0).unwrap())
            .unwrap(),
        0x30
    );
    model.borrow_mut().power_stuck = false;
    assert_eq!(
        controller
            .verb(Verb::short(0, 1, 0xf05, 0).unwrap())
            .unwrap(),
        0
    );
    model.borrow_mut().power_error = true;
    assert_eq!(
        controller
            .verb(Verb::short(0, 1, 0xf05, 0).unwrap())
            .unwrap(),
        0x100
    );
    controller.shutdown().unwrap();
}
#[test]
fn reservation_survives_failed_reset() {
    for lost_reply in [false, true] {
        let mut fixture = Fixture::new();
        let model = graph_model();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let id = controller
            .allocate_stream(Direction::Playback, pcm(), 128, 2, &mut fixture.allocator)
            .unwrap();
        if lost_reply {
            model.borrow_mut().drop_reply_command =
                Some(Verb::short(0, 2, 0x706, id.tag() << 4).unwrap().raw());
        } else {
            model.borrow_mut().binding_read_failure = true;
        }
        assert!(controller.bind_converter(&graph, 2, id, 0).is_err());
        assert_eq!(
            controller.converter_bindings,
            [ConverterBinding {
                stream: id,
                codec: 0,
                node: 2,
                channel: 0
            }]
        );
        let before = access_counts(&model);
        assert_eq!(
            controller.bind_converter(&graph, 2, id, 0),
            Err(Error::NeedsReset)
        );
        assert_eq!(access_counts(&model), before);
        {
            let mut m = model.borrow_mut();
            m.drop_reply_command = None;
            m.binding_read_failure = false;
            m.reset_enter_stuck = true;
        }
        assert!(controller.reinitialize().is_err());
        assert_eq!(controller.converter_bindings.len(), 1);
        model.borrow_mut().reset_enter_stuck = false;
        controller.reinitialize().unwrap();
        assert!(controller.converter_bindings.is_empty());
    }
}
#[test]
fn converter_channel_spans() {
    let mut fixture = Fixture::new();
    let model = graph_model();
    model.borrow_mut().parameters.insert((6, 9), 1);
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    let id = controller
        .allocate_stream(
            Direction::Playback,
            PcmFormat {
                channels: 4,
                ..pcm()
            },
            128,
            2,
            &mut fixture.allocator,
        )
        .unwrap();
    controller.bind_converter(&graph, 2, id, 0).unwrap();
    controller.bind_converter(&graph, 6, id, 2).unwrap();
    assert_eq!(controller.converter_bindings.len(), 2);
    assert_eq!(model.borrow().bindings[&2], id.tag() << 4);
    assert_eq!(model.borrow().bindings[&6], (id.tag() << 4) | 2);
    let before = access_counts(&model);
    assert_eq!(
        controller.bind_converter(&graph, 2, id, 0),
        Err(Error::RouteInUse)
    );
    assert_eq!(access_counts(&model), before);
    controller.reinitialize().unwrap();
    assert!(controller.converter_bindings.is_empty());
}

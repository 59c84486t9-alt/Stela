// SPDX-License-Identifier: GPL-2.0-only
//! Conexant codec routing and lifecycle tests.
use super::*;

fn device(id: u32, eapds: usize) -> Rc<RefCell<Model>> {
    let model = analog_model();
    let mut m = model.borrow_mut();
    m.parameters.insert((0, 0), id);
    // Seven base widgets plus extra disconnected pins. EAPD enumeration must
    // include firmware-disconnected pins, just as cx_auto_parse_eapd does.
    m.parameters.insert((1, 4), (2 << 16) | 9);
    m.parameters.insert((4, 0x0c), 0x18);
    m.parameters.insert((4, 0x0e), 2);
    m.connection_words.insert((4, 0), 3 | (7 << 8));
    m.parameters.insert((3, 0x0e), 2);
    m.connection_words.insert((3, 0), 4 | (5 << 8));
    for node in 8..=10 {
        m.parameters.insert((node, 9), 4 << 20);
        m.parameters.insert((node, 0x0c), 0x10);
        m.pin_defaults.insert(node, 1 << 30);
    }
    for node in [4, 5, 8, 9, 10].into_iter().take(eapds) {
        *m.parameters.get_mut(&(node, 0x0c)).unwrap() |= 1 << 16;
        m.route_controls.insert((node, 0xf0c), 5);
    }
    drop(m);
    model
}

fn playback_options() -> PinOptions {
    PinOptions::Playback {
        headphone: true,
        eapd: None,
    }
}

fn headset_device(id: u32, present: bool) -> Rc<RefCell<Model>> {
    let model = device(id, 3);
    let mut m = model.borrow_mut();
    m.conexant_headset_model = true;
    m.conexant_detection_ready = Some(0);
    m.conexant_type = 0x800;
    m.parameters.insert((1, 4), (2 << 16) | 27);
    for node in 11..=0x1c {
        m.parameters.insert((node, 9), 0);
    }
    m.parameters.insert((0x16, 9), (4 << 20) | 1 | (1 << 8));
    m.parameters.insert((0x16, 0x0c), 0x18);
    m.parameters.insert((0x16, 0x0e), 1);
    m.connection_words.insert((0x16, 0), 2);
    m.parameters.insert((0x19, 9), (4 << 20) | 1 | (1 << 1));
    m.parameters.insert((0x19, 0x0c), 0x1124);
    m.parameters.insert((0x1c, 9), 0xf << 20);
    m.connection_words.insert((3, 0), 0x19);
    m.parameters.insert((3, 0x0e), 1);
    m.pin_senses.insert(0x19, if present { 1 << 31 } else { 0 });
    drop(m);
    model
}

fn minimum_mute_device(
    codec: u32,
    converter: u8,
    channels: u8,
    hardware_mute: bool,
) -> Rc<RefCell<Model>> {
    let model = device(codec, 3);
    let mut m = model.borrow_mut();
    m.parameters.insert((1, 4), (2 << 16) | 16);
    for node in 11..=0x11 {
        m.parameters.insert((node, 9), 0xf << 20);
    }
    let caps = 0x0000_1f1f | if hardware_mute { 1 << 31 } else { 0 };
    for node in [0x10, 0x11] {
        m.parameters
            .insert((node, 9), u32::from(channels == 2) | (1 << 2) | (1 << 3));
        m.parameters.insert((node, 0x12), caps);
        if !hardware_mute {
            m.outputs_without_hardware_mute.push(node);
        }
    }
    m.parameters.insert((4, 0x0e), 1);
    m.connection_words.insert((4, 0), u32::from(converter));
    drop(m);
    model
}

mod routing;

mod headset;

mod minimum_gain;

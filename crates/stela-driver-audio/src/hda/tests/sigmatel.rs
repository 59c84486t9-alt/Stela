// SPDX-License-Identifier: GPL-2.0-only
//! Sigmatel codec routing and lifecycle tests.
use super::*;
mod controls;
fn device(id: u32) -> Rc<RefCell<Model>> {
    let model = analog_model();
    let mut m = model.borrow_mut();
    m.parameters.insert((0, 0), id);
    m.parameters.insert((1, 4), (2 << 16) | 13);
    m.parameters.insert((1, 0x11), 8);
    m.route_controls.insert((1, 0xf15), 0xa5);
    m.route_controls.insert((1, 0xf16), 0x5a);
    m.route_controls.insert((1, 0xf17), 0x3c);
    for node in 8..=0x0e {
        m.parameters.insert((node, 9), 0xf << 20);
    }
    m.parameters.insert((8, 9), (4 << 20) | 1 | (1 << 8));
    m.parameters.insert((8, 0x0c), 0x18 | (1 << 16));
    m.parameters.insert((8, 0x0e), 1);
    m.connection_words.insert((8, 0), 7);
    // The fixed DAC0 mux can carry a real output route.
    m.parameters.insert((6, 9), (3 << 20) | 1 | (1 << 8));
    m.parameters.insert((6, 0x0e), 1);
    m.connection_words.insert((6, 0), 2);
    m.parameters.insert((7, 9), (3 << 20) | 1 | (1 << 8));
    m.parameters.insert((7, 0x0e), 1);
    m.connection_words.insert((7, 0), 2);
    m.parameters
        .insert((0x0e, 9), (2 << 20) | 1 | (1 << 2) | (1 << 8));
    m.parameters.insert((0x0e, 0x0e), 1);
    m.connection_words.insert((0x0e, 0), 6);
    m.connection_words
        .insert((4, 0), if id == 0x8384_7690 { 7 } else { 0x0e });
    m.parameters.insert((5, 0x0c), 0x20 | 0x3700 | 7);
    m.pin_defaults.insert(5, 0x03a1_0020);
    m.pin_senses.insert(5, 0x8000_005a);
    drop(m);
    model
}

fn stac922x_device(id: u32, inherited_amp: bool) -> Rc<RefCell<Model>> {
    let model = device(id);
    let mut m = model.borrow_mut();
    m.parameters.insert((1, 4), (2 << 16) | 21);
    for node in 0x0f..=0x16 {
        m.parameters.insert((node, 9), 0xf << 20);
    }
    // Capture mux output has a broken reported range. The
    // independent device clamps gain to 0..2 and has no mute bit.
    m.parameters.insert(
        (0x12, 9),
        (3 << 20) | 1 | (1 << 2) | (1 << 8) | if inherited_amp { 0 } else { 1 << 3 },
    );
    m.parameters.insert((0x12, 0x12), 0x8000_1f1f);
    m.parameters.insert((0x12, 0x0e), 1);
    m.connection_words.insert((0x12, 0), 5);
    m.parameters.insert((3, 0x0e), 1);
    m.connection_words.insert((3, 0), 0x12);
    m.connection_words.insert((4, 0), 2);
    m.parameters.insert((0x16, 9), 6 << 20);
    m.parameters.insert((0x16, 0x13), 0xff);
    m.route_controls.insert((0x16, 0xf0f), 0x20);
    m.stac922x_capture_amp = true;
    drop(m);
    model
}

fn idt83_device(id: u32) -> Rc<RefCell<Model>> {
    let model = analog_model();
    let mut m = model.borrow_mut();
    m.parameters.insert((0, 0), id);
    m.idt83_map_requires_d0 = true;
    m.parameters.insert((1, 4), (2 << 16) | 15);
    m.parameters.insert((1, 0x11), 8);
    m.route_controls.insert((1, 0xf15), 0xa5);
    m.route_controls.insert((1, 0xf16), 0x5a);
    m.route_controls.insert((1, 0xf17), 0x3c);
    for node in 4..=0x10 {
        m.parameters.insert((node, 9), 0xf << 20);
    }
    for node in 0x0a..=0x10 {
        m.parameters.insert((node, 9), (4 << 20) | 1 | (1 << 7));
        m.parameters.insert((node, 0x0c), 0x17);
        m.pin_defaults.insert(node, 0x0101_0010);
        m.pin_senses.insert(node, 0x8000_005a);
    }
    m.parameters
        .insert((0x0a, 9), (4 << 20) | 1 | (1 << 2) | (1 << 7) | (1 << 8));
    m.parameters.insert((0x0a, 0x0e), 1);
    m.connection_words.insert((0x0a, 0), 2);
    m.parameters.insert((0x0a, 0x0c), 0x1f | (1 << 16));
    m.pin_defaults.insert(0x0a, 0x0221_0010);
    m.parameters
        .insert((0x0b, 9), (4 << 20) | 1 | (1 << 1) | (1 << 7));
    m.parameters.insert((0x0b, 0x0c), 0x20 | 0x3700 | 7);
    m.pin_defaults.insert(0x0b, 0x03a1_0020);
    m.parameters.insert((3, 0x0e), 1);
    m.connection_words.insert((3, 0), 0x0b);
    m.pin_defaults.insert(0x0c, 0x9017_0030); // Fixed: powered despite absent raw sense.
    m.pin_senses.insert(0x0c, 0);
    m.pin_defaults.insert(0x0d, 0x4000_0100); // None: source disables it.
    m.pin_defaults.insert(0x0e, 0x0101_0110); // Jack no-presence hint: keep on.
    m.pin_senses.insert(0x0e, 0);
    m.parameters.insert((0x0f, 0x0c), 0x10); // Jack without detector: keep on.
    m.pin_defaults.insert(0x10, 0xc101_0010); // Jack+fixed: keep on.
    m.pin_senses.insert(0x10, 0);
    drop(m);
    model
}
fn idt83_playback() -> PinOptions {
    PinOptions::Playback {
        headphone: true,
        eapd: None,
    }
}

fn idt73_device(id: u32) -> Rc<RefCell<Model>> {
    let model = idt83_device(id);
    let mut m = model.borrow_mut();
    m.parameters.insert((1, 4), (2 << 16) | 30);
    for node in 0x11..=0x1f {
        m.parameters.insert((node, 9), 0xf << 20);
    }
    m.parameters.insert((0x11, 9), (4 << 20) | 1 | (1 << 7));
    m.parameters.insert((0x11, 0x0c), 0x17);
    m.pin_defaults.insert(0x11, 0x0101_0010);
    m.pin_senses.insert(0x11, 0);
    m.parameters.insert((0x1f, 9), (6 << 20) | 1);
    m.parameters.insert((0x1f, 0x13), 0x7f);
    m.route_controls.insert((1, 0xf15), 0xa4);
    m.idt73_model = true;
    drop(m);
    model
}

mod gpio;

mod stac922x;

mod idt83;

mod idt73;

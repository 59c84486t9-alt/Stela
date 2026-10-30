// SPDX-License-Identifier: GPL-2.0-only
//! Cirrus codec routing and lifecycle tests.
use super::*;
mod controls;
fn device(id: u32, shared: u8) -> Rc<RefCell<Model>> {
    let model = analog_model();
    let mut m = model.borrow_mut();
    m.parameters.insert((0, 0), id);
    m.parameters.insert((1, 4), (2 << 16) | 20);
    for node in 2..=0x15 {
        m.parameters.insert((node, 9), 0xf << 20);
    }
    m.parameters.insert((2, 9), 1 | (1 << 2) | (1 << 10));
    m.parameters.insert((2, 0x0f), 1);
    for node in [5, 6] {
        m.parameters
            .insert((node, 9), (1 << 20) | 1 | (1 << 1) | (1 << 8));
        m.parameters.insert((node, 0x0e), 2);
        m.connection_words.insert((node, 0), 0x0c | (0x0d << 8));
    }
    m.adc_amp_index_zero = vec![5, 6];
    for (node, kind) in [(7, 1 << 20), (8, 0)] {
        m.parameters
            .insert((node, 9), kind | 1 | (1 << 9) | (1 << 10));
        m.parameters.insert((node, 0x0f), 1);
    }
    m.parameters
        .insert((9, 9), (4 << 20) | 1 | (1 << 2) | (1 << 8));
    m.parameters.insert((9, 0x0c), 0x1f | (1 << 16));
    m.parameters.insert((9, 0x0e), 1);
    m.connection_words.insert((9, 0), 2);
    m.pin_defaults.insert(9, 0x0221_0010);
    m.pin_senses.insert(9, 0x8000_0042);
    m.route_controls.insert((9, 0xf0c), 5);
    for node in [0x0c, 0x0d] {
        m.parameters.insert((node, 9), (4 << 20) | 1 | (1 << 1));
        m.parameters.insert((node, 0x0c), 0x20 | 0x3700 | 7);
        m.pin_defaults.insert(node, 0x03a1_0020);
        m.pin_senses.insert(node, 0x8000_005a);
    }
    for (index, node) in [0x0e, 0x12, 0x15].into_iter().enumerate() {
        m.parameters.insert((node, 9), (4 << 20) | 1 | (1 << 9));
        m.parameters
            .insert((node, 0x0c), if node == 0x15 { 0x10 } else { 0x20 });
        m.pin_defaults.insert(
            node,
            if shared & (1 << index) == 0 {
                0x4000_0100
            } else if node == 0x15 {
                0x014b_1180
            } else {
                0x90a6_0150
            },
        );
    }
    m.parameters.insert(
        (0x11, 9),
        (0xf << 20) | (1 << 6) | if id == 0x1013_4207 { 1 << 10 } else { 0 },
    );
    m.parameters.insert((0x11, 0x10), 25 << 8);
    m.parameters.insert((0x11, 0x0f), 0); // Inherits AFG D0.
    m.cirrus_model = true;
    drop(m);
    model
}
fn playback() -> PinOptions {
    PinOptions::Playback {
        headphone: true,
        eapd: Some(true),
    }
}
fn capture() -> PinOptions {
    PinOptions::Capture {
        vref: Vref::EightyPercent,
    }
}

pub(super) fn cs4208_device(inherited: bool, pin18: bool) -> Rc<RefCell<Model>> {
    let model = analog_model();
    let mut m = model.borrow_mut();
    m.parameters.insert((0, 0), 0x1013_4208);
    m.parameters.insert((1, 4), (2 << 16) | 35);
    for node in 2..=0x24 {
        m.parameters.insert((node, 9), 0xf << 20);
    }
    m.parameters.insert((2, 9), 1 | (1 << 2) | (1 << 10));
    m.parameters.insert((2, 0x0f), 1);
    m.parameters
        .insert((0x10, 9), (4 << 20) | 1 | (1 << 2) | (1 << 3) | (1 << 8));
    m.parameters.insert((0x10, 0x12), 0x8000_3f3f);
    m.parameters.insert((0x10, 0x0c), 0x1f | (1 << 16));
    m.parameters.insert((0x10, 0x0e), 1);
    m.connection_words.insert((0x10, 0), 2);
    m.pin_defaults.insert(0x10, 0x0221_0010);
    m.pin_senses.insert(0x10, 0x8000_0042);
    m.route_controls.insert((0x10, 0xf0c), 5);
    m.parameters.insert((0x0d, 9), (4 << 20) | 1 | (1 << 1));
    m.parameters.insert((0x0d, 0x0c), 0x20 | 0x3700 | 7);
    m.pin_defaults.insert(0x0d, 0x03a1_0020);
    m.pin_senses.insert(0x0d, 0x8000_005a);
    for node in [0x18, 0x1b, 0x1c] {
        let kind = if pin18 && node == 0x18 {
            4 << 20
        } else {
            1 << 20
        };
        let caps = kind
            | if node == 0x18 { 0 } else { 1 }
            | (1 << 1)
            | if inherited { 0 } else { 1 << 3 }
            | if pin18 && node == 0x18 { 0 } else { 1 << 8 };
        m.parameters.insert((node, 9), caps);
        m.parameters
            .insert((node, 0x0d), 0x8000_1f0f | (u32::from(node & 3) << 16));
        if pin18 && node == 0x18 {
            m.parameters.insert((node, 0x0c), 0x20 | 0x3700 | 7);
            m.pin_defaults.insert(node, 0x03a1_0020);
            m.pin_senses.insert(node, 0x8000_005a);
        } else {
            m.parameters.insert((node, 0x0e), 2);
            m.connection_words.insert(
                (node, 0),
                0x0c | ((if pin18 && node == 0x1b { 0x18 } else { 0x0d }) << 8),
            );
        }
    }
    m.parameters.insert((0x0c, 9), (4 << 20) | 1);
    m.parameters.insert((0x0c, 0x0c), 0x20 | 0x3700);
    m.pin_defaults.insert(0x0c, 0x0181_0020);
    m.parameters.insert(
        (0x24, 9),
        (0xf << 20) | (1 << 6) | if inherited { 0 } else { 1 << 10 },
    );
    m.parameters.insert((0x24, 0x10), 53 << 8);
    m.parameters.insert((0x24, 0x0f), 0);
    m.cirrus_cs4208_model = true;
    drop(m);
    model
}

fn cs4210_device(inherited: bool, raw_steps: u8) -> Rc<RefCell<Model>> {
    let model = analog_model();
    let mut m = model.borrow_mut();
    m.parameters.insert((0, 0), 0x1013_4210);
    m.parameters.insert((1, 4), (2 << 16) | 10);
    for node in 2..=0x0b {
        m.parameters.insert((node, 9), 0xf << 20);
    }
    m.parameters.insert(
        (2, 9),
        1 | (1 << 2) | (1 << 10) | if inherited { 0 } else { 1 << 3 },
    );
    let raw = 0x8003_001f | (u32::from(raw_steps) << 8);
    m.parameters
        .insert((if inherited { 1 } else { 2 }, 0x12), raw);
    m.parameters.insert((2, 0x0f), 1);
    m.parameters
        .insert((3, 9), (1 << 20) | 1 | (1 << 1) | (1 << 8));
    m.parameters.insert((3, 0x0e), 2);
    m.connection_words.insert((3, 0), 7 | (8 << 8));
    for (node, default) in [(5, 0x0321_401f), (6, 0x9017_0010)] {
        m.parameters.insert((node, 9), (4 << 20) | 1 | (1 << 8));
        m.parameters
            .insert((node, 0x0c), if node == 5 { 0x18 } else { 0x10 });
        m.parameters.insert((node, 0x0e), 1);
        m.connection_words.insert((node, 0), 2);
        m.pin_defaults.insert(node, default);
    }
    for (node, default) in [(7, 0x0381_3031), (8, 0xb7a7_0037), (9, 0xb7a6_003e)] {
        m.parameters.insert(
            (node, 9),
            (4 << 20) | 1 | if node == 9 { 1 << 9 } else { 0 },
        );
        m.parameters
            .insert((node, 0x0c), 0x20 | if node == 9 { 0 } else { 0x3700 });
        m.pin_defaults.insert(node, default);
    }
    m.parameters.insert((0x0a, 9), (4 << 20) | 1 | (1 << 9));
    m.parameters.insert((0x0a, 0x0c), 0x10);
    m.pin_defaults.insert(0x0a, 0x0345_10f0);
    m.parameters.insert((0x0b, 9), (0xf << 20) | (1 << 6));
    m.parameters.insert((0x0b, 0x10), 28 << 8);
    m.coefficients.insert((0x0b, 1), 0x6e18);
    m.coefficients.insert((0x0b, 4), 0xd5a0);
    m.cirrus_cs4210_model = true;
    drop(m);
    model
}
fn cs4210_playback() -> PinOptions {
    PinOptions::Playback {
        headphone: false,
        eapd: None,
    }
}

mod cs4206;

mod cs4208;

mod cs4210;

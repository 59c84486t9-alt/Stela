// SPDX-License-Identifier: GPL-2.0-only
// Linux mousedev touchpad emulation reference: drivers/input/mousedev.c,
// Copyright (c) 1999-2001 Vojtech Pavlik.
//! ELAN and Cypress I²C touchpads, and the RMI4 and ELAN SMBus companions of
//! PS/2 touchpads, as a mouse: their first contact's movement becomes
//! [`Input::Motion`] and their buttons [`Input::MouseButtons`], as Linux
//! `mousedev` emulates a mouse from a touchpad, tap to click included.
use super::{
    Input, cyapa, elan,
    hid_i2c::Interrupt,
    rmi::{self, FunctionReport},
};
use crate::{
    Clock,
    bus::{i2c::Bus, smbus},
};
use alloc::{boxed::Box, string::String, vec::Vec};

/// mousedev's `FRACTION_DENOM`: motion keeps 1/128 count remainders.
const FRACTION: i32 = 128;
/// mousedev's default `tap_time`: a touch shorter than this is a click.
const TAP_US: u64 = 200_000;
/// Frames one poll reads at most.
const POLL_FRAMES: usize = 16;

/// A touchpad's pointer state, as mousedev's touchpad emulation keeps it.
#[derive(Debug, Default)]
pub struct Translator {
    /// The pad's width in its own units; motion across it is 256 counts.
    width: i32,
    history: [(i32, i32); 4],
    /// Frames since the contact touched down.
    frames: usize,
    fraction: (i32, i32),
    /// When the contact touched down.
    touched_us: Option<u64>,
    buttons: u8,
}

impl Translator {
    /// A translator for a pad whose x axis runs `0..=maximum_x`.
    pub fn new(maximum_x: u16) -> Self {
        Self {
            width: if maximum_x == 0 {
                256 * 2
            } else {
                i32::from(maximum_x)
            },
            ..Self::default()
        }
    }

    /// One frame: the first contact's position, top-down, if a finger is
    /// on the pad, and the buttons held (left, right, middle in bits 0..2),
    /// at `now_us`.
    pub fn frame(
        &mut self,
        contact: Option<(u16, u16)>,
        buttons: u8,
        now_us: u64,
        inputs: &mut Vec<Input>,
    ) {
        match contact {
            Some((x, y)) => {
                let (x, y) = (i32::from(x), i32::from(y));
                self.touched_us.get_or_insert(now_us);
                self.history[self.frames & 3] = (x, y);
                if self.frames >= 2 {
                    // mousedev_touchpad_event: the change since two frames
                    // ago, scaled to 256 counts across the pad's width on
                    // both axes; its y is down-positive here, as `Motion`.
                    let (old_x, old_y) = self.history[(self.frames - 2) & 3];
                    let scale = |delta: i32, fraction: &mut i32| -> i32 {
                        let total = delta * 256 * FRACTION / self.width + *fraction;
                        let counts = total / FRACTION;
                        *fraction = total - counts * FRACTION;
                        counts
                    };
                    let mut fraction = self.fraction;
                    let dx = scale(x - old_x, &mut fraction.0);
                    let dy = scale(y - old_y, &mut fraction.1);
                    self.fraction = fraction;
                    if (dx, dy) != (0, 0) {
                        let counts = |v: i32| v.clamp(i16::MIN.into(), i16::MAX.into()) as i16;
                        inputs.push(Input::Motion {
                            dx: counts(dx),
                            dy: counts(dy),
                        });
                    }
                }
                self.frames += 1;
            }
            None => {
                // mousedev_touchpad_touch: a short touch is a left click.
                if let Some(touched) = self.touched_us.take()
                    && now_us.saturating_sub(touched) < TAP_US
                    && self.buttons & 1 == 0
                    && buttons & 1 == 0
                {
                    inputs.push(Input::MouseButtons(self.buttons | 1));
                    inputs.push(Input::MouseButtons(self.buttons));
                }
                self.frames = 0;
                self.fraction = (0, 0);
            }
        }
        if buttons != self.buttons {
            self.buttons = buttons;
            inputs.push(Input::MouseButtons(buttons));
        }
    }

    /// The buttons alone changed, as a button-only frame reports them.
    pub fn buttons(&mut self, buttons: u8, inputs: &mut Vec<Input>) {
        if buttons != self.buttons {
            self.buttons = buttons;
            inputs.push(Input::MouseButtons(buttons));
        }
    }
}

type BoxedBus = Box<dyn Bus>;
type BoxedInterrupt = Box<dyn Interrupt>;
type BoxedSmbus = Box<dyn smbus::Bus>;

/// An ELAN touchpad over SMBus, its interrupt a Host Notify.
pub type ElanSmbus = elan::smbus::Device<BoxedSmbus, BoxedInterrupt, Clock>;

/// An RMI4 touchpad over SMBus, its attention a Host Notify.
pub type RmiSmbus = rmi::Device<
    rmi::transport::Smbus<BoxedSmbus, Box<dyn rmi::transport::Companion>, Clock>,
    Box<dyn rmi::Attention>,
    Clock,
>;

/// RMI4 2D object types a finger reports: `RMI_2D_OBJECT_FINGER` and
/// `RMI_2D_OBJECT_GLOVE`.
const RMI_FINGERS: [u8; 2] = [1, 6];

/// The touchpad drivers a [`TouchpadInput`] reads.
#[allow(
    clippy::large_enum_variant,
    reason = "InputDevice boxes the whole touchpad input"
)]
pub enum Driver {
    Elan(elan::I2cDevice<BoxedBus, BoxedInterrupt, Clock>),
    /// Cypress Gen3.
    Cypress(cyapa::Device<BoxedBus, BoxedInterrupt, Clock>),
    /// Cypress Gen5 and Gen6.
    CypressPip(cyapa::pip::Device<BoxedBus, BoxedInterrupt, Clock>),
    /// ELAN over SMBus, the companion of an Elantech PS/2 touchpad.
    ElanSmbus(ElanSmbus),
    /// Synaptics RMI4 over SMBus, the InterTouch companion of a Synaptics
    /// PS/2 touchpad.
    Rmi(Box<RmiSmbus>),
}

/// Why reading a touchpad failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Elan(elan::Error),
    Cypress(cyapa::Error),
    CypressPip(cyapa::pip::Error),
    Rmi(rmi::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Elan(error) => error.fmt(f),
            Self::Cypress(error) => error.fmt(f),
            Self::CypressPip(error) => error.fmt(f),
            Self::Rmi(error) => error.fmt(f),
        }
    }
}

/// An initialized touchpad and its mouse emulation.
pub struct TouchpadInput {
    driver: Driver,
    translator: Translator,
    clock: Clock,
    pub name: String,
}

impl TouchpadInput {
    /// Emulate a mouse from `driver`, which is initialized: its queried
    /// maximum sets the motion scale.
    pub fn new(driver: Driver, clock: Clock, name: String) -> Self {
        let maximum_x = match &driver {
            Driver::Elan(device) => device.capabilities().map_or(0, |c| c.maximum.0),
            Driver::Cypress(device) => device.capabilities().map_or(0, |c| c.maximum.0),
            Driver::CypressPip(device) => device.capabilities().map_or(0, |c| c.maximum.0),
            Driver::ElanSmbus(device) => device.capabilities().map_or(0, |c| c.maximum.0),
            Driver::Rmi(device) => rmi_maximum(device).0,
        };
        Self {
            driver,
            translator: Translator::new(maximum_x),
            clock,
            name,
        }
    }

    /// Append the motion and buttons of the frames the pad has ready.
    pub fn poll(&mut self, inputs: &mut Vec<Input>) -> Result<(), Error> {
        for _ in 0..POLL_FRAMES {
            let now = self.clock.now_us();
            match &mut self.driver {
                Driver::Elan(device) => match device.poll().map_err(Error::Elan)? {
                    None => break,
                    Some(elan::Frame::Absolute(frame)) => {
                        let contact = frame
                            .contacts
                            .iter()
                            .flatten()
                            .next()
                            .map(|c| (c.x, c.y_top_down));
                        self.translator
                            .frame(contact, frame.buttons & 7, now, inputs);
                    }
                    Some(elan::Frame::Trackpoint(frame)) => {
                        if let Some((dx, dy)) = frame.motion
                            && (dx, dy) != (0, 0)
                        {
                            inputs.push(Input::Motion { dx, dy });
                        }
                        self.translator.buttons(frame.buttons & 7, inputs);
                    }
                },
                Driver::Cypress(device) => match device.poll().map_err(Error::Cypress)? {
                    None => break,
                    Some(frame) => {
                        let contact = frame.contacts.iter().flatten().next().map(|c| (c.x, c.y));
                        self.translator.frame(contact, frame.buttons, now, inputs);
                    }
                },
                Driver::CypressPip(device) => match device.poll().map_err(Error::CypressPip)? {
                    None => break,
                    Some(cyapa::pip::Frame::Touches { touches, .. }) => {
                        let contact = touches
                            .active
                            .iter()
                            .flatten()
                            .find(|c| c.kind == cyapa::pip::ContactType::Finger)
                            .map(|c| (c.x, c.y));
                        let buttons = self.translator.buttons;
                        self.translator.frame(contact, buttons, now, inputs);
                    }
                    Some(cyapa::pip::Frame::Buttons { buttons, .. }) => {
                        self.translator.buttons(buttons & 7, inputs);
                    }
                    Some(_) => {}
                },
                Driver::ElanSmbus(device) => match device.poll().map_err(Error::Elan)? {
                    None => break,
                    Some(elan::Frame::Absolute(frame)) => {
                        let contact = frame
                            .contacts
                            .iter()
                            .flatten()
                            .next()
                            .map(|c| (c.x, c.y_top_down));
                        self.translator
                            .frame(contact, frame.buttons & 7, now, inputs);
                    }
                    Some(elan::Frame::Trackpoint(frame)) => {
                        if let Some((dx, dy)) = frame.motion
                            && (dx, dy) != (0, 0)
                        {
                            inputs.push(Input::Motion { dx, dy });
                        }
                        self.translator.buttons(frame.buttons & 7, inputs);
                    }
                },
                Driver::Rmi(device) => {
                    let poll = device.poll_input();
                    let (_, maximum_y) = rmi_maximum(device);
                    let polled = !poll.reports.is_empty();
                    for report in poll.reports {
                        let buttons = self.translator.buttons;
                        // The InterTouch platform data flips y, which RMI4
                        // reports bottom-up.
                        let contact = match report {
                            FunctionReport::F11(frame) => frame
                                .contacts
                                .iter()
                                .find(|c| matches!(c.state, 1 | 2))
                                .map(|c| (c.x, maximum_y.saturating_sub(c.y))),
                            FunctionReport::F12(frame) => frame
                                .contacts
                                .iter()
                                .find(|c| RMI_FINGERS.contains(&c.object_type))
                                .map(|c| (c.x, maximum_y.saturating_sub(c.y))),
                            FunctionReport::F30(frame) => {
                                self.translator.buttons(rmi_buttons(&frame.buttons), inputs);
                                continue;
                            }
                            FunctionReport::F3A(frame) => {
                                let pressed =
                                    frame.buttons.iter().map(|b| (b.gpio_index, b.pressed));
                                self.translator.buttons(rmi_buttons_of(pressed), inputs);
                                continue;
                            }
                            FunctionReport::F03(_) | FunctionReport::F1A(_) => continue,
                        };
                        self.translator.frame(contact, buttons, now, inputs);
                    }
                    if let Some(error) = poll.error {
                        return Err(Error::Rmi(error));
                    }
                    if !polled {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    /// Whether the pad stopped after a failure and is no longer read.
    pub fn stopped(&self) -> bool {
        match &self.driver {
            Driver::Elan(device) => device.state() == elan::State::Uncertain,
            Driver::Cypress(device) => device.state() == cyapa::State::Uncertain,
            Driver::CypressPip(device) => device.state() == cyapa::pip::State::Uncertain,
            Driver::ElanSmbus(device) => device.state() == elan::State::Uncertain,
            Driver::Rmi(device) => device.control_state() == rmi::ControlState::Uncertain,
        }
    }
}

/// The pad's maximum x and y, from its F11 or F12 sensor.
fn rmi_maximum(device: &RmiSmbus) -> (u16, u16) {
    device
        .f11_capabilities()
        .map(|c| c.maximum)
        .chain(device.f12_capabilities().filter_map(|c| c.maximum))
        .next()
        .unwrap_or((0, 0))
}

/// Mouse buttons from F30 GPIO buttons: the first three valid buttons are
/// left, right and middle, as `rmi_f30_map_gpios` maps them from BTN_LEFT.
fn rmi_buttons(buttons: &[rmi::f30::Button]) -> u8 {
    rmi_buttons_of(buttons.iter().map(|b| (b.gpio_index, b.pressed)))
}

/// Mouse buttons from GPIO buttons in their pin order, the first three left,
/// right and middle.
fn rmi_buttons_of(buttons: impl Iterator<Item = (u8, bool)>) -> u8 {
    buttons
        .take(3)
        .enumerate()
        .filter(|(_, (_, pressed))| *pressed)
        .fold(0, |mask, (bit, _)| mask | 1 << bit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn motion_is_the_change_since_two_frames_ago_scaled_to_the_pad_width() {
        let mut pad = Translator::new(1024);
        let mut inputs = Vec::new();
        for (at, x) in [0, 64, 128, 192].into_iter().enumerate() {
            pad.frame(Some((x, 100)), 0, at as u64 * 300_000, &mut inputs);
        }
        // Two frames of 64 units across a 1024-unit pad is 32 counts.
        assert_eq!(
            inputs,
            [
                Input::Motion { dx: 32, dy: 0 },
                Input::Motion { dx: 32, dy: 0 }
            ]
        );
    }

    #[test]
    fn remainders_carry_into_later_frames() {
        let mut pad = Translator::new(1024);
        let mut inputs = Vec::new();
        for (at, x) in [0, 1, 2, 3, 4, 5].into_iter().enumerate() {
            pad.frame(Some((x, 0)), 0, at as u64 * 300_000, &mut inputs);
        }
        // Each frame moves half a count; every second one carries a count.
        assert_eq!(
            inputs,
            [
                Input::Motion { dx: 1, dy: 0 },
                Input::Motion { dx: 1, dy: 0 }
            ]
        );
    }

    #[test]
    fn a_short_touch_clicks_and_a_long_one_does_not() {
        let mut pad = Translator::new(1024);
        let mut inputs = Vec::new();
        pad.frame(Some((10, 10)), 0, 0, &mut inputs);
        pad.frame(None, 0, 100_000, &mut inputs);
        assert_eq!(
            inputs,
            [Input::MouseButtons(1), Input::MouseButtons(0)],
            "a tap"
        );
        inputs.clear();
        pad.frame(Some((10, 10)), 0, 200_000, &mut inputs);
        pad.frame(None, 0, 500_000, &mut inputs);
        assert!(inputs.is_empty());
    }

    #[test]
    fn rmi_gpio_buttons_are_left_right_and_middle_in_pin_order() {
        let pressed = |pins: &[(u8, bool)]| rmi_buttons_of(pins.iter().copied());
        assert_eq!(pressed(&[(0, true)]), 1);
        assert_eq!(pressed(&[(2, false), (5, true)]), 2);
        assert_eq!(pressed(&[(0, true), (1, true), (2, true), (3, true)]), 7);
    }

    #[test]
    fn button_changes_report_once_each() {
        let mut pad = Translator::new(1024);
        let mut inputs = Vec::new();
        pad.frame(None, 1, 0, &mut inputs);
        pad.frame(None, 1, 1, &mut inputs);
        pad.buttons(0, &mut inputs);
        assert_eq!(inputs, [Input::MouseButtons(1), Input::MouseButtons(0)]);
    }

    #[test]
    fn a_lifted_finger_starts_motion_afresh() {
        let mut pad = Translator::new(1024);
        let mut inputs = Vec::new();
        pad.frame(Some((0, 0)), 0, 0, &mut inputs);
        pad.frame(Some((64, 0)), 0, 300_000, &mut inputs);
        pad.frame(None, 0, 600_000, &mut inputs);
        pad.frame(Some((900, 0)), 0, 900_000, &mut inputs);
        pad.frame(Some((900, 0)), 0, 1_200_000, &mut inputs);
        assert!(inputs.is_empty(), "no jump from the old position");
    }
}

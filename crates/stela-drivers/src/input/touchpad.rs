// SPDX-License-Identifier: GPL-2.0-only
// Linux mousedev touchpad emulation reference: drivers/input/mousedev.c,
// Copyright (c) 1999-2001 Vojtech Pavlik.
//! ELAN and Cypress I²C touchpads as a mouse: their first contact's movement
//! becomes [`Input::Motion`] and their buttons [`Input::MouseButtons`], as
//! Linux `mousedev` emulates a mouse from a touchpad, tap to click included.
use super::{Input, cyapa, elan, hid_i2c::Interrupt};
use crate::{Clock, bus::i2c::Bus};
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
}

/// Why reading a touchpad failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Elan(elan::Error),
    Cypress(cyapa::Error),
    CypressPip(cyapa::pip::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Elan(error) => error.fmt(f),
            Self::Cypress(error) => error.fmt(f),
            Self::CypressPip(error) => error.fmt(f),
        }
    }
}

/// An initialized ELAN or Cypress touchpad and its mouse emulation.
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
        }
    }
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

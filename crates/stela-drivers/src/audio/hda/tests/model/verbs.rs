// SPDX-License-Identifier: GPL-2.0-only
//! Codec verb responses for the controller test model.
use super::*;
impl Model {
    pub(super) fn reply_for(&mut self, command: u32) -> u32 {
        if command & 0x0fff_ffff == 0x000f_0000 {
            if self.link_initializations < self.codec_ready_after_resets {
                return 0;
            }
            if let Some(value) = self.codec_vendor_overrides.get(&((command >> 28) as u8)) {
                return *value;
            }
        }
        if let Some(value) = self.constant_reply {
            return value;
        }
        let node = ((command >> 20) & 127) as u8;
        let verb = ((command >> 8) & 0xfff) as u16;
        let long = (command >> 16) & 15;
        if self.conexant_headset_model && node == 0x1c {
            if self.conexant_vendor_fault == Some(verb) {
                return u32::MAX;
            }
            if command & 0x000f_ffff == 0x0003_be10 {
                self.conexant_trim = Some(0x0e10);
                return 0;
            }
            if verb == 0xca0 {
                self.conexant_detection_reads += 1;
                return if self
                    .conexant_detection_ready
                    .is_some_and(|time| self.clock.now_us() >= time)
                {
                    0x80
                } else {
                    0
                };
            }
            if verb == 0xcb0 {
                return self.conexant_type;
            }
        }

        if long == 3 {
            let value = command as u16;
            let output = value & (1 << 15) != 0;
            assert_eq!(value & (1 << 14) != 0, !output);
            let index = ((value >> 8) & 15) as u8;
            if !output && self.adc_amp_index_zero.contains(&node) && index != 0 {
                return 0;
            }
            let mut gain = if output && self.outputs_without_hardware_mute.contains(&node) {
                value as u8 & 0x7f
            } else {
                value as u8
            };
            if self.cirrus_cs4210_model && node == 2 && output {
                // Physical CS4210 gain ceiling is the 0dB offset,
                // despite its incorrectly advertised raw step count.
                let caps = if self.parameters[&(2, 9)] & (1 << 3) == 0 {
                    self.parameters[&(1, 0x12)]
                } else {
                    self.parameters[&(2, 0x12)]
                };
                gain = (gain & 0x80) | (gain & 0x7f).min(caps as u8 & 0x7f);
            }
            if self.stac922x_capture_amp && node == 0x12 && output {
                gain = (gain & 0x7f).min(2);
            }
            if value & (1 << 13) != 0 {
                self.amplifiers.insert((node, output, index, 0), gain);
            }
            if value & (1 << 12) != 0 {
                self.amplifiers.insert((node, output, index, 1), gain);
            }
            return 0;
        }
        if long == 0xb {
            if self.reject_amplifier {
                return 0xff;
            }
            let value = command as u16;
            let output = value & (1 << 15) != 0;
            let channel = u8::from(value & (1 << 13) == 0);
            if !output && self.adc_amp_index_zero.contains(&node) && value & 15 != 0 {
                return u32::MAX;
            }
            if self.reject_amplifier_channel == Some((node, channel)) {
                return u32::MAX;
            }
            return u32::from(
                *self
                    .amplifiers
                    .get(&(node, output, value as u8 & 15, channel))
                    .unwrap_or(&0x80),
            );
        }
        match long {
            5 => {
                self.coefficient_indexes.insert(node, command as u16);
                return 0;
            }
            13 => {
                if let Some((target, value)) = self.coefficient_index_reply
                    && target == node
                {
                    return value;
                }
                return if self.coefficient_index_failed {
                    u32::MAX
                } else {
                    u32::from(*self.coefficient_indexes.get(&node).unwrap_or(&0))
                };
            }
            4 => {
                self.coefficient_writes += 1;
                *self.coefficient_write_nodes.entry(node).or_default() += 1;
                self.coefficient_events.push((
                    node,
                    *self.coefficient_indexes.get(&node).unwrap_or(&0),
                    command as u16,
                    self.clock.now_us(),
                ));
                if !self.reject_coefficient_write && self.reject_coefficient_node != Some(node) {
                    if self.cirrus_model && node == 0x11 {
                        let index = *self.coefficient_indexes.get(&node).unwrap_or(&0);
                        let value = command as u16;
                        let processing = self.route_controls.get(&(node, 0xf03)) == Some(&1);
                        let valid = if index == 8 && value == 0x9999 && processing {
                            self.cirrus_errata_stage = 1;
                            self.cirrus_errata_complete = false;
                            self.cirrus_errata_powered = [false; 2];
                            true
                        } else {
                            match (self.cirrus_errata_stage, index, value) {
                                (1, 0x17, 0xa412) if processing => {
                                    self.cirrus_errata_stage = 2;
                                    true
                                }
                                (2, 1, 9) if processing => {
                                    self.cirrus_errata_stage = 3;
                                    true
                                }
                                (3, 0x17, 0x2412)
                                    if processing
                                        && self.cirrus_errata_powered == [true; 2]
                                        && [7, 8].iter().all(|node| {
                                            self.power_ready
                                                .get(node)
                                                .is_some_and(|ready| self.clock.now_us() >= *ready)
                                        }) =>
                                {
                                    self.cirrus_errata_stage = 4;
                                    true
                                }
                                (4, 8, 0) if processing => {
                                    self.cirrus_errata_stage = 5;
                                    true
                                }
                                (5, 1, 8) if processing => {
                                    self.cirrus_errata_stage = 6;
                                    true
                                }
                                (_, 1..=4, _) if processing && self.cirrus_errata_complete => true,
                                _ => false,
                            }
                        };
                        if !valid {
                            self.cirrus_errata_invalid = true;
                            return u32::MAX;
                        }
                    }
                    if self.cirrus_cs4208_model && node == 0x24 {
                        let index = *self.coefficient_indexes.get(&node).unwrap_or(&0);
                        if self.route_controls.get(&(node, 0xf03)) != Some(&1)
                            || self
                                .power_ready
                                .get(&1)
                                .is_none_or(|ready| self.clock.now_us() < *ready)
                            || !matches!(index, 0x33 | 0x34)
                            || (index == 0x34 && self.coefficients.get(&(node, 0x33)) != Some(&1))
                        {
                            return u32::MAX;
                        }
                    }
                    if self.cirrus_cs4210_model && node == 0x0b {
                        let index = *self.coefficient_indexes.get(&node).unwrap_or(&0);
                        let value = command as u16;
                        let processing = self.route_controls.get(&(node, 0xf03)) == Some(&1);
                        let powered = self
                            .power_ready
                            .get(&1)
                            .is_some_and(|ready| self.clock.now_us() >= *ready);
                        let expected = [
                            (1, 0x6e00),
                            (1, 1),
                            (2, 2),
                            (3, 0x0e),
                            (6, 0x9999),
                            (0x0a, 0x14cb),
                            (0x11, 0xa2d0),
                            (0x1a, 0x02a9),
                            (0x1b, 0x1006),
                            (1, 1),
                        ];
                        let stage = usize::from(self.cirrus_cs4210_stage);
                        let valid = powered
                            && if stage < expected.len() {
                                (index, value) == expected[stage]
                                    && if stage == 0 { !processing } else { processing }
                                    && (stage < 4
                                        || self.route_control_writes.get(&(node, 0xf03))
                                            == Some(&2))
                            } else {
                                index == 4 && processing
                            };
                        if !valid {
                            self.cirrus_cs4210_invalid = true;
                            return u32::MAX;
                        }
                        if stage < expected.len() {
                            self.cirrus_cs4210_stage += 1;
                        }
                    }
                    self.coefficients.insert(
                        (node, *self.coefficient_indexes.get(&node).unwrap_or(&0)),
                        command as u16,
                    );
                    if node == 0x58
                        && self.coefficient_indexes.get(&node) == Some(&0)
                        && command as u16 == 0xf888
                    {
                        self.depop_started_at = Some(self.clock.now_us());
                    }
                    if (self.cirrus_model
                        && node == 0x11
                        && self.coefficients.get(&(node, 3)).copied().unwrap_or(0) & 0x400 == 0)
                        || (self.cirrus_cs4208_model && node == 0x24)
                        || (self.cirrus_cs4210_model
                            && node == 0x0b
                            && self.coefficients.get(&(node, 1)).copied().unwrap_or(0) & 1 == 0)
                    {
                        *self.coefficient_indexes.entry(node).or_default() += 1;
                    }
                }
                return 0;
            }
            12 => {
                if self.cirrus_model && node == 0x11 && !self.cirrus_errata_complete {
                    self.cirrus_early_coefficient_reads += 1;
                }
                if let Some(value) = self.coefficient_read_fault
                    && self
                        .coefficient_fault_node
                        .is_none_or(|target| target == node)
                    && (!self.coefficient_fault_after_write
                        || if let Some(target) = self.coefficient_fault_node {
                            self.coefficient_write_nodes
                                .get(&target)
                                .copied()
                                .unwrap_or(0)
                                >= self.coefficient_fault_write_threshold
                        } else {
                            self.coefficient_writes >= self.coefficient_fault_write_threshold
                        })
                {
                    return value;
                }
                if node == 0x58
                    && self.coefficient_indexes.get(&node) == Some(&0)
                    && let Some(start) = self.depop_started_at
                    && let Some(delay) = self.depop_delay_us
                    && self.clock.now_us().saturating_sub(start) >= delay
                {
                    self.depop_started_at = None;
                    *self.coefficients.entry((0x58, 0)).or_default() &= !0x8000;
                    if self.depop_mutate_saved {
                        for (index, mask) in [(0x38, 0x100), (0x0d, 2), (0x36, 0x200)] {
                            *self.coefficients.entry((0x20, index)).or_default() &= !mask;
                        }
                    }
                }
                let value = *self
                    .coefficients
                    .get(&(node, *self.coefficient_indexes.get(&node).unwrap_or(&0)))
                    .unwrap_or(&0);
                if (self.cirrus_model
                    && node == 0x11
                    && self.coefficients.get(&(node, 3)).copied().unwrap_or(0) & 0x400 == 0)
                    || (self.cirrus_cs4208_model && node == 0x24)
                    || (self.cirrus_cs4210_model
                        && node == 0x0b
                        && self.coefficients.get(&(node, 1)).copied().unwrap_or(0) & 1 == 0)
                {
                    *self.coefficient_indexes.entry(node).or_default() += 1;
                }
                return u32::from(value);
            }
            _ => (),
        }
        match verb {
            0x788 => {
                if self.idt73_model {
                    return u32::MAX;
                }
                self.idt83_amplifier_mode = Some(command as u8);
                self.idt83_amplifier_reply
            }
            0x705 => {
                if self.codec_power_model {
                    if !self.power_stuck
                        && self
                            .power_ready
                            .get(&node)
                            .is_some_and(|ready| self.clock.now_us() >= *ready)
                    {
                        self.codec_actual_power
                            .insert(node, *self.codec_requested_power.get(&node).unwrap_or(&0));
                    }
                    self.codec_requested_power.insert(node, command as u8 & 15);
                }
                if self.cirrus_model && self.cirrus_errata_stage == 3 && matches!(node, 7 | 8) {
                    self.cirrus_errata_powered[usize::from(node - 7)] = true;
                }
                self.power_ready
                    .insert(node, self.clock.now_us() + self.power_delay);
                0
            }
            0xf05 => {
                if self.codec_power_model {
                    let requested = *self.codec_requested_power.get(&node).unwrap_or(&0);
                    if !self.power_stuck
                        && self
                            .power_ready
                            .get(&node)
                            .is_some_and(|ready| self.clock.now_us() >= *ready)
                    {
                        self.codec_actual_power.insert(node, requested);
                    }
                    let actual = *self.codec_actual_power.get(&node).unwrap_or(&0);
                    return u32::from(requested)
                        | (u32::from(actual) << 4)
                        | if self.power_error { 1 << 8 } else { 0 };
                }
                if self.power_error {
                    1 << 8
                } else if self.power_stuck
                    || self.clock.now_us() < *self.power_ready.get(&node).unwrap_or(&u64::MAX)
                {
                    3 << 4
                } else {
                    0
                }
            }
            0x701 | 0x703 | 0x707 | 0x708 | 0x70c | 0x70f | 0x715 | 0x716 | 0x717 | 0x7e7
            | 0x7ec => {
                if self.cirrus_model && node == 0x11 && verb == 0x703 && command as u8 == 0 {
                    self.cirrus_errata_complete = self.cirrus_errata_stage == 6;
                }
                if self.idt73_model {
                    let gpio_ready = [0xf15, 0xf16, 0xf17].iter().all(|get| {
                        self.route_controls
                            .get(&(1, *get))
                            .is_some_and(|value| value & 1 != 0)
                    });
                    if (verb == 0x70f && node == 0x1f && !gpio_ready)
                        || (verb == 0x7ec
                            && (!gpio_ready
                                || self.route_controls.get(&(0x1f, 0xf0f)) != Some(&0xff)
                                || self
                                    .power_ready
                                    .get(&1)
                                    .is_none_or(|ready| self.clock.now_us() < *ready)))
                        || (verb == 0x715
                            && command as u8 & 1 == 0
                            && ((0..4).any(|index| {
                                self.bytes[stream_base(index) + SD_CTL] & SD_RUN != 0
                            }) || (0x0a..=0x11)
                                .any(|pin| self.route_controls.get(&(pin, 0xf07)) != Some(&0))))
                    {
                        return u32::MAX;
                    }
                }
                *self
                    .route_control_writes
                    .entry((node, verb + 0x800))
                    .or_default() += 1;
                if self.conexant_headset_model && node == 0x19 && verb == 0x707 {
                    self.conexant_mic_writes += 1;
                }
                let value = if verb == 0x70f {
                    let max = *self.parameters.get(&(node, 0x13)).unwrap_or(&0) as u8 & 0x7f;
                    (command as u8 & 0x80) | (command as u8 & 0x7f).min(max)
                } else {
                    command as u8
                };
                self.route_controls.insert((node, verb + 0x800), value);
                if verb == 0x7ec {
                    self.idt83_power_map = u32::from(value);
                }
                0
            }
            0xf01 | 0xf03 | 0xf07 | 0xf08 | 0xf0c | 0xf0f | 0xf15 | 0xf16 | 0xf17 | 0xfec => {
                if self.idt73_model
                    && verb == 0xf15
                    && self.idt73_gpio_input_after_write.is_some_and(|threshold| {
                        self.route_control_writes
                            .get(&(node, verb))
                            .copied()
                            .unwrap_or(0)
                            >= threshold
                    })
                {
                    // InputGPIO1 changes independently after the DATA write;
                    // its readback is not controlled by the source-ownedGPIO0.
                    *self.route_controls.entry((node, verb)).or_default() &= !2;
                    self.idt73_gpio_input_after_write = None;
                }
                if self.conexant_headset_model
                    && node == 0x19
                    && verb == 0xf07
                    && self
                        .conexant_mic_fault_after
                        .is_some_and(|count| self.conexant_mic_writes >= count)
                {
                    return u32::MAX;
                }
                if self.reject_route_control == Some(verb)
                    && self.reject_route_node.is_none_or(|target| target == node)
                    && (!self.reject_route_after_write
                        || self
                            .route_control_writes
                            .get(&(node, verb))
                            .is_some_and(|count| *count >= self.reject_route_write_threshold))
                {
                    0xffff_ffff
                } else if verb == 0xfec {
                    if self.idt83_map_requires_d0
                        && self
                            .power_ready
                            .get(&node)
                            .is_none_or(|ready| self.clock.now_us() < *ready)
                    {
                        u32::MAX
                    } else {
                        self.idt83_power_map
                    }
                } else {
                    u32::from(*self.route_controls.get(&(node, verb)).unwrap_or(&0))
                }
            }

            0xf00 => *self.parameters.get(&(node, command as u8)).unwrap_or(&0),
            0xf02 => *self
                .connection_words
                .get(&(node, command as u8))
                .unwrap_or(&0),
            0xf1c => *self.pin_defaults.get(&node).unwrap_or(&0x0101_4010),
            0xf09 => *self.pin_senses.get(&node).unwrap_or(&0),
            0xf20 => 0x1043_8693,
            0x709 => {
                self.sense_triggers.push(node);
                0
            }
            0x706 => {
                self.bindings.insert(node, command as u8);
                0
            }
            0xf06 => {
                if self.binding_read_failure {
                    u32::MAX
                } else {
                    u32::from(*self.bindings.get(&node).unwrap_or(&0))
                }
            }
            0xa00 => u32::from(*self.formats.get(&node).unwrap_or(&0)),
            _ if (command >> 16) & 15 == 2 => {
                self.formats.insert(node, command as u16);
                0
            }
            _ => 0,
        }
    }
}

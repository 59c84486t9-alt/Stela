// SPDX-License-Identifier: GPL-2.0-only
//! Register, command-ring and DMA state for controller tests.
use super::*;
mod verbs;
pub(super) struct Event {
    pub(super) due: u64,
    pub(super) offset: usize,
    pub(super) value: u32,
    pub(super) bytes: usize,
}
pub(super) struct Reply {
    pub(super) due: u64,
    pub(super) value: u32,
    pub(super) extra: u32,
}
pub(super) struct Model {
    pub(super) bytes: Vec<u8>,
    pub(super) link_controls: Vec<usize>,
    pub(super) link_down_stuck: bool,
    pub(super) link_up_stuck: bool,
    pub(super) reject_link_clock: bool,
    pub(super) link_clock_lost_on_power_up: bool,
    pub(super) link_reads: BTreeMap<usize, usize>,
    pub(super) clock: ModelClock,
    pub(super) hardware_delay: u64,
    pub(super) consume_delay: u64,
    pub(super) response_delay: u64,
    pub(super) next_consume: u64,
    pub(super) events: Vec<Event>,
    pub(super) replies: Vec<Reply>,
    pub(super) self_clear: bool,
    pub(super) reset_enter_stuck: bool,
    pub(super) reset_gate: Option<Rc<Cell<bool>>>,
    pub(super) link_initializations: u8,
    pub(super) advertised_codecs: u16,
    pub(super) codec_ready_after_resets: u8,
    pub(super) drop_reply_until_resets: u8,
    pub(super) codec_vendor_overrides: BTreeMap<u8, u32>,
    pub(super) reset_exit_stuck: bool,
    pub(super) command_stop_stuck: bool,
    pub(super) corb_reset_stuck: bool,
    pub(super) stream_start_stuck: bool,
    pub(super) stream_stop_stuck: bool,
    pub(super) stream_reset_stuck: bool,
    pub(super) drop_reply: bool,
    pub(super) drop_reply_command: Option<u32>,
    pub(super) drop_reply_min_coefficient_writes: usize,
    pub(super) wrong_codec: bool,
    pub(super) inject_unsolicited: bool,
    pub(super) duplicate_reply: bool,
    pub(super) rirb_reset_stuck: bool,
    pub(super) response_backpressure: bool,
    pub(super) response_count: u16,
    pub(super) command_start_read_failure: Option<usize>,
    pub(super) command_started_once: bool,
    pub(super) control_read_failure: Option<(usize, usize)>,
    pub(super) control_failure_after_write: Option<(usize, u32, usize)>,
    pub(super) control_failure_active: bool,
    pub(super) control_failed_reads: usize,
    pub(super) binding_read_failure: bool,
    pub(super) commands: Vec<u32>,
    pub(super) command_times: Vec<(u32, u64)>,
    pub(super) constant_reply: Option<u32>,
    pub(super) parameters: BTreeMap<(u8, u8), u32>,
    pub(super) pin_defaults: BTreeMap<u8, u32>,
    pub(super) pin_senses: BTreeMap<u8, u32>,
    pub(super) conexant_headset_model: bool,
    pub(super) conexant_detection_ready: Option<u64>,
    pub(super) conexant_detection_reads: usize,
    pub(super) conexant_type: u32,
    pub(super) conexant_vendor_fault: Option<u16>,
    pub(super) conexant_trim: Option<u16>,
    pub(super) conexant_mic_writes: usize,
    pub(super) conexant_mic_fault_after: Option<usize>,
    pub(super) sense_triggers: Vec<u8>,
    pub(super) coefficient_indexes: BTreeMap<u8, u16>,
    pub(super) coefficients: BTreeMap<(u8, u16), u16>,
    pub(super) coefficient_read_fault: Option<u32>,
    pub(super) coefficient_fault_after_write: bool,
    pub(super) coefficient_fault_node: Option<u8>,
    pub(super) coefficient_fault_write_threshold: usize,
    pub(super) coefficient_write_nodes: BTreeMap<u8, usize>,
    pub(super) coefficient_events: Vec<(u8, u16, u16, u64)>,
    pub(super) depop_started_at: Option<u64>,
    pub(super) depop_delay_us: Option<u64>,
    pub(super) depop_mutate_saved: bool,
    pub(super) coefficient_index_failed: bool,
    pub(super) coefficient_index_reply: Option<(u8, u32)>,
    pub(super) reject_coefficient_write: bool,
    pub(super) reject_coefficient_node: Option<u8>,
    pub(super) coefficient_writes: usize,
    pub(super) connection_words: BTreeMap<(u8, u8), u32>,
    pub(super) formats: BTreeMap<u8, u16>,
    pub(super) bindings: BTreeMap<u8, u8>,
    pub(super) route_controls: BTreeMap<(u8, u16), u8>,
    pub(super) amplifiers: BTreeMap<(u8, bool, u8, u8), u8>,
    pub(super) outputs_without_hardware_mute: Vec<u8>,
    pub(super) stac922x_capture_amp: bool,
    pub(super) reject_amplifier_channel: Option<(u8, u8)>,
    pub(super) idt83_amplifier_mode: Option<u8>,
    pub(super) idt83_amplifier_reply: u32,
    pub(super) idt83_power_map: u32,
    pub(super) idt83_map_requires_d0: bool,
    pub(super) idt73_model: bool,
    pub(super) idt73_gpio_input_after_write: Option<usize>,
    pub(super) cirrus_model: bool,
    pub(super) cirrus_cs4208_model: bool,
    pub(super) cirrus_cs4210_model: bool,
    pub(super) cirrus_cs4210_stage: u8,
    pub(super) cirrus_cs4210_invalid: bool,
    pub(super) cirrus_errata_stage: u8,
    pub(super) cirrus_errata_powered: [bool; 2],
    pub(super) cirrus_errata_complete: bool,
    pub(super) cirrus_errata_invalid: bool,
    pub(super) cirrus_early_coefficient_reads: usize,
    pub(super) adc_amp_index_zero: Vec<u8>,
    pub(super) codec_power_model: bool,
    pub(super) codec_requested_power: BTreeMap<u8, u8>,
    pub(super) codec_actual_power: BTreeMap<u8, u8>,
    pub(super) power_ready: BTreeMap<u8, u64>,
    pub(super) power_delay: u64,
    pub(super) power_stuck: bool,
    pub(super) power_error: bool,
    pub(super) reject_route_control: Option<u16>,
    pub(super) reject_route_after_write: bool,
    pub(super) reject_route_write_threshold: usize,
    pub(super) route_control_writes: BTreeMap<(u8, u16), usize>,
    pub(super) reject_route_node: Option<u8>,
    pub(super) reject_amplifier: bool,
    pub(super) last_dma_time: u64,
    pub(super) dma_step_bytes: usize,
    pub(super) playback: Vec<u8>,
    pub(super) capture_counter: u8,
    pub(super) stream_descriptors_seen: usize,
    pub(super) reads: usize,
    pub(super) writes: Vec<(usize, u32, usize)>,
}

impl Model {
    pub(super) fn new(entries: u16) -> Rc<RefCell<Self>> {
        let clock = ModelClock(Rc::new(Cell::new(0)));
        let mut model = Self {
            bytes: vec![0; 0x440],
            link_controls: Vec::new(),
            link_down_stuck: false,
            link_up_stuck: false,
            reject_link_clock: false,
            link_clock_lost_on_power_up: false,
            link_reads: BTreeMap::new(),
            clock,
            hardware_delay: 2,
            consume_delay: 2,
            response_delay: 3,
            next_consume: 0,
            events: Vec::new(),
            replies: Vec::new(),
            self_clear: false,
            reset_enter_stuck: false,
            reset_gate: None,
            link_initializations: 0,
            advertised_codecs: 1,
            codec_ready_after_resets: 0,
            drop_reply_until_resets: 0,
            codec_vendor_overrides: BTreeMap::new(),
            reset_exit_stuck: false,
            command_stop_stuck: false,
            corb_reset_stuck: false,
            stream_start_stuck: false,
            stream_stop_stuck: false,
            stream_reset_stuck: false,
            drop_reply: false,
            drop_reply_command: None,
            drop_reply_min_coefficient_writes: 0,
            wrong_codec: false,
            inject_unsolicited: false,
            duplicate_reply: false,
            rirb_reset_stuck: false,
            response_backpressure: false,
            response_count: 0,
            command_start_read_failure: None,
            command_started_once: false,
            control_read_failure: None,
            control_failure_after_write: None,
            control_failure_active: false,
            control_failed_reads: 0,
            binding_read_failure: false,
            commands: Vec::new(),
            command_times: Vec::new(),
            constant_reply: Some(0x1234_abcd),
            parameters: BTreeMap::new(),
            pin_defaults: BTreeMap::new(),
            pin_senses: BTreeMap::new(),
            conexant_headset_model: false,
            conexant_detection_ready: None,
            conexant_detection_reads: 0,
            conexant_type: 0,
            conexant_vendor_fault: None,
            conexant_trim: None,
            conexant_mic_writes: 0,
            conexant_mic_fault_after: None,
            sense_triggers: Vec::new(),
            coefficient_indexes: BTreeMap::new(),
            coefficients: BTreeMap::new(),
            coefficient_read_fault: None,
            coefficient_fault_after_write: false,
            coefficient_fault_node: None,
            coefficient_fault_write_threshold: 1,
            coefficient_write_nodes: BTreeMap::new(),
            coefficient_events: Vec::new(),
            depop_started_at: None,
            depop_delay_us: Some(0),
            depop_mutate_saved: false,
            coefficient_index_failed: false,
            coefficient_index_reply: None,
            reject_coefficient_write: false,
            reject_coefficient_node: None,
            coefficient_writes: 0,
            connection_words: BTreeMap::new(),
            formats: BTreeMap::new(),
            bindings: BTreeMap::new(),
            route_controls: BTreeMap::new(),
            amplifiers: BTreeMap::new(),
            outputs_without_hardware_mute: Vec::new(),
            stac922x_capture_amp: false,
            reject_amplifier_channel: None,
            idt83_amplifier_mode: None,
            idt83_amplifier_reply: 0,
            idt83_power_map: 0,
            idt83_map_requires_d0: false,
            idt73_model: false,
            idt73_gpio_input_after_write: None,
            cirrus_model: false,
            cirrus_cs4208_model: false,
            cirrus_cs4210_model: false,
            cirrus_cs4210_stage: 0,
            cirrus_cs4210_invalid: false,
            cirrus_errata_stage: 0,
            cirrus_errata_powered: [false; 2],
            cirrus_errata_complete: false,
            cirrus_errata_invalid: false,
            cirrus_early_coefficient_reads: 0,
            adc_amp_index_zero: Vec::new(),
            codec_power_model: false,
            codec_requested_power: BTreeMap::new(),
            codec_actual_power: BTreeMap::new(),
            power_ready: BTreeMap::new(),
            power_delay: 12,
            power_stuck: false,
            power_error: false,
            reject_route_control: None,
            reject_route_after_write: false,
            reject_route_write_threshold: 1,
            route_control_writes: BTreeMap::new(),
            reject_route_node: None,
            reject_amplifier: false,
            last_dma_time: 0,
            dma_step_bytes: 0,
            playback: Vec::new(),
            capture_counter: 0,
            stream_descriptors_seen: 0,
            reads: 0,
            writes: Vec::new(),
        };
        model.set(VMAJ, 1, 1);
        model.set(GCAP, (2 << 12) | (2 << 8) | 1, 2);
        model.set(OUTPAY, 60, 2);
        model.set(INPAY, 29, 2);
        model.set(GCTL, GCTL_RESET, 4);
        let capability = match entries {
            2 => 1 << 4,
            16 => 1 << 5,
            256 => 1 << 6,
            _ => panic!(),
        };
        model.set(CORBSIZE, capability, 1);
        model.set(RIRBSIZE, capability, 1);
        Rc::new(RefCell::new(model))
    }

    pub(super) fn get(&self, offset: usize, bytes: usize) -> u32 {
        (0..bytes).fold(0, |value, index| {
            value | (u32::from(self.bytes[offset + index]) << (index * 8))
        })
    }
    pub(super) fn set(&mut self, offset: usize, value: u32, bytes: usize) {
        for index in 0..bytes {
            self.bytes[offset + index] = (value >> (index * 8)) as u8;
        }
    }
    pub(super) fn size(&self, offset: usize) -> u16 {
        match self.bytes[offset] & 3 {
            0 => 2,
            1 => 16,
            2 => 256,
            _ => panic!(),
        }
    }
    pub(super) fn address(&self, low: usize, high: usize) -> u64 {
        u64::from(self.get(low, 4)) | (u64::from(self.get(high, 4)) << 32)
    }

    pub(super) fn advance(&mut self) {
        let now = self.clock.now_us();
        let mut index = 0;
        while index < self.events.len() {
            if self.events[index].due > now {
                index += 1;
                continue;
            }
            let event = self.events.remove(index);
            let was_reset = self.get(GCTL, 4) & GCTL_RESET == 0;
            let event_value = if self.link_controls.contains(&event.offset) {
                (self.get(event.offset, 4) & !(1 << 23)) | (event.value & (1 << 23))
            } else {
                event.value
            };
            self.set(event.offset, event_value, event.bytes);
            if event.offset == GCTL && event.value & GCTL_RESET == 0 {
                self.replies.clear(); // Link reset discards in-flight codec responses.
                self.route_controls.retain(|(_, verb), _| *verb != 0xf08);
            }
            if event.offset == GCTL && event.value & GCTL_RESET != 0 && was_reset {
                self.link_initializations += 1;
                self.set(STATESTS, u32::from(self.advertised_codecs), 2);
            }
        }
        let response_limit = match self.get(RINTCNT, 2) as u16 {
            0 => 256,
            value => value,
        };
        if self.bytes[CORBCTL] & COMMAND_RUN != 0
            && now >= self.next_consume
            && (!self.response_backpressure || self.response_count < response_limit)
        {
            let rp = self.get(CORBRP, 2) as u16;
            let wp = self.get(CORBWP, 2) as u16;
            if rp < self.size(CORBSIZE) && rp != wp {
                let next = (rp + 1) % self.size(CORBSIZE);
                let address = self.address(CORBLBASE, CORBUBASE);
                assert_ne!(address, 0);
                // SAFETY: the controller allocated this aligned CORB in kept
                // fixture RAM. next is reduced to the selected ring size, and
                // register polling serializes CPU and modeled device access.
                let command =
                    unsafe { ((address as *const u32).add(usize::from(next))).read_volatile() }
                        .to_le();
                self.commands.push(command);
                self.command_times.push((command, now));
                self.set(CORBRP, u32::from(next), 2);
                self.next_consume = now + self.consume_delay;
                let response = self.reply_for(command);
                if self.answers(command) {
                    let codec = if self.wrong_codec { 1 } else { command >> 28 };
                    if self.inject_unsolicited {
                        self.replies.push(Reply {
                            due: now + self.response_delay,
                            value: 0xaaaa_5555,
                            extra: codec | RESPONSE_UNSOL,
                        });
                    }
                    self.replies.push(Reply {
                        due: now + self.response_delay,
                        value: response,
                        extra: codec,
                    });
                    if self.duplicate_reply {
                        self.replies.push(Reply {
                            due: now + self.response_delay,
                            value: response,
                            extra: codec,
                        });
                    }
                }
            }
        }
        if self.bytes[RIRBCTL] & COMMAND_RUN != 0 {
            let mut index = 0;
            while index < self.replies.len() {
                if self.replies[index].due > now {
                    index += 1;
                    continue;
                }
                let reply = self.replies.remove(index);
                self.emit(reply.value, reply.extra);
            }
        }
        if now != self.last_dma_time {
            self.last_dma_time = now;
            if self.dma_step_bytes != 0 {
                for index in 0..4 {
                    if self.bytes[stream_base(index) + SD_CTL] & SD_RUN != 0 {
                        self.dma_stream(index);
                    }
                }
            }
        }
    }

    pub(super) fn answers(&self, command: u32) -> bool {
        !self.drop_reply
            && !(self.drop_reply_command == Some(command)
                && self.coefficient_writes >= self.drop_reply_min_coefficient_writes)
            && self.link_initializations >= self.drop_reply_until_resets
    }

    /// The immediate command interface answers synchronously.
    pub(super) fn immediate(&mut self, status: u32) {
        let mut status = status & !u32::from(IRS_BUSY);
        let command = self.get(IC, 4);
        self.commands.push(command);
        let response = self.reply_for(command);
        if self.answers(command) {
            self.set(IR, response, 4);
            status |= u32::from(IRS_VALID);
        }
        self.set(IRS, status, 2);
    }

    pub(super) fn emit(&mut self, value: u32, extra: u32) {
        let next = (self.get(RIRBWP, 2) as u16 + 1) % self.size(RIRBSIZE);
        let address = self.address(RIRBLBASE, RIRBUBASE);
        assert_ne!(address, 0);
        // SAFETY: address names the RIRB allocation. next is modulo
        // the ring size and its entry has two aligned u32 words; emission is
        // synchronous with the controller's register polling.
        unsafe {
            ((address as *mut u32).add(usize::from(next) * 2)).write_volatile(value.to_le());
            ((address as *mut u32).add(usize::from(next) * 2 + 1)).write_volatile(extra.to_le());
        }
        self.set(RIRBWP, u32::from(next), 2);
        self.response_count += 1;
        if self.bytes[RIRBCTL] & RIRB_RESPONSE_ENABLE != 0 {
            self.bytes[RIRBSTS] |= RIRB_RESPONSE;
        }
    }

    pub(super) fn write(&mut self, offset: usize, value: u32, bytes: usize) {
        self.advance();
        self.writes.push((offset, value, bytes));
        if self.control_failure_after_write == Some((offset, value, bytes)) {
            self.control_failure_active = true;
        }
        if offset == STATESTS
            || offset == CORBSTS
            || offset == RIRBSTS
            || (offset >= 0x80 && (offset - 0x80) % 0x20 == SD_STS)
        {
            let old = self.get(offset, bytes);
            if offset == RIRBSTS && old & value & u32::from(RIRB_RESPONSE) != 0 {
                self.response_count = 0;
            }
            self.set(offset, old & !value, bytes);
            return;
        }
        if offset == CORBSIZE || offset == RIRBSIZE {
            self.bytes[offset] = (self.bytes[offset] & 0x70) | (value as u8 & 3);
            return;
        }
        if offset == IRS {
            let status = self.get(IRS, 2) & !(value & u32::from(IRS_VALID));
            if value & u32::from(IRS_BUSY) != 0 {
                self.immediate(status);
            } else {
                self.set(IRS, status, 2);
            }
            return;
        }
        if offset == CORBRP {
            if self.corb_reset_stuck {
                return;
            }
            self.set(offset, if self.self_clear { 0 } else { value }, bytes);
            return;
        }
        if offset == RIRBWP && value & u32::from(POINTER_RESET) != 0 {
            if !self.rirb_reset_stuck {
                self.set(offset, 0, bytes);
            }
            return;
        }
        if self.link_controls.contains(&offset) {
            assert_eq!(bytes, 4);
            let old = self.get(offset, 4);
            let mut stored = (value & !(1 << 23)) | (old & (1 << 23));
            if value & 15 != old & 15 {
                assert_eq!(
                    old & ((1 << 16) | (1 << 23)),
                    0,
                    "SCF changed before link acknowledged off"
                );
                if self.reject_link_clock {
                    stored = (stored & !15) | (old & 15);
                }
            }
            if value & (1 << 16) != 0 && self.link_clock_lost_on_power_up {
                stored &= !15;
            }
            self.set(offset, stored, 4);
            if !(value & (1 << 16) == 0 && self.link_down_stuck
                || value & (1 << 16) != 0 && self.link_up_stuck)
            {
                self.events.push(Event {
                    due: self.clock.now_us() + self.hardware_delay,
                    offset,
                    value: if value & (1 << 16) != 0 {
                        stored | (1 << 23)
                    } else {
                        stored & !(1 << 23)
                    },
                    bytes: 4,
                });
            }
            return;
        }
        if offset == GCTL {
            if self.get(GCTL, 4) & GCTL_RESET == value & GCTL_RESET {
                // Ordinary UNSOL gate writes are immediate native-width
                // controls; only CRST transitions use the reset handshake.
                self.set(offset, value, bytes);
                return;
            }
            if let Some(gate) = &self.reset_gate {
                assert!(
                    !gate.get(),
                    "GCTL written while mandatory PCI clock gating remained enabled"
                );
            }
            if (value & GCTL_RESET == 0 && self.reset_enter_stuck)
                || (value & GCTL_RESET != 0 && self.reset_exit_stuck)
            {
                return;
            }
            self.events.push(Event {
                due: self.clock.now_us() + self.hardware_delay,
                offset,
                value,
                bytes,
            });
            return;
        }
        if (offset == CORBCTL || offset == RIRBCTL)
            && value & u32::from(COMMAND_RUN) == 0
            && self.command_stop_stuck
        {
            return;
        }
        if offset >= 0x80 && (offset - 0x80).is_multiple_of(0x20) {
            assert_eq!(bytes, 1, "wide SD_CTL access aliases W1C status");
            let old = self.bytes[offset];
            if value as u8 & SD_RESET != 0 {
                if self.stream_reset_stuck {
                    return;
                }
                self.set(offset + SD_LPIB, 0, 4);
            }
            if (value as u8 & SD_RUN != 0 && self.stream_start_stuck)
                || (old & SD_RUN != 0 && value as u8 & SD_RUN == 0 && self.stream_stop_stuck)
            {
                return;
            }
            self.events.push(Event {
                due: self.clock.now_us() + self.hardware_delay,
                offset,
                value,
                bytes,
            });
            return;
        }
        self.set(offset, value, bytes);
        if offset == CORBCTL
            && value & u32::from(COMMAND_RUN) != 0
            && self.bytes[RIRBCTL] & COMMAND_RUN != 0
        {
            self.command_started_once = true;
        }
    }

    pub(super) fn dma_stream(&mut self, index: u8) {
        let base = stream_base(index);
        let cbl = self.get(base + SD_CBL, 4) as usize;
        let lvi = self.get(base + SD_LVI, 2) as usize;
        let bdl = self.address(base + SD_BDLPL, base + SD_BDLPU);
        assert!(bdl.is_multiple_of(128) && bdl != 0 && lvi < 256);
        let mut descriptors = Vec::new();
        let mut total = 0;
        for entry in 0..=lvi {
            // SAFETY: bdl names the fixture-backed descriptor list. entry is
            // bounded by its programmed LVI, and the controller emits aligned
            // 16-byte descriptors kept throughout this synchronous transfer.
            let (address, len, ioc) = unsafe {
                let ptr = (bdl as *const u8).add(entry * 16);
                (
                    (ptr as *const u64).read_volatile(),
                    (ptr.add(8) as *const u32).read_volatile(),
                    (ptr.add(12) as *const u32).read_volatile(),
                )
            };
            let len = len as usize;
            assert!(address.is_multiple_of(128) && len != 0 && len.is_multiple_of(128));
            assert!(
                (address as usize & 4095) + len <= 4096,
                "4K BDLE boundary crossed"
            );
            assert!(ioc <= 1);
            descriptors.push((address, len, ioc));
            total += len;
        }
        assert_eq!(total, cbl);
        self.stream_descriptors_seen += descriptors.len();
        let mut position = self.get(base + SD_LPIB, 4) as usize;
        for _ in 0..self.dma_step_bytes {
            let mut start = 0;
            let &(address, length, ioc) = descriptors
                .iter()
                .find(|(_, length, _)| {
                    let inside = position < start + length;
                    if !inside {
                        start += length;
                    }
                    inside
                })
                .unwrap();
            let address = (address + (position - start) as u64) as *mut u8;
            if index < 2 {
                // SAFETY: position selects a byte within the PCM
                // descriptor above. Capture and CPU buffer access are serialized
                // by the controller's synchronous polling and stopped-buffer API.
                unsafe {
                    address.write_volatile(self.capture_counter);
                }
                self.capture_counter = self.capture_counter.wrapping_add(1);
            } else {
                // SAFETY: address is within the selected PCM extent;
                // playback reads run synchronously with register polling.
                self.playback.push(unsafe { address.read_volatile() });
            }
            position += 1;
            if position == start + length && ioc != 0 {
                self.bytes[base + SD_STS] |= SD_COMPLETE;
            }
            if position == cbl {
                position = 0;
            }
        }
        self.set(base + SD_LPIB, position as u32, 4);
    }
}

#[derive(Clone)]
pub(super) struct ModelRegisters(pub(super) Rc<RefCell<Model>>);
impl Registers for ModelRegisters {
    fn region_bytes(&self) -> usize {
        self.0.borrow().bytes.len()
    }
    fn read8(&mut self, offset: usize) -> u8 {
        let mut m = self.0.borrow_mut();
        m.reads += 1;
        m.advance();
        if (m.command_started_once && m.command_start_read_failure == Some(offset))
            || (m.control_failure_active && m.control_read_failure == Some((offset, 1)))
        {
            return u8::MAX;
        }
        m.get(offset, 1) as u8
    }
    fn read16(&mut self, offset: usize) -> u16 {
        let mut m = self.0.borrow_mut();
        m.reads += 1;
        m.advance();
        if m.control_failure_active && m.control_read_failure == Some((offset, 2)) {
            return u16::MAX;
        }
        m.get(offset, 2) as u16
    }
    fn read32(&mut self, offset: usize) -> u32 {
        let mut m = self.0.borrow_mut();
        if m.link_controls.contains(&offset) {
            *m.link_reads.entry(offset).or_default() += 1;
        }
        m.reads += 1;
        m.advance();
        if m.control_failure_active && m.control_read_failure == Some((offset, 4)) {
            m.control_failed_reads += 1;
            return u32::MAX;
        }
        m.get(offset, 4)
    }
    fn write8(&mut self, offset: usize, value: u8) {
        self.0.borrow_mut().write(offset, u32::from(value), 1);
    }
    fn write16(&mut self, offset: usize, value: u16) {
        self.0.borrow_mut().write(offset, u32::from(value), 2);
    }
    fn write32(&mut self, offset: usize, value: u32) {
        self.0.borrow_mut().write(offset, value, 4);
    }
}

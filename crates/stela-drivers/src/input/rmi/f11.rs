// SPDX-License-Identifier: GPL-2.0-only
//! Ordinary five-byte F11 absolute/relative reports and native controls.
//! Pinned source and retained copyrights are in input/THIRD_PARTY.md.
use super::{
    Error, Function,
    transport::{Transport, buffer},
};
use crate::bus::i2c::Timer;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Configuration {
    pub dribble: Option<bool>,
    pub palm_detect: Option<bool>,
    pub delta_x_threshold: Option<u8>,
    pub delta_y_threshold: Option<u8>,
    pub prefer_relative: bool,
    pub rezero_wait_us: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    pub number: u8,
    pub address: u16,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub function: Function,
    pub queries: Vec<Query>,
    pub controls: [u8; 12],
    pub fingers: usize,
    pub has_absolute: bool,
    pub has_relative: bool,
    pub maximum: (u16, u16),
    pub dimensions_mm: Option<(u16, u16)>,
    pub general_information2: Option<u8>,
    pub reports_absolute: bool,
    pub packet_size: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contact {
    pub object_index: u8,
    /// Exact two-bit state:0 absent,1 present,2 inaccurate,3 reserved.
    pub state: u8,
    pub x: u16,
    pub y: u16,
    pub pressure: u8,
    pub width_x: u8,
    pub width_y: u8,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub function: Function,
    pub contacts: Vec<Contact>,
    pub relative: Vec<(i8, i8)>,
    /// Includes exact gesture, pinch/flick/rotation and shape bytes.
    pub raw_packet: Vec<u8>,
}
struct Reader<'a, X> {
    transport: &'a mut X,
    base: u16,
    offset: usize,
    queries: Vec<Query>,
}
impl<X: Transport> Reader<'_, X> {
    fn take(&mut self, number: u8, length: usize) -> Result<&[u8], Error> {
        let address = register(self.base, self.offset)?;
        let mut bytes = buffer(length)?;
        self.queries.try_reserve(1).map_err(|_| Error::Allocation)?;
        self.transport.read(address, &mut bytes)?;
        self.offset += length;
        self.queries.push(Query {
            number,
            address,
            bytes,
        });
        Ok(&self.queries[self.queries.len() - 1].bytes)
    }
}
// These advertised extensions add records or change widths whose wire layout
// is not implemented by this ordinary-format engine.
fn extension(query: u8, flags: u8, unsupported: u8) -> Result<(), Error> {
    if flags & unsupported != 0 {
        return Err(Error::UnsupportedF11Extension {
            query,
            flags: flags & unsupported,
        });
    }
    Ok(())
}
fn register(base: u16, offset: usize) -> Result<u16, Error> {
    u16::try_from(usize::from(base) + offset).map_err(|_| Error::RegisterDescriptor)
}
pub(super) struct Engine {
    pub(super) capabilities: Capabilities,
    configuration: Configuration,
    relative_offset: usize,
    interrupt_offset: u16,
}
impl Engine {
    pub(super) fn configure<X: Transport>(
        transport: &mut X,
        function: Function,
        configuration: Configuration,
    ) -> Result<Self, Error> {
        let mut reader = Reader {
            transport,
            base: function.query,
            offset: 0,
            queries: Vec::new(),
        };
        let general = reader.take(0, 1)?[0];
        let query1 = reader.take(1, 4)?[0];
        let has_relative = query1 & 8 != 0;
        let has_absolute = query1 & 16 != 0;
        if !has_absolute && !has_relative {
            return Err(Error::UnsupportedFormat {
                function: 0x11,
                format: query1,
            });
        }
        let fingers = if query1 & 7 == 5 {
            10
        } else {
            usize::from(query1 & 7) + 1
        };
        let abs_query = if has_absolute {
            reader.take(5, 1)?[0]
        } else {
            0
        };
        if abs_query & 3 != 0 {
            return Err(Error::UnsupportedFormat {
                function: 0x11,
                format: abs_query & 3,
            });
        }
        extension(5, abs_query, 0x60)?;
        if has_relative {
            reader.take(6, 1)?;
        }
        let (gesture7, gesture8) = if query1 & 32 != 0 {
            let bytes = reader.take(7, 2)?;
            (bytes[0], bytes[1])
        } else {
            (0, 0)
        };
        extension(7, gesture7, 0x80)?;
        extension(8, gesture8, 0xf8)?;
        if general & 8 != 0 {
            let flags = reader.take(9, 1)?[0];
            extension(9, flags, 0x60)?;
        }
        let shapes = if gesture8 & 4 != 0 {
            Some(reader.take(10, 1)?[0] & 31)
        } else {
            None
        };
        if general & 16 != 0 {
            reader.take(11, 1)?;
        }
        let query12 = if general & 32 != 0 {
            reader.take(12, 1)?[0]
        } else {
            0
        };
        extension(12, query12, 0x06)?;
        if abs_query & 128 != 0 {
            reader.take(13, 1)?;
        }
        let general_information2 = if query12 & 16 != 0 {
            Some(reader.take(14, 1)?[0])
        } else {
            None
        };
        let dimensions_mm = if query12 & 32 != 0 {
            let bytes = reader.take(15, 4)?;
            let dimensions = (
                u16::from_le_bytes([bytes[0], bytes[1]]) / 10,
                u16::from_le_bytes([bytes[2], bytes[3]]) / 10,
            );
            reader.offset += 8; // advertised bezel queries19..26, not consumed
            Some(dimensions)
        } else {
            None
        };
        if general & 64 != 0 {
            reader.offset += 1;
        }
        if general & 128 != 0 {
            let query28 = reader.take(28, 1)?[0];
            if query28 & 64 != 0 {
                reader.offset += 1;
                let flags = reader.take(36, 1)?[0];
                extension(36, flags, 0x20)?;
            }
        }
        let queries = reader.queries;
        let reports_absolute = has_absolute && !configuration.prefer_relative;
        if !reports_absolute && !has_relative {
            return Err(Error::UnsupportedFormat {
                function: 0x11,
                format: query1,
            });
        }
        let interrupt_offset = u16::from(!reports_absolute);
        if u16::from(function.interrupt_count) <= interrupt_offset {
            return Err(Error::InterruptLimit);
        }
        let mut controls = [0; 12];
        transport.read(function.control, &mut controls)?;
        let maximum = (
            u16::from_le_bytes([controls[6], controls[7]]),
            u16::from_le_bytes([controls[8], controls[9]]),
        );
        if let Some(value) = configuration.delta_x_threshold {
            controls[2] = value;
        }
        if let Some(value) = configuration.delta_y_threshold {
            controls[3] = value;
        }
        if configuration
            .delta_x_threshold
            .is_some_and(|value| value != 0)
            || configuration
                .delta_y_threshold
                .is_some_and(|value| value != 0)
        {
            controls[0] = (controls[0] & !7) | 1;
        }
        if let Some(enabled) = configuration.dribble {
            if abs_query & 16 == 0 {
                return Err(Error::UnsupportedControl(0));
            }
            controls[0] = if enabled {
                controls[0] | 64
            } else {
                controls[0] & !64
            };
        }
        if let Some(enabled) = configuration.palm_detect {
            if gesture8 & 1 == 0 {
                return Err(Error::UnsupportedControl(11));
            }
            controls[11] = if enabled {
                controls[11] | 1
            } else {
                controls[11] & !1
            };
        }
        // Initialize the real control bank, never the read-only query bank.
        transport.write(function.control, &controls)?;
        let mut actual = [0; 12];
        transport.read(function.control, &mut actual)?;
        if actual != controls {
            return Err(Error::ConfigurationRejected);
        }
        let state_bytes = fingers.div_ceil(4);
        let relative_offset = state_bytes + if has_absolute { fingers * 5 } else { 0 };
        let mut packet_size = relative_offset + if has_relative { fingers * 2 } else { 0 };
        packet_size += usize::from(gesture7 != 0) + usize::from(gesture7 != 0 || gesture8 != 0);
        let pinch = gesture7 & 64 != 0;
        let flick = gesture7 & 16 != 0;
        let rotate = gesture8 & 2 != 0;
        // Follow the source's actual pointer layout: pinch aliases flick[0],
        // rotation aliases flick[1..3]. Without flick, pinch and rotation are
        // disjoint. The source's separate size formula undercounts some cases.
        packet_size += if flick {
            3
        } else {
            usize::from(pinch) + 2 * usize::from(rotate)
        };
        if let Some(shapes) = shapes {
            packet_size += (usize::from(shapes) + 1).div_ceil(8);
        }
        if packet_size > transport.maximum_read(function.data) {
            return Err(Error::AddressRange {
                address: function.data,
                length: packet_size,
            });
        }
        Ok(Self {
            capabilities: Capabilities {
                function,
                queries,
                controls,
                fingers,
                has_absolute,
                has_relative,
                maximum,
                dimensions_mm,
                general_information2,
                reports_absolute,
                packet_size,
            },
            configuration,
            relative_offset,
            interrupt_offset,
        })
    }
    pub(super) fn interrupt_bit(&self) -> u16 {
        self.capabilities.function.interrupt_start + self.interrupt_offset
    }
    pub(super) fn resume<X: Transport, T: Timer>(
        &self,
        transport: &mut X,
        timer: &T,
    ) -> Result<(), Error> {
        if self.configuration.rezero_wait_us != 0 {
            timer
                .check_duration(self.configuration.rezero_wait_us)
                .map_err(Error::Clock)?;
            let start = timer.start();
            while timer.elapsed_us(start) < self.configuration.rezero_wait_us {
                timer.relax();
            }
            transport.write(self.capabilities.function.command, &[1])?;
        }
        Ok(())
    }
    pub(super) fn read<X: Transport>(&self, transport: &mut X) -> Result<Frame, Error> {
        let capabilities = &self.capabilities;
        let mut raw_packet = buffer(capabilities.packet_size)?;
        transport.read(capabilities.function.data, &mut raw_packet)?;
        let mut contacts = Vec::new();
        let mut relative = Vec::new();
        if capabilities.has_absolute {
            contacts
                .try_reserve_exact(capabilities.fingers)
                .map_err(|_| Error::Allocation)?;
            let start = capabilities.fingers.div_ceil(4);
            for index in 0..capabilities.fingers {
                let bytes = &raw_packet[start + index * 5..start + (index + 1) * 5];
                contacts.push(Contact {
                    object_index: index as u8,
                    state: (raw_packet[index / 4] >> (2 * (index % 4))) & 3,
                    x: (u16::from(bytes[0]) << 4) | u16::from(bytes[2] & 15),
                    y: (u16::from(bytes[1]) << 4) | u16::from(bytes[2] >> 4),
                    pressure: bytes[4],
                    width_x: bytes[3] & 15,
                    width_y: bytes[3] >> 4,
                });
            }
        }
        if capabilities.has_relative {
            relative
                .try_reserve_exact(capabilities.fingers)
                .map_err(|_| Error::Allocation)?;
            for index in 0..capabilities.fingers {
                relative.push((
                    raw_packet[self.relative_offset + index * 2] as i8,
                    raw_packet[self.relative_offset + index * 2 + 1] as i8,
                ));
            }
        }
        Ok(Frame {
            function: capabilities.function,
            contacts,
            relative,
            raw_packet,
        })
    }
}

//! USB2 standard configuration observed through the actual EP0 transport.
use super::*;
use schedule::endpoint_index;
const MAX_CONFIGURATION: usize = 4096;

fn endpoints(bytes: &[u8]) -> Result<[bool; 32], Error> {
    if bytes.len() < 9
        || bytes[0] != 9
        || bytes[1] != 2
        || usize::from(u16::from_le_bytes([bytes[2], bytes[3]])) != bytes.len()
        || bytes[5] == 0
        || bytes[7] & 0x80 == 0
        || bytes[8] > 250
    {
        return Err(Error::Invalid);
    }
    let mut endpoints = [false; 32];
    let mut occupied = [false; 32];
    let mut alternates = [false; 256];
    let mut interfaces = [false; 256];
    let mut interface = None;
    let mut expected = 0;
    let mut observed = 0;
    let mut cursor = 9;
    while cursor < bytes.len() {
        let len = usize::from(bytes[cursor]);
        if len < 2 || cursor.checked_add(len).is_none_or(|end| end > bytes.len()) {
            return Err(Error::Invalid);
        }
        let record = &bytes[cursor..cursor + len];
        match record[1] {
            4 => {
                if len < 9 {
                    return Err(Error::Invalid);
                }
                if interface.is_some_and(|alternate| alternate == 0) && observed != expected {
                    return Err(Error::Invalid);
                }
                let number = usize::from(record[2]);
                let alternate = record[3];
                if alternate != 0 {
                    alternates[number] = true;
                }
                if alternate == 0 {
                    if interfaces[number] {
                        return Err(Error::Invalid);
                    }
                    interfaces[number] = true;
                }
                interface = Some(alternate);
                expected = record[4];
                observed = 0;
            }
            5 => {
                if len < 7 || interface.is_none() {
                    return Err(Error::Invalid);
                }
                observed = observed.checked_add(1).ok_or(Error::Invalid)?;
                if interface == Some(0) {
                    let endpoint = record[2];
                    if endpoint & 0x70 != 0 || endpoint & 15 == 0 {
                        return Err(Error::Invalid);
                    }
                    let address = endpoint_index(endpoint);
                    if occupied[address] {
                        return Err(Error::Invalid);
                    }
                    occupied[address] = true;
                    let kind = record[3] & 3;
                    if kind == 0 || record[3] & 0xc0 != 0 || (kind != 1 && record[3] & 0xfc != 0) {
                        return Err(Error::Invalid);
                    }
                    if kind == 2 {
                        // USB2 HS bulk wMaxPacketSize is exactly512, no multiplier.
                        if u16::from_le_bytes([record[4], record[5]]) != 512 || record[3] != 2 {
                            return Err(Error::Invalid);
                        }
                        let index = endpoint_index(endpoint);
                        if endpoints[index] {
                            return Err(Error::Invalid);
                        }
                        endpoints[index] = true;
                    }
                }
            }
            2 => return Err(Error::Invalid),
            _ => (), // Class/IAD/HID descriptors grant no transport capability.
        }
        cursor += len;
    }
    if interface.is_some_and(|alternate| alternate == 0) && observed != expected
        || interfaces.iter().filter(|value| **value).count() != usize::from(bytes[4])
        || alternates
            .iter()
            .zip(interfaces)
            .any(|(alternate, default)| *alternate && !default)
    {
        return Err(Error::Invalid);
    }
    Ok(endpoints)
}
impl Controller {
    /// Fetch one real configuration by descriptor index, validate its default
    /// alternate interfaces and HS bulk endpoints, then select its actual value
    /// over USB. Successful configuration invalidates every previous BulkPipe.
    pub fn configure(
        &mut self,
        id: &DeviceId,
        descriptor_index: u8,
    ) -> Result<Vec<BulkPipe>, Error> {
        let index = self.identity(id)?;
        let device = self.ports[index].as_ref().expect("validated");
        if device.address == 0 {
            return Err(Error::Invalid);
        }
        let configuration = device
            .configuration
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        let header =
            self.control_internal(id, [0x80, 6, descriptor_index, 2, 0, 0, 9, 0], &[], 9)?;
        if header.len() != 9 || header[0] != 9 || header[1] != 2 {
            return Err(Error::Invalid);
        }
        let bytes = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if !(9..=MAX_CONFIGURATION).contains(&bytes) {
            return Err(Error::Unsupported("EHCI configuration descriptor size"));
        }
        let length = (bytes as u16).to_le_bytes();
        let description = self.control_internal(
            id,
            [0x80, 6, descriptor_index, 2, 0, 0, length[0], length[1]],
            &[],
            bytes,
        )?;
        if description.get(..9) != Some(header.as_slice()) {
            return Err(Error::Invalid);
        }
        let admitted = endpoints(&description)?;
        let mut pipes = Vec::new();
        pipes
            .try_reserve_exact(admitted.iter().filter(|value| **value).count())
            .map_err(|_| Error::Exhausted)?;
        for (endpoint, admitted) in admitted.iter().copied().enumerate() {
            if admitted {
                let endpoint = (endpoint & 15) as u8 | if endpoint >= 16 { 0x80 } else { 0 };
                pipes.push(BulkPipe {
                    device: id.clone(),
                    configuration,
                    endpoint,
                });
            }
        }
        // Old pipe admission is revoked before a state-changing request that
        // might complete on the bus despite a later host-side error.
        self.ports[index].as_mut().expect("retained").configuration = configuration;
        self.ports[index].as_mut().expect("retained").endpoints = [None; 32];
        self.control_internal(id, [0, 9, description[5], 0, 0, 0, 0, 0], &[], 0)?;
        for pipe in &pipes {
            self.ports[index].as_mut().expect("live").endpoints[endpoint_index(pipe.endpoint)] =
                Some(Endpoint {
                    toggle: false,
                    ping: false,
                    halted: false,
                });
        }
        Ok(pipes)
    }
}

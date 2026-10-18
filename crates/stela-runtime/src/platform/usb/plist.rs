//! Four-byte big-endian length framing, separate from mux/USB boundaries.
//! libimobiledevice fa0f7919 `src/property_list_service.c` sends the XML or
//! binary plist length before its bytes. This helper preserves opaque payloads;
//! it does not interpret or invent a guest service response.
use alloc::vec::Vec;
pub const MAX_PLIST: usize = 1024 * 1024;
pub const QUERY_TYPE: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>Request</key><string>QueryType</string></dict></plist>";

pub fn frame(bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_PLIST {
        return Err("plist payload length out of bounds");
    }
    let mut result = Vec::with_capacity(4 + bytes.len());
    result.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    result.extend_from_slice(bytes);
    Ok(result)
}
#[derive(Default)]
pub struct Channel {
    prefix: [u8; 4],
    used: usize,
    length: Option<usize>,
    payload: Vec<u8>,
}
impl Channel {
    /// Returns the consumed prefix and at most one complete plist. Call again
    /// on the remaining input to consume coalesced messages with backpressure.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<(usize, Option<Vec<u8>>), &'static str> {
        let mut consumed = 0;
        while self.used < 4 && consumed < bytes.len() {
            self.prefix[self.used] = bytes[consumed];
            self.used += 1;
            consumed += 1;
        }
        if self.used < 4 {
            return Ok((consumed, None));
        }
        if self.length.is_none() {
            let length = u32::from_be_bytes(self.prefix) as usize;
            if length == 0 || length > MAX_PLIST {
                return Err("plist payload length out of bounds");
            }
            self.length = Some(length);
        }
        let length = self.length.unwrap();
        let count = (length - self.payload.len()).min(bytes.len() - consumed);
        self.payload
            .extend_from_slice(&bytes[consumed..consumed + count]);
        consumed += count;
        if self.payload.len() != length {
            return Ok((consumed, None));
        }
        let payload = core::mem::take(&mut self.payload);
        self.used = 0;
        self.length = None;
        Ok((consumed, Some(payload)))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragmented_and_coalesced_length_prefixes_preserve_bytes() {
        let wire = frame(QUERY_TYPE).unwrap();
        let mut channel = Channel::default();
        let mut answer = None;
        for byte in &wire {
            let (consumed, plist) = channel.receive(&[*byte]).unwrap();
            assert_eq!(consumed, 1);
            if plist.is_some() {
                answer = plist;
            }
        }
        assert_eq!(answer.unwrap(), QUERY_TYPE);
        let mut combined = wire.clone();
        combined.extend_from_slice(&wire);
        let (consumed, plist) = channel.receive(&combined).unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(plist.unwrap(), QUERY_TYPE);
        assert!(channel.receive(&combined[consumed..]).unwrap().1.is_some());
    }
    #[test]
    fn refuses_lengths_before_allocating_payloads() {
        for length in [0, u32::MAX, (MAX_PLIST + 1) as u32] {
            let mut channel = Channel::default();
            assert!(channel.receive(&length.to_be_bytes()).is_err());
            assert_eq!(channel.payload.capacity(), 0);
        }
        assert!(frame(&[]).is_err());
    }
}

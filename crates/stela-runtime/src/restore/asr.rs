//! ASR negotiation and raw transfer (pinned idevicerestore asr.c). No length
//! prefix surrounds XML; checksum SHA-1 covers each 128-KiB payload chunk,
//! including the final short chunk. It is not an Image4 trust check.
use super::{
    Error, Result,
    plist::{self, Limits, Value},
    store::Store,
    stream::{ByteStream, Output, XmlStream},
};
use crate::payload::ReadAt;
use alloc::{string::String, vec::Vec};
use core::task::Poll;
use sha1::{Digest, Sha1};
pub const PORT: u16 = 12345;
pub const CHUNK_BYTES: usize = 128 * 1024;
const SHA1_BYTES: usize = 20;
const PACKET_BYTES: u64 = 1450;
const FEC_STRIDE: u64 = 40;
const PACKETS_PER_FEC: u64 = 25;
pub trait ImageSource {
    fn size(&self, component: &str) -> Result<u64>;
    /// Returns exactly len bytes, or fails. Must preserve source identity.
    fn read_at(&mut self, component: &str, offset: u64, len: usize) -> Result<Vec<u8>>;
}
impl<R: ReadAt> ImageSource for Store<R> {
    fn size(&self, path: &str) -> Result<u64> {
        self.member_len(path)
    }
    fn read_at(&mut self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        self.read_at(path, offset, len)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Initiate,
    Validation,
    Oob,
    Payload,
    Complete,
    Failed,
}
pub struct Sender {
    image: String,
    size: u64,
    phase: Phase,
    checksum: bool,
    offset: u64,
    oob_remaining: u64,
    output: Output,
    xml: XmlStream,
}
impl Sender {
    pub fn new(image: String, source: &impl ImageSource) -> Result<Self> {
        let size = source.size(&image)?;
        if size == 0 {
            return Err(Error::Invalid("empty ASR image"));
        }
        Ok(Self {
            image,
            size,
            phase: Phase::Initiate,
            checksum: false,
            offset: 0,
            oob_remaining: 0,
            output: Output::default(),
            xml: XmlStream::new(Limits::default()),
        })
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn poll(
        &mut self,
        stream: &mut impl ByteStream,
        source: &mut impl ImageSource,
    ) -> Poll<Result<()>> {
        let r = self.step(stream, source);
        if matches!(r, Poll::Ready(Err(_))) {
            self.phase = Phase::Failed;
        }
        r
    }
    fn step(
        &mut self,
        stream: &mut impl ByteStream,
        source: &mut impl ImageSource,
    ) -> Poll<Result<()>> {
        if self.phase == Phase::Failed {
            return Poll::Ready(Err(Error::Invalid("ASR already failed")));
        }
        if self.phase == Phase::Complete {
            return Poll::Ready(Ok(()));
        }
        if source.size(&self.image)? != self.size {
            return Poll::Ready(Err(Error::Invalid("ASR image identity/size changed")));
        }
        if self.output.is_pending() {
            return match self.output.poll(stream) {
                Poll::Ready(Ok(())) => Poll::Pending,
                r => r,
            };
        }
        if self.phase == Phase::Oob {
            if self.oob_remaining == 0 {
                self.phase = Phase::Validation;
                return Poll::Pending;
            }
            let n = self.oob_remaining.min(CHUNK_BYTES as u64) as usize;
            let bytes = source.read_at(&self.image, self.offset, n)?;
            if bytes.len() != n {
                return Poll::Ready(Err(Error::Invalid("short ASR OOB read")));
            }
            self.output.queue(bytes, CHUNK_BYTES)?;
            self.offset += n as u64;
            self.oob_remaining -= n as u64;
            return Poll::Pending;
        }
        if self.phase == Phase::Payload {
            if self.offset == self.size {
                self.phase = Phase::Complete;
                return Poll::Ready(Ok(()));
            }
            let n = (self.size - self.offset).min(CHUNK_BYTES as u64) as usize;
            let mut bytes = source.read_at(&self.image, self.offset, n)?;
            if bytes.len() != n {
                return Poll::Ready(Err(Error::Invalid("short ASR payload read")));
            }
            if self.checksum {
                let digest = Sha1::digest(&bytes);
                bytes.extend_from_slice(&digest);
            }
            self.output.queue(bytes, CHUNK_BYTES + SHA1_BYTES)?;
            self.offset += n as u64;
            return Poll::Pending;
        }
        let msg = match self.xml.poll(stream) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(v) => v?,
        };
        let command = msg.required("Command")?.string()?;
        match command {
            "Initiate" => {
                self.checksum = msg
                    .get("Checksum Chunks")
                    .map(Value::boolean)
                    .transpose()?
                    .unwrap_or(false);
                let mut packet = Value::dict([
                    ("Version", Value::Integer(1)),
                    ("Stream ID", Value::Integer(1)),
                    (
                        "Payload",
                        Value::dict([
                            ("Port", Value::Integer(1)),
                            ("Size", Value::Integer(self.size)),
                        ]),
                    ),
                    ("FEC Slice Stride", Value::Integer(FEC_STRIDE)),
                    ("Packet Payload Size", Value::Integer(PACKET_BYTES)),
                    ("Packets Per FEC", Value::Integer(PACKETS_PER_FEC)),
                ]);
                if self.checksum {
                    let Value::Dict(d) = &mut packet else {
                        unreachable!()
                    };
                    d.insert(
                        "Checksum Chunk Size".into(),
                        Value::Integer(CHUNK_BYTES as u64),
                    );
                }
                self.output.queue(
                    plist::encode_xml(&packet, Limits::default())?,
                    Limits::default().bytes,
                )?;
                self.phase = Phase::Validation;
            }
            "OOBData" if self.phase == Phase::Validation => {
                let offset = msg.required("OOB Offset")?.uint()?;
                let len = msg.required("OOB Length")?.uint()?;
                if offset.checked_add(len).is_none_or(|end| end > self.size) {
                    return Poll::Ready(Err(super::refuse(
                        "ASR OOB range overflow/past image",
                        &msg,
                    )));
                }
                self.offset = offset;
                self.oob_remaining = len;
                self.phase = Phase::Oob;
            }
            "Payload" if self.phase == Phase::Validation => {
                self.phase = Phase::Payload;
                self.offset = 0;
            }
            _ => {
                return Poll::Ready(Err(super::refuse(
                    "ASR command out of phase or unsupported",
                    &msg,
                )));
            }
        }
        Poll::Pending
    }
}
#[cfg(test)]
mod tests {
    use super::super::{store::tests::fixture, stream::tests::Memory};
    use super::*;
    fn xml(v: Value) -> Vec<u8> {
        plist::encode_xml(&v, Limits::default()).unwrap()
    }
    #[test]
    fn repeated_initiate_oob_and_checksummed_payload_over_partial_stream() {
        let data: Vec<_> = (0..CHUNK_BYTES + 17).map(|i| (i * 13) as u8).collect();
        let mut source = fixture(&data, false);
        let mut input = xml(Value::dict([("Command", Value::from("Initiate"))]));
        input.extend(xml(Value::dict([
            ("Command", Value::from("Initiate")),
            ("Checksum Chunks", Value::Boolean(true)),
        ])));
        input.extend(xml(Value::dict([
            ("Command", Value::from("OOBData")),
            ("OOB Offset", Value::Integer(7)),
            ("OOB Length", Value::Integer(9)),
        ])));
        input.extend(xml(Value::dict([("Command", Value::from("Payload"))])));
        let mut stream = Memory::new(input, 37);
        let mut sender = Sender::new("os.dmg".into(), &source).unwrap();
        for _ in 0..100_000 {
            if let Poll::Ready(v) = sender.poll(&mut stream, &mut source) {
                v.unwrap();
                break;
            }
        }
        assert_eq!(sender.phase(), Phase::Complete);
        let output = stream.output;
        let end = output
            .windows(8)
            .enumerate()
            .filter(|(_, w)| *w == b"</plist>")
            .nth(1)
            .unwrap()
            .0
            + 9;
        assert_eq!(&output[end..end + 9], &data[7..16]);
        let p = &output[end + 9..];
        assert_eq!(&p[..CHUNK_BYTES], &data[..CHUNK_BYTES]);
        assert_eq!(
            &p[CHUNK_BYTES..CHUNK_BYTES + 20],
            Sha1::digest(&data[..CHUNK_BYTES]).as_slice()
        );
        assert_eq!(&p[CHUNK_BYTES + 20..CHUNK_BYTES + 37], &data[CHUNK_BYTES..]);
        assert_eq!(
            &p[CHUNK_BYTES + 37..],
            Sha1::digest(&data[CHUNK_BYTES..]).as_slice()
        );
    }
    #[test]
    fn large_oob_is_chunked_and_overflow_refuses_with_original_request() {
        let data = vec![0x53; super::super::store::MAX_READ_BYTES + 3];
        for overflow in [false, true] {
            let mut source = fixture(&data, false);
            let mut input = xml(Value::dict([("Command", Value::from("Initiate"))]));
            input.extend(xml(Value::dict([
                ("Command", Value::from("OOBData")),
                (
                    "OOB Offset",
                    Value::Integer(if overflow { u64::MAX } else { 0 }),
                ),
                ("OOB Length", Value::Integer(data.len() as u64)),
            ])));
            if !overflow {
                input.extend(xml(Value::dict([("Command", Value::from("Payload"))])));
            }
            let mut stream = Memory::new(input, 30000);
            let mut sender = Sender::new("os.dmg".into(), &source).unwrap();
            let mut result = None;
            for _ in 0..100_000 {
                if let Poll::Ready(r) = sender.poll(&mut stream, &mut source) {
                    result = Some(r);
                    break;
                }
            }
            if overflow {
                let Error::Refused { request, .. } = result.unwrap().unwrap_err() else {
                    panic!("missing OOB context")
                };
                assert_eq!(
                    request.required("OOB Offset").unwrap().uint().unwrap(),
                    u64::MAX
                );
            } else {
                result.unwrap().unwrap();
                let at = stream
                    .output
                    .windows(8)
                    .position(|w| w == b"</plist>")
                    .unwrap()
                    + 9;
                assert_eq!(&stream.output[at..at + data.len()], data);
                assert_eq!(&stream.output[at + data.len()..], data);
            }
        }
    }
    #[test]
    fn malformed_ranges_and_commands_are_terminal() {
        for v in [
            Value::dict([("Command", Value::from("Payload"))]),
            Value::dict([
                ("Command", Value::from("Initiate")),
                ("Checksum Chunks", Value::Integer(1)),
            ]),
        ] {
            let mut source = fixture(b"hello", false);
            let mut stream = Memory::new(xml(v), 1);
            let mut sender = Sender::new("os.dmg".into(), &source).unwrap();
            for _ in 0..2000 {
                if let Poll::Ready(v) = sender.poll(&mut stream, &mut source) {
                    assert!(v.is_err());
                    break;
                }
            }
            assert_eq!(sender.phase(), Phase::Failed);
            assert!(matches!(
                sender.poll(&mut stream, &mut source),
                Poll::Ready(Err(_))
            ));
        }
    }
}

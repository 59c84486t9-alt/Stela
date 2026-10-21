//! Original fixed TA/3D shared-scene identity. This is neither a framebuffer
//! extent match nor a queue index. The AP writes the same selected buffer
//! object into TA descriptor +1030 and 3D descriptor +8c0 (G13X setter
//! 0x1baffb0..0x1bb008c tail-calls 0x1b0059c). Their setup encoders publish
//! its firmware pointer at TA +1c / 3D +14, with contexts +3c / +54.

use super::{Encoding, Frame, Submission};
use crate::platform::apple::agx::{
    channel::{Kind, Record},
    uat::CONTEXTS,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    context: u32,
    buffer: u64,
}
impl Key {
    pub fn read(submission: &Submission, frame: &Frame) -> Result<Self, &'static str> {
        if submission.encoding != Encoding::Fixed {
            return Err("GFX newer-family render scene fields are not qualified");
        }
        let (record, buffer, context) = match submission.command.kind {
            Kind::Ta => (Record::SetupTa, 0x1c, 0x3c),
            Kind::ThreeD => (Record::Setup3d, 0x14, 0x54),
            _ => return Err("GFX render scene requires an accepted TA or 3D command"),
        };
        if frame.record != record
            || frame.bytes().len() as u64 != Encoding::Fixed.record_bytes(record)
        {
            return Err("GFX render scene does not have its complete accepted setup record");
        }
        let stream_end = submission
            .stream
            .checked_add(u64::from(submission.stream_bytes))
            .ok_or("GFX render scene stream extent wraps")?;
        let frame_end = frame
            .va
            .checked_add(frame.bytes().len() as u64)
            .ok_or("GFX render scene record extent wraps")?;
        if frame.va < submission.stream || frame_end > stream_end {
            return Err("GFX render scene record is outside its accepted stream");
        }
        let context = frame.u32(context)?;
        if context != submission.context || context as usize >= CONTEXTS {
            return Err("GFX render scene context differs from its accepted command");
        }
        let buffer = frame.u64(buffer)?;
        if buffer == 0 {
            return Err("GFX render setup has no shared scene object");
        }
        // Original 3D also publishes buffer+3c as its busy-flag pointer.
        buffer
            .checked_add(0x3f)
            .ok_or("GFX render shared scene extent wraps")?;
        Ok(Self { context, buffer })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::agx::channel::{Command, Stamp};
    fn submission(kind: Kind) -> Submission {
        Submission {
            command: Command { va: 0x1000, kind },
            encoding: Encoding::Fixed,
            counter: 1,
            context: 5,
            stamp: Stamp {
                driver: 0x2000,
                firmware: 0x2004,
                value: 0x100,
                index: 1,
            },
            stream: 0x3000,
            stream_bytes: 0x400,
        }
    }
    fn setup(kind: Kind, buffer: u64) -> Frame {
        let (record, at, context) = match kind {
            Kind::Ta => (Record::SetupTa, 0x1c, 0x3c),
            Kind::ThreeD => (Record::Setup3d, 0x14, 0x54),
            _ => unreachable!(),
        };
        let mut data = alloc::vec![0;record.bytes() as usize];
        data[at..at + 8].copy_from_slice(&buffer.to_le_bytes());
        data[context..context + 4].copy_from_slice(&5u32.to_le_bytes());
        Frame {
            va: 0x3000,
            record,
            data,
        }
    }
    #[test]
    fn distinct_producer_fields_bind_one_scene_without_using_dimensions_or_counters() {
        let ta = submission(Kind::Ta);
        let mut fragment = submission(Kind::ThreeD);
        fragment.counter = 17;
        assert_eq!(
            Key::read(&ta, &setup(Kind::Ta, 0x4000)),
            Key::read(&fragment, &setup(Kind::ThreeD, 0x4000))
        );
        assert_ne!(
            Key::read(&ta, &setup(Kind::Ta, 0x4000)),
            Key::read(&fragment, &setup(Kind::ThreeD, 0x5000))
        );
    }
    #[test]
    fn missing_wrong_context_or_overflowing_scene_fields_refuse() {
        let ta = submission(Kind::Ta);
        for address in [0, u64::MAX - 0x3e] {
            assert!(Key::read(&ta, &setup(Kind::Ta, address)).is_err());
        }
        let mut frame = setup(Kind::Ta, 0x4000);
        frame.data[0x3c..0x40].copy_from_slice(&6u32.to_le_bytes());
        assert!(Key::read(&ta, &frame).is_err());
        assert!(Key::read(&ta, &setup(Kind::ThreeD, 0x4000)).is_err());
        let mut foreign = setup(Kind::Ta, 0x4000);
        foreign.va -= 4;
        assert!(Key::read(&ta, &foreign).is_err());
        foreign.va = ta.stream + u64::from(ta.stream_bytes) - 4;
        assert!(Key::read(&ta, &foreign).is_err());
        let mut wrapping = ta.clone();
        wrapping.stream = u64::MAX - 4;
        assert!(Key::read(&wrapping, &setup(Kind::Ta, 0x4000)).is_err());
        let mut newer = ta;
        newer.encoding = Encoding::G14X;
        assert!(Key::read(&newer, &setup(Kind::Ta, 0x4000)).is_err());
    }
}

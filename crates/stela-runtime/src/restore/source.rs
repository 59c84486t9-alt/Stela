//! Exact archive extent within read-only host storage. Partition padding is
//! excluded from ZIP end-record searches; no read can escape the extent.
use super::{Error, Result};
use alloc::{format, string::String};
use stela_formats::payload::ReadAt;
pub struct Extent<R> {
    reader: R,
    bytes: u64,
}
impl<R: ReadAt> Extent<R> {
    pub fn new(reader: R, bytes: u64) -> Result<Self> {
        if bytes == 0 || bytes > reader.len() {
            return Err(Error::Invalid("archive extent outside source"));
        }
        Ok(Self { reader, bytes })
    }
}
impl<R: ReadAt> ReadAt for Extent<R> {
    type Error = String;
    fn len(&self) -> u64 {
        self.bytes
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> core::result::Result<(), String> {
        if offset
            .checked_add(buffer.len() as u64)
            .is_none_or(|end| end > self.bytes)
        {
            return Err("read outside archive extent".into());
        }
        self.reader
            .read_at(offset, buffer)
            .map_err(|e| format!("{e:?}"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Source;
    impl ReadAt for Source {
        type Error = ();
        fn len(&self) -> u64 {
            1024
        }
        fn read_at(&mut self, _: u64, b: &mut [u8]) -> core::result::Result<(), ()> {
            b.fill(42);
            Ok(())
        }
    }
    #[test]
    fn extent_rejects_padding_overflow_and_short_source() {
        assert!(Extent::new(Source, 0).is_err());
        assert!(Extent::new(Source, 1025).is_err());
        let mut e = Extent::new(Source, 513).unwrap();
        assert_eq!(e.len(), 513);
        let mut b = [0; 2];
        e.read_at(511, &mut b).unwrap();
        assert_eq!(b, [42; 2]);
        assert!(e.read_at(512, &mut b).is_err());
        assert!(e.read_at(u64::MAX, &mut b).is_err());
        e.read_at(513, &mut []).unwrap();
        assert!(e.read_at(514, &mut []).is_err());
    }
}

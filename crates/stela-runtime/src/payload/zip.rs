//! Read members of a ZIP64 archive, such as an IPSW, in place.
//!
//! Only the central directory and the local header of each read member are
//! parsed. Stored members stream straight from the file; deflate members
//! stream through `miniz_oxide`'s inflater with a 32 KiB window, so a
//! multi-gigabyte member needs no more memory than that.
use super::{MemberRead, PayloadError, ReadAt};
use alloc::{boxed::Box, string::String, vec, vec::Vec};
use miniz_oxide::inflate::{
    TINFLStatus,
    core::{DecompressorOxide, decompress, inflate_flags::TINFL_FLAG_HAS_MORE_INPUT},
};

const END: u32 = 0x0605_4b50;
const END64: u32 = 0x0606_4b50;
const LOCATOR64: u32 = 0x0706_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const LOCAL: u32 = 0x0403_4b50;
const END_BYTES: usize = 22;
const LOCATOR_BYTES: u64 = 20;
const CENTRAL_BYTES: usize = 46;
const LOCAL_BYTES: usize = 30;
/// The end record plus the longest comment it may carry.
const END_SEARCH: u64 = END_BYTES as u64 + 0xffff;
/// A sane bound for an IPSW's directory (about 1,600 entries in 26A434).
const MAX_DIRECTORY_BYTES: u64 = 32 * 1024 * 1024;
const MAX_ENTRIES: u64 = 1 << 20;
const WINDOW: usize = 32 * 1024;
const INPUT: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Stored,
    Deflate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub method: Method,
    pub compressed_bytes: u64,
    pub bytes: u64,
    pub crc32: u32,
    /// Unix mode from central-directory external attributes, when supplied.
    pub unix_mode: Option<u16>,
    local_header: u64,
}

pub struct Archive {
    entries: Vec<Entry>,
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn corrupt(what: &'static str) -> PayloadError {
    PayloadError::Archive(what)
}

fn read<R: ReadAt>(reader: &mut R, offset: u64, length: usize) -> Result<Vec<u8>, PayloadError> {
    let end = offset
        .checked_add(length as u64)
        .ok_or(corrupt("offset overflow"))?;
    if end > reader.len() {
        return Err(corrupt("record past the end of the archive"));
    }
    let mut bytes = vec![0u8; length];
    reader
        .read_at(offset, &mut bytes)
        .map_err(PayloadError::io)?;
    Ok(bytes)
}

impl Archive {
    pub fn open<R: ReadAt>(reader: &mut R) -> Result<Self, PayloadError> {
        let length = reader.len();
        if length < END_BYTES as u64 {
            return Err(corrupt("too short for a ZIP archive"));
        }
        let tail_start = length.saturating_sub(END_SEARCH);
        let tail = read(reader, tail_start, (length - tail_start) as usize)?;
        let end = (0..=tail.len() - END_BYTES)
            .rev()
            .find(|&at| {
                u32_at(&tail, at) == END
                    && at + END_BYTES + u16_at(&tail, at + 20) as usize == tail.len()
            })
            .ok_or(corrupt("no end of central directory record"))?;
        let record = &tail[end..];
        let mut count = u16_at(record, 10) as u64;
        let mut size = u32_at(record, 12) as u64;
        let mut start = u32_at(record, 16) as u64;
        if u16_at(record, 4) != 0 || u16_at(record, 6) != 0 {
            return Err(corrupt("multi-disk archives are not supported"));
        }
        let end_offset = tail_start + end as u64;
        if count == 0xffff || size == 0xffff_ffff || start == 0xffff_ffff {
            let at = end_offset
                .checked_sub(LOCATOR_BYTES)
                .ok_or(corrupt("no ZIP64 locator"))?;
            let locator = read(reader, at, LOCATOR_BYTES as usize)?;
            if u32_at(&locator, 0) != LOCATOR64 {
                return Err(corrupt("no ZIP64 locator"));
            }
            let record = read(reader, u64_at(&locator, 8), 56)?;
            if u32_at(&record, 0) != END64 {
                return Err(corrupt("no ZIP64 end record"));
            }
            count = u64_at(&record, 32);
            size = u64_at(&record, 40);
            start = u64_at(&record, 48);
        }
        if size > MAX_DIRECTORY_BYTES || count > MAX_ENTRIES {
            return Err(corrupt("central directory exceeds limits"));
        }
        let directory = read(reader, start, size as usize)?;
        let mut entries = Vec::with_capacity(count as usize);
        let mut at = 0usize;
        for _ in 0..count {
            if at + CENTRAL_BYTES > directory.len() || u32_at(&directory, at) != CENTRAL {
                return Err(corrupt("bad central directory entry"));
            }
            let header = &directory[at..];
            let flags = u16_at(header, 8);
            let method = u16_at(header, 10);
            let name_bytes = u16_at(header, 28) as usize;
            let extra_bytes = u16_at(header, 30) as usize;
            let comment_bytes = u16_at(header, 32) as usize;
            let next = at + CENTRAL_BYTES + name_bytes + extra_bytes + comment_bytes;
            if next > directory.len() {
                return Err(corrupt("central directory entry overruns"));
            }
            let name = core::str::from_utf8(&header[CENTRAL_BYTES..CENTRAL_BYTES + name_bytes])
                .map_err(|_| corrupt("member name is not UTF-8"))?;
            let mut bytes = u32_at(header, 24) as u64;
            let mut compressed_bytes = u32_at(header, 20) as u64;
            let mut local_header = u32_at(header, 42) as u64;
            let mut extra = &header[CENTRAL_BYTES + name_bytes..][..extra_bytes];
            while extra.len() >= 4 {
                let id = u16_at(extra, 0);
                let field = u16_at(extra, 2) as usize;
                let body = extra
                    .get(4..4 + field)
                    .ok_or(corrupt("extra field overruns"))?;
                if id == 1 {
                    let mut values = body
                        .as_chunks::<8>()
                        .0
                        .iter()
                        .map(|v| u64::from_le_bytes(*v));
                    for value in [&mut bytes, &mut compressed_bytes, &mut local_header] {
                        if *value == 0xffff_ffff {
                            *value = values.next().ok_or(corrupt("short ZIP64 extra field"))?;
                        }
                    }
                }
                extra = &extra[4 + field..];
            }
            let method = match method {
                0 => Method::Stored,
                8 => Method::Deflate,
                _ => return Err(PayloadError::Unsupported("ZIP compression method")),
            };
            if flags & 1 != 0 {
                return Err(PayloadError::Unsupported("encrypted ZIP member"));
            }
            if method == Method::Stored && compressed_bytes != bytes {
                return Err(corrupt("stored member sizes differ"));
            }
            entries.push(Entry {
                name: name.into(),
                method,
                compressed_bytes,
                bytes,
                crc32: u32_at(header, 16),
                unix_mode: (header[5] == 3).then(|| (u32_at(header, 38) >> 16) as u16),
                local_header,
            });
            at = next;
        }
        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn find(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.name == name)
    }

    /// Bounded random access. Stored members read directly; deflate members
    /// replay through the existing bounded inflater, without buffering the file.
    /// Integrity is the caller's responsibility, as for `open_member`.
    pub fn read_member_at<R: ReadAt>(
        &self,
        reader: &mut R,
        entry: &Entry,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), PayloadError> {
        if offset
            .checked_add(output.len() as u64)
            .is_none_or(|end| end > entry.bytes)
        {
            return Err(corrupt("member read range"));
        }
        let mut stream = self.open_member(reader, entry)?;
        if entry.method == Method::Stored {
            stream.progress.next += offset;
            stream.progress.remaining_input -= offset;
            stream.progress.remaining_output -= offset;
        } else {
            let mut discard = [0; 4096];
            let mut remaining = offset;
            while remaining > 0 {
                let n = remaining.min(discard.len() as u64) as usize;
                let n = stream.read(&mut discard[..n])?;
                if n == 0 {
                    return Err(corrupt("short random member read"));
                }
                remaining -= n as u64;
            }
        }
        let mut done = 0;
        while done < output.len() {
            let n = stream.read(&mut output[done..])?;
            if n == 0 {
                return Err(corrupt("short random member read"));
            }
            done += n;
        }
        Ok(())
    }

    /// Stream one member's uncompressed bytes.
    pub fn open_member<'r, R: ReadAt>(
        &self,
        reader: &'r mut R,
        entry: &Entry,
    ) -> Result<MemberStream<'r, R>, PayloadError> {
        let progress = self.start_member(reader, entry)?;
        Ok(MemberStream { reader, progress })
    }

    /// A resumable position at the start of a member's uncompressed bytes.
    /// Unlike [`MemberStream`] it borrows no reader, so a caller may keep it
    /// between reads and advance it with [`Self::pump`]: a deflate member
    /// read block by block then resumes its inflater instead of replaying it
    /// from the start each time.
    pub fn start_member<R: ReadAt>(
        &self,
        reader: &mut R,
        entry: &Entry,
    ) -> Result<Progress, PayloadError> {
        let local = read(reader, entry.local_header, LOCAL_BYTES)?;
        if u32_at(&local, 0) != LOCAL {
            return Err(corrupt("bad local header"));
        }
        let data = entry.local_header
            + LOCAL_BYTES as u64
            + u16_at(&local, 26) as u64
            + u16_at(&local, 28) as u64;
        match data.checked_add(entry.compressed_bytes) {
            Some(end) if end <= reader.len() => {}
            _ => return Err(corrupt("member data past the end of the archive")),
        }
        let inflater = (entry.method == Method::Deflate).then(|| Inflater {
            state: Box::default(),
            input: vec![0; INPUT],
            start: 0,
            filled: 0,
            window: vec![0; WINDOW],
            position: 0,
            ready: 0..0,
            finished: false,
        });
        Ok(Progress {
            next: data,
            remaining_input: entry.compressed_bytes,
            remaining_output: entry.bytes,
            inflater,
            produced: 0,
        })
    }

    /// Advance a [`Progress`] by up to `buffer.len()` uncompressed bytes.
    pub fn pump<R: ReadAt>(
        &self,
        reader: &mut R,
        progress: &mut Progress,
        buffer: &mut [u8],
    ) -> Result<usize, PayloadError> {
        let n = progress.read(reader, buffer)?;
        progress.produced += n as u64;
        Ok(n)
    }

    /// Fill `output` with the member's bytes at `offset`, resuming `cursor`
    /// when it is positioned at or before `offset` and re-opening it
    /// otherwise. Sequential reads of a deflate member then inflate it once,
    /// not once per block. Integrity is the caller's, as for `open_member`.
    pub fn read_member_resuming<R: ReadAt>(
        &self,
        reader: &mut R,
        entry: &Entry,
        cursor: &mut Option<Progress>,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), PayloadError> {
        if offset
            .checked_add(output.len() as u64)
            .is_none_or(|end| end > entry.bytes)
        {
            return Err(corrupt("member read range"));
        }
        // Reuse the cursor only when it has not yet passed this offset.
        let mut progress = match cursor.take() {
            Some(progress) if progress.produced <= offset => progress,
            _ => self.start_member(reader, entry)?,
        };
        let mut discard = [0; 4096];
        while progress.produced < offset {
            let want = (offset - progress.produced).min(discard.len() as u64) as usize;
            if self.pump(reader, &mut progress, &mut discard[..want])? == 0 {
                return Err(corrupt("short random member read"));
            }
        }
        let mut done = 0;
        while done < output.len() {
            let n = self.pump(reader, &mut progress, &mut output[done..])?;
            if n == 0 {
                return Err(corrupt("short random member read"));
            }
            done += n;
        }
        *cursor = Some(progress);
        Ok(())
    }
}

/// How many uncompressed bytes of a member have been produced, and the
/// inflater state to produce the next ones.
pub struct Progress {
    next: u64,
    remaining_input: u64,
    remaining_output: u64,
    inflater: Option<Inflater>,
    produced: u64,
}

impl Progress {
    /// Uncompressed bytes produced so far.
    pub fn produced(&self) -> u64 {
        self.produced
    }
}

struct Inflater {
    state: Box<DecompressorOxide>,
    input: Vec<u8>,
    start: usize,
    filled: usize,
    window: Vec<u8>,
    position: usize,
    ready: core::ops::Range<usize>,
    finished: bool,
}

pub struct MemberStream<'r, R: ReadAt> {
    reader: &'r mut R,
    progress: Progress,
}

impl Progress {
    fn fill<R: ReadAt>(
        &mut self,
        reader: &mut R,
        buffer: &mut [u8],
    ) -> Result<usize, PayloadError> {
        let count = (buffer.len() as u64).min(self.remaining_input) as usize;
        reader
            .read_at(self.next, &mut buffer[..count])
            .map_err(PayloadError::io)?;
        self.next += count as u64;
        self.remaining_input -= count as u64;
        Ok(count)
    }

    fn read<R: ReadAt>(
        &mut self,
        reader: &mut R,
        buffer: &mut [u8],
    ) -> Result<usize, PayloadError> {
        if self.inflater.is_none() {
            let count = self.fill(reader, buffer)?;
            self.remaining_output -= count as u64;
            return Ok(count);
        }
        loop {
            let inflater = self.inflater.as_mut().unwrap();
            if !inflater.ready.is_empty() {
                let count = buffer.len().min(inflater.ready.len());
                let start = inflater.ready.start;
                buffer[..count].copy_from_slice(&inflater.window[start..start + count]);
                inflater.ready.start += count;
                self.remaining_output = self
                    .remaining_output
                    .checked_sub(count as u64)
                    .ok_or(corrupt("member inflates past its size"))?;
                return Ok(count);
            }
            if inflater.finished {
                if self.remaining_output != 0 {
                    return Err(corrupt("member inflates short of its size"));
                }
                return Ok(0);
            }
            if inflater.start == inflater.filled && self.remaining_input > 0 {
                let mut input = core::mem::take(&mut self.inflater.as_mut().unwrap().input);
                let count = self.fill(reader, &mut input);
                let inflater = self.inflater.as_mut().unwrap();
                inflater.input = input;
                inflater.start = 0;
                inflater.filled = count?;
            }
            let more = self.remaining_input > 0;
            let inflater = self.inflater.as_mut().unwrap();
            let flags = if more { TINFL_FLAG_HAS_MORE_INPUT } else { 0 };
            let (status, consumed, produced) = decompress(
                &mut inflater.state,
                &inflater.input[inflater.start..inflater.filled],
                &mut inflater.window,
                inflater.position,
                flags,
            );
            inflater.start += consumed;
            inflater.ready = inflater.position..inflater.position + produced;
            inflater.position = (inflater.position + produced) % WINDOW;
            match status {
                TINFLStatus::Done => inflater.finished = true,
                TINFLStatus::HasMoreOutput => {}
                TINFLStatus::NeedsMoreInput if more || produced > 0 => {}
                _ => return Err(corrupt("deflate stream is damaged or truncated")),
            }
        }
    }
}

impl<R: ReadAt> MemberRead for MemberStream<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, PayloadError> {
        self.progress.read(self.reader, buffer)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::payload::tests::Memory;

    /// Build an archive; `zip64` forces the ZIP64 end records and extra fields.
    pub(crate) fn archive(members: &[(&str, &[u8], bool)], zip64: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data, deflate) in members {
            let body = if *deflate {
                miniz_oxide::deflate::compress_to_vec(data, 6)
            } else {
                data.to_vec()
            };
            let offset = out.len() as u64;
            let crc = crate::payload::gpt::crc32(data);
            let method: u16 = if *deflate { 8 } else { 0 };
            let small = |v: u64| if zip64 { 0xffff_ffff } else { v as u32 };
            out.extend_from_slice(&LOCAL.to_le_bytes());
            out.extend_from_slice(&[20, 0, 0, 0]);
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&[3, 0]);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b"xyz");
            out.extend_from_slice(&body);
            let extra: Vec<u8> = if zip64 {
                [1u16.to_le_bytes(), 24u16.to_le_bytes()]
                    .concat()
                    .into_iter()
                    .chain((data.len() as u64).to_le_bytes())
                    .chain((body.len() as u64).to_le_bytes())
                    .chain(offset.to_le_bytes())
                    .collect()
            } else {
                Vec::new()
            };
            central.extend_from_slice(&CENTRAL.to_le_bytes());
            central.extend_from_slice(&[45, 0, 45, 0, 0, 0]);
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&[0; 4]);
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&small(body.len() as u64).to_le_bytes());
            central.extend_from_slice(&small(data.len() as u64).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&(extra.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0; 10]);
            central.extend_from_slice(&small(offset).to_le_bytes());
            central.extend_from_slice(name.as_bytes());
            central.extend_from_slice(&extra);
        }
        let start = out.len() as u64;
        out.extend_from_slice(&central);
        let count = members.len() as u64;
        if zip64 {
            let record = out.len() as u64;
            out.extend_from_slice(&END64.to_le_bytes());
            out.extend_from_slice(&44u64.to_le_bytes());
            out.extend_from_slice(&[45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            out.extend_from_slice(&count.to_le_bytes());
            out.extend_from_slice(&count.to_le_bytes());
            out.extend_from_slice(&(central.len() as u64).to_le_bytes());
            out.extend_from_slice(&start.to_le_bytes());
            out.extend_from_slice(&LOCATOR64.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&record.to_le_bytes());
            out.extend_from_slice(&1u32.to_le_bytes());
        }
        out.extend_from_slice(&END.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        let n = if zip64 { 0xffff } else { count as u16 };
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&n.to_le_bytes());
        let (size, offset) = if zip64 {
            (0xffff_ffffu32, 0xffff_ffffu32)
        } else {
            (central.len() as u32, start as u32)
        };
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&5u16.to_le_bytes());
        out.extend_from_slice(b"notes");
        out
    }

    fn drain(stream: &mut impl MemberRead, chunk: usize) -> Result<Vec<u8>, PayloadError> {
        let mut out = Vec::new();
        let mut buffer = vec![0u8; chunk];
        loop {
            let count = stream.read(&mut buffer)?;
            if count == 0 {
                return Ok(out);
            }
            out.extend_from_slice(&buffer[..count]);
        }
    }

    fn sample(bytes: usize) -> Vec<u8> {
        // Compressible but not trivial, so back-references cross the window.
        (0..bytes).map(|i| ((i / 7) ^ (i >> 11)) as u8).collect()
    }

    #[test]
    fn stored_and_deflate_members_stream_from_classic_and_zip64_archives() {
        let big = sample(300_000);
        for zip64 in [false, true] {
            let bytes = archive(
                &[
                    ("BuildManifest.plist", b"<plist/>", false),
                    ("a/b.dmg", &big, true),
                    ("empty", b"", true),
                ],
                zip64,
            );
            let mut memory = Memory(bytes);
            let archive = Archive::open(&mut memory).unwrap();
            assert_eq!(archive.entries().len(), 3);
            for (name, expected) in [
                ("BuildManifest.plist", &b"<plist/>"[..]),
                ("a/b.dmg", &big),
                ("empty", b""),
            ] {
                let entry = archive.find(name).unwrap().clone();
                assert_eq!(entry.bytes, expected.len() as u64);
                for chunk in [1, 4096, 100_000] {
                    let mut stream = archive.open_member(&mut memory, &entry).unwrap();
                    assert_eq!(
                        drain(&mut stream, chunk).unwrap(),
                        expected,
                        "{name} {chunk}"
                    );
                }
            }
        }
    }

    /// A reader that counts the bytes it serves, to show the cost of reading
    /// a deflate member block by block.
    struct Counting {
        inner: Memory,
        served: core::cell::Cell<u64>,
    }
    impl ReadAt for Counting {
        type Error = <Memory as ReadAt>::Error;
        fn len(&self) -> u64 {
            self.inner.len()
        }
        fn read_at(&mut self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
            self.served.set(self.served.get() + bytes.len() as u64);
            self.inner.read_at(offset, bytes)
        }
    }

    #[test]
    fn a_resumed_cursor_reads_a_deflate_member_once_not_once_per_block() {
        let big = sample(400_000);
        let bytes = archive(&[("m", &big, true)], false);
        let mut memory = Counting {
            inner: Memory(bytes),
            served: core::cell::Cell::new(0),
        };
        let archive = Archive::open(&mut memory).unwrap();
        let entry = archive.find("m").unwrap().clone();
        let compressed = entry.compressed_bytes;

        // Read every 64 KiB block in order, resuming the cursor.
        let block = 64 * 1024u64;
        let mut cursor = None;
        let mut joined = Vec::new();
        memory.served.set(0);
        let mut offset = 0;
        while offset < entry.bytes {
            let n = (entry.bytes - offset).min(block) as usize;
            let mut out = vec![0; n];
            archive
                .read_member_resuming(&mut memory, &entry, &mut cursor, offset, &mut out)
                .unwrap();
            joined.extend_from_slice(&out);
            offset += n as u64;
        }
        assert_eq!(joined, big);
        let resumed = memory.served.get();
        // The whole compressed stream is read about once, not once per block.
        assert!(
            resumed < compressed * 2,
            "resumed read served {resumed} of {compressed} compressed bytes"
        );

        // Re-opening per block instead reads far more: each block replays the
        // inflater from the member start.
        memory.served.set(0);
        offset = 0;
        while offset < entry.bytes {
            let n = (entry.bytes - offset).min(block) as usize;
            let mut out = vec![0; n];
            let mut fresh = None;
            archive
                .read_member_resuming(&mut memory, &entry, &mut fresh, offset, &mut out)
                .unwrap();
            offset += n as u64;
        }
        assert!(
            memory.served.get() > resumed * 3,
            "re-opening served {} vs resumed {resumed}",
            memory.served.get()
        );

        // A cursor already past the offset re-opens and still reads correctly.
        let mut back = cursor.take();
        let mut out = vec![0; 100];
        archive
            .read_member_resuming(&mut memory, &entry, &mut back, 0, &mut out)
            .unwrap();
        assert_eq!(out, &big[..100]);
    }

    #[test]
    fn damaged_archives_and_members_fail_instead_of_returning_short_data() {
        let big = sample(100_000);
        let bytes = archive(&[("m", &big, true)], true);
        let mut short = Memory(bytes[..bytes.len() - 30].to_vec());
        assert!(Archive::open(&mut short).is_err());
        let mut memory = Memory(bytes.clone());
        let archive = Archive::open(&mut memory).unwrap();
        let entry = archive.find("m").unwrap().clone();
        // Corrupt the deflate body.
        let data = entry.local_header as usize + LOCAL_BYTES + 1 + 3;
        let mut damaged = bytes.clone();
        for byte in &mut damaged[data + 10..data + 60] {
            *byte ^= 0x5a;
        }
        let mut damaged = Memory(damaged);
        let result = archive
            .open_member(&mut damaged, &entry)
            .and_then(|mut s| drain(&mut s, 4096));
        assert!(result.map_or(true, |out| out != big));
        // A size that disagrees with the stream fails.
        let mut longer = entry.clone();
        longer.bytes += 1;
        let mut stream = archive.open_member(&mut memory, &longer).unwrap();
        assert!(drain(&mut stream, 4096).is_err());
        assert!(Archive::open(&mut Memory(vec![0; 10])).is_err());
    }
}

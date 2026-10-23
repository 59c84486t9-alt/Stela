//! Bounds-checked Metal library containers and LLVM bitcode wrappers.
//!
//! The MTLB layout is reverse-engineered, not a public Apple ABI. See
//! `metal/README.md` for its sources and contract. Shader bytes,
//! metadata and digest remain borrowed from the original input.
use alloc::vec::Vec;
use core::{fmt, ops::Range, str};
use sha2::{Digest, Sha256};

const HEADER_BYTES: usize = 88;
const LLVM_WRAPPER_MAGIC: u32 = 0x0b17_c0de;
const LLVM_WRAPPER_BYTES: usize = 20;
const LLVM_MAGIC: &[u8; 4] = b"BC\xc0\xde";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Truncated,
    Overflow,
    Magic,
    Version,
    FileSize,
    SectionOverlap,
    FunctionCount,
    TagSize,
    DuplicateTag([u8; 4]),
    MissingTag([u8; 4]),
    Terminator,
    Name,
    Metadata,
    Hash,
    Bitcode,
    Allocation,
    ResourceLimit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    /// Byte offset in the original input, not an extracted temporary buffer.
    pub offset: usize,
    pub kind: ErrorKind,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Metal library {:?} at {:#x}", self.kind, self.offset)
    }
}

impl core::error::Error for Error {}

type Result<T> = core::result::Result<T, Error>;

fn error(offset: usize, kind: ErrorKind) -> Error {
    Error { offset, kind }
}

fn bytes(data: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| error(offset, ErrorKind::Overflow))?;
    data.get(offset..end)
        .ok_or_else(|| error(offset, ErrorKind::Truncated))
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes(data, offset, 2)?.try_into().unwrap(),
    ))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes(data, offset, 4)?.try_into().unwrap(),
    ))
}

fn u64_at(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes(data, offset, 8)?.try_into().unwrap(),
    ))
}

fn host_size(value: u64, offset: usize) -> Result<usize> {
    usize::try_from(value).map_err(|_| error(offset, ErrorKind::Overflow))
}

fn section(data: &[u8], header_offset: usize, count_prefix: bool) -> Result<Range<usize>> {
    let offset = host_size(u64_at(data, header_offset)?, header_offset)?;
    let mut size = host_size(u64_at(data, header_offset + 8)?, header_offset + 8)?;
    // MTLB's function-list size excludes its leading u32 function count.
    if count_prefix {
        size = size
            .checked_add(4)
            .ok_or_else(|| error(header_offset, ErrorKind::Overflow))?;
    }
    bytes(data, offset, size)?;
    Ok(offset..offset + size)
}

/// Raw tagged metadata. Unknown tags remain visible to later compiler stages.
#[derive(Clone, Copy, Debug)]
pub struct Tags<'a> {
    bytes: &'a [u8],
    offset: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct Tag<'a> {
    pub name: [u8; 4],
    pub value: &'a [u8],
    pub offset: usize,
}

impl<'a> Iterator for Tags<'a> {
    type Item = Result<Tag<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }
        let offset = self.offset;
        let parsed = (|| {
            let name: [u8; 4] = bytes(self.bytes, 0, 4)?.try_into().unwrap();
            if &name == b"ENDT" {
                if self.bytes.len() != 4 {
                    return Err(error(0, ErrorKind::Terminator));
                }
                return Ok((4, None));
            }
            let size = usize::from(u16_at(self.bytes, 4)?);
            let value = bytes(self.bytes, 6, size)?;
            Ok((
                6 + size,
                Some(Tag {
                    name,
                    value,
                    offset,
                }),
            ))
        })();
        match parsed {
            Ok((used, tag)) => {
                self.bytes = &self.bytes[used..];
                self.offset += used;
                tag.map(Ok)
            }
            Err(mut failure) => {
                failure.offset += offset;
                self.bytes = &[];
                Some(Err(failure))
            }
        }
    }
}

impl<'a> Tags<'a> {
    /// Remaining original tag-stream range, including its ENDT terminator.
    pub fn range(&self) -> Range<usize> {
        self.offset..self.offset + self.bytes.len()
    }

    fn checked(data: &'a [u8], offset: usize) -> Result<Self> {
        if !data.ends_with(b"ENDT") {
            return Err(error(offset + data.len(), ErrorKind::Terminator));
        }
        let tags = Self {
            bytes: data,
            offset,
        };
        for tag in tags {
            tag?;
        }
        Ok(tags)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub platform: u16,
    pub format: Version,
    /// Preserve the container's library kind and target OS without inventing
    /// support for a dynamic library, a companion, or a future target.
    pub kind: u8,
    pub target_os: u8,
    pub minimum_os: Version,
}

/// A structurally validated library. AIR digests are checked by [`Function::air`]
/// when selected for compilation, avoiding hashing every unused shader.
#[derive(Debug)]
pub struct Library<'a> {
    pub header: Header,
    functions: Vec<Function<'a>>,
    pub header_extensions: Option<Tags<'a>>,
}

impl<'a> Library<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        Self::parse_bounded(data, usize::MAX)
    }

    /// Apply the caller's entry budget before allocating the function table.
    pub fn parse_bounded(data: &'a [u8], max_functions: usize) -> Result<Self> {
        bytes(data, 0, HEADER_BYTES)?;
        if &data[..4] != b"MTLB" {
            return Err(error(0, ErrorKind::Magic));
        }
        let header = Header {
            platform: u16_at(data, 4)?,
            format: Version {
                major: u16_at(data, 6)?,
                minor: u16_at(data, 8)?,
            },
            kind: data[10],
            target_os: data[11],
            minimum_os: Version {
                major: u16_at(data, 12)?,
                minor: u16_at(data, 14)?,
            },
        };
        if header.format.major != 2 {
            return Err(error(6, ErrorKind::Version));
        }
        if u64_at(data, 16)? != data.len() as u64 {
            return Err(error(16, ErrorKind::FileSize));
        }
        let functions_range = section(data, 24, true)?;
        let public = section(data, 40, false)?;
        let private = section(data, 56, false)?;
        let code = section(data, 72, false)?;
        let sections = [&functions_range, &public, &private, &code];
        for (index, a) in sections.iter().enumerate() {
            if !a.is_empty() && a.start < HEADER_BYTES {
                return Err(error(a.start, ErrorKind::SectionOverlap));
            }
            for b in &sections[..index] {
                if !a.is_empty() && !b.is_empty() && a.start < b.end && b.start < a.end {
                    return Err(error(a.start, ErrorKind::SectionOverlap));
                }
            }
        }
        let count = u32_at(data, functions_range.start)? as usize;
        if count > functions_range.len().saturating_sub(4) / 8 {
            return Err(error(functions_range.start, ErrorKind::FunctionCount));
        }
        if count > max_functions {
            return Err(error(functions_range.start, ErrorKind::ResourceLimit));
        }
        let mut functions = Vec::new();
        functions
            .try_reserve_exact(count)
            .map_err(|_| error(functions_range.start, ErrorKind::Allocation))?;
        let mut offset = functions_range.start + 4;
        for _ in 0..count {
            let size = u32_at(data, offset)? as usize;
            if size < 8 || size > functions_range.end - offset {
                return Err(error(offset, ErrorKind::TagSize));
            }
            functions.push(Function::parse(
                data, offset, size, &public, &private, &code,
            )?);
            offset += size;
        }
        if offset != functions_range.end {
            return Err(error(offset, ErrorKind::FunctionCount));
        }
        let header_extensions = if functions_range.end < public.start {
            Some(Tags::checked(
                &data[functions_range.end..public.start],
                functions_range.end,
            )?)
        } else {
            None
        };
        Ok(Self {
            header,
            functions,
            header_extensions,
        })
    }

    pub fn functions(&self) -> &[Function<'a>] {
        &self.functions
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Function<'a> {
    pub name: &'a str,
    /// MTLB stage value, deliberately not the differently numbered MTLFunctionType.
    pub kind: u8,
    pub air_version: Version,
    pub language_version: Version,
    pub tags: Tags<'a>,
    pub public_metadata: Option<Tags<'a>>,
    pub private_metadata: Option<Tags<'a>>,
    pub digest: &'a [u8; 32],
    pub module_offset: usize,
    module: &'a [u8],
}

impl<'a> Function<'a> {
    fn parse(
        data: &'a [u8],
        offset: usize,
        size: usize,
        public: &Range<usize>,
        private: &Range<usize>,
        code: &Range<usize>,
    ) -> Result<Self> {
        let tags = Tags::checked(bytes(data, offset + 4, size - 4)?, offset + 4)?;
        let mut name = None;
        let mut kind = None;
        let mut digest = None;
        let mut module_size = None;
        let mut offsets = None;
        let mut versions = None;
        for tag in tags {
            let tag = tag?;
            let slot = match &tag.name {
                b"NAME" => &mut name,
                b"TYPE" => &mut kind,
                b"HASH" => &mut digest,
                b"MDSZ" => &mut module_size,
                b"OFFT" => &mut offsets,
                b"VERS" => &mut versions,
                _ => continue,
            };
            if slot.replace(tag.value).is_some() {
                return Err(error(tag.offset, ErrorKind::DuplicateTag(tag.name)));
            }
        }
        let required = |value: Option<&'a [u8]>, tag| {
            value.ok_or_else(|| error(offset, ErrorKind::MissingTag(tag)))
        };
        let name = required(name, *b"NAME")?;
        let name = name
            .strip_suffix(&[0])
            .filter(|name| !name.is_empty() && !name.contains(&0))
            .ok_or_else(|| error(offset, ErrorKind::Name))?;
        let name = str::from_utf8(name).map_err(|_| error(offset, ErrorKind::Name))?;
        let exact = |value: &'a [u8], size| {
            if value.len() == size {
                Ok(value)
            } else {
                Err(error(offset, ErrorKind::TagSize))
            }
        };
        let kind = exact(required(kind, *b"TYPE")?, 1)?[0];
        let digest = exact(required(digest, *b"HASH")?, 32)?.try_into().unwrap();
        let module_size = host_size(
            u64_at(exact(required(module_size, *b"MDSZ")?, 8)?, 0)?,
            offset,
        )?;
        let offsets = exact(required(offsets, *b"OFFT")?, 24)?;
        let versions = exact(required(versions, *b"VERS")?, 8)?;
        let relative_code = host_size(u64_at(offsets, 16)?, offset)?;
        let module_offset = code
            .start
            .checked_add(relative_code)
            .ok_or_else(|| error(offset, ErrorKind::Overflow))?;
        if relative_code > code.len() || module_size > code.len() - relative_code {
            return Err(error(module_offset, ErrorKind::Truncated));
        }
        let module = bytes(data, module_offset, module_size)?;
        let public_metadata = metadata(data, public, u64_at(offsets, 0)?, offset)?;
        let private_metadata = metadata(data, private, u64_at(offsets, 8)?, offset)?;
        Ok(Self {
            name,
            kind,
            digest,
            module_offset,
            module,
            air_version: Version {
                major: u16_at(versions, 0)?,
                minor: u16_at(versions, 2)?,
            },
            language_version: Version {
                major: u16_at(versions, 4)?,
                minor: u16_at(versions, 6)?,
            },
            tags,
            public_metadata,
            private_metadata,
        })
    }

    /// Original wrapped/raw module extent; no payload copy or semantic rewrite.
    pub fn module_range(&self) -> Range<usize> {
        self.module_offset..self.module_offset + self.module.len()
    }

    /// Verify the archive's digest before returning the LLVM reader's input.
    pub fn air(&self) -> Result<Air<'a>> {
        if Sha256::digest(self.module).as_slice() != self.digest {
            return Err(error(self.module_offset, ErrorKind::Hash));
        }
        Air::parse(self.module).map_err(|mut failure| {
            failure.offset += self.module_offset;
            failure
        })
    }
}

fn metadata<'a>(
    data: &'a [u8],
    section: &Range<usize>,
    relative: u64,
    source: usize,
) -> Result<Option<Tags<'a>>> {
    let relative = host_size(relative, source)?;
    if relative == 0 && section.is_empty() {
        return Ok(None);
    }
    if relative > section.len() || section.len() - relative < 4 {
        return Err(error(source, ErrorKind::Metadata));
    }
    let offset = section.start + relative;
    let size = u32_at(data, offset)? as usize;
    if size < 8 || size > section.len() - relative {
        return Err(error(offset, ErrorKind::Metadata));
    }
    Ok(Some(Tags::checked(
        &data[offset + 4..offset + size],
        offset + 4,
    )?))
}

/// Validated LLVM wrapper framing, not LLVM IR validation or shader compilation.
#[derive(Clone, Copy, Debug)]
pub struct Air<'a> {
    pub bitcode: &'a [u8],
    pub cpu_type: Option<u32>,
}

impl<'a> Air<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.starts_with(LLVM_MAGIC) {
            return Ok(Self {
                bitcode: data,
                cpu_type: None,
            });
        }
        if u32_at(data, 0)? != LLVM_WRAPPER_MAGIC {
            return Err(error(0, ErrorKind::Bitcode));
        }
        bytes(data, 0, LLVM_WRAPPER_BYTES)?;
        if u32_at(data, 4)? != 0 {
            return Err(error(4, ErrorKind::Version));
        }
        let offset = u32_at(data, 8)? as usize;
        let size = u32_at(data, 12)? as usize;
        if offset < LLVM_WRAPPER_BYTES || size < 4 {
            return Err(error(8, ErrorKind::Bitcode));
        }
        let bitcode = bytes(data, offset, size)?;
        if !bitcode.starts_with(LLVM_MAGIC) || data[offset + size..].iter().any(|byte| *byte != 0) {
            return Err(error(offset, ErrorKind::Bitcode));
        }
        Ok(Self {
            bitcode,
            cpu_type: Some(u32_at(data, 16)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    fn tag(out: &mut Vec<u8>, name: &[u8; 4], value: &[u8]) {
        out.extend_from_slice(name);
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(value);
    }

    fn u64_field(out: &mut [u8], at: usize, value: usize) {
        out[at..at + 8].copy_from_slice(&(value as u64).to_le_bytes());
    }

    /// An original synthetic container. Its payload is only LLVM framing, not a
    /// valid shader; AIR semantics are the LLVM reader/compiler's responsibility.
    fn fixture(duplicate: bool) -> Vec<u8> {
        let mut module = vec![];
        for word in [LLVM_WRAPPER_MAGIC, 0, 20, 8, u32::MAX] {
            module.extend_from_slice(&word.to_le_bytes());
        }
        module.extend_from_slice(b"BC\xc0\xde\0\0\0\0");
        module.resize(32, 0);
        let mut entry = vec![0; 4];
        tag(&mut entry, b"NAME", b"kernel\0");
        if duplicate {
            tag(&mut entry, b"NAME", b"second\0");
        }
        tag(&mut entry, b"TYPE", &[2]);
        tag(&mut entry, b"HASH", &Sha256::digest(&module));
        tag(&mut entry, b"MDSZ", &(module.len() as u64).to_le_bytes());
        tag(&mut entry, b"OFFT", &[0; 24]);
        tag(&mut entry, b"VERS", &[2, 0, 8, 0, 4, 0, 0, 0]);
        tag(&mut entry, b"FUTR", &[0xa7, 0xb8, 0xc9]);
        entry.extend_from_slice(b"ENDT");
        let size = entry.len();
        entry[..4].copy_from_slice(&(size as u32).to_le_bytes());
        let mut data = vec![0; HEADER_BYTES];
        data[..4].copy_from_slice(b"MTLB");
        data[4..6].copy_from_slice(&0x8001u16.to_le_bytes());
        data[6..8].copy_from_slice(&2u16.to_le_bytes());
        data[8..10].copy_from_slice(&9u16.to_le_bytes());
        data[11] = 0x81;
        data[12] = 26;
        u64_field(&mut data, 24, HEADER_BYTES);
        u64_field(&mut data, 32, size);
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&entry);
        // Header extension is not part of the four principal section spans.
        tag(&mut data, b"UUID", &[0x42; 16]);
        data.extend_from_slice(b"ENDT");
        let public = data.len();
        data.extend_from_slice(&8u32.to_le_bytes());
        data.extend_from_slice(b"ENDT");
        u64_field(&mut data, 40, public);
        u64_field(&mut data, 48, 8);
        let private = data.len();
        data.extend_from_slice(&8u32.to_le_bytes());
        data.extend_from_slice(b"ENDT");
        u64_field(&mut data, 56, private);
        u64_field(&mut data, 64, 8);
        let code = data.len();
        data.extend_from_slice(&module);
        u64_field(&mut data, 72, code);
        u64_field(&mut data, 80, module.len());
        let file_size = data.len();
        u64_field(&mut data, 16, file_size);
        data
    }

    #[test]
    fn original_sections_and_unknown_tags_are_preserved() {
        let data = fixture(false);
        let library = Library::parse(&data).unwrap();
        assert_eq!(library.header.platform, 0x8001);
        assert_eq!(library.header.format, Version { major: 2, minor: 9 });
        assert_eq!(
            library.header.minimum_os,
            Version {
                major: 26,
                minor: 0
            }
        );
        let function = &library.functions()[0];
        assert_eq!(function.name, "kernel");
        assert_eq!(function.kind, 2);
        assert_eq!(function.air_version, Version { major: 2, minor: 8 });
        let future = function
            .tags
            .into_iter()
            .find(|tag| tag.as_ref().unwrap().name == *b"FUTR")
            .unwrap()
            .unwrap();
        assert_eq!(future.value, &[0xa7, 0xb8, 0xc9]);
        let uuid = library.header_extensions.unwrap().next().unwrap().unwrap();
        assert_eq!(uuid.name, *b"UUID");
        assert_eq!(uuid.value, &[0x42; 16]);
        assert!(function.public_metadata.unwrap().next().is_none());
        let air = function.air().unwrap();
        assert_eq!(air.cpu_type, Some(u32::MAX));
        assert_eq!(air.bitcode, b"BC\xc0\xde\0\0\0\0");
        let bitcode_at = function.module_offset + LLVM_WRAPPER_BYTES;
        assert_eq!(air.bitcode.as_ptr(), data[bitcode_at..].as_ptr());
    }

    #[test]
    fn every_truncated_prefix_and_duplicate_required_tag_is_rejected() {
        let data = fixture(false);
        for end in 0..data.len() {
            assert!(Library::parse(&data[..end]).is_err(), "prefix {end}");
        }
        assert!(
            matches!(Library::parse(&fixture(true)).unwrap_err().kind, ErrorKind::DuplicateTag(tag) if tag == *b"NAME")
        );
    }

    #[test]
    fn payload_integrity_is_checked_when_selected() {
        let mut data = fixture(false);
        let module_at = Library::parse(&data).unwrap().functions()[0].module_offset;
        data[module_at + 24] ^= 1;
        let library = Library::parse(&data).unwrap();
        let failure = library.functions()[0].air().unwrap_err();
        assert_eq!(failure, error(module_at, ErrorKind::Hash));
    }

    #[test]
    fn overlapping_out_of_bounds_and_overflowed_sections_fail() {
        let mut data = fixture(false);
        let public = u64_at(&data, 40).unwrap();
        data[72..80].copy_from_slice(&public.to_le_bytes());
        assert_eq!(
            Library::parse(&data).unwrap_err().kind,
            ErrorKind::SectionOverlap
        );
        for field in [24, 32, 40, 48, 56, 64, 72, 80] {
            let mut data = fixture(false);
            data[field..field + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            assert!(Library::parse(&data).is_err(), "field {field}");
        }
    }

    #[test]
    fn wrapper_offsets_versions_padding_and_magic_are_checked() {
        let data = fixture(false);
        let function = Library::parse(&data).unwrap().functions()[0];
        assert!(Air::parse(b"BC\xc0\xde").is_ok());
        for (at, word) in [(0, 0), (4, 1), (8, 0), (8, u32::MAX), (12, u32::MAX)] {
            let mut module = function.module.to_vec();
            module[at..at + 4].copy_from_slice(&word.to_le_bytes());
            assert!(Air::parse(&module).is_err(), "wrapper field {at}");
        }
        let mut module = function.module.to_vec();
        module[31] = 1;
        assert_eq!(Air::parse(&module).unwrap_err().kind, ErrorKind::Bitcode);
        let mut module = function.module.to_vec();
        module[20] = 0;
        assert_eq!(Air::parse(&module).unwrap_err().kind, ErrorKind::Bitcode);
    }

    #[test]
    fn malformed_tag_and_metadata_offsets_never_escape_their_sections() {
        let base = fixture(false);
        let function = Library::parse(&base).unwrap().functions()[0];
        for name in [*b"OFFT", *b"VERS", *b"HASH", *b"MDSZ"] {
            let mut data = base.clone();
            let tag = function
                .tags
                .into_iter()
                .find(|tag| tag.as_ref().unwrap().name == name)
                .unwrap()
                .unwrap();
            data[tag.offset + 4..tag.offset + 6].copy_from_slice(&u16::MAX.to_le_bytes());
            assert!(Library::parse(&data).is_err());
        }
        let tag = function
            .tags
            .into_iter()
            .find(|tag| tag.as_ref().unwrap().name == *b"OFFT")
            .unwrap()
            .unwrap();
        for field in [0, 8, 16] {
            let mut data = base.clone();
            data[tag.offset + 6 + field..tag.offset + 14 + field]
                .copy_from_slice(&u64::MAX.to_le_bytes());
            assert!(Library::parse(&data).is_err());
        }
        let mut data = base.clone();
        data[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            Library::parse(&data).unwrap_err().kind,
            ErrorKind::FunctionCount
        );
    }

    #[test]
    fn bounded_mutations_cannot_panic_or_allocate_from_an_unchecked_count() {
        let base = fixture(false);
        let mut random = 0x51ae_17d3u32;
        for _ in 0..10_000 {
            random = random.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let index = random as usize % base.len();
            let mut data = base.clone();
            data[index] ^= (random >> 24) as u8 | 1;
            if let Ok(library) = Library::parse(&data) {
                for function in library.functions() {
                    let _ = function.air();
                }
            }
        }
    }
}

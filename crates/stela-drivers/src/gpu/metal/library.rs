//! Bounds-checked Metal library containers and LLVM bitcode wrappers.
//!
//! The MTLB layout is reverse-engineered, not a public Apple ABI. See
//! `metal/README.md` for its source and qualification scope. Shader bytes,
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
mod tests;

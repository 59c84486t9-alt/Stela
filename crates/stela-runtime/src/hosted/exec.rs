//! Image activation as XNU's `execve` performs it for an arm64e Mach-O
//! (`bsd/kern/kern_exec.c`, `mach_loader.c`): the main executable and its
//! dynamic linker mapped at their slides, the main thread's stack with the
//! kernel's argument block and apple strings, and the dynamic linker's
//! entry state. The caller supplies the images' load commands already
//! parsed; this module owns their placement in the process.
use super::memory::{
    self, PAGE_BYTES, PAGE_MASK, Protection, round_host_page, round_page, trunc_page,
};
use crate::process::{KernelArgsPlan, ProcessArguments, plan_kernel_args};
use anyhow::{Context as _, Result, ensure};
use std::{fs::File, os::fd::AsRawFd, path::PathBuf};

/// arm64 `USRSTACK64` (`bsd/arm/vmparam.h`) and the default 8 MiB stack
/// (`DFLSSIZ`).
pub const USER_STACK_TOP: u64 = 0x1_6fe0_0000;
pub const STACK_BYTES: u64 = 8 << 20;
/// The guard page below the stack the kernel allocates with it.
const STACK_GUARD_BYTES: u64 = PAGE_BYTES;
/// Where the main executable's image may go: above the host's 4 GiB
/// `__PAGEZERO`, as an arm64 PIE's TEXT does.
const EXECUTABLE_HINT: u64 = 0x1_0000_0000;
/// The dynamic linker's placement hint, well above the executable.
const DYLINKER_HINT: u64 = 0x2_0000_0000;
/// `executable_path=` (`EXECUTABLE_KEY`).
const EXECUTABLE_KEY: &str = "executable_path=";

/// One `LC_SEGMENT_64` of an image file.
#[derive(Debug, Clone)]
pub struct Segment {
    pub name: String,
    /// Unslid `vmaddr` and `vmsize`.
    pub address: u64,
    pub bytes: u64,
    /// The segment's bytes in the file, from the file's start (a fat slice's
    /// offset included).
    pub file_offset: u64,
    pub file_bytes: u64,
    pub initial: Protection,
    pub maximum: Protection,
}

#[derive(Debug, Clone)]
pub struct Image {
    pub path: PathBuf,
    pub segments: Vec<Segment>,
}

impl Image {
    /// The mapped extent: every segment except an inaccessible zero-file
    /// `__PAGEZERO` reservation, which the host's own `__PAGEZERO` covers.
    fn extent(&self) -> Result<(u64, u64)> {
        let mapped: Vec<&Segment> = self.mapped_segments().collect();
        let start = mapped
            .iter()
            .map(|s| s.address)
            .min()
            .context("image has no mapped segment")?;
        let end = mapped
            .iter()
            .map(|s| s.address + s.bytes)
            .max()
            .context("image has no mapped segment")?;
        ensure!(
            start & PAGE_MASK == 0,
            "image start {start:#x} is not page aligned"
        );
        Ok((start, round_page(end).context("image end overflow")?))
    }

    fn mapped_segments(&self) -> impl Iterator<Item = &Segment> {
        self.segments
            .iter()
            .filter(|s| !(s.file_bytes == 0 && s.initial == Protection::NONE && s.address == 0))
            .filter(|s| s.bytes != 0)
    }

    /// The unslid address of the Mach header: the segment at file offset
    /// zero of the slice.
    pub fn header_address(&self, slice_offset: u64) -> Option<u64> {
        self.segments
            .iter()
            .find(|s| s.file_offset == slice_offset && s.file_bytes != 0)
            .map(|s| s.address)
    }
}

/// An image mapped at `slide`.
#[derive(Debug, Clone, Copy)]
pub struct Mapped {
    pub slide: u64,
    pub start: u64,
    pub end: u64,
}

/// Map `image` wherever its extent fits at or above `hint`, page aligned,
/// as `load_machfile` slides a PIE image.
pub fn map_image(image: &Image, hint: u64) -> Result<Mapped> {
    let (start, end) = image.extent()?;
    let size = end - start;
    let reserved = memory::allocate(hint.max(start), size, true, Protection::NONE)?;
    let slide = reserved - start;
    let file =
        File::open(&image.path).with_context(|| format!("cannot open {}", image.path.display()))?;
    for segment in image.mapped_segments() {
        let address = segment.address + slide;
        ensure!(
            segment.file_bytes <= segment.bytes,
            "{}: file bytes exceed the segment",
            segment.name
        );
        // The file's bytes in whole host pages: a host page wholly past
        // the file's end cannot be mapped from it, and the rest of the
        // segment's last guest page is the reservation's zeroed memory.
        let file_pages = round_host_page(segment.file_bytes).context("segment size overflow")?;
        if segment.file_bytes != 0 {
            ensure!(
                segment.file_offset & PAGE_MASK == 0,
                "{}: file offset {:#x} is not page aligned",
                segment.name,
                segment.file_offset
            );
            // SAFETY: a fixed private file mapping inside this image's
            // fresh reservation.
            let mapped = unsafe {
                libc::mmap(
                    address as *mut libc::c_void,
                    file_pages.min(segment.bytes) as usize,
                    Protection::READ_WRITE.0,
                    libc::MAP_PRIVATE | libc::MAP_FIXED,
                    file.as_raw_fd(),
                    segment.file_offset as libc::off_t,
                )
            };
            ensure!(
                mapped as u64 == address,
                "cannot map {} of {}: {}",
                segment.name,
                image.path.display(),
                std::io::Error::last_os_error()
            );
            // Bytes past the segment's file size in its last page are zero.
            let tail = segment.file_bytes..file_pages.min(segment.bytes);
            if !tail.is_empty() {
                let zeros = vec![0u8; (tail.end - tail.start) as usize];
                ensure!(memory::write(address + tail.start, &zeros), "segment tail");
            }
        }
        // The zero-fill remainder is the reservation's own zeroed memory.
        memory::protect(address, segment.bytes, segment.initial)?;
    }
    Ok(Mapped {
        slide,
        start: reserved,
        end: reserved + size,
    })
}

pub fn map_executable(image: &Image) -> Result<Mapped> {
    map_image(image, EXECUTABLE_HINT)
}

pub fn map_dylinker(image: &Image) -> Result<Mapped> {
    map_image(image, DYLINKER_HINT)
}

/// The main thread's stack: its guard page and 8 MiB below `USRSTACK64`,
/// or wherever the host has room.
#[derive(Debug, Clone, Copy)]
pub struct Stack {
    pub allocation: u64,
    pub allocation_bytes: u64,
    pub base: u64,
    pub top: u64,
}

pub fn map_stack() -> Result<Stack> {
    let allocation_bytes = STACK_BYTES + STACK_GUARD_BYTES;
    let wanted = USER_STACK_TOP - allocation_bytes;
    let allocation = memory::allocate(wanted, allocation_bytes, false, Protection::READ_WRITE)
        .or_else(|_| memory::allocate(wanted, allocation_bytes, true, Protection::READ_WRITE))?;
    memory::protect(allocation, STACK_GUARD_BYTES, Protection::NONE)?;
    Ok(Stack {
        allocation,
        allocation_bytes,
        base: allocation + STACK_GUARD_BYTES,
        top: allocation + allocation_bytes,
    })
}

/// The apple strings XNU's `exec_add_apple_strings` adds after
/// `executable_path`, in its order.
#[derive(Debug, Clone, Default)]
pub struct AppleStrings {
    pub pfz: u64,
    pub stack_guard: [u64; 4],
    pub malloc_entropy: [u64; 2],
    pub ptr_munge: u64,
    pub stack: Option<Stack>,
    pub executable_file: Option<(u64, u64)>,
    pub dyld_file: Option<(u64, u64)>,
    pub cdhash: Option<[u8; 20]>,
    pub boot_hash: Option<[u8; 20]>,
    pub thread_port: Option<u32>,
    pub security_config: u32,
}

impl AppleStrings {
    pub fn render(&self) -> Vec<Vec<u8>> {
        let mut strings = vec![format!("pfz={:#x}", self.pfz)];
        // The first guard value keeps an embedded NUL byte (its low byte).
        strings.push(format!(
            "stack_guard={:#x},{:#x},{:#x},{:#x}",
            self.stack_guard[0] & !0xff,
            self.stack_guard[1],
            self.stack_guard[2],
            self.stack_guard[3]
        ));
        strings.push(format!(
            "malloc_entropy={:#x},{:#x}",
            self.malloc_entropy[0], self.malloc_entropy[1]
        ));
        strings.push(format!("ptr_munge={:#x}", self.ptr_munge));
        if let Some(stack) = self.stack {
            strings.push(format!(
                "main_stack={:#x},{:#x},{:#x},{:#x}",
                stack.top,
                stack.top - stack.base,
                stack.allocation,
                stack.allocation_bytes
            ));
        }
        if let Some((fsid, object)) = self.executable_file {
            strings.push(format!("executable_file={fsid:#x},{object:#x}"));
        }
        if let Some((fsid, object)) = self.dyld_file {
            strings.push(format!("dyld_file={fsid:#x},{object:#x}"));
        }
        if let Some(cdhash) = self.cdhash {
            strings.push(format!("executable_cdhash={}", hex::encode(cdhash)));
        }
        if let Some(hash) = self.boot_hash {
            strings.push(format!("executable_boothash={}", hex::encode(hash)));
        }
        if let Some(port) = self.thread_port {
            strings.push(format!("th_port={port:#x}"));
        }
        strings.push(format!("security_config={:#x}", self.security_config));
        strings.into_iter().map(String::into_bytes).collect()
    }
}

/// Install the kernel's argument block at the stack's top: the main Mach
/// header address, argc, argv, envp and apple, with `executable_path`
/// first among the apple strings.
pub fn install_arguments(
    stack: &Stack,
    header: u64,
    executable_path: &[u8],
    argv: &[Vec<u8>],
    environment: &[Vec<u8>],
    apple: &AppleStrings,
) -> Result<KernelArgsPlan> {
    let mut path = EXECUTABLE_KEY.as_bytes().to_vec();
    path.extend_from_slice(executable_path);
    let plan = plan_kernel_args(
        stack.base,
        stack.top - stack.base,
        header,
        &path,
        &ProcessArguments {
            argv: argv.to_vec(),
            environment: environment.to_vec(),
            apple: apple.render(),
        },
    )?;
    ensure!(
        memory::write(plan.payload_address, &plan.initial_bytes),
        "cannot write the argument block"
    );
    Ok(plan)
}

/// `stat`'s device and inode of `path`, the `executable_file=`/`dyld_file=`
/// values (`vnode_get_va_fsid`, `va_fileid`).
pub fn file_identity(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.dev(), metadata.ino()))
}

pub fn page_floor(address: u64) -> u64 {
    trunc_page(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn images_map_at_a_slide_with_file_bytes_and_zero_fill() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("image");
        let mut data = vec![0xabu8; PAGE_BYTES as usize * 2];
        data[PAGE_BYTES as usize..].fill(0xcd);
        std::fs::write(&path, &data).unwrap();
        let image = Image {
            path,
            segments: vec![
                Segment {
                    name: "__PAGEZERO".into(),
                    address: 0,
                    bytes: 0x1_0000_0000,
                    file_offset: 0,
                    file_bytes: 0,
                    initial: Protection::NONE,
                    maximum: Protection::NONE,
                },
                Segment {
                    name: "__TEXT".into(),
                    address: 0x1_0000_0000,
                    bytes: PAGE_BYTES,
                    file_offset: 0,
                    file_bytes: PAGE_BYTES,
                    initial: Protection::READ_EXECUTE,
                    maximum: Protection::READ_EXECUTE,
                },
                Segment {
                    name: "__DATA".into(),
                    address: 0x1_0000_4000,
                    bytes: PAGE_BYTES * 2,
                    file_offset: PAGE_BYTES,
                    file_bytes: 0x100,
                    initial: Protection::READ_WRITE,
                    maximum: Protection::READ_WRITE,
                },
            ],
        };
        let mapped = map_executable(&image).unwrap();
        assert_eq!(mapped.slide & PAGE_MASK, 0);
        let text = 0x1_0000_0000 + mapped.slide;
        assert_eq!(memory::read(text, 4).unwrap(), [0xab; 4]);
        assert!(!memory::write(text, &[0]));
        let data = text + PAGE_BYTES;
        assert_eq!(memory::read(data + 0xff, 2).unwrap(), [0xcd, 0]);
        assert_eq!(memory::read(data + PAGE_BYTES, 4).unwrap(), [0; 4]);
        assert!(memory::write(data + PAGE_BYTES, &[1]));
        memory::deallocate(mapped.start, mapped.end - mapped.start).unwrap();
    }

    #[test]
    fn a_segment_ending_at_the_files_end_maps_in_host_pages() {
        // A thin image whose last segment ends 0x1a50 bytes into its last
        // 16 KiB page, at the end of the file: the host pages past the
        // file's end come from the reservation, zeroed.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("image");
        let tail = 0x1a50;
        let mut data = vec![0xabu8; PAGE_BYTES as usize + tail];
        data[PAGE_BYTES as usize..].fill(0xcd);
        std::fs::write(&path, &data).unwrap();
        let segment = |name: &str, address, file_offset, file_bytes, initial| Segment {
            name: name.into(),
            address,
            bytes: PAGE_BYTES,
            file_offset,
            file_bytes,
            initial,
            maximum: initial,
        };
        let image = Image {
            path,
            segments: vec![
                segment(
                    "__TEXT",
                    0x1_0000_0000,
                    0,
                    PAGE_BYTES,
                    Protection::READ_EXECUTE,
                ),
                segment(
                    "__LINKEDIT",
                    0x1_0000_4000,
                    PAGE_BYTES,
                    tail as u64,
                    Protection::READ,
                ),
            ],
        };
        let mapped = map_executable(&image).unwrap();
        let linkedit = 0x1_0000_4000 + mapped.slide;
        let last = linkedit + tail as u64 - 1;
        assert_eq!(memory::read(last, 2).unwrap(), [0xcd, 0]);
        assert_eq!(memory::read(linkedit + PAGE_BYTES - 4, 4).unwrap(), [0; 4]);
        memory::deallocate(mapped.start, mapped.end - mapped.start).unwrap();
    }

    #[test]
    fn apple_strings_follow_exec_order() {
        let strings = AppleStrings {
            pfz: 0xf_ffff_8000,
            ptr_munge: 0x1234,
            thread_port: Some(0x103),
            cdhash: Some([0xaa; 20]),
            ..Default::default()
        }
        .render();
        let text: Vec<String> = strings
            .into_iter()
            .map(|s| String::from_utf8(s).unwrap())
            .collect();
        assert_eq!(text[0], "pfz=0xfffff8000");
        assert!(text[1].starts_with("stack_guard=0x0,"));
        assert_eq!(text[3], "ptr_munge=0x1234");
        assert!(text.contains(&format!("executable_cdhash={}", "aa".repeat(20))));
        assert_eq!(text.last().unwrap(), "security_config=0x0");
        assert!(text.contains(&"th_port=0x103".to_string()));
    }
}

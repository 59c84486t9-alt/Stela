//! The task's information (`task_info`, `osfmk/kern/task.c`) and the
//! location of dyld's image list it keeps (`task_set_dyld_info`).
//!
//! The task is the host task (process accounting), so most flavors are the
//! host kernel's answer. The rest restate it in arm64 terms: the flavors
//! whose layout differs between the kernels (`TASK_BASIC_INFO_64` is the
//! 32-bit layout on arm64, `TASK_BASIC_INFO_64_2` arm64's own), the times
//! in absolute time (the profile's 24 MHz timebase), the VM page size, the
//! executable's UUID and dyld's image list, which are the guest's.
use super::super::Kernel;
use super::server::{MIG_BAD_ARGUMENTS, Reply, Request};
use crate::hosted::darwin::{KERN_FAILURE, KERN_INVALID_ARGUMENT, KERN_SUCCESS};
use crate::hosted::threads::lock;
use crate::hosted::{host, memory};
use anyhow::{Result, bail};

/// `task_info_t`'s MIG bound (`array[*:93+1] of integer_t`).
const TASK_INFO_MAX: u32 = 94;

/// `task_flavor_t`s (`osfmk/mach/task_info.h`) the hosted kernel restates,
/// with their counts in words.
const TASK_ABSOLUTETIME_INFO: u32 = 1;
const TASK_BASIC_INFO_32: u32 = 4;
const TASK_BASIC_INFO_64: u32 = 5;
const TASK_DYLD_INFO: u32 = 17;
const TASK_BASIC_INFO_64_2: u32 = 18;
const TASK_EXTMOD_INFO: u32 = 19;
const TASK_POWER_INFO: u32 = 21;
const TASK_VM_INFO: u32 = 22;
const TASK_VM_INFO_PURGEABLE: u32 = 23;
const TASK_POWER_INFO_V2: u32 = 26;
const TASK_SECURITY_CONFIG_INFO: u32 = 32;
const TASK_IPC_SPACE_POLICY_INFO: u32 = 33;
const TASK_BASIC_INFO_32_COUNT: u32 = 8;
const TASK_BASIC_INFO_64_2_COUNT: u32 = 10;
/// The host's (x86) `TASK_BASIC_INFO_64`, whose layout is arm64's
/// `TASK_BASIC_INFO_64_2`.
const HOST_TASK_BASIC_INFO_64: u32 = 5;
/// `TASK_DYLD_INFO`'s counts: without and with `all_image_info_format`.
const TASK_LEGACY_DYLD_INFO_COUNT: u32 = 4;
const TASK_DYLD_INFO_COUNT: u32 = 5;
/// `TASK_DYLD_ALL_IMAGE_INFO_64`.
const TASK_DYLD_ALL_IMAGE_INFO_64: u32 = 1;
/// The doublewords of each flavor that are absolute time: the totals and
/// live threads' user and system times; the power information's total
/// user and system times, and (v2, after the six of `cpu_energy` and the
/// four of `gpu_energy`) the time on performance cores.
const ABSOLUTETIME_TIMES: &[usize] = &[0, 1, 2, 3];
const POWER_INFO_TIMES: &[usize] = &[0, 1];
const POWER_INFO_V2_TIMES: &[usize] = &[0, 1, 10];
/// `task_vm_info.page_size`.
const VM_INFO_PAGE_SIZE: usize = 3;

unsafe extern "C" {
    fn task_info(task: u32, flavor: i32, info: *mut u32, count: *mut u32) -> i32;
}

/// `task_info(flavor, task_info_outCnt)` on this task's port `port`.
pub(super) fn info(kernel: &Kernel, port: u32, request: &Request) -> Result<Reply> {
    let (Some(flavor), Some(count)) = (request.word(8), request.word(12)) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    let count = count.min(TASK_INFO_MAX);
    Ok(match flavor {
        TASK_BASIC_INFO_64 if count < TASK_BASIC_INFO_32_COUNT => {
            Reply::Failure(KERN_INVALID_ARGUMENT)
        }
        TASK_BASIC_INFO_64 => host_words(port, TASK_BASIC_INFO_32, TASK_BASIC_INFO_32_COUNT)
            .map_or_else(Reply::Failure, words),
        TASK_BASIC_INFO_64_2 if count < TASK_BASIC_INFO_64_2_COUNT => {
            Reply::Failure(KERN_INVALID_ARGUMENT)
        }
        TASK_BASIC_INFO_64_2 => {
            host_words(port, HOST_TASK_BASIC_INFO_64, TASK_BASIC_INFO_64_2_COUNT)
                .map_or_else(Reply::Failure, words)
        }
        TASK_ABSOLUTETIME_INFO | TASK_POWER_INFO | TASK_POWER_INFO_V2 => {
            let times = match flavor {
                TASK_ABSOLUTETIME_INFO => ABSOLUTETIME_TIMES,
                TASK_POWER_INFO => POWER_INFO_TIMES,
                _ => POWER_INFO_V2_TIMES,
            };
            match host_words(port, flavor, count) {
                Ok(mut answer) => {
                    restate_times(&mut answer, times);
                    words(answer)
                }
                Err(code) => Reply::Failure(code),
            }
        }
        TASK_VM_INFO | TASK_VM_INFO_PURGEABLE => match host_words(port, flavor, count) {
            Ok(mut answer) => {
                if let Some(page_size) = answer.get_mut(VM_INFO_PAGE_SIZE) {
                    *page_size = memory::PAGE_BYTES as u32;
                }
                words(answer)
            }
            Err(code) => Reply::Failure(code),
        },
        TASK_EXTMOD_INFO => match host_words(port, flavor, count) {
            Ok(mut answer) => {
                let header = lock(&kernel.process.executable).header;
                let uuid = image_uuid(header).unwrap_or_default();
                for (word, bytes) in answer.iter_mut().zip(uuid.as_chunks::<4>().0) {
                    *word = u32::from_le_bytes(*bytes);
                }
                words(answer)
            }
            Err(code) => Reply::Failure(code),
        },
        TASK_DYLD_INFO => lock(&kernel.process.dyld_info).task_info(count),
        TASK_SECURITY_CONFIG_INFO | TASK_IPC_SPACE_POLICY_INFO => bail!(
            "task_info flavor {flavor}: the task's security configuration and IPC space \
             policy, which exec derives from the image's signature, are not modeled"
        ),
        // The host task's own answer, which is this task's.
        _ => Reply::Forward,
    })
}

/// The host kernel's `flavor` answer for this task in `count` words.
fn host_words(port: u32, flavor: u32, count: u32) -> Result<Vec<u32>, u32> {
    let mut answer = vec![0u32; TASK_INFO_MAX as usize];
    let mut filled = count.min(TASK_INFO_MAX);
    // SAFETY: this task's port and a buffer of `filled` words.
    let code =
        unsafe { task_info(port, flavor as i32, answer.as_mut_ptr(), &raw mut filled) } as u32;
    if code != KERN_SUCCESS {
        return Err(code);
    }
    answer.truncate(filled.min(TASK_INFO_MAX) as usize);
    Ok(answer)
}

/// A reply of `task_info_outCnt` and the words.
fn words(answer: Vec<u32>) -> Reply {
    let mut body = (answer.len() as u32).to_le_bytes().to_vec();
    body.extend(answer.iter().flat_map(|word| word.to_le_bytes()));
    Reply::Success(body)
}

/// Restate the absolute times at the doubleword indexes `times` from the
/// host's nanoseconds in the guest's counter ticks.
fn restate_times(answer: &mut [u32], times: &[usize]) {
    for &index in times {
        if let Some(pair) = answer.get_mut(2 * index..2 * index + 2) {
            let ticks = host::counter_at(u64::from(pair[0]) | u64::from(pair[1]) << 32);
            pair[0] = ticks as u32;
            pair[1] = (ticks >> 32) as u32;
        }
    }
}

/// `MH_MAGIC_64` and the load commands read here.
const MH_MAGIC_64: u32 = 0xfeed_facf;
const MACH_HEADER_64_BYTES: u64 = 32;
const LC_SEGMENT_64: u32 = 0x19;
const LC_UUID: u32 = 0x1b;
/// `segment_command_64` and `section_64` field offsets and sizes.
const SEGMENT_NAME: usize = 8;
const SEGMENT_ADDRESS: usize = 24;
const SEGMENT_FILE_OFFSET: usize = 40;
const SEGMENT_FILE_BYTES: usize = 48;
const SEGMENT_SECTIONS: usize = 64;
const SEGMENT_BYTES: usize = 72;
const SECTION_BYTES: usize = 80;
const SECTION_ADDRESS: usize = 32;
const SECTION_SIZE: usize = 40;
const NAME_BYTES: usize = 16;

/// The load commands of the Mach-O image whose header is mapped at
/// `header` in this process, each with its bytes; `None` when the header
/// cannot be read.
fn load_commands(header: u64) -> Option<Vec<(u32, Vec<u8>)>> {
    let fixed = memory::read(header, MACH_HEADER_64_BYTES as usize)?;
    let word = |bytes: &[u8], at: usize| {
        u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
    };
    if word(&fixed, 0) != MH_MAGIC_64 {
        return None;
    }
    let (count, size) = (word(&fixed, 16), word(&fixed, 20));
    let commands = memory::read(header + MACH_HEADER_64_BYTES, size as usize)?;
    let mut at = 0usize;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let command = commands.get(at..at + 8)?;
        let (kind, bytes) = (word(command, 0), word(command, 4) as usize);
        out.push((kind, commands.get(at..at.checked_add(bytes)?)?.to_vec()));
        at += bytes.max(8);
    }
    Some(out)
}

fn name_is(field: &[u8], name: &str) -> bool {
    let end = field
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(field.len());
    &field[..end] == name.as_bytes()
}

fn double(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
}

/// The image's `LC_UUID`.
fn image_uuid(header: u64) -> Option<[u8; 16]> {
    load_commands(header)?
        .iter()
        .find(|(kind, _)| *kind == LC_UUID)
        .and_then(|(_, bytes)| bytes.get(8..24)?.try_into().ok())
}

/// The slid address and size of the `__all_image_info` section of a
/// `__DATA_DIRTY` or `__DATA` segment of the dynamic linker mapped at
/// `header` (`note_all_image_info_section`), the image's slide being where
/// its header is mapped past the segment holding it.
fn all_image_info(header: u64) -> Option<(u64, u64)> {
    let commands = load_commands(header)?;
    let segments = || {
        commands
            .iter()
            .filter(|(kind, bytes)| *kind == LC_SEGMENT_64 && bytes.len() >= SEGMENT_BYTES)
            .map(|(_, bytes)| bytes)
    };
    let text = segments().find(|bytes| {
        double(bytes, SEGMENT_FILE_OFFSET) == 0 && double(bytes, SEGMENT_FILE_BYTES) != 0
    })?;
    let slide = header.wrapping_sub(double(text, SEGMENT_ADDRESS));
    segments()
        .filter(|bytes| {
            let name = &bytes[SEGMENT_NAME..SEGMENT_NAME + NAME_BYTES];
            name_is(name, "__DATA_DIRTY") || name_is(name, "__DATA")
        })
        .find_map(|bytes| {
            let sections = u32::from_le_bytes(
                bytes[SEGMENT_SECTIONS..SEGMENT_SECTIONS + 4]
                    .try_into()
                    .expect("four bytes"),
            ) as usize;
            (0..sections).find_map(|index| {
                let at = SEGMENT_BYTES + index * SECTION_BYTES;
                let section = bytes.get(at..at + SECTION_BYTES)?;
                name_is(&section[..NAME_BYTES], "__all_image_info").then(|| {
                    (
                        double(section, SECTION_ADDRESS).wrapping_add(slide),
                        double(section, SECTION_SIZE),
                    )
                })
            })
        })
}

/// The location of dyld's image list (`all_image_info_addr`, `_size`) and
/// whether it is final (`TF_DYLD_ALL_IMAGE_FINAL`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DyldInfo {
    address: u64,
    size: u64,
    last: bool,
}

impl DyldInfo {
    /// The task's after exec loaded the dynamic linker whose header is
    /// mapped at `header`: its `__all_image_info` section, if any.
    pub(crate) fn of_dylinker(header: u64) -> Self {
        let mut info = Self::default();
        if let Some((address, size)) = all_image_info(header) {
            info.set(address, size);
        }
        info
    }

    /// `task_set_dyld_info(addr, size, false)`: refused once final, and
    /// final after the second nonzero location.
    pub(crate) fn set(&mut self, address: u64, size: u64) -> u32 {
        if address.checked_add(size).is_none() || self.last {
            return KERN_FAILURE;
        }
        let input = address != 0 || size != 0;
        let current = self.address != 0 || self.size != 0;
        (self.address, self.size) = (address, size);
        self.last = input && current;
        KERN_SUCCESS
    }

    /// `task_info(TASK_DYLD_INFO)` with `count` words: the legacy layout
    /// without the format.
    fn task_info(&self, count: u32) -> Reply {
        if count < TASK_LEGACY_DYLD_INFO_COUNT {
            return Reply::Failure(KERN_INVALID_ARGUMENT);
        }
        let mut answer = vec![
            self.address as u32,
            (self.address >> 32) as u32,
            self.size as u32,
            (self.size >> 32) as u32,
        ];
        if count >= TASK_DYLD_INFO_COUNT {
            answer.push(TASK_DYLD_ALL_IMAGE_INFO_64);
        }
        words(answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dyld_info_moves_once_then_is_final() {
        let mut info = DyldInfo::default();
        assert_eq!(info.set(0x1_0000, 0x170), KERN_SUCCESS);
        assert!(!info.last);
        // dyld's own move to its copy in the shared cache.
        assert_eq!(info.set(0x1_8000_0000, 0x170), KERN_SUCCESS);
        assert!(info.last);
        assert_eq!(info.set(0x2_0000, 0x170), KERN_FAILURE);
        assert_eq!((info.address, info.size), (0x1_8000_0000, 0x170));
        assert_eq!(DyldInfo::default().set(u64::MAX, 2), KERN_FAILURE);
        let Reply::Success(body) = info.task_info(5) else {
            panic!("TASK_DYLD_INFO failed");
        };
        assert_eq!(body.len(), 4 + 20);
        assert_eq!(u32::from_le_bytes(body[..4].try_into().unwrap()), 5);
        assert_eq!(double(&body, 4), 0x1_8000_0000);
        assert_eq!(double(&body, 12), 0x170);
        assert_eq!(u32::from_le_bytes(body[20..].try_into().unwrap()), 1);
        let Reply::Success(legacy) = info.task_info(4) else {
            panic!("legacy TASK_DYLD_INFO failed");
        };
        assert_eq!(legacy.len(), 4 + 16);
        assert!(matches!(
            info.task_info(3),
            Reply::Failure(KERN_INVALID_ARGUMENT)
        ));
    }

    /// A Mach header with a `__TEXT` segment at `text`, a `__DATA` segment
    /// with an `__all_image_info` section at `section` and an `LC_UUID`.
    fn image(text: u64, section: u64) -> Vec<u8> {
        let mut commands = Vec::new();
        let segment = |name: &str, address: u64, file_offset: u64, sections: &[(&str, u64)]| {
            let size = SEGMENT_BYTES + sections.len() * SECTION_BYTES;
            let mut bytes = vec![0u8; size];
            bytes[..4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
            bytes[4..8].copy_from_slice(&(size as u32).to_le_bytes());
            bytes[SEGMENT_NAME..SEGMENT_NAME + name.len()].copy_from_slice(name.as_bytes());
            bytes[SEGMENT_ADDRESS..SEGMENT_ADDRESS + 8].copy_from_slice(&address.to_le_bytes());
            bytes[SEGMENT_FILE_OFFSET..SEGMENT_FILE_OFFSET + 8]
                .copy_from_slice(&file_offset.to_le_bytes());
            bytes[SEGMENT_FILE_BYTES..SEGMENT_FILE_BYTES + 8]
                .copy_from_slice(&0x4000u64.to_le_bytes());
            bytes[SEGMENT_SECTIONS..SEGMENT_SECTIONS + 4]
                .copy_from_slice(&(sections.len() as u32).to_le_bytes());
            for (index, (name, address)) in sections.iter().enumerate() {
                let at = SEGMENT_BYTES + index * SECTION_BYTES;
                bytes[at..at + name.len()].copy_from_slice(name.as_bytes());
                bytes[at + SECTION_ADDRESS..at + SECTION_ADDRESS + 8]
                    .copy_from_slice(&address.to_le_bytes());
                bytes[at + SECTION_SIZE..at + SECTION_SIZE + 8]
                    .copy_from_slice(&0x170u64.to_le_bytes());
            }
            bytes
        };
        commands.extend(segment("__TEXT", text, 0, &[("__text", text + 0x1000)]));
        commands.extend(segment(
            "__DATA",
            text + 0x8000,
            0x8000,
            &[("__data", text + 0x8000), ("__all_image_info", section)],
        ));
        let mut uuid = vec![0u8; 24];
        uuid[..4].copy_from_slice(&LC_UUID.to_le_bytes());
        uuid[4..8].copy_from_slice(&24u32.to_le_bytes());
        uuid[8..].copy_from_slice(&[0xab; 16]);
        commands.extend(uuid);
        let mut header = vec![0u8; MACH_HEADER_64_BYTES as usize];
        header[..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        header[16..20].copy_from_slice(&3u32.to_le_bytes());
        header[20..24].copy_from_slice(&(commands.len() as u32).to_le_bytes());
        header.extend(commands);
        header
    }

    #[test]
    fn exec_finds_the_slid_all_image_info_section() {
        let bytes = image(0, 0x8100);
        // The image mapped at `header`, slid by its address.
        let header = bytes.as_ptr() as u64;
        assert_eq!(all_image_info(header), Some((header + 0x8100, 0x170)));
        assert_eq!(image_uuid(header), Some([0xab; 16]));
        let info = DyldInfo::of_dylinker(header);
        assert_eq!(
            (info.address, info.size, info.last),
            (header + 0x8100, 0x170, false)
        );
        // An image linked at an address slides by the difference.
        let linked = image(0x1_0000_0000, 0x1_0000_8100);
        let header = linked.as_ptr() as u64;
        assert_eq!(all_image_info(header), Some((header + 0x8100, 0x170)));
        let mut garbage = [0u8; 64];
        garbage[0] = 1;
        assert_eq!(all_image_info(garbage.as_ptr() as u64), None);
    }

    #[test]
    fn absolute_times_are_counter_ticks() {
        // One second of user time, half a second of system time.
        let mut answer = vec![1_000_000_000u32, 0, 500_000_000, 0, 7, 7];
        restate_times(&mut answer, POWER_INFO_TIMES);
        assert_eq!(answer, [24_000_000, 0, 12_000_000, 0, 7, 7]);
        let mut wide = vec![0u32, 10, 0, 0];
        restate_times(&mut wide, &[0, 1, 5]);
        let ticks = host::counter_at(10u64 << 32);
        assert_eq!(wide, [ticks as u32, (ticks >> 32) as u32, 0, 0]);
    }

    #[test]
    fn the_host_answers_the_restated_layouts() {
        let port = host::task();
        let basic = host_words(port, TASK_BASIC_INFO_32, TASK_BASIC_INFO_32_COUNT).unwrap();
        assert_eq!(basic.len(), 8);
        let wide = host_words(port, HOST_TASK_BASIC_INFO_64, TASK_BASIC_INFO_64_2_COUNT).unwrap();
        assert_eq!(wide.len(), 10);
        // The virtual size, as a 64-bit value after the suspend count.
        assert!(u64::from(wide[1]) | u64::from(wide[2]) << 32 > 0);
        let vm = host_words(port, TASK_VM_INFO, TASK_INFO_MAX).unwrap();
        assert_eq!(vm[VM_INFO_PAGE_SIZE], 4096);
    }
}

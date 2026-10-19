//! Which image activator `execve` would run on a file's first page
//! (`bsd/kern/kern_exec.c` `execsw`): a Mach-O with an arm64 slice, or a
//! `#!` interpreter script, whose line is tokenized as
//! `exec_shell_imgact` and `exec_extract_strings` do. Anything else fails
//! as the arm64 kernel fails it.

/// `IMG_SHSIZE`: the part of the first page an interpreter line must end in.
pub const SCRIPT_LINE_BYTES: usize = 512;
pub const ENOEXEC: i32 = 8;
/// `EBADARCH`: a Mach-O with no slice this machine runs.
pub const EBADARCH: i32 = 86;
const MH_MAGIC_64: u32 = 0xfeed_facf;
const MH_CIGAM_64: u32 = 0xcffa_edfe;
const MH_MAGIC: u32 = 0xfeed_face;
const MH_CIGAM: u32 = 0xcefa_edfe;
const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;

/// What the file is to `execve`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Activator {
    /// A Mach-O this machine runs.
    MachO,
    /// A script: the interpreter line's tokens, the interpreter first.
    Interpreter(Vec<Vec<u8>>),
}

/// The activator for a file whose first bytes are `head` (at least the
/// first page, or the whole file if shorter), or the errno `execve`
/// returns.
pub fn activator(head: &[u8]) -> Result<Activator, i32> {
    let word = |at: usize, big: bool| {
        head.get(at..at + 4).map(|bytes| {
            let bytes: [u8; 4] = bytes.try_into().unwrap();
            if big {
                u32::from_be_bytes(bytes)
            } else {
                u32::from_le_bytes(bytes)
            }
        })
    };
    match word(0, false) {
        Some(MH_MAGIC_64) => {
            return if word(4, false) == Some(CPU_TYPE_ARM64) {
                Ok(Activator::MachO)
            } else {
                Err(EBADARCH)
            };
        }
        Some(MH_CIGAM_64 | MH_MAGIC | MH_CIGAM) => return Err(EBADARCH),
        _ => {}
    }
    if let Some(magic @ (FAT_MAGIC | FAT_MAGIC_64)) = word(0, true) {
        // `struct fat_arch` is 20 bytes, `fat_arch_64` 32.
        let stride = if magic == FAT_MAGIC { 20 } else { 32 };
        let count = word(4, true).unwrap_or(0) as usize;
        let arm64 = (0..count).any(|index| word(8 + index * stride, true) == Some(CPU_TYPE_ARM64));
        return if arm64 {
            Ok(Activator::MachO)
        } else {
            Err(EBADARCH)
        };
    }
    if head.starts_with(b"#!") {
        return interpreter_line(head).map(Activator::Interpreter);
    }
    Err(ENOEXEC)
}

/// The CPU type and subtype (capability bits included) of each Mach-O
/// slice in a file whose first bytes are `head`: the thin image's own, or
/// each fat architecture's in header order. Empty for anything else.
pub fn slices(head: &[u8]) -> Vec<(u32, u32)> {
    let word = |at: usize, big: bool| {
        head.get(at..at + 4).map(|bytes| {
            let bytes: [u8; 4] = bytes.try_into().unwrap();
            if big {
                u32::from_be_bytes(bytes)
            } else {
                u32::from_le_bytes(bytes)
            }
        })
    };
    if word(0, false) == Some(MH_MAGIC_64) {
        return word(4, false).zip(word(8, false)).into_iter().collect();
    }
    let Some(magic @ (FAT_MAGIC | FAT_MAGIC_64)) = word(0, true) else {
        return Vec::new();
    };
    let stride = if magic == FAT_MAGIC { 20 } else { 32 };
    let count = word(4, true).unwrap_or(0) as usize;
    (0..count)
        .map_while(|index| word(8 + index * stride, true).zip(word(12 + index * stride, true)))
        .collect()
}

/// `exec_shell_imgact`'s line, split as `exec_extract_strings` splits it:
/// on spaces and tabs, ending at a newline or `#`, within the first
/// `IMG_SHSIZE` bytes.
fn interpreter_line(head: &[u8]) -> Result<Vec<Vec<u8>>, i32> {
    let whitespace = |byte: u8| byte == b' ' || byte == b'\t';
    let end_of_line = |byte: u8| byte == b'#' || byte == b'\n';
    let mut line = [0u8; SCRIPT_LINE_BYTES];
    let length = head.len().min(SCRIPT_LINE_BYTES);
    line[..length].copy_from_slice(&head[..length]);
    let start = (2..SCRIPT_LINE_BYTES)
        .find(|&index| !whitespace(line[index]))
        .ok_or(ENOEXEC)?;
    if end_of_line(line[start]) {
        return Err(ENOEXEC);
    }
    let end = (start..SCRIPT_LINE_BYTES)
        .find(|&index| end_of_line(line[index]))
        .ok_or(ENOEXEC)?;
    Ok(line[start..end]
        .split(|&byte| whitespace(byte))
        .filter(|token| !token.is_empty())
        .map(<[u8]>::to_vec)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts_and_slices_choose_their_activator() {
        assert_eq!(
            activator(b"#!  /usr/bin/perl -w -T # comment\nprint 1;\n"),
            Ok(Activator::Interpreter(vec![
                b"/usr/bin/perl".to_vec(),
                b"-w".to_vec(),
                b"-T".to_vec(),
            ]))
        );
        assert_eq!(activator(b"#!\n"), Err(ENOEXEC));
        assert_eq!(activator(b"#! /bin/sh"), Err(ENOEXEC));
        assert_eq!(activator(b"plain text\n"), Err(ENOEXEC));
        let mut thin = MH_MAGIC_64.to_le_bytes().to_vec();
        thin.extend(CPU_TYPE_ARM64.to_le_bytes());
        assert_eq!(activator(&thin), Ok(Activator::MachO));
        let mut x86 = MH_MAGIC_64.to_le_bytes().to_vec();
        x86.extend(0x0100_0007u32.to_le_bytes());
        assert_eq!(activator(&x86), Err(EBADARCH));
        let mut fat = FAT_MAGIC.to_be_bytes().to_vec();
        fat.extend(2u32.to_be_bytes());
        fat.extend(0x0100_0007u32.to_be_bytes());
        fat.extend([0; 16]);
        fat.extend(CPU_TYPE_ARM64.to_be_bytes());
        fat.extend([0; 16]);
        assert_eq!(activator(&fat), Ok(Activator::MachO));
        assert_eq!(
            slices(&fat),
            [(0x0100_0007, 0), (CPU_TYPE_ARM64, 0)],
            "fat architectures in order"
        );
        let mut thin_e = thin.clone();
        thin_e.extend(0x8000_0002u32.to_le_bytes());
        assert_eq!(slices(&thin_e), [(CPU_TYPE_ARM64, 0x8000_0002)]);
        assert!(slices(b"#! /bin/sh\n").is_empty());
    }
}

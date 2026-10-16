//! Multiboot module intake. Module bytes are borrowed unchanged.
use core::{ptr, slice};
const IDENTITY_END: usize = 1 << 30;
const MAX_COMMAND_BYTES: usize = 4096;
const MEMORY_MAP: u32 = 1 << 6;
const MODULES: u32 = 1 << 3;
const COMMAND_LINE: u32 = 1 << 2;
#[repr(C)]
#[derive(Clone, Copy)]
struct Info {
    flags: u32,
    lower: u32,
    upper: u32,
    device: u32,
    command: u32,
    modules_count: u32,
    modules_address: u32,
    symbols: [u32; 4],
    map_bytes: u32,
    map_address: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Module {
    start: u32,
    end: u32,
    command: u32,
    reserved: u32,
}
#[derive(Clone, Copy, Debug)]
pub struct Transport {
    pub module_start: usize,
    pub module_end: usize,
    map_start: usize,
    map_end: usize,
    command: usize,
    // All trusted-loader input storage remains reserved, including unused
    // module command bytes and the complete standard Multiboot info extent.
    live: [(usize, usize); 6],
}
fn command_bytes(address: usize) -> Result<usize, &'static str> {
    if address == 0 {
        return Ok(0);
    }
    for bytes in 1..=MAX_COMMAND_BYTES {
        if extent(address, bytes).is_none() {
            return Err("command extent overflow");
        }
        if unsafe { ptr::read((address + bytes - 1) as *const u8) } == 0 {
            return Ok(bytes);
        }
    }
    Err("unterminated command line")
}
fn extent(start: usize, bytes: usize) -> Option<usize> {
    start
        .checked_add(bytes)
        .filter(|end| start != 0 && *end <= IDENTITY_END)
}
impl Transport {
    /// # Safety
    /// Exact Multiboot1 entry from trusted QEMU loader; advertised transport
    /// bytes are live immutable identity-mapped RAM for the duration of boot.
    pub unsafe fn read(address: u32, magic: u32) -> Result<Self, &'static str> {
        if magic != 0x2bad_b002 || extent(address as usize, 116).is_none() {
            return Err("invalid Multiboot1 entry");
        }
        let info = unsafe { ptr::read_unaligned(address as *const Info) };
        if info.flags & (MEMORY_MAP | MODULES) != (MEMORY_MAP | MODULES) || info.modules_count != 1
        {
            return Err("one unchanged source module and E820 map required");
        }
        if extent(info.modules_address as usize, size_of::<Module>()).is_none() {
            return Err("invalid module descriptor extent");
        }
        let module = unsafe { ptr::read_unaligned(info.modules_address as *const Module) };
        if module.end <= module.start
            || extent(module.start as usize, (module.end - module.start) as usize).is_none()
        {
            return Err("invalid original source module extent");
        }
        let map_start = info.map_address as usize;
        let map_end = extent(map_start, info.map_bytes as usize).ok_or("invalid E820 extent")?;
        let command = if info.flags & COMMAND_LINE != 0 {
            info.command as usize
        } else {
            0
        };
        let command_extent = command_bytes(command)?;
        let module_command_extent = command_bytes(module.command as usize)?;
        let transport = Self {
            module_start: module.start as usize,
            module_end: module.end as usize,
            map_start,
            map_end,
            command,
            live: [
                (address as usize, 116),
                (info.modules_address as usize, size_of::<Module>()),
                (map_start, info.map_bytes as usize),
                (command, command_extent),
                (module.command as usize, module_command_extent),
                (module.start as usize, (module.end - module.start) as usize),
            ],
        };
        if !transport.normal_ram(
            transport.module_start,
            transport.module_end - transport.module_start,
        )? {
            return Err("source module is outside normal RAM");
        }
        Ok(transport)
    }
    pub fn overlaps(&self, start: usize, bytes: usize) -> Result<bool, &'static str> {
        let end = start
            .checked_add(bytes)
            .ok_or("reservation extent overflow")?;
        for (input, length) in self.live {
            let input_end = input
                .checked_add(length)
                .ok_or("transport extent overflow")?;
            if length != 0 && start < input_end && input < end {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub fn normal_ram(&self, start: usize, bytes: usize) -> Result<bool, &'static str> {
        let end = start.checked_add(bytes).ok_or("RAM extent overflow")? as u64;
        let mut at = self.map_start;
        let mut covered = false;
        while at < self.map_end {
            if at.checked_add(4).is_none_or(|v| v > self.map_end) {
                return Err("truncated E820 size");
            }
            let size = unsafe { ptr::read_unaligned(at as *const u32) } as usize;
            let next = at
                .checked_add(4)
                .and_then(|v| v.checked_add(size))
                .ok_or("E820 overflow")?;
            if size < 20 || next > self.map_end {
                return Err("invalid E820 record");
            }
            let base = unsafe { ptr::read_unaligned((at + 4) as *const u64) };
            let length = unsafe { ptr::read_unaligned((at + 12) as *const u64) };
            let kind = unsafe { ptr::read_unaligned((at + 20) as *const u32) };
            let limit = base
                .checked_add(length)
                .ok_or("E820 physical range overflow")?;
            if kind == 1 && base <= start as u64 && end <= limit {
                covered = true;
            }
            at = next;
        }
        Ok(covered)
    }
    pub fn command(&self) -> Result<&'static str, &'static str> {
        if self.command == 0 {
            return Ok("");
        }
        for bytes in 0..MAX_COMMAND_BYTES {
            if extent(self.command, bytes + 1).is_none() {
                return Err("command extent overflow");
            }
            if unsafe { ptr::read((self.command + bytes) as *const u8) } == 0 {
                let raw = unsafe { slice::from_raw_parts(self.command as *const u8, bytes) };
                return core::str::from_utf8(raw).map_err(|_| "command is not UTF-8");
            }
        }
        Err("unterminated command line")
    }
    pub fn source(&self) -> &'static [u8] {
        // SAFETY: validated live immutable trusted-loader module. Its reserved
        // physical extent is excluded from heap, tables and code/RAM arenas.
        unsafe {
            slice::from_raw_parts(
                self.module_start as *const u8,
                self.module_end - self.module_start,
            )
        }
    }
}

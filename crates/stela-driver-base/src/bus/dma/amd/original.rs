//! AMD48882rev3.11 original host DTE interpretation. These are DATA decoders,
//! not root/source/allocation owners or completion/engine/IRQ receipts.
//! Actual original-root adoption must keep the real table and control owners.

const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const MODE: u64 = 7 << 9;
const IR: u64 = 1 << 61;
const IW: u64 = 1 << 62;
const V: u64 = 1;
const TV: u64 = 2;
const DOMAIN: u64 = 0xffff;
const SYSTEM_MANAGEMENT: u64 = 3 << 40;
const EXCLUSION: u64 = 1 << 39;
const IO_CONTROL: u64 = 3 << 35;
const IOTLB: u64 = 1 << 32;
const IRQ_FIELDS: u64 = 1 | (1 << 5) | (7 << 56) | (3 << 60) | (3 << 62);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Width,
    Reserved,
    BypassPolicy,
    GuestOrHardwareWriter,
    InterruptTable,
    DormantRoot,
    Untranslated,
    Address,
}

/// Literal ordinary-memory semantics from Table7pp73–74/Table8p74. Special
/// system-management, exclusion, port-I/O and ATS policy is NOT resolved here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataMode {
    /// V0: fields127:1 invalid, ordinary addresses forwarded untranslated.
    Untranslated,
    /// V1/TV0: ordinary requests requiring a walk terminate, Mode/IR/IW ignored.
    /// SysMgt/EX/IoCtl/I remain valid; this alone is NOT a containment grant.
    WalkTerminated,
    /// V1/TV1/Mode0: SPA=GPA, actual IR/IW decide ordinary DMA permissions.
    Identity { read: bool, write: bool },
    Paged {
        levels: u8,
        root: u64,
        domain: u16,
        read: bool,
        write: bool,
    },
}
pub fn data_mode(words: [u64; 4]) -> Result<DataMode, Error> {
    let low = words[0];
    if low & V == 0 {
        return Ok(DataMode::Untranslated);
    }
    if low & TV == 0 {
        return Ok(DataMode::WalkTerminated);
    }
    if low & !(V | TV | MODE | ADDRESS | IR | IW) != 0 {
        return Err(Error::GuestOrHardwareWriter);
    }
    let read = low & IR != 0;
    let write = low & IW != 0;
    let levels = ((low & MODE) >> 9) as u8;
    match levels {
        0 => Ok(DataMode::Identity { read, write }),
        1..=6 => Ok(DataMode::Paged {
            levels,
            root: low & ADDRESS,
            domain: (words[1] & DOMAIN) as u16,
            read,
            write,
        }),
        _ => Err(Error::Reserved),
    }
}

/// Initial read-only host-profile decoder, preserving the actual interrupt
/// bytes as data. This type confers no right to mutate a table or enable DMA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Dte {
    words: [u64; 4],
    mode: DataMode,
}
impl Dte {
    pub fn inspect_host(words: [u64; 4], physical_bits: u8) -> Result<Self, Error> {
        if !(32..=52).contains(&physical_bits) {
            return Err(Error::Width);
        }
        // No guest translation, hardware A/D updates, ATS, CXL attributes,
        // encryption overrides or unrecognized write-capable table formats.
        if words[0] & !(V | TV | MODE | ADDRESS | IR | IW) != 0 {
            return Err(Error::GuestOrHardwareWriter);
        }
        // V1/TV0 still honors these fields. Never preserve SMM/unity/exclusion/
        // I/O or remote-IOTLB bypass as permission for a private ordinary domain.
        if words[1] & (SYSTEM_MANAGEMENT | EXCLUSION | IO_CONTROL | IOTLB) != 0 {
            return Err(Error::BypassPolicy);
        }
        if words[1] & !DOMAIN != 0 {
            return Err(Error::GuestOrHardwareWriter);
        }
        // Initial mode retains ordinary unremapped/blocked IRQ policy only.
        // Active/dormant interrupt-table/GCR3/GVA/virtualization backing needs
        // its separate real owner. No IRQ-history conclusion follows IV0.
        if words[2] & !IRQ_FIELDS != 0 || words[3] != 0 || ((words[2] >> 60) & 3) > 1 {
            return Err(Error::InterruptTable);
        }
        let mode = data_mode(words)?;
        if mode == DataMode::Untranslated {
            return Err(Error::Untranslated);
        }
        if mode == DataMode::WalkTerminated && words[0] & (MODE | ADDRESS | IR | IW) != 0 {
            return Err(Error::DormantRoot);
        }
        if let DataMode::Paged { root, .. } = mode
            && root >= 1u64 << physical_bits
        {
            return Err(Error::Address);
        }
        Ok(Self { words, mode })
    }
    pub fn mode(self) -> DataMode {
        self.mode
    }
    pub fn words(self) -> [u64; 4] {
        self.words
    }
    /// Canonical DATA update for a consumed real retirement owner to publish.
    /// Actual mutation must preserve original CPU/control/table custody and
    /// acknowledge matched invalidations. This value itself grants none.
    pub fn blocked_data(self) -> [u64; 4] {
        [V, self.words[1], self.words[2], self.words[3]]
    }
}

pub mod retirement;
pub mod tables;
#[cfg(test)]
mod tests;

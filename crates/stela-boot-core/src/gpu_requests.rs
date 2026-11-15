//! The request codes the GPU reports count a service's host calls under: an
//! ioctl's own code, and a small code of its own for each other host call
//! (a map, a page fault, a file open), below every ioctl's, which carries
//! its argument's size and direction. [`Request`] prints either, so a long
//! map or fault reads as one rather than as request zero.

/// A host call that is not an ioctl, by its code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum HostCall {
    Open = 1,
    Close = 2,
    Duplicate = 3,
    Device = 4,
    Map = 5,
    Unmap = 6,
    Fault = 7,
    Thread = 8,
    Wake = 9,
    Export = 10,
    Shutdown = 11,
}

impl HostCall {
    const ALL: [Self; 11] = [
        Self::Open,
        Self::Close,
        Self::Duplicate,
        Self::Device,
        Self::Map,
        Self::Unmap,
        Self::Fault,
        Self::Thread,
        Self::Wake,
        Self::Export,
        Self::Shutdown,
    ];

    pub const fn code(self) -> u32 {
        self as u32
    }

    fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Close => "close",
            Self::Duplicate => "dup",
            Self::Device => "device",
            Self::Map => "map",
            Self::Unmap => "unmap",
            Self::Fault => "fault",
            Self::Thread => "thread",
            Self::Wake => "wake",
            Self::Export => "export",
            Self::Shutdown => "shutdown",
        }
    }
}

/// A request code as the reports print it: an ioctl's in hex, another host
/// call's by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request(pub u32);

impl core::fmt::Display for Request {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match HostCall::ALL.iter().find(|call| call.code() == self.0) {
            Some(call) => f.write_str(call.name()),
            None => write!(f, "{:#x}", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HostCall, Request};
    use alloc::format;

    #[test]
    fn host_calls_print_by_name_and_ioctls_in_hex() {
        assert_eq!(format!("{}", Request(HostCall::Map.code())), "map");
        assert_eq!(format!("{}", Request(HostCall::Fault.code())), "fault");
        // DRM_IOCTL_NOUVEAU_GEM_NEW.
        assert_eq!(format!("{}", Request(0xc030_6480)), "0xc0306480");
        assert_eq!(format!("{}", Request(0)), "0x0");
        // Every ioctl code carries its argument's size, at bit 16: none is
        // as small as a host call's.
        for call in HostCall::ALL {
            assert!(call.code() < 1 << 16);
            assert_eq!(format!("{}", Request(call.code())), call.name());
        }
    }
}

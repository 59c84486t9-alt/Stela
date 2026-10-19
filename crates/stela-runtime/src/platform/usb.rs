//! Native USB bus peers. No guest code execution or translator callbacks.
pub mod control;
pub mod hid;
pub mod host;
pub mod hub;
pub mod mux;
pub mod plist;
pub mod session;

/// The initial transport profile has USB2 high-speed packets only.
pub const MAX_PACKET: usize = 512;

/// A function's signaling speed on its port (USB 2.0 7.1.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Speed {
    Low,
    Full,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token {
    Setup,
    Out,
    In,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    Ack(usize),
    Nak,
    Stall,
}

/// One synchronous bus transaction, reached only by the machine owner.
/// `data` carries OUT bytes, or provides space for an IN packet. A NAK has
/// no payload effect. DMA failures remain errors; they are never a USB ACK.
pub trait BusPeer {
    fn reset(&mut self) -> Result<(), &'static str>;
    fn packet(
        &mut self,
        endpoint: u8,
        token: Token,
        data: &mut [u8],
    ) -> Result<Reply, &'static str>;
}

/// A device on a host controller's port: the bus transactions of
/// [`BusPeer`], and when an endpoint that NAKed next has something to say.
/// A host polls periodic endpoints; asking this keeps an idle bus from
/// polling one that would only NAK.
pub trait Function: BusPeer {
    /// The current system count, before a burst of transactions.
    fn set_time(&mut self, now: u64);
    /// The system count from which IN `endpoint` would answer other than
    /// NAK: `Some(0)` at once, a later count for a timed report, `None`
    /// until new input arrives.
    fn ready_at(&self, endpoint: u8) -> Option<u64>;
    /// The function on downstream port `port` (from 1) while it can take
    /// transactions: a hub's enabled, unsuspended port. Other functions
    /// have no downstream ports.
    fn downstream(&mut self, _port: u8) -> Option<&mut dyn Function> {
        None
    }
    fn downstream_ref(&self, _port: u8) -> Option<&dyn Function> {
        None
    }
}

/// The function an xHCI route string names below `root` (xHCI 1.2 8.9:
/// four bits per hub tier, tier 1 in bits 3:0, ended by a zero port).
pub fn route<'a>(root: &'a mut dyn Function, route: u32) -> Option<&'a mut dyn Function> {
    let mut function = root;
    let mut rest = route & 0xf_ffff;
    while rest & 0xf != 0 {
        function = function.downstream((rest & 0xf) as u8)?;
        rest >>= 4;
    }
    Some(function)
}

/// [`route`] for a shared reference.
pub fn route_ref<'a>(root: &'a dyn Function, route: u32) -> Option<&'a dyn Function> {
    let mut function = root;
    let mut rest = route & 0xf_ffff;
    while rest & 0xf != 0 {
        function = function.downstream_ref((rest & 0xf) as u8)?;
        rest >>= 4;
    }
    Some(function)
}

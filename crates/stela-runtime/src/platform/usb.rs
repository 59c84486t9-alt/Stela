//! Native USB bus peers. No guest code execution or translator callbacks.
pub mod hid;
pub mod host;
pub mod mux;
pub mod plist;
pub mod session;

/// The initial transport profile has USB2 high-speed packets only.
pub const MAX_PACKET: usize = 512;

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
}

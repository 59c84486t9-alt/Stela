//! Native USB bus peers. No guest code execution or translator callbacks.

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

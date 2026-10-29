//! Owners required by the source endpoint. No successful defaults.
use super::super::platform::owner::Completion;
use super::wire::Buffer;
use crate::Result;
use alloc::rc::Rc;
use stela_contracts::bus::Access;

#[derive(Clone, Debug)]
pub struct Request {
    pub(super) owner: Rc<()>,
    pub(super) serial: u64,
    pub(super) operation: u64,
}
impl Request {
    pub fn same_operation(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.owner, &other.owner)
            && self.serial == other.serial
            && self.operation == other.operation
    }
}
#[derive(Clone, Debug)]
pub struct WaitKey(pub(super) Rc<()>);
impl WaitKey {
    pub fn same_waiter(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

/// Canonical AP allocation, with kept mapping/descriptor ownership. Dropping
/// this value is not unmap/release. A write returns its byte prefix,
/// including on post-effect refusal; Busy/Refused commit no bytes. Reads return
/// exactly the requested extent or refuse, never a private database mirror.
pub trait Mapping {
    fn geometry(&self) -> Buffer;
    /// Runtime104b23c equivalent, derived by the cache/map owner.
    fn synchronization_granule(&self) -> Result<u64>;
    fn write(
        &mut self,
        request: &Request,
        offset: u64,
        bytes: &[u8],
        access: &mut Access<'_>,
    ) -> Completion<usize>;
    fn read(
        &mut self,
        request: &Request,
        offset: u64,
        bytes: usize,
        access: &mut Access<'_>,
    ) -> Completion<alloc::vec::Vec<u8>>;
    fn synchronize(
        &mut self,
        request: &Request,
        offset: u64,
        bytes: u64,
        access: &mut Access<'_>,
    ) -> Completion<()>;
}
/// Source failure may retire a map attempt, but is never an invented mapping.
pub enum MapResult<M> {
    Mapped(M),
    SourceError(u32),
}

/// Immediate receive callbacks use these resources independently of the blocked
/// synchronous registration/global DB worker. Neither callback grants MC/PTD ACK.
pub trait Wake {
    fn publication_ack(&mut self, key: &WaitKey, access: &mut Access<'_>) -> Completion<()>;
    fn queue_refresh(&mut self, access: &mut Access<'_>) -> Completion<()>;
}
pub trait Resources {
    type Mapping: Mapping;
    /// Claim the singleton RTKit builtin endpoint4 and global DB work.
    fn claim(&mut self, request: &Request, access: &mut Access<'_>) -> Completion<()>;
    fn map(
        &mut self,
        request: &Request,
        buffer: Buffer,
        flags: u32,
        access: &mut Access<'_>,
    ) -> Completion<MapResult<Self::Mapping>>;
    fn dsb_sy(&mut self, request: &Request, access: &mut Access<'_>) -> Completion<()>;
    /// Read and convert the configured native clock, not supplied time.
    fn converted_clock(&mut self, request: &Request, access: &mut Access<'_>) -> Completion<u64>;
    fn send(
        &mut self,
        request: &Request,
        endpoint: u8,
        payload: u64,
        access: &mut Access<'_>,
    ) -> Completion<()>;
    fn arm_wait(
        &mut self,
        request: &Request,
        key: &WaitKey,
        access: &mut Access<'_>,
    ) -> Completion<()>;
    fn wait(&mut self, request: &Request, key: &WaitKey, access: &mut Access<'_>)
    -> Completion<()>;
    fn unmap(
        &mut self,
        request: &Request,
        mapping: &mut Self::Mapping,
        access: &mut Access<'_>,
    ) -> Completion<()>;
    fn release(
        &mut self,
        request: &Request,
        mapping: &mut Self::Mapping,
        access: &mut Access<'_>,
    ) -> Completion<()>;
}

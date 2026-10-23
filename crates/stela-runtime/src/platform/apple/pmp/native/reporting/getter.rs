//! Native callable representation retained out of band; never host pointers.
use super::{record::Layout, resources::Request};
use super::super::platform::owner::Completion;
use crate::platform::apple::bus::Access;
use alloc::boxed::Box;

pub trait Scalar {
    fn get(&mut self, request: &Request, access: &mut Access<'_>) -> Completion<u64>;
}
pub trait Pair {
    fn get(&mut self, request: &Request, index: u32, access: &mut Access<'_>) -> Completion<(u64, u64)>;
}
pub trait Indexed {
    fn get(&mut self, request: &Request, index: u32, access: &mut Access<'_>) -> Completion<u64>;
}
pub trait State {
    fn get(&mut self, request: &Request, index: u32, access: &mut Access<'_>) -> Completion<[u64; 4]>;
}
pub enum LiveGetter {
    Scalar(Box<dyn Scalar>),
    Pairs { count: u32, getter: Box<dyn Pair> },
    Scalars { count: u32, getter: Box<dyn Indexed> },
    States { count: u32, descriptions: u16, getter: Box<dyn State> },
}
impl LiveGetter {
    pub fn layout(&self) -> Layout {
        match self {
            Self::Scalar(_) => Layout::Scalar,
            Self::Pairs { count, .. } => Layout::Pairs(*count),
            Self::Scalars { count, .. } => Layout::Scalars(*count),
            Self::States { count, descriptions, .. } => Layout::States { count: *count, descriptions: *descriptions },
        }
    }
    pub(super) fn get(&mut self, request: &Request, index: u32, access: &mut Access<'_>) -> Completion<alloc::vec::Vec<u8>> {
        fn bytes<T>(value: Completion<T>, encode: impl FnOnce(T) -> alloc::vec::Vec<u8>) -> Completion<alloc::vec::Vec<u8>> {
            match value {
                Completion::Busy { deadline } => Completion::Busy { deadline },
                Completion::Refused(e) => Completion::Refused(e),
                Completion::Retired { value, refusal } => Completion::Retired { value: encode(value), refusal },
            }
        }
        match self {
            Self::Scalar(g) => bytes(g.get(request, access), |v| v.to_le_bytes().to_vec()),
            Self::Pairs { getter, .. } => bytes(getter.get(request, index, access), |(a,b)| [a.to_le_bytes(), b.to_le_bytes()].concat()),
            Self::Scalars { getter, .. } => bytes(getter.get(request, index, access), |v| v.to_le_bytes().to_vec()),
            Self::States { getter, .. } => bytes(getter.get(request, index, access), |v| v.into_iter().flat_map(u64::to_le_bytes).collect()),
        }
    }
}
impl Scalar for super::super::cache::metrics::Counter {
    fn get(&mut self, _: &Request, _: &mut Access<'_>) -> Completion<u64> {
        Completion::Retired { value: self.value(), refusal: None }
    }
}

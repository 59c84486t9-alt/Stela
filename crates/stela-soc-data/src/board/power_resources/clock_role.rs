//! Source driver roles distinguish published gate indices from start-time
//! dependencies. This grants no native PMGR resource or lifecycle authority.
use super::{DomainId, Node, name_of};
use alloc::{string::String, vec::Vec};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ClockRole {
    /// Ordinary consumers retain all collected ancestor and local gates.
    #[default]
    Consumer,
    /// A bound PMGR function provider publishes its own gate-index metadata;
    /// its IOService start does not call that provider's enableDeviceClock.
    PmgrProvider(PmgrClockProvider),
}

/// Source-created provider identity, not an arbitrary gate exemption. Private
/// fields retain the actual function binding and active ancestor requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PmgrClockProvider {
    phandle: u32,
    ancestor_clocks: Vec<DomainId>,
}
impl PmgrClockProvider {
    pub fn phandle(&self) -> u32 {
        self.phandle
    }
    pub(super) fn ancestors(&self) -> &[DomainId] {
        &self.ancestor_clocks
    }
}

pub(super) struct ProviderNode<'a> {
    registers: &'a [u8],
    phandle: u32,
}
impl ProviderNode<'_> {
    pub(super) fn role(&self, node: &Node<'_>, ancestors: &[DomainId]) -> ClockRole {
        if node
            .property("reg")
            .is_some_and(|raw| core::ptr::eq(raw, self.registers))
        {
            ClockRole::PmgrProvider(PmgrClockProvider {
                phandle: self.phandle,
                ancestor_clocks: ancestors.to_vec(),
            })
        } else {
            ClockRole::Consumer
        }
    }
}

/// The 26A434 M1/M2 Pro and Max personalities inherit ApplePMGR::start,
/// whose superclass start is IOService::start. AppleT600xIO/AppleT602xIO
/// processDevice delegates to the no-op AppleARMIO method; its separate
/// enableDeviceClock receiver uses the bound function only when called.
/// Pinned source slots and function windows are tested below.
const PROVIDER_BINDINGS: [(&str, &str); 4] = [
    ("arm-io,t6000", "pmgr1,t6000"),
    ("arm-io,t6000", "pmgr1,t6001"),
    ("arm-io,t6020", "pmgr1,t6020"),
    ("arm-io,t6020", "pmgr1,t6021"),
];

/// The actual arm-io function-clock_gate must target the direct qualified
/// controller by phandle and selector clkG. A family match alone grants no
/// role, and no passive index becomes a successful later gate operation.
pub(super) fn provider<'a>(root: &Node<'a>) -> Result<Option<ProviderNode<'a>>, String> {
    let io = root
        .child("arm-io")
        .or_else(|| (name_of(root) == "arm-io").then(|| root.clone()));
    let Some(io) = io else {
        return Ok(None);
    };
    let children = io
        .children()
        .ok_or("clock provider has malformed arm-io children")?;
    let candidates = children
        .iter()
        .filter(|node| {
            PROVIDER_BINDINGS
                .iter()
                .any(|&(bus, controller)| io.compatible(bus) && node.compatible(controller))
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Ok(None);
    }
    let Some(raw) = io.property("function-clock_gate") else {
        return Ok(None);
    };
    let [phandle, selector] = raw.as_chunks::<4>().0 else {
        return Err("PMGR clock function binding requires a phandle and selector".into());
    };
    if raw.len() != 8 {
        return Err("PMGR clock function binding has partial cells".into());
    }
    let phandle = u32::from_le_bytes(*phandle);
    if phandle == 0 {
        return Err("PMGR clock function has a zero phandle".into());
    }
    if u32::from_le_bytes(*selector) != 0x636c6b47 {
        return Ok(None);
    }
    let mut pending = alloc::vec![root.clone()];
    let mut references = 0;
    while let Some(node) = pending.pop() {
        if node
            .property("AAPL,phandle")
            .filter(|raw| raw.len() == 4)
            .is_some_and(|raw| u32::from_le_bytes(raw.try_into().expect("checked u32")) == phandle)
        {
            references += 1;
        }
        pending.extend(
            node.children()
                .ok_or("clock provider has malformed source descendants")?,
        );
    }
    if references > 1 {
        return Err("PMGR clock provider phandle is ambiguous".into());
    }
    let mut selected = candidates.into_iter().filter(|node| {
        node.property("AAPL,phandle")
            .filter(|raw| raw.len() == 4)
            .is_some_and(|raw| u32::from_le_bytes(raw.try_into().expect("checked u32")) == phandle)
    });
    let Some(node) = selected.next() else {
        return Ok(None);
    };
    if selected.next().is_some() {
        return Err("PMGR clock provider phandle is ambiguous".into());
    }
    super::super::apertures::registers(node)
        .ok_or("PMGR clock provider lacks complete actual reg pairs")?;
    Ok(Some(ProviderNode {
        registers: node.property("reg").expect("checked reg pairs"),
        phandle,
    }))
}

#[cfg(test)]
mod tests;

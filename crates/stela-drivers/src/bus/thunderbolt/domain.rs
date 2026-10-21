// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2018 Intel Corporation
//! Physical-controller-scoped topology observations and hotplug invalidation.
//!
//! Routing/upstream checks and subtree removal follow the read-only portion of
//! Linux tb.c hotplug handling. These records do not authorize any router or
//! own a tunnel. Invalidating observations never pretends to stop device DMA.
use super::{
    config::{PlugEvent, Route},
    topology::{AdapterKind, AdapterObservation, Inventory, Path},
};
use crate::bus::pci;
use alloc::vec::Vec;

/// The actual enumerated NHI requester plus a platform-issued ownership/reset
/// epoch. The platform must never reuse an epoch for a new controller lifetime.
/// This is not a Type-C connector identity or a guessed connector/router map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub nhi: pci::Address,
    pub epoch: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Identity,
    HistoryBudget,
    GenerationExhausted,
    RootRequired,
    UnknownRouter,
    UnknownPort,
    Upstream,
    NotLane,
    Depth,
    Inventory,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub generation: u64,
    pub inventory: Inventory,
    /// None means currently observed; the invalidating generation is retained
    /// forever in this bounded journal. Old inventory bytes are never rewritten.
    pub invalidated_at: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub generation: u64,
    pub invalidated: Vec<Path>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hotplug {
    /// A real event only requests a scan. It does not establish a connection.
    Rescan {
        generation: u64,
        path: Path,
    },
    Removed(Change),
    AlreadyObserved {
        generation: u64,
        path: Path,
    },
    UpstreamIgnored {
        generation: u64,
    },
    ControlAdapter {
        generation: u64,
    },
    AdapterChanged {
        generation: u64,
        router: Route,
        port: u8,
    },
}
pub struct Domain {
    identity: Identity,
    generation: u64,
    history: Vec<Observation>,
    limit: u16,
}
impl Domain {
    pub fn new(identity: Identity, history_limit: u16) -> Result<Self, Error> {
        if identity.nhi.device >= 32 || identity.nhi.function >= 8 || identity.epoch == 0 {
            return Err(Error::Identity);
        }
        if history_limit == 0 {
            return Err(Error::HistoryBudget);
        }
        Ok(Self {
            identity,
            generation: 0,
            history: Vec::new(),
            limit: history_limit,
        })
    }
    pub fn identity(&self) -> Identity {
        self.identity
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn history(&self) -> &[Observation] {
        &self.history
    }
    pub fn current(&self, route: Route) -> Option<&Observation> {
        self.history.iter().rev().find(|record| {
            record.invalidated_at.is_none() && record.inventory.path.route() == route
        })
    }
    fn next_generation(&self) -> Result<u64, Error> {
        self.generation
            .checked_add(1)
            .ok_or(Error::GenerationExhausted)
    }
    fn validate(inventory: &Inventory) -> Result<(), Error> {
        let max = inventory.header.max_port();
        if inventory.upstream_port > max || inventory.adapters.len() != usize::from(max) {
            return Err(Error::Inventory);
        }
        let mut seen = 0u64;
        for adapter in &inventory.adapters {
            let port = match adapter {
                AdapterObservation::Present { port, .. }
                | AdapterObservation::Unimplemented { port, .. } => *port,
            };
            if port == 0 || port > max || seen & (1u64 << port) != 0 {
                return Err(Error::Inventory);
            }
            seen |= 1u64 << port;
        }
        Ok(())
    }
    fn parent(path: Path) -> Result<(Path, u8), Error> {
        let depth = path.depth();
        if depth == 0 {
            return Err(Error::RootRequired);
        }
        let shift = (depth - 1) * 8;
        let port = (path.route().raw() >> shift) as u8;
        let route =
            Route::new(path.route().raw() & ((1u64 << shift) - 1)).map_err(|_| Error::Inventory)?;
        Ok((Path::new(route).map_err(|_| Error::Inventory)?, port))
    }
    fn lane(&self, parent: Path, port: u8) -> Result<(), Error> {
        let record = self.current(parent.route()).ok_or(Error::UnknownRouter)?;
        if port == 0 || port > record.inventory.header.max_port() {
            return Err(Error::UnknownPort);
        }
        if port == record.inventory.upstream_port {
            return Err(Error::Upstream);
        }
        if !record.inventory.adapters.iter().any(|adapter|matches!(adapter,AdapterObservation::Present { port:number,header,.. } if *number==port && header.kind()==AdapterKind::Lane)) { return Err(Error::NotLane); }
        Ok(())
    }
    fn invalidate(&mut self, path: Path, generation: u64) -> Vec<Path> {
        let mut invalidated = Vec::new();
        for record in &mut self.history {
            if record.invalidated_at.is_none()
                && (record.inventory.path == path || record.inventory.path.is_descendant_of(path))
            {
                invalidated.push(record.inventory.path);
                record.invalidated_at = Some(generation);
            }
        }
        // Consumers tear descendants down before parents. This is an ordering
        // requirement for future CM/tunnel owners, not a DMA teardown receipt.
        invalidated.sort_by_key(|path| core::cmp::Reverse(path.depth()));
        invalidated
    }
    pub fn observe(&mut self, inventory: Inventory) -> Result<Change, Error> {
        Self::validate(&inventory)?;
        if self.history.len() >= usize::from(self.limit) {
            return Err(Error::HistoryBudget);
        }
        let path = inventory.path;
        if path.depth() != 0 {
            let root = self
                .current(Route::new(0).map_err(|_| Error::Inventory)?)
                .ok_or(Error::RootRequired)?;
            if path.depth()
                > if root.inventory.header.usb4_version() > 0 || inventory.header.usb4_version() > 0
                {
                    5
                } else {
                    6
                }
            {
                return Err(Error::Depth);
            }
            let (parent, port) = Self::parent(path)?;
            self.lane(parent, port)?;
        }
        let generation = self.next_generation()?;
        let invalidated = self.invalidate(path, generation);
        self.history.push(Observation {
            generation,
            inventory,
            invalidated_at: None,
        });
        self.generation = generation;
        Ok(Change {
            generation,
            invalidated,
        })
    }
    /// Apply a checked event from this domain's own Channel. Unknown sources
    /// remain errors; port numbers never create observations or authorization.
    /// The containing CM must independently tear actual tunnels down before
    /// releasing requester domains or allowing any affected device reuse.
    pub fn hotplug(&mut self, event: PlugEvent) -> Result<Hotplug, Error> {
        let record = self.current(event.route).ok_or(Error::UnknownRouter)?;
        if event.port > record.inventory.header.max_port() {
            return Err(Error::UnknownPort);
        }
        let generation = self.next_generation()?;
        let result=if event.port==0 { Hotplug::ControlAdapter { generation } }
        else if event.port==record.inventory.upstream_port { Hotplug::UpstreamIgnored { generation } }
        else if !record.inventory.adapters.iter().any(|adapter|matches!(adapter,AdapterObservation::Present { port,header,.. } if *port==event.port && header.kind()==AdapterKind::Lane)) { Hotplug::AdapterChanged { generation,router:event.route,port:event.port } }
        else {
            let root=self.current(Route::new(0).map_err(|_|Error::Inventory)?).ok_or(Error::RootRequired)?;
            let path=record.inventory.path.downstream(event.port,root.inventory.header.usb4_version()>0).map_err(|_|Error::Depth)?;
            if event.unplug { Hotplug::Removed(Change { generation,invalidated:self.invalidate(path,generation) }) }
            else if self.current(path.route()).is_some() { Hotplug::AlreadyObserved { generation,path } }
            else { Hotplug::Rescan { generation,path } }
        };
        self.generation = generation;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::super::topology::{AdapterHeader, RouterHeader};
    use super::*;
    fn identity() -> Identity {
        Identity {
            nhi: pci::Address {
                segment: 3,
                bus: 4,
                device: 5,
                function: 6,
            },
            epoch: 7,
        }
    }
    fn inventory(raw: u64, usb4: bool) -> Inventory {
        let mut ports = Vec::new();
        for port in 1..=3 {
            let mut raw = [0; 8];
            raw[2] = if port == 3 { 0x200101 } else { 1 };
            raw[3] = u32::from(port) << 20;
            ports.push(AdapterObservation::Present {
                port,
                header: AdapterHeader { raw },
                capabilities: Vec::new(),
            });
        }
        Inventory {
            path: Path::new(Route::new(raw).unwrap()).unwrap(),
            upstream_port: if raw == 0 { 0 } else { 2 },
            header: RouterHeader {
                raw: [
                    0x12348086,
                    3 << 14,
                    raw as u32,
                    (raw >> 32) as u32,
                    if usb4 { 1 << 29 } else { 0 },
                ],
            },
            capabilities: Vec::new(),
            adapters: ports,
        }
    }
    fn event(route: u64, port: u8, unplug: bool) -> PlugEvent {
        PlugEvent {
            route: Route::new(route).unwrap(),
            port,
            unplug,
            header_flags: 0,
        }
    }
    #[test]
    fn controller_scoped_history_preserves_unplugged_subtree_and_sibling() {
        let mut domain = Domain::new(identity(), 20).unwrap();
        domain.observe(inventory(0, true)).unwrap();
        domain.observe(inventory(1, true)).unwrap();
        domain.observe(inventory(0x101, true)).unwrap();
        domain.observe(inventory(2, true)).unwrap();
        let original = domain.history()[1].inventory.clone();
        let result = domain.hotplug(event(0, 1, true)).unwrap();
        let Hotplug::Removed(change) = result else {
            panic!("removal")
        };
        assert_eq!(
            change
                .invalidated
                .iter()
                .map(|path| path.route().raw())
                .collect::<Vec<_>>(),
            vec![0x101, 1]
        );
        assert_eq!(domain.history()[1].inventory, original);
        assert_eq!(domain.history()[1].invalidated_at, Some(5));
        assert!(domain.current(Route::new(1).unwrap()).is_none());
        assert!(domain.current(Route::new(2).unwrap()).is_some());
        assert!(
            matches!(domain.hotplug(event(0,1,false)).unwrap(),Hotplug::Rescan { path,.. } if path.route().raw()==1)
        );
        assert_eq!(domain.history().len(), 4);
        domain.observe(inventory(1, true)).unwrap();
        assert_eq!(domain.history().len(), 5);
        assert_eq!(domain.history()[1].inventory, original);
        assert_eq!(domain.identity(), identity());
    }
    #[test]
    fn parent_upstream_adapter_and_unknown_events_cannot_invent_routes() {
        let mut domain = Domain::new(identity(), 20).unwrap();
        assert_eq!(domain.observe(inventory(1, true)), Err(Error::RootRequired));
        domain.observe(inventory(0, true)).unwrap();
        assert_eq!(domain.observe(inventory(3, true)), Err(Error::NotLane));
        domain.observe(inventory(1, true)).unwrap();
        assert_eq!(domain.observe(inventory(0x201, true)), Err(Error::Upstream));
        let generation = domain.generation();
        assert_eq!(
            domain.hotplug(event(4, 1, false)),
            Err(Error::UnknownRouter)
        );
        assert_eq!(domain.hotplug(event(0, 4, true)), Err(Error::UnknownPort));
        assert_eq!(domain.generation(), generation);
        assert!(matches!(
            domain.hotplug(event(1, 2, true)).unwrap(),
            Hotplug::UpstreamIgnored { .. }
        ));
        assert!(matches!(
            domain.hotplug(event(0, 0, true)).unwrap(),
            Hotplug::ControlAdapter { .. }
        ));
        assert!(matches!(
            domain.hotplug(event(0, 3, true)).unwrap(),
            Hotplug::AdapterChanged { .. }
        ));
        assert!(matches!(
            domain.hotplug(event(0, 1, false)).unwrap(),
            Hotplug::AlreadyObserved { .. }
        ));
        assert_eq!(domain.history().len(), 2);
    }
    #[test]
    fn rejected_budget_malformed_or_overflow_observation_never_mutates_history() {
        let mut domain = Domain::new(identity(), 2).unwrap();
        domain.observe(inventory(0, true)).unwrap();
        let mut malformed = inventory(1, true);
        malformed.adapters[0] = malformed.adapters[1].clone();
        assert_eq!(domain.observe(malformed), Err(Error::Inventory));
        assert_eq!(domain.generation(), 1);
        domain.observe(inventory(1, true)).unwrap();
        let history = domain.history().to_vec();
        assert_eq!(
            domain.observe(inventory(0, true)),
            Err(Error::HistoryBudget)
        );
        assert_eq!(domain.history(), history);
        assert_eq!(domain.generation(), 2);
        domain.generation = u64::MAX;
        assert_eq!(
            domain.hotplug(event(0, 1, true)),
            Err(Error::GenerationExhausted)
        );
        assert_eq!(domain.history(), history);
    }
    #[test]
    fn refreshed_root_invalidates_existing_tree_before_publishing_new_observation() {
        let mut domain = Domain::new(identity(), 20).unwrap();
        domain.observe(inventory(0, false)).unwrap();
        domain.observe(inventory(1, false)).unwrap();
        let changed = domain.observe(inventory(0, true)).unwrap();
        assert_eq!(
            changed
                .invalidated
                .iter()
                .map(|path| path.route().raw())
                .collect::<Vec<_>>(),
            vec![1, 0]
        );
        assert!(domain.current(Route::new(1).unwrap()).is_none());
        assert_eq!(domain.history().len(), 3);
        assert_eq!(
            domain
                .current(Route::new(0).unwrap())
                .unwrap()
                .inventory
                .header
                .usb4_version(),
            1
        );
    }
}

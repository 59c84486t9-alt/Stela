//! Plan broad physical windows around explicitly supplied, existing owners.
use super::{Bus, DeviceId, MapError};
use alloc::vec::Vec;

/// An explicit existing subview. It retains no storage and authorizes no MMIO
/// effects. The planner rechecks its actual owner and affine offsets each time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedView {
    device: DeviceId,
    start: u64,
    end: u64,
    device_offset: u64,
}

impl Bus {
    /// Validate a complete already-owned view, including every byte and its
    /// device offset. Neither endpoint probes nor a matching device ID alone
    /// qualify a subview. Adjacent bindings must preserve one affine mapping.
    pub fn shared_view(
        &self,
        device: DeviceId,
        start: u64,
        bytes: u64,
        device_offset: u64,
    ) -> Result<SharedView, MapError> {
        if device.0 >= self.devices.len() {
            return Err(MapError::UnknownDevice);
        }
        if bytes == 0 {
            return Err(MapError::Empty);
        }
        let end = start.checked_add(bytes).ok_or(MapError::Overflow)?;
        device_offset.checked_add(bytes).ok_or(MapError::Overflow)?;
        let mut cursor = start;
        for region in self
            .regions
            .iter()
            .filter(|r| r.start < end && start < r.end)
        {
            if region.start > cursor {
                return Err(MapError::InvalidSharedView);
            }
            if region.device != device {
                return Err(MapError::Overlap {
                    existing: region.device,
                });
            }
            if region.device_offset + (cursor - region.start) != device_offset + (cursor - start) {
                return Err(MapError::InvalidSharedView);
            }
            cursor = end.min(region.end);
        }
        if cursor != end {
            return Err(MapError::InvalidSharedView);
        }
        Ok(SharedView {
            device,
            start,
            end,
            device_offset,
        })
    }

    /// Coalesce physical aliases and leave complete actual child routes intact.
    /// Offsets in the returned bindings are physical addresses. Planning is
    /// read-only; callers install the complete result in one transaction.
    pub fn container_bindings(
        &self,
        views: &[(u64, u64)],
        children: &[DeviceId],
    ) -> Result<Vec<(u64, u64, u64)>, MapError> {
        self.container_bindings_with_shared(views, children, &[])
    }

    /// Partial intersections additionally require explicit, completely validated
    /// shared views. These describe physical aliases of actual owners, never a
    /// second model, storage allocation or relaxed gap/overlap admission.
    pub fn container_bindings_with_shared(
        &self,
        views: &[(u64, u64)],
        children: &[DeviceId],
        shared: &[SharedView],
    ) -> Result<Vec<(u64, u64, u64)>, MapError> {
        if views.is_empty() {
            return Err(MapError::Empty);
        }
        if children.iter().any(|id| id.0 >= self.devices.len()) {
            return Err(MapError::UnknownDevice);
        }
        let mut spans = Vec::new();
        for &(start, bytes) in views {
            if bytes == 0 {
                return Err(MapError::Empty);
            }
            spans.push((start, start.checked_add(bytes).ok_or(MapError::Overflow)?));
        }
        spans.sort_unstable();
        let mut union: Vec<(u64, u64)> = Vec::new();
        for (start, end) in spans {
            if let Some(last) = union.last_mut()
                && start <= last.1
            {
                last.1 = last.1.max(end);
            } else {
                union.push((start, end));
            }
        }
        let mut shared = shared.to_vec();
        shared.sort_unstable_by_key(|view| view.start);
        for view in &shared {
            self.shared_view(
                view.device,
                view.start,
                view.end - view.start,
                view.device_offset,
            )?;
            if !union
                .iter()
                .any(|&(start, end)| start <= view.start && view.end <= end)
            {
                return Err(MapError::InvalidSharedView);
            }
        }
        if shared.windows(2).any(|pair| pair[0].end > pair[1].start) {
            return Err(MapError::ProposedOverlap);
        }
        let mut bindings = Vec::new();
        for (start, end) in union {
            let mut cursor = start;
            for child in self
                .regions
                .iter()
                .filter(|region| region.start < end && start < region.end)
            {
                let cut_start = start.max(child.start);
                let cut_end = end.min(child.end);
                let whole_child =
                    children.contains(&child.device) && child.start >= start && child.end <= end;
                if !whole_child {
                    let mut covered = cut_start;
                    for view in shared.iter().filter(|view| view.device == child.device) {
                        if view.end <= covered {
                            continue;
                        }
                        if view.start > covered {
                            break;
                        }
                        covered = cut_end.min(view.end);
                        if covered == cut_end {
                            break;
                        }
                    }
                    if covered != cut_end {
                        return Err(MapError::Overlap {
                            existing: child.device,
                        });
                    }
                }
                if cursor < cut_start {
                    bindings.push((cursor, cut_start - cursor, cursor));
                }
                cursor = cut_end;
            }
            if cursor < end {
                bindings.push((cursor, end - cursor, cursor));
            }
        }
        Ok(bindings)
    }

    /// The placed window holding `address`: its bounds, owner and the
    /// owner's offset at its start.
    pub fn window_at(&self, address: u64) -> Option<(u64, u64, DeviceId, u64)> {
        self.regions
            .iter()
            .find(|region| region.start <= address && address < region.end)
            .map(|region| {
                (
                    region.start,
                    region.end,
                    region.device,
                    region.device_offset,
                )
            })
    }

    /// A diagnostic names the actual retained owner without accessing it.
    pub fn device_name(&self, id: DeviceId) -> Option<&'static str> {
        self.devices.get(id.0).map(|device| device.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
    use alloc::boxed::Box;

    struct Refusing;
    impl MmioDevice for Refusing {
        fn name(&self) -> &'static str {
            "child"
        }
        fn read(
            &mut self,
            offset: u64,
            width: Width,
            _: &mut Access<'_>,
        ) -> Result<u64, MmioError> {
            Err(refuse(
                "child",
                offset,
                width,
                Direction::Read,
                "unqualified",
            ))
        }
        fn write(
            &mut self,
            offset: u64,
            width: Width,
            _: u64,
            _: &mut Access<'_>,
        ) -> Result<(), MmioError> {
            Err(refuse(
                "child",
                offset,
                width,
                Direction::Write,
                "unqualified",
            ))
        }
    }

    #[test]
    fn aliases_coalesce_without_replacing_actual_child_routes() {
        let mut bus = Bus::new();
        let child = bus
            .install(Box::new(Refusing), &[(0x1800, 0x400, 0x40)])
            .unwrap();
        let bindings = bus
            .container_bindings(
                &[(0x1000, 0x1000), (0x1400, 0x400), (0x3000, 0x400)],
                &[child],
            )
            .unwrap();
        assert_eq!(
            bindings,
            [
                (0x1000, 0x800, 0x1000),
                (0x1c00, 0x400, 0x1c00),
                (0x3000, 0x400, 0x3000)
            ]
        );
        let container = bus.install(Box::new(Refusing), &bindings).unwrap();
        assert_eq!(bus.route(0x1808, Width::Double), Ok((child, 0x48)));
        assert_eq!(bus.route(0x1400, Width::Word), Ok((container, 0x1400)));
        assert!(bus.route(0x2000, Width::Word).is_err());
        assert_eq!(bus.route(0x3000, Width::Word), Ok((container, 0x3000)));
    }

    #[test]
    fn unrelated_or_partial_children_and_malformed_views_leave_no_routes() {
        let mut bus = Bus::new();
        let child = bus
            .install(Box::new(Refusing), &[(0x1800, 0x400, 0)])
            .unwrap();
        for (views, allowed) in [
            (vec![(0x1000, 0x1000)], vec![]),
            (vec![(0x1900, 0x1000)], vec![child]),
            (vec![(0x1000, 0x900)], vec![child]),
            (vec![(0x1000, 0x400), (u64::MAX, 2)], vec![child]),
            (vec![(0x1000, 0)], vec![child]),
            (vec![], vec![child]),
        ] {
            assert!(bus.container_bindings(&views, &allowed).is_err());
            assert_eq!(bus.regions.len(), 1);
            assert_eq!(bus.devices.len(), 1);
            assert!(bus.route(0x1000, Width::Word).is_err());
        }
        assert!(
            bus.container_bindings(&[(0x1000, 0x400)], &[DeviceId(5)])
                .is_err()
        );
        assert_eq!(
            bus.container_bindings(&[(0x1800, 0x400)], &[child]),
            Ok(vec![])
        );
        assert_eq!(bus.device_name(child), Some("child"));
    }
    #[test]
    fn explicit_partial_view_keeps_the_complete_actual_bank_and_offsets() {
        let mut bus = Bus::new();
        let id = bus
            .install(Box::new(Refusing), &[(0x1800, 0x1000, 0x40)])
            .unwrap();
        let view = bus.shared_view(id, 0x1c00, 0x400, 0x440).unwrap();
        let views = [(0x1000, 0x400), (0x1c00, 0x400)];
        assert!(bus.container_bindings(&views, &[id]).is_err());
        let bindings = bus
            .container_bindings_with_shared(&views, &[], &[view])
            .unwrap();
        assert_eq!(bindings, [(0x1000, 0x400, 0x1000)]);
        bus.install(Box::new(Refusing), &bindings).unwrap();
        for (pa, offset) in [
            (0x1800, 0x40),
            (0x1c00, 0x440),
            (0x2000, 0x840),
            (0x27fc, 0x103c),
        ] {
            assert_eq!(bus.route(pa, Width::Word), Ok((id, offset)));
        }
        assert_eq!(bus.regions.len(), 2);
        assert_eq!(bus.devices.len(), 2);
    }

    #[test]
    fn shared_view_requires_full_affine_same_owner_coverage() {
        let mut bus = Bus::new();
        let id = bus
            .install(
                Box::new(Refusing),
                &[(0x1000, 0x100, 0), (0x1200, 0x100, 0x200)],
            )
            .unwrap();
        assert_eq!(
            bus.shared_view(id, 0x1000, 0x300, 0),
            Err(MapError::InvalidSharedView)
        );
        assert_eq!(
            bus.shared_view(id, 0x1000, 0x100, 1),
            Err(MapError::InvalidSharedView)
        );
        assert_eq!(bus.shared_view(id, 0x1000, 0, 0), Err(MapError::Empty));
        assert_eq!(bus.shared_view(id, u64::MAX, 2, 0), Err(MapError::Overflow));
        assert_eq!(
            bus.shared_view(id, 0x1000, 1, u64::MAX),
            Err(MapError::Overflow)
        );
        assert_eq!(
            bus.shared_view(DeviceId(9), 0x1000, 1, 0),
            Err(MapError::UnknownDevice)
        );
        bus.map(id, 0x1100, 0x100, 0x104).unwrap();
        assert_eq!(
            bus.shared_view(id, 0x1000, 0x300, 0),
            Err(MapError::InvalidSharedView)
        );
        bus.regions[1].device_offset = 0x100;
        assert!(bus.shared_view(id, 0x1000, 0x300, 0).is_ok());
        let other = bus.add(Box::new(Refusing));
        bus.regions[1].device = other;
        assert_eq!(
            bus.shared_view(id, 0x1000, 0x300, 0),
            Err(MapError::Overlap { existing: other })
        );
    }

    #[test]
    fn shared_plan_revalidates_witnesses_and_every_cut_before_publication() {
        let mut bus = Bus::new();
        let id = bus
            .install(Box::new(Refusing), &[(0x1000, 0x1000, 0x40)])
            .unwrap();
        let view = bus.shared_view(id, 0x1400, 0x400, 0x440).unwrap();
        for (views, shared) in [
            (vec![(0x1400, 0x800)], vec![view]), // incomplete cut
            (vec![(0x1400, 0x200)], vec![view]), // unused authority outside declared view
            (vec![(0x1400, 0x400)], vec![view, view]),
            (vec![(0x1400, 0x400), (u64::MAX, 2)], vec![view]),
        ] {
            assert!(
                bus.container_bindings_with_shared(&views, &[], &shared)
                    .is_err()
            );
            assert_eq!((bus.regions.len(), bus.devices.len()), (1, 1));
        }
        assert_eq!(
            bus.container_bindings_with_shared(&[(0x1400, 0x400)], &[], &[view]),
            Ok(vec![])
        );
        bus.regions[0].device_offset += 4;
        assert_eq!(
            bus.container_bindings_with_shared(&[(0x1400, 0x400)], &[], &[view]),
            Err(MapError::InvalidSharedView)
        );
    }
}

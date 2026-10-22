//! Plan broad physical windows around explicitly supplied, existing owners.
use super::{Bus, DeviceId, MapError};
use alloc::vec::Vec;

impl Bus {
    /// Coalesce physical aliases and leave the actual child routes intact.
    /// Offsets in the returned bindings are physical addresses. Planning is
    /// read-only; callers install the complete result in one transaction.
    pub(crate) fn container_bindings(
        &self,
        views: &[(u64, u64)],
        children: &[DeviceId],
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
        let mut bindings = Vec::new();
        for (start, end) in union {
            let mut cursor = start;
            for child in self
                .regions
                .iter()
                .filter(|region| region.start < end && start < region.end)
            {
                // A partial cut would assert ownership of an unqualified
                // subview of a real bank. Require its complete declaration.
                if !children.contains(&child.device) || child.start < start || child.end > end {
                    return Err(MapError::Overlap {
                        existing: child.device,
                    });
                }
                if cursor < child.start {
                    bindings.push((cursor, child.start - cursor, cursor));
                }
                cursor = child.end;
            }
            if cursor < end {
                bindings.push((cursor, end - cursor, cursor));
            }
        }
        Ok(bindings)
    }

    /// A diagnostic names the actual retained owner without accessing it.
    pub(crate) fn device_name(&self, id: DeviceId) -> Option<&'static str> {
        self.devices.get(id.0).map(|device| device.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
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
}

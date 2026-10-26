//! How the hosted kernel services each kind of request, for the
//! requirement matrix ([`crate::hosted_registry::requirements`]): the same tables
//! the dispatchers consult, so a row's status is the dispatcher's own
//! behavior.
use super::{bsd, mach};

/// One request's disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    /// The host kernel performs it unchanged; `overlay` names a model of
    /// part of its arguments that precedes the forwarding.
    Forwarded { overlay: Option<&'static str> },
    /// The hosted kernel's own model, by family.
    Modeled { family: &'static str },
    /// The run stops naming the request and the reason.
    Refused { reason: &'static str },
}

impl Service {
    pub fn served(self) -> bool {
        !matches!(self, Self::Refused { .. })
    }
}

fn find(table: &[(&str, &'static str)], name: &str) -> Option<&'static str> {
    table
        .iter()
        .find(|(entry, _)| *entry == name)
        .map(|&(_, text)| text)
}

/// The BSD call `name` of the pinned catalog, and its named limit.
pub fn bsd(name: &str) -> (Service, Option<&'static str>) {
    let service = match bsd::family(name) {
        Some(bsd::Family::Forwarded) => Service::Forwarded {
            overlay: bsd::overlay(name),
        },
        Some(family) => Service::Modeled {
            family: family.name(),
        },
        None => Service::Refused {
            reason: find(bsd::REFUSED, name).unwrap_or("no family services it"),
        },
    };
    (service, find(bsd::LIMITS, name))
}

/// The 26A434 addition at the BSD number `number`, a number the pinned
/// catalog reserves: its name, service and named limit.
pub fn bsd_addition(number: u32) -> Option<(&'static str, Service, Option<&'static str>)> {
    use bsd::additions;
    let name = additions::addition(u16::try_from(number).ok()?)?;
    let service = if additions::CALLS.contains(&name) {
        Service::Modeled {
            family: bsd::Family::Additions.name(),
        }
    } else {
        Service::Refused {
            reason: additions::UNIMPLEMENTED,
        }
    };
    Some((name, service, find(additions::LIMITS, name)))
}

/// The Mach trap `name` of the pinned catalog, and its named limit.
pub fn mach(name: &str) -> (Service, Option<&'static str>) {
    let service = match mach::forwarded(name) {
        Some(true) => Service::Forwarded { overlay: None },
        Some(false) => Service::Modeled {
            family: "Mach traps",
        },
        None => Service::Refused {
            reason: find(mach::REFUSED, name).unwrap_or("no family services it"),
        },
    };
    (service, find(mach::LIMITS, name))
}

/// The 26A434 trap at the reserved Mach index `index`: its name and
/// service.
pub fn mach_addition(index: u32) -> Option<(&'static str, Service)> {
    mach::addition(index).map(|name| {
        (
            name,
            Service::Modeled {
                family: "Mach traps",
            },
        )
    })
}

/// The kernel object a MIG subsystem's requests address in this task.
pub fn mig_object(subsystem: &str) -> Option<&'static str> {
    mach::object_of(subsystem).map(mach::object_name)
}

/// The MIG routine `routine` of `subsystem` sent to this task's, a
/// thread's or the host's kernel object, and its named limit.
pub fn mig(subsystem: &str, routine: &str) -> (Service, Option<&'static str>) {
    mach::mig_service(subsystem, routine)
}

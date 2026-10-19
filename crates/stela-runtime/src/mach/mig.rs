//! The pinned catalog of kernel-served MIG routines: the request message ids
//! the kernel's own objects (tasks, threads, the host, VM maps, ports,
//! clocks, processors, vouchers, ...) answer, by subsystem.
//!
//! The rows in [`generated`] are the subsystems xnu registers for its
//! objects (`osfmk/kern/ipc_kobject.c` `mig_e[]`), read from their
//! `osfmk/**/*.defs` preprocessed as the kernel's MIG build preprocesses
//! them and numbered as MIG numbers them (`cargo xtask darwin-catalogs`). Provenance matches the
//! [Mach-trap catalog](super::catalog): `xnu-12377.121.6`; subsystem bases
//! and routine order are append-only ABI.

mod generated;

/// One kernel-served subsystem: message ids `[base, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subsystem {
    pub name: &'static str,
    /// The configuration option its registry entry is conditional on.
    pub guard: Option<&'static str>,
    pub base: u32,
    pub end: u32,
    pub source: &'static str,
}

/// One routine: its request message id. A reply is `id + 100`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Routine {
    pub id: u32,
    pub subsystem: &'static str,
    pub name: &'static str,
    /// A `simpleroutine` sends no reply.
    pub simple: bool,
}

/// The distance from a request id to its reply's (`MIG_REPLY_ID`).
pub const REPLY_OFFSET: u32 = 100;

pub fn subsystems() -> &'static [Subsystem] {
    generated::SUBSYSTEMS
}

/// The kernel-served subsystem whose ids include `id`.
pub fn subsystem(id: u32) -> Option<&'static Subsystem> {
    generated::SUBSYSTEMS
        .iter()
        .find(|subsystem| (subsystem.base..subsystem.end).contains(&id))
}

/// The routine a request id names; `None` for a skipped number or an id no
/// kernel-served subsystem holds.
pub fn routine(id: u32) -> Option<&'static Routine> {
    generated::ROUTINES
        .binary_search_by_key(&id, |routine| routine.id)
        .ok()
        .map(|index| &generated::ROUTINES[index])
}

/// The routine of `subsystem` named `name`.
pub fn named(subsystem: &str, name: &str) -> Option<&'static Routine> {
    generated::ROUTINES
        .iter()
        .find(|routine| routine.subsystem == subsystem && routine.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_sorted_and_within_its_subsystems() {
        let routines = generated::ROUTINES;
        assert!(routines.windows(2).all(|pair| pair[0].id < pair[1].id));
        for routine in routines {
            let subsystem = subsystem(routine.id).expect("a routine lies in its subsystem");
            assert_eq!(subsystem.name, routine.subsystem);
        }
        for pair in subsystems().windows(2) {
            assert!(pair[0].end <= pair[1].base);
        }
    }

    #[test]
    fn startup_subsystems_are_kernel_served() {
        for (name, base) in [
            ("mach_host", 200),
            ("host_priv", 400),
            ("mach_port", 3200),
            ("task", 3400),
            ("thread_act", 3600),
            ("mach_vm", 4800),
        ] {
            let subsystem = subsystems()
                .iter()
                .find(|subsystem| subsystem.name == name)
                .unwrap_or_else(|| panic!("{name} is not kernel-served"));
            assert_eq!(subsystem.base, base);
        }
        // Names are the kernel's server routines (`KERNEL_SERVER` variants).
        let info = named("task", "task_info_from_user").expect("task_info");
        assert_eq!(routine(info.id), Some(info));
        assert!(!info.simple);
        let page_size = named("mach_host", "_host_page_size").expect("host_page_size");
        assert_eq!(subsystem(page_size.id).map(|s| s.name), Some("mach_host"));
        // `exc` starts at 2401, as its definitions declare.
        assert_eq!(subsystem(2400), None);
    }
}

//! The hosted process's requirement matrix: every kernel service an
//! unchanged 26A434 process can request of the arm64 kernel, and how the
//! hosted kernel provides it.
//!
//! The call rows are the [census] of the original images' call sites:
//! every BSD system call, Mach trap and platform call a stub in the guest
//! shared cache or dyld issues. The MIG rows are every routine of the
//! kernel-served subsystems in the pinned MIG catalog. Each row's status
//! is the dispatcher's own ([`super::kernel::services`]): forwarded to the
//! host kernel, modeled by a family of the hosted kernel, either with a
//! named limit, or refused with a reason. `cargo xtask progress` renders
//! the matrix into `docs/research/hosted-requirements.md` and its counts
//! into the README.
use super::kernel::services::{self, Service};
use crate::darwin::catalog as bsd_catalog;
use crate::mach::{catalog as mach_catalog, mig};
use std::fmt::Write as _;

pub mod census;

/// The images a call site is in.
pub const LIBSYSTEM_KERNEL: u8 = 1 << 0;
pub const DYLD: u8 = 1 << 1;
pub const IOKIT: u8 = 1 << 2;

/// One census entry: a call number and the 26A434 stub that issues it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Site {
    pub number: u32,
    pub stub: &'static str,
    pub images: u8,
}

impl Site {
    pub const fn new(number: u32, stub: &'static str, images: u8) -> Self {
        Self {
            number,
            stub,
            images,
        }
    }
}

/// The matrix's areas, in document order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Area {
    Bsd,
    Mach,
    Platform,
    Mig,
}

impl Area {
    pub const ALL: [Area; 4] = [Area::Bsd, Area::Mach, Area::Platform, Area::Mig];

    pub fn title(self) -> &'static str {
        match self {
            Self::Bsd => "BSD system calls",
            Self::Mach => "Mach traps",
            Self::Platform => "Platform calls",
            Self::Mig => "Kernel-object MIG routines",
        }
    }
}

/// A row's status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Implemented,
    /// Serviced, without the named part of the arm64 kernel's contract.
    Partial(&'static str),
    /// The run stops naming the request and the reason.
    Refused(&'static str),
}

/// One requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub area: Area,
    /// The call number, trap index, platform operation or message id.
    pub number: u32,
    pub name: String,
    /// Who services it: `forwarded`, a family's name, or `refused`.
    pub service: String,
    pub status: Status,
    /// A model preceding a forwarded call, or the census's images.
    pub note: Option<&'static str>,
}

const ADDITION: &str = "a 26A434 addition at a number the pinned catalog reserves: not implemented";

fn status(service: Service, limit: Option<&'static str>) -> (String, Status, Option<&'static str>) {
    match service {
        Service::Forwarded { overlay } => (
            "forwarded".into(),
            limit.map_or(Status::Implemented, Status::Partial),
            overlay,
        ),
        Service::Modeled { family } => (
            family.into(),
            limit.map_or(Status::Implemented, Status::Partial),
            None,
        ),
        Service::Refused { reason } => ("refused".into(), Status::Refused(reason), None),
    }
}

/// A stub's call name: its symbol without the leading underscores.
fn stub_name(stub: &str) -> String {
    stub.trim_start_matches('_').to_owned()
}

fn bsd_rows() -> impl Iterator<Item = Row> {
    census::BSD.iter().map(|site| {
        let entry = bsd_catalog::entry(site.number as u16);
        let (name, (service, status, note)) = match entry {
            Some(entry) if entry.prototype().is_some() => {
                let (service, limit) = services::bsd(entry.name);
                (entry.name.to_owned(), self::status(service, limit))
            }
            // Number zero is the indirect call: X0 holds the number.
            _ if site.number == 0 => (
                "syscall (indirect)".to_owned(),
                ("dispatcher".into(), Status::Implemented, None),
            ),
            _ => match services::bsd_addition(site.number) {
                Some((name, service, limit)) => (name.to_owned(), self::status(service, limit)),
                None => (
                    stub_name(site.stub),
                    ("refused".into(), Status::Refused(ADDITION), None),
                ),
            },
        };
        Row {
            area: Area::Bsd,
            number: site.number,
            name,
            service,
            status,
            note,
        }
    })
}

/// The fast traps `handle_svc` answers before the trap table.
const FAST_TRAPS: &[(u32, &str)] = &[(3, "mach_absolute_time"), (4, "mach_continuous_time")];

fn mach_rows() -> impl Iterator<Item = Row> {
    census::MACH.iter().map(|site| {
        let entry = mach_catalog::entry(site.number);
        let fast = FAST_TRAPS.iter().find(|(index, _)| *index == site.number);
        let (name, (service, status, note)) = match (entry, fast) {
            (_, Some(&(_, name))) => (
                name.to_owned(),
                ("fast traps".into(), Status::Implemented, None),
            ),
            (Some(entry), None) if entry.reserved == mach_catalog::Reserved::No => {
                let (service, limit) = services::mach(entry.name);
                (entry.name.to_owned(), status(service, limit))
            }
            _ if let Some((name, service)) = services::mach_addition(site.number) => {
                (name.to_owned(), status(service, None))
            }
            _ => (
                stub_name(site.stub),
                ("refused".into(), Status::Refused(ADDITION), None),
            ),
        };
        Row {
            area: Area::Mach,
            number: site.number,
            name,
            service,
            status,
            note,
        }
    })
}

/// `platform_syscall` operations (X3): 2 and 3 set and read
/// `cthread_self`; the rest return with every register unchanged.
fn platform_rows() -> impl Iterator<Item = Row> {
    [
        (2, "set cthread_self (TPIDRRO_EL0)"),
        (3, "get cthread_self (TPIDRRO_EL0)"),
    ]
    .into_iter()
    .map(|(number, name)| Row {
        area: Area::Platform,
        number,
        name: name.to_owned(),
        service: "platform".into(),
        status: Status::Implemented,
        note: None,
    })
}

fn mig_rows() -> impl Iterator<Item = Row> {
    mig::subsystems()
        .iter()
        // 32-bit VM maps are not part of the arm64 LP64 kernel.
        .filter(|subsystem| subsystem.guard != Some("VM32_SUPPORT"))
        .flat_map(|subsystem| {
            (subsystem.base..subsystem.end)
                .filter_map(mig::routine)
                .map(move |routine| {
                    let (service, limit) = services::mig(subsystem.name, routine.name);
                    let (service, status, note) = status(service, limit);
                    let object = services::mig_object(subsystem.name).unwrap_or("another object");
                    Row {
                        area: Area::Mig,
                        number: routine.id,
                        name: format!("{}.{} ({object})", subsystem.name, routine.name),
                        service,
                        status,
                        note,
                    }
                })
        })
}

/// Every row, area by area.
pub fn matrix() -> Vec<Row> {
    bsd_rows()
        .chain(mach_rows())
        .chain(platform_rows())
        .chain(mig_rows())
        .collect()
}

/// Rows implemented, partial and refused.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub implemented: usize,
    pub partial: usize,
    pub refused: usize,
}

impl Counts {
    pub fn total(self) -> usize {
        self.implemented + self.partial + self.refused
    }

    fn add(&mut self, status: Status) {
        match status {
            Status::Implemented => self.implemented += 1,
            Status::Partial(_) => self.partial += 1,
            Status::Refused(_) => self.refused += 1,
        }
    }
}

pub fn counts<'a>(rows: impl IntoIterator<Item = &'a Row>) -> Counts {
    let mut counts = Counts::default();
    for row in rows {
        counts.add(row.status);
    }
    counts
}

fn number(row: &Row) -> String {
    match row.area {
        Area::Mach => format!("-{}", row.number),
        _ => row.number.to_string(),
    }
}

/// The summary table: one line per area and the total.
pub fn render_summary(rows: &[Row]) -> String {
    let mut out = String::from(
        "| Hosted process requirement | Implemented | Partial | Refused | Total |\n\
         | --- | --- | --- | --- | --- |\n",
    );
    for area in Area::ALL {
        let counts = counts(rows.iter().filter(|row| row.area == area));
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            area.title(),
            counts.implemented,
            counts.partial,
            counts.refused,
            counts.total()
        );
    }
    let all = counts(rows);
    let _ = writeln!(
        out,
        "| **All** | **{} / {} ({:.1}%)** | {} | {} | {} |",
        all.implemented,
        all.total(),
        100.0 * all.implemented as f64 / all.total().max(1) as f64,
        all.partial,
        all.refused,
        all.total()
    );
    out
}

/// The whole matrix: the summary, then each area's refused and partial
/// rows one by one and its implemented rows by service.
pub fn render(rows: &[Row]) -> String {
    let mut out = render_summary(rows);
    for area in Area::ALL {
        let rows: Vec<&Row> = rows.iter().filter(|row| row.area == area).collect();
        let _ = write!(out, "\n### {}\n", area.title());
        let refused: Vec<_> = rows
            .iter()
            .filter_map(|row| match row.status {
                Status::Refused(reason) => Some((row, reason)),
                _ => None,
            })
            .collect();
        if !refused.is_empty() {
            out.push_str("\n| Number | Refused | Reason |\n| --- | --- | --- |\n");
            for (row, reason) in refused {
                let _ = writeln!(out, "| {} | `{}` | {reason} |", number(row), row.name);
            }
        }
        let partial: Vec<_> = rows
            .iter()
            .filter_map(|row| match row.status {
                Status::Partial(limit) => Some((row, limit)),
                _ => None,
            })
            .collect();
        if !partial.is_empty() {
            out.push_str("\n| Number | Partial | Service | Limit |\n| --- | --- | --- | --- |\n");
            for (row, limit) in partial {
                let _ = writeln!(
                    out,
                    "| {} | `{}` | {} | {limit} |",
                    number(row),
                    row.name,
                    row.service
                );
            }
        }
        let mut services: Vec<&str> = rows
            .iter()
            .filter(|row| row.status == Status::Implemented)
            .map(|row| row.service.as_str())
            .collect();
        services.sort_unstable();
        services.dedup();
        if !services.is_empty() {
            out.push_str("\n| Implemented by | Count | Requests |\n| --- | --- | --- |\n");
        }
        for service in services {
            let names: Vec<String> = rows
                .iter()
                .filter(|row| row.status == Status::Implemented && row.service == service)
                .map(|row| format!("`{}`", row.name))
                .collect();
            let _ = writeln!(
                out,
                "| {service} | {} | {} |",
                names.len(),
                names.join(", ")
            );
        }
        let mut overlays: Vec<&str> = rows.iter().filter_map(|row| row.note).collect();
        overlays.sort_unstable();
        overlays.dedup();
        for overlay in overlays {
            let names: Vec<String> = rows
                .iter()
                .filter(|row| row.note == Some(overlay))
                .map(|row| format!("`{}`", row.name))
                .collect();
            let _ = writeln!(
                out,
                "\nForwarded after a model: {overlay} ({}).",
                names.join(", ")
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_census_is_sorted_unique_and_dispatchable() {
        for sites in [census::BSD, census::MACH, census::PLATFORM] {
            assert!(sites.windows(2).all(|pair| pair[0].number < pair[1].number));
            assert!(sites.iter().all(|site| site.images != 0));
        }
        assert_eq!(
            census::BSD.len() + census::MACH.len() + census::PLATFORM.len(),
            530
        );
        // Every BSD number lies in the pinned table, every Mach index too.
        assert!(
            census::BSD
                .iter()
                .all(|site| bsd_catalog::entry(site.number as u16).is_some())
        );
        assert!(
            census::MACH
                .iter()
                .all(|site| mach_catalog::entry(site.number).is_some())
        );
    }

    #[test]
    fn every_row_has_one_status_and_refusals_give_reasons() {
        let rows = matrix();
        let counts = counts(&rows);
        assert_eq!(counts.total(), rows.len());
        for row in &rows {
            match row.status {
                Status::Refused(reason) => {
                    assert_eq!(row.service, "refused", "{}", row.name);
                    assert!(!reason.is_empty());
                }
                _ => assert_ne!(row.service, "refused", "{}", row.name),
            }
        }
        // A refusal reason is never the dispatcher's fallback: each
        // refused call is named with its reason.
        assert!(
            rows.iter()
                .all(|row| row.status != Status::Refused("no family services it")),
            "{:?}",
            rows.iter()
                .filter(|row| row.status == Status::Refused("no family services it"))
                .map(|row| &row.name)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn statuses_follow_the_dispatchers() {
        let rows = matrix();
        let find = |area: Area, name: &str| {
            rows.iter()
                .find(|row| row.area == area && row.name == name)
                .unwrap_or_else(|| panic!("{name}"))
        };
        assert_eq!(find(Area::Bsd, "read").service, "forwarded");
        assert_eq!(find(Area::Bsd, "mmap").service, "memory");
        assert_eq!(find(Area::Bsd, "sys_sysctlbyname").service, "sysctl");
        assert_eq!(find(Area::Bsd, "fork").service, "process");
        assert_eq!(find(Area::Bsd, "ptrace").service, "system");
        assert_eq!(find(Area::Bsd, "__mac_execve").service, "process");
        assert!(matches!(
            find(Area::Bsd, "mremap_encrypted").status,
            Status::Refused(_)
        ));
        // Each 26A434 addition is serviced by its family or refused by name.
        for name in ["pipe2", "dup3", "getumask", "register_uexc_handler"] {
            let row = find(Area::Bsd, name);
            assert!(
                row.service == "26A434 additions" || row.status == Status::Refused(ADDITION),
                "{name}"
            );
        }
        assert_eq!(
            find(Area::Mach, "mach_absolute_time").status,
            Status::Implemented
        );
        assert_eq!(
            find(Area::Mig, "mach_host.host_info (host)").service,
            "kernel objects"
        );
        assert!(matches!(
            find(Area::Mig, "task.task_info_from_user (task)").status,
            Status::Partial(_)
        ));
        assert!(matches!(
            find(Area::Mig, "thread_act.thread_set_state_from_user (thread)").status,
            Status::Partial(_)
        ));
        assert!(matches!(
            find(Area::Mig, "thread_act.thread_abort (thread)").status,
            Status::Refused(_)
        ));
        let rendered = render(&rows);
        assert!(rendered.starts_with("| Hosted process requirement |"));
        assert!(rendered.contains("### Kernel-object MIG routines"));
    }
}

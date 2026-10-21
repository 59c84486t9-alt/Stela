//! The performance domains' `voltage-states` tables, hand-off properties
//! iBoot adds to `/arm-io/pmgr`.
//!
//! The shipped DeviceTree lists the domains in `/arm-io/pmgr` `perf-domains`,
//! 28-byte entries whose byte 0 numbers the domain's table, byte 2 is 1 for a
//! CPU cluster, and bytes 12..28 name it (J473AP: `SOC` 0, `ECPU` 1, `DCS` 2,
//! `PCPU` 5, `ANE` 8, `DISP` 11). It ships tables for only some of them;
//! 26A434 J473AP `ApplePMGR::initDriver` looks up `voltage-states<table>` for
//! every domain and panics on one it lacks ("voltage-states1 not found").
//!
//! A table is a run of `(u32, u32)` states. The driver reads it two ways:
//!
//! - a CPU cluster's states are `(period, voltage)`, lowest first, ending at
//!   the first zero period. iBoot (26A434 `iBoot.j473.RELEASE`, the routine
//!   that writes `voltage-states1`, `-sram` and `-extra`) stores the period as
//!   65,536 × 10⁹ / the state's clock in Hz, and the driver reads the clock
//!   back as 65,536,000 / period MHz. The states are the SoC's operating
//!   points (`machine::soc::operating_points`);
//! - any other domain's table whose first state has voltage 0 is a list of
//!   state numbers, `(0, 0), (1, 0), …`, and the domain has as many states as
//!   the last number plus one. The IPSW DeviceTree ships `voltage-states0`,
//!   `2` and `9` in this form; the driver asserts the list is not empty.
//!
//! iBoot fills these tables from the chip itself: each state's voltage from
//! its calibration fuses, and the non-CPU domains' clocks from their PLL
//! registers. An emulated chip has neither. The CPU tables leave the voltage
//! 0, which the driver uses only for its dynamic energy estimate (V² × f), so
//! the estimate states no energy rather than an invented one. Every other
//! domain gets one state, `(0, 0)`: the machine does not scale its clock, so
//! the domain has a single operating point. The optional `-sram` and
//! `-extra` tables are not published. A CPU cluster of a SoC without
//! operating-point evidence keeps no table: inventing clocks would be a
//! placeholder, so the bundle records the gap and the driver's own stop
//! ("voltage-states1 not found") remains the explicit failure, after the
//! monitors and the kernel's earlier boot have run.
use crate::apple_device_tree::DeviceTree;
use alloc::{format, string::String, vec::Vec};
use anyhow::{Result, ensure};
use stela_runtime::machine::soc;

const PMGR: &str = "/arm-io/pmgr";
const PERF_DOMAINS: &str = "perf-domains";
const DOMAIN: usize = 28;
/// The period unit: a state's period is this over its clock in Hz.
const PERIOD_SCALE: u64 = 65_536 * 1_000_000_000;

/// What [`publish`] did for one domain without a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Contents {
    /// A CPU cluster's operating points.
    OperatingPoints,
    /// A single state, for a domain whose clock the machine does not scale.
    SingleState,
    /// Nothing: the SoC has no operating-point evidence for this cluster.
    Unpublished,
}

/// A domain table [`publish`] wrote or left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub name: String,
    /// The domain's name in `perf-domains`.
    pub domain: String,
    pub contents: Contents,
}

/// A CPU cluster's table: its operating points as periods, voltages 0, or
/// `None` when the SoC with `chip_id` has none.
fn cluster(domain: &str, chip_id: u32) -> Result<Option<Vec<u8>>> {
    // The original J314s tree has separate PCPU (table 5) and PCPU1
    // (table 13) records. The suffix identifies a domain, not a core count;
    // each table retains its own identity and uses its core type's OPPs.
    let (cluster_type, suffix) = if let Some(suffix) = domain.strip_prefix("ECPU") {
        (b'E', suffix)
    } else if let Some(suffix) = domain.strip_prefix("PCPU") {
        (b'P', suffix)
    } else {
        anyhow::bail!("CPU domain {domain} names no cluster type");
    };
    ensure!(
        suffix.bytes().all(|byte| byte.is_ascii_digit()),
        "CPU domain {domain} has an invalid cluster suffix"
    );
    let Some(points) = soc::operating_points(chip_id)
        .and_then(|clusters| clusters.into_iter().find(|(kind, _)| *kind == cluster_type))
        .map(|(_, points)| points)
    else {
        return Ok(None);
    };
    ensure!(!points.is_empty(), "{domain} has no operating points");
    let mut value = Vec::with_capacity(points.len() * 8);
    for &mhz in points {
        let period = u32::try_from(PERIOD_SCALE / (u64::from(mhz) * 1_000_000))?;
        value.extend_from_slice(&period.to_le_bytes());
        value.extend_from_slice(&0u32.to_le_bytes());
    }
    Ok(Some(value))
}

/// Add the table of each `perf-domains` domain that lacks one. Returns the
/// tables written; a tree without the domains gets none.
pub fn publish(tree: &mut DeviceTree, chip_id: u32) -> Result<Vec<Table>> {
    let Some(domains) = tree.property(PMGR, PERF_DOMAINS).map(|p| p.value.clone()) else {
        return Ok(Vec::new());
    };
    ensure!(
        domains.len().is_multiple_of(DOMAIN),
        "{PMGR} {PERF_DOMAINS} is not a run of {DOMAIN}-byte domains"
    );
    let mut written = Vec::new();
    for entry in domains.as_chunks::<DOMAIN>().0 {
        let name = format!("voltage-states{}", entry[0]);
        if tree.property(PMGR, &name).is_some() {
            continue;
        }
        let label = &entry[12..];
        let label = &label[..label.iter().position(|&b| b == 0).unwrap_or(label.len())];
        let domain = String::from(core::str::from_utf8(label)?);
        let (contents, value) = if entry[2] == 1 {
            match cluster(&domain, chip_id)? {
                Some(value) => (Contents::OperatingPoints, Some(value)),
                None => (Contents::Unpublished, None),
            }
        } else {
            (Contents::SingleState, Some([0u8; 8].to_vec()))
        };
        if let Some(value) = value {
            tree.set_property(PMGR, &name, value)?;
        }
        written.push(Table {
            name,
            domain,
            contents,
        });
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apple_device_tree::Node;
    use alloc::vec;

    fn domain(table: u8, cpu: bool, name: &str) -> [u8; DOMAIN] {
        let mut entry = [0u8; DOMAIN];
        entry[0] = table;
        entry[2] = u8::from(cpu);
        entry[3] = table;
        entry[12..12 + name.len()].copy_from_slice(name.as_bytes());
        entry
    }

    fn tree() -> DeviceTree {
        let domains = [
            domain(0, false, "SOC"),
            domain(1, true, "ECPU"),
            domain(5, true, "PCPU"),
            domain(8, false, "ANE"),
        ];
        with_domains(Some(&domains.concat()))
    }

    fn with_domains(domains: Option<&[u8]>) -> DeviceTree {
        let mut pmgr = Node::named("pmgr").unwrap();
        if let Some(domains) = domains {
            pmgr.set_property(PERF_DOMAINS, domains.to_vec()).unwrap();
        }
        pmgr.set_property("voltage-states0", [0u8; 24].to_vec())
            .unwrap();
        let mut io = Node::named("arm-io").unwrap();
        io.children.push(pmgr);
        let mut root = Node::named("device-tree").unwrap();
        root.children.push(io);
        DeviceTree { root }
    }

    fn word(value: &[u8], index: usize) -> u32 {
        u32::from_le_bytes(value[index * 4..index * 4 + 4].try_into().unwrap())
    }

    #[test]
    fn every_domain_without_a_table_gets_one() {
        let mut tree = tree();
        let written = publish(&mut tree, 0x8112).unwrap();
        let names: Vec<_> = written.iter().map(|table| table.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["voltage-states1", "voltage-states5", "voltage-states8"]
        );
        assert_eq!(written[2].domain, "ANE");
        assert_eq!(written[0].contents, Contents::OperatingPoints);
        assert_eq!(written[2].contents, Contents::SingleState);
        // 600 MHz is period 109,226, which the driver reads back as 600 MHz.
        let e = &tree.property(PMGR, "voltage-states1").unwrap().value;
        assert_eq!(e.len(), 7 * 8);
        assert_eq!((word(e, 0), word(e, 1)), (109_226, 0));
        assert_eq!(65_536_000 / 109_226, 600);
        let p = &tree.property(PMGR, "voltage-states5").unwrap().value;
        assert_eq!(p.len(), 17 * 8);
        assert_eq!(word(p, 32), 18_703);
        // A domain whose clock the machine does not scale has one state.
        let ane = &tree.property(PMGR, "voltage-states8").unwrap().value;
        assert_eq!(ane, &vec![0u8; 8]);
        // The shipped table stays, and a second publish writes nothing.
        assert_eq!(
            tree.property(PMGR, "voltage-states0").unwrap().value.len(),
            24
        );
        assert!(publish(&mut tree, 0x8112).unwrap().is_empty());
    }

    #[test]
    fn numbered_cpu_domains_keep_independent_table_identities() {
        let domains = [
            domain(1, true, "ECPU"),
            domain(5, true, "PCPU"),
            domain(13, true, "PCPU1"),
        ];
        let mut tree = with_domains(Some(&domains.concat()));
        let written = publish(&mut tree, 0x6000).unwrap();
        assert_eq!(written.len(), 3);
        assert!(
            written
                .iter()
                .all(|t| t.contents == Contents::OperatingPoints)
        );
        assert_eq!(written[2].domain, "PCPU1");
        let first = &tree.property(PMGR, "voltage-states5").unwrap().value;
        let second = &tree.property(PMGR, "voltage-states13").unwrap().value;
        assert!(!first.is_empty());
        assert_eq!(first, second);
        assert_eq!(
            cluster("ECPU12", 0x6000).unwrap(),
            cluster("ECPU", 0x6000).unwrap()
        );
        assert!(cluster("PCPU1", 0x8122).unwrap().is_none());
        for invalid in ["PCPU-1", "PCPU1x", "PCPU１", "PCPU ", "MCPU", ""] {
            assert!(cluster(invalid, 0x6000).is_err(), "{invalid}");
        }
    }

    #[test]
    fn a_cpu_domain_without_operating_points_keeps_no_table() {
        // The M3 (0x8122) has no public operating points.
        let mut m3 = tree();
        let written = publish(&mut m3, 0x8122).unwrap();
        assert_eq!(written[0].contents, Contents::Unpublished);
        assert!(m3.property(PMGR, "voltage-states1").is_none());
        assert_eq!(written[2].contents, Contents::SingleState);
        assert!(publish(&mut with_domains(None), 0x8122).unwrap().is_empty());
        assert!(publish(&mut with_domains(Some(&[0; 27])), 0x8112).is_err());
    }
}

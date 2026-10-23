//! Shared source-v1 bridge record decoding, independent of native admission.
//!
//! Original 26A434 ApplePMGR maps four-byte counter headers to 36-byte
//! configurations and reads 76-byte device dependency rows. T8112 KC file
//! 0x2b71bd8..0x2b71fd8/0x2b73c80 and T6000 0x2b3a674 establish the same
//! table geometry. Register layout, optional-bank tuning and initial contents
//! remain separate, chip-qualified inputs.
use super::super::Node;
use alloc::{string::String, vec::Vec};

pub(in crate::machine::soc) struct Records<'a> {
    headers: &'a [[u8; 4]],
    configs: &'a [[u8; 36]],
    dependencies: &'a [[u8; 76]],
    axi: Option<&'a [[u8; 4]]>,
}

pub(in crate::machine::soc) struct Record {
    pub header: [u8; 4],
    pub configs: Vec<[u8; 36]>,
    pub axi: Option<[u8; 4]>,
    pub devices: Vec<u8>,
}

impl<'a> Records<'a> {
    /// Validate the entire known source table before selecting any bank.
    /// Borrowed lengths bound all indexing; no count-sized allocation occurs.
    pub fn new(node: &Node<'a>, count: usize) -> Result<Self, String> {
        let headers = node
            .property("bridge-counters")
            .ok_or("PMGR has no bridge counter headers")?;
        let configs = node.property("bridge-counter-configs").unwrap_or_default();
        let dependencies = node.property("device-bridges").unwrap_or_default();
        let axi = node.property("axi2af-axi-config");
        if !headers.len().is_multiple_of(4)
            || headers.len() / 4 != count
            || !configs.len().is_multiple_of(36)
            || !dependencies.len().is_multiple_of(76)
            || axi.is_some_and(|bytes| !bytes.len().is_multiple_of(4) || bytes.len() / 4 != count)
        {
            return Err("PMGR bridge properties have partial records or wrong counts".into());
        }
        let headers = headers.as_chunks::<4>().0;
        let configs = configs.as_chunks::<36>().0;
        let dependencies = dependencies.as_chunks::<76>().0;
        for header in headers {
            let first = usize::from(header[2]);
            let end = first + usize::from(header[3]);
            if configs.get(first..end).is_none() {
                return Err("bridge counter header exceeds configuration records".into());
            }
        }
        for row in dependencies {
            for bridge in dependency_ids(row) {
                if usize::from(bridge) >= count {
                    return Err("device-bridges names an absent bridge".into());
                }
            }
        }
        Ok(Self {
            headers,
            configs,
            dependencies,
            axi: axi.map(|bytes| bytes.as_chunks::<4>().0),
        })
    }

    pub fn record(&self, id: usize) -> Option<Record> {
        let header = *self.headers.get(id)?;
        let first = usize::from(header[2]);
        let end = first + usize::from(header[3]);
        let mut devices = Vec::new();
        for row in self.dependencies {
            if dependency_ids(row).any(|bridge| usize::from(bridge) == id)
                && !devices.contains(&row[3])
            {
                devices.push(row[3]);
            }
        }
        Some(Record {
            header,
            configs: self.configs[first..end].to_vec(),
            axi: self.axi.map(|rows| rows[id]),
            devices,
        })
    }
}

fn dependency_ids(row: &[u8; 76]) -> impl Iterator<Item = u8> + '_ {
    // Slot zero can name bridge zero; only subsequent zero slots terminate.
    row[4..]
        .iter()
        .copied()
        .enumerate()
        .take_while(|&(slot, bridge)| slot == 0 || bridge != 0)
        .map(|(_, bridge)| bridge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::adt::encode;

    #[test]
    fn first_zero_is_a_bridge_and_later_zero_terminates_without_reading_tail() {
        let mut dependency = [0; 76];
        dependency[3] = 9;
        dependency[5] = 1;
        dependency[7] = 255; // After the terminator: not another dependency.
        let mut other = dependency;
        other[3] = 10;
        let rows = [dependency, dependency, other].concat();
        let data = encode(
            &[
                ("bridge-counters", &[0, 0, 0, 1, 0, 0, 1, 0]),
                ("bridge-counter-configs", &[7; 36]),
                ("device-bridges", &rows),
                ("axi2af-axi-config", &[1, 2, 3, 4, 5, 6, 7, 8]),
            ],
            &[],
        );
        let node = Node::root(&data).unwrap();
        let records = Records::new(&node, 2).unwrap();
        for id in 0..2 {
            let record = records.record(id).unwrap();
            assert_eq!(record.devices, [9, 10]);
            assert_eq!(record.configs.len(), usize::from(id == 0));
        }
        assert_eq!(records.record(1).unwrap().axi, Some([5, 6, 7, 8]));
        assert!(records.record(2).is_none());
        assert!(Records::new(&node, usize::MAX).is_err());
    }

    #[test]
    fn every_header_and_active_dependency_is_checked_before_selecting_a_bank() {
        let mut dependency = [0; 76];
        dependency[4] = 2;
        for (headers, configs, dependencies, axi) in [
            (&[0, 0, 0][..], &[0; 36][..], &[][..], &[][..]),
            (&[0, 0, 0, 1], &[0; 35], &[], &[]),
            (&[0, 0, 1, 1], &[0; 36], &[], &[]),
            (&[0, 0, 0, 0], &[], &[0; 75], &[]),
            (&[0, 0, 0, 0], &[], &dependency, &[]),
            (&[0, 0, 0, 0], &[], &[], &[0; 3]),
        ] {
            let mut properties = alloc::vec![
                ("bridge-counters", headers),
                ("bridge-counter-configs", configs),
                ("device-bridges", dependencies),
            ];
            if !axi.is_empty() {
                properties.push(("axi2af-axi-config", axi));
            }
            let data = encode(&properties, &[]);
            assert!(Records::new(&Node::root(&data).unwrap(), 1).is_err());
        }
    }
}

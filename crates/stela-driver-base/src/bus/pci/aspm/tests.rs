use super::*;
use crate::{
    Clock,
    bus::pci::{Address, EcamConfig},
};
use alloc::{rc::Rc, vec};
use core::cell::RefCell;

type Writes = Rc<RefCell<Vec<(Address, u16, u32)>>>;

struct Config {
    words: [u32; 1024],
    address: Address,
    writes: Writes,
    refuses_aspm: bool,
    refuses_l1ss: bool,
    failed_read: Option<u16>,
}

impl ConfigSpace for Config {
    fn read32(&self, offset: u16) -> Result<u32, crate::bus::pci::ConfigError> {
        Ok({
            if self.failed_read == Some(offset) {
                return Ok(u32::MAX);
            }
            self.words[usize::from(offset / 4)]
        })
    }
    fn write32(&mut self, offset: u16, value: u32) -> Result<(), crate::bus::pci::ConfigError> {
        assert!(
            offset >= 0x100,
            "ASPM must not write a DWORD containing W1C Link Status"
        );
        self.writes.borrow_mut().push((self.address, offset, value));
        self.words[usize::from(offset / 4)] = value | if self.refuses_l1ss { ASPM_L1_2 } else { 0 };
        Ok(())
    }
    fn write16(&mut self, offset: u16, value: u16) -> Result<(), crate::bus::pci::ConfigError> {
        self.writes
            .borrow_mut()
            .push((self.address, offset, u32::from(value)));
        let shift = (offset & 2) * 8;
        let value = if self.refuses_aspm {
            value | PCIE_ASPM
        } else {
            value
        };
        let word = &mut self.words[usize::from(offset / 4)];
        *word = (*word & !(0xffff << shift)) | (u32::from(value) << shift);
        Ok(())
    }

    fn read8(&self, offset: u16) -> Result<u8, crate::bus::pci::ConfigError> {
        Ok((self.read32(offset & !3)? >> ((offset & 3) * 8)) as u8)
    }

    fn write8(&mut self, offset: u16, value: u8) -> Result<(), crate::bus::pci::ConfigError> {
        let shift = (offset & 3) * 8;
        let word = self.read32(offset & !3)? & !(0xff << shift) | u32::from(value) << shift;
        self.write32(offset & !3, word)
    }

    fn read16(&self, offset: u16) -> Result<u16, crate::bus::pci::ConfigError> {
        Ok((self.read32(offset & !3)? >> ((offset & 2) * 8)) as u16)
    }
}

fn address(segment: u16, bus: u8, device: u8) -> Address {
    Address {
        segment,
        bus,
        device,
        function: 0,
    }
}

fn device(at: Address, bridge: Option<(u8, u8)>, writes: &Writes) -> Function<Config> {
    let mut config = Config {
        words: [0; 1024],
        address: at,
        writes: Rc::clone(writes),
        refuses_aspm: false,
        refuses_l1ss: false,
        failed_read: None,
    };
    config.words[0] = 0x10d3_8086;
    config.words[1] = 1 << 20; // status capability-list flag
    config.words[2] = if bridge.is_some() {
        0x0604_0000
    } else {
        0x0200_0000
    };
    config.words[13] = 0x40;
    config.words[16] =
        (1 | if bridge.is_some() { 4 << 4 } else { 0 }) << 16 | u32::from(CAPABILITY_PCIE);
    // Preserve all unrelated Link Control bits and W1C Link Status.
    config.words[20] = 0xc000_a5a3;
    if let Some((secondary, subordinate)) = bridge {
        config.words[3] = 1 << 16;
        config.words[6] =
            u32::from(at.bus) | u32::from(secondary) << 8 | u32::from(subordinate) << 16;
    }
    Function::new(at, config).unwrap()
}

#[test]
fn disables_the_exact_link_downstream_first_with_narrow_writes() {
    let writes = Writes::default();
    let mut endpoint = device(address(3, 8, 0), None, &writes);
    let parent_address = address(3, 4, 2);
    let mut functions = vec![
        device(address(3, 0, 1), Some((4, 12)), &writes), // ancestor, not parent
        device(address(0, 4, 2), Some((8, 8)), &writes),  // different segment
        device(parent_address, Some((8, 12)), &writes),
        device(address(3, 4, 3), Some((9, 10)), &writes), // sibling link
    ];
    disable_aspm_with(&mut endpoint, &mut functions).unwrap();
    assert_eq!(
        *writes.borrow(),
        [
            (endpoint.address, 0x50, 0xa5a0),
            (parent_address, 0x50, 0xa5a0)
        ]
    );
    assert_eq!(endpoint.config.words[20], 0xc000_a5a0);
    assert_eq!(functions[2].config.words[20], 0xc000_a5a0);
    assert_eq!(functions[0].config.words[20], 0xc000_a5a3);
    assert_eq!(functions[1].config.words[20], 0xc000_a5a3);
    assert_eq!(functions[3].config.words[20], 0xc000_a5a3);
}

#[test]
fn a_root_bus_endpoint_disables_its_own_link_control() {
    let writes = Writes::default();
    let mut endpoint = device(address(0, 0, 3), None, &writes);
    let mut disabled = device(address(0, 0, 1), Some((0, 0)), &writes);
    disable_aspm_with(&mut endpoint, core::slice::from_mut(&mut disabled)).unwrap();
    assert_eq!(*writes.borrow(), [(endpoint.address, 0x50, 0xa5a0)]);
    assert_eq!(disabled.config.words[20], 0xc000_a5a3);
    writes.borrow_mut().clear();
    disable_aspm_with(&mut endpoint, &mut []).unwrap();
    assert!(writes.borrow().is_empty());
}

#[test]
fn link_speed_reads_the_status_or_zero_without_a_link() {
    let writes = Writes::default();
    let mut endpoint = device(address(0, 8, 0), None, &writes);
    endpoint.config.words[20] = 0x0043_0000;
    assert_eq!(link_speed(&endpoint).unwrap(), 3);
    endpoint.config.words[16] = (1 | 9 << 4) << 16 | u32::from(CAPABILITY_PCIE);
    assert_eq!(link_speed(&endpoint).unwrap(), 0);
}

#[test]
fn aspm_control_reads_the_link_or_zero_without_one() {
    let writes = Writes::default();
    let mut endpoint = device(address(0, 8, 0), None, &writes);
    assert_eq!(aspm_control(&endpoint).unwrap(), PCIE_ASPM);
    endpoint.config.words[20] = 0xc000_a5a2;
    assert_eq!(aspm_control(&endpoint).unwrap(), 2);
    assert_eq!(link_control_word(&endpoint).unwrap(), 0xa5a2);
    // A root-complex integrated endpoint has no link.
    endpoint.config.words[16] = (1 | 9 << 4) << 16 | u32::from(CAPABILITY_PCIE);
    assert_eq!(aspm_control(&endpoint).unwrap(), 0);
    assert_eq!(link_control_word(&endpoint).unwrap(), 0);
    assert!(writes.borrow().is_empty());
}

#[test]
fn both_capabilities_must_be_valid_before_any_register_is_changed() {
    let writes = Writes::default();
    let mut endpoint = device(address(0, 8, 0), None, &writes);
    let mut parent = device(address(0, 4, 1), Some((8, 8)), &writes);
    parent.config.words[16] = 0; // no PCIe capability
    assert!(disable_aspm_with(&mut endpoint, &mut [parent]).is_err());
    assert!(writes.borrow().is_empty());
    endpoint.config.words[16] = 0x0091_0010; // RC-integrated endpoint, no link control
    assert!(disable_aspm_with(&mut endpoint, &mut []).is_err());
    assert!(writes.borrow().is_empty());
}

#[test]
fn duplicate_parents_invalid_bus_routing_and_capability_loops_fail() {
    let writes = Writes::default();
    let mut endpoint = device(address(0, 8, 0), None, &writes);
    let mut parents = [
        device(address(0, 4, 1), Some((8, 8)), &writes),
        device(address(0, 4, 2), Some((8, 8)), &writes),
    ];
    assert!(disable_aspm_with(&mut endpoint, &mut parents).is_err());
    parents[0].config.words[6] ^= 1; // primary bus disagrees with address
    assert!(disable_aspm_with(&mut endpoint, &mut parents[..1]).is_err());
    endpoint.config.words[16] |= 0x4000; // self-referential capability chain
    assert!(disable_aspm_with(&mut endpoint, &mut []).is_err());
    assert!(writes.borrow().is_empty());
}

#[test]
fn a_refused_aspm_change_is_reported() {
    let writes = Writes::default();
    let mut endpoint = device(address(0, 0, 3), None, &writes);
    endpoint.config.refuses_aspm = true;
    assert!(matches!(
        disable_aspm_with(&mut endpoint, &mut []),
        Err(BlockError::Device { .. })
    ));
}

#[test]
fn ecam_halfword_store_does_not_replace_the_adjacent_halfword() {
    let mut words = [0xc000_a5a3u32; 64];
    // SAFETY: the fixture owns this exact stable ECAM backing.
    let mut config = unsafe { EcamConfig::raw(words.as_mut_ptr() as u64) };
    config.write16(0x50, 0xa5a0).unwrap();
    assert_eq!(words[20], 0xc000_a5a0);
    config.write16(0x52, 0x1234).unwrap();
    assert_eq!(words[20], 0x1234_a5a0);
}

#[test]
fn unmapped_or_overlapping_segment_windows_are_not_scanned() {
    let writes = Writes::default();
    let endpoint = device(address(1, 2, 0), None, &writes);
    let window = EcamWindow {
        base: 0x8000_0000,
        segment: 1,
        start_bus: 0,
        end_bus: 3,
    };
    let mut handoff = Handoff {
        firmware: None,
        completion: None,
        ecam: vec![window],
        mapped: vec![window.range()],
        dma: 0..0,
        clock: Clock {
            ticks_per_microsecond: 1,
        },
    };
    assert_eq!(segment_windows(&endpoint, &handoff).unwrap(), [window]);
    handoff.mapped.clear();
    assert!(segment_windows(&endpoint, &handoff).is_err());
    handoff.mapped.push(window.range());
    handoff.ecam.push(window);
    assert!(segment_windows(&endpoint, &handoff).is_err());
    handoff.ecam = vec![EcamWindow {
        segment: 0,
        ..window
    }];
    assert!(segment_windows(&endpoint, &handoff).is_err());
}

fn add_l1ss(function: &mut Function<Config>, at: u16, control: u32) {
    function.config.words[0x100 / 4] = u32::from(at) << 20 | 0x0001_0001;
    function.config.words[usize::from(at / 4)] = 0x0001_001e;
    function.config.words[usize::from((at + 4) / 4)] = 0x1f;
    function.config.words[usize::from((at + 8) / 4)] = control;
}

#[test]
fn l1_2_changes_only_aspm_bit_downstream_before_parent_with_dword_access() {
    let writes = Writes::default();
    let mut endpoint = device(address(0, 8, 0), None, &writes);
    let mut parent = device(address(0, 4, 1), Some((8, 12)), &writes);
    add_l1ss(&mut endpoint, 0x180, 0x5abca50f);
    add_l1ss(&mut parent, 0x240, 0xabcdff0f);
    let parent_address = parent.address;
    disable_l1_2_with(&mut endpoint, core::slice::from_mut(&mut parent)).unwrap();
    assert_eq!(
        *writes.borrow(),
        [
            (endpoint.address, 0x188, 0x5abca50b),
            (parent_address, 0x248, 0xabcdff0b)
        ]
    );
    assert_eq!(endpoint.config.words[20], 0xc000_a5a3);
    assert_eq!(parent.config.words[20], 0xc000_a5a3);
    assert_eq!(endpoint.config.words[0x188 / 4], 0x5abca50b);
    assert_eq!(parent.config.words[0x248 / 4], 0xabcdff0b);
    writes.borrow_mut().clear();
    disable_l1_2_with(&mut endpoint, core::slice::from_mut(&mut parent)).unwrap();
    assert!(
        writes.borrow().is_empty(),
        "already-disabled controls need no write"
    );
}

#[test]
fn l1ss_absence_skips_missing_controls_and_malformed_capabilities_still_refuse() {
    let writes = Writes::default();
    let mut endpoint = device(address(0, 8, 0), None, &writes);
    let mut parent = device(address(0, 4, 1), Some((8, 8)), &writes);
    disable_l1_2_with(&mut endpoint, core::slice::from_mut(&mut parent)).unwrap();
    add_l1ss(&mut endpoint, 0x180, 0xf);
    disable_l1_2_with(&mut endpoint, core::slice::from_mut(&mut parent)).unwrap();
    assert_eq!(*writes.borrow(), [(endpoint.address, 0x188, 0xb)]);
    writes.borrow_mut().clear();
    disable_l1_2_with(&mut endpoint, &mut []).unwrap();
    assert!(writes.borrow().is_empty());
    add_l1ss(&mut parent, 0x180, 0xf);
    let mut older_endpoint = device(address(0, 8, 0), None, &writes);
    disable_l1_2_with(&mut older_endpoint, core::slice::from_mut(&mut parent)).unwrap();
    assert_eq!(*writes.borrow(), [(parent.address, 0x188, 0xb)]);
    writes.borrow_mut().clear();
    for invalid in 0..8 {
        let mut broken = device(address(0, 4, 1), Some((8, 8)), &writes);
        add_l1ss(&mut broken, 0x180, 0xf);
        match invalid {
            0 => broken.config.words[0x180 / 4] |= 0x180 << 20, // loop
            1 => broken.config.words[0x180 / 4] |= 0x183 << 20, // misalignment
            2 => broken.config.words[0x180 / 4] |= 0x080 << 20, // below extended space
            3 => broken.config.words[0x180 / 4] = 0x0002_001e,  // unknown L1SS version
            4 => {
                broken.config.words[0x180 / 4] |= 0x200 << 20;
                broken.config.words[0x200 / 4] = 0x0001_001e;
            }
            5 => broken.config.words[0x184 / 4] = 0, // support absent
            6 => {
                broken.config.words[0x184 / 4] = 0x10;
            } // enabled unsupported L1.2
            _ => {
                broken.config.words[0x100 / 4] = 0xff4 << 20 | 0x10001;
                broken.config.words[0xff4 / 4] = 0x1001e;
            }
        }
        assert!(
            disable_l1_2_with(&mut endpoint, core::slice::from_mut(&mut broken)).is_err(),
            "invalid {invalid}"
        );
        assert!(writes.borrow().is_empty());
    }
}

#[test]
fn l1ss_failed_reads_and_refused_changes_leave_observable_partial_state() {
    let writes = Writes::default();
    for failed in [0x100, 0x180, 0x184, 0x188] {
        let mut endpoint = device(address(0, 8, 0), None, &writes);
        let mut parent = device(address(0, 4, 1), Some((8, 8)), &writes);
        add_l1ss(&mut endpoint, 0x180, 0xf);
        add_l1ss(&mut parent, 0x180, 0xf);
        parent.config.failed_read = Some(failed);
        assert_eq!(
            disable_l1_2_with(&mut endpoint, core::slice::from_mut(&mut parent)),
            if failed == 0x180 {
                Err(BlockError::PciCapability(
                    super::super::CapabilityError::FailedRead { offset: failed },
                ))
            } else {
                Err(BlockError::Device { status: u32::MAX })
            }
        );
        assert!(writes.borrow().is_empty());
    }
    let mut endpoint = device(address(0, 8, 0), None, &writes);
    let mut parent = device(address(0, 4, 1), Some((8, 8)), &writes);
    add_l1ss(&mut endpoint, 0x180, 0xf);
    add_l1ss(&mut parent, 0x180, 0xf);
    endpoint.config.refuses_l1ss = true;
    assert!(disable_l1_2_with(&mut endpoint, core::slice::from_mut(&mut parent)).is_err());
    assert_eq!(writes.borrow().len(), 1);
    writes.borrow_mut().clear();
    endpoint.config.refuses_l1ss = false;
    parent.config.refuses_l1ss = true;
    assert!(disable_l1_2_with(&mut endpoint, core::slice::from_mut(&mut parent)).is_err());
    assert_eq!(writes.borrow().len(), 2);
    assert_eq!(endpoint.config.words[0x188 / 4], 0xb);
    assert_eq!(parent.config.words[0x188 / 4], 0xf);
}

#[test]
fn extended_headers_cannot_alias_l1ss_bodies_in_either_traversal_direction() {
    for body in [0x184u16, 0x188, 0x18c] {
        for reverse in [false, true] {
            for broken_parent in [false, true] {
                let writes = Writes::default();
                let mut endpoint = device(address(0, 8, 0), None, &writes);
                let mut parent = device(address(0, 4, 1), Some((8, 8)), &writes);
                add_l1ss(&mut endpoint, 0x180, 0x0001_0005);
                add_l1ss(&mut parent, 0x180, 0x0001_0005);
                let broken = if broken_parent {
                    &mut parent
                } else {
                    &mut endpoint
                };
                let unknown_header = if body == 0x184 {
                    0x0001_001f
                } else {
                    0x0001_0005
                };
                if reverse {
                    broken.config.words[0x100 / 4] = u32::from(body) << 20 | 0x0001_0001;
                    broken.config.words[usize::from(body / 4)] = 0x180 << 20 | unknown_header;
                } else {
                    broken.config.words[0x180 / 4] |= u32::from(body) << 20;
                    broken.config.words[usize::from(body / 4)] = unknown_header;
                }
                let endpoint_before = endpoint.config.words;
                let parent_before = parent.config.words;
                assert!(
                    disable_l1_2_with(&mut endpoint, core::slice::from_mut(&mut parent)).is_err(),
                    "body {body:x} reverse {reverse} parent {broken_parent}"
                );
                assert!(writes.borrow().is_empty());
                assert_eq!(endpoint.config.words, endpoint_before);
                assert_eq!(parent.config.words, parent_before);
            }
        }
    }
}

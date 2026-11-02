// SPDX-License-Identifier: GPL-2.0-only
use super::*;
#[test]
fn minimum_source_failure_keeps_real_uas_tag_pending_and_blocks_late_credit() {
    let mut memory = vec![0u64; 1024 * 1024];
    let (mut host, hardware, _dma) = fixture(&mut memory, HIGH_SPEED, 32, 0);
    host.begin(LUN, &READ, Data::In(512)).unwrap();
    let tag = host.engine.tag;
    let pending = host.engine.pending.iter().filter(|x| x.is_some()).count();
    assert!(host.engine.active.is_some() && pending > 0);
    assert_eq!(
        host.delay(u64::MAX),
        Err(BlockError::PciPower(crate::bus::pci::power::Error::Clock))
    );
    assert!(host.engine.poisoned);
    let accesses = hardware.borrow().accesses;
    assert_eq!(
        host.end(),
        Some(Err(BlockError::PciPower(
            crate::bus::pci::power::Error::Clock
        )))
    );
    assert!(host.engine.active.is_some());
    assert_eq!(
        host.engine.pending.iter().filter(|x| x.is_some()).count(),
        pending
    );
    assert_eq!(host.engine.tag, tag);
    assert_eq!(
        host.command(LUN, &READ, Data::In(512)),
        Err(BlockError::PciPower(crate::bus::pci::power::Error::Clock))
    );
    assert_eq!(hardware.borrow().accesses, accesses);
}

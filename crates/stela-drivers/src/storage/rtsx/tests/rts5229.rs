//! Actual RTS5229 HAIMR/PHY/card peer, including revision-C pull controls.
use super::*;
mod uhs;

fn chip(mmc: bool, present: bool, revision: u8) -> Rc<RefCell<Chip>> {
    let chip = Chip::new(mmc, present);
    {
        let mut c = chip.borrow_mut();
        c.config[2..4].copy_from_slice(&0x5229u16.to_le_bytes());
        c.config[0x727] = 0;
        c.regs[0x3e90] = revision;
        // Fields interpreted as reverse/no-MMC on newer chips are ordinary
        // preserved bits here; source5229 does not use those board policies.
        c.config[0x814..0x818].copy_from_slice(&0x00c0_4030u32.to_le_bytes());
    }
    chip
}

#[test]
fn native_rts5229_actual_revision_power_and_drive_profile_runs_changed_sd_and_mmc_io() {
    for revision in [0, 2, 15] {
        for mmc in [false, true] {
            let chip = chip(mmc, true, revision);
            let mut host = make_host(&chip, true).unwrap();
            assert_eq!(host.inner.borrow().silicon_version, revision);
            assert_eq!(chip.borrow().phy[0], 0xba42);
            assert_eq!(
                chip.borrow().regs[0x3d5a],
                0,
                "no newer chip CLK drive array"
            );
            let mut disk = host.poll().unwrap().unwrap();
            assert_eq!(disk.info().bus_width, 4);
            assert_eq!(
                disk.info().clock_hz,
                if mmc { 52_000_000 } else { 50_000_000 }
            );
            assert_eq!(chip.borrow().phy[8], 0x4fe4);
            assert_eq!(chip.borrow().regs[0x3d5e] & 7, 2);
            assert_eq!(
                chip.borrow().regs[0x3d62],
                if revision == 2 { 0xd9 } else { 0xe9 }
            );
            assert_eq!(
                chip.borrow().regs[0x3d55] & 8,
                0,
                "MS outputs remain disabled"
            );
            let mut bytes = [0xa5; 1024];
            disk.read(3, &mut bytes).unwrap();
            assert_eq!(&bytes[..512], &chip.borrow_mut().card.block(3)[..]);
            assert_eq!(&bytes[512..], &chip.borrow_mut().card.block(4)[..]);
            bytes.fill(0x39);
            disk.write(6, &bytes).unwrap();
            disk.flush().unwrap();
            assert_eq!(&bytes[..512], &chip.borrow_mut().card.block(6)[..]);
            let mut alias = disk.clone();
            disk.shutdown(true).unwrap();
            assert_eq!(
                chip.borrow().regs[0x3d62],
                if revision == 2 { 0xe5 } else { 0xd5 }
            );
            assert!(alias.flush().is_err());
        }
    }
}

#[test]
fn native_rts5229_empty_socket_and_unknown_shared_ms_remain_owned_and_unpublished() {
    let chip = chip(false, false, 2);
    let mut host = make_host(&chip, false).unwrap();
    assert!(host.poll().unwrap().is_none());
    chip.borrow_mut().bipr |= SD_EXIST;
    let mut disk = host.poll().unwrap().unwrap();
    chip.borrow_mut().bipr |= MS_EXIST;
    let mut bytes = [0xa5; 512];
    assert!(disk.read(0, &mut bytes).is_err());
    assert_eq!(bytes, [0xa5; 512]);
    assert_eq!(chip.borrow().regs[0x3d50] & 3, 3);
    assert_eq!(chip.borrow().regs[0x3e75] & 6, 0);
}

#[test]
fn native_rts5229_failed_revision_or_voltage_phy_ack_never_publishes_commands() {
    for revision in [false, true] {
        let chip = chip(false, true, 2);
        if revision {
            chip.borrow_mut().stuck_haimr = Some(DUMMY_REG_RESET_0);
        }
        if revision {
            assert!(make_host(&chip, false).is_err());
            assert_eq!(chip.borrow().phy, [0; 256]);
        } else {
            let mut host = make_host(&chip, false).unwrap();
            chip.borrow_mut().stuck_phy = true;
            assert!(host.poll().is_err());
            assert!(host.inner.borrow().medium.is_none());
        }
        assert!(
            !chip
                .borrow()
                .effects
                .iter()
                .any(|effect| matches!(effect, Effect::Command(..)))
        );
    }
}

#[test]
#[ignore = "requires pinned original RTS5229 setup/voltage/power effect records"]
fn unchanged_linux_rts5229_setup_drive_pull_and_power_effects_match_native() {
    let records = std::fs::read_to_string(
        std::env::var_os("STELA_RTSX5229_ORACLE").expect("set STELA_RTSX5229_ORACLE"),
    )
    .unwrap();
    let mut cases = 0;
    for line in records.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        assert_eq!(words[0], "R");
        let n = |at: usize| words[at].parse::<u32>().unwrap();
        let chip = chip(false, false, n(1) as u8);
        {
            let mut c = chip.borrow_mut();
            let setting1 = if n(2) == 0 { 1 << 24 } else { 0 }
                | n(3) << 26
                | n(5) << 25
                | if n(6) == 0 { 0 } else { 3 << 28 };
            let setting2 = n(4) << 5 | 0x00c0_4010;
            c.config[0x724..0x728].copy_from_slice(&setting1.to_le_bytes());
            c.config[0x814..0x818].copy_from_slice(&setting2.to_le_bytes());
            c.regs[0x3e90] |= 0xa0;
        }
        let host = make_host(&chip, true).unwrap();
        assert_eq!(u32::from(host.inner.borrow().silicon_version), n(7));
        assert_eq!(u32::from(chip.borrow().regs[0x3d53]), n(8));
        assert_eq!(u32::from(chip.borrow().phy[0]), n(15));
        chip.borrow_mut().regs[0x3d5e] = 0xb8;
        host.inner.borrow_mut().rts5229_voltage(true).unwrap();
        assert_eq!(u32::from(chip.borrow().regs[0x3d5e]), n(16));
        assert_eq!(u32::from(chip.borrow().regs[0x3d5e] & 7), n(9));
        assert_eq!(u32::from(chip.borrow().phy[8]), n(17));
        host.inner.borrow_mut().rts5229_voltage(false).unwrap();
        assert_eq!(u32::from(chip.borrow().regs[0x3d5e]), n(18));
        assert_eq!(u32::from(chip.borrow().regs[0x3d5e] & 7), n(10));
        assert_eq!(u32::from(chip.borrow().phy[8]), n(19));
        host.inner.borrow_mut().configure_card().unwrap();
        {
            let c = chip.borrow();
            assert_eq!(u32::from(c.regs[0x3d61]), n(11));
            assert_eq!(u32::from(c.regs[0x3d62]), n(12));
            assert_eq!(u32::from(c.regs[0x3d50] & 3), n(20));
            assert_eq!(u32::from(c.regs[0x3e75] & 6), n(21));
            // The actual model's partial/full-power stores independently check
            // >=150us using the real Clock; this is the donor delay argument.
            assert_eq!(n(22), 150);
        }
        host.inner.borrow_mut().power_off().unwrap();
        let c = chip.borrow();
        assert_eq!(u32::from(c.regs[0x3d61]), n(13));
        assert_eq!(u32::from(c.regs[0x3d62]), n(14));
        assert_eq!(u32::from(c.regs[0x3d50] & 3), n(23));
        assert_eq!(u32::from(c.regs[0x3e75] & 6), n(24));
        assert!(
            !c.effects
                .iter()
                .any(|effect| matches!(effect, Effect::Command(..)))
        );
        cases += 1;
    }
    assert_eq!(cases, 384);
}

use super::*;
use alloc::{string::String, vec};

struct Recorded {
    events: Vec<String>,
}
impl Recorded {
    fn event(&mut self, kind: char, a: u32, b: u32) {
        self.events.push(format!("{kind}{a}:{b}"));
    }
}
impl Host for Recorded {
    fn command(
        &mut self,
        opcode: Opcode,
        argument: u32,
        _: Response,
        _: Option<usize>,
    ) -> Result<[u32; 4], BlockError> {
        match opcode.number() {
            6 => self.event('W', argument >> 16 & 255, argument >> 8 & 255),
            13 => self.event('S', 1, 0),
            _ => panic!("unqualified recorded MMC command"),
        }
        Ok([0x900, 0, 0, 0])
    }
    fn clock(&self) -> Clock {
        Clock {
            ticks_per_microsecond: 1000,
        }
    }
    fn location(&self) -> &str {
        "recorded MMC native boundaries"
    }
    fn voltage(&mut self) -> Result<u32, BlockError> {
        panic!("not an identification fixture")
    }
    fn writable(&mut self) -> Result<bool, BlockError> {
        panic!("not an identification fixture")
    }
    fn allow_kind(&self, _: Kind) -> Result<(), BlockError> {
        Ok(())
    }
    fn high_speed_supported(&self) -> bool {
        true
    }
    fn mmc_width(&self) -> u8 {
        8
    }
    fn set_bus_width(&mut self, v: u8) -> Result<(), BlockError> {
        self.event('B', u32::from(v), 0);
        Ok(())
    }
    fn set_high_speed(&mut self) -> Result<(), BlockError> {
        self.event('T', 1, 0);
        Ok(())
    }
    fn set_clock(&mut self, v: u32) -> Result<u32, BlockError> {
        self.event('C', v, 0);
        Ok(v)
    }
    fn scratch(&self) -> &[u8] {
        &[]
    }
    fn retire(&mut self, error: BlockError) -> BlockError {
        error
    }
    fn mmc_fast_modes(&self) -> bool {
        true
    }
    fn set_mmc_signal_voltage(&mut self) -> Result<(), BlockError> {
        self.event('V', 1, 0);
        Ok(())
    }
    fn set_mmc_timing(&mut self, timing: Timing) -> Result<(), BlockError> {
        self.event(
            'T',
            match timing {
                Timing::HighSpeed => 1,
                Timing::MmcHs200 => 9,
                Timing::MmcHs400 => 10,
                Timing::MmcDdr52 => 8,
                _ => panic!("unqualified timing"),
            },
            0,
        );
        Ok(())
    }
    fn set_mmc_strobe(&mut self, enable: bool) -> Result<(), BlockError> {
        self.event('E', u32::from(enable), 0);
        Ok(())
    }
    fn tune_mmc(&mut self) -> Result<(), BlockError> {
        self.event('Q', 21, 0);
        Ok(())
    }
    fn mmc_switch_status(&mut self, _: u16, crc_fatal: bool) -> Result<(), BlockError> {
        self.event('S', u32::from(crc_fatal), 0);
        Ok(())
    }
}

#[test]
#[ignore = "requires integrity-checked original MMC fast-mode procedure records"]
fn unchanged_linux_hs200_hs400_and_strobe_procedure_order_matches_native() {
    extern crate std;
    let trace = std::fs::read_to_string(
        std::env::var_os("STELA_MMC_FAST_ORACLE").expect("set STELA_MMC_FAST_ORACLE"),
    )
    .unwrap();
    let mut cases = 0;
    for line in trace.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        assert_eq!(words[0], "F");
        let number = |i: usize| words[i].parse::<u32>().unwrap();
        let mut ext = vec![0u8; 512];
        ext[196] =
            if number(2) == 0 { 1 } else { 3 } | 1 << 4 | if number(1) != 0 { 1 << 6 } else { 0 };
        ext[184] = u8::from(number(1) == 2);
        ext[236] = (((number(4) + 3) % 16) << 4) as u8;
        ext[237] = (number(4) << 4) as u8;
        ext[253] = (((number(4) + 7) % 16) << 4) as u8;
        let mut host = Recorded { events: vec![] };
        let mut info = CardInfo {
            kind: Kind::Mmc,
            cid: [0; 4],
            csd: [0; 4],
            scr: None,
            ext_csd: None,
            clock_hz: 400_000,
            bus_width: 8,
            signal_voltage: SignalVoltage::V1_8,
            timing: Timing::Legacy,
        };
        {
            let mut session = Session::new(&mut host, 1);
            let mode = session.fast_mode(&ext).unwrap();
            session.host.set_mmc_signal_voltage().unwrap();
            session.host.set_bus_width(8).unwrap();
            session
                .select_fast_mode(
                    mode,
                    if number(3) != 0 { OCR_180 } else { OCR_330 },
                    &mut ext,
                    &mut info,
                )
                .unwrap();
        }
        assert_eq!(host.events.join(" "), words[5..].join(" "), "{line}");
        cases += 1;
    }
    assert_eq!(cases, 192);
}

#[test]
#[ignore = "requires integrity-checked original MMC DDR52 procedure records"]
fn unchanged_linux_ddr52_hardware_busy_switch_order_matches_native() {
    extern crate std;
    let trace = std::fs::read_to_string(
        std::env::var_os("STELA_MMC_DDR52_ORACLE").expect("set STELA_MMC_DDR52_ORACLE"),
    )
    .unwrap();
    let mut cases = 0;
    for line in trace.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        assert_eq!(words[0], "D");
        let number = |i: usize| words[i].parse::<u32>().unwrap();
        let mut ext = vec![0u8; 512];
        ext[196] = 7;
        ext[238] = (((number(2) + 5) % 16) << 4) as u8;
        ext[239] = (number(2) << 4) as u8;
        ext[200] = (((number(2) + 9) % 16) << 4) as u8;
        ext[202] = (((number(2) + 11) % 16) << 4) as u8;
        let mut host = Recorded { events: vec![] };
        let mut info = CardInfo {
            kind: Kind::Mmc,
            cid: [0; 4],
            csd: [0; 4],
            scr: None,
            ext_csd: None,
            clock_hz: 400_000,
            bus_width: 1,
            signal_voltage: SignalVoltage::V3_3,
            timing: Timing::Legacy,
        };
        {
            let mut session = Session::new(&mut host, 1);
            assert!(session.ddr52_supported(&ext));
            session.begin_ddr52(&mut ext, &mut info).unwrap();
            session.host.set_bus_width(8).unwrap();
            session
                .finish_ddr52(
                    if number(1) != 0 { OCR_180 } else { OCR_330 },
                    &mut ext,
                    &mut info,
                )
                .unwrap();
        }
        assert_eq!(host.events.join(" "), words[3..].join(" "), "{line}");
        cases += 1;
    }
    assert_eq!(cases, 32);
}

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
#[ignore = "requires integrity-checked explicit MMC retuning procedure records"]
fn unchanged_linux_explicit_mmc_hs400_downgrade_tune_and_restore_match_native() {
    extern crate std;
    let trace = std::fs::read_to_string(
        std::env::var_os("STELA_MMC_RETUNE_ORACLE").expect("set STELA_MMC_RETUNE_ORACLE"),
    )
    .unwrap();
    let mut cases = 0;
    for line in trace.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        assert_eq!(words[0], "R");
        let n = |at: usize| words[at].parse::<u32>().unwrap();
        let hs400 = n(1) != 0;
        let mut ext = vec![0; 512];
        ext[196] = if n(2) == 0 { 1 } else { 3 } | 0x50;
        ext[183] = if hs400 { 6 } else { 2 };
        ext[185] = (n(3) << 4) as u8 | if hs400 { 3 } else { 2 };
        let mut info = CardInfo {
            kind: Kind::Mmc,
            cid: [0; 4],
            csd: [0; 4],
            scr: None,
            ext_csd: Some(ext),
            clock_hz: 200_000_000,
            bus_width: 8,
            signal_voltage: SignalVoltage::V1_8,
            timing: if hs400 {
                Timing::MmcHs400
            } else {
                Timing::MmcHs200
            },
        };
        let mut host = Recorded { events: vec![] };
        Session::new(&mut host, 1).retune_mmc(&mut info).unwrap();
        assert_eq!(host.events.join(" "), words[4..].join(" "), "{line}");
        assert_eq!(info.ext_csd.as_ref().unwrap()[185] >> 4, n(3) as u8);
        cases += 1;
    }
    assert_eq!(cases, 16);
}

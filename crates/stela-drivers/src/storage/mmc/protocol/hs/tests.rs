use super::*;
use alloc::{string::String, vec};

struct Recorded {
    events: Vec<String>,
    maximum_hz: u32,
    width: u8,
}
impl Recorded {
    fn event(&mut self, kind: char, a: u32) {
        self.events.push(format!("{kind}{a}:0"));
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
            6 => self
                .events
                .push(format!("W{}:{}", argument >> 16 & 255, argument >> 8 & 255)),
            13 => self.event('S', 1),
            _ => panic!("not a recorded ordinary-HS boundary"),
        }
        Ok([0x900, 0, 0, 0])
    }
    fn clock(&self) -> Clock {
        Clock {
            ticks_per_microsecond: 1000,
        }
    }
    fn location(&self) -> &str {
        "recorded MMC HS"
    }
    fn voltage(&mut self) -> Result<u32, BlockError> {
        panic!("not identification")
    }
    fn writable(&mut self) -> Result<bool, BlockError> {
        panic!("not identification")
    }
    fn allow_kind(&self, _: Kind) -> Result<(), BlockError> {
        Ok(())
    }
    fn high_speed_supported(&self) -> bool {
        true
    }
    fn mmc_width(&self) -> u8 {
        self.width
    }
    fn set_bus_width(&mut self, width: u8) -> Result<(), BlockError> {
        self.event('B', u32::from(width));
        Ok(())
    }
    fn set_high_speed(&mut self) -> Result<(), BlockError> {
        self.event('T', 1);
        Ok(())
    }
    fn set_clock(&mut self, requested: u32) -> Result<u32, BlockError> {
        let actual = requested.min(self.maximum_hz);
        self.event('C', actual);
        Ok(actual)
    }
    fn scratch(&self) -> &[u8] {
        &[]
    }
    fn retire(&mut self, error: BlockError) -> BlockError {
        error
    }
}

#[test]
#[ignore = "requires integrity-checked ordinary MMC HS original procedure records"]
fn unchanged_linux_ordinary_mmc_hs_status_clock_and_power_class_order_matches_native() {
    extern crate std;
    let trace = std::fs::read_to_string(
        std::env::var_os("STELA_MMC_HS_ORACLE").expect("set STELA_MMC_HS_ORACLE"),
    )
    .unwrap();
    let mut cases = 0;
    for line in trace.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        assert_eq!(words[0], "H");
        let n = |at: usize| words[at].parse::<u32>().unwrap();
        let width = if n(3) == 0 { 4 } else { 8 };
        let mut host = Recorded {
            events: vec![],
            maximum_hz: if n(4) == 0 { 200_000_000 } else { 25_000_000 },
            width,
        };
        let mut ext = vec![0; 512];
        ext[196] = if n(2) == 0 { 1 } else { 3 };
        for (index, high, low) in [(201, 1, 2), (200, 3, 4), (203, 5, 6), (202, 7, 8)] {
            ext[index] = ((((n(5) + high) % 16) << 4) | ((n(5) + low) % 16)) as u8;
        }
        let mut info = CardInfo {
            kind: Kind::Mmc,
            cid: [0; 4],
            csd: [0; 4],
            scr: None,
            ext_csd: None,
            clock_hz: 400_000,
            bus_width: width,
            signal_voltage: SignalVoltage::V3_3,
            timing: Timing::Legacy,
        };
        {
            let mut session = Session::new(&mut host, 1);
            session.begin_sdr_hs(&mut ext, &mut info).unwrap();
            session.host.set_bus_width(width).unwrap();
            session
                .select_sdr_power_class(
                    match n(1) {
                        0 => OCR_180,
                        1 => OCR_300,
                        _ => OCR_330,
                    },
                    &mut ext,
                    &info,
                )
                .unwrap();
        }
        assert_eq!(host.events.join(" "), words[6..].join(" "), "{line}");
        cases += 1;
    }
    assert_eq!(cases, 384);
}

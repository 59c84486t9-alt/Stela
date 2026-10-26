//! Compare actual immediate stores and results to whole original Linux helpers.
extern crate std;
use super::*;

#[test]
#[ignore = "requires pinned original AMD SoundWire command/polling records"]
fn unchanged_linux_amd_immediate_words_page_ack_and_timeout_effects_match_native() {
    let records = std::fs::read_to_string(
        std::env::var_os("STELA_AMD_SOUNDWIRE_ORACLE").expect("set STELA_AMD_SOUNDWIRE_ORACLE"),
    )
    .unwrap();
    let mut cases = 0;
    for line in records.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        assert_eq!(words[0], "A");
        let n = |at: usize| words[at].parse::<u32>().unwrap();
        let manager = if n(1) == 0 {
            Manager::First
        } else {
            Manager::Second
        };
        let paged = n(2) != 0;
        let write = n(3) != 0;
        let msg = Message {
            device: n(4) as u8,
            address: n(5) as u16,
            page: paged.then_some([0x17, 0x23]),
        };
        let length = n(6) as usize;
        let fault = n(7);
        let chip = Hardware::new(manager);
        {
            let mut h = chip.borrow_mut();
            let page = msg.page.unwrap_or([0; 2]);
            for i in 0..length {
                let address = msg.address + i as u16;
                h.memory.insert(
                    (page[0], page[1], address),
                    (u32::from(address) * 37
                        + u32::from(msg.device) * 13
                        + u32::from(page[0]) * 3
                        + u32::from(page[1]) * 7) as u8,
                );
            }
            let last = length + usize::from(paged) * 2 - 1;
            if fault == 3 {
                h.response_bits = 3;
            } else if matches!(fault, 1 | 2) {
                h.response_at = Some(last);
                h.response_bits = if fault == 1 { 2 } else { 0 };
            } else if fault == 4 {
                h.delay_at = Some(last);
                h.response_after = 2_000;
            }
        }
        let mut host = controller(&chip, 100_000);
        let tx: Vec<_> = (0..length)
            .map(|i| ((i as u8).wrapping_mul(37)) ^ 0x91)
            .collect();
        let mut output = vec![0xa5; length];
        let result = if write {
            host.write_registers(msg, &tx)
        } else {
            host.read_registers(msg, &mut output)
        };
        let expected_class = match n(8) {
            0 => None,
            1 => Some(ErrorKind::Ignored),
            2 => Some(ErrorKind::Nack),
            3 => Some(ErrorKind::Timeout),
            value => panic!("unexpected source result {value}"),
        };
        assert_eq!(result.err().map(|e| e.kind), expected_class, "{line}");
        let trace: Vec<_> = chip
            .borrow()
            .trace
            .iter()
            .filter(|a| a.write)
            .map(|a| (a.at as u32, a.value))
            .collect();
        let effects = n(9) as usize;
        let source_trace: Vec<_> = (0..effects)
            .map(|i| (n(10 + i * 2), n(11 + i * 2)))
            .collect();
        assert_eq!(trace, source_trace, "{line}");
        let hex = words[10 + effects * 2];
        let bytes: Vec<_> = (0..length)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        if expected_class.is_none() {
            assert_eq!(if write { &tx } else { &output }, &bytes, "{line}");
            drop(host.release().ok().unwrap());
        } else {
            assert_eq!(output, vec![0xa5; length], "native whole-output staging");
            assert!(host.release().is_err());
        }
        cases += 1;
    }
    assert_eq!(cases, 1440);
}

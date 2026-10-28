//! Original-source success/error wire effects; caller staging is separate.
extern crate std;
use super::*;

#[test]
#[ignore = "oracle: STELA_CADENCE_SOUNDWIRE_ORACLE"]
fn unchanged_linux_command_and_page_batches_match_native_control_word_effects() {
    let text = std::fs::read_to_string(
        std::env::var_os("STELA_CADENCE_SOUNDWIRE_ORACLE")
            .expect("set STELA_CADENCE_SOUNDWIRE_ORACLE"),
    )
    .unwrap();
    let mut cases = 0;
    for line in text.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        assert_eq!(fields[0], "C");
        let n = |i: usize| fields[i].parse::<usize>().unwrap();
        let layout = if n(1) == 0 {
            Layout::Legacy
        } else {
            Layout::Extended
        };
        let (mut host, h) = setup(layout);
        let message = Message {
            device: n(5) as u8,
            address: n(6) as u16,
            page: (n(2) != 0).then_some([0x17, 0x23]),
            ssp_sync: n(4) != 0,
        };
        let read = n(3) != 0;
        let length = n(7);
        let fault = n(8);
        let pages = message.page.unwrap_or([0; 2]);
        for i in 0..length {
            let at = message.address + i as u16;
            let value = (u32::from(at) * 37
                + u32::from(message.device) * 13
                + u32::from(pages[0]) * 3
                + u32::from(pages[1]) * 7) as u8;
            h.borrow_mut()
                .data
                .insert((message.device, pages[0], pages[1], at), value);
        }
        if fault != 0 {
            let at = if fault == 3 {
                length + if message.page.is_some() { 2 } else { 0 } - 1
            } else {
                0
            };
            if fault == 2 {
                h.borrow_mut().ignored = Some(at);
            } else {
                h.borrow_mut().nack = Some(at);
            }
        }
        let mut bytes: Vec<_> = (0..length)
            .map(|i| {
                if read {
                    0xa5
                } else {
                    (i as u8).wrapping_mul(37) ^ 0x91
                }
            })
            .collect();
        let result = if read {
            host.read_registers(message, &mut bytes)
        } else {
            host.write_registers(message, &bytes)
        };
        let expected: Vec<_> = (0..n(10))
            .map(|i| (n(11 + i * 2), n(12 + i * 2) as u32))
            .collect();
        assert_eq!(h.borrow().effects, expected, "source case {cases}: {line}");
        if n(9) == 0 {
            result.unwrap();
            let payload = fields[11 + n(10) * 2];
            let original: Vec<_> = (0..length)
                .map(|i| u8::from_str_radix(&payload[i * 2..i * 2 + 2], 16).unwrap())
                .collect();
            assert_eq!(bytes, original, "source case {cases}");
            drop(host.release().ok().unwrap());
            assert_eq!(h.borrow().drops, 1);
        } else {
            let error = result.unwrap_err();
            assert_eq!(
                error.kind,
                if fault == 2 {
                    ErrorKind::Ignored
                } else {
                    ErrorKind::Nack
                }
            );
            assert_eq!(
                n(9),
                if message.page.is_some() && error.completed == 0 {
                    4
                } else if fault == 2 {
                    1
                } else {
                    2
                }
            );
            if read {
                assert_eq!(bytes, vec![0xa5; length]);
            }
            drop(host);
            assert_eq!(h.borrow().drops, 0);
        }
        cases += 1;
    }
    assert_eq!(cases, 2880);
}

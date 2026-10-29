// SPDX-License-Identifier: GPL-2.0-only
//! External, separately checked whole-original-C trace. This test starts no
//! child, compiles nothing and requires a complete exact sixty-case trace.
use super::*;
fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    assert!(
        s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn drain(e: &mut Engine) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(frame) = e.frames.pop_front() {
        e.published(&frame).unwrap();
        out.push(frame.bytes);
    }
    out
}
fn connected(credit: bool) -> (Engine, Vec<u8>, Vec<u8>) {
    let mut e = Engine::new();
    e.start().unwrap();
    drain(&mut e);
    e.receive(&transport(0, 0, &[0x81, 1, 0, 1], true)).unwrap();
    drain(&mut e);
    let mut bitmap = vec![0x84, 0, 0, 0];
    bitmap.extend_from_slice(&[0; 32]);
    bitmap[4] = 1 << 5;
    e.receive(&transport(0, 0, &bitmap, true)).unwrap();
    drain(&mut e);
    let mut props = vec![0; 32];
    props[0] = 0x85;
    props[1] = 5;
    props[4..20].copy_from_slice(&HID_GUID);
    props[20] = 1;
    props[21] = 1;
    props[24..28].copy_from_slice(&4096u32.to_le_bytes());
    e.receive(&transport(0, 0, &props, true)).unwrap();
    let connect = drain(&mut e).pop().unwrap();
    e.receive(&transport(0, 0, &[0x86, 5, 1, 0], true)).unwrap();
    let flow = drain(&mut e).pop().unwrap();
    if credit {
        e.receive(&transport(0, 0, &[8, 5, 1, 0, 0, 0, 0, 0], true))
            .unwrap();
    }
    (e, connect, flow)
}
fn request(cmd: u8, device: u8, id: Option<u8>, body: &[u8]) -> Vec<u8> {
    let (mut e, _, _) = connected(true);
    e.request(cmd, device, id, body).unwrap();
    assert!(!e.credit_available());
    drain(&mut e)
        .into_iter()
        .flat_map(|v| v[4..].to_vec())
        .collect()
}
#[test]
#[ignore = "oracle: STELA_ISH_ORACLE_60_V1, STELA_ISH_ORACLE_TRACE"]
fn original_linux_whole_helpers_match_sixty_wire_fragment_credit_and_refusal_cases() {
    let path =
        std::env::var("STELA_ISH_ORACLE_TRACE").expect("external qualified original-C trace");
    let text = std::fs::read_to_string(path).unwrap();
    assert!(text.ends_with('\n'));
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some("STELA_ISH_ORACLE_60_V1"));
    let mut expected = Vec::new();
    for device in [7, 19] {
        for id in [1, 2] {
            for command in [4, 2] {
                expected.push(request(command, device, Some(id), &[]));
            }
        }
    }
    for device in [7, 19] {
        for n in [1, 4, 125, 249] {
            let body = (0..n).map(|j| (j * 17 + 3) as u8).collect::<Vec<_>>();
            expected.push(request(3, device, None, &body));
        }
    }
    expected.push(request(33, 0, None, &[]));
    for device in [7, 19] {
        for command in [0, 1] {
            expected.push(request(command, device, None, &[]));
        }
    }
    let (mut e, connect, flow) = connected(true);
    expected.push(connect);
    e.disconnect().unwrap();
    expected.push(drain(&mut e).pop().unwrap());
    expected.push(flow);
    assert_eq!(expected.len(), 24);
    for (index, bytes) in expected.iter().enumerate() {
        let p = lines.next().unwrap().split(' ').collect::<Vec<_>>();
        assert_eq!(p.len(), 4);
        assert_eq!(p[0], "W");
        assert_eq!(p[1].parse::<usize>().unwrap(), index);
        assert_eq!(p[2].parse::<usize>().unwrap(), bytes.len());
        assert_eq!(&hex(p[3]), bytes);
    }
    let mut index = 0;
    for n in [1usize, 6, 7, 123, 124, 125, 248, 249, 1024] {
        for mode in 0..4 {
            let p = lines.next().unwrap().split(' ').collect::<Vec<_>>();
            assert_eq!(p.len(), 13);
            assert_eq!(p[0], "I");
            let fields = p[1..]
                .iter()
                .map(|s| s.parse::<usize>().unwrap())
                .collect::<Vec<_>>();
            let active = mode == 0;
            let credit = usize::from(mode != 1);
            let count = if active { n.div_ceil(MTU) } else { 0 };
            assert_eq!(
                fields,
                [
                    index,
                    n,
                    mode,
                    credit,
                    if active { 0 } else { credit },
                    0,
                    0,
                    usize::from(active),
                    usize::from(active),
                    usize::from(!active),
                    usize::from(active),
                    count
                ]
            );
            let body = (0..n).map(|j| (j * 29 + 11) as u8).collect::<Vec<_>>();
            let encoded = if active {
                fragment_message(5, 1, &body).unwrap()
            } else {
                Vec::new()
            };
            assert_eq!(encoded.len(), count);
            for (fragment, frame) in encoded.iter().enumerate() {
                let f = lines.next().unwrap().split(' ').collect::<Vec<_>>();
                assert_eq!(f.len(), 4);
                assert_eq!(f[0], "F");
                assert_eq!(f[1].parse::<usize>().unwrap(), fragment);
                assert_eq!(f[2].parse::<usize>().unwrap(), frame.bytes.len());
                assert_eq!(hex(f[3]), frame.bytes);
            }
            // Original C free-list/sending/offset diagnostics above are checked
            // independently. The production engine uses owned queued messages rather
            // than Linux list nodes; its observable publication/credit policy agrees.
            let (mut check, _, _) = connected(mode == 0);
            match mode {
                0 => {
                    check.request(3, 7, None, &[]).unwrap();
                    assert!(!check.credit_available());
                    assert!(!check.frames.is_empty());
                }
                1 => {
                    check.request(3, 7, None, &[]).unwrap();
                    assert!(!check.credit_available());
                    assert!(check.frames.is_empty());
                }
                2 => {
                    check.disconnect().unwrap();
                    drain(&mut check);
                    check
                        .receive(&transport(0, 0, &[0x87, 5, 1, 0], true))
                        .unwrap();
                    assert!(check.request(3, 7, None, &[]).is_err());
                    assert!(check.frames.is_empty());
                }
                _ => {
                    let mut stopped = Engine::new();
                    assert!(stopped.request(3, 7, None, &[]).is_err());
                    assert!(stopped.frames.is_empty());
                }
            }
            index += 1;
        }
    }
    assert_eq!(index, 36);
    assert_eq!(lines.next(), Some("END 60"));
    assert_eq!(lines.next(), None);
}

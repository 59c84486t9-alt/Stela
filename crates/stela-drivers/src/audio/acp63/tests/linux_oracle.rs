// SPDX-License-Identifier: GPL-2.0-only
//! Linux oracle cases.
use super::*;

#[test]
#[ignore = "oracle: STELA_ACP70_ORACLE"]
fn acp70_unchanged_linux_power_and_init_oracle() {
    use std::fmt::Write;
    let path = std::env::var("STELA_ACP70_ORACLE").unwrap();
    let original = std::fs::read_to_string(path).unwrap();
    let mut actual = std::string::String::from("linux a804c5742bff224d4cb4d25dd383554d598be32b\n");
    for status in [0, 1, 2, 0x80, 0x100] {
        let (mut controller, device, _) = fixture70(0x70);
        device.lock().unwrap().words[0x1028 / 4] = status;
        writeln!(actual, "case {status:08x}").unwrap();
        let result = controller.initialize();
        {
            let model = device.lock().unwrap();
            for (offset, value) in &model.writes {
                // These are the original source's init registers. Native
                // ATU/BME/drain containment additionally precedes DMA, but
                // never substitutes for a source effect in this trace.
                if matches!(
                    *offset,
                    0x1024 | 0x1004 | 0x1000 | 0x1014 | 0x1a00 | 0x1a04 | 0x1400
                ) {
                    writeln!(actual, "w {offset:04x} {value:08x}").unwrap();
                }
            }
        }
        let code = if result.is_ok() {
            0
        } else {
            assert_eq!(result, Err(Error::Timeout(Phase::PowerOn)));
            -110
        };
        writeln!(actual, "result {code}").unwrap();
        if status == 0x100 {
            device.lock().unwrap().words[0x1028 / 4] = 0;
        }
        controller.shutdown().unwrap();
    }
    assert_eq!(actual, original);
}

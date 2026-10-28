//! Controller command limits and no-data Write Zeroes encoding.
use super::*;

#[test]
fn write_zeroes_default_uses_mdts_without_the_payload_bounce_cap() {
    for (mdts, command_bytes, payload_bytes) in [
        (0, MAX_COMMAND_BYTES, BOUNCE_BYTES),
        (4, 64 * 1024, 64 * 1024),
        (7, 512 * 1024, BOUNCE_BYTES),
        (31, MAX_COMMAND_BYTES, BOUNCE_BYTES),
        (63, MAX_COMMAND_BYTES, BOUNCE_BYTES),
        (64, MAX_COMMAND_BYTES, BOUNCE_BYTES),
        (255, MAX_COMMAND_BYTES, BOUNCE_BYTES),
    ] {
        let f = Fixture::new();
        {
            let mut model = f.model.lock().unwrap();
            model.oncs = COMMANDS_WRITE_ZEROES;
            model.mdts = mdts;
        }
        let attached = f.attach().unwrap();
        let features = attached.namespaces[0].identity().features;
        assert_eq!(features.max_transfer, payload_bytes, "MDTS {mdts}");
        assert_eq!(
            features.write_zeroes.unwrap().blocks,
            (command_bytes / 512) as u64,
            "MDTS {mdts}"
        );
    }
}

#[test]
fn explicit_wzsl_overrides_mdts_and_still_obeys_nlb_width() {
    for (wzsl, blocks) in [(1, 16), (8, 2048), (20, 65536), (255, 65536)] {
        let f = Fixture::new();
        {
            let mut model = f.model.lock().unwrap();
            model.registers.insert(8, 0x0001_0200);
            model.oncs = COMMANDS_WRITE_ZEROES;
            model.mdts = 1;
            model.nvm_limits = Some((wzsl, 0));
        }
        let attached = f.attach().unwrap();
        let features = attached.namespaces[0].identity().features;
        assert_eq!(features.max_transfer, 8192);
        assert_eq!(features.write_zeroes.unwrap().blocks, blocks, "WZSL {wzsl}");
    }
}

#[test]
fn write_zeroes_nlb_boundaries_have_no_host_data_pointers() {
    let fixture = Fixture::new();
    let attached = fixture.attach().unwrap();
    let mut controller = attached.namespaces[0].controller.borrow_mut();
    for blocks in [1, 65536] {
        let command = Command::WriteZeroes {
            lba: 0x1_0000_0000,
            blocks,
            unmap: false,
        };
        let words = controller.io_command(0, 1, 512, &command).unwrap();
        assert_eq!(words[0], u32::from(IO_WRITE_ZEROES));
        assert_eq!(words[1], 1);
        assert_eq!(words[6..10], [0; 4]);
        assert_eq!(words[10..12], [0, 1]);
        assert_eq!(words[12], (blocks - 1) as u32);
    }
    for blocks in [0, 65537] {
        let command = Command::WriteZeroes {
            lba: 0,
            blocks,
            unmap: false,
        };
        assert_eq!(
            controller.io_command(0, 1, 512, &command),
            Err(BlockError::Unsupported("Write Zeroes past 65536 blocks"))
        );
    }
}

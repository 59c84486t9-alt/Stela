use super::*;

const ADDRESS: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x02];
const PEER: [u8; 6] = [1, 2, 3, 4, 5, 6];

fn packet(opcode: u16, parameters: &[u8]) -> Vec<u8> {
    let mut packet = opcode.to_le_bytes().to_vec();
    packet.push(parameters.len() as u8);
    packet.extend_from_slice(parameters);
    packet
}

/// The single Command Complete `events` holds for `opcode`: its status and
/// return parameters.
fn complete(events: &[Vec<u8>], opcode: u16) -> (u8, Vec<u8>) {
    assert_eq!(events.len(), 1, "one event: {events:02x?}");
    let e = &events[0];
    assert_eq!(e[0], COMMAND_COMPLETE);
    assert_eq!(usize::from(e[1]), e.len() - 2);
    assert_eq!(e[2], 1, "one command packet allowed");
    assert_eq!(u16::from_le_bytes([e[3], e[4]]), opcode);
    (e[5], e[6..].to_vec())
}

fn run(model: &mut Model, opcode: u16, parameters: &[u8]) -> Vec<Vec<u8>> {
    model.command(&packet(opcode, parameters), 0)
}

fn ok(model: &mut Model, opcode: u16, parameters: &[u8]) -> Vec<u8> {
    let (status, returns) = complete(&run(model, opcode, parameters), opcode);
    assert_eq!(status, SUCCESS, "{opcode:#06x}");
    returns
}

fn status(events: &[Vec<u8>], opcode: u16) -> u8 {
    let e = &events[0];
    assert_eq!(e[..2], [COMMAND_STATUS, 4]);
    assert_eq!(e[3], 1);
    assert_eq!(u16::from_le_bytes([e[4], e[5]]), opcode);
    e[2]
}

fn supported(opcode: u16) -> bool {
    let bitmap = supported_commands();
    COMMANDS
        .iter()
        .find(|c| c.opcode == opcode)
        .is_some_and(|c| bitmap[usize::from(c.octet)] & 1 << c.bit != 0)
}

#[test]
fn bluetoothd_bring_up_completes_in_order() {
    let mut model = Model::new(ADDRESS);
    // The init steps of bluetoothd's HCI bring-up (0x100193274..0x10019191c),
    // each gated on its Supported Commands bit.
    ok(&mut model, 0x0c03, &[]);
    let version = ok(&mut model, 0x1001, &[]);
    assert_eq!(version, [HCI_VERSION, 0, 0, LMP_VERSION, 0xff, 0xff, 0, 0]);
    let commands = ok(&mut model, 0x1002, &[]);
    assert_eq!(commands, supported_commands());
    assert_eq!(ok(&mut model, 0x1009, &[]), ADDRESS);
    let features = ok(&mut model, 0x1003, &[]);
    assert_eq!(features, LMP_FEATURES.to_le_bytes());
    assert_ne!(features[4] & 1 << 6, 0, "LE supported (controller)");
    assert_ne!(features[7] & 1 << 7, 0, "extended features");
    let page = ok(&mut model, 0x1004, &[1]);
    assert_eq!(page[..2], [1, MAX_FEATURE_PAGE]);
    assert_eq!(page[2], 0, "the host enabled nothing yet");
    assert_eq!(ok(&mut model, 0x2003, &[]), [0; 8]);
    ok(
        &mut model,
        0x0c01,
        &[0xff, 0xff, 0xfb, 0xff, 0x07, 0xf8, 0xbf, 0x3d],
    );
    ok(&mut model, 0x0c63, &[0; 8]);
    ok(&mut model, 0x2001, &[0x1f, 0, 0, 0, 0, 0, 0, 0]);
    ok(&mut model, 0x0c56, &[1]);
    ok(&mut model, 0x0c6d, &[1, 0]);
    assert_eq!(ok(&mut model, 0x1004, &[1])[2], 0b11, "SSP and LE host");
    assert_eq!(ok(&mut model, 0x2002, &[]), [251, 0, LE_ACL_BUFFERS]);
    assert_eq!(ok(&mut model, 0x201c, &[]), LE_STATES.to_le_bytes());
    assert_eq!(ok(&mut model, 0x200f, &[]), [ACCEPT_LIST_SIZE as u8]);
    assert_eq!(ok(&mut model, 0x1005, &[]), [0xfd, 0x03, 0, 8, 0, 0, 0]);
    ok(&mut model, 0x0c33, &[0xfd, 0x03, 0, 8, 0, 0, 0]);
    ok(&mut model, 0x0c31, &[1]);
    ok(&mut model, 0x0c5b, &[0]);
    assert_eq!(ok(&mut model, 0x2007, &[]), [0]);
    // Device configuration at the login window.
    ok(&mut model, 0x0c24, &[0x0c, 0x01, 0x1c]);
    assert_eq!(ok(&mut model, 0x0c23, &[]), [0x0c, 0x01, 0x1c]);
    let mut name = [0; 248];
    name[..4].copy_from_slice(b"Mini");
    ok(&mut model, 0x0c13, &name);
    assert_eq!(ok(&mut model, 0x0c14, &[]), name);
    ok(&mut model, 0x0c18, &[0x00, 0x20]);
    ok(&mut model, 0x0c1a, &[3]);
    ok(&mut model, 0x0c45, &[2]);
    ok(&mut model, 0x0c52, &[0; 241]);
    assert_eq!(model.air().scan_enable, 3);
    // Steps bluetoothd takes only when their bits are set: none is.
    for optional in [0x2060, 0x2074, 0x202f, 0x207d, 0x2087, 0x20a2] {
        assert!(!supported(optional), "{optional:#06x}");
        assert!(!implements(optional));
    }
}

#[test]
fn the_bitmap_lists_every_implemented_command_and_nothing_else() {
    let bitmap = supported_commands();
    let set: u32 = bitmap.iter().map(|b| b.count_ones()).sum();
    assert_eq!(set as usize, COMMANDS.len());
    for command in COMMANDS {
        assert!(supported(command.opcode));
    }
    // Reset is octet 5 bit 7 (Vol 4 Part E 6.27).
    assert_ne!(bitmap[5] & 0x80, 0);
}

#[test]
fn unknown_opcodes_answer_unknown_command_and_are_reported_once() {
    let mut model = Model::new(ADDRESS);
    for _ in 0..2 {
        // A Broadcom vendor command and Write Secure Connections Host Support.
        for opcode in [0xfc4c, 0x0c7a] {
            let (status, returns) = complete(&run(&mut model, opcode, &[1]), opcode);
            assert_eq!((status, returns.len()), (UNKNOWN_COMMAND, 0));
        }
    }
    assert_eq!(model.take_unknown(), [0xfc4c, 0x0c7a]);
    assert!(model.take_unknown().is_empty());
    // A known command with the wrong length is invalid, not unknown, and
    // keeps its return parameters' length.
    let (status, returns) = complete(&run(&mut model, 0x1009, &[0]), 0x1009);
    assert_eq!((status, returns), (INVALID_PARAMETERS, vec![0; 6]));
}

#[test]
fn acl_data_returns_its_buffer_and_goes_nowhere() {
    let mut model = Model::new(ADDRESS);
    let events = model.acl(&[0x40, 0x20, 2, 0, 9, 9]);
    assert_eq!(
        events,
        [vec![NUMBER_OF_COMPLETED_PACKETS, 5, 1, 0x40, 0, 1, 0]]
    );
    assert!(
        model.acl(&[0xff, 0x2f, 0, 0]).is_empty(),
        "a reserved handle"
    );
    assert_eq!(model.discarded_acl, 2);
    // Host Number Of Completed Packets answers only on error.
    assert!(run(&mut model, 0x0c35, &[1, 0x40, 0, 1, 0]).is_empty());
    let (status, _) = complete(&run(&mut model, 0x0c35, &[2, 0x40, 0]), 0x0c35);
    assert_eq!(status, INVALID_PARAMETERS);
}

#[test]
fn le_scanning_follows_its_parameters_and_reports_nothing() {
    let mut model = Model::new(ADDRESS);
    // Active, 60 ms in 60 ms, random own address, no filter.
    let parameters = [1, 0x60, 0, 0x60, 0, 1, 0];
    ok(&mut model, 0x200b, &parameters);
    let (missing, _) = complete(&run(&mut model, 0x200c, &[1, 1]), 0x200c);
    assert_eq!(missing, INVALID_PARAMETERS, "no random address yet");
    ok(&mut model, 0x2005, &[1, 2, 3, 4, 5, 0xc6]);
    ok(&mut model, 0x200c, &[1, 1]);
    assert_eq!(model.air().scanning, Some((1, 1)));
    let (busy, _) = complete(&run(&mut model, 0x200b, &parameters), 0x200b);
    assert_eq!(busy, COMMAND_DISALLOWED);
    let (busy, _) = complete(&run(&mut model, 0x2005, &[1; 6]), 0x2005);
    assert_eq!(busy, COMMAND_DISALLOWED);
    assert!(model.advance(u64::MAX).is_empty(), "nothing in range");
    assert_eq!(model.deadline(), None);
    ok(&mut model, 0x200c, &[0, 0]);
    assert_eq!(model.air().scanning, None);
    // Window longer than interval.
    let (bad, _) = complete(&run(&mut model, 0x200b, &[0, 4, 0, 5, 0, 0, 0]), 0x200b);
    assert_eq!(bad, INVALID_PARAMETERS);
}

#[test]
fn a_page_ends_with_page_timeout_after_the_page_timeout() {
    let mut model = Model::new(ADDRESS);
    // 0x0100 slots, 160 ms.
    ok(&mut model, 0x0c18, &[0x00, 0x01]);
    let mut create = PEER.to_vec();
    create.extend_from_slice(&[0x18, 0xcc, 1, 0, 0, 0, 1]);
    let start = 1000;
    let events = model.command(&packet(0x0405, &create), start);
    assert_eq!((events.len(), status(&events, 0x0405)), (1, SUCCESS));
    let end = start + 0x100 * SLOT;
    assert_eq!(model.deadline(), Some(end));
    assert!(model.advance(end - 1).is_empty());
    let mut expected = vec![CONNECTION_COMPLETE, 11, PAGE_TIMEOUT, 0, 0];
    expected.extend_from_slice(&PEER);
    expected.extend_from_slice(&[1, 0]);
    assert_eq!(model.advance(end), [expected]);
    assert_eq!(model.deadline(), None);
    // Disconnect names no connection.
    assert_eq!(
        status(&run(&mut model, 0x0406, &[0, 0, 0x13]), 0x0406),
        UNKNOWN_CONNECTION
    );
}

#[test]
fn cancelled_attempts_end_with_unknown_connection_identifier() {
    let mut model = Model::new(ADDRESS);
    let mut create = PEER.to_vec();
    create.extend_from_slice(&[0x18, 0xcc, 1, 0, 0, 0, 1]);
    run(&mut model, 0x0405, &create);
    let events = run(&mut model, 0x0408, &PEER);
    assert_eq!(events.len(), 2);
    assert_eq!(complete(&events[..1], 0x0408), (SUCCESS, PEER.to_vec()));
    assert_eq!(
        events[1][..3],
        [CONNECTION_COMPLETE, 11, UNKNOWN_CONNECTION]
    );
    // Nothing left to cancel.
    let (status_, _) = complete(&run(&mut model, 0x0408, &PEER), 0x0408);
    assert_eq!(status_, UNKNOWN_CONNECTION);
    // An LE connection never completes until cancelled.
    // LE Meta is masked by default (Vol 4 Part E 7.3.1).
    ok(
        &mut model,
        0x0c01,
        &[0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0, 0x20],
    );
    let mut le = vec![0x60, 0, 0x30, 0, 0, 0];
    le.extend_from_slice(&PEER);
    le.extend_from_slice(&[0, 0x18, 0, 0x28, 0, 0, 0, 0x48, 0, 0, 0, 0, 0]);
    assert_eq!(status(&run(&mut model, 0x200d, &le), 0x200d), SUCCESS);
    assert_eq!(
        status(&run(&mut model, 0x200d, &le), 0x200d),
        COMMAND_DISALLOWED
    );
    assert!(model.advance(u64::MAX).is_empty());
    let events = run(&mut model, 0x200e, &[]);
    assert_eq!(complete(&events[..1], 0x200e).0, SUCCESS);
    assert_eq!(
        events[1][..4],
        [LE_META, 19, LE_CONNECTION_COMPLETE, UNKNOWN_CONNECTION]
    );
    assert_eq!(events[1][7..14], [0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(
        complete(&run(&mut model, 0x200e, &[]), 0x200e).0,
        COMMAND_DISALLOWED
    );
}

#[test]
fn an_inquiry_completes_with_no_results_unless_masked() {
    let mut model = Model::new(ADDRESS);
    let inquiry = [0x33, 0x8b, 0x9e, 2, 0];
    assert_eq!(
        status(&model.command(&packet(0x0401, &inquiry), 0), 0x0401),
        SUCCESS
    );
    assert_eq!(
        status(&run(&mut model, 0x0401, &inquiry), 0x0401),
        COMMAND_DISALLOWED
    );
    assert!(model.air().inquiring);
    assert_eq!(model.deadline(), Some(2 * INQUIRY_UNIT));
    assert_eq!(
        model.advance(2 * INQUIRY_UNIT),
        [vec![INQUIRY_COMPLETE, 1, SUCCESS]]
    );
    // Masked: the inquiry still ends, silently.
    ok(
        &mut model,
        0x0c01,
        &[0xfe, 0xff, 0xff, 0xff, 0xff, 0x1f, 0, 0],
    );
    model.command(&packet(0x0401, &inquiry), 0);
    assert!(model.advance(2 * INQUIRY_UNIT).is_empty());
    assert!(!model.air().inquiring);
    // Not an inquiry access code.
    assert_eq!(
        status(&run(&mut model, 0x0401, &[0, 0, 0, 2, 0]), 0x0401),
        INVALID_PARAMETERS
    );
}

#[test]
fn reset_ends_procedures_without_events_and_restores_defaults() {
    let mut model = Model::new(ADDRESS);
    ok(&mut model, 0x0c18, &[0x10, 0]);
    run(&mut model, 0x0401, &[0x33, 0x8b, 0x9e, 1, 0]);
    ok(&mut model, 0x0c03, &[]);
    assert!(model.advance(u64::MAX).is_empty());
    assert_eq!(ok(&mut model, 0x0c17, &[]), 0x2000u16.to_le_bytes());
}

#[test]
fn the_address_is_stable_unicast_and_locally_administered() {
    let a = address(0x0011_2233_4455_6677);
    assert_eq!(a, address(0x0011_2233_4455_6677));
    assert_ne!(a, address(0x0011_2233_4455_6678));
    for ecid in 0..256 {
        let a = address(ecid);
        assert_eq!(a[5] & 0x03, 0x02, "unicast, locally administered");
        let lap = u32::from_le_bytes([a[0], a[1], a[2], 0]);
        assert!(!(0x9e8b00..=0x9e8b3f).contains(&lap));
    }
}

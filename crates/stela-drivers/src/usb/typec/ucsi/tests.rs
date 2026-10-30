extern crate std;
use super::*;
use alloc::{collections::VecDeque, rc::Rc};
use core::cell::Cell;

#[derive(Clone, Copy, Default)]
enum Wait {
    #[default]
    Complete,
    Busy,
    Quiet,
}
struct Reply {
    command: u64,
    bytes: Vec<u8>,
    flags: u32,
    wait: Wait,
}
impl Reply {
    fn new(command: Command, bytes: &[u8]) -> Self {
        Self {
            command: command.control,
            bytes: bytes.to_vec(),
            flags: 0,
            wait: Wait::Complete,
        }
    }
}
#[derive(Clone, Copy)]
enum State {
    Idle,
    Reset,
    Command(Wait),
    Ack(bool),
    Cancel,
}
struct Ppm {
    version: u16,
    state: State,
    cci: u32,
    replies: VecDeque<Reply>,
    payload: Vec<u8>,
    flags: u32,
    connector: u8,
    next_connector: u8,
    controls: Vec<u64>,
    outgoing: Vec<u8>,
    reads: usize,
    calls: usize,
    fail_at: usize,
    fail_after_control: Option<u8>,
    cancel_complete: bool,
    reset_complete: bool,
    /// CCI bits reported once alongside the next reset completion.
    reset_extra: u32,
}
impl Ppm {
    fn new(replies: Vec<Reply>) -> Self {
        Self {
            version: 0x0200,
            state: State::Idle,
            cci: 0,
            replies: replies.into(),
            payload: Vec::new(),
            flags: 0,
            connector: 0,
            next_connector: 0,
            controls: Vec::new(),
            outgoing: Vec::new(),
            reads: 0,
            calls: 0,
            fail_at: usize::MAX,
            fail_after_control: None,
            cancel_complete: true,
            reset_complete: true,
            reset_extra: 0,
        }
    }
    fn io(&mut self) -> Result<(), TransportError> {
        self.calls += 1;
        if self.calls == self.fail_at {
            Err(TransportError::Io(self.calls as u64))
        } else {
            Ok(())
        }
    }
}
impl Transport for Ppm {
    fn read_version(&mut self) -> Result<u16, TransportError> {
        self.io()?;
        Ok(self.version)
    }
    fn poll_cci(&mut self) -> Result<u32, TransportError> {
        self.io()?;
        self.cci = match self.state {
            State::Idle => u32::from(self.connector) << 1,
            State::Reset if self.reset_complete => {
                RESET_COMPLETE | core::mem::take(&mut self.reset_extra)
            }
            State::Reset => 0,
            State::Command(Wait::Complete) => {
                COMMAND_COMPLETE
                    | self.flags
                    | ((self.payload.len() as u32) << 8)
                    | (u32::from(self.connector) << 1)
            }
            State::Command(Wait::Busy) => BUSY | 0x01ff_ffff,
            State::Command(Wait::Quiet) => 0,
            State::Ack(true) => {
                self.state = State::Ack(false);
                return Ok(self.cci);
            }
            State::Ack(false) => {
                self.state = State::Idle;
                ACK_COMPLETE | (u32::from(self.connector) << 1)
            }
            State::Cancel if self.cancel_complete => CANCEL_COMPLETE | COMMAND_COMPLETE,
            State::Cancel => CANCEL_COMPLETE,
        };
        Ok(self.cci)
    }
    fn read_message_in(&mut self, bytes: &mut [u8]) -> Result<(), TransportError> {
        self.io()?;
        assert!(matches!(self.state, State::Command(Wait::Complete)));
        assert_eq!(self.cci & COMMAND_COMPLETE, COMMAND_COMPLETE);
        bytes.copy_from_slice(&self.payload[..bytes.len()]);
        self.reads += 1;
        Ok(())
    }
    fn write_message_out(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.io()?;
        self.outgoing = bytes.to_vec();
        Ok(())
    }
    fn write_control(&mut self, control: u64) -> Result<(), TransportError> {
        self.io()?;
        self.controls.push(control);
        match control as u8 {
            1 => {
                self.state = State::Reset;
                self.connector = 0;
            }
            2 => {
                assert!(matches!(self.state, State::Command(Wait::Busy)));
                self.state = State::Cancel;
            }
            4 => {
                assert_eq!(control & ACK_COMMAND, ACK_COMMAND);
                if control & ACK_CONNECTOR != 0 {
                    assert_ne!(self.connector, 0);
                    self.connector = self.next_connector;
                    self.next_connector = 0;
                }
                self.state = State::Ack(true);
            }
            _ => {
                assert!(matches!(self.state, State::Idle | State::Reset));
                let reply = self.replies.pop_front().expect("unplanned PPM command");
                assert_eq!(control, reply.command);
                self.payload = reply.bytes;
                self.flags = reply.flags;
                self.state = State::Command(reply.wait);
            }
        }
        if self.fail_after_control == Some(control as u8) {
            return Err(TransportError::Io(0xdead));
        }
        Ok(())
    }
}
#[derive(Clone)]
struct Time(Rc<Cell<u64>>);
impl Timer for Time {
    fn now_us(&self) -> u64 {
        self.0.get()
    }
    fn delay_us(&self, us: u64) {
        self.0.set(self.0.get().wrapping_add(us));
    }
}
fn make_controller(replies: Vec<Reply>) -> Controller<Ppm, Time> {
    Controller::new(Ppm::new(replies), Time(Rc::new(Cell::new(0)))).unwrap()
}
fn port() -> ConnectorNumber {
    ConnectorNumber::new(1).unwrap()
}
fn status() -> [u8; 19] {
    let mut bytes = [0; 19];
    bytes[2] = 0x78;
    bytes[3] = 0x20;
    bytes[10] = 0x40;
    bytes
}
fn initialized() -> Controller<Ppm, Time> {
    let mut cap = [0; 16];
    cap[4] = 0x81;
    cap[5] = 0xff;
    cap[6] = 0x3f;
    let capability = Capability::parse(&cap).unwrap();
    let mut controller = make_controller(vec![
        Reply::new(Command::global(NOTIFY | NOTIFY_BASIC), &[]),
        Reply::new(Command::capability(), &cap),
        Reply::new(
            Command::connector_capability(port()),
            &[0xff, 0xff, 0x0f, 0],
        ),
        Reply::new(Command::connector_status(port()), &status()),
        Reply::new(
            Command::global(NOTIFY | capability.notifications(Version::new(0x0200).unwrap())),
            &[],
        ),
    ]);
    controller.initialize().unwrap();
    controller
}

#[test]
fn initialization_drives_real_commands_and_keeps_wire_observations() {
    let controller = initialized();
    assert!(controller.initialized());
    assert_eq!(controller.generation(), 1);
    assert_eq!(controller.capability().unwrap().reported_connectors, 0x81);
    let snapshot = controller.connectors()[0];
    assert!(snapshot.status.connected());
    assert!(snapshot.status.power_source());
    assert!(snapshot.status.usb_data());
    assert!(snapshot.status.alternate_mode());
    assert_eq!(snapshot.status.orientation_reversed(), Some(true));
    assert_eq!(
        controller
            .transport
            .controls
            .iter()
            .filter(|c| **c as u8 == 4)
            .count(),
        5
    );
    assert!(controller.transport.replies.is_empty());
}
#[test]
fn reset_required_and_stale_reset_completion_cleared_before_new_epoch() {
    let mut controller = make_controller(vec![Reply::new(Command::global(NOTIFY), &[])]);
    assert_eq!(
        controller.execute(Command::current_cam(port()), &mut [0; 1], &[]),
        Err(Error::NeedsReset)
    );
    controller.transport.state = State::Reset;
    controller.reset().unwrap();
    assert_eq!(controller.transport.controls, vec![NOTIFY, RESET]);
    assert_eq!(controller.timer.now_us(), RESET_POLL_US);
}
#[test]
fn reset_completes_on_its_bit_and_resets_again_while_the_ppm_reports_other_work() {
    let mut controller = make_controller(Vec::new());
    controller.transport.reset_extra = BUSY;
    controller.reset().unwrap();
    assert_eq!(controller.transport.controls, vec![RESET, RESET]);
}
#[test]
fn busy_timeout_cancels_acknowledges_and_never_claims_command_success() {
    let mut hanging = Reply::new(Command::current_cam(port()), &[]);
    hanging.wait = Wait::Busy;
    let mut controller = make_controller(vec![
        hanging,
        Reply::new(Command::current_cam(port()), &[7]),
    ]);
    controller.reset().unwrap();
    assert!(matches!(
        controller.execute(Command::current_cam(port()), &mut [0; 1], &[]),
        Err(Error::Cancelled { .. })
    ));
    assert_eq!(
        &controller.transport.controls[2..],
        &[CANCEL, ACK | ACK_COMMAND]
    );
    assert!(controller.fault().is_none());
    let mut result = [0];
    controller
        .execute(Command::current_cam(port()), &mut result, &[])
        .unwrap();
    assert_eq!(result, [7]);
}
#[test]
fn incomplete_cancel_and_quiet_timeouts_require_explicit_reset() {
    for wait in [Wait::Busy, Wait::Quiet] {
        let mut hanging = Reply::new(Command::current_cam(port()), &[]);
        hanging.wait = wait;
        let mut controller = make_controller(vec![hanging]);
        controller.reset().unwrap();
        controller.transport.cancel_complete = false;
        let error = controller
            .execute(Command::current_cam(port()), &mut [0; 1], &[])
            .unwrap_err();
        assert!(matches!(error, Error::Timeout { .. }));
        let calls = controller.transport.calls;
        assert_eq!(
            controller.execute(Command::current_cam(port()), &mut [0; 1], &[]),
            Err(error)
        );
        assert_eq!(calls, controller.transport.calls);
        controller.reset().unwrap();
        assert!(controller.fault().is_none());
        assert_eq!(controller.generation(), 2);
    }
}
#[test]
fn ppm_error_reads_error_status_with_version_correct_connector() {
    for version in [0x0120, 0x0200] {
        let command = Command::alternate_mode(port(), Recipient::Partner, 3);
        let mut failed = Reply::new(command, &[]);
        failed.flags = ERROR;
        let target = if version > 0x0120 {
            port().control()
        } else {
            0
        };
        let mut controller = make_controller(vec![
            failed,
            Reply::new(Command::global(ERROR_STATUS | target), &[0x10, 0x80]),
        ]);
        controller.transport.version = version;
        controller.version = Version::new(version).unwrap();
        controller.reset().unwrap();
        assert!(matches!(
            controller.execute(command, &mut [0; 6], &[]),
            Err(Error::Ppm { status: 0x8010, .. })
        ));
        assert!(controller.fault().is_none());
        assert_eq!(controller.transport.reads, 1);
    }
}
#[test]
fn unsupported_does_not_read_payload_or_poison_the_controller() {
    let mut reply = Reply::new(Command::current_cam(port()), &[9]);
    reply.flags = NOT_SUPPORTED;
    let mut controller = make_controller(vec![reply]);
    controller.reset().unwrap();
    let mut bytes = [0xaa];
    assert!(matches!(
        controller.execute(Command::current_cam(port()), &mut bytes, &[]),
        Err(Error::NotSupported { .. })
    ));
    assert_eq!(bytes, [0xaa]);
    assert_eq!(controller.transport.reads, 0);
    assert!(controller.fault().is_none());
}
#[test]
fn malformed_status_keeps_connector_latched_and_does_not_publish_partial_state() {
    for bytes in [vec![1; 8], vec![1; 20]] {
        let mut controller = initialized();
        let old = controller.connectors()[0];
        controller.transport.connector = 1;
        controller.poll_change().unwrap();
        controller
            .transport
            .replies
            .push_back(Reply::new(Command::connector_status(port()), &bytes));
        assert!(matches!(
            controller.service_change(),
            Err(Error::InvalidResponseLength { .. })
        ));
        assert_eq!(controller.pending_change(), Some(port()));
        assert_eq!(controller.connectors()[0], old);
        assert_eq!(
            controller.transport.controls.last(),
            Some(&(ACK | ACK_COMMAND))
        );
        controller
            .transport
            .replies
            .push_back(Reply::new(Command::connector_status(port()), &status()));
        assert!(controller.service_change().unwrap().is_some());
        assert_eq!(controller.pending_change(), None);
    }
}
#[test]
fn same_connector_relatched_during_ack_is_not_lost() {
    let mut controller = initialized();
    controller.transport.connector = 1;
    controller.transport.next_connector = 1;
    controller.poll_change().unwrap();
    controller
        .transport
        .replies
        .push_back(Reply::new(Command::connector_status(port()), &status()));
    controller.service_change().unwrap();
    assert_eq!(controller.pending_change(), Some(port()));
    assert_eq!(
        controller.transport.controls.last(),
        Some(&(ACK | ACK_COMMAND | ACK_CONNECTOR))
    );
}
#[test]
fn contradictory_connector_and_failed_read_never_look_like_success() {
    let mut controller = initialized();
    controller.observe_notification(2).unwrap();
    assert!(matches!(
        controller.observe_notification(4),
        Err(Error::InvalidConnector {
            number: 2,
            count: 1
        })
    ));
    let mut controller = make_controller(vec![]);
    controller.reset().unwrap();
    assert_eq!(
        controller.observe_notification(u32::MAX),
        Err(Error::InvalidCci(u32::MAX))
    );
    assert!(controller.fault().is_some());
}
#[test]
fn initialization_failure_and_failed_reset_invalidate_public_metadata() {
    let mut controller = initialized();
    controller.transport.reset_complete = false;
    assert!(matches!(
        controller.reset(),
        Err(Error::Timeout {
            phase: Phase::Reset,
            ..
        })
    ));
    assert!(!controller.initialized());
    assert!(controller.capability().is_none());
    assert!(controller.connectors().is_empty());
    let mut controller = make_controller(vec![
        Reply::new(Command::global(NOTIFY | NOTIFY_BASIC), &[]),
        Reply::new(Command::capability(), &[0; 16]),
    ]);
    assert!(controller.initialize().is_err());
    assert!(controller.fault().is_some());
    assert!(!controller.initialized());
}
#[test]
fn transport_failures_at_every_command_io_boundary_block_replay() {
    let command = Command::current_cam(port());
    let mut baseline = make_controller(vec![Reply::new(command, &[7])]);
    baseline.reset().unwrap();
    let first = baseline.transport.calls + 1;
    baseline.execute(command, &mut [0; 1], &[0x55]).unwrap();
    let last = baseline.transport.calls;
    for fail_at in first..=last {
        let mut controller = make_controller(vec![Reply::new(command, &[7])]);
        controller.reset().unwrap();
        controller.transport.fail_at = fail_at;
        let mut output = [0xaa];
        let error = controller
            .execute(command, &mut output, &[0x55])
            .unwrap_err();
        assert!(matches!(error, Error::Transport { .. }));
        assert_eq!(output, [0xaa]);
        let calls = controller.transport.calls;
        assert_eq!(
            controller.execute(command, &mut output, &[0x55]),
            Err(error)
        );
        assert_eq!(calls, controller.transport.calls);
    }
}
#[test]
fn response_and_output_bounds_are_checked_without_exposing_partial_data() {
    let command = Command::current_cam(port());
    let mut controller = make_controller(vec![Reply::new(command, &[7, 8])]);
    controller.reset().unwrap();
    let mut output = [0xaa];
    assert!(matches!(
        controller.execute(command, &mut output, &[]),
        Err(Error::InvalidResponseLength { bytes: 2, .. })
    ));
    assert_eq!(output, [0xaa]);
    assert_eq!(controller.transport.reads, 0);
    let calls = controller.transport.calls;
    assert_eq!(
        controller.execute(command, &mut [0; 256], &[]),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        controller.execute(command, &mut [], &[0; 257]),
        Err(Error::InvalidArgument)
    );
    assert_eq!(calls, controller.transport.calls);
}

#[test]
fn uncertain_publication_keeps_pending_event_and_requires_reset() {
    for fail in [0x12, 4] {
        let mut controller = initialized();
        controller.transport.connector = 1;
        controller.poll_change().unwrap();
        controller
            .transport
            .replies
            .push_back(Reply::new(Command::connector_status(port()), &status()));
        controller.transport.fail_after_control = Some(fail);
        let old = controller.connectors()[0];
        assert!(matches!(
            controller.service_change(),
            Err(Error::Transport { .. })
        ));
        assert_eq!(controller.pending_change(), Some(port()));
        assert_eq!(controller.connectors()[0], old);
        let calls = controller.transport.calls;
        assert!(
            controller
                .execute(Command::current_cam(port()), &mut [0; 1], &[])
                .is_err()
        );
        assert_eq!(controller.transport.calls, calls);
    }
}
#[test]
fn role_command_completion_does_not_manufacture_a_role_transition() {
    let mut controller = initialized();
    let old = controller.connectors()[0];
    for command in [
        Command::request_data_role(port(), DataRole::Device, true),
        Command::request_power_role(port(), PowerRole::Sink, false),
        Command::new_cam(port(), 3, true),
    ] {
        controller
            .transport
            .replies
            .push_back(Reply::new(command, &[]));
        controller.execute(command, &mut [], &[]).unwrap();
        assert_eq!(controller.connectors()[0], old);
    }
    assert_eq!(
        Command::alternate_mode(port(), Recipient::CablePlugOther, 0x12).control(),
        0x12_0103_000c
    );
    assert_eq!(
        Command::pdos(port(), true, true, 5, 4).unwrap().control(),
        0x7_0581_0010
    );
    assert!(Command::pdos(port(), false, false, 0, 0).is_err());
    assert!(Command::pdos(port(), false, false, 0, 5).is_err());
}

#[test]
fn failure_to_read_error_status_is_explicit_and_does_not_recurse() {
    let command = Command::current_cam(port());
    let mut failed = Reply::new(command, &[]);
    failed.flags = ERROR;
    let mut detail = Reply::new(Command::global(ERROR_STATUS | port().control()), &[]);
    detail.flags = ERROR;
    let mut controller = make_controller(vec![failed, detail]);
    controller.reset().unwrap();
    match controller.execute(command, &mut [0; 1], &[]) {
        Err(Error::ErrorStatus { failure, .. }) => {
            assert!(matches!(*failure, Error::PpmRejected { .. }))
        }
        other => panic!("unexpected error-status result {other:?}"),
    }
    assert_eq!(controller.transport.reads, 0);
    assert!(controller.transport.replies.is_empty());
}
/// Runs only with the immutable generated trace from ucsi_oracle.py.
#[test]
#[ignore = "oracle: STELA_UCSI_ORACLE"]
fn unchanged_linux_notifications_and_command_ack_oracle() {
    let path = std::env::var("STELA_UCSI_ORACLE").expect("STELA_UCSI_ORACLE trace path");
    let trace = std::fs::read_to_string(path).unwrap();
    let mut notifications = 0;
    let mut commands = 0;
    for line in trace.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        match fields[0] {
            "N" => {
                let version = u16::from_str_radix(fields[1], 16).unwrap();
                let features = u16::from_str_radix(fields[2], 16).unwrap();
                let expected = u64::from_str_radix(fields[3], 16).unwrap();
                let mut bytes = [0; 16];
                bytes[4] = 1;
                bytes[5..7].copy_from_slice(&features.to_le_bytes());
                assert_eq!(
                    Capability::parse(&bytes)
                        .unwrap()
                        .notifications(Version::new(version).unwrap()),
                    expected,
                    "version {version:x} features {features:x}"
                );
                notifications += 1;
            }
            "C" => {
                let kind: u8 = fields[1].parse().unwrap();
                let acknowledge = fields[2] == "1";
                let expected: i32 = fields[3].parse().unwrap();
                let count: usize = fields[4].parse().unwrap();
                let expected_controls: Vec<_> = fields[5..]
                    .iter()
                    .map(|value| u64::from_str_radix(value, 16).unwrap())
                    .collect();
                assert_eq!(count, expected_controls.len());
                let command = Command::current_cam(port());
                let mut reply = Reply::new(command, &[0x5a; 3]);
                match kind {
                    0 => {}
                    1 => reply.flags = NOT_SUPPORTED,
                    2 => reply.flags = ERROR,
                    3 => reply.wait = Wait::Busy,
                    _ => panic!("unknown oracle scenario"),
                }
                let mut controller = make_controller(vec![reply]);
                controller.reset().unwrap();
                controller.transport.connector = 1;
                controller.pending = Some(port());
                let mut bytes = [0; 4];
                let receipt = controller.run(command, &mut bytes, &[], acknowledge);
                match (expected, receipt) {
                    (3, Ok(receipt)) => {
                        assert_eq!(receipt.bytes, 3);
                        assert_eq!(&bytes[..3], &[0x5a; 3]);
                    }
                    (-95, Err(Error::NotSupported { .. }))
                    | (-5, Err(Error::PpmRejected { .. }))
                    | (-16, Err(Error::Cancelled { .. })) => {}
                    (_, other) => panic!("Linux result {expected}, Stela result {other:?}"),
                }
                assert_eq!(&controller.transport.controls[1..], expected_controls);
                commands += 1;
            }
            _ => panic!("unknown oracle trace record"),
        }
    }
    assert_eq!(notifications, 393216);
    assert_eq!(commands, 8);
}
#[test]
fn suspend_disables_firmware_notifications_and_invalidates_snapshots() {
    let mut controller = initialized();
    controller
        .transport
        .replies
        .push_back(Reply::new(Command::global(NOTIFY), &[]));
    controller.suspend().unwrap();
    assert!(!controller.initialized());
    assert!(controller.connectors().is_empty());
    assert_eq!(controller.capability(), None);
    assert_eq!(
        controller.execute(Command::current_cam(port()), &mut [0; 1], &[]),
        Err(Error::NeedsReset)
    );
    assert_eq!(
        &controller.transport.controls[controller.transport.controls.len() - 2..],
        &[NOTIFY, ACK | ACK_COMMAND]
    );
}
#[test]
fn failed_suspend_keeps_transport_fault_and_retires_old_snapshots() {
    let mut controller = initialized();
    controller
        .transport
        .replies
        .push_back(Reply::new(Command::global(NOTIFY), &[]));
    controller.transport.fail_after_control = Some(NOTIFY as u8);
    assert!(controller.suspend().is_err());
    assert!(!controller.initialized());
    assert!(controller.connectors().is_empty());
    assert!(controller.fault().is_some());
}

#[test]
fn resume_reinitializes_firmware_and_replaces_every_snapshot_generation() {
    let mut controller = initialized();
    let old = controller.connectors()[0];
    controller
        .transport
        .replies
        .push_back(Reply::new(Command::global(NOTIFY), &[]));
    controller.suspend().unwrap();
    let fresh = initialized();
    // Replay the discovery requests against the stateful PPM;
    // firmware status and capability payloads remain supplied by replies.
    let mut cap = [0; 16];
    cap[4] = 1;
    cap[5] = 0xff;
    cap[6] = 0x3f;
    let capability = Capability::parse(&cap).unwrap();
    controller.transport.replies.extend([
        Reply::new(Command::global(NOTIFY | NOTIFY_BASIC), &[]),
        Reply::new(Command::capability(), &cap),
        Reply::new(
            Command::connector_capability(port()),
            &[0xff, 0xff, 0x0f, 0],
        ),
        Reply::new(Command::connector_status(port()), &status()),
        Reply::new(
            Command::global(NOTIFY | capability.notifications(controller.version())),
            &[],
        ),
    ]);
    controller.resume().unwrap();
    assert_eq!(controller.generation(), old.generation + 1);
    assert_eq!(controller.connectors()[0].generation, old.generation + 1);
    assert_eq!(
        controller.connectors()[0].status,
        fresh.connectors()[0].status
    );
    assert!(controller.transport.replies.is_empty());
}
#[test]
fn resume_refreshes_firmware_version_before_publishing_commands() {
    let mut controller = initialized();
    controller
        .transport
        .replies
        .push_back(Reply::new(Command::global(NOTIFY), &[]));
    controller.suspend().unwrap();
    let publications = controller.transport.controls.len();
    controller.transport.version = 0x0400;
    assert_eq!(controller.resume(), Err(Error::UnsupportedVersion(0x0400)));
    assert_eq!(controller.transport.controls.len(), publications);
    assert!(controller.connectors().is_empty());
    assert_eq!(controller.last_completion(), None);
    assert!(controller.fault().is_some());
}

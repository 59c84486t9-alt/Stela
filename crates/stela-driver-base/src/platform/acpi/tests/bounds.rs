//! The interpreter's time bounds: ACPICA's own per-loop, Sleep and Stall
//! bounds through the OSL contract, and the bridge's bound on one call.
use super::*;
use std::time::{Duration, Instant};

/// `AE_AML_LOOP_TIMEOUT`.
const LOOP_TIMEOUT: Error = Error(0x3021);
/// `AE_AML_OPERAND_VALUE`.
const OPERAND_VALUE: Error = Error(0x3004);

/// The fixture namespace with `aml` appended to its DSDT.
fn with(aml: &[u8]) -> (Services, Arc<Counts>) {
    let mut dsdt = include_bytes!("../fixtures/namespace.aml").to_vec();
    dsdt.extend_from_slice(aml);
    let length = dsdt.len() as u32;
    dsdt[4..8].copy_from_slice(&length.to_le_bytes());
    checksum(&mut dsdt, 9);
    fixture_dsdt(dsdt)
}

/// Name (DONE, 5)
const DONE: &[u8] = &[0x08, b'D', b'O', b'N', b'E', 0x0a, 5];

fn done(session: &Session) -> Option<Value<'_>> {
    session
        .handle("\\DONE")
        .unwrap()
        .evaluate(None, &[])
        .unwrap()
}

fn evaluate<'a>(session: &'a Session, path: &str) -> Result<Option<Value<'a>>, Error> {
    session.handle(path).unwrap().evaluate(None, &[])
}

/// A clock that runs a second per read, so ACPICA's 30 s loop bound is
/// reached within 30 reads.
static FAST: AtomicU64 = AtomicU64::new(0);
unsafe extern "C" fn fast_timer(_: *mut c_void) -> u64 {
    FAST.fetch_add(10_000_000, Ordering::SeqCst)
}

#[test]
fn a_while_one_loop_ends_with_loop_timeout_and_the_namespace_goes_on() {
    let _serial = TEST_SERIAL.lock().unwrap();
    // Method (LOOP) { While (One) {} }
    let mut aml = vec![0x14, 9, b'L', b'O', b'O', b'P', 0, 0xa2, 2, 1];
    aml.extend_from_slice(DONE);
    let (mut services, _) = with(&aml);
    services.timer = fast_timer;
    // SAFETY: the serialized fixture's whole provider goes to the session.
    let session = unsafe { Session::start(services, Mode::InterpreterOnly) }.unwrap();
    assert_eq!(evaluate(&session, "\\LOOP"), Err(LOOP_TIMEOUT));
    assert_eq!(done(&session), Some(Value::Integer(5)));
    session.shutdown().unwrap();
}

static SLEPT: AtomicU64 = AtomicU64::new(0);
unsafe extern "C" fn recorded_sleep(_: *mut c_void, ms: u64) {
    SLEPT.fetch_max(ms, Ordering::SeqCst);
}

#[test]
fn a_huge_sleep_lasts_two_seconds_and_a_long_stall_is_refused() {
    let _serial = TEST_SERIAL.lock().unwrap();
    // Method (SLP0) { Sleep (0xFFFFFFFF) Return (One) }
    let mut aml = vec![
        0x14, 15, b'S', b'L', b'P', b'0', 0, 0x5b, 0x22, 0x0c, 0xff, 0xff, 0xff, 0xff, 0xa4, 1,
    ];
    // Method (STL0) { Stall (256) }
    aml.extend_from_slice(&[0x14, 11, b'S', b'T', b'L', b'0', 0, 0x5b, 0x21, 0x0b, 0, 1]);
    aml.extend_from_slice(DONE);
    let (mut services, _) = with(&aml);
    services.sleep = recorded_sleep;
    SLEPT.store(0, Ordering::SeqCst);
    // SAFETY: the serialized fixture's whole provider goes to the session.
    let session = unsafe { Session::start(services, Mode::InterpreterOnly) }.unwrap();
    assert_eq!(evaluate(&session, "\\SLP0"), Ok(Some(Value::Integer(1))));
    // ACPI_MAX_SLEEP, as Linux's interpreter caps it.
    assert_eq!(SLEPT.load(Ordering::SeqCst), 2000);
    assert_eq!(evaluate(&session, "\\STL0"), Err(OPERAND_VALUE));
    assert_eq!(done(&session), Some(Value::Integer(5)));
    session.shutdown().unwrap();
}

#[test]
fn a_wait_forever_ends_at_the_bound_and_names_its_method() {
    let _serial = TEST_SERIAL.lock().unwrap();
    // Event (EVT0)
    let mut aml = vec![0x5b, 0x02, b'E', b'V', b'T', b'0'];
    // Method (WAIT) { Return (Wait (EVT0, 0xFFFF)) }
    aml.extend_from_slice(&[
        0x14, 16, b'W', b'A', b'I', b'T', 0, 0xa4, 0x5b, 0x25, b'E', b'V', b'T', b'0', 0x0b, 0xff,
        0xff,
    ]);
    aml.extend_from_slice(DONE);
    let (services, _) = with(&aml);
    // SAFETY: the serialized fixture's whole provider goes to the session.
    let session = unsafe { Session::start(services, Mode::InterpreterOnly) }.unwrap();
    let began = Instant::now();
    let bound = Bound::begin(100);
    // Wait returns True (nonzero) when it timed out.
    let Ok(Some(Value::Integer(timed_out))) = evaluate(&session, "\\WAIT") else {
        panic!("Wait's result")
    };
    let overrun = bound.end().unwrap_err();
    assert_ne!(timed_out, 0);
    assert!(began.elapsed() < Duration::from_secs(5));
    let at = overrun.at.unwrap();
    assert_eq!(at.method, "\\WAIT");
    assert!(!at.in_loop);
    assert_eq!(done(&session), Some(Value::Integer(5)));
    // SAFETY: between calls, on the interpreter's only thread.
    assert_eq!(unsafe { running() }, None);
    session.shutdown().unwrap();
}

#[test]
fn a_loop_past_the_bound_ends_at_its_next_iteration() {
    let _serial = TEST_SERIAL.lock().unwrap();
    // Method (SPIN) { While (One) { Sleep (1) } }
    let mut aml = vec![
        0x14, 12, b'S', b'P', b'I', b'N', 0, 0xa2, 5, 1, 0x5b, 0x22, 1,
    ];
    // Method (FAST) { Return (Timer) }
    aml.extend_from_slice(&[0x14, 9, b'F', b'A', b'S', b'T', 0, 0xa4, 0x5b, 0x33]);
    aml.extend_from_slice(DONE);
    let (services, _) = with(&aml);
    // SAFETY: the serialized fixture's whole provider goes to the session.
    let session = unsafe { Session::start(services, Mode::InterpreterOnly) }.unwrap();
    let timer = |session: &Session| match evaluate(session, "\\FAST") {
        Ok(Some(Value::Integer(time))) => time,
        other => panic!("Timer: {other:?}"),
    };
    let before = timer(&session);
    let began = Instant::now();
    let bound = Bound::begin(50);
    assert_eq!(evaluate(&session, "\\SPIN"), Err(LOOP_TIMEOUT));
    let overrun = bound.end().unwrap_err();
    // Without the bound the loop would run ACPICA's 30 s.
    assert!(began.elapsed() < Duration::from_secs(5));
    let at = overrun.at.unwrap();
    assert_eq!(at.method, "\\SPIN");
    assert!(at.in_loop);
    assert!(matches!(at.opcode, 0x00a2 | 0x5b22), "{at}");
    // The namespace goes on, with its time still monotonic.
    assert_eq!(done(&session), Some(Value::Integer(5)));
    assert!(timer(&session) > before);
    session.shutdown().unwrap();
}

#[test]
fn a_table_load_that_never_finishes_ends_at_a_bound_begun_before_the_start() {
    let _serial = TEST_SERIAL.lock().unwrap();
    // Module-level code: While (One) { Sleep (1) }
    let (services, counts) = with(&[0xa2, 5, 1, 0x5b, 0x22, 1]);
    let began = Instant::now();
    let bound = Bound::begin(50);
    // SAFETY: the serialized fixture's whole provider goes to the session.
    let session = unsafe { Session::start(services, Mode::InterpreterOnly) };
    let overrun = bound.end().unwrap_err();
    assert!(began.elapsed() < Duration::from_secs(5));
    let at = overrun.at.unwrap();
    assert_eq!(at.method, "\\");
    assert!(at.in_loop);
    drop(session);
    assert!(counts.destroyed.load(Ordering::SeqCst));
}

#[test]
fn locations_name_the_waiting_opcodes() {
    let at = Location {
        method: "\\_SB.PCI0.LPCB.EC0.WAIT".into(),
        opcode: 0x5b22,
        offset: 0x1c,
        in_loop: true,
    };
    assert_eq!(
        std::format!("{}", Overrun { at: Some(at) }),
        "in \\_SB.PCI0.LPCB.EC0.WAIT at AML offset 0x1c, opcode 0x5b22 (Sleep) in a While loop"
    );
    assert_eq!(
        std::format!("{}", Overrun { at: None }),
        "outside any AML method"
    );
}

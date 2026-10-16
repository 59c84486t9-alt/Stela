use crate::{blocks::retirement::ConsumerKey, system::execution::authority::PeExecutionAuthority};

#[test]
fn host_return_cannot_grant_ready_or_retirement_before_requalification() {
    let mut authority = unsafe { PeExecutionAuthority::new_pe() };
    let key = ConsumerKey(());
    let attempt = authority.begin_native(&key).unwrap();
    authority.enter_system(&key, attempt).unwrap();
    authority.suspend_system(&key, attempt).unwrap();
    assert!(!authority.ready());
    assert!(!authority.system_attempt(attempt));
    assert!(authority.check_observation(&key).is_err());
    authority.resume_suspended(&key, attempt).unwrap();
    assert!(!authority.ready());
    assert!(!authority.system_attempt(attempt));
    assert!(authority.check_observation(&key).is_err());
    authority.qualify_wake(&key, attempt).unwrap();
    assert!(authority.system_attempt(attempt));
    authority.start_retirement(&key, attempt).unwrap();
    authority.finish_retirement(&key, attempt, false).unwrap();
    assert!(authority.ready());
}

#[test]
fn stale_wake_attempt_poison_cannot_reopen_entry() {
    let mut authority = unsafe { PeExecutionAuthority::new_pe() };
    let key = ConsumerKey(());
    let attempt = authority.begin_native(&key).unwrap();
    authority.enter_system(&key, attempt).unwrap();
    authority.suspend_system(&key, attempt).unwrap();
    assert!(authority.resume_suspended(&key, attempt + 1).is_err());
    assert!(authority.resume_suspended(&key, attempt).is_err());
    assert!(authority.qualify_wake(&key, attempt).is_err());
    assert!(authority.begin_native(&key).is_err());
}

#[test]
fn retirement_during_wake_requalification_poison_is_sticky() {
    let mut authority = unsafe { PeExecutionAuthority::new_pe() };
    let key = ConsumerKey(());
    let attempt = authority.begin_native(&key).unwrap();
    authority.enter_system(&key, attempt).unwrap();
    authority.suspend_system(&key, attempt).unwrap();
    authority.resume_suspended(&key, attempt).unwrap();
    assert!(authority.start_retirement(&key, attempt).is_err());
    assert!(authority.qualify_wake(&key, attempt).is_err());
    assert!(authority.begin_native(&key).is_err());
}

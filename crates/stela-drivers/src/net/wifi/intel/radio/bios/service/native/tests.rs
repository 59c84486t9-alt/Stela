// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Stela contributors
use super::*;
use crate::firmware::HandoffProvider;
use crate::net::wifi::intel::platform::Stage;

static EMPTY: HandoffProvider<'static> = HandoffProvider::new(None);

fn bios(observations: Observations) -> NativeBios {
    // SAFETY: no session, so nothing is evaluated.
    unsafe { NativeBios::new(None, None, &EMPTY, observations) }
}

#[test]
fn every_request_names_the_method_iwlwifi_evaluates() {
    for (request, name) in [
        (Request::Glai, Some("GLAI")),
        (Request::WideBandwidth, Some("WBEM")),
        (Request::ExternalClock, Some("ECKV")),
        (Request::Country, Some("WRDD")),
        (Request::PowerTable(Variable::Wrds), Some("WRDS")),
        (Request::PowerTable(Variable::Ewrd), Some("EWRD")),
        (Request::PowerTable(Variable::Wgds), Some("WGDS")),
        (Request::PowerTable(Variable::Ppag), Some("PPAG")),
        (Request::PowerTable(Variable::Wtas), Some("WTAS")),
        (Request::Dsm(3), None),
    ] {
        assert_eq!(method(request), Ok(name), "{request:?}");
    }
    assert_eq!(
        method(Request::PowerTable(Variable::Splc)),
        Err(IoError::Unavailable)
    );
}

#[test]
fn evaluated_objects_and_statuses_keep_what_the_parsers_read() {
    assert_eq!(
        object(Value::Package(alloc::vec![
            Value::Integer(2),
            Value::Buffer(alloc::vec![1, 2]),
            Value::String(b"x".to_vec()),
        ])),
        Object::Package(alloc::vec![
            Object::Integer(2),
            Object::Buffer(alloc::vec![1, 2]),
            Object::Other,
        ])
    );
    assert_eq!(status(acpi::NOT_FOUND), IoError::NotFound);
    assert_eq!(status(acpi::LIMIT), IoError::BoundExceeded);
    assert_eq!(status(acpi::Error(0x3003)), IoError::Failed(0x3003));
}

#[test]
fn variables_follow_what_boot_observed_and_no_namespace_is_unavailable() {
    let mut observations = Observations::default();
    observations.set(
        Variable::Wrds,
        Observation::Absent {
            stage: Stage::Probe,
            status: platform::NOT_FOUND,
            reported_bytes: None,
        },
    );
    observations.set(
        Variable::Ewrd,
        Observation::Failed {
            stage: Stage::Read,
            status: 7,
            reported_bytes: None,
        },
    );
    let mut bios = bios(observations);
    assert_eq!(bios.variable(Variable::Wrds), Err(IoError::NotFound));
    assert_eq!(bios.variable(Variable::Ewrd), Err(IoError::Failed(7)));
    assert_eq!(bios.variable(Variable::Wgds), Err(IoError::Unavailable));
    assert_eq!(bios.evaluate(Request::Glai), Err(IoError::Unavailable));
    assert_eq!(bios.dmi_identity(), Err(IoError::Unavailable));
}

#[test]
fn smbios_strings_lose_their_terminator() {
    assert_eq!(
        text(Field::Value(b"Dell Inc.\0")).as_deref(),
        Some("Dell Inc.")
    );
    assert_eq!(text(Field::Absent), None);
    assert_eq!(text(Field::NotObserved), None);
}

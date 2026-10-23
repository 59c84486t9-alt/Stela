// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2017 Intel Deutschland GmbH
// Copyright (C) 2019-2026 Intel Corporation
//! Owned BIOS reads for one real Intel function. Parsing copied observations
//! remains separate from this unsafe platform-service implementation contract.
use super::{GeneralConfiguration, Scalar, ScalarKind};
use crate::net::wifi::intel::{platform::Variable, radio::lari};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Glai,
    WideBandwidth,
    ExternalClock,
    /// Intel DSM GUID f21202bf-8f78-4dc6-a5b3-1f738e285ade, revision 0,
    /// no fourth-argument payload, at the actual function's ACPI handle.
    Dsm(u8),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Object {
    Integer(u64),
    Buffer(Vec<u8>),
    Package(Vec<Object>),
    Other,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoError {
    /// The platform service has not been implemented or cannot be called now.
    /// This is never a BIOS absence and must prevent command publication.
    Unavailable,
    /// A collection bound prevented a complete actual observation.
    BoundExceeded,
    /// Actual qualified lookup/invocation failed, retaining its platform code.
    Failed(u64),
    NotFound,
}
impl IoError {
    fn incomplete(self) -> bool {
        matches!(self, Self::Unavailable | Self::BoundExceeded)
    }
}
/// Actual ACPI and EFI reads, owned independently of copied resource bytes.
/// # Safety
/// Implementors perform real reads at the device/firmware namespace bound by
/// `ColdRadio::begin_lari`, retaining every resource needed for those services.
/// ACPI requests must use that function's real handle (including a genuinely
/// observed missing handle), exact method/GUID/revision and original values.
/// EFI reads use the requested descriptor's exact GUID/name and preserve full
/// returned bytes. NotFound/Failed require an actual attempted qualified read;
/// missing AML/EFI support, invalid lifetime/root mapping or incomplete capture
/// must return Unavailable/BoundExceeded, never pretend the object is absent.
/// Returned objects are bounded to 4096 bytes/256 nodes/depth 4; exceeding that
/// native collection envelope returns BoundExceeded. The provider must remain
/// valid until independently stopped; uncertain owner Drop retains it.
pub unsafe trait BiosIo: 'static {
    fn evaluate(&mut self, request: Request) -> Result<Object, IoError>;
    fn variable(&mut self, variable: Variable) -> Result<Vec<u8>, IoError>;
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Read {
    Acpi(Request, Result<Object, IoError>),
    Uefi(Variable, Result<Vec<u8>, IoError>),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    IncompleteAcpi(Request, IoError),
    IncompleteUefi(Variable, IoError),
}
#[derive(Clone, Copy)]
struct Cache {
    values: [u32; 15],
    valid: u32,
    source: lari::Source,
    revision: u8,
}
pub(crate) struct Session<B: BiosIo> {
    pub(crate) io: B,
    reads: Vec<Read>,
    locked: Option<bool>,
    cache: Option<Cache>,
    external_clock: Option<lari::Observation>,
}
impl<B: BiosIo> Session<B> {
    pub(crate) fn new(io: B) -> Self {
        Self {
            io,
            reads: Vec::new(),
            locked: None,
            cache: None,
            external_clock: None,
        }
    }
    pub(crate) fn reads(&self) -> &[Read] {
        &self.reads
    }
    /// Actual source ECKV selection in this session's original namespace.
    /// Missing services are incomplete observations, not an absent clock.
    pub(crate) fn external_clock(&mut self) -> Result<lari::Observation, Error> {
        if let Some(observation) = self.external_clock {
            return Ok(observation);
        }
        let mut value = None;
        if self.locked()?
            && let Some(raw) = self.uefi(Variable::Eckv)?
            && let Ok(scalar) = Scalar::parse(ScalarKind::ExternalClock, &raw)
        {
            value = Some(lari::Value {
                value: scalar.value(),
                source: lari::Source::Uefi,
                revision: 0,
            });
        }
        if value.is_none()
            && let Some((0, raw)) = self
                .acpi(Request::ExternalClock)?
                .as_ref()
                .and_then(wifi_value)
        {
            value = Some(lari::Value {
                value: raw as u32,
                source: lari::Source::Acpi,
                revision: 0,
            });
        }
        let observation = value.map_or(lari::Observation::Unavailable, lari::Observation::Observed);
        self.external_clock = Some(observation);
        Ok(observation)
    }
    fn acpi(&mut self, request: Request) -> Result<Option<Object>, Error> {
        let result = self.io.evaluate(request);
        self.reads.push(Read::Acpi(request, result.clone()));
        match result {
            Ok(object) => Ok(Some(object)),
            Err(e) if e.incomplete() => Err(Error::IncompleteAcpi(request, e)),
            Err(_) => Ok(None),
        }
    }
    fn uefi(&mut self, variable: Variable) -> Result<Option<Vec<u8>>, Error> {
        let result = self.io.variable(variable);
        self.reads.push(Read::Uefi(variable, result.clone()));
        match result {
            Ok(raw) if raw.len() > 4096 => {
                Err(Error::IncompleteUefi(variable, IoError::BoundExceeded))
            }
            Ok(raw) => Ok(Some(raw)),
            Err(e) if e.incomplete() => Err(Error::IncompleteUefi(variable, e)),
            Err(_) => Ok(None),
        }
    }
    fn locked(&mut self) -> Result<bool, Error> {
        if let Some(locked) = self.locked {
            return Ok(locked);
        }
        let locked = self
            .acpi(Request::Glai)?
            .as_ref()
            .and_then(wifi_value)
            .is_some_and(|(revision, status)| revision == 0 && (1..=2).contains(&status));
        self.locked = Some(locked);
        Ok(locked)
    }
    fn load_uefi(&mut self) -> Result<(), Error> {
        if self.cache.is_some() {
            return Ok(());
        }
        if let Some(raw) = self.uefi(Variable::GeneralConfiguration)?
            && let Ok(table) = GeneralConfiguration::parse(&raw)
        {
            self.cache = Some(Cache {
                values: core::array::from_fn(|i| table.raw_function(i).unwrap()),
                valid: table.source_function_bitmap(),
                source: lari::Source::Uefi,
                revision: 4,
            });
        }
        Ok(())
    }
    fn load_acpi(&mut self) -> Result<(), Error> {
        if self.cache.is_some() {
            return Ok(());
        }
        let mut cache = Cache {
            values: [0; 15],
            valid: 1,
            source: lari::Source::Acpi,
            revision: 0,
        };
        if let Some(query) = self
            .acpi(Request::Dsm(0))?
            .as_ref()
            .and_then(|o| integer(o, 4))
        {
            cache.values[0] = query as u32;
            for index in 1..15u8 {
                if query & (1 << index) == 0 || index == 5 {
                    continue;
                }
                let size = if index <= 2 { 1 } else { 4 };
                if let Some(value) = self
                    .acpi(Request::Dsm(index))?
                    .as_ref()
                    .and_then(|o| integer(o, size))
                {
                    // Source truncates integer objects to u32, even for the
                    // expected one-byte functions; only buffer copies use size.
                    cache.values[usize::from(index)] = value as u32;
                    cache.valid |= 1 << index;
                }
            }
        }
        self.cache = Some(cache);
        Ok(())
    }
    pub(crate) fn observe(&mut self, input: lari::Input) -> Result<lari::Observation, Error> {
        let locked = self.locked()?;
        let result = match input {
            lari::Input::Dsm(index) => {
                if locked {
                    self.load_uefi()?;
                }
                // Linux shares this cache between both paths: a valid UEFI
                // cache with a missing function cannot trigger fresh AML reads.
                self.load_acpi()?;
                let cache = self.cache.as_ref().unwrap();
                (index < 15 && index != 5 && cache.valid & (1 << index) != 0).then(|| lari::Value {
                    value: cache.values[usize::from(index)],
                    source: cache.source,
                    revision: cache.revision,
                })
            }
            lari::Input::WideBandwidth => {
                let mut value = None;
                if locked
                    && let Some(raw) = self.uefi(Variable::Wbem)?
                    && let Ok(scalar) = Scalar::parse(ScalarKind::WideBandwidth, &raw)
                {
                    value = Some(lari::Value {
                        value: scalar.value(),
                        source: lari::Source::Uefi,
                        revision: 0,
                    });
                }
                if value.is_none()
                    && let Some((0, raw)) = self
                        .acpi(Request::WideBandwidth)?
                        .as_ref()
                        .and_then(wifi_value)
                {
                    value = Some(lari::Value {
                        value: (raw as u32) & 3,
                        source: lari::Source::Acpi,
                        revision: 0,
                    });
                }
                value
            }
        };
        Ok(result.map_or(lari::Observation::Unavailable, lari::Observation::Observed))
    }
}
fn integer(object: &Object, size: usize) -> Option<u64> {
    match object {
        Object::Integer(value) => Some(*value),
        Object::Buffer(raw) => {
            let mut bytes = [0; 8];
            let length = size.min(raw.len());
            bytes[..length].copy_from_slice(&raw[..length]);
            Some(u64::from_le_bytes(bytes))
        }
        _ => None,
    }
}
fn wifi_value(object: &Object) -> Option<(i32, u64)> {
    let Object::Package(outer) = object else {
        return None;
    };
    if outer.len() < 2 {
        return None;
    }
    let Object::Integer(revision) = outer[0] else {
        return None;
    };
    for object in &outer[1..] {
        if let Object::Package(inner) = object
            && inner.len() == 2
            && inner[0] == Object::Integer(7)
        {
            return match inner[1] {
                Object::Integer(value) => Some((revision as i32, value)),
                _ => None,
            };
        }
    }
    None
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::vec;
    struct Model {
        scenario: u32,
    }
    fn pattern(scenario: u32, index: u32) -> u32 {
        0x9e3779b9u32.wrapping_mul(index + 1) ^ scenario
    }
    fn package(revision: u64, value: u64, domain: u64) -> Object {
        Object::Package(vec![
            Object::Integer(revision),
            Object::Package(vec![Object::Integer(domain), Object::Integer(value)]),
        ])
    }
    fn buffer(value: u64, length: usize) -> Object {
        Object::Buffer(value.to_le_bytes()[..length].to_vec())
    }
    // SAFETY: exact modeled raw namespace calls; this grants no real platform
    // attachment. The unchanged source oracle separately consumes these inputs.
    unsafe impl BiosIo for Model {
        fn evaluate(&mut self, request: Request) -> Result<Object, IoError> {
            let s = self.scenario;
            Ok(match request {
                Request::ExternalClock => panic!("ECKV is outside the historical LARI model"),
                Request::Glai => {
                    let mode = s % 8;
                    if mode == 0 {
                        return Err(IoError::NotFound);
                    }
                    package(
                        if mode == 5 {
                            1
                        } else if mode == 7 {
                            0x100000000
                        } else {
                            0
                        },
                        [0, 0, 1, 2, 3, 1, 1, 1][mode as usize],
                        if mode == 6 { 8 } else { 7 },
                    )
                }
                Request::WideBandwidth => {
                    let mode = (s / 512) % 8;
                    if mode == 0 {
                        return Err(IoError::NotFound);
                    }
                    package(
                        if mode == 1 { 1 } else { 0 },
                        u64::from(pattern(s, 31)),
                        if mode == 2 { 8 } else { 7 },
                    )
                }
                Request::Dsm(0) => match (s / 64) % 8 {
                    0 => return Err(IoError::NotFound),
                    1 => Object::Other,
                    2 => Object::Integer(0),
                    3 => Object::Integer(0x7fff),
                    4 => buffer(0x7fff, 1),
                    5 => buffer(0x7fff, 3),
                    6 => buffer(0x7fff, 8),
                    _ => Object::Integer(0xffffffff00007fff),
                },
                Request::Dsm(index) => {
                    let kind = (u32::from(index) + (s / 512) % 8) % 6;
                    let value = 0x1234567800000000 | u64::from(pattern(s, u32::from(index)));
                    match kind {
                        0 => return Err(IoError::NotFound),
                        1 => Object::Other,
                        2 => Object::Integer(value),
                        3 => buffer(value, 0),
                        4 => buffer(value, 1),
                        _ => buffer(value, 8),
                    }
                }
            })
        }
        fn variable(&mut self, variable: Variable) -> Result<Vec<u8>, IoError> {
            let dsm = variable == Variable::GeneralConfiguration;
            assert!(dsm || variable == Variable::Wbem);
            let mode = (self.scenario / if dsm { 8 } else { 512 }) % 8;
            if mode == 0 {
                return Err(IoError::NotFound);
            }
            let mut raw = vec![if dsm {
                if mode == 2 { 3 } else { 4 }
            } else if mode == 2 {
                1
            } else {
                0
            }];
            if dsm {
                let masks = [0, 0, 0, 0, 0x7fff, 0xaaaa, 0x5555, 1 << 4];
                for f in 0..32 {
                    raw.extend(
                        if f == 0 {
                            masks[mode as usize]
                        } else {
                            pattern(self.scenario, f)
                        }
                        .to_le_bytes(),
                    );
                }
            } else {
                raw.extend(pattern(self.scenario, 30).to_le_bytes());
            }
            if mode == 1 {
                raw.pop();
            }
            Ok(raw)
        }
    }
    fn call_ids(reads: &[Read]) -> Vec<u64> {
        reads
            .iter()
            .map(|read| match read {
                Read::Acpi(Request::Glai, _) => 1,
                Read::Acpi(Request::WideBandwidth, _) => 2,
                Read::Acpi(Request::ExternalClock, _) => panic!("unexpected historical ECKV read"),
                Read::Acpi(Request::Dsm(index), _) => 10 + u64::from(*index),
                Read::Uefi(Variable::GeneralConfiguration, _) => 3,
                Read::Uefi(Variable::Wbem, _) => 4,
                _ => panic!("unexpected call"),
            })
            .collect()
    }
    #[test]
    fn locked_uefi_cache_never_fills_missing_functions_from_copied_acpi() {
        let mut session = Session::new(Model {
            scenario: 2 + 3 * 8 + 3 * 64,
        }); // locked, valid UEFI with empty bitmap
        assert_eq!(
            session.observe(lari::Input::Dsm(4)).unwrap(),
            lari::Observation::Unavailable
        );
        assert_eq!(
            session.observe(lari::Input::Dsm(1)).unwrap(),
            lari::Observation::Unavailable
        );
        assert_eq!(session.reads().len(), 2);
        assert!(matches!(session.reads()[0], Read::Acpi(Request::Glai, _)));
        assert!(matches!(
            session.reads()[1],
            Read::Uefi(Variable::GeneralConfiguration, _)
        ));
        // Invalid UEFI falls back to actual AML once, and reuses its original
        // values/source/revision through later UEFI getter attempts.
        let mut session = Session::new(Model {
            scenario: 2 + 2 * 8 + 3 * 64,
        });
        let value = session.observe(lari::Input::Dsm(2)).unwrap();
        assert!(matches!(
            value,
            lari::Observation::Observed(lari::Value {
                source: lari::Source::Acpi,
                revision: 0,
                ..
            })
        ));
        let reads = session.reads().len();
        assert_eq!(session.observe(lari::Input::Dsm(2)).unwrap(), value);
        assert_eq!(session.reads().len(), reads);
    }
    struct Missing {
        request: Option<Request>,
        variable: Option<Variable>,
        error: IoError,
    }
    // SAFETY: modeled incomplete/failed service responses, never physical authority.
    unsafe impl BiosIo for Missing {
        fn evaluate(&mut self, request: Request) -> Result<Object, IoError> {
            if self.request == Some(request) {
                return Err(self.error);
            }
            Model {
                scenario: 2 + 4 * 8 + 3 * 64,
            }
            .evaluate(request)
        }
        fn variable(&mut self, variable: Variable) -> Result<Vec<u8>, IoError> {
            if self.variable == Some(variable) {
                return Err(self.error);
            }
            Model {
                scenario: 2 + 4 * 8 + 3 * 64,
            }
            .variable(variable)
        }
    }
    #[test]
    fn incomplete_service_or_collection_never_becomes_policy_absence() {
        for error in [IoError::Unavailable, IoError::BoundExceeded] {
            for (request, variable, input) in [
                (Some(Request::Glai), None, lari::Input::Dsm(4)),
                (
                    None,
                    Some(Variable::GeneralConfiguration),
                    lari::Input::Dsm(4),
                ),
                (None, Some(Variable::Wbem), lari::Input::WideBandwidth),
                (
                    Some(Request::WideBandwidth),
                    None,
                    lari::Input::WideBandwidth,
                ),
            ] {
                let mut session = Session::new(Missing {
                    request,
                    variable,
                    error,
                });
                assert!(session.observe(input).is_err());
                assert!(session.reads().iter().any(|r| match r {
                    Read::Acpi(_, Err(e)) | Read::Uefi(_, Err(e)) => *e == error,
                    _ => false,
                }));
            }
        }
        let mut session = Session::new(Missing {
            request: Some(Request::Glai),
            variable: None,
            error: IoError::Failed(0x1234),
        });
        // Actual source failure defaults GLAI to unlocked and can exhaust the
        // genuine ACPI path. The exact failure remains in the original reads.
        session.observe(lari::Input::Dsm(4)).unwrap();
        assert_eq!(
            session.reads()[0],
            Read::Acpi(Request::Glai, Err(IoError::Failed(0x1234)))
        );
        assert!(session.reads().iter().all(|r| !matches!(r, Read::Uefi(..))));
    }
    #[test]
    #[ignore = "requires fresh unchanged Linux BIOS source-selection/cache oracle"]
    fn unchanged_linux_bios_selection_cache_and_complete_raw_call_order() {
        use sha2::{Digest, Sha256};
        let bytes =
            std::fs::read(std::env::var("STELA_IWLWIFI_BIOS_SELECTION_ORACLE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&bytes)),
            "8e819022cad9cfa05aced446905120f3075b060bb0aabe6a1da8d4c8130269c7"
        );
        let mut current = None;
        let mut session = None;
        let mut rows = 0;
        for line in core::str::from_utf8(&bytes).unwrap().lines() {
            let f: Vec<u64> = line
                .split_whitespace()
                .map(|s| s.parse().unwrap())
                .collect();
            assert_eq!(f.len(), 9 + f[7] as usize);
            if current != Some(f[0]) {
                current = Some(f[0]);
                session = Some(Session::new(Model {
                    scenario: f[0] as u32,
                }));
            }
            let session = session.as_mut().unwrap();
            let input = if f[1] == 99 {
                lari::Input::WideBandwidth
            } else {
                lari::Input::Dsm(f[1] as u8)
            };
            let result = session.observe(input).unwrap();
            match result {
                lari::Observation::Observed(value) => {
                    assert_eq!(f[2], 1, "{line}");
                    assert_eq!(u64::from(value.value), f[3], "{line}");
                    assert_eq!(
                        match value.source {
                            lari::Source::Acpi => 1,
                            lari::Source::Uefi => 2,
                        },
                        f[4],
                        "{line}"
                    );
                    assert_eq!(u64::from(value.revision), f[5], "{line}");
                }
                lari::Observation::Unavailable => assert_eq!(f[2], 0, "{line}"),
                lari::Observation::NotObserved => panic!("unobserved {line}"),
            }
            assert_eq!(session.locked.unwrap(), f[6] > 0, "{line}");
            assert_eq!(session.reads().len() as u64, f[7], "{line}");
            let ids = call_ids(session.reads());
            assert_eq!(ids, f[9..], "{line}");
            assert_eq!(
                ids.iter()
                    .fold(0u64, |h, id| h.wrapping_mul(131).wrapping_add(*id)),
                f[8],
                "{line}"
            );
            rows += 1;
        }
        assert_eq!(rows, 65536);
        assert_eq!(current, Some(4095));
    }
    struct ClockModel(u8);
    // SAFETY: exact raw modeled ECKV namespaces; no native platform authority.
    unsafe impl BiosIo for ClockModel {
        fn evaluate(&mut self, request: Request) -> Result<Object, IoError> {
            match request {
                Request::Glai => Ok(package(0, u64::from(self.0 != 4), 7)),
                Request::ExternalClock if self.0 == 5 => Err(IoError::Unavailable),
                Request::ExternalClock if self.0 == 6 => Err(IoError::NotFound),
                Request::ExternalClock => {
                    Ok(package(if self.0 == 7 { 1 } else { 0 }, 0x1_0000_0001, 7))
                }
                _ => panic!("unrequested clock source"),
            }
        }
        fn variable(&mut self, variable: Variable) -> Result<Vec<u8>, IoError> {
            assert_eq!(variable, Variable::Eckv);
            match self.0 {
                0 => Ok(vec![0, 2, 0, 0, 0]),
                1 => Ok(vec![99, 2, 0, 0, 0]),
                2 => Err(IoError::Unavailable),
                3 => Err(IoError::BoundExceeded),
                _ => Err(IoError::NotFound),
            }
        }
    }
    #[test]
    fn clock_selection_requires_actual_source_and_preserves_fallback_and_truncation() {
        for scenario in 0..8 {
            let mut session = Session::new(ClockModel(scenario));
            let result = session.external_clock();
            if scenario == 2 || scenario == 3 {
                assert_eq!(
                    result,
                    Err(Error::IncompleteUefi(
                        Variable::Eckv,
                        if scenario == 2 {
                            IoError::Unavailable
                        } else {
                            IoError::BoundExceeded
                        }
                    ))
                );
                assert_eq!(session.reads().len(), 2);
            } else if scenario == 5 {
                assert_eq!(
                    result,
                    Err(Error::IncompleteAcpi(
                        Request::ExternalClock,
                        IoError::Unavailable
                    ))
                );
            } else {
                let expected = match scenario {
                    0 => lari::Observation::Observed(lari::Value {
                        value: 2,
                        source: lari::Source::Uefi,
                        revision: 0,
                    }),
                    6 | 7 => lari::Observation::Unavailable,
                    _ => lari::Observation::Observed(lari::Value {
                        value: 1,
                        source: lari::Source::Acpi,
                        revision: 0,
                    }),
                };
                assert_eq!(result, Ok(expected));
                let count = session.reads().len();
                assert_eq!(session.external_clock(), Ok(expected));
                assert_eq!(session.reads().len(), count);
                assert_eq!(count, if scenario == 0 || scenario == 4 { 2 } else { 3 });
                if scenario == 4 {
                    assert!(matches!(
                        session.reads()[1],
                        Read::Acpi(Request::ExternalClock, _)
                    ));
                }
            }
        }
    }
}

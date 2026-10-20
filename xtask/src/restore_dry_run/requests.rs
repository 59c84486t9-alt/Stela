//! The request matrix: every message restored can send this host, with the
//! Arguments variants each data type takes, in protocol order, and how the
//! answer is judged. Evidence for each row is in
//! `docs/research/restore-dry-run.md`.
use super::context::{Ctx, SMALL, info, strings};
use super::image4;
use anyhow::{Context as _, Result, anyhow, ensure};
use plist::{Dictionary, Value};
use std::collections::BTreeSet;
use stela_runtime::restore::route::Route;

/// Data types restored 26A434 lists in its host compatibility table
/// (R `0x2457e0..0x2459f8`, `is_host_compatible`).
pub const RESTORED_DATA_TYPES: [&str; 67] = [
    "SystemImageData",
    "SystemImageRootHash",
    "SystemImageCanonicalMetadata",
    "ProvisioningData",
    "FDRTrustData",
    "FDRMemoryCommit",
    "NORData",
    "FUDData",
    "EANData",
    "PersonalizedData",
    "RootData",
    "OverlayRootDataCount",
    "KernelCache",
    "RootTicket",
    "BuildIdentityDict",
    "BuildIdentityDictV2",
    "BasebandBootData",
    "BasebandStackData",
    "BasebandData",
    "DiagData",
    "BasebandUpdaterOutputData",
    "GrapeFWData",
    "HPMFWData",
    "SsoServiceTicket",
    "S3EOverride",
    "USBCOverride",
    "USBCFWData",
    "OpalFWData",
    "StockholmPostflight",
    "FirmwareUpdaterPreflight",
    "DeviceRestoreInfoPreflight",
    "ReceiptManifest",
    "FirmwareUpdaterData",
    "FirmwareUpdaterDataV2",
    "FirmwareUpdaterDataV3",
    "RamdiskFWData",
    "PeppyFWData",
    "NitrogenFWData",
    "RecoveryOSImage",
    "RecoveryOSASRImage",
    "RecoveryOSIBEC",
    "RecoveryOSKernelCache",
    "RecoveryOSDeviceTree",
    "RecoveryOSAppleLogo",
    "RecoveryOSStaticTrustCache",
    "RecoveryOSRootTicketData",
    "RecoveryOSFileAssetImage",
    "FileData",
    "FileDataDone",
    "RecoveryOSVersionData",
    "RecoveryOSOverlayRootDataCount",
    "RecoveryOSIBootFWFilesImages",
    "SourceBootObjectV3",
    "SourceBootObjectV4",
    "SourceBootObjectV5",
    "RecoveryOSLocalPolicy",
    "PersonalizedBootObjectV3",
    "OverlayRootDataForKey",
    "OverlayRootDataForKeyIndex",
    "HostSystemTime",
    "BootabilityBundle",
    "BootabilityBundleV2",
    "AuthInstallCACert",
    "RestoreLocalPolicy",
    "UpdateVolumeOverlayRootDataCount",
    "MessageUseStreamedImageFile",
    "URLAsset",
];
/// Message types in the same table (R `0x245750..0x2457d8`).
pub const RESTORED_MESSAGE_TYPES: [&str; 18] = [
    "MsgType",
    "ProgressMsg",
    "StatusMsg",
    "CheckpointMsg",
    "DataRequestMsg",
    "PreviousRestoreLogMsg",
    "BBUpdateStatusMsg",
    "ProvisioningStatusMsg",
    "ProvisioningAck",
    "ProvisioningInfo",
    "FDRSubmit",
    "ReceivedFinalStatusMsg",
    "RestoredCrash",
    "AsyncDataRequestMsg",
    "AsyncWait",
    "RestoreAttestation",
    "CrashLog",
    "RestoreProtocol",
];
/// Data types restored 26A434 requests from its own code (an xref other
/// than the compatibility table), with one request site each.
pub const REQUESTED: [(&str, &str); 26] = [
    ("BasebandUpdaterOutputData", "0x2ea50"),
    ("BootabilityBundle", "0x32c94"),
    ("BuildIdentityDict", "0x2dcb8"),
    ("DeviceRestoreInfoPreflight", "0x2e41c"),
    ("EANData", "0x36e7c"),
    ("FDRMemoryCommit", "0x7251c"),
    ("FDRTrustData", "0x70e50"),
    ("FUDData", "0x2c878"),
    ("FirmwareUpdaterData", "0x14dbc0"),
    ("FirmwareUpdaterDataV3", "0x2f05c"),
    ("FirmwareUpdaterPreflight", "0x2e390"),
    ("HostSystemTime", "0x315dc"),
    ("NORData", "0x36514"),
    ("PersonalizedBootObjectV3", "0x2e644"),
    ("PersonalizedData", "0x2e6ec"),
    ("RamdiskFWData", "0x2d94c"),
    ("ReceiptManifest", "0x36a80"),
    ("RecoveryOSASRImage", "0x22e60"),
    ("RecoveryOSLocalPolicy", "0x2b9f8"),
    ("RecoveryOSRootTicketData", "0x2d0b4"),
    ("RecoveryOSVersionData", "0x10da8"),
    ("RootTicket", "0x2d144"),
    ("S3EOverride", "0x14de70"),
    ("SourceBootObjectV4", "0x14de60"),
    ("SsoServiceTicket", "0x26db8"),
    ("SystemImageData", "0x26bf4"),
];

pub enum Transfer {
    /// A reply frame on the control stream.
    Control,
    /// FileData frames and FileDataDone on a DataPort.
    File,
    /// Raw bytes on a DataPort until the host closes it.
    Raw,
    /// ASR on a DataPort; `prefix` bounds the payload read.
    Asr,
    /// No reply; the session continues.
    Event,
    /// StatusMsg, answered by ReceivedFinalStatusMsg.
    Final,
}

pub enum Outcome {
    Reply(Value),
    Bytes(Vec<u8>),
    Asr(String),
    Event,
    Refused(String),
}

pub enum Verdict {
    Ok(String),
    Refused(String),
    Failed(String),
    Skipped(String),
}

pub type Check = Box<dyn Fn(&mut Ctx, &Outcome) -> Verdict>;

pub struct Step {
    pub label: String,
    pub message: Dictionary,
    pub transfer: Transfer,
    pub check: Check,
}

pub fn dict<const N: usize>(pairs: [(&str, Value); N]) -> Dictionary {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}
fn s(v: &str) -> Value {
    Value::String(v.into())
}
fn data(kind: &str, args: Option<Dictionary>) -> Dictionary {
    let mut m = dict([("MsgType", s("DataRequestMsg")), ("DataType", s(kind))]);
    if let Some(a) = args {
        m.insert("Arguments".into(), a.into());
    }
    m
}
fn describe(args: &Option<Dictionary>) -> String {
    let Some(a) = args else {
        return String::new();
    };
    let fields: Vec<_> = a
        .iter()
        .map(|(k, v)| match v {
            Value::String(t) => format!("{k}={t}"),
            Value::Boolean(b) => format!("{k}={b}"),
            Value::Integer(i) => format!("{k}={i}"),
            Value::Data(d) => format!("{k}=<{} bytes>", d.len()),
            Value::Array(x) => format!("{k}=[{}]", x.len()),
            Value::Dictionary(_) => format!("{k}={{..}}"),
            _ => k.clone(),
        })
        .collect();
    format!(" {}", fields.join(" "))
}
fn step(kind: &str, args: Option<Dictionary>, transfer: Transfer, check: Check) -> Step {
    Step {
        label: format!("{kind}{}", describe(&args)),
        message: data(kind, args),
        transfer,
        check,
    }
}

/// Unwrap a reply dictionary or fail the verdict.
fn reply(o: &Outcome) -> Result<&Dictionary, Verdict> {
    match o {
        Outcome::Reply(Value::Dictionary(d)) => Ok(d),
        Outcome::Reply(_) => Err(Verdict::Failed("reply is not a dictionary".into())),
        Outcome::Refused(r) => Err(Verdict::Failed(format!("refused: {r}"))),
        _ => Err(Verdict::Failed("no control reply".into())),
    }
}
fn verdict(r: Result<String>) -> Verdict {
    match r {
        Ok(s) => Verdict::Ok(s),
        Err(e) => Verdict::Failed(format!("{e:#}")),
    }
}
/// A request whose correct outcome is a refusal by name.
fn refusal(why: &'static str) -> Check {
    Box::new(move |_, o| match o {
        Outcome::Refused(r) => Verdict::Refused(format!("{why} ({r})")),
        _ => Verdict::Failed(format!("answered; expected a refusal: {why}")),
    })
}
/// The route's allow-list: a request outside it refuses by name.
fn routed(route: Route, kind: &'static str, check: Check) -> Check {
    if route.allows(kind) {
        return check;
    }
    Box::new(move |_, o| match o {
        Outcome::Refused(r) if r.contains("firmware option study") => {
            Verdict::Refused(format!("outside the study route ({r})"))
        }
        Outcome::Refused(r) => Verdict::Failed(format!("refused for another reason: {r}")),
        _ => Verdict::Failed("answered a request outside the study route".into()),
    })
}
/// An answer that may only refuse when no valid answer exists in the IPSW:
/// `possible` says whether one does, and why not.
fn oracle(
    possible: impl Fn(&mut Ctx) -> Result<String> + 'static,
    answered: impl Fn(&mut Ctx, &Outcome) -> Result<String> + 'static,
) -> Check {
    Box::new(move |ctx, o| match o {
        Outcome::Refused(r) => match possible(ctx) {
            Ok(how) => Verdict::Failed(format!("refused ({r}), but {how}")),
            Err(why) => Verdict::Refused(format!("{why:#} ({r})")),
        },
        _ => verdict(answered(ctx, o)),
    })
}

/// Messages restored reports and the host only records.
pub fn events() -> Vec<Step> {
    let checkpoint = dict([
        ("MsgType", s("CheckpointMsg")),
        ("CHECKPOINT_ID", Value::Integer(1621.into())),
        ("CHECKPOINT_NAME", s("is_host_compatible")),
        ("CHECKPOINT_RESULT", Value::Integer(0.into())),
        ("CHECKPOINT_COMPLETE", Value::Boolean(true)),
    ]);
    let weights = dict([
        ("weight_count", Value::Integer(98.into())),
        (
            "operation_ids",
            Value::Dictionary(dict([("id_12", Value::Integer(12.into()))])),
        ),
        (
            "operation_weights",
            Value::Dictionary(dict([("id_12", Value::Integer(300.into()))])),
        ),
        ("operation_progresses", Value::Dictionary(Dictionary::new())),
    ]);
    let mut out = vec![
        ("CheckpointMsg is_host_compatible".to_string(), checkpoint),
        (
            "ProgressMsg Operation=30 Progress=-1 OperationWeights".into(),
            dict([
                ("MsgType", s("ProgressMsg")),
                ("Operation", Value::Integer(30.into())),
                ("Progress", Value::Integer((-1i64).into())),
                ("OperationWeights", Value::Dictionary(weights)),
            ]),
        ),
        (
            "ProgressMsg Operation=14 Progress=57".into(),
            dict([
                ("MsgType", s("ProgressMsg")),
                ("Operation", Value::Integer(14.into())),
                ("Progress", Value::Integer(57.into())),
            ]),
        ),
        (
            "PreviousRestoreLogMsg".into(),
            dict([
                ("MsgType", s("PreviousRestoreLogMsg")),
                ("PreviousRestoreLog", s("dry run")),
            ]),
        ),
    ];
    for kind in [
        "RestoredCrash",
        "CrashLog",
        "AsyncWait",
        "FDRSubmit",
        "RestoreProtocol",
    ] {
        out.push((kind.to_string(), dict([("MsgType", s(kind))])));
    }
    out.into_iter()
        .map(|(label, message)| Step {
            label,
            message,
            transfer: Transfer::Event,
            check: Box::new(|_, o| match o {
                Outcome::Event => Verdict::Ok("recorded; the session continues".into()),
                Outcome::Refused(r) => Verdict::Failed(format!("refused: {r}")),
                _ => Verdict::Failed("unexpected reply".into()),
            }),
        })
        .collect()
}

/// Data requests the host answers, in the order restored makes them.
pub fn answers(route: Route, ctx: &Ctx) -> Vec<Step> {
    let mut out = vec![];
    out.push(step(
        "HostSystemTime",
        None,
        Transfer::Control,
        routed(
            route,
            "HostSystemTime",
            Box::new(|_, o| {
                let d = match reply(o) {
                    Ok(d) => d,
                    Err(v) => return v,
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                verdict(
                    d.get("SetHostTimeOnDevice")
                        .and_then(Value::as_unsigned_integer)
                        .ok_or_else(|| anyhow!("no integer SetHostTimeOnDevice"))
                        .and_then(|t| {
                            ensure!(t.abs_diff(now) <= 30, "host time {t} is not now ({now})");
                            Ok(format!("SetHostTimeOnDevice={t}"))
                        }),
                )
            }),
        ),
    ));
    let mut async_time = data("HostSystemTime", None);
    async_time.insert("MsgType".into(), s("AsyncDataRequestMsg"));
    async_time.insert(
        "AsyncContextUUID".into(),
        s("15C1EDB0-A414-43F8-9AF6-4E28F13D8956"),
    );
    out.push(Step {
        label: "HostSystemTime (AsyncDataRequestMsg)".into(),
        message: async_time,
        transfer: Transfer::Control,
        check: routed(
            route,
            "HostSystemTime",
            Box::new(|_, o| match reply(o) {
                Ok(d) if d.contains_key("SetHostTimeOnDevice") => {
                    Verdict::Ok("answered as the synchronous request".into())
                }
                Ok(_) => Verdict::Failed("no SetHostTimeOnDevice".into()),
                Err(v) => v,
            }),
        ),
    });
    for (kind, recovery) in [("RootTicket", false), ("RecoveryOSRootTicketData", true)] {
        let args = recovery.then(|| dict([("IsRecoveryOS", Value::Boolean(true))]));
        let kind_static: &'static str = kind;
        out.push(step(
            kind,
            args,
            Transfer::Control,
            routed(
                route,
                kind_static,
                Box::new(|ctx, o| {
                    let d = match reply(o) {
                        Ok(d) => d,
                        Err(v) => return v,
                    };
                    verdict((|| {
                        let t = d
                            .get("RootTicketData")
                            .and_then(Value::as_data)
                            .ok_or_else(|| anyhow!("no RootTicketData data (R 0x2d0e4)"))?;
                        let global = ctx.global.as_ref().ok_or_else(|| anyhow!("no apticket"))?;
                        ensure!(t == global.bytes, "RootTicketData is not {}", global.path);
                        let m = image4::im4m(t)?;
                        ctx.check_ticket(&m, None)?;
                        let names = ctx.components(false);
                        let covered = names
                            .iter()
                            .filter(|n| {
                                ctx.digest(n, false)
                                    .is_some_and(|d| !m.tags_with(&d).is_empty())
                            })
                            .count();
                        Ok(format!(
                            "{} unchanged; covers {covered} of {} components",
                            global.path,
                            names.len()
                        ))
                    })())
                }),
            ),
        ));
    }
    // load_sep_os (R 0x2d514) asks for NORData with FlashVersion1 = "1".
    out.push(step(
        "NORData",
        Some(dict([("FlashVersion1", s("1"))])),
        Transfer::Control,
        if route.flashes_nor() {
            oracle(
                |ctx| {
                    let llb = ctx.covered("LLB", false)?;
                    ensure!(llb.ticket.is_some(), "the global ticket does not cover LLB");
                    Ok("LLB is covered".into())
                },
                |_, o| {
                    let d = match o {
                        Outcome::Reply(Value::Dictionary(d)) => d,
                        _ => return Err(anyhow!("no reply")),
                    };
                    ensure!(d.contains_key("LlbImageData"), "no LlbImageData");
                    Ok("NOR firmware set".into())
                },
            )
        } else {
            Box::new(|ctx, o| {
                let d = match reply(o) {
                    Ok(d) => d,
                    Err(v) => return v,
                };
                verdict((|| {
                    let keys: BTreeSet<_> = d.keys().map(String::as_str).collect();
                    ensure!(
                        keys.iter()
                            .all(|k| ["RestoreSEPImageData", "SEPPatchImageData"].contains(k)),
                        "unexpected NORData keys {keys:?}"
                    );
                    let sep = d
                        .get("RestoreSEPImageData")
                        .and_then(Value::as_data)
                        .ok_or_else(|| anyhow!("no RestoreSEPImageData (R 0x2d514)"))?;
                    let want = ctx.covered("RestoreSEP", false)?;
                    // seputil `--restore -` decodes one IMG4 (seputil
                    // 0x100012f54); no ticket covers `rsep`, so it has no
                    // manifest.
                    let payload = super::image4::img4_payload_alone(sep)
                        .context("RestoreSEPImageData is not an IMG4 of one IM4P")?;
                    ensure!(
                        payload == want.image.as_slice(),
                        "RestoreSEPImageData is not the IM4P typed {} that the RestoreSEP digest covers",
                        want.kind
                    );
                    Ok(format!(
                        "RestoreSEPImageData: IMG4 of the IM4P typed {}, SHA-384 = RestoreSEP Digest, no manifest",
                        want.kind
                    ))
                })())
            })
        },
    ));
    // copy_build_identity_for_variant_type (R 0x2dc54..0x2dcb8).
    let variant = info(&ctx.identity, "Variant").unwrap_or_default();
    for (recovery, variant) in [
        (false, variant.clone()),
        (true, "macOS Customer".to_string()),
    ] {
        let args = dict([
            ("IsRecoveryOS", Value::Boolean(recovery)),
            ("BuildIdentityApplyOverrides", Value::Boolean(false)),
            ("Variant", s(&variant)),
        ]);
        out.push(step(
            "BuildIdentityDict",
            Some(args),
            Transfer::Control,
            routed(
                route,
                "BuildIdentityDict",
                Box::new(move |ctx, o| {
                    let d = match reply(o) {
                        Ok(d) => d,
                        Err(v) => return v,
                    };
                    verdict((|| {
                        let got = d
                            .get("BuildIdentityDict")
                            .and_then(Value::as_dictionary)
                            .ok_or_else(|| {
                                anyhow!("no BuildIdentityDict dictionary (R 0x2dd20)")
                            })?;
                        let want = ctx
                            .chosen(recovery)
                            .ok_or_else(|| anyhow!("no macOS Customer identity for this board"))?;
                        ensure!(
                            got == want,
                            "BuildIdentityDict differs from the BuildManifest identity"
                        );
                        d.get("Variant")
                            .and_then(Value::as_string)
                            .ok_or_else(|| anyhow!("no Variant string (R 0x2dd48)"))?;
                        Ok(format!(
                            "identity {} unchanged",
                            info(got, "Variant").unwrap_or_default()
                        ))
                    })())
                }),
            ),
        ));
    }
    out.push(step(
        "ReceiptManifest",
        None,
        Transfer::Control,
        routed(
            route,
            "ReceiptManifest",
            Box::new(|ctx, o| {
                let d = match reply(o) {
                    Ok(d) => d,
                    Err(v) => return v,
                };
                verdict((|| {
                    ensure!(
                        d.get("ReceiptManifest") == ctx.identity.get("Manifest"),
                        "ReceiptManifest is not the identity's Manifest"
                    );
                    Ok("the identity's Manifest".into())
                })())
            }),
        ),
    ));
    out.push(step(
        "FDRTrustData",
        None,
        Transfer::Control,
        routed(
            route,
            "FDRTrustData",
            Box::new(|_, o| match reply(o) {
                Ok(d) if d.is_empty() => Verdict::Ok(
                    "empty, as the public host; restored logs the absent trust data and continues (R 0x70ecc)"
                        .into(),
                ),
                Ok(d) => Verdict::Ok(format!("{} keys", d.len())),
                Err(v) => v,
            }),
        ),
    ));
    out
}

/// SourceBootObjectV4 and PersonalizedBootObjectV3 over a DataPort, for each
/// special name and each component (MSUBootObjectCopier, 14 call sites).
pub fn boot_objects(route: Route, ctx: &Ctx) -> Vec<Step> {
    let mut out = vec![];
    let class = info(&ctx.identity, "DeviceClass").unwrap_or_default();
    let macos = info(&ctx.identity, "MacOSVariant").unwrap_or_default();
    let erase = info(&ctx.identity, "Variant").unwrap_or_default();
    let globals: Vec<(Dictionary, Option<String>)> = vec![
        (
            dict([("ImageName", s("__GlobalManifest__"))]),
            Some(format!(
                "Firmware/Manifests/restore/{macos}/apticket.{class}.im4m"
            )),
        ),
        (
            dict([
                ("ImageName", s("__GlobalManifest__")),
                ("Variant", s(&macos)),
            ]),
            Some(format!(
                "Firmware/Manifests/restore/{macos}/apticket.{class}.im4m"
            )),
        ),
        (
            dict([
                ("ImageName", s("__GlobalManifest__")),
                ("Variant", s(&erase)),
            ]),
            Some(format!(
                "Firmware/Manifests/restore/{erase}/apticket.{class}.im4m"
            )),
        ),
        (
            dict([
                ("ImageName", s("__GlobalManifest__")),
                ("Variant", s(&erase)),
                ("GlobalManifestPrefix", s("centauri/centauri")),
                ("GlobalManifestSuffix", s(".insecure")),
                ("GlobalManifestOptional", Value::Boolean(true)),
            ]),
            Some(format!(
                "Firmware/Manifests/restore/{erase}/centauri/centauri.{class}.insecure.im4m"
            )),
        ),
        (
            dict([("ImageName", s("__RestoreVersion__"))]),
            Some("RestoreVersion.plist".into()),
        ),
        (
            dict([("ImageName", s("__SystemVersion__"))]),
            Some("SystemVersion.plist".into()),
        ),
    ];
    for (args, path) in globals {
        let path = path.unwrap();
        out.push(step(
            "SourceBootObjectV4",
            Some(args),
            Transfer::File,
            routed(route, "SourceBootObjectV4", source_check(path)),
        ));
    }
    // V5 is answered as V4; restored 26A434 names it only in its table.
    if let Some(path) = ctx.path("iBoot", false) {
        out.push(step(
            "SourceBootObjectV5",
            Some(dict([("ImageName", s("iBoot"))])),
            Transfer::File,
            routed(route, "SourceBootObjectV5", source_check(path)),
        ));
    }
    for recovery in [false, true] {
        for name in ctx.components(recovery) {
            let Some(path) = ctx.path(&name, recovery) else {
                continue;
            };
            // The recovery identity's rows that name another file.
            if recovery && ctx.path(&name, false).as_deref() == Some(path.as_str()) {
                continue;
            }
            let mut args = dict([("ImageName", s(&name))]);
            if recovery {
                args.insert("IsRecoveryOS".into(), Value::Boolean(true));
            }
            let size = ctx.member_size(&path).unwrap_or(0);
            if size > SMALL && !ctx.full {
                let label = format!("SourceBootObjectV4{}", describe(&Some(args)));
                out.push(Step {
                    label,
                    message: Dictionary::new(),
                    transfer: Transfer::Event,
                    check: Box::new(move |_, _| {
                        Verdict::Skipped(format!("{path}: {size} bytes; --full streams it"))
                    }),
                });
                continue;
            }
            out.push(step(
                "SourceBootObjectV4",
                Some(args.clone()),
                Transfer::File,
                routed(route, "SourceBootObjectV4", source_check(path.clone())),
            ));
            if recovery {
                continue;
            }
            let n = name.clone();
            let m = name.clone();
            out.push(step(
                "PersonalizedBootObjectV3",
                Some(args),
                Transfer::File,
                routed(
                    route,
                    "PersonalizedBootObjectV3",
                    oracle(
                        move |ctx| personalizable(ctx, &n),
                        move |ctx, o| match o {
                            Outcome::Bytes(b) => ctx.check_img4(&m, false, b),
                            _ => Err(anyhow!("no FileData")),
                        },
                    ),
                ),
            ));
        }
    }
    out
}

/// Whether Image4 would accept a global-ticket IMG4 of `name`.
fn personalizable(ctx: &mut Ctx, name: &str) -> Result<String> {
    let c = ctx.covered(name, false)?;
    let ticket = c
        .ticket
        .ok_or_else(|| anyhow!("no global ticket entry covers {name} ({})", c.kind))?;
    Ok(format!(
        "the {ticket} covers {name} as {}{}",
        c.kind,
        if c.retyped { " (retyped)" } else { "" }
    ))
}

fn source_check(path: String) -> Check {
    let p = path.clone();
    oracle(
        move |ctx| {
            ensure!(ctx.member_size(&p).is_some(), "{p} is not in the IPSW");
            if ctx.inventory.member(&p).is_none() {
                return Ok(format!(
                    "{p} is in the IPSW, absent from the payload inventory"
                ));
            }
            Ok(format!("{p} is in the IPSW and the inventory"))
        },
        move |ctx, o| {
            let Outcome::Bytes(b) = o else {
                return Err(anyhow!("no FileData"));
            };
            let want = ctx.member(&path)?;
            ensure!(
                b.as_slice() == want.as_slice(),
                "{} bytes differ from {path} ({} bytes)",
                b.len(),
                want.len()
            );
            Ok(format!("{path}, {} bytes unchanged", b.len()))
        },
    )
}

/// The manifest-flag image requests: FUDData, PersonalizedData, EANData.
pub fn images(route: Route, ctx: &Ctx) -> Vec<Step> {
    let mut out = vec![];
    let names = ctx.components(false);
    let mut flags = BTreeSet::new();
    for n in &names {
        if let Some(i) = ctx
            .component(n, false)
            .and_then(|c| c.get("Info"))
            .and_then(Value::as_dictionary)
        {
            for (k, v) in i {
                if k.starts_with("Is") && v.as_boolean() == Some(true) {
                    flags.insert(k.clone());
                }
            }
        }
    }
    let flagged = |flag: &str| -> Vec<String> {
        names
            .iter()
            .filter(|n| ctx.flag(n, flag))
            .cloned()
            .collect()
    };
    // FUDData (copy_fud_data_for_type, R 0x2c878).
    let fud = flagged("IsFUDFirmware");
    out.push(list_step(
        route,
        "FUDData",
        dict([("FUDImageList", Value::Boolean(true))]),
        "FUDImageList",
        fud.clone(),
    ));
    for name in &fud {
        out.push(image_step(
            route,
            "FUDData",
            dict([("ImageName", s(name))]),
            "FUDImageData",
            name,
        ));
    }
    out.push(all_step(
        route,
        "FUDData",
        Dictionary::new(),
        "FUDImageData",
        fud,
    ));
    // PersonalizedData by ImageType (R 0x2e6ec, 0x36e84).
    for flag in &flags {
        if flag == "IsFUDFirmware" {
            continue;
        }
        let members = flagged(flag);
        out.push(list_step(
            route,
            "PersonalizedData",
            dict([("ImageType", s(flag)), ("ImageList", Value::Boolean(true))]),
            "ImageList",
            members.clone(),
        ));
        for name in &members {
            out.push(image_step(
                route,
                "PersonalizedData",
                dict([("ImageType", s(flag)), ("ImageName", s(name))]),
                "ImageData",
                name,
            ));
        }
        out.push(all_step(
            route,
            "PersonalizedData",
            dict([("ImageType", s(flag))]),
            "ImageData",
            members,
        ));
    }
    // EANData (copy_ibfw_ean, R 0x36e7c): the iBoot EAN images.
    let ean = flagged("IsiBootEANFirmware");
    for args in [
        dict([("EANImageList", Value::Boolean(true))]),
        Dictionary::new(),
    ] {
        let ean = ean.clone();
        out.push(step(
            "EANData",
            Some(args),
            Transfer::Control,
            routed(
                route,
                "EANData",
                oracle(
                    move |ctx| {
                        for n in &ean {
                            personalizable(ctx, n)?;
                        }
                        Ok("the global ticket covers every EAN image".into())
                    },
                    |_, _| {
                        Err(anyhow!(
                            "answered EANData, which this host does not implement"
                        ))
                    },
                ),
            ),
        ));
    }
    out
}

fn list_step(
    route: Route,
    kind: &'static str,
    args: Dictionary,
    key: &'static str,
    want: Vec<String>,
) -> Step {
    step(
        kind,
        Some(args),
        Transfer::Control,
        routed(
            route,
            kind,
            Box::new(move |_, o| {
                let d = match reply(o) {
                    Ok(d) => d,
                    Err(v) => return v,
                };
                let got = strings(d.get(key));
                let want: BTreeSet<_> = want.iter().cloned().collect();
                match got {
                    Some(g) if g == want => Verdict::Ok(format!("{key}: {} names", g.len())),
                    Some(g) => Verdict::Failed(format!("{key} {g:?}, manifest flags {want:?}")),
                    None => Verdict::Failed(format!("no {key} array")),
                }
            }),
        ),
    )
}

fn image_step(
    route: Route,
    kind: &'static str,
    args: Dictionary,
    key: &'static str,
    name: &str,
) -> Step {
    let (n, m) = (name.to_string(), name.to_string());
    step(
        kind,
        Some(args),
        Transfer::Control,
        routed(
            route,
            kind,
            oracle(
                move |ctx| personalizable(ctx, &n),
                move |ctx, o| {
                    let Outcome::Reply(Value::Dictionary(d)) = o else {
                        return Err(anyhow!("no reply"));
                    };
                    ensure!(
                        d.get("ImageName").and_then(Value::as_string) == Some(m.as_str()),
                        "ImageName is not echoed"
                    );
                    let b = d
                        .get(key)
                        .and_then(Value::as_data)
                        .ok_or_else(|| anyhow!("no {key} data"))?;
                    ctx.check_img4(&m, false, b)
                },
            ),
        ),
    )
}

fn all_step(
    route: Route,
    kind: &'static str,
    args: Dictionary,
    key: &'static str,
    names: Vec<String>,
) -> Step {
    let checked = names.clone();
    step(
        kind,
        Some(args),
        Transfer::Control,
        routed(
            route,
            kind,
            oracle(
                move |ctx| {
                    ensure!(!names.is_empty(), "no component carries the flag");
                    let mut bytes = 0;
                    for n in &names {
                        personalizable(ctx, n)?;
                        bytes += ctx.covered(n, false)?.image.len();
                    }
                    ensure!(
                        bytes <= 8 << 20,
                        "the {} images total {bytes} bytes, over the 8 MiB reply bound",
                        names.len()
                    );
                    Ok("every image is covered".into())
                },
                move |ctx, o| {
                    let Outcome::Reply(Value::Dictionary(d)) = o else {
                        return Err(anyhow!("no reply"));
                    };
                    let images = d
                        .get(key)
                        .and_then(Value::as_dictionary)
                        .ok_or_else(|| anyhow!("no {key} dictionary"))?;
                    for n in &checked {
                        let b = images
                            .get(n)
                            .and_then(Value::as_data)
                            .ok_or_else(|| anyhow!("{key} lacks {n}"))?;
                        ctx.check_img4(n, false, b)?;
                    }
                    Ok(format!("{} images, each covered", checked.len()))
                },
            ),
        ),
    )
}

/// Firmware updaters, the system volume objects, the HTTP proxies, the
/// recovery policy and the transfers on their own DataPorts.
pub fn others(route: Route, tss: bool, ctx: &Ctx) -> Vec<Step> {
    let mut out = vec![];
    let cryptex = dict([
        ("MessageArgUpdaterName", s("Cryptex1")),
        ("MessageArgType", s("FirmwareResponseData")),
        (
            "DeviceGeneratedRequest",
            Value::Dictionary(dict([("@Cryptex1,Ticket", Value::Boolean(true))])),
        ),
        (
            "DeviceGeneratedTags",
            Value::Dictionary(dict([(
                "ResponseTags",
                Value::Array(vec![s("Cryptex1,Ticket")]),
            )])),
        ),
    ]);
    out.push(step(
        "FirmwareUpdaterData",
        Some(cryptex),
        Transfer::Control,
        routed(
            route,
            "FirmwareUpdaterData",
            Box::new(|ctx, o| {
                let d = match reply(o) {
                    Ok(d) => d,
                    Err(v) => return v,
                };
                verdict((|| {
                    let t = d
                        .get("FirmwareResponseData")
                        .and_then(Value::as_dictionary)
                        .and_then(|r| r.get("Cryptex1,Ticket"))
                        .and_then(Value::as_data)
                        .ok_or_else(|| anyhow!("no FirmwareResponseData Cryptex1,Ticket"))?;
                    let c = ctx
                        .cryptex
                        .as_ref()
                        .ok_or_else(|| anyhow!("no cryptex1 apticket"))?;
                    ensure!(t == c.bytes, "Cryptex1,Ticket is not {}", c.path);
                    let m = image4::im4m(t)?;
                    ctx.check_ticket(&m, None)?;
                    Ok(format!("{} unchanged", c.path))
                })())
            }),
        ),
    ));
    // The updaters restored names at R 0x2f05c and 0x14dbc0.
    for updater in [
        "SE",
        "Savage",
        "Veridian",
        "AppleTCON",
        "Orion",
        "Madea",
        "Canary",
        "Timer",
    ] {
        out.push(step(
            "FirmwareUpdaterData",
            Some(dict([
                ("MessageArgUpdaterName", s(updater)),
                ("MessageArgType", s("FirmwareResponseData")),
                (
                    "DeviceGeneratedRequest",
                    Value::Dictionary(Dictionary::new()),
                ),
            ])),
            Transfer::Control,
            routed(
                route,
                "FirmwareUpdaterData",
                refusal("updater tickets need a personalized TSS response"),
            ),
        ));
    }
    for kind in [
        "FirmwareUpdaterDataV3",
        "FirmwareUpdaterPreflight",
        "DeviceRestoreInfoPreflight",
    ] {
        out.push(step(
            kind,
            Some(dict([
                ("MessageArgUpdaterName", s("SE")),
                ("MessageArgType", s("FirmwareResponsePreflight")),
            ])),
            Transfer::Control,
            refusal("updater-specific semantics are not implemented"),
        ));
    }
    out.push(step(
        "SystemImageRootHash",
        None,
        Transfer::Control,
        routed(
            route,
            "SystemImageRootHash",
            oracle(
                |ctx| personalizable(ctx, "SystemVolume"),
                |ctx, o| {
                    let Outcome::Reply(Value::Dictionary(d)) = o else {
                        return Err(anyhow!("no reply"));
                    };
                    let b = d
                        .get("SystemImageRootHashFile")
                        .and_then(Value::as_data)
                        .ok_or_else(|| anyhow!("no SystemImageRootHashFile"))?;
                    Ok(format!(
                        "{}; restored 26A434 names it only in its compatibility table",
                        ctx.check_img4("SystemVolume", false, b)?
                    ))
                },
            ),
        ),
    ));
    out.push(step(
        "SystemImageCanonicalMetadata",
        None,
        Transfer::Control,
        routed(
            route,
            "SystemImageCanonicalMetadata",
            oracle(
                |ctx| {
                    let p = ctx
                        .path("Ap,SystemVolumeCanonicalMetadata", false)
                        .ok_or_else(|| anyhow!("no canonical metadata component"))?;
                    ensure!(ctx.member_size(&p).is_some(), "{p} is not in the IPSW");
                    Ok(format!("{p} is in the IPSW"))
                },
                |ctx, o| {
                    let Outcome::Reply(Value::Dictionary(d)) = o else {
                        return Err(anyhow!("no reply"));
                    };
                    let b = d
                        .get("SystemImageCanonicalMetadataFile")
                        .and_then(Value::as_data)
                        .ok_or_else(|| anyhow!("no SystemImageCanonicalMetadataFile"))?;
                    let p = ctx
                        .path("Ap,SystemVolumeCanonicalMetadata", false)
                        .ok_or_else(|| anyhow!("no canonical metadata component"))?;
                    ensure!(*ctx.member(&p)? == b, "{p} differs from the IPSW member");
                    Ok(format!(
                        "{p} unchanged, {} bytes; restored 26A434 names it only in its compatibility table",
                        b.len()
                    ))
                },
            ),
        ),
    ));
    // URLAsset: the system-image content-key GET. When the inventory carries
    // the offline recipient keys, restored's exact `fcs-key-url` request is
    // answered with the PEM; otherwise, and for an unknown URL, it refuses.
    if let Some(key) = ctx.inventory.aea_keys.first() {
        let url = key.url.clone();
        let pem = key.key_pem.clone().into_bytes();
        let member = key.member.clone();
        out.push(step(
            "URLAsset",
            Some(dict([("RequestMethod", s("GET")), ("RequestURL", s(&url))])),
            Transfer::Control,
            routed(
                route,
                "URLAsset",
                Box::new(move |_, o| {
                    let Outcome::Reply(Value::Dictionary(d)) = o else {
                        return Verdict::Failed("no reply".into());
                    };
                    match d.get("ResponseBody").and_then(Value::as_data) {
                        Some(body) if body == pem.as_slice() => Verdict::Ok(format!(
                            "the recipient key for {member} ({} bytes), offline",
                            body.len()
                        )),
                        _ => Verdict::Failed("ResponseBody is not the recorded key".into()),
                    }
                }),
            ),
        ));
    }
    out.push(step(
        "URLAsset",
        Some(dict([
            ("RequestMethod", s("GET")),
            ("RequestURL", s("https://example.invalid/asset")),
        ])),
        Transfer::Control,
        routed(
            route,
            "URLAsset",
            refusal("no prefetched HTTP response is staged for these exact Arguments"),
        ),
    ));
    out.push(step(
        "StreamedImageDecryptionKey",
        Some(dict([
            ("RequestMethod", s("POST")),
            ("RequestURL", s("http://127.0.0.1:9")),
            (
                "RequestAdditionalHeaders",
                Value::Dictionary(Dictionary::new()),
            ),
            ("RequestBody", Value::Data(vec![0; 16])),
        ])),
        Transfer::Control,
        routed(
            route,
            "StreamedImageDecryptionKey",
            refusal("no prefetched HTTP response is staged for these exact Arguments"),
        ),
    ));
    let policy = dict([
        ("Ap,NextStageIM4MHash", Value::Data(vec![1; 48])),
        ("Ap,RecoveryOSPolicyNonceHash", Value::Data(vec![2; 48])),
        ("Ap,VolumeUUID", s("15C1EDB0-A414-43F8-9AF6-4E28F13D8956")),
    ]);
    out.push(step(
        "RecoveryOSLocalPolicy",
        Some(policy),
        Transfer::Control,
        routed(
            route,
            "RecoveryOSLocalPolicy",
            if tss {
                Box::new(|ctx, o| {
                    let d = match reply(o) {
                        Ok(d) => d,
                        Err(v) => return v,
                    };
                    verdict(super::tss::check_policy(ctx, d))
                })
            } else {
                refusal("the recoveryOS LocalPolicy needs Apple's signing service (--tss)")
            },
        ),
    ));
    out.push(step(
        "BootabilityBundle",
        None,
        Transfer::Raw,
        routed(
            route,
            "BootabilityBundle",
            oracle(
                |ctx| {
                    let n = ctx
                        .zip
                        .keys()
                        .filter(|k| k.starts_with("BootabilityBundle/Restore/Bootability/"))
                        .count();
                    ensure!(n > 0, "the IPSW has no BootabilityBundle");
                    let missing = ctx
                        .zip
                        .keys()
                        .filter(|k| {
                            k.starts_with("BootabilityBundle/Restore/") && !k.ends_with('/')
                        })
                        .filter(|k| ctx.inventory.member(k).is_none())
                        .count();
                    Ok(format!(
                        "the IPSW has {n} Bootability entries ({missing} files absent from the payload inventory)"
                    ))
                },
                |ctx, o| match o {
                    Outcome::Bytes(b) => super::cpio::check(ctx, b),
                    _ => Err(anyhow!("no raw transfer")),
                },
            ),
        ),
    ));
    for kind in ["SystemImageData", "RecoveryOSASRImage"] {
        out.push(Step {
            label: format!("{kind} WillSendImageVerificationProgress=true"),
            message: data(
                kind,
                Some(dict([(
                    "WillSendImageVerificationProgress",
                    Value::Boolean(true),
                )])),
            ),
            transfer: Transfer::Asr,
            check: routed(
                route,
                if kind == "SystemImageData" {
                    "SystemImageData"
                } else {
                    "RecoveryOSASRImage"
                },
                Box::new(|_, o| match o {
                    Outcome::Asr(s) => Verdict::Ok(s.clone()),
                    Outcome::Refused(r) => Verdict::Failed(format!("refused: {r}")),
                    _ => Verdict::Failed("no ASR exchange".into()),
                }),
            ),
        });
    }
    out
}

/// Every advertised data type without a row above, and the messages the
/// host refuses: each must refuse by name.
pub fn refusals(advertised: &BTreeSet<String>, covered: &BTreeSet<String>) -> Vec<Step> {
    let mut out = vec![];
    for kind in advertised.difference(covered) {
        if [
            "FileData",
            "FileDataDone",
            "DataType",
            "MessageUseStreamedImageFile",
        ]
        .contains(&kind.as_str())
        {
            continue;
        }
        let requested = REQUESTED.iter().find(|(k, _)| k == kind).map(|(_, at)| *at);
        let why: &'static str = match requested {
            Some(_) => "restored requests it; this host has no answer",
            None => "advertised vocabulary; this host has no answer",
        };
        let at = requested.map(|a| format!(" (R {a})")).unwrap_or_default();
        out.push(Step {
            label: format!("{kind}{at}"),
            message: data(kind, Some(Dictionary::new())),
            transfer: Transfer::Control,
            check: refusal(why),
        });
    }
    out.push(step(
        "UnadvertisedDataType",
        None,
        Transfer::Control,
        refusal("not in the host's vocabulary"),
    ));
    for (label, message, why) in [
        (
            "BBUpdateStatusMsg",
            dict([("MsgType", s("BBUpdateStatusMsg"))]),
            "J473 has no baseband",
        ),
        (
            "ProvisioningInfo",
            dict([("MsgType", s("ProvisioningInfo"))]),
            "no factory provisioning",
        ),
        (
            "ProvisioningAck",
            dict([("MsgType", s("ProvisioningAck"))]),
            "no factory provisioning",
        ),
        (
            "ProvisioningStatusMsg",
            dict([("MsgType", s("ProvisioningStatusMsg"))]),
            "no factory provisioning",
        ),
        (
            "UnknownMsg",
            dict([("MsgType", s("UnknownMsg"))]),
            "not a restored message type",
        ),
        (
            "StatusMsg Status=0 AMRError=-1",
            dict([
                ("MsgType", s("StatusMsg")),
                ("Status", Value::Integer(0.into())),
                ("AMRError", Value::Integer((-1i64).into())),
            ]),
            "the device reports failure",
        ),
    ] {
        out.push(Step {
            label: label.into(),
            message,
            transfer: Transfer::Control,
            check: refusal(why),
        });
    }
    out
}
pub fn attestation() -> Step {
    Step {
        label: "RestoreAttestation".into(),
        message: dict([("MsgType", s("RestoreAttestation"))]),
        transfer: Transfer::Control,
        check: Box::new(|_, o| match reply(o) {
            Ok(d) if d.get("RestoreShouldAttest") == Some(&Value::Boolean(false)) => {
                Verdict::Ok("RestoreShouldAttest=false (R 0x34d94)".into())
            }
            Ok(_) => Verdict::Failed("no RestoreShouldAttest=false".into()),
            Err(v) => v,
        }),
    }
}

pub fn final_status() -> Step {
    Step {
        label: "StatusMsg Status=0".into(),
        message: dict([
            ("MsgType", s("StatusMsg")),
            ("Status", Value::Integer(0.into())),
        ]),
        transfer: Transfer::Final,
        check: Box::new(|_, o| match reply(o) {
            Ok(d)
                if d.get("MsgType").and_then(Value::as_string)
                    == Some("ReceivedFinalStatusMsg") =>
            {
                Verdict::Ok("ReceivedFinalStatusMsg; the host closed the session".into())
            }
            Ok(_) => Verdict::Failed("final acknowledgement is not ReceivedFinalStatusMsg".into()),
            Err(v) => v,
        }),
    }
}

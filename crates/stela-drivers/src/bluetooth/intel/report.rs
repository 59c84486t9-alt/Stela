// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2015 Intel Corporation
//! Owned native-consumer evidence. Only metadata is copied from Catalog images;
//! actual stage identities and receipts are moved from the bounded initializer.
use super::{
    ControllerIdentity, DsbrReport, FirmwareEvidence, FirmwareReceipt, Report, StageObservation,
};
use alloc::{boxed::Box, vec::Vec};

/// Upload provenance is distinct from an observed already-running image whose
/// source, configuration history and signature authentication remain unknown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnedFirmwareEvidence {
    Uploaded {
        firmware: Box<FirmwareReceipt>,
        configuration: Box<FirmwareReceipt>,
    },
    MultiStage {
        firmware: Vec<FirmwareReceipt>,
        configuration: Box<FirmwareReceipt>,
    },
    RunningUnknown,
}
/// Initialization observations retained beyond provider/catalog lifetime. This
/// contains no firmware buffers and is not a current transport/radio state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedReport {
    pub before: ControllerIdentity,
    pub after: ControllerIdentity,
    pub evidence: OwnedFirmwareEvidence,
    pub boot_notification: Option<[u8; 6]>,
    pub address: [u8; 6],
    pub dsbr: DsbrReport,
    pub stages: Vec<StageObservation>,
}
impl From<Report<'_>> for OwnedReport {
    fn from(report: Report<'_>) -> Self {
        let evidence = match report.evidence {
            FirmwareEvidence::Uploaded {
                firmware,
                configuration,
            } => OwnedFirmwareEvidence::Uploaded {
                firmware: Box::new(firmware.into()),
                configuration: Box::new(configuration.into()),
            },
            FirmwareEvidence::MultiStage {
                firmware,
                configuration,
            } => OwnedFirmwareEvidence::MultiStage {
                firmware: firmware.into_iter().map(Into::into).collect(),
                configuration: Box::new(configuration.into()),
            },
            FirmwareEvidence::RunningUnknown => OwnedFirmwareEvidence::RunningUnknown,
        };
        Self {
            before: report.before,
            after: report.after,
            evidence,
            boot_notification: report.boot_notification,
            address: report.address,
            dsbr: report.dsbr,
            stages: report.stages,
        }
    }
}

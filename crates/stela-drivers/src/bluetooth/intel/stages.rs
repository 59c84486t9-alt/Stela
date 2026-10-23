// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2015 Intel Corporation
//! Bounded secure boot stages, adapted from pinned btintel_bootloader_setup_tlv.
//! IML inherits only named prior-observed ROM inputs after the same hardware's
//! genuine boot event and matching image/version. No FW_ID is guessed before IML.
use super::*;

struct Prepared<'p> {
    image: Image<'p>,
    configuration: Option<Image<'p>>,
    sfi: firmware::Sfi<'p>,
    address: [u8; 6],
    intermediate: bool,
    inherited: Vec<InheritedField>,
}
impl<B: CommandIo> Engine<'_, B> {
    pub(super) fn run<'p>(&mut self, provider: &'p dyn Provider) -> Result<Report<'p>> {
        let before = self.identity(&[0xff])?;
        if before.is_operational() {
            return self.observe_running(before);
        }
        self.hci.intel_mode(true)?;
        let mut stages = Vec::new();
        let mut pending = before.clone();
        match self.upload_stages(provider, before, &mut stages, &mut pending) {
            Ok(report) => Ok(report),
            Err(cause) if !stages.is_empty() => Err(Error::Stages {
                pending: Box::new(pending),
                completed: stages,
                cause: Box::new(cause),
            }),
            Err(e) => Err(e),
        }
    }
    fn prepare<'p>(
        &mut self,
        provider: &'p dyn Provider,
        before: &ControllerIdentity,
        initial: Option<&TlvIdentity>,
    ) -> Result<Prepared<'p>> {
        let (
            hardware,
            revision,
            sfi_name,
            ddc_name,
            minimum,
            address,
            engine,
            intermediate,
            inherited,
        ) = match before {
            ControllerIdentity::Legacy(i) => {
                let boot = BootParameters::parse(&self.command(READ_BOOT_PARAMS, &[])?)?;
                (
                    i.hardware_label(),
                    i.revision_label(&boot),
                    i.filename(&boot, "sfi"),
                    i.filename(&boot, "ddc"),
                    boot.minimum_build,
                    boot.address,
                    None,
                    false,
                    Vec::new(),
                )
            }
            ControllerIdentity::Tlv(i) => {
                let boot = i.boot_requirements(initial)?;
                (
                    i.hardware_label(),
                    initial.map_or_else(|| i.revision_label(), |old| i.iml_revision_label(old)),
                    i.filename("sfi"),
                    i.filename("ddc"),
                    boot.minimum,
                    boot.address,
                    Some(boot.engine),
                    i.hardware_variant() >= 0x1e && i.image_type == 1,
                    boot.inherited,
                )
            }
        };
        let target = match before {
            ControllerIdentity::Legacy(i) => i.target(&hardware, &revision),
            ControllerIdentity::Tlv(i) => i.target(&hardware, &revision),
        };
        let firmware_result = provider.load(Requirement {
            name: &sfi_name,
            target,
            minimum_bytes: match engine {
                None => firmware::RSA_BYTES + 1,
                Some(2 | 3) => firmware::HYBRID_PAYLOAD + 1,
                Some(_) => firmware::RSA_BYTES + 321,
            },
        });
        // An initial IML image has no invented DDC companion. For the actual
        // operational stage, record BOTH immutable loads before the first error.
        let configuration_result = (!intermediate).then(|| {
            provider.load(Requirement {
                name: &ddc_name,
                target,
                minimum_bytes: 3,
            })
        });
        let image = firmware_result?;
        let configuration = configuration_result.transpose()?;
        let sfi = match engine {
            None => firmware::Sfi::parse(image.bytes(), minimum)?,
            Some(sbe) => {
                let ControllerIdentity::Tlv(identity) = before else {
                    unreachable!()
                };
                firmware::Sfi::parse_tlv(image.bytes(), minimum, sbe, identity.hardware_variant())?
            }
        };
        if let Some(ddc) = configuration {
            firmware::ddc(ddc.bytes())?;
        }
        Ok(Prepared {
            image,
            configuration,
            sfi,
            address,
            intermediate,
            inherited,
        })
    }
    fn upload(&mut self, sfi: &firmware::Sfi<'_>) -> Result<[u8; 6]> {
        // Each stage requires its own secure result and genuine boot event.
        self.secure = false;
        self.boot = None;
        self.allow_secure = false;
        self.allow_boot = false;
        let deadline = self.now().saturating_add(UPLOAD_US);
        for (section_index, (kind, bytes)) in sfi.sections.iter().enumerate() {
            let count = bytes.len().div_ceil(FRAGMENT_BYTES);
            for (index, fragment) in bytes.chunks(FRAGMENT_BYTES).enumerate() {
                if self.now() >= deadline {
                    return Err(Error::Timeout("overall firmware upload"));
                }
                self.allow_secure = section_index + 1 == sfi.sections.len() && index + 1 == count;
                let mut parameters = Vec::with_capacity(fragment.len() + 1);
                parameters.push(*kind);
                parameters.extend_from_slice(fragment);
                if self.command(SECURE_SEND, &parameters)?.len() != 1 {
                    return Err(Error::Protocol("secure-send completion length"));
                }
            }
        }
        self.vendor(false)?;
        self.allow_secure = false;
        self.allow_boot = true;
        let mut reset = vec![0, 1, 0, 1];
        reset.extend_from_slice(&sfi.boot_address.to_le_bytes());
        if !self.events.is_empty() {
            return Err(Error::Protocol("stale response before reset"));
        }
        // Reset has actual transport delivery only, never a synthetic HCI CC.
        self.submit(INTEL_RESET, &reset)?;
        self.vendor(true)?;
        self.hci.finish_boot()?;
        self.allow_boot = false;
        Ok(self.boot.unwrap())
    }
    pub(super) fn apply_dsbr(&mut self, identity: &ControllerIdentity) -> Result<DsbrReport> {
        let mut report = DsbrReport::new(self.dsbr);
        let required = matches!(identity,ControllerIdentity::Tlv(i) if match i.hardware_variant() {
            0x1c | 0x1d => i.image_type == 3,
            0x1e | 0x22 => i.image_type == 2 && (i.cnvi_top >> 24) & 0xf == 1,
            0x1f => i.image_type == 2,
            _ => false,
        });
        if required {
            let parameters = self.dsbr.parameters();
            if self.command(SET_DSBR, &parameters)?.len() != 1 {
                return Err(Error::Protocol("DSBR command completion length"));
            }
            report.applied = Some(parameters);
        }
        Ok(report)
    }
    fn upload_stages<'p>(
        &mut self,
        provider: &'p dyn Provider,
        initial_identity: ControllerIdentity,
        stages: &mut Vec<StageObservation>,
        pending: &mut ControllerIdentity,
    ) -> Result<Report<'p>> {
        let mut before = initial_identity.clone();
        let mut images = Vec::new();
        let mut dsbr = DsbrReport::new(self.dsbr);
        // Fresh IML is supported only with its own complete security/OTP/minimum
        // observations. There is no inferred earlier loader or image provenance.
        let mut initial_bootloader = None;
        for _ in 0..2 {
            let prepared = self.prepare(provider, &before, initial_bootloader.as_ref())?;
            if stages.is_empty()
                && matches!(&before, ControllerIdentity::Tlv(i) if i.image_type == 2)
            {
                dsbr = self.apply_dsbr(&before)?;
            }
            let boot_notification = self.upload(&prepared.sfi)?;
            if matches!(before, ControllerIdentity::Legacy(_)) {
                self.hci.intel_mode(false)?;
            }
            let after = self.identity(before.parameters())?;
            *pending = after.clone();
            let observation = StageObservation {
                before: before.clone(),
                after: after.clone(),
                firmware: prepared.image.into(),
                boot_notification,
                inherited: prepared.inherited,
                dsbr: DsbrReport::new(self.dsbr),
                dsbr_before: if stages.is_empty() {
                    dsbr
                } else {
                    DsbrReport::new(self.dsbr)
                },
            };
            if let Err(cause) = validate_boot(
                &before,
                &after,
                prepared.intermediate,
                prepared.sfi.build,
                initial_bootloader.as_ref(),
            ) {
                return Err(Error::RejectedBoot {
                    cause: Box::new(cause),
                    observation: Box::new(observation),
                });
            }
            if prepared.intermediate
                && let ControllerIdentity::Tlv(old) = &before
            {
                initial_bootloader = Some(old.clone());
            }
            stages.push(observation);
            let applied = self.apply_dsbr(&after)?;
            stages.last_mut().unwrap().dsbr = applied;
            if applied.applied.is_some() {
                dsbr = applied;
            }
            images.push(prepared.image);
            if prepared.intermediate {
                before = after;
                continue;
            }
            if matches!(before, ControllerIdentity::Tlv(_)) {
                self.hci.intel_mode(false)?;
            }
            let address = self.address()?;
            if address != prepared.address {
                return Err(Error::Protocol("postboot address differs from OTP"));
            }
            let configuration = prepared.configuration.unwrap();
            let deadline = self.now().saturating_add(COMMAND_US);
            for record in firmware::ddc(configuration.bytes())? {
                if self.now() >= deadline {
                    return Err(Error::Timeout("DDC configuration"));
                }
                if self.command(WRITE_DDC, record)?.len() != 1 {
                    return Err(Error::Protocol("DDC completion length"));
                }
            }
            let final_identity = self.identity(after.parameters())?;
            *pending = final_identity.clone();
            if final_identity != after || !self.events.is_empty() {
                return Err(Error::Protocol(
                    "identity changed/surplus completions during DDC configuration",
                ));
            }
            let evidence = if images.len() == 1 {
                FirmwareEvidence::Uploaded {
                    firmware: images[0],
                    configuration,
                }
            } else {
                FirmwareEvidence::MultiStage {
                    firmware: images,
                    configuration,
                }
            };
            return Ok(Report {
                before: initial_identity,
                after,
                evidence,
                boot_notification: self.boot,
                address,
                dsbr,
                stages: core::mem::take(stages),
            });
        }
        Err(Error::Protocol("Intel firmware stage bound exceeded"))
    }
}

fn validate_boot(
    before: &ControllerIdentity,
    after: &ControllerIdentity,
    intermediate: bool,
    build: [u8; 3],
    initial: Option<&TlvIdentity>,
) -> Result<()> {
    let expected_type = if intermediate { 2 } else { 3 };
    let type_matches = match after {
        ControllerIdentity::Legacy(_) => after.is_operational(),
        ControllerIdentity::Tlv(i) => i.image_type == expected_type,
    };
    if !before.same_hardware(after)
        || !type_matches
        || (matches!(before, ControllerIdentity::Tlv(_))
            || matches!(before,ControllerIdentity::Legacy(i) if i.hardware_variant >= 0x11))
            && after.build() != Some(build)
    {
        return Err(Error::Protocol("postboot identity/version mismatch"));
    }
    if let (ControllerIdentity::Tlv(old), ControllerIdentity::Tlv(current)) = (before, after) {
        current.validate_security(old)?;
        if let Some(initial) = initial {
            current.validate_security(initial)?;
        }
        if intermediate {
            current.boot_requirements(Some(old))?;
        }
    }
    Ok(())
}

//! A run's report: what the guest printed checked against what the run
//! asked for, written to `run.json`, and the run's exit code.
use super::{
    FAILED_EXIT, IDLE_EXIT, PayloadMode, Run, TIMEOUT_EXIT, audio_check, binding, disks,
    first_guest_panic, first_unsupported, host_firmware, native_clock_proof,
    native_irq_work_verified, native_isolation_verified, native_level_verified,
    native_mmio_observation, native_mmio_verified, native_stack_observation, native_work_verified,
    network, preboot::Preboot, qemu_accelerator, staged, storage::Paths, verify_kernel,
};
use anyhow::{Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    process::{ExitCode, ExitStatus},
    time::Instant,
};

/// What a finished run leaves for its report.
pub(super) struct Outcome {
    pub(super) paths: Paths,
    pub(super) preboot: Option<Preboot>,
    pub(super) disks: Vec<disks::Disk>,
    pub(super) attached: Vec<(PathBuf, String)>,
    pub(super) network: network::Check,
    /// `stela.cfg`.
    pub(super) options: String,
    pub(super) command_line: Vec<String>,
    /// The launch-time bindings of QEMU, the application and `source.bin`.
    pub(super) qemu: Value,
    pub(super) qemu_version: String,
    pub(super) qemu_process_image: Option<Value>,
    pub(super) image: Value,
    pub(super) source: Option<Value>,
    pub(super) started: Instant,
    /// QEMU's exit, or `None` when the run timed out.
    pub(super) status: Option<ExitStatus>,
}

/// Write and print `run.json`, then fail on any check that did not pass.
pub(super) fn finish(arguments: &Run, outcome: Outcome) -> Result<ExitCode> {
    let Outcome {
        paths,
        preboot,
        disks,
        attached,
        network,
        options,
        command_line,
        qemu,
        qemu_version,
        qemu_process_image,
        image,
        source,
        started,
        status,
    } = outcome;
    let output = &paths.output;
    let mut code = match status {
        Some(status) => status.code().map_or(TIMEOUT_EXIT, |code| code as u8),
        None => TIMEOUT_EXIT,
    };
    let qemu_returncode = code;
    let serial_text = fs::read_to_string(&paths.serial).unwrap_or_default();
    let mount_exit = arguments
        .audio_check
        .map(|_| audio_check::guest_exit(&serial_text));
    if let Some(result) = &mount_exit {
        code = result.as_ref().copied().unwrap_or(FAILED_EXIT);
    }
    let unsupported = first_unsupported(&serial_text);
    // The installed-system scenario ends at the bundle's entry: what the
    // engine meets after it is reported but does not fail the run.
    let mut entered = false;
    let verification = if let Some(preboot) = &preboot {
        let checked = preboot.verify(&serial_text);
        entered = checked.is_ok();
        Some(
            checked
                .unwrap_or_else(|error| json!({ "passed": false, "reason": format!("{error:#}") })),
        )
    } else if arguments.bundle.is_none()
        && arguments.module.is_none()
        && !arguments.guestless()
        && !arguments.native_mmio_check
        && !arguments.native_clock_check
    {
        let checked = verify_kernel(&serial_text);
        if checked.is_err() && code == IDLE_EXIT {
            code = FAILED_EXIT;
        }
        Some(checked.map_or_else(
            |error| json!({ "passed": false, "reason": error }),
            |()| json!({ "passed": true }),
        ))
    } else {
        None
    };
    // Before the outputs are bound, as it writes the peer's snapshot.
    let network = network.verify(arguments, output, &serial_text)?;
    let outputs: Vec<Value> = [
        "serial.txt",
        "stdout.txt",
        "stderr.txt",
        "network-check-peer.txt",
        audio_check::WAV,
    ]
    .into_iter()
    .map(|name| output.join(name))
    .filter(|path| path.exists())
    .map(|path| binding(&path))
    .collect::<Result<_>>()?;
    let storage = match arguments.storage_check {
        true => Some(disks::verify(&disks, &paths.serial)),
        false => None,
    };
    let host_firmware = arguments
        .host_firmware
        .as_ref()
        .map(|_| host_firmware::report(&paths.volume, &serial_text))
        .transpose()?;
    let audio = arguments.audio_check.map(|mode| {
        if let Some(Err(error)) = &mount_exit {
            bail!("invalid guest exit status: {error:#}");
        }
        audio_check::normal_exit(
            qemu_returncode,
            &fs::read_to_string(output.join("stdout.txt"))?,
        )?;
        let mut report = audio_check::verify(mode, &serial_text, output)?;
        report["qemu_shutdown"] = json!("acknowledged-qmp-quit");
        report["mount_returncode"] =
            json!(mount_exit.as_ref().and_then(|result| result.as_ref().ok()));
        Ok::<_, anyhow::Error>(report)
    });
    // A native fixture passes only when the guest stopped idle with no
    // unsupported operation or panic.
    let clean = status.is_some()
        && code == IDLE_EXIT
        && unsupported.is_none()
        && first_guest_panic(&serial_text).is_none();
    let native_clock = arguments.native_clock_check.then(|| {
        let observation = native_clock_proof(&serial_text);
        json!({ "passed": observation.is_some() && clean
            && !serial_text.contains("STELA PANIC"),
            "observation": observation })
    });
    let native_mmio = arguments.native_mmio_check.then(|| {
        json!({ "passed": native_mmio_verified(&serial_text) && clean
            && !serial_text.contains("STELA PANIC"),
            "observation": native_mmio_observation(&serial_text),
            "stack_observation": native_stack_observation(&serial_text) })
    });
    let native_irq_work = arguments.native_irq_work_check.then(|| {
        json!({ "passed": native_irq_work_verified(&serial_text) && status.is_some() && code == IDLE_EXIT
            && !serial_text.contains("STELA PANIC") && !serial_text.contains("STOP UNSUPPORTED") })
    });
    let native_work = arguments
        .native_work_check
        .then(|| json!({ "passed": native_work_verified(&serial_text) && clean }));
    let native_dma = arguments.native_dma_check.then(|| {
        json!({
            "passed": serial_text.lines().any(|line| line.starts_with("CHECK native-dma PASS "))
                && !serial_text.lines().any(|line| line.starts_with("CHECK native-dma FAIL "))
                && clean,
        })
    });
    let native_dma_isolation = arguments
        .native_dma_isolation_check
        .then(|| json!({ "passed": native_isolation_verified(&serial_text) && clean }));
    let native_irq = arguments.native_dma_check.then(|| {
        let level_passed = native_level_verified(&serial_text);
        json!({
            "level_passed": level_passed,
            "passed": level_passed && serial_text.lines().any(|line| line.starts_with("CHECK native-irq PASS "))
                && !serial_text.lines().any(|line| line.starts_with("CHECK native-irq FAIL "))
                && clean,
        })
    });
    let network_report = network.as_ref().map(|result| match result {
        Ok(report) => report.clone(),
        Err(error) => json!({ "passed": false, "reason": error }),
    });
    let mut report = json!({
        "command": command_line,
        "qemu": qemu,
        "qemu_version": qemu_version,
        "host_firmware": host_firmware,
        "qemu_process_image": qemu_process_image,
        "image": image,
        "source": source,
        "usb_image": arguments.usb_image,
        "usb_serial": arguments.usb_image.as_ref().map(|_| &arguments.usb_serial),
        "usb_writable": arguments.usb_writable,
        "no_la57": arguments.no_la57,
        "qemu_host_cores": arguments.host_cores,
        "qemu_host_threads": arguments.host_threads,
        "qemu_accelerator": qemu_accelerator(arguments.icount, arguments.kvm),
        "native_dma": native_dma,
        "native_work": native_work,
        "native_irq_work": native_irq_work,
        "native_dma_isolation": native_dma_isolation,
        "native_irq": native_irq,
        "options": options,
        "scenario": verification,
        "bundle": arguments.bundle,
        "preboot_disk": arguments.preboot_disk,
        "directory_volume": arguments.directory_volume,
        "restore_manifest": arguments.restore_manifest,
        "verify_on_read": arguments.verify_on_read,
        "storage_disks": attached
            .iter()
            .map(|(path, serial)| json!({ "path": path, "serial": serial }))
            .collect::<Vec<_>>(),
        "first_unsupported": unsupported,
        "first_guest_panic": first_guest_panic(&serial_text),
        "returncode": code,
        "qemu_returncode": qemu_returncode,
        "payload": arguments.payload.map(|mode| {
            matches!(mode, PayloadMode::Stage | PayloadMode::StagePath)
        }),
        "staging": paths.target.exists().then(|| staged(&paths.target)).transpose()?,
        "timed_out": status.is_none(),
        "wall_seconds": started.elapsed().as_secs_f64(),
        "outputs": outputs,
        "audio": audio.as_ref().map(|result| match result {
            Ok(report) => report.clone(),
            Err(error) => json!({ "passed": false, "reason": format!("{error:#}") }),
        }),
        "storage": storage.as_ref().map(|result| match result {
            Ok(disks) => disks.clone(),
            Err(error) => json!({ "error": format!("{error:#}") }),
        }),
        "network": network_report,
    });
    report["native_mmio"] = native_mmio.unwrap_or(Value::Null);
    report["native_clock"] = native_clock.unwrap_or(Value::Null);
    report["hpet"] = json!(arguments.hpet);
    fs::write(output.join("run.json"), format!("{report:#}\n"))?;
    println!("{report:#}");
    if let Some(Err(error)) = storage {
        return Err(error.context("host storage check failed"));
    }
    ensure!(
        report["host_firmware"].is_null() || report["host_firmware"]["passed"] == true,
        "host firmware did not survive the before/after EBS verification"
    );
    if let Some(Err(error)) = network {
        bail!("host network check failed: {error}");
    }
    if let Some(Err(error)) = audio {
        return Err(error.context("native audio check failed"));
    }
    ensure!(
        !arguments.native_dma_check || report["native_dma"]["passed"] == true,
        "native DMA fixture did not verify actual device traffic, fault and teardown"
    );
    ensure!(
        !arguments.native_dma_check || report["native_irq"]["passed"] == true,
        "native IRQ fixture did not verify MSI and shared level delivery, ACK and drained removal"
    );
    ensure!(
        !arguments.native_dma_isolation_check || report["native_dma_isolation"]["passed"] == true,
        "native DMA isolation fixture did not verify two requesters, matched fault and teardown"
    );
    ensure!(
        !arguments.native_work_check || report["native_work"]["passed"] == true,
        "native work did not verify actual owned contexts, ABI/control/flags and teardown"
    );
    ensure!(
        !arguments.native_irq_work_check || report["native_irq_work"]["passed"] == true,
        "native IRQ work did not qualify actual MSI/context/deferred execution and lifecycle"
    );
    ensure!(
        !arguments.native_mmio_check || report["native_mmio"]["passed"] == true,
        "native MMIO did not verify actual mappings, context refusals, retirement and reuse"
    );
    ensure!(
        !arguments.native_clock_check || report["native_clock"]["passed"] == true,
        "native clock did not verify IRQ progress, idle waits, guest mux and quiet retirement"
    );
    if arguments.native_dma_check
        || arguments.native_dma_isolation_check
        || arguments.native_work_check
        || arguments.native_irq_work_check
        || arguments.native_mmio_check
        || arguments.native_clock_check
    {
        return Ok(ExitCode::SUCCESS);
    }
    Ok(ExitCode::from(match (preboot.is_some(), entered) {
        (true, true) => 0,
        (true, false) => FAILED_EXIT,
        (false, _) => code,
    }))
}

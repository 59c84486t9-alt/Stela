//! A run's QEMU machine: its CPU, memory, firmware, devices other than
//! storage and network, console and debugging.
use super::{
    Display, FIRMWARE_CODE, FIRMWARE_VARIABLES, Iommu, Run, UsbDiskModel, option_path, overlay,
    qemu_accelerator, qemu_cpu, qemu_machine,
};
use anyhow::{Result, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command as Process,
};

/// Paths used to create or reopen QEMU firmware variables.
pub(super) struct VariableStoreOptions<'a> {
    pub(super) qemu: &'a Path,
    pub(super) firmware: &'a Path,
    pub(super) output: &'a Path,
}

/// The firmware's variable store and its format. A qcow2 stick keeps its
/// variables in a qcow2 of its own, so `savevm` can checkpoint the whole
/// machine.
pub(super) fn variables(
    arguments: &Run,
    options: VariableStoreOptions<'_>,
) -> Result<(PathBuf, &'static str)> {
    let VariableStoreOptions {
        qemu,
        firmware,
        output,
    } = options;
    let checkpointed = arguments
        .usb_image
        .as_ref()
        .is_some_and(|image| image.extension().is_some_and(|e| e == "qcow2"));
    let variables = if checkpointed {
        let variables = arguments
            .usb_image
            .as_ref()
            .unwrap()
            .with_extension("vars.qcow2");
        if !variables.exists() {
            overlay(qemu, &firmware.join(FIRMWARE_VARIABLES), &variables)?;
        }
        (variables, "qcow2")
    } else {
        let variables = output.join("variables.fd");
        fs::copy(firmware.join(FIRMWARE_VARIABLES), &variables)?;
        (variables, "raw")
    };
    ensure!(
        arguments.loadvm.is_none() || checkpointed,
        "--loadvm needs a .qcow2 --usb-image"
    );
    Ok(variables)
}

/// QEMU binary, firmware state and guest execution class.
pub(super) struct MachineOptions<'a> {
    pub(super) qemu: &'a Path,
    pub(super) firmware: &'a Path,
    pub(super) variables: &'a Path,
    pub(super) format: &'a str,
    pub(super) system: bool,
    pub(super) bundle: bool,
}

/// QEMU with the machine, its CPUs and memory, and the firmware.
pub(super) fn command(arguments: &Run, options: MachineOptions<'_>) -> Process {
    let MachineOptions {
        qemu,
        firmware,
        variables,
        format,
        system,
        bundle,
    } = options;
    let usb = arguments.usb_image.is_some();
    let mut command = Process::new(qemu);
    // A USB's startup choices take a keyboard. System mode places the guest
    // beside the window with LA57, which the selected CPU exposes unless
    // `--no-la57` hides it.
    let cpu = qemu_cpu(
        arguments.cpu.as_deref().or(arguments.kvm.then_some("host")),
        arguments.no_la57,
        usb || system || arguments.host_check(),
    );
    let keyboard = if usb { "on" } else { "off" };
    let memory = arguments.memory.clone().unwrap_or_else(|| {
        match (bundle, system) {
            (true, _) => "12G",
            (false, true) => "8G",
            (false, false) => "1G",
        }
        .into()
    });
    command
        .arg("-machine")
        .arg(qemu_machine(keyboard, arguments.hpet))
        .args([
            "-accel",
            qemu_accelerator(arguments.icount, arguments.kvm),
            "-cpu",
            &cpu,
            "-smp",
        ])
        .arg(format!(
            "cpus={},sockets=1,cores={},threads={}",
            u32::from(arguments.host_cores) * u32::from(arguments.host_threads),
            arguments.host_cores,
            arguments.host_threads
        ))
        .args(
            arguments
                .icount
                .map(|shift| ["-icount".into(), format!("shift={shift},sleep=off")])
                .into_iter()
                .flatten(),
        )
        .args(["-m", &memory, "-nodefaults", "-no-reboot"])
        .args(
            arguments
                .loadvm
                .iter()
                .flat_map(|tag| ["-loadvm", tag.as_str()]),
        )
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,readonly=on,file={}",
            option_path(&firmware.join(FIRMWARE_CODE))
        ))
        .arg("-drive")
        .arg(format!(
            "if=pflash,format={format},file={}",
            option_path(variables)
        ));
    // An IOMMU precedes the PCI devices it translates for.
    match arguments.iommu {
        Some(Iommu::Intel) => command.args(["-device", "intel-iommu,intremap=off"]),
        Some(Iommu::Amd) => command.args(["-device", "amd-iommu,intremap=off"]),
        None => &mut command,
    };
    command
}

/// How the mount stops QEMU: the debug-exit port, or QMP for an audio check.
pub(super) fn attach_exit(arguments: &Run, output: &Path, command: &mut Process) {
    if let Some(mode) = arguments.audio_check {
        mode.attach(command, output);
        // isa-debug-exit calls exit() before the audio backend finalizes its
        // WAV. Quit through QMP after the mount stops so cleanup can finish.
        command.args(["-qmp", "stdio"]);
    } else {
        command.args(["-device", "isa-debug-exit,iobase=0xf4,iosize=4"]);
    }
}

/// The display a bundle's kernel draws on through the mount's GOP, and
/// `--input`'s virtio keyboard and tablet.
pub(super) fn attach_display(arguments: &Run, bundle: bool, command: &mut Process) {
    if bundle {
        command.args(["-device", "VGA"]);
    }
    if arguments.input {
        command.args([
            "-device",
            "virtio-keyboard-pci",
            "-device",
            "virtio-tablet-pci",
        ]);
    }
}

/// `--host-audio`'s HD Audio controller and codec.
pub(super) fn attach_audio(arguments: &Run, command: &mut Process) {
    if arguments.host_audio {
        command.args([
            "-audiodev",
            "none,id=host-audio",
            "-device",
            "intel-hda,id=host-hda",
            "-device",
            "hda-duplex,bus=host-hda.0,audiodev=host-audio",
        ]);
    }
}

/// The host's xHCI controller, when a USB device needs it.
pub(super) fn attach_usb(arguments: &Run, command: &mut Process) {
    let host_usb = arguments.usb_image.is_some()
        || arguments.usb_input
        || arguments.usb_network
        || !arguments.usb_disk.is_empty();
    if host_usb {
        command.args([
            "-device",
            if arguments.usb_disk_model == Some(UsbDiskModel::UasUsb2) {
                "qemu-xhci,id=host-usb,p3=0"
            } else {
                "qemu-xhci,id=host-usb"
            },
        ]);
    }
}

/// `--usb-input`'s keyboard, tablet and mouse.
pub(super) fn attach_usb_input(arguments: &Run, command: &mut Process) {
    if arguments.usb_input {
        for device in ["usb-kbd", "usb-tablet", "usb-mouse"] {
            command
                .arg("-device")
                .arg(format!("{device},bus=host-usb.0"));
        }
    }
}

/// The UART, logged to `serial`, and the monitor.
pub(super) fn attach_console(arguments: &Run, serial: &Path, command: &mut Process) {
    match arguments.display {
        Display::None => command
            .args(["-display", "none"])
            .arg("-serial")
            .arg(format!("file:{}", serial.display())),
        // Cocoa sizes its text console from the chardev; GTK's VTE console
        // sizes itself and refuses the options.
        Display::Window if cfg!(target_os = "macos") => command
            .args(["-display", "cocoa", "-chardev"])
            .arg(format!(
                "vc,id=uart,cols=132,rows=50,logfile={}",
                option_path(serial)
            ))
            .args(["-serial", "chardev:uart"]),
        Display::Window => command
            .args(["-display", "gtk", "-chardev"])
            .arg(format!("vc,id=uart,logfile={}", option_path(serial)))
            .args(["-serial", "chardev:uart"]),
    };
    match arguments.monitor {
        Some(port) => command
            .arg("-monitor")
            .arg(format!("telnet:127.0.0.1:{port},server=on,wait=off")),
        None => command.args(["-monitor", "none"]),
    };
}

/// The IOMMU and `edu` devices the native DMA and IRQ fixtures drive.
pub(super) fn attach_iommu(arguments: &Run, command: &mut Process) {
    if arguments.native_dma_check
        || arguments.native_dma_isolation_check
        || arguments.native_irq_work_check
    {
        command.args(["-device", "intel-iommu,intremap=off,caching-mode=on"]);
        if arguments.native_dma_isolation_check {
            command.args(["-device", "edu,addr=2", "-device", "edu,addr=3"]);
        } else {
            command.args(["-device", "edu"]);
        }
    }
}

/// `--gdb`: a paused machine waiting for the debugger.
pub(super) fn attach_debugger(arguments: &Run, command: &mut Process) {
    if let Some(port) = arguments.gdb {
        command
            .arg("-gdb")
            .arg(format!("tcp:127.0.0.1:{port}"))
            .arg("-S");
        eprintln!("paused: gdb -ex 'target remote 127.0.0.1:{port}'");
    }
}

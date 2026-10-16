#!/usr/bin/env python3
"""Execute a packaged shared-runtime diagnostic in bounded single-BSP x86 QEMU.

The module is passed unchanged to QEMU. Its ARM placement and initial state are
ordinary explicit machine data. All target compilation and native execution are
inside the real freestanding shared runtime; this host tool only launches QEMU.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import time
import tempfile


def binding(path):
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def run(args, monitor_type):
    args.output.mkdir(parents=True, exist_ok=False)
    serial = args.output / 'serial.txt'
    command = [str(args.qemu), '-machine',
               'q35,smm=off,sata=off,usb=off,smbus=off,hpet=off,i8042=off,vmport=off',
               '-accel', 'tcg,thread=single', '-cpu', 'qemu64', '-smp', '1', '-m', '1G',
               '-nodefaults', '-no-reboot', '-display', args.display, '-monitor', 'none',
               '-device', 'isa-debug-exit,iobase=0xf4,iosize=4',
               '-kernel', str(args.image), '-initrd', str(args.module), '-append', args.append]
    if args.display == 'cocoa':
        command.extend(['-chardev', 'vc,id=uart,cols=132,rows=50,logfile=' + str(serial), '-serial', 'chardev:uart'])
    else:
        command.extend(['-serial', 'file:' + str(serial)])
    qmp_directory = tempfile.TemporaryDirectory(prefix="stela-qmp-", dir="/tmp") if args.capture_console else None
    qmp_socket = Path(qmp_directory.name) / "q" if qmp_directory else None
    if qmp_socket:
        command.extend(["-qmp", f"unix:{qmp_socket},server=on,wait=off"])
    start = time.monotonic()
    report = dict(command=command, runner=binding(Path(__file__).resolve()), qemu=binding(args.qemu), image=binding(args.image),
                  original_module=binding(args.module), timeout_seconds=args.timeout,
                  platform='One BSP; TCG single; SMM off; no optional/default DMA devices; IF must actually be clear; terminal assembly NMI handlers.',
                  claim='Bounded component diagnostic; intact macOS boot/installation unverified.')
    (args.output / 'start.json').write_text(json.dumps(report, indent=2) + '\n')
    with (args.output / 'stdout.txt').open('wb') as out, (args.output / 'stderr.txt').open('wb') as err:
        process = subprocess.Popen(command, stdout=out, stderr=err)
        if qmp_socket:
            try:
                deadline = time.monotonic() + min(2, args.timeout / 2)
                while not qmp_socket.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                # Capture the actual text-console surface once after initial UART.
                time.sleep(min(1, max(0, deadline - time.monotonic())))
                monitor = monitor_type(socket_path=qmp_socket)
                try:
                    image = args.output / "console.ppm"
                    report["qmp_screendump"] = monitor.execute("screendump", {"filename": str(image)})
                    report["console_image"] = binding(image)
                finally:
                    monitor.close()
            except (OSError, RuntimeError, ValueError) as error:
                report["console_capture_failure"] = str(error)
        try:
            report['returncode'] = process.wait(timeout=max(0.01, args.timeout - (time.monotonic() - start)))
            report['timed_out'] = False
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            report['returncode'] = process.returncode
            report['timed_out'] = True
    report['wall_seconds'] = time.monotonic() - start
    if qmp_directory:
        qmp_directory.cleanup()
    report['outputs'] = [binding(p) for p in [serial, args.output / 'stdout.txt', args.output / 'stderr.txt'] if p.exists()]
    (args.output / 'completion.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    # Preserve actual debug-exit carrier; 33 means requested component stop only.
    return report['returncode'] if not report['timed_out'] else 124


def configure_parser(parser):
    parser.add_argument('--qemu', required=True, type=lambda v: Path(v).resolve())
    parser.add_argument('--image', required=True, type=lambda v: Path(v).resolve())
    parser.add_argument('--module', required=True, type=lambda v: Path(v).resolve())
    parser.add_argument('--output', required=True, type=lambda v: Path(v).resolve())
    parser.add_argument('--display', choices=['none', 'cocoa'], default='none',
                        help='Optional visible host UART console; creates no guest VGA/display device.')
    parser.add_argument('--capture-console', action='store_true',
                        help='One actual QMP screendump attempt using the existing VM monitor.')
    parser.add_argument('--append', default='')
    parser.add_argument('--timeout', type=float, default=60)

#!/usr/bin/env python3
"""Build, launch, inspect, and smoke-test the x86 native-code development VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".stela" / "vm"
# Keep UNIX socket paths below macOS's 104-byte limit even in deep checkouts.
QMP_PORT = 4444
GDB_PORT = 1234


def fixture_symbols(path):
    """Read symbols from our locally generated ELF32 fixture (no extra tools)."""
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x01\x01":
        raise RuntimeError("Expected a little-endian ELF32 fixture")
    table = struct.unpack_from("<I", data, 32)[0]
    stride, count = struct.unpack_from("<HH", data, 46)
    sections = [struct.unpack_from("<10I", data, table + index * stride) for index in range(count)]
    result = {}
    for section in sections:
        if section[1] != 2:  # SHT_SYMTAB
            continue
        strings_section = sections[section[6]]
        strings = data[strings_section[4]:strings_section[4] + strings_section[5]]
        for offset in range(section[4], section[4] + section[5], section[9]):
            name, value = struct.unpack_from("<II", data, offset)
            symbol = strings[name:].split(b"\0", 1)[0].decode()
            if symbol in ("_start", "long_mode", "payload", "completed"):
                result[symbol] = value
    if len(result) != 4:
        raise RuntimeError("Fixture symbols are incomplete")
    return result


def qemu_binary():
    local = ROOT / ".tools/qemu/bin/qemu-system-x86_64"
    return str(local) if local.exists() else shutil.which("qemu-system-x86_64")


def build(native=None):
    STATE.mkdir(parents=True, exist_ok=True)
    clang = shutil.which("clang") or "/usr/bin/clang"
    native_data = Path(native).read_bytes() if native else None
    if native_data is not None and not 0 < len(native_data) <= 32768:
        raise RuntimeError("Native fixture must be between 1 and 32768 bytes")
    sectors = (len(native_data) + 511) // 512 if native_data else 0
    definitions = ["-DSTELA_TRANSLATED", f"-DSTELA_NATIVE_SECTORS={sectors}"] if native else []
    subprocess.run([clang, "--target=i386-unknown-none-elf", *definitions, "-g", "-c", str(ROOT / "dev/vm/boot.S"), "-o", str(STATE / "boot.o")], check=True)
    lld = shutil.which("ld.lld") or shutil.which("rust-lld")
    if not lld:
        candidates = list((ROOT / ".tools/rust/rustup/toolchains").glob("*/lib/rustlib/*/bin/rust-lld"))
        if not candidates:
            rustc = shutil.which("rustc")
            if rustc:
                sysroot = subprocess.check_output([rustc, "--print", "sysroot"], text=True).strip()
                candidates = list(Path(sysroot).glob("lib/rustlib/*/bin/rust-lld"))
        lld = str(candidates[0]) if candidates else None
    if not lld:
        raise SystemExit("Install Rust (rust-lld) or LLVM (ld.lld) to link the fixture.")
    base = [lld, "-flavor", "gnu"] if Path(lld).name == "rust-lld" else [lld]
    args = ["-m", "elf_i386", "--image-base", "0", "-Ttext", "0x7c00", "-e", "_start", str(STATE / "boot.o")]
    link_env = os.environ.copy()
    if Path(lld).name == "rust-lld" and os.uname().sysname == "Darwin":
        link_env["DYLD_LIBRARY_PATH"] = str(Path(lld).resolve().parents[3])
    subprocess.run([*base, *args, "-o", str(STATE / "boot.elf")], check=True, env=link_env)
    subprocess.run([*base, *args, "--oformat", "binary", "-o", str(STATE / "boot.img")], check=True, env=link_env)
    data = (STATE / "boot.img").read_bytes()
    if len(data) != 512 or data[-2:] != b"\x55\xaa":
        raise SystemExit("Invalid boot fixture")
    if native_data is not None:
        (STATE / "boot.img").write_bytes(data + native_data.ljust(sectors * 512, b"\0"))
    symbols = fixture_symbols(STATE / "boot.elf")
    (STATE / "symbols.json").write_text(json.dumps(symbols, indent=2) + "\n")
    (STATE / "debug.lldb").write_text(
        "gdb-remote 127.0.0.1:1234\n"
        f"breakpoint set --hardware --address {symbols['payload']:#x}\n"
        "continue\nregister read rax rip rsp\n"
        f"disassemble --start-address {symbols['payload']:#x} --count 8\n"
    )
    return STATE / "boot.img"


def command(paused=True, native=None):
    binary = qemu_binary()
    if not binary:
        raise SystemExit("Install QEMU or run python3 dev/bootstrap-qemu-macos.py first.")
    image = build(native)
    args = [binary, "-machine", "pc", "-accel", "tcg", "-cpu", "qemu64", "-smp", "1", "-m", "64M",
            "-drive", f"file={image},format=raw,if=ide", "-snapshot",
            "-display", "none", "-serial", "none", "-monitor", "none", "-nic", "none",
            "-debugcon", f"file:{STATE / 'debug.log'}", "-global", "isa-debugcon.iobase=0xe9",
            "-qmp", f"tcp:127.0.0.1:{QMP_PORT},server=on,wait=off",
            "-gdb", f"tcp:127.0.0.1:{GDB_PORT}", "-no-reboot",
            "-d", "guest_errors,cpu_reset", "-D", str(STATE / "qemu.log")]
    if paused:
        args.append("-S")
    return args


class Monitor:
    def __init__(self):
        self.socket = socket.create_connection(("127.0.0.1", QMP_PORT), timeout=5)
        self.stream = self.socket.makefile("rwb")
        json.loads(self.stream.readline())
        self.execute("qmp_capabilities")

    def close(self):
        self.stream.close()
        self.socket.close()

    def execute(self, name, arguments=None):
        request = {"execute": name}
        if arguments is not None:
            request["arguments"] = arguments
        self.stream.write(json.dumps(request).encode() + b"\n")
        self.stream.flush()
        while True:
            reply = json.loads(self.stream.readline())
            if "error" in reply:
                raise RuntimeError(reply["error"])
            if "return" in reply:
                return reply["return"]

    def human(self, command):
        return self.execute("human-monitor-command", {"command-line": command})


def smoke(native=None, expected=42):
    args = command(paused=True, native=native)
    for port in (QMP_PORT, GDB_PORT):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
    (STATE / "debug.log").write_text("")
    with open(STATE / "stderr.log", "w") as log:
        process = subprocess.Popen(args, stdout=log, stderr=log)
        monitor = None
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError((STATE / "stderr.log").read_text())
                try:
                    monitor = Monitor()
                    break
                except OSError:
                    time.sleep(0.05)
            if monitor is None:
                raise RuntimeError("QMP did not start")
            # Exercise the debugger protocol independently of QMP.
            with socket.create_connection(("127.0.0.1", GDB_PORT), timeout=5) as debug:
                debug.sendall(b"$?#3f")
                reply = b""
                while b"#" not in reply:
                    chunk = debug.recv(4096)
                    if not chunk:
                        raise RuntimeError("Debugger disconnected")
                    reply += chunk
                if b"$T" not in reply and b"$S" not in reply:
                    raise RuntimeError("GDB stub did not report a stopped CPU")
                debug.sendall(b"+")
            monitor.execute("cont")
            while time.monotonic() < deadline:
                if "OK" in (STATE / "debug.log").read_text():
                    break
                time.sleep(0.05)
            monitor.execute("stop")
            memory = monitor.human("xp /1gx 0x5000")
            registers = monitor.human("info registers")
            if f"0x{expected:016x}" not in memory or f"RAX={expected:016x}" not in registers:
                raise RuntimeError(f"Unexpected guest state:\n{memory}\n{registers}")
            report = {"test": "x86_64_translated_leaf_fixture" if native else "x86_64_long_mode_fixture", "passed": True, "expected_result": expected,
                      "physical_memory": memory, "registers": registers, "debugger": "GDB remote stub handshake passed",
                      "qemu": subprocess.check_output([qemu_binary(), "--version"], text=True).splitlines()[0]}
            if native:
                report["native_sha256"] = hashlib.sha256(Path(native).read_bytes()).hexdigest()
            filename = "aot-smoke-report.json" if native else "smoke-report.json"
            (STATE / filename).write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(report, indent=2))
            monitor.execute("quit")
        finally:
            if monitor:
                monitor.close()
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("build")
    run = sub.add_parser("run", help="start paused; GDB :1234, QMP :4444")
    run.add_argument("--native", type=Path, help="AOT leaf native.bin to load at 0x10000")
    smoke_parser = sub.add_parser("smoke", help="boot, inspect registers/memory, then stop QEMU")
    smoke_parser.add_argument("--native", type=Path)
    smoke_parser.add_argument("--expected", type=lambda value: int(value, 0), default=42)
    sub.add_parser("debug", help="attach LLDB and break at the native payload")
    inspect = sub.add_parser("monitor")
    inspect.add_argument("command", help="QEMU monitor command, e.g. 'info registers'")
    args = parser.parse_args()
    if args.action == "build":
        print(build())
    elif args.action == "run":
        print("Paused. Connect GDB/LLDB to 127.0.0.1:1234. QMP: 127.0.0.1:4444.", flush=True)
        args = command(native=args.native)
        os.execv(args[0], args)
    elif args.action == "smoke":
        smoke(args.native, args.expected)
    elif args.action == "debug":
        commands = STATE / "debug.lldb"
        if not commands.exists():
            raise SystemExit("Start dev/vm.py run in another terminal first.")
        lldb = shutil.which("lldb")
        prefix = [lldb] if lldb else ["/usr/bin/xcrun", "lldb"]
        subprocess.run([*prefix, "-s", str(commands)], check=True)
    else:
        monitor = Monitor()
        try:
            print(monitor.human(args.command))
        finally:
            monitor.close()


if __name__ == "__main__":
    main()

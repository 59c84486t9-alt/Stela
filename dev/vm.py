#!/usr/bin/env python3
"""Build, launch, inspect, and smoke-test the x86 native-code development VM."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import time
from evidence import write_evidence

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


def physical_u64(monitor, address):
    output = monitor.human(f"xp /1gx {address:#x}")
    match = re.search(r":\s+(0x[0-9a-fA-F]+)", output)
    if match is None:
        raise RuntimeError(f"Cannot read physical memory: {output}")
    return int(match.group(1), 16), output


def memory_expectation(value):
    try:
        address, expected = (int(part, 0) for part in value.split("="))
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected ADDRESS=VALUE (decimal or hexadecimal)") from error
    if not 0 <= address <= (1 << 64) - 8 or not 0 <= expected < (1 << 64):
        raise argparse.ArgumentTypeError("address/value exceeds unsigned 64-bit range")
    return address, expected


def block_exit_expectation(value):
    try:
        pc, kind = (int(part, 0) for part in value.split("="))
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected PC=KIND (decimal or hexadecimal)") from error
    if not 0 <= pc < (1 << 64) or not 0 <= kind <= 5:
        raise argparse.ArgumentTypeError("block PC must fit u64 and KIND must be in 0..5")
    return pc, kind


def smoke(native=None, expected=42, expect_memory=(), expect_block_exit=None):
    if expect_block_exit is not None and native is None:
        raise ValueError("block-exit checks require a native block fixture")
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
            result, memory = physical_u64(monitor, 0x5000)
            registers = monitor.human("info registers")
            if result != expected or f"RAX={expected:016x}" not in registers:
                raise RuntimeError(f"Unexpected guest state:\n{memory}\n{registers}")
            memory_checks = []
            for address, value in expect_memory:
                actual, observation = physical_u64(monitor, address)
                if actual != value:
                    raise RuntimeError(f"Unexpected memory at {address:#x}: {actual:#x}, expected {value:#x}")
                memory_checks.append({"address": address, "expected": value, "actual": actual, "observation": observation})
            observed_exit = None
            exit_observations = None
            if expect_block_exit is not None:
                next_pc, pc_observation = physical_u64(monitor, 0x5010)
                kind, kind_observation = physical_u64(monitor, 0x5018)
                observed_exit = (next_pc, kind)
                if observed_exit != expect_block_exit:
                    raise RuntimeError(f"Unexpected native block exit: {observed_exit}, expected {expect_block_exit}")
                exit_observations = {"next_pc_physical_address": 0x5010,
                                     "kind_physical_address": 0x5018,
                                     "next_pc": pc_observation, "kind": kind_observation}
            test = ("x86_64_translated_block_fixture" if expect_block_exit is not None else
                    "x86_64_translated_leaf_fixture" if native else "x86_64_long_mode_fixture")
            report = {"test": test, "passed": True, "expected_result": expected,
                      "physical_memory": memory, "registers": registers, "debugger": "GDB remote stub handshake passed",
                      "qemu": subprocess.check_output([qemu_binary(), "--version"], text=True).splitlines()[0]}
            report["memory_checks"] = memory_checks
            report["source_sha256"] = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                       for name in ("dev/vm.py", "dev/vm/boot.S")}
            report["boot_image_sha256"] = hashlib.sha256((STATE / "boot.img").read_bytes()).hexdigest()
            report["boot_elf_sha256"] = hashlib.sha256((STATE / "boot.elf").read_bytes()).hexdigest()
            if observed_exit is not None:
                report["block_exit"] = observed_exit
                report["expected_block_exit"] = expect_block_exit
                report["block_exit_observations"] = exit_observations
                report["limits"] = "Native block ABI/debugger proof only; no architectural exception entry, host syscall delivery or macOS boot."
            if native:
                report["native_sha256"] = hashlib.sha256(Path(native).read_bytes()).hexdigest()
                manifest = Path(native).parent / "manifest.json"
                if manifest.is_file():
                    manifest_bytes = manifest.read_bytes()
                    receipt = json.loads(manifest_bytes)
                    if receipt.get("native_sha256") != report["native_sha256"]:
                        raise RuntimeError("Native fixture manifest hash does not match executed bytes")
                    report["native_manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
                    report["native_manifest"] = receipt
            filename = ("block-smoke-report.json" if expect_block_exit is not None else
                        "aot-smoke-report.json" if native else "smoke-report.json")
            write_evidence(STATE / filename,report)
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
    run.add_argument("--native", type=Path, help="AOT leaf/block native.bin to load at 0x10000")
    smoke_parser = sub.add_parser("smoke", help="boot, inspect registers/memory, then stop QEMU")
    smoke_parser.add_argument("--native", type=Path)
    smoke_parser.add_argument("--expected", type=lambda value: int(value, 0), default=42)
    smoke_parser.add_argument("--expect-memory", type=memory_expectation, action="append", default=[], metavar="ADDRESS=VALUE")
    smoke_parser.add_argument("--expect-block-exit", type=block_exit_expectation, metavar="PC=KIND",
                              help="check native block RAX/RDX return tuple; requires --native")
    sub.add_parser("debug", help="attach LLDB and break at the native payload")
    inspect = sub.add_parser("monitor")
    inspect.add_argument("command", help="QEMU monitor command, e.g. 'info registers'")
    args = parser.parse_args()
    if args.action == "smoke" and args.expect_block_exit is not None and args.native is None:
        parser.error("--expect-block-exit requires --native")
    if args.action == "build":
        print(build())
    elif args.action == "run":
        print("Paused. Connect GDB/LLDB to 127.0.0.1:1234. QMP: 127.0.0.1:4444.", flush=True)
        args = command(native=args.native)
        os.execv(args[0], args)
    elif args.action == "smoke":
        smoke(args.native, args.expected, args.expect_memory, args.expect_block_exit)
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

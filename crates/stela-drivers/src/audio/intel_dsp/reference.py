#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""UNRUN: execute the unchanged pinned CNL notification acknowledgement body.

Only the native-register access environment is modeled. The donor C function
and its register macros are extracted verbatim after whole-file hash checks.
This bounded oracle does not emulate SOF firmware, ROM, PCM or physical audio.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time


# Share the waitid ABI adapter between the two driver oracle runners.
_WAIT_PATH = Path(__file__).resolve().parents[3] / "tests/reference/child_wait.py"
_WAIT_SPEC = importlib.util.spec_from_file_location("stela_oracle_child_wait", _WAIT_PATH)
child_wait = importlib.util.module_from_spec(_WAIT_SPEC)
_WAIT_SPEC.loader.exec_module(child_wait)

PIN = "a804c5742bff224d4cb4d25dd383554d598be32b"
DONORS = {
    "sound/soc/sof/intel/cnl.c": "05a2e471c1f602251eb13d026ecf62d315cb07d55c34fd6564f3a6c7e527ef27",
    "sound/soc/sof/intel/hda.h": "f377dbb6688b331a11b3a673d02540f70d86ba386a117660937d00a98ae60186",
}


def digest(path):
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


class Evidence:
    """Fresh retained artifacts; never replace an earlier source/run receipt."""

    def __init__(self, output):
        if output.exists():
            raise SystemExit(f"refusing existing trace: {output}")
        self.root = output.parent / (output.name + ".evidence")
        self.root.mkdir(parents=True, exist_ok=False)
        self.environment = dict(os.environ)
        self.cancellation = None
        self.waiter = child_wait.ChildWaiter()
        self.environment.update(GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0", LC_ALL="C")
        self.record = {
            "schema": 1,
            "pin": PIN,
            "status": "running",
            "started_utc": datetime.now(timezone.utc).isoformat(),
            "harness_sha256": digest(Path(__file__)),
            "child_wait_sha256": digest(_WAIT_PATH),
            "wait_backend": self.waiter.backend,
            "commands": [],
            # Selected effective settings, deliberately not a full environment.
            "environment": {key: self.environment.get(key) for key in (
                "PATH", "CC", "GIT_NO_LAZY_FETCH", "GIT_TERMINAL_PROMPT", "LC_ALL"
            )},
            "limits": "Original CNL host-done body only; no ROM/firmware/PCM/native DMA proof",
        }
        self.save()

    def save(self):
        (self.root / "receipt.json").write_text(json.dumps(self.record, indent=2) + "\n")

    def check_cancelled(self):
        if self.cancellation is not None:
            raise InterruptedError(f"harness interrupted by signal {self.cancellation}")

    def command(self, name, arguments, timeout):
        self.check_cancelled()
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise RuntimeError("reference runner requires exclusive child-reaping ownership")
        item = {"name": name, "argv": arguments, "timeout_seconds": timeout}
        self.record["commands"].append(item)
        self.save()
        stdout = self.root / (name + ".stdout")
        stderr = self.root / (name + ".stderr")
        # File-backed output cannot fill a pipe. Kill only this command's own
        # process group on timeout, including compiler descendants.
        with stdout.open("xb") as out, stderr.open("xb") as err:
            process = subprocess.Popen(arguments, stdout=out, stderr=err,
                                       env=self.environment, start_new_session=True)
            group_cleaned = False
            try:
                deadline = time.monotonic() + timeout
                while True:
                    # Signal handlers only record cancellation, including
                    # throughout Popen. Deliver it after owning the child and
                    # before a wait can reap it. No asynchronous exception can
                    # orphan a half-created child or signal a retired PGID.
                    self.check_cancelled()
                    if self.waiter.exited_unreaped(process.pid):
                        # Keep the original leader unreaped until all members
                        # are signaled. Even a leader that exited during a
                        # cancellation cannot orphan descendants or allow its
                        # numeric group ID to be reused before this cleanup.
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        group_cleaned = True
                        item["group_cleanup"] = "before original leader reap"
                        item["returncode"] = process.wait()
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(arguments, timeout)
                    time.sleep(min(remaining, 0.05))
            except BaseException as error:
                item["timed_out"] = isinstance(error, subprocess.TimeoutExpired)
                item["interruption"] = type(error).__name__
                if isinstance(error, ChildProcessError):
                    # An external reaper invalidates the PID/group lease.
                    # Never signal that now-unowned numeric group ID or
                    # manufacture an exit status by asking Popen to wait.
                    item["leader_ownership"] = "lost; refused group signal"
                    raise
                if not group_cleaned and process.returncode is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                item["returncode"] = process.wait()
                if item["timed_out"]:
                    raise RuntimeError(f"{name} timed out after {timeout}s") from None
                raise
            finally:
                item["stdout_sha256"] = digest(stdout)
                item["stderr_sha256"] = digest(stderr)
                self.save()
        if item["returncode"]:
            raise RuntimeError(f"{name} failed ({item['returncode']}); see {stderr}")
        self.check_cancelled()
        return stdout.read_bytes()


def donor(evidence, git_dir, name, index):
    data = evidence.command(f"donor-{index}",
                            ["git", f"--git-dir={git_dir}", "show", f"{PIN}:{name}"], 30)
    if hashlib.sha256(data).hexdigest() != DONORS[name]:
        raise SystemExit(f"donor hash mismatch: {name}")
    return data.decode()


def function(source, name):
    match = re.search(r"static void " + re.escape(name) + r"\([^)]*\)\s*\{", source)
    if not match:
        raise SystemExit(f"missing original function {name}")
    depth = 1
    end = match.end()
    while depth and end < len(source):
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    if depth:
        raise SystemExit(f"unterminated original function {name}")
    return source[match.start():end]


def generate(evidence, args):
    source = donor(evidence, args.linux_git_dir, "sound/soc/sof/intel/cnl.c", 0)
    header = donor(evidence, args.linux_git_dir, "sound/soc/sof/intel/hda.h", 1)
    evidence.record["verified_donors"] = DONORS
    evidence.save()
    names = ["CNL_DSP_IPC_BASE", "CNL_DSP_REG_HIPCTDR", "CNL_DSP_REG_HIPCTDA", "CNL_DSP_REG_HIPCTDR_BUSY", "CNL_DSP_REG_HIPCTDA_DONE"]
    macros = []
    for name in names:
        match = re.search(r"^#define\s+" + name + r"\s+.*$", header, re.MULTILINE)
        if not match:
            raise SystemExit(f"missing original macro {name}")
        macros.append(match.group())
    program = """#include <stdint.h>
#include <stdio.h>
#define BIT(n) (1u << (n))
#define HDA_DSP_BAR 0
struct snd_sof_dev { unsigned unused; };
static uint32_t registers[256];
static void snd_sof_dsp_update_bits_forced(struct snd_sof_dev *s, int bar,
                                         unsigned offset, uint32_t mask, uint32_t bits) {
    (void)s; (void)bar;
    uint32_t value = (registers[offset] & ~mask) | bits;
    printf("%x %08x\\n", offset, value);
    registers[offset] = value;
}
""" + "\n".join(macros) + "\n" + function(source, "cnl_ipc_host_done") + """
int main(void) {
    struct snd_sof_dev device = {0};
    registers[CNL_DSP_REG_HIPCTDR] = 0xf0000000;
    cnl_ipc_host_done(&device);
    return 0;
}
"""
    c_file = evidence.root / "original.c"
    binary = evidence.root / "original"
    c_file.write_text(program)
    evidence.record["generated_c_sha256"] = digest(c_file)
    compiler = shutil.which(os.environ.get("CC", "clang"))
    if compiler is None:
        raise RuntimeError("selected C compiler not found")
    evidence.record["compiler"] = {"path": str(Path(compiler).resolve()),
                                   "sha256": digest(Path(compiler))}
    evidence.save()
    evidence.command("compile", [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                                 str(c_file), "-o", str(binary)], 120)
    # Persist the executable's identity before executing it, including on failure.
    evidence.record["executable_sha256"] = digest(binary)
    evidence.save()
    trace = evidence.command("execute", [str(binary)], 10)
    if not re.fullmatch(rb"[0-9a-f]+ [0-9a-f]{8}\n[0-9a-f]+ [0-9a-f]{8}\n", trace):
        raise RuntimeError("original C body returned a malformed two-write trace")
    with args.output.open("xb") as output:
        output.write(trace)
    evidence.record["trace_sha256"] = digest(args.output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux-git-dir", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    evidence = Evidence(args.output)
    def interrupted(signum, _frame):
        evidence.cancellation = signum

    previous_term = signal.signal(signal.SIGTERM, interrupted)
    previous_int = signal.signal(signal.SIGINT, interrupted)
    try:
        generate(evidence, args)
        evidence.check_cancelled()
        evidence.record["status"] = "passed"
    except BaseException as error:
        evidence.record["status"] = "failed"
        evidence.record["error"] = str(error)
        raise
    finally:
        try:
            evidence.record["finished_utc"] = datetime.now(timezone.utc).isoformat()
            evidence.save()
        finally:
            signal.signal(signal.SIGTERM, previous_term)
            signal.signal(signal.SIGINT, previous_int)


if __name__ == "__main__":
    main()

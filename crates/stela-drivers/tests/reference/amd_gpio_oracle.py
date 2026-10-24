#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""UNRUN pinned Linux AMD GPIO debounce oracle.

Compile the exact original function and register macro prefix. Only the MMIO
storage callbacks are modeled. Compare configuration bits, not timing or native
attachment. Linux's >=1s error still writes and its ordinary RMW can clear W1C
status; Stela deliberately refuses the former before effects and preserves the
latter. Those differences are explicit, not hidden by trace equivalence.
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
_WAIT_PATH = Path(__file__).resolve().with_name("child_wait.py")
_WAIT_SPEC = importlib.util.spec_from_file_location("stela_oracle_child_wait", _WAIT_PATH)
child_wait = importlib.util.module_from_spec(_WAIT_SPEC)
_WAIT_SPEC.loader.exec_module(child_wait)

PIN = "a804c5742bff224d4cb4d25dd383554d598be32b"
DONORS = {'drivers/pinctrl/pinctrl-amd.c': 'b1c35108f7b322ca1f7dbef6dce3de4f4ea4e359a44e2776b70016c96af16848', 'drivers/pinctrl/pinctrl-amd.h': '0c41dad9fc3c43efc67ee97a76cbb56fd268c96f5fad3d7793186d2ca6f6a7f8'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
        self.quarantined_commands = []  # Retain failed-cleanup owners until interpreter exit.
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
            "limits": "Unchanged AMD debounce encoding only; modeled readl/writel; no native GPIO/IRQ/PM/electrical timing proof",
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
            item["pid"] = process.pid
            item["pgid"] = process.pid  # start_new_session=True
            item["pgid_source"] = "Popen(start_new_session=True)"
            item["leader_reaped"] = False
            cleanup_attempted = False
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
                        cleanup_attempted = True
                        self.waiter.cleanup_owned_group(process.pid, item)
                        group_cleaned = True
                        item["returncode"] = process.wait()
                        item["leader_reaped"] = True
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(arguments, timeout)
                    time.sleep(min(remaining, 0.05))
            except BaseException as error:
                item["timed_out"] = isinstance(error, subprocess.TimeoutExpired)
                item["interruption"] = type(error).__name__
                if isinstance(error, ChildProcessError):
                    # ECHILD invalidates the lease. Never signal or ask Popen
                    # to manufacture a status for an externally reaped child.
                    item["leader_ownership"] = "lost; refused group signal"
                    if cleanup_attempted:
                        item["cleanup_error"] = type(error).__name__
                    raise
                if cleanup_attempted and not group_cleaned:
                    item["cleanup_error"] = type(error).__name__
                    item["cleanup_error_repr"] = repr(error)
                    item["cleanup_error_errno"] = getattr(error, "errno", None)
                    item["leader_ownership"] = "quarantined on shared helper until interpreter exit"
                    self.quarantined_commands.append(process)
                    child_wait.quarantine_failed_cleanup(process)
                    raise  # Do not let Popen.__del__ poll/reap this retained owner.
                if not group_cleaned and process.returncode is None:
                    try:
                        cleanup_attempted = True
                        self.waiter.cleanup_owned_group(process.pid, item)
                        group_cleaned = True
                    except ChildProcessError:
                        item["leader_ownership"] = "lost; refused group signal"
                        item["cleanup_error"] = "ChildProcessError"
                        raise
                    except BaseException as cleanup_error:
                        item["cleanup_error"] = type(cleanup_error).__name__
                        item["cleanup_error_repr"] = repr(cleanup_error)
                        item["cleanup_error_errno"] = getattr(cleanup_error, "errno", None)
                        item["leader_ownership"] = "quarantined on shared helper until interpreter exit"
                        self.quarantined_commands.append(process)
                        child_wait.quarantine_failed_cleanup(process)
                        raise
                item["returncode"] = process.wait()
                item["leader_reaped"] = True
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


def function(source):
    match = re.search(r"^static int amd_gpio_set_debounce\([^;]+?\n\{", source, re.M)
    if match is None:
        raise ValueError("missing pinned debounce function")
    end, depth = match.end(), 1
    while depth and end < len(source):
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    if depth:
        raise ValueError("unterminated pinned debounce function")
    return source[match.start():end]


def generate(evidence, args):
    texts = {}
    for index, (name, expected) in enumerate(DONORS.items()):
        raw = evidence.command(f"donor-{index}",
            ["git", f"--git-dir={args.linux_git_dir}", "show", f"{PIN}:{name}"], 30)
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError(f"pinned source hash mismatch: {name}")
        texts[name] = raw.decode()
    original = function(texts["drivers/pinctrl/pinctrl-amd.c"])
    header = texts["drivers/pinctrl/pinctrl-amd.h"]
    # Preserve the original macro prefix verbatim; do not copy kernel structs.
    prefix, separator, _ = header.partition("struct amd_function {")
    if not separator:
        raise ValueError("missing original header boundary")
    constants = evidence.root / "donor_constants.h"
    constants.write_text(prefix + "\n#endif\n")
    evidence.record.update(verified_donors=DONORS,
        function_sha256=hashlib.sha256(original.encode()).hexdigest(),
        macro_prefix_sha256=hashlib.sha256(prefix.encode()).hexdigest(),
        cases=672,
        comparison="Configuration bits only. Original C errors write; Stela invalid requests must not. Native firmware/IRQ/PM/timing unqualified.")
    program = r"""
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
#define BIT(n) (UINT32_C(1) << (n))
#define GENMASK(h, l) ((UINT32_MAX >> (31 - (h))) & (UINT32_MAX << (l)))
#include "donor_constants.h"
struct amd_gpio { uint8_t *base; };
static u32 registers[256];
static unsigned writes;
static unsigned index_of(const void *address) {
    uintptr_t start = (uintptr_t)registers;
    uintptr_t at = (uintptr_t)address;
    assert(at >= start && at - start < sizeof(registers));
    assert((at - start) % sizeof(u32) == 0);
    return (unsigned)((at - start) / sizeof(u32));
}
static u32 readl(const void *address) { return registers[index_of(address)]; }
static void writel(u32 value, void *address) {
    writes++;
    registers[index_of(address)] = value;
}
""" + original + r"""
int main(void) {
    const unsigned pins[] = {0, 1, 62, 64, 127, 128, 183};
    const u32 seeds[] = {0, 0x000003ff, 0x00e60000, 0x31010000};
    const unsigned durations[] = {0, 1, 60, 61, 62, 915, 975, 976, 977,
        3899, 3900, 3901, 15624, 15625, 249999, 250000, 250001, 937500,
        999999, 1000000, UINT32_MAX};
    struct amd_gpio device = {.base = (uint8_t *)registers};
    puts("AMD_GPIO_DEBOUNCE a804c5742bff224d4cb4d25dd383554d598be32b 672");
    for (unsigned p = 0; p < sizeof(pins) / sizeof(pins[0]); p++)
        for (unsigned internal = 0; internal < (pins[p] == 0 ? 2u : 1u); internal++)
            for (unsigned s = 0; s < sizeof(seeds) / sizeof(seeds[0]); s++)
                for (unsigned d = 0; d < sizeof(durations) / sizeof(durations[0]); d++) {
                    memset(registers, 0, sizeof(registers));
                    registers[pins[p]] = seeds[s];
                    registers[WAKE_INT_MASTER_REG / 4] = internal ? INTERNAL_GPIO0_DEBOUNCE : 0;
                    writes = 0;
                    int result = amd_gpio_set_debounce(&device, pins[p], durations[d]);
                    printf("DB %u %u %08x %u %d %08x %u\n", pins[p], internal,
                        seeds[s], durations[d], result, registers[pins[p]], writes);
                }
    return 0;
}
"""
    source = evidence.root / "original.c"
    binary = evidence.root / "original"
    source.write_text(program)
    evidence.record["generated_c_sha256"] = digest(source)
    compiler = shutil.which(os.environ.get("CC", "clang"))
    if compiler is None:
        raise RuntimeError("selected C compiler not found")
    evidence.record["compiler"] = {"path": str(Path(compiler).resolve()),
                                   "sha256": digest(Path(compiler))}
    evidence.save()
    evidence.command("compile", [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-O1", "-g", "-fsanitize=address,undefined", str(source), "-o", str(binary)], 120)
    evidence.record["executable_sha256"] = digest(binary)
    evidence.save()
    trace = evidence.command("execute", [str(binary)], 10)
    lines = trace.splitlines()
    if lines[0] != f"AMD_GPIO_DEBOUNCE {PIN} 672".encode() or len(lines) != 673:
        raise ValueError("malformed/incomplete debounce oracle trace")
    if any(re.fullmatch(rb"DB [0-9]+ [01] [0-9a-f]{8} [0-9]+ -?[0-9]+ [0-9a-f]{8} 1", line) is None
           for line in lines[1:]):
        raise ValueError("malformed original function result")
    with args.output.open("xb") as stream:
        stream.write(trace)
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

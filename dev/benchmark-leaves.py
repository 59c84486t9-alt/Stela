#!/usr/bin/env python3
"""Benchmark native Stela output against optimizing C on own bounded leaves.

Correctness compares original ARM in Unicorn with both native implementations
outside the timer. Timing occurs entirely in a C function-pointer batch loop;
Unicorn and Python dispatch are never timed. This is a GuestState ABI fixture
benchmark, not Rosetta, application, kernel-service, or whole-OS performance.
"""
import argparse
from contextlib import ExitStack
import ctypes
import hashlib
import json
import math
import mmap
import multiprocessing
from pathlib import Path
import platform
import random
import statistics
import struct
import subprocess
import time

from differential import BASE, MASK, ROOT, State, executable, reference, states
from evidence import write_evidence

NAMES = ("bench_integer", "bench_sum", "bench_copy_sum")
COUNTS = (1, 16, 64, 256, 1024)
RAM_SIZE = 65536
INPUT = 1024
OUTPUT = 16384
C_FUNCTION = ctypes.CFUNCTYPE(None, ctypes.POINTER(State))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def command(arguments):
    return subprocess.check_output([str(a) for a in arguments], text=True, timeout=180)


def timed_command(arguments):
    start = time.perf_counter_ns()
    output = command(arguments)
    return output, time.perf_counter_ns() - start


def text_slice(cli, path, architecture):
    rows = json.loads(command([cli, "binary-text", path]))
    return next(row["slice"] for row in rows if row["slice"]["artifact"]["architecture"] == architecture)


def prepare(artifact_root, clang):
    cli = ROOT / "target/debug/stela"
    assembly = ROOT / "tests/fixtures/benchmark-arm64.S"
    c_source = ROOT / "dev/native-benchmark.c"
    arm_object = artifact_root / "benchmark-arm64.o"
    c_library = artifact_root / ("native-benchmark.dylib" if platform.system() == "Darwin" else "native-benchmark.so")
    arm_command = [clang, "--target=arm64-apple-macos", "-c", assembly, "-o", arm_object]
    c_command = [clang, "-O3", "-std=c11", "-fPIC", "-Wall", "-Wextra", "-Werror",
                 "-dynamiclib" if platform.system() == "Darwin" else "-shared", c_source, "-o", c_library]
    subprocess.run([str(arg) for arg in arm_command], check=True, timeout=60)
    subprocess.run([str(arg) for arg in c_command], check=True, timeout=60)
    text = text_slice(cli, arm_object, "arm64")
    section = next(section for section in text["sections"] if section["name"] == "__text")
    raw = bytes.fromhex(section["data_hex"])
    symbols = text["defined_text_symbols"]
    benchmarks = []
    fingerprint = None
    cache = artifact_root / "first-use-cache"
    for index, name in enumerate(NAMES):
        start = symbols["_" + name] - section["guest_address"]
        end = symbols["_" + NAMES[index + 1]] - section["guest_address"] if index + 1 < len(NAMES) else len(raw)
        source = raw[start:end]
        if not source or source[-4:] != bytes.fromhex("c0035fd6"):
            raise ValueError("benchmark symbol extent is not a complete reviewed leaf")
        path = artifact_root / (name + ".arm64")
        path.write_bytes(source)
        arguments = [cli, "prepare-leaf", path, "--guest-base", hex(BASE + start), "--cache-dir", cache]
        cold_text, cold_ns = timed_command(arguments)
        cold = json.loads(cold_text)
        warm_text, warm_ns = timed_command(arguments)
        warm = json.loads(warm_text)
        if cold["cache_hit"] or not warm["cache_hit"] or cold["key"] != warm["key"]:
            raise AssertionError("first-use/disk-reuse cache observation failed")
        manifest = cold["manifest"]
        observed = manifest["identity"]["compiler_source_sha256"]
        if fingerprint is not None and fingerprint != observed:
            raise AssertionError("compiler changed during benchmark preparation")
        fingerprint = observed
        native = Path(cold["directory"]) / "native.bin"
        if digest(native) != manifest["native_sha256"]:
            raise AssertionError("generated benchmark checksum mismatch")
        benchmarks.append({"name": name, "source": source, "native": native.read_bytes(),
                           "arm_source": str(path), "arm_sha256": digest(path),
                           "native_artifact": str(native), "native_sha256": digest(native),
                           "native_bytes": manifest["native_bytes"], "source_map": manifest["source_map"],
                           "cache_key": cold["key"], "compiler_source_sha256": observed,
                           "guest_base": manifest["identity"]["guest_base"],
                           "first_use_cli_wall_ns": cold_ns, "disk_reuse_cli_wall_ns": warm_ns})
    startup = [timed_command([cli, "--help"])[1] for _ in range(5)]
    metadata = {"artifact_root": str(artifact_root), "arm_object_sha256": digest(arm_object),
                "c_library": str(c_library), "c_library_sha256": digest(c_library),
                "stela_executable_sha256": digest(cli), "compiler_source_sha256": fingerprint,
                "clang_version": command([clang, "--version"]).strip(),
                "clang_commands": [[str(a) for a in args] for args in (arm_command, c_command)],
                "source_hashes": {str(p.relative_to(ROOT)): digest(p) for p in
                                  (assembly, c_source, Path(__file__), ROOT / "dev/differential.py")},
                "cli_startup_help_wall_ns": startup,
                "translation_latency_scope": "Direct prebuilt CLI process wall time includes startup, hashing, disk I/O and JSON; cargo build is outside timings. These values are not isolated compiler-algorithm latency. Help startup samples are context only and are not subtracted."}
    return benchmarks, metadata


def state_result(state, ram):
    return {"x": list(state.x), "sp": state.sp, "nzcv": state.nzcv, "memory": bytes(ram)}


def initial_state(original, address, count, seed=None):
    state = State.from_buffer_copy(original)
    state.x[10], state.x[11] = address + INPUT, address + OUTPUT
    state.x[12] = count
    if seed is not None:
        state.x[13] = seed
    state.sp = address + RAM_SIZE // 2
    return state


def independent_sum(name, count, state, ram):
    if name == "bench_integer":
        return (count * state.x[13] + 3 * count * (count - 1) // 2) & MASK
    return sum(struct.unpack_from("<" + "Q" * count, ram, INPUT)) & MASK if count else 0


def measured_batch(timer, function, state, calls, expected):
    checksum = ctypes.c_uint64()
    elapsed = timer(function, ctypes.byref(state), calls, ctypes.byref(checksum))
    if elapsed == MASK or not elapsed:
        raise RuntimeError("native C monotonic timer failed or returned zero interval")
    if checksum.value != expected * calls & MASK:
        raise AssertionError("timed native batch checksum mismatch")
    return elapsed


def distribution(samples, calls):
    per_call = [value / calls for value in samples]
    return {"trial_elapsed_ns": samples, "calls_per_trial": calls,
            "median_ns_per_call": statistics.median(per_call),
            "min_ns_per_call": min(per_call), "max_ns_per_call": max(per_call),
            "population_stddev_ns_per_call": statistics.pstdev(per_call)}


def execute(benchmarks, metadata, calls, warmup, trials, verify_only, min_trial_ms, max_calls):
    library = ctypes.CDLL(metadata["c_library"])
    timer = library.stela_benchmark
    timer.argtypes = [ctypes.c_void_p, ctypes.POINTER(State), ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64)]
    timer.restype = ctypes.c_uint64
    resolution = library.stela_clock_resolution_ns
    resolution.argtypes = []
    resolution.restype = ctypes.c_uint64
    timer_resolution = resolution()
    if timer_resolution == MASK:
        raise RuntimeError("native timer resolution query failed")
    randomizer = random.Random(0x50e77a)
    original_ram = randomizer.randbytes(RAM_SIZE)
    edge_seeds = (0, 1, MASK, 0x8000000000000000, 0x7fffffffffffffff, 0xffffffff, 0x100000000, 0xdeadbeef01234567)
    all_states = states(all_flags=True)
    comparisons = 0
    results = []
    overhead = None
    overhead_calibration = None
    calibration_calls = 0

    def calibrate(function, state, expected):
        nonlocal calibration_calls
        elapsed = measured_batch(timer, function, state, calls, expected)
        calibration_calls += calls
        target = int(min_trial_ms * 1000000)
        desired = (calls * target + elapsed - 1) // elapsed
        selected = max(calls, min(max_calls, desired))
        return selected, {"pilot_calls": calls, "pilot_elapsed_ns": elapsed,
                          "target_baseline_trial_ns": target, "selected_equal_calls_per_implementation": selected,
                          "cap_reached": desired > max_calls}
    with ExitStack() as stack:
        region = stack.enter_context(mmap.mmap(-1, RAM_SIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE))
        marker = ctypes.c_char.from_buffer(region)
        ram_address = ctypes.addressof(marker)
        del marker
        if not verify_only:
            empty = library.bench_empty
            empty_address = ctypes.cast(empty, ctypes.c_void_p).value
            state = initial_state(all_states[0], ram_address, 1)
            measured_batch(timer, empty_address, state, warmup, state.x[0])
            overhead_calls, overhead_calibration = calibrate(empty_address, state, state.x[0])
            overhead = distribution([measured_batch(timer, empty_address, state, overhead_calls, state.x[0])
                                     for _ in range(trials)], overhead_calls)
        for benchmark in benchmarks:
            native_address = stack.enter_context(executable(benchmark["native"]))
            native_function = C_FUNCTION(native_address)
            c_function = getattr(library, benchmark["name"])
            c_function.argtypes = [ctypes.POINTER(State)]
            c_function.restype = None
            c_address = ctypes.cast(c_function, ctypes.c_void_p).value
            # Zero and tiny/boundary counts plus all 16 initial NZCV values.
            for count in (0, 1, 2, 16, 64, 256, 1024):
                for index, original in enumerate(all_states):
                    state = initial_state(original, ram_address, count, edge_seeds[index % len(edge_seeds)])
                    expected = reference(benchmark["source"], state, (ram_address, original_ram))
                    if expected["x"][0] != independent_sum(benchmark["name"], count, state, original_ram):
                        raise AssertionError("original ARM differs from independent sum contract")
                    for function in (native_function, c_function):
                        actual_state = State.from_buffer_copy(state)
                        region[:] = original_ram
                        function(ctypes.byref(actual_state))
                        if state_result(actual_state, region) != expected:
                            raise AssertionError(f"native benchmark correctness failed: {benchmark['name']}, {count}, {index}")
                        comparisons += 1
            if verify_only:
                continue
            for count in COUNTS:
                initial = initial_state(all_states[0], ram_address, count, 0x123456789abcdef0)
                expected = reference(benchmark["source"], initial, (ram_address, original_ram))
                expected_sum = independent_sum(benchmark["name"], count, initial, original_ram)
                functions = {"stela": native_address, "clang_o3": c_address}
                samples = {key: [] for key in functions}
                for pointer in functions.values():
                    warm_state = State.from_buffer_copy(initial)
                    region[:] = original_ram
                    measured_batch(timer, pointer, warm_state, warmup, expected_sum)
                    if state_result(warm_state, region) != expected:
                        raise AssertionError("warmup changed repeated-call semantics")
                pilot_state = State.from_buffer_copy(initial)
                region[:] = original_ram
                case_calls, calibration = calibrate(c_address, pilot_state, expected_sum)
                if state_result(pilot_state, region) != expected:
                    raise AssertionError("calibration changed repeated-call semantics")
                for trial in range(trials):
                    # Alternate order to reduce systematic first/second bias.
                    order = ("stela", "clang_o3") if trial % 2 == 0 else ("clang_o3", "stela")
                    for key in order:
                        state = State.from_buffer_copy(initial)
                        region[:] = original_ram
                        samples[key].append(measured_batch(timer, functions[key], state, case_calls, expected_sum))
                        if state_result(state, region) != expected:
                            raise AssertionError("timed repetitions changed final register/RAM state")
                entry = {"workload": benchmark["name"], "iterations_or_elements": count,
                         "ordinary_ram_bytes_per_input": 0 if benchmark["name"] == "bench_integer" else count * 8,
                         "expected_result": expected_sum, "calibration": calibration,
                         **{key: distribution(value, case_calls) for key, value in samples.items()}}
                entry["stela_over_clang_o3_median_ratio"] = entry["stela"]["median_ns_per_call"] / entry["clang_o3"]["median_ns_per_call"]
                results.append(entry)
    return {"correctness_comparisons": comparisons, "timings": results,
            "timed_native_calls": sum(entry["stela"]["calls_per_trial"] * 2 * trials for entry in results),
            "warmup_native_calls": len(results) * 2 * warmup,
            "correctness_native_calls": comparisons,
            "empty_call_overhead": overhead,
            "empty_overhead_calibration": overhead_calibration,
            "calibration_native_calls": calibration_calls,
            "timer_reported_resolution_ns": timer_resolution,
            "observed_elapsed_gcd_ns": math.gcd(*(sample for entry in results for key in ("stela", "clang_o3")
                                                  for sample in entry[key]["trial_elapsed_ns"])) if results else None,
            "empty_overhead_timed_calls": 0 if verify_only else trials * overhead["calls_per_trial"],
            "empty_overhead_warmup_calls": 0 if verify_only else warmup}


def worker(pipe, arguments):
    try:
        pipe.send(execute(*arguments))
    except BaseException as error:
        pipe.send({"error": repr(error)})
    finally:
        pipe.close()


def bounded_execute(arguments, timeout):
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=worker, args=(send, arguments))
    process.start()
    send.close()
    try:
        deadline = time.monotonic() + timeout
        while not receive.poll(0.25):
            if process.exitcode is not None or time.monotonic() >= deadline:
                raise RuntimeError(f"benchmark worker failed/timed out: exit={process.exitcode}")
        result = receive.recv()
        process.join(2)
        if process.exitcode != 0 or "error" in result:
            raise RuntimeError(f"benchmark worker failed: {result}, exit={process.exitcode}")
        return result
    finally:
        if process.is_alive():
            process.kill()
        process.join()
        receive.close()


def cpu_metadata():
    if platform.system() == "Darwin":
        return command(["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"]).strip()
    lines = Path("/proc/cpuinfo").read_text().splitlines()
    return next((line.split(":", 1)[1].strip() for line in lines if line.startswith("model name")), platform.processor())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--calls", type=int, default=20000)
    parser.add_argument("--min-trial-ms", type=float, default=2.0)
    parser.add_argument("--max-calls", type=int, default=10000000)
    parser.add_argument("--warmup", type=int, default=2000)
    parser.add_argument("--trials", type=int, default=7)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--clang", default="/usr/bin/clang")
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if platform.machine() not in ("x86_64", "AMD64") or platform.system() not in ("Darwin", "Linux"):
        parser.error("benchmarks require native x86-64 macOS or Linux")
    if not 1 <= args.calls <= 10000000 or not 1 <= args.warmup <= 1000000 or not 3 <= args.trials <= 31 or not 1 <= args.timeout <= 3600 or not args.calls <= args.max_calls <= 10000000 or not 0 <= args.min_trial_ms <= 100:
        parser.error("calls/warmup/trials/timeout exceed bounded research limits")
    subprocess.run([str(ROOT / "dev/cargo"), "build", "--locked", "-p", "stela-cli"], check=True, timeout=180)
    artifacts = ROOT / ".stela/benchmarks/artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    import tempfile
    directory = Path(tempfile.mkdtemp(prefix="native-leaves-", dir=artifacts))
    benchmarks, metadata = prepare(directory, args.clang)
    result = bounded_execute((benchmarks, metadata, args.calls, args.warmup, args.trials, args.verify_only, args.min_trial_ms, args.max_calls), args.timeout)
    cli = ROOT / "target/debug/stela"
    if digest(cli) != metadata["stela_executable_sha256"]:
        raise AssertionError("Stela CLI changed during benchmark run")
    report = {"kind": "native_leaf_microbenchmark", "passed": True, "timing_completed": not args.verify_only,
              "environment": {"cpu": cpu_metadata(), "platform": platform.platform(), "machine": platform.machine(),
                              "python": platform.python_version(), "timer": "C clock_gettime CLOCK_MONOTONIC_RAW where available, else CLOCK_MONOTONIC"},
              **metadata, "benchmarks": [{key: value for key, value in item.items() if key not in ("source", "native")} for item in benchmarks],
              "settings": {"pilot_calls": args.calls, "min_baseline_trial_ms": args.min_trial_ms, "maximum_calls_per_trial": args.max_calls, "warmup_calls_per_case_per_implementation": args.warmup,
                           "trials": args.trials, "counts": list(COUNTS), "calibration_scope": "One optimizing-C pilot per case selects the same call count for both timed implementations, targeting baseline duration subject to cap. Raw pilot calls/time retained separately; no timing subtraction."}, **result,
              "ratio_interpretation": "Stela/clang-O3 median time: above 1 means Stela is slower on this fixture.",
              "empty_overhead_scope": "clang-compiled empty function through the same C indirect-call/checksum batch, reported for context only; never subtracted from workload timings.",
              "timing_scope": "Warm RX code and ordinary RAM, C batches indirect function calls plus checksum/state reads. Python, Unicorn, correctness comparison and compilation are outside native execution timers. No CPU pinning or frequency control; short trials and host noise limit precision. Trial order alternates; raw times and spread retained. C reference is an optimizing compiler baseline, not Rosetta performance.",
              "correctness_scope": "Original ARM Unicorn versus each native implementation: all x0..x30, SP, all16 NZCV initial combinations, entire64KiB RAM; seven counts0..1024 plus arithmetic seed edges. Independent result sums, warmup and repeated-call final-state checks.",
              "limits": "Three own microfixtures with the memory-backed GuestState/direct-RAM ABI, fixed count at most1024, disjoint aligned input/output/state, finite execution. No application, OS, boot, PAC, SIMD translation, runtime helper, syscall, concurrent invalidation or cross-ISA hardware performance claim. Optimizing C may strength-reduce/vectorize these loops; current Stela retains guest-register memory traffic."}
    output = args.output or ROOT / ".stela/benchmarks" / ("leaf-correctness.json" if args.verify_only else "leaf-baseline.json")
    snapshot = write_evidence(output, report)
    print(json.dumps({"report": str(output), "evidence": str(snapshot), "timing_completed": report["timing_completed"],
                      "correctness_comparisons": result["correctness_comparisons"], "benchmark_cases": len(result["timings"]),
                      "timed_native_calls": result["timed_native_calls"],
                      "stela_over_clang_ratios": [{"workload": entry["workload"], "count": entry["iterations_or_elements"],
                                                    "ratio": entry["stela_over_clang_o3_median_ratio"]} for entry in result["timings"]]}, indent=2))


if __name__ == "__main__":
    main()

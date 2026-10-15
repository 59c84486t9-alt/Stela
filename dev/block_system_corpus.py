"""Shared source-bound launcher for focused Rust System block corpora.

Family adapters own original schemas and comparisons. This module only builds or
checks one exact runtime test executable, invokes its ignored corpus, and binds
unchanged source/evidence inputs. It never replays old receipts as fresh results.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess

BUILD_KIND = 'system_runtime_corpus_build_v1'
RUNTIME_CRATES = ('stela-core', 'stela-compiler', 'stela-runtime')


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def runtime_source_inventory(root, additional=()):
    """Include build manifests and every current Rust source, including additions."""
    root = Path(root).resolve()
    paths = [root / name for name in ('Cargo.lock', 'Cargo.toml', 'rust-toolchain.toml', 'dev/cargo')]
    crates = list(RUNTIME_CRATES)
    optional = root / 'crates/stela-state'
    if optional.exists():
        assert optional.is_dir() and (optional / 'Cargo.toml').is_file() and (optional / 'src').is_dir(), 'Incomplete canonical stela-state crate'
        crates.append('stela-state')
    for crate in crates:
        directory = root / 'crates' / crate
        assert (directory / 'Cargo.toml').is_file() and (directory / 'src').is_dir(), 'Incomplete runtime source crate'
        paths.append(directory / 'Cargo.toml')
        if (directory / 'build.rs').exists():
            assert (directory / 'build.rs').is_file(), 'Invalid crate build script'
            paths.append(directory / 'build.rs')
        paths.extend(sorted((directory / 'src').rglob('*.rs')))
    paths.extend(Path(path).resolve() for path in additional)
    return {str(path.relative_to(root)): sha256(path) for path in sorted(set(paths))}


def require_build_binding(binding, family, executable, inventory):
    assert binding['kind'] == BUILD_KIND, 'Expected a focused System corpus build binding'
    assert binding['family'] == family, 'Runtime executable was bound for another corpus family'
    assert binding['runtime_test_executable_sha256'] == sha256(executable), 'Runtime test executable changed'
    assert binding['source_before_after_sha256'] == inventory, 'Runtime build source closure differs'


def run_runtime_corpus(root, *, family, test_name, environment, report_path, output_dir,
                       source_inventory, frozen_inputs, no_build,
                       runtime_test_executable=None, runtime_build_binding=None):
    """Run one exact ignored test. source_inventory is a fresh callable mapping.

    The family supplies all original dependency hashes and owns output validation.
    A --no-build caller must supply the matching executable AND source binding.
    """
    root, output_dir = Path(root).resolve(), Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    inventory = source_inventory()
    frozen = {Path(path).resolve(): digest for path, digest in frozen_inputs.items()}
    assert all(sha256(path) == digest for path, digest in frozen.items()), 'Original input changed before launch'
    if not no_build:
        command = [str(root / 'dev/cargo'), 'test', '--locked', '-p', 'stela-runtime',
                   '--lib', '--no-run', '--message-format=json']
        build = subprocess.run(command, cwd=root, capture_output=True, text=True, check=False)
        (output_dir / 'build.stdout').write_text(build.stdout)
        (output_dir / 'build.stderr').write_text(build.stderr)
        assert build.returncode == 0, 'Runtime corpus build failed; see retained logs'
        artifacts = [json.loads(line) for line in build.stdout.splitlines() if line.startswith('{')]
        executables = [row['executable'] for row in artifacts
                       if row.get('reason') == 'compiler-artifact' and row.get('executable')
                       and row['target']['name'] == 'stela_runtime' and row['profile']['test']]
        assert len(executables) == 1, 'Expected one runtime library test executable'
        runtime_test_executable = Path(executables[0]).resolve()
        assert source_inventory() == inventory, 'Source inventory changed during build'
        binding = {'kind': BUILD_KIND, 'family': family, 'command': command,
                   'runtime_test_executable_sha256': sha256(runtime_test_executable),
                   'build_stdout_sha256': sha256(output_dir / 'build.stdout'),
                   'build_stderr_sha256': sha256(output_dir / 'build.stderr'),
                   'source_before_after_sha256': inventory}
        runtime_build_binding = output_dir / 'build-source.json'
        runtime_build_binding.write_text(json.dumps(binding, indent=2) + '\n')
    assert runtime_test_executable is not None, '--no-build requires --runtime-test-executable'
    assert runtime_build_binding is not None, '--no-build requires --runtime-build-binding'
    executable = Path(runtime_test_executable).resolve()
    binding_path = Path(runtime_build_binding).resolve()
    binding = json.loads(binding_path.read_text())
    require_build_binding(binding, family, executable, inventory)
    frozen.update({executable: sha256(executable), binding_path: sha256(binding_path)})
    command = [str(executable), '--exact', test_name, '--ignored', '--test-threads=1']
    env = dict(os.environ, **{key: str(value) for key, value in environment.items()})
    with (output_dir / 'runtime.stdout').open('xb') as stdout, (output_dir / 'runtime.stderr').open('xb') as stderr:
        result = subprocess.run(command, cwd=root, env=env, stdout=stdout, stderr=stderr, timeout=120)
    assert result.returncode == 0, 'Runtime corpus failed; see retained logs'
    report = json.loads(Path(report_path).read_text())
    assert report['passed'], 'Runtime corpus did not report success'
    for relative, digest in report['compiled_sources_sha256'].items():
        assert inventory[relative] == digest, 'Compiled runtime source identity differs'
    assert source_inventory() == inventory, 'Source inventory changed during corpus execution'
    assert all(sha256(path) == digest for path, digest in frozen.items()), 'Frozen evidence inputs changed'
    return report, {'runtime_test_executable_sha256': frozen[executable],
                    'runtime_build_binding_sha256': frozen[binding_path],
                    'shared_sources_sha256': inventory, 'command': command,
                    'new_original_captures': 0}

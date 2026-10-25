#!/usr/bin/env python3
"""Compiled regression controls for the N1–N4 compiler integration.

Every source is compiled before policy is applied. Foreign declarations are never
executed. Configuration uses Clippy's DefId map; assertions inspect compiler
reports and diagnostics, never source names or an operation/symbol table.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent.parent
CASES = {
    'substituted-attribute': {'N3'},
    'extern-crate-alias-dormant': set(),
    'extern-crate-alias-invoked': {'clippy::disallowed_methods'},
    'qualified-reexport-failed-target': {'N4'},
    'conditional-binding': {'N2', 'N4'},
    'foreign-temporary': {'N2'},
    'operation-completeness': {'clippy::disallowed_methods', 'clippy::disallowed_types'},
    'accepted-retyping': set(),
}


def cargo(project, env, *args):
    return subprocess.run(['flock', '/tmp/muse-cargo.lock', 'cargo', '+1.98.0', *args], cwd=project,
                          env={**env, 'CARGO_BUILD_JOBS': '2'}, capture_output=True, text=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    default_driver = Path(os.environ.get('INTERNAL_READ_DRIVER', str(Path(os.environ.get('CARGO_HOME', str(Path.home() / '.cargo'))) / 'internal-read-clippy/target/debug/clippy-driver')))
    parser.add_argument('--driver', type=Path, default=default_driver)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    driver = args.driver.resolve()
    if not driver.is_file():
        parser.error('built policy Clippy driver required')
    base_env = {k: v for k, v in os.environ.items() if not k.startswith(('INTERNAL_READ_', 'CLIPPY_')) and k not in {'RUSTC_WORKSPACE_WRAPPER', 'RUSTC_WRAPPER', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS'}}
    sysroot = subprocess.check_output(['rustc', '+1.98.0', '--print', 'sysroot'], text=True).strip()
    base_env['LD_LIBRARY_PATH'] = str(Path(sysroot) / 'lib') + (':' + base_env['LD_LIBRARY_PATH'] if base_env.get('LD_LIBRARY_PATH') else '')
    summary = []
    with tempfile.TemporaryDirectory(prefix='internal-read-controls-') as temporary:
        project = Path(temporary)
        (project / 'Cargo.toml').write_text('''[package]
name = "ratarmount-index"
version = "0.0.0"
edition = "2024"
[dependencies]
rustix = { version = "=1.1.5", features = ["fs"] }
[lib]
path = "lib.rs"
[workspace]
''')
        policy = json.loads((HERE / 'policy.json').read_text())
        policy['reviewed_target_files'] = []
        (project / 'policy.json').write_text(json.dumps(policy))
        conf = project / 'conf'
        conf.mkdir()
        shutil.copyfile(HERE / 'clippy.toml', conf / 'clippy.toml')
        for case, expected in CASES.items():
            source = (HERE / 'fixtures/controls' / f'{case}.rs').read_text()
            source = '#![allow(clippy::missing_safety_doc)]\n' + source
            (project / 'lib.rs').write_text(source)
            check = cargo(project, base_env, 'check', '--offline', '--lib', '--all-features', '--message-format=json')
            if check.returncode:
                raise AssertionError(f'{case}: baseline failed to compile:\n{check.stderr}\n{check.stdout}')
            report = project / f'{case}.jsonl'
            flags = ['-Dwarnings', '-Dclippy::disallowed_methods', '-Dclippy::disallowed_types', '-Dclippy::disallowed_macros', '-Dunfulfilled_lint_expectations', '--cfg', 'internal_read_inventory', '--check-cfg=cfg(internal_read_inventory)']
            env = {**base_env, 'RUSTC_WORKSPACE_WRAPPER': str(driver), 'CLIPPY_ARGS': '__CLIPPY_HACKERY__'.join(flags), 'CLIPPY_CONF_DIR': str(conf), 'INTERNAL_READ_REPORT': str(report), 'INTERNAL_READ_CONFIG': str(project / 'policy.json'), 'INTERNAL_READ_ROOT': str(project), 'RUSTC_BOOTSTRAP': '1', 'CARGO_TARGET_DIR': str(project / 'policy-target')}
            run = cargo(project, env, 'check', '--offline', '--lib', '--all-features', '--message-format=json')
            events = [json.loads(line) for line in report.read_text().splitlines()] if report.exists() else []
            mechanisms = {event['policy'] for event in events if event.get('kind') == 'syntax'}
            if any(event.get('kind') == 'foreign_block' and not event.get('allowed') for event in events):
                mechanisms.add('N2')
            disallowed_codes = []
            for line in run.stdout.splitlines():
                message = json.loads(line)
                diagnostic = message.get('message', {})
                code = diagnostic.get('code') or {}
                if code.get('code', '').startswith('clippy::disallowed_'):
                    mechanisms.add(code['code'])
                    disallowed_codes.append(code['code'])
            if case == 'operation-completeness':
                assert disallowed_codes.count('clippy::disallowed_methods') == 7, disallowed_codes
                assert disallowed_codes.count('clippy::disallowed_types') == 1, disallowed_codes
            independent = None
            # An early N4 error stops rustc before the mandatory late HIR N2
            # pass. Review only this fixture's target predicates in a second
            # compilation to prove the foreign block independently fails N2.
            if case == 'conditional-binding' and 'N2' not in mechanisms:
                policy['reviewed_target_files'] = [{'file': 'lib.rs', 'reviewer': 'compiled control', 'reason': 'Expose the independent HIR N2 rejection after the primary N4 refusal.'}]
                (project / 'policy.json').write_text(json.dumps(policy))
                independent_report = project / 'conditional-independent.jsonl'
                independent_env = {**env, 'INTERNAL_READ_REPORT': str(independent_report), 'CARGO_TARGET_DIR': str(project / 'independent-target')}
                independent_run = cargo(project, independent_env, 'check', '--offline', '--lib', '--all-features', '--message-format=json')
                independent_events = [json.loads(line) for line in independent_report.read_text().splitlines()]
                independent_n2 = any(event.get('kind') in {'foreign_block', 'raw_foreign'} and not event.get('allowed') for event in independent_events)
                if independent_run.returncode and independent_n2:
                    mechanisms.add('N2')
                independent = {'policy_exit': independent_run.returncode, 'N2_refused': independent_n2}
                policy['reviewed_target_files'] = []
                (project / 'policy.json').write_text(json.dumps(policy))
            if bool(run.returncode) != bool(expected) or not expected.issubset(mechanisms):
                raise AssertionError(f'{case}: wanted {sorted(expected)}, observed exit={run.returncode}, mechanisms={sorted(mechanisms)}\n{run.stderr}\n{run.stdout}')
            summary.append({'fixture': case, 'check_exit': check.returncode, 'policy_exit': run.returncode, 'observed_mechanisms': sorted(mechanisms), 'expected_mechanisms': sorted(expected), 'disallowed_diagnostic_counts': {code: disallowed_codes.count(code) for code in sorted(set(disallowed_codes))}, 'independent_compilation': independent, 'accepted_gap': case in {'extern-crate-alias-dormant', 'accepted-retyping'}})
    result = {'schema': 1, 'scope': 'Compiled production libraries; declarations are not executed.', 'cases': summary}
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

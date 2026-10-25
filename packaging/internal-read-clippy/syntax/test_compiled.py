#!/usr/bin/env python3
"""Regression: compiler-loaded pre-cfg syntax and exact foreign-module authority.

This exercises the actual policy driver. The harness writes explicit fixture
inputs, and rustc chooses the loaded modules. It never discovers production
source, resolves imports, or classifies calls.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    sysroot = subprocess.check_output(['rustc', '+1.98.0', '--print', 'sysroot'], text=True).strip()
    results = []
    with tempfile.TemporaryDirectory(prefix='internal-read-syntax-') as temporary:
        root = Path(temporary)
        (root / 'conf').mkdir()
        (root / 'conf/clippy.toml').write_text('disallowed-methods=[{path="std::fs::read",reason="inventory-op:fs::read"}]\n')
        config = json.loads((HERE / 'policy.json').read_text())
        config['allowed_extern_module'] = 'control::ffi'
        config['reviewed_target_files'] = []
        config['include_exceptions'] = []
        policy = root / 'policy.json'
        env = {**os.environ, 'CARGO_PKG_NAME': 'ratarmount-index', 'CARGO_CRATE_NAME': 'control', 'INTERNAL_READ_ROOT': str(root), 'INTERNAL_READ_CONFIG': str(policy), 'CLIPPY_CONF_DIR': str(root / 'conf'), 'RUSTC_BOOTSTRAP': '1', 'LD_LIBRARY_PATH': str(Path(sysroot) / 'lib')}
        def run(name, source, *, reject=None, files=None, reviewed=False, root_forbid=True, native=True, allow_ffi=False):
            config['allowed_extern_module'] = 'control::ffi' if allow_ffi else 'reviewed::ffi'
            config['reviewed_target_files'] = [{'file': 'custom-root.rs', 'reviewer': 'compiled fixture', 'reason': 'Test exact reviewed-file behavior independently of N2.'}] if reviewed else []
            policy.write_text(json.dumps(config))
            for file, content in (files or {}).items():
                path = root / file
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            src = root / 'custom-root.rs'
            src.write_text(('#![forbid(unused_macros)]\n' if root_forbid else '') + source + '\n')
            common = [str(src), '--crate-name=control', '--crate-type=lib', '--edition=2024', '--emit=metadata', '--out-dir', str(root)]
            if native:
                check = subprocess.run(['rustc', '+1.98.0', *common], env=env, capture_output=True, text=True)
                assert check.returncode == 0, (name, 'fixture must compile before enforcement', check.stderr)
            report = root / 'report.jsonl'
            env['INTERNAL_READ_REPORT'] = str(report)
            done = subprocess.run([str(args.driver.resolve()), *common, '-Dclippy::disallowed_methods', '-Dclippy::disallowed_types', '-Dclippy::disallowed_macros'], env=env, capture_output=True, text=True)
            events = [json.loads(line) for line in report.read_text().splitlines()] if report.exists() else []
            observed = {row.get('policy') for row in events if row.get('kind') == 'syntax'}
            observed.update('N2' for row in events if row.get('kind') in {'foreign_block', 'link_name', 'raw_n2'} and not row.get('allowed'))
            # N2 is a compiler hard diagnostic after exact HIR module lookup.
            if 'N2 ' in done.stderr or 'N2:' in done.stderr:
                observed.add('N2')
            assert bool(done.returncode) == bool(reject), (name, done.returncode, done.stderr)
            if reject:
                assert reject in observed, (name, reject, sorted(str(x) for x in observed), done.stderr)
            (args.output / f'{name}.stderr').write_text(done.stderr)
            (args.output / f'{name}.jsonl').write_text(report.read_text() if report.exists() else '')
            results.append({'name': name, 'compiled': native, 'exit': done.returncode, 'expected': reject or 'accept', 'observed': sorted(str(x) for x in observed)})
            return events
        # N3 checks macro grammar before cfg substitution or invocation.
        run('substituted-attribute', 'macro_rules! m { ($g:meta) => { #[$g] pub fn hidden() {} } } m!(cfg(not(clippy)));', reject='N3')
        run('repeated-attribute', '#[macro_export] macro_rules! m { ($($g:meta),*) => { $(#[$g])* pub fn hidden() {} } }', reject='N3')
        run('generic-attribute-matcher', '#[macro_export] macro_rules! m { (#[$g:meta]) => { pub fn visible() {} } }')
        run('nested-generic-attribute-matcher', '#[macro_export] macro_rules! outer { () => { macro_rules! inner { (#[$g:meta]) => { pub fn visible() {} } } } }')
        run('literal-cfg-matcher', '#[macro_export] macro_rules! m { (#[cfg(unix)]) => {} }', reject='N3')
        run('raw-cfg-transcriber', '#[macro_export] macro_rules! m { () => { #[r#cfg(unix)] pub fn hidden() {} } }', reject='N3')
        run('nested-cfg-macro', '#[macro_export] macro_rules! outer { () => { macro_rules! inner { () => { #[cfg_attr(all(),allow(dead_code))] pub fn hidden() {} } } } }', reject='N3')
        # N2 does not inspect a foreign declaration's name or optional ABI text.
        for name, matcher, head, args_text in [
            ('optional-abi', '$kw:ident $($abi:literal)?', 'unsafe $kw $($abi)?', 'extern "C"'),
            ('repeated-abi', '$kw:ident $($abi:literal)*', 'unsafe $kw $($abi)*', 'extern "C"'),
            ('omitted-abi', '$kw:ident', 'unsafe $kw', 'extern'),
            ('attribute-head', '$kw:ident', '#[allow(dead_code)] unsafe $kw', 'extern'),
        ]:
            run(name, f'macro_rules! m {{ ({matcher}) => {{ {head} {{ pub fn any_foreign_name(); }} }} }} m!({args_text});', reject='N2')
        run('ordinary-abi-functions-types', 'pub extern "C" fn callback() {} pub type Callback = extern "C" fn(); extern crate std as alias;')
        run('arbitrary-link-name', 'unsafe extern "C" { #[link_name="arbitrary_not_an_operation_table"] pub fn callback(); }', reject='N2')
        run('cfg-attr-link-name', 'unsafe extern "C" { #[cfg_attr(all(),link_name="arbitrary")] pub fn callback(); }', reject='N2')
        run('external-exact-ffi', '#[path="ffi-body.rs"] pub mod ffi;', files={'ffi-body.rs': 'unsafe extern "C" { pub fn arbitrary(); }'}, allow_ffi=True)
        run('external-ffi-sibling-reuse', '#[path="ffi-body.rs"] pub mod ffi; #[path="ffi-body.rs"] pub mod sibling;', files={'ffi-body.rs': 'unsafe extern "C" { pub fn arbitrary(); }'}, reject='N2', allow_ffi=True)
        run('inactive-ffi-child', 'pub mod ffi { #[cfg(windows)] pub mod child { unsafe extern "C" { pub fn arbitrary(); } } }', reject='N2', reviewed=True, allow_ffi=True)
        foreign_macro = '#[macro_export] macro_rules! foreign { () => { unsafe extern "C" { pub fn arbitrary(); } } }'
        run('foreign-macro-root-owner', 'pub mod ffi {' + foreign_macro + '} crate::foreign!();', reject='N2', allow_ffi=True)
        run('foreign-macro-sibling-owner', 'pub mod ffi {' + foreign_macro + '} pub mod sibling { crate::foreign!(); }', reject='N2', allow_ffi=True)
        run('foreign-macro-child-owner', 'pub mod ffi {' + foreign_macro + 'pub mod child { crate::foreign!(); }}', reject='N2', allow_ffi=True)
        run('foreign-macro-exact-owner', 'pub mod ffi {' + foreign_macro + 'crate::foreign!();}', allow_ffi=True)
        run('foreign-link-name-root-owner', 'pub mod ffi { #[macro_export] macro_rules! foreign { () => { unsafe extern "C" { #[link_name="any_name"] pub fn arbitrary(); } } } } crate::foreign!();', reject='N2', allow_ffi=True)
        env['OUT_DIR'] = str(root / 'generated')
        for name, text in [('explicit', 'unsafe extern "C" { pub fn arbitrary(); }'), ('omitted', 'unsafe extern { pub fn arbitrary(); }')]:
            run('generated-foreign-' + name, 'include!(concat!(env!("OUT_DIR"),"/foreign.rs"));', files={'generated/foreign.rs': text}, reject='N2')
        # N4 sees loaded source before target pruning, with test/feature context.
        payload = '#[cfg(windows)] pub fn windows_only() {}\n'
        for path in ['tests/reader.rs', 'vendor/reader.rs', 'build.rs']:
            events = run('loaded-' + path.replace('/', '-').replace('.', '-'), f'#[path="{path}"] mod production;', files={path: payload}, reject='N4')
            assert any(row.get('kind') == 'target_predicate' and row.get('span', {}).get('file') == path for row in events)
        run('unloaded-test-module', '#[cfg(test)] #[path="does-not-exist.rs"] mod tests;')
        run('loaded-test-subtree', '#[path="loaded.rs"] mod production;', files={'loaded.rs': '#[cfg(test)] mod tests { unsafe extern "C" { pub fn arbitrary(); } #[cfg(windows)] fn hidden(){} #[macro_export] macro_rules! ignored { () => { #[cfg(unix)] fn hidden(){} } } }'})
        run('unloaded-feature-module', '#[cfg(feature="off")] #[path="does-not-exist.rs"] mod dormant;')
        run('nested-cfg-attr-target', '#[cfg_attr(all(),cfg_attr(all(),cfg(target_os="windows")))] pub fn hidden() {}', reject='N4')
        run('raw-target-predicate', '#[cfg(r#target_os="windows")] pub fn hidden() {}', reject='N4')
        run('target-cfg-macro', 'pub fn target() -> bool { cfg!(all(unix,target_family="unix")) }', reject='N4')
        run('feature-only-predicate', '#[cfg(feature="off")] pub fn hidden() {}')
        run('target-attribute-not-predicate', '#[cfg_attr(feature="simd",target_feature(enable="sse2"))] pub fn visible() {}')
        run('reviewed-file-before-edit', '#[cfg(windows)] pub fn hidden() {}', reviewed=True)
        run('reviewed-file-unrelated-edit', '// unrelated edit\n#[cfg(windows)] pub fn hidden() {}\npub fn extra() {}', reviewed=True)
        run('custom-root-missing-forbid', 'pub fn visible() {}', reject='N3', root_forbid=False)
        run('reserved-cfg', '#[cfg(internal_read_inventory)] pub fn hidden() {}', reject='EXPECT')
        run('reserved-raw-cfg', '#[cfg(r#internal_read_inventory)] pub fn hidden() {}', reject='EXPECT')
        run('reserved-cfg-macro', 'pub fn hidden() -> bool { cfg!(internal_read_inventory) }', reject='EXPECT')
    (args.output / 'summary.json').write_text(json.dumps(results, indent=2) + '\n')
    print(f'{len(results)} compiled syntax regressions passed')


if __name__ == '__main__':
    main()

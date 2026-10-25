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
        def run(name, source, *, reject=None, files=None, reviewed=False, root_forbid=True, native=True, allow_ffi=False, reject_detail=None, flags=()):
            config['allowed_extern_module'] = 'control::ffi' if allow_ffi else 'reviewed::ffi'
            config['reviewed_target_files'] = [{'file': 'custom-root.rs', 'reviewer': 'compiled fixture', 'reason': 'Test exact reviewed-file behavior independently of N2.'}] if reviewed else []
            policy.write_text(json.dumps(config))
            for file, content in (files or {}).items():
                path = root / file
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            src = root / 'custom-root.rs'
            src.write_text(('#![forbid(unused_macros)]\n' if root_forbid else '') + source + '\n')
            common = [str(src), '--crate-name=control', '--crate-type=lib', '--edition=2024', '--emit=metadata', '--out-dir', str(root), *flags]
            if native:
                check = subprocess.run(['rustc', '+1.98.0', *common], env=env, capture_output=True, text=True)
                assert check.returncode == 0, (name, 'fixture must compile before enforcement', check.stderr)
            report = root / 'report.jsonl'
            env['INTERNAL_READ_REPORT'] = str(report)
            done = subprocess.run([str(args.driver.resolve()), *common, '--error-format=json', '-Dclippy::disallowed_methods', '-Funused_macros', '-Dclippy::disallowed_types', '-Dclippy::disallowed_macros'], env=env, capture_output=True, text=True)
            events = [json.loads(line) for line in report.read_text().splitlines()] if report.exists() else []
            observed = {row.get('policy') for row in events if row.get('kind') == 'syntax'}
            observed.update('N2' for row in events if row.get('kind') in {'foreign_block', 'link_name', 'raw_n2'} and not row.get('allowed'))
            # N2 is a compiler hard diagnostic after exact HIR module lookup.
            if 'N2 ' in done.stderr or 'N2:' in done.stderr:
                observed.add('N2')
            if reject == 'Clippy':
                assert any(row.get('kind') == 'operation' and row.get('resolved') == 'std::fs::read' and row.get('lint') == 'clippy::disallowed_methods' for row in events), (name, events, done.stderr)
                assert any(json.loads(line).get('code', {}) and json.loads(line)['code']['code'] == 'clippy::disallowed_methods' for line in done.stderr.splitlines() if line.startswith('{')), (name, done.stderr)
                observed.add('Clippy')
            assert bool(done.returncode) == bool(reject), (name, done.returncode, done.stderr)
            if reject:
                assert reject in observed, (name, reject, sorted(str(x) for x in observed), done.stderr)
                if reject == 'N4' or reject_detail:
                    detail = reject_detail or 'target predicate outside reviewed file'
                    assert reject + ': ' + detail in done.stderr, (name, detail, done.stderr)
            elif done.returncode == 0:
                assert not any(row.get('kind') == 'syntax' for row in events), (name, events)
            (args.output / f'{name}.stderr').write_text(done.stderr)
            (args.output / f'{name}.jsonl').write_text(report.read_text() if report.exists() else '')
            results.append({'name': name, 'compiled': native, 'exit': done.returncode, 'expected': reject or 'accept', 'observed': sorted(str(x) for x in observed)})
            return events
        # Regression: substituting the macro_rules keyword must not generate an
        # unaudited macro whose substituted attribute hides a fixed read.
        for predicate, suffix in [('not(clippy)', 'not-clippy'), ('windows', 'windows')]:
            run('substituted-macro-keyword-' + suffix, '''macro_rules! make {
                ($kw:ident $d:tt) => {
                    $kw! hidden {
                        ($d h:tt $d a:tt) => {
                            $d h $d a pub fn hidden() { let _ = std::fs::read("x"); }
                        }
                    }
                }
            }
            make!(macro_rules $);
            hidden!(# [cfg(''' + predicate + ''')]);''', reject='N3',
                reject_detail='metavariable macro invocation head')
        # A directly written definition still receives the ordinary body audit.
        run('literal-top-level-macro-definition',
            'macro_rules! visible { () => { pub fn visible() -> u8 { 7 } }; } visible!();')
        # Every opaque token stream is checked, even if a macro discards it.
        for name, payload in [('bare-keyword', 'macro_rules'),
                              ('nested-keyword', '(macro_rules)'),
                              ('substituted-head', '$head ! ()')]:
            run('discarded-' + name,
                'macro_rules! ignore { ($($t:tt)*) => {}; } ignore! { ' + payload + ' }',
                reject='N3')
        run('discarded-keyword-in-inactive-body',
            '#[cfg(any())] pub fn hidden() { ignore!(macro_rules); }', reject='N3')
        run('keyword-in-root-attribute', '#![doc = stringify!(macro_rules)]', reject='N3')
        run('keyword-in-item-attribute', '#[doc = stringify!(macro_rules)] pub fn visible() {}', reject='N3')
        run('keyword-in-declarative-macro-body',
            '#![feature(decl_macro)] pub macro ignored($($t:tt)*) { stringify!(macro_rules) }', reject='N3')
        run('substituted-declarative-macro-head',
            '#![feature(decl_macro)] pub macro invoke($head:ident) { $head ! () }', reject='N3')
        # Regression: -D must permit reviewed direct expects, but source cannot
        # lower the acquisition lint or hide an approval in cfg_attr.
        for reviewed in (False, True):
            suffix = '-reviewed' if reviewed else ''
            for scope, wrap in [
                ('crate', lambda attr: '#![' + attr + '] pub fn visible() {}'),
                ('module', lambda attr: '#[' + attr + '] pub mod nested { pub fn visible() {} }'),
                ('item', lambda attr: '#[' + attr + '] pub fn visible() {}'),
            ]:
                for level in ('allow', 'warn'):
                    run('source-' + level + '-' + scope + suffix,
                        wrap(level + '(clippy::disallowed_methods)'),
                        reviewed=reviewed, reject='EXPECT',
                        reject_detail='allow/warn of disallowed lint is refused')
                for predicate in ('all()', 'any()'):
                    run('cfg-attr-expect-' + scope + '-' + predicate + suffix,
                        wrap('cfg_attr(' + predicate + ',expect(clippy::disallowed_methods,reason="review"))'),
                        reviewed=reviewed, reject='EXPECT',
                        reject_detail='cfg_attr-wrapped disallowed lint level is refused')
            run('nested-cfg-attr-warn' + suffix,
                '#[cfg_attr(all(),cfg_attr(any(),warn(clippy::disallowed_methods)))] pub fn visible() {}',
                reviewed=reviewed, reject='EXPECT',
                reject_detail='cfg_attr-wrapped disallowed lint level is refused')
        run('direct-reviewed-expect', 'pub fn load() { #[expect(clippy::disallowed_methods,reason="review")] let _ = std::fs::read("x"); }')
        # Regression: unsupported subjects also need fail-closed review, even
        # when a reviewed Windows cfg strips the subject before HIR exists.
        for subject, source in [
            ('field', '#[cfg(windows)] pub struct Hidden { #[expect(clippy::disallowed_types,reason="ordinary review")] field: std::fs::OpenOptions }'),
            ('variant', '#[cfg(windows)] pub enum Hidden { #[expect(clippy::disallowed_methods,reason="ordinary review")] Value }'),
            ('parameter', '#[cfg(windows)] pub fn hidden(#[expect(clippy::disallowed_types,reason="ordinary review")] value: std::fs::OpenOptions) {}'),
            ('crate', '#![cfg(windows)] #![expect(clippy::disallowed_methods,reason="ordinary review")] pub fn hidden() {}'),
        ]:
            run('inactive-unsupported-expect-' + subject, source, reviewed=True,
                reject='EXPECT', reject_detail='inventory expectation must own a narrow statement/type leaf')
        run('test-module-allow-outside-production',
            '#[cfg(test)] #[allow(clippy::disallowed_methods)] mod tests { fn load() { let _ = std::fs::read("x"); } }',
            reject='EXPECT', reject_detail='allow/warn of disallowed lint is refused')
        for group in ('all', 'style'):
            run('source-group-allow-' + group,
                '#![allow(clippy::' + group + ')] pub fn visible() {}',
                reject='EXPECT', reject_detail='allow/warn of disallowed lint is refused')
            run('source-group-expect-' + group,
                '#![expect(clippy::' + group + ',reason="review")] pub fn load() { let _ = std::fs::read("x"); }',
                reject='EXPECT', reject_detail='disallowed lint requires direct expect with literal reason')
            run('macro-group-allow-' + group,
                'macro_rules! m { () => { #[allow(clippy::' + group + ')] pub fn load() { let _ = std::fs::read("x"); } }; } m!();',
                reject='EXPECT', reject_detail='allow/warn of disallowed lint is refused')
        run('macro-literal-allow',
            'macro_rules! m { () => { #[allow(clippy::disallowed_methods)] pub fn load() { let _ = std::fs::read("x"); } }; } m!();',
            reject='EXPECT', reject_detail='allow/warn of disallowed lint is refused')
        run('crate-root-boolean-target',
            '#![cfg_attr(true,cfg(windows))] pub fn load() { let _ = std::fs::read("x"); }',
            reject='N4', reject_detail='cfg_attr predicate or attributes could not be parsed')
        run('crate-root-clippy-stripping',
            '#![cfg(not(clippy))] pub fn load() { let _ = std::fs::read("x"); }',
            reject='N4', reject_detail='clippy cfg predicate hides code from native Clippy')

        # N3 checks macro grammar before cfg substitution or invocation.
        run('substituted-attribute', 'macro_rules! m { ($g:meta) => { #[$g] pub fn hidden() {} } } m!(cfg(not(clippy)));', reject='N3')
        run('repeated-attribute', '#[macro_export] macro_rules! m { ($($g:meta),*) => { $(#[$g])* pub fn hidden() {} } }', reject='N3')
        run('generic-attribute-matcher', '#[macro_export] macro_rules! m { (#[$g:meta]) => { pub fn visible() {} } }')
        run('nested-generic-attribute-matcher', '#[macro_export] macro_rules! outer { () => { macro_rules! inner { (#[$g:meta]) => { pub fn visible() {} } } } }', reject='N3')
        run('literal-cfg-matcher', '#[macro_export] macro_rules! m { (#[cfg(unix)]) => {} }', reject='N3')
        run('raw-cfg-transcriber', '#[macro_export] macro_rules! m { () => { #[r#cfg(unix)] pub fn hidden() {} } }', reject='N3')
        run('nested-cfg-macro', '#[macro_export] macro_rules! outer { () => { macro_rules! inner { () => { #[cfg_attr(all(),allow(dead_code))] pub fn hidden() {} } } } }', reject='N3')
        # Regression: substituted attribute delimiters/prefixes hid a read from
        # native Clippy without a literal bracket group immediately after #.
        hidden_read = 'pub fn hidden() { let _ = std::fs::read("x"); }'
        for name, matcher, attribute, invocation in [
            ('substituted-brackets', '$a:tt', '# $a', '[cfg(windows)]'),
            ('repeated-substituted-brackets', '$($a:tt)*', '$(# $a)*', '[cfg(windows)]'),
            ('substituted-prefix', '$h:tt $a:meta', '$h [$a]', '# cfg(windows)'),
        ]:
            run(name, f'macro_rules! m {{ ({matcher}) => {{ {attribute} {hidden_read} }} }} m!({invocation});', reject='N3')
        run('inner-substituted-brackets', 'macro_rules! m { ($a:tt) => { mod hidden { #! $a ' + hidden_read + ' } } } m!([cfg(windows)]);', reject='N3')
        run('inner-substituted-prefix', 'macro_rules! m { ($h:tt $a:meta) => { mod hidden { $h ! [$a] ' + hidden_read + ' } } } m!(# cfg(windows));', reject='N3')
        # Regression: no subject keyword list may admit substituted attributes
        # on statements, fields, variants or across repetition boundaries.
        for name, source in [
            ('both-substituted-item', 'macro_rules! m { ($h:tt $a:tt) => { $h $a pub fn hidden() { let _ = std::fs::read("x"); } } } m!(# [cfg(windows)]);'),
            ('substituted-statement', 'macro_rules! m { ($h:tt $a:meta) => { pub fn visible() { $h [$a] std::fs::read("x").unwrap(); } } } m!(# cfg(windows));'),
            ('substituted-block', 'macro_rules! m { ($h:tt $a:meta) => { pub fn visible() { $h [$a] { let _ = std::fs::read("x"); } } } } m!(# cfg(windows));'),
            ('substituted-return', 'macro_rules! m { ($h:tt $a:meta) => { pub fn visible() { $h [$a] return { let _ = std::fs::read("x"); }; } } } m!(# cfg(windows));'),
            ('substituted-if', 'macro_rules! m { ($h:tt $a:meta) => { pub fn visible() { $h [$a] if true { let _ = std::fs::read("x"); } } } } m!(# cfg(windows));'),
            ('repeated-substituted-statement', 'macro_rules! m { ($($h:tt $a:meta)*) => { pub fn visible() { $($h [$a])* std::fs::read("x").unwrap(); } } } m!(# cfg(windows));'),
            ('substituted-field', 'macro_rules! m { ($h:tt $a:meta) => { pub struct Visible { $h [$a] value: [u8; { let _ = std::fs::read("x"); 1 }] } } } m!(# cfg(windows));'),
            ('substituted-variant', 'macro_rules! m { ($h:tt $a:meta) => { pub enum Visible { Present, $h [$a] Hidden = { let _ = std::fs::read("x"); 1 }, } } } m!(# cfg(windows));'),
            ('optional-hash', 'macro_rules! m { ($($h:tt)?; $a:meta) => { $($h)? [$a] pub fn hidden() { let _=std::fs::read("x"); } } } m!(#; cfg(windows));'),
            ('optional-bracket', 'macro_rules! m { ($h:tt; $($a:tt)?) => { $h $($a)? pub fn hidden() { let _=std::fs::read("x"); } } } m!(#; [cfg(windows)]);'),
            ('optional-both', 'macro_rules! m { ($($h:tt)?; $($a:tt)?) => { $($h)? $($a)? pub fn hidden() { let _=std::fs::read("x"); } } } m!(#; [cfg(windows)]);'),
            ('optional-hash-inner', 'macro_rules! m { ($($h:tt)?; $a:meta) => { mod nested { $($h)? ! [$a] pub fn hidden() { let _=std::fs::read("x"); } } } } m!(#; cfg(windows));'),
            ('optional-between', 'macro_rules! m { ($h:tt; $(($b:tt))?; $a:meta) => { $h $($b)? [$a] pub fn hidden() { let _=std::fs::read("x"); } } } m!(#; ; cfg(windows));'),
        ]:
            run(name, source, reject='N3')
        # Regression: one capture name has different tokens across repetition
        # iterations; an unknown repeated prefix must not hide a fixed read.
        for name, source in [
            ('repeated-prefix-star', 'macro_rules! m { ($($a:tt)*) => { pub fn visible() { $($a)* std::fs::read("x").unwrap(); } } } m!(#[cfg(windows)]);'),
            ('repeated-prefix-plus', 'macro_rules! m { ($($a:tt)+) => { pub fn visible() { $($a)+ std::fs::read("x").unwrap(); } } } m!(#[cfg(windows)]);'),
            ('repeated-prefix-optional', 'macro_rules! m { ($(($($a:tt)*))?) => { pub fn visible() { $($($a)*)? std::fs::read("x").unwrap(); } } } m!((#[cfg(windows)]));'),
        ]:
            run(name, source, reject='N3')
        run('harmless-repeated-arguments', 'macro_rules! m { ($($a:tt),*) => { pub fn values() -> [u8; 2] { [$($a),*] } } } m!(1, 2);')
        run('harmless-repeated-statements', 'macro_rules! m { ($($a:tt)*) => { pub fn values() { $(let _ = $a;)* } } } m!(1 2);')
        run('harmless-trailing-macro-arguments', 'macro_rules! m { ($($a:tt)*) => { pub fn values() -> String { format!("prefix {}", $($a)*) } } } m!(7);')
        run('whole-item-forwarding', 'macro_rules! m { ($($a:tt)*) => { $($a)* } } m!(pub fn visible() {});')
        run('nested-typed-indexing', 'macro_rules! outer { ($e:expr) => { macro_rules! inner { () => { $e[0] }; } pub fn first() -> u8 { inner!() } } } outer!([7]);', reject='N3')
        # Regression: make!($) substitutes escaped dollars before a generated
        # matcher can hide a fixed read with a substituted attribute.
        run('escaped-dollar-macro-generator', '''macro_rules! make {
            ($d:tt) => { macro_rules! hidden {
                ($d h:tt $d a:tt) => {
                    $d h $d a pub fn hidden() { let _ = std::fs::read("x"); }
                }
            } }
        }
        make!($);
        hidden!(# [cfg(windows)]);''', reject='N3',
            reject_detail='macro_rules token outside literal definition')
        run('typed-ident-indexing', 'macro_rules! m { ($array:ident) => { $array[0] }; } pub fn first(array: [u8; 1]) -> u8 { m!(array) }')
        run('ambiguous-tt-indexing', 'macro_rules! m { ($array:tt) => { $array[0] }; } pub fn first(array: [u8; 1]) -> u8 { m!(array) }', reject='N3')
        # Regression: raw invocation payloads cannot carry macro definitions,
        # including generic matchers and definitions inside nested groups.
        forward = 'macro_rules! pass { ($($t:tt)*) => { $($t)* }; } '
        nested_cfg = 'macro_rules! hidden { () => { #[cfg(windows)] ' + hidden_read + ' } } hidden!();'
        run('payload-nested-cfg-macro', forward + 'pass! { ' + nested_cfg + ' }', reject='N3')
        run('payload-grouped-nested-cfg-macro', forward + 'pass! { mod nested { ' + nested_cfg + ' } }', reject='N3')
        run('payload-nested-substituted-attribute', forward + 'pass! { macro_rules! hidden { ($a:meta) => { #[$a] ' + hidden_read + ' } } hidden!(cfg(windows)); }', reject='N3')
        run('payload-nested-substituted-brackets', forward + 'pass! { macro_rules! hidden { ($a:tt) => { # $a ' + hidden_read + ' } } hidden!([cfg(windows)]); }', reject='N3')
        run('payload-nested-generic-matcher', forward + 'pass! { macro_rules! visible { (#[$a:meta]) => { pub fn visible() {} } } visible!(#[allow(dead_code)]); }', reject='N3')
        run('opaque-payload-cfg', 'macro_rules! ignore { ($($t:tt)*) => {}; } ignore! { #[cfg(windows)] ' + hidden_read + ' }')
        run('opaque-payload-extern', 'macro_rules! ignore { ($($t:tt)*) => {}; } ignore! { unsafe extern { fn arbitrary(); } }')
        payload_foreign = 'macro_rules! foreign { () => { unsafe extern { pub fn arbitrary(); } } } foreign!();'
        run('payload-nested-foreign-macro', forward + 'pass! { ' + payload_foreign + ' }', reject='N3')
        run('payload-nested-foreign-exact-owner', forward + 'pub mod ffi { pass! { ' + payload_foreign + ' } }', allow_ffi=True, reject='N3')
        run('payload-nested-foreign-sibling-owner', forward + 'pub mod sibling { pass! { ' + payload_foreign + ' } }', reject='N3', allow_ffi=True)
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
        run('loaded-test-subtree', '#[path="loaded.rs"] mod production;', files={'loaded.rs': '#[cfg(test)] mod tests { unsafe extern "C" { pub fn arbitrary(); } #[cfg(windows)] fn hidden(){} #[macro_export] macro_rules! ignored { () => { #[cfg(unix)] fn hidden(){} } } }'}, reject='N4')
        run('unloaded-feature-module', '#[cfg(feature="off")] #[path="does-not-exist.rs"] mod dormant;')
        run('nested-cfg-attr-target', '#[cfg_attr(all(),cfg_attr(all(),cfg(target_os="windows")))] pub fn hidden() {}', reject='N4')
        # Regression: a failed nested predicate parse previously became an
        # empty any(), skipping N4 before the compiler stripped a hidden read.
        run('boolean-any-target', '#[cfg(any(false,windows))] pub fn hidden() { let _ = std::fs::read("x"); }', reject='N4')
        run('boolean-any-target-cfg-attr', '#[cfg_attr(all(),cfg(any(false,windows)))] pub fn hidden() { let _ = std::fs::read("x"); }', reject='N4')
        run('boolean-any-feature-inactive', '#[cfg(any(false,feature="off"))] pub fn hidden() { let _ = std::fs::read("x"); }')
        run('raw-target-predicate', '#[cfg(r#target_os="windows")] pub fn hidden() {}', reject='N4')
        # Regression: target syntax and suppression checks cannot depend on
        # debug/release, feature selection, or an inactive inline parent.
        run('release-conjunct-target', '#[cfg(all(not(debug_assertions), windows))] pub fn hidden() { let _ = std::fs::read("x"); }', reject='N4')
        run('enabled-feature-conjunct-target', '#[cfg(all(not(feature="backend"), windows))] pub fn hidden() { let _ = std::fs::read("x"); }', flags=('--cfg', 'feature="backend"'), reject='N4')
        run('enabled-feature-parent-target', '#[cfg(not(feature="backend"))] mod hidden { #[cfg(windows)] pub fn load() { let _ = std::fs::read("x"); } }', flags=('--cfg', 'feature="backend"'), reject='N4')
        for predicate in ['windows', 'unix', 'target_os="windows"', 'target_family="windows"', 'target_arch="wasm32"', 'target_env="msvc"', 'target_pointer_width="32"']:
            run('structural-target-' + predicate.split('=')[0], '#[cfg_attr(any(),cfg(all(any(),not(' + predicate + '))))] pub fn hidden() {}', reject='N4')
        for reviewed in (False, True):
            for level, attribute, detail in [
                ('allow', 'allow(clippy::disallowed_methods)', 'allow/warn of disallowed lint is refused'),
                ('warn', 'warn(clippy::disallowed_types)', 'allow/warn of disallowed lint is refused'),
                ('cfg-attr-expect', 'cfg_attr(all(),expect(clippy::disallowed_methods,reason="review"))', 'cfg_attr-wrapped disallowed lint level is refused'),
            ]:
                run('inactive-parent-' + level + ('-reviewed' if reviewed else ''), '#[cfg(any())] mod hidden { #[' + attribute + '] pub fn load() {} }', reviewed=reviewed, reject='EXPECT', reject_detail=detail)
                run('release-parent-' + level + ('-reviewed' if reviewed else ''), '#[cfg(not(debug_assertions))] mod hidden { #[' + attribute + '] pub fn load() {} }', reviewed=reviewed, reject='EXPECT', reject_detail=detail)
        # Regression: cfg! is a boolean and strips no code, including nested
        # invocations and imports. The native lint still sees both branches.
        run('target-cfg-macro', 'pub fn target() -> bool { cfg!(all(unix,target_family="unix")) }')
        run('nested-target-cfg-macro', 'pub fn target() -> String { format!("{}", cfg!(windows)) }')
        run('if-target-cfg-positive', 'pub fn visible() -> u8 { if cfg!(windows) { 1 } else { 2 } }')
        run('harmless-macro-nesting', 'macro_rules! outer { () => { macro_rules! inner { () => { 7 } } pub fn value() -> u8 { inner!() } } } outer!();', reject='N3')
        run('macro-body-cfg-positive', 'macro_rules! platform { () => { pub fn visible() -> bool { cfg!(windows) } } } platform!();')
        run('nested-macro-body-cfg-positive', 'macro_rules! outer { () => { macro_rules! inner { () => { cfg!(windows) } } pub fn value() -> bool { inner!() } } } outer!();', reject='N3')
        run('macro-body-cfg-read', 'macro_rules! platform { () => { pub fn visible() { if cfg!(windows) { let _ = std::fs::read("x"); } } } } platform!();', reject='Clippy')
        run('opaque-cfg-macro-data', 'pub const TEXT: &str = stringify!(cfg!(windows));')
        run('if-target-cfg-read', 'pub fn visible() { if cfg!(windows) { let _ = std::fs::read("x"); } }', reject='Clippy')
        for name, attribute in [
            ('boolean-true-target', 'cfg_attr(true,cfg(windows))'),
            ('boolean-false-target', 'cfg_attr(false,cfg(windows))'),
            ('nested-boolean-target', 'cfg_attr(all(),cfg_attr(true,cfg(windows)))'),
            ('boolean-true-clippy', 'cfg_attr(true,cfg(not(clippy)))'),
        ]:
            run(name, '#[' + attribute + '] pub fn hidden() { let _ = std::fs::read("x"); }', reject='N4', reject_detail='cfg_attr predicate or attributes could not be parsed')
        for reviewed in [False, True]:
            for name, attribute in [
                ('positive', 'cfg(clippy)'),
                ('negative', 'cfg(not(clippy))'),
                ('boolean-any-negative', 'cfg(any(false,not(clippy)))'),
                ('boolean-any-cfg-attr', 'cfg_attr(all(),cfg(any(false,not(clippy))))'),
                ('conditional-positive', 'cfg_attr(clippy, cfg(windows))'),
                ('conditional-negative', 'cfg_attr(not(clippy), cfg(windows))'),
                ('nested-negative', 'cfg_attr(all(), cfg_attr(all(), cfg(not(clippy))))'),
            ]:
                run('clippy-cfg-' + name + ('-reviewed' if reviewed else ''), '#[' + attribute + '] pub fn hidden() { let _ = std::fs::read("x"); }', reviewed=reviewed, reject='N4', reject_detail='clippy cfg predicate hides code from native Clippy')
        run('feature-only-predicate', '#[cfg(feature="off")] pub fn hidden() {}')
        run('target-attribute-not-predicate', '#[cfg_attr(feature="simd",target_feature(enable="sse2"))] pub fn visible() {}')
        run('reviewed-file-before-edit', '#[cfg(windows)] pub fn hidden() {}', reviewed=True)
        run('reviewed-file-unrelated-edit', '// unrelated edit\n#[cfg(windows)] pub fn hidden() {}\npub fn extra() {}', reviewed=True)
        run('custom-root-no-source-forbid', 'pub fn visible() {}', root_forbid=False)
        run('reserved-cfg', '#[cfg(internal_read_inventory)] pub fn hidden() {}', reject='EXPECT')
        run('reserved-raw-cfg', '#[cfg(r#internal_read_inventory)] pub fn hidden() {}', reject='EXPECT')
        run('reserved-cfg-macro', 'pub fn hidden() -> bool { cfg!(internal_read_inventory) }', reject='EXPECT')
    (args.output / 'summary.json').write_text(json.dumps(results, indent=2) + '\n')
    print(f'{len(results)} compiled syntax regressions passed')


if __name__ == '__main__':
    main()

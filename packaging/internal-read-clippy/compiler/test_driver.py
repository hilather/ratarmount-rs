#!/usr/bin/env python3
"""Compiled regressions for the pinned Clippy lookup/expansion hooks."""
import argparse
import json
import os
from pathlib import Path
import importlib.util
import contextlib
import io
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('policy',HERE.parent/'policy.py')
policy_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy_module)

def main():
    p=argparse.ArgumentParser();p.add_argument('--driver',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=True)
    results=[]
    with tempfile.TemporaryDirectory(prefix='internal-read-driver-') as td:
        root=Path(td);(root/'included.rs').write_text('pub const VALUE:u32=42;\n');(root/'expr.rs').write_text('42u32\n');(root/'empty.rs').write_text('// empty\n')
        conf=root/'conf';conf.mkdir()
        config=json.loads((HERE.parent/'policy.json').read_text());config['restricted_packages']=[];config['include_exceptions']=[]
        policy=root/'policy.json'
        sysroot=subprocess.check_output(['rustc','+1.98.0','--print','sysroot'],text=True).strip()
        env={**os.environ,'INTERNAL_READ_ROOT':str(root),'INTERNAL_READ_CONFIG':str(policy),'CLIPPY_CONF_DIR':str(conf),'LD_LIBRARY_PATH':str(Path(sysroot)/'lib'),'RUSTC_BOOTSTRAP':'1'}
        def run(name,source,*,reject=False,rules=None,crate='control',source_path=None,extra_flags=(),crate_type='lib',native_baseline=False,root_forbid=True):
            (conf/'clippy.toml').write_text(rules or 'disallowed-methods=[{path="std::fs::read",reason="inventory-op:fs::read"}]\ndisallowed-macros=[{path="std::include",reason="review include"}]\n')
            policy.write_text(json.dumps(config));src=source_path or root/'lib.rs';src.parent.mkdir(parents=True,exist_ok=True);src.write_text(('#![forbid(unused_macros)]\n' if root_forbid else '')+source+'\n')
            report=root/'report.jsonl';env['INTERNAL_READ_REPORT']=str(report)
            rustargs=[str(src),'--crate-name',crate,'--crate-type='+crate_type,'--edition=2024','--emit=metadata','--out-dir',str(root)]
            baseline=None
            if native_baseline:
                baseline=subprocess.run(['rustc','+1.98.0',*rustargs,'-Dwarnings'],env=env,capture_output=True,text=True)
                (a.output/(name+'.baseline.stderr')).write_text(baseline.stderr)
                assert baseline.returncode==0,(name,'native baseline',baseline.returncode,baseline.stderr)
            cmd=[str(a.driver.resolve()),*rustargs,'--error-format=json','-Dclippy::disallowed_methods','-Funused_macros','-Dclippy::disallowed_types','-Dclippy::disallowed_macros',*extra_flags]
            done=subprocess.run(cmd,env=env,capture_output=True,text=True)
            rows=[json.loads(line) for line in report.read_text().splitlines()] if report.exists() else []
            (a.output/(name+'.stderr')).write_text(done.stderr)
            (a.output/(name+'.jsonl')).write_text(report.read_text() if report.exists() else '')
            assert bool(done.returncode)==bool(reject),(name,done.returncode,done.stderr)
            if reject:
                diagnostics=[json.loads(line) for line in done.stderr.splitlines() if line.startswith('{')]
                if reject.startswith('clippy::') or reject in {'E0453', 'unfulfilled_lint_expectations'}:
                    assert any(row.get('code') and row['code']['code']==reject for row in diagnostics),(name,reject,done.stderr)
                else:
                    assert any(reject in row.get('message','') for row in diagnostics),(name,reject,done.stderr)
            result={'name':name,'exit':done.returncode,'expected':'reject' if reject else 'accept','operations':[r.get('resolved') for r in rows if r['kind']=='operation']}
            if baseline is not None:result['native_baseline_exit']=baseline.returncode
            results.append(result)
            return rows
        # Regression: command-line forbid enforces unused_macros independently
        # of look-alike attributes and local attempts to lower the lint.
        spoof='#![forbid(rustdoc::unused_macros)]\n#![allow(unused_macros)]\nmacro_rules! hidden {()=>{pub fn read(){let _=std::fs::read("x");}}}'
        rows=run('qualified-unused-macros-forbid',spoof,root_forbid=False,native_baseline=True,reject='E0453',extra_flags=['-Dwarnings'])
        assert 'E0453' in (a.output/'qualified-unused-macros-forbid.stderr').read_text()
        assert 'unused_macros' in (a.output/'qualified-unused-macros-forbid.stderr').read_text()
        run('exact-unused-macros-forbid-list','#![forbid(dead_code, unused_macros)] pub fn visible(){}',root_forbid=False,native_baseline=True,extra_flags=['-Dwarnings'])

        # Regression: cfg! and its aliases yield bools and never strip code.
        # They are accepted; native Clippy diagnoses reads in either branch.
        package_before=env.get('CARGO_PKG_NAME')
        env['CARGO_PKG_NAME']=config['classified_packages'][0]
        config['restricted_packages']=[env['CARGO_PKG_NAME']]
        aliases={
            'simple':'use std::cfg as target_cfg;',
            'grouped':'use std::{cfg as target_cfg};',
            'nested':'use {std::{cfg as target_cfg}};',
            'raw':'use ::std::r#cfg as r#target_cfg;',
        }
        for name,import_source in aliases.items():
            rows=run('cfg-alias-'+name,import_source+'pub const VALUE:bool=target_cfg!(windows);',native_baseline=True,extra_flags=['-Dwarnings'])
            assert not any(r['kind']=='syntax' and r['policy']=='N4' for r in rows)
        rows=run('aliased-cfg-read',aliases['simple']+'pub fn load(){if target_cfg!(windows){let _=std::fs::read("x");}}',native_baseline=True,reject='clippy::disallowed_methods',extra_flags=['-Fclippy::disallowed_methods'])
        assert any(r.get('resolved')=='std::fs::read' and r.get('lint')=='clippy::disallowed_methods' for r in rows)
        assert any(json.loads(line).get('code', {}) and json.loads(line)['code']['code']=='clippy::disallowed_methods' for line in (a.output/'aliased-cfg-read.stderr').read_text().splitlines() if line.startswith('{'))
        run('ordinary-cfg-import','use std::cfg; pub const VALUE:bool=cfg!(debug_assertions);',native_baseline=True,extra_flags=['-Dwarnings'])
        run('unrelated-macro-alias','use std::stringify as target_string; pub const VALUE:&str=target_string!(windows);',native_baseline=True,extra_flags=['-Dwarnings'])
        reviewed_before=config['reviewed_target_files']
        config['reviewed_target_files']=[{'file':'lib.rs'}]
        run('cfg-alias-reviewed',aliases['simple']+'pub const VALUE:bool=target_cfg!(windows);',native_baseline=True,extra_flags=['-Dwarnings'])
        config['reviewed_target_files']=reviewed_before
        config['restricted_packages']=[]
        run('cfg-alias-unrestricted',aliases['simple']+'pub const VALUE:bool=target_cfg!(windows);',native_baseline=True,extra_flags=['-Dwarnings'])
        if package_before is None:env.pop('CARGO_PKG_NAME')
        else:env['CARGO_PKG_NAME']=package_before
        for configured in [['std::include'],['core::include'],['std::include','core::include']]:
            rules='disallowed-macros=['+','.join('{path="'+path+'",reason="review include"}' for path in configured)+']\n'
            for pos in ['item','expression']:
                for spelling in ['include','::std::include','::core::include']:
                    src=spelling+'!("included.rs");' if pos=='item' else 'pub fn value()->u32{'+spelling+'!("expr.rs")} '
                    rows=run('include-'+str(len(results)),src,reject='clippy::disallowed_macros',rules=rules)
                    assert any(r.get('resolved')=='core::macros::builtin::include' for r in rows)
        run('configured-println','pub fn log(){println!("control");}',reject='clippy::disallowed_macros',rules='disallowed-macros=[{path="std::println",reason="positive macro control"}]\n')
        run('empty-include','include!("empty.rs");',reject='clippy::disallowed_macros')
        run('unrelated-include','macro_rules! include {()=>{42};} pub fn x()->u32{include!()}',reject=False)
        csi=root/'ratarmount-csi/src/lib.rs'
        config['include_exceptions']=[{'file':'ratarmount-csi/src/lib.rs','item':'ratarmount_csi::csi','reason':'Reviewed fixture include only.'}]
        rows=run('include-reviewed','pub mod csi{include!("../../included.rs");}',crate='ratarmount_csi',source_path=csi)
        assert len([row for row in rows if row['kind']=='include_exception'])==1
        approved=policy_module.manifest([('fixture',a.output/'include-reviewed.jsonl')],{'fixture':1})
        approved_file=root/'approved.json';approved_file.write_text(policy_module.canonical(approved))
        run('include-deleted','pub mod csi{}',crate='ratarmount_csi',source_path=csi)
        deleted=policy_module.manifest([('fixture',a.output/'include-deleted.jsonl')],{'fixture':1})
        try:
            with contextlib.redirect_stderr(io.StringIO()):policy_module.check_diff(deleted,approved_file)
        except policy_module.PolicyError:pass
        else:raise AssertionError('deleted reviewed include must change actual generated manifest')
        run('include-relocated','pub mod csi{include!("../../included.rs");}',crate='ratarmount_csi',source_path=root/'moved/src/lib.rs',reject='clippy::disallowed_macros')
        run('include-duplicated','pub mod csi{include!("../../empty.rs");include!("../../empty.rs");}',crate='ratarmount_csi',source_path=csi)
        try:policy_module.manifest([('fixture',a.output/'include-duplicated.jsonl')],{'fixture':1})
        except policy_module.PolicyError:pass
        else:raise AssertionError('multiple reviewed includes must fail actual manifest generation')
        config['include_exceptions']=[]
        # Regression: inactive crate-root link_name attributes bypassed N2
        # because check_attributes sees only their configured spelling.
        for name,attribute in [
            ('crate-root-inactive-link-name', '#![cfg_attr(any(),link_name="arbitrary")]'),
            ('crate-root-nested-inactive-link-name', '#![cfg_attr(all(),cfg_attr(any(),link_name="arbitrary"))]'),
        ]:
            rows=run(name,attribute+' pub fn visible(){}',native_baseline=True,reject='N2')
            assert any(row.get('policy')=='N2' and row.get('detail')=='link_name outside reviewed module' for row in rows)
        run('extern-root','unsafe extern "C"{pub fn mkostemp(p:*mut u8)->i32;}',reject='N2')
        config['allowed_extern_module']='control::ffi'
        run('extern-exact','pub mod ffi{unsafe extern "C"{pub fn mkostemp(p:*mut u8)->i32;}}')
        run('extern-child','pub mod ffi{pub mod child{unsafe extern "C"{pub fn mkostemp(p:*mut u8)->i32;}}}',reject='N2')
        run('extern-macro-root','pub mod ffi{#[macro_export] macro_rules! expose{()=>{unsafe extern "C"{pub fn mkostemp(p:*mut u8)->i32;}}}} expose!();',reject='N2')
        config['allowed_extern_module']='other::ffi'
        run('ordinary-abi','pub extern "C" fn f(){} pub type F=extern "C" fn();')
        run('direct-read','pub fn read(){let _=std::fs::read("x");}',reject='clippy::disallowed_methods')
        # Regression: repo-defined proc-macro implementation bodies are ordinary
        # production libraries. No generated output is audited or assigned here.
        proc_source='extern crate proc_macro; #[proc_macro] pub fn source(input:proc_macro::TokenStream)->proc_macro::TokenStream{let _=std::fs::read("implementation input");input}'
        proc_rows=run('proc-macro-implementation-read',proc_source,crate='implementation_proc',crate_type='proc-macro',native_baseline=True,reject='clippy::disallowed_methods')
        results[-1]['mechanism']='native Clippy DefId in a production proc-macro implementation'
        proc_operations=[row for row in proc_rows if row['kind']=='operation']
        assert len(proc_operations)==1 and proc_operations[0]['resolved']=='std::fs::read' and proc_operations[0]['lint']=='clippy::disallowed_methods'
        rows=run('aliased-read','extern crate std as s; pub use s::fs::read as acquire; pub fn read(){let _=acquire("x");}',reject='clippy::disallowed_methods')
        assert any(r.get('resolved')=='std::fs::read' for r in rows)
        def mark(identifier,item,lint="clippy::disallowed_methods"):
            metadata={'id':identifier,'item':item,'disposition':'test','category':'fixture','reason':'Regression: canonical impl owner identity.','creation':{'policy':'none','basis':'existing input only'}}
            literal=json.dumps('internal-read:v1 '+json.dumps(metadata,separators=(',',':')))
            return '#[expect('+lint+',reason='+literal+')]'
        flags=['--cfg','internal_read_inventory','--check-cfg=cfg(internal_read_inventory)','-Dunfulfilled_lint_expectations']
        # Regression: the ordinary-build bookkeeping switch must not suppress
        # an unfulfilled approval in the selected production compilation.
        dormant='#![cfg_attr(not(internal_read_inventory),allow(unfulfilled_lint_expectations))]'
        run('inventory-switch-stale-expect', dormant+'pub fn load(){'+mark('STALE','control::load')+'let _=();}',
            extra_flags=[*flags,'-Dwarnings'],reject='unfulfilled_lint_expectations')
        impl_source='pub struct A<T>(pub T);pub struct B<T>(pub T);impl<T>A<T>{pub fn load(){'+mark('IMPL-A','<control::A<T0>>::load')+'let _=std::fs::read("a");}}impl<T>B<T>{pub fn load(){'+mark('IMPL-B','<control::B<T0>>::load')+'let _=std::fs::read("b");}}'
        impl_rows=run('distinct-impl-owners',impl_source,extra_flags=flags)
        assert {row['owner'] for row in impl_rows if row['kind']=='operation'}=={'<control::A<T0>>::load','<control::B<T0>>::load'}
        first=policy_module.manifest([('fixture',a.output/'distinct-impl-owners.jsonl')],{'fixture':1})
        run('unrelated-impl-insertion','pub struct Earlier;impl Earlier{pub fn unrelated(){}}'+impl_source,extra_flags=flags)
        second=policy_module.manifest([('fixture',a.output/'unrelated-impl-insertion.jsonl')],{'fixture':1})
        assert first==second,'unrelated impl insertion must preserve actual generated impl-owner manifest'
        renamed=impl_source.replace('A<T>','A<U>').replace('B<T>','B<U>').replace('impl<T>','impl<U>').replace('pub T','pub U')
        run('generic-binder-renaming',renamed,extra_flags=flags)
        third=policy_module.manifest([('fixture',a.output/'generic-binder-renaming.jsonl')],{'fixture':1})
        assert first==third,'declaration generic binder names must normalize by index'
        trait_source='pub struct A;pub struct B;pub trait Load{fn load();}impl Load for A{fn load(){'+mark('TRAIT-A','<control::A as control::Load<control::A>>::load')+'let _=std::fs::read("a");}}impl Load for B{fn load(){'+mark('TRAIT-B','<control::B as control::Load<control::B>>::load')+'let _=std::fs::read("b");}}'
        trait_rows=run('distinct-trait-impl-owners',trait_source,extra_flags=flags)
        assert {row['owner'] for row in trait_rows if row['kind']=='operation'}=={'<control::A as control::Load<control::A>>::load','<control::B as control::Load<control::B>>::load'}
        policy_module.manifest([('fixture',a.output/'distinct-trait-impl-owners.jsonl')],{'fixture':1})
        def lifetime_source(binder):
            return "pub struct Reader<'"+binder+">(pub &'"+binder+" str);impl<'"+binder+">Reader<'"+binder+">{pub fn load(){"+mark('LIFETIME',"<control::Reader<'L0>>::load")+'let _=std::fs::read("x");}}'
        run('lifetime-binder-original',lifetime_source('a'),extra_flags=flags)
        run('lifetime-binder-renamed',lifetime_source('b'),extra_flags=flags)
        lifetime_a=policy_module.manifest([('fixture',a.output/'lifetime-binder-original.jsonl')],{'fixture':1})
        lifetime_b=policy_module.manifest([('fixture',a.output/'lifetime-binder-renamed.jsonl')],{'fixture':1})
        assert lifetime_a==lifetime_b,'lifetime binder rename must preserve canonical manifest'
        def pointer_source(binder,approval=''):
            return "pub trait Load{fn load();}impl Load for for<'"+binder+">fn(&'"+binder+" str){fn load(){"+approval+'let _=std::fs::read("x");}}'
        pointer_probe=run('late-binder-unmarked',pointer_source('a'),reject='clippy::disallowed_methods')
        pointer_owner=next(row['owner'] for row in pointer_probe if row['kind']=='operation')
        assert "'B0:0" in pointer_owner and "'a" not in pointer_owner and '{impl#' not in pointer_owner
        pointer_mark=mark('LATE-LIFETIME',pointer_owner)
        run('late-binder-original',pointer_source('a',pointer_mark),extra_flags=flags)
        run('late-binder-renamed',pointer_source('z',pointer_mark),extra_flags=flags)
        pointer_a=policy_module.manifest([('fixture',a.output/'late-binder-original.jsonl')],{'fixture':1})
        pointer_b=policy_module.manifest([('fixture',a.output/'late-binder-renamed.jsonl')],{'fixture':1})
        assert pointer_a==pointer_b,'late-bound lifetime names must normalize structurally'

        def const_source(binder):
            return 'pub struct Buffer<const '+binder+':usize>(pub [u8;'+binder+']);impl<const '+binder+':usize>Buffer<'+binder+'>{pub fn load(){'+mark('CONST','<control::Buffer<C0>>::load')+'let _=std::fs::read("x");}}'
        run('const-binder-original',const_source('N'),extra_flags=flags)
        run('const-binder-renamed',const_source('M'),extra_flags=flags)
        const_a=policy_module.manifest([('fixture',a.output/'const-binder-original.jsonl')],{'fixture':1})
        const_b=policy_module.manifest([('fixture',a.output/'const-binder-renamed.jsonl')],{'fixture':1})
        assert const_a==const_b,'const binder rename must preserve canonical manifest'
        imported=mark('IMPORT','control','clippy::disallowed_types')+'pub use std::fs::{File,OpenOptions};'
        type_rules='disallowed-types=[{path="std::fs::OpenOptions",reason="inventory-op:OpenOptions"}]\n'
        run('import-original',imported,extra_flags=flags,rules=type_rules)
        run('import-syntax-changed',imported.replace('{File,OpenOptions}','{OpenOptions,File}'),extra_flags=flags,rules=type_rules)
        run('import-line-shifted','\n\n'+imported,extra_flags=flags,rules=type_rules)
        original_import=policy_module.manifest([('fixture',a.output/'import-original.jsonl')],{'fixture':1})
        changed_import=policy_module.manifest([('fixture',a.output/'import-syntax-changed.jsonl')],{'fixture':1})
        shifted_import=policy_module.manifest([('fixture',a.output/'import-line-shifted.jsonl')],{'fixture':1})
        assert original_import!=changed_import,'full handwritten use syntax must affect manifest leaf digest'
        assert original_import==shifted_import,'pure line shift must preserve use manifest'
        generated=root/'out/generated.rs';generated.parent.mkdir(exist_ok=True)
        generated.write_text('pub fn generated_load(){'+mark('GENERATED','control::generated_load')+'let _=std::fs::read("x");}')
        generated_rows=run('generated-invented-mark','include!("out/generated.rs");',extra_flags=flags,rules='disallowed-methods=[{path="std::fs::read",reason="inventory-op:fs::read"}]\n')
        assert all(not row.get('source_leaf_observed') for row in generated_rows if row['kind']=='operation')
        try:policy_module.manifest([('fixture',a.output/'generated-invented-mark.jsonl')],{'fixture':1})
        except policy_module.PolicyError:pass
        else:raise AssertionError('generated matching literal must remain unowned in actual manifest')
        # Regression: a real OUT_DIR include gives a generated read an
        # unowned primary span, independently of the include macro ban.
        out_dir=root/'build-output';out_dir.mkdir()
        (out_dir/'generated_read.rs').write_text('pub fn generated_plain_read(){let _=std::fs::read("generated input");}')
        env['OUT_DIR']=str(out_dir)
        generated_source='include!(concat!(env!("OUT_DIR"),"/generated_read.rs"));'
        generated_rules='disallowed-methods=[{path="std::fs::read",reason="inventory-op:fs::read"}]\n'
        out_rows=run('generated-out-dir-read',generated_source,rules=generated_rules,native_baseline=True,reject='clippy::disallowed_methods')
        results[-1]['mechanism']='native Clippy DefId for generated std::fs::read'
        assert [row['resolved'] for row in out_rows if row['kind']=='operation']==['std::fs::read']
        out_collection=run('generated-out-dir-collection-unowned',generated_source,rules=generated_rules,extra_flags=['--force-warn','clippy::disallowed_methods'])
        out_operations=[row for row in out_collection if row['kind']=='operation']
        assert len(out_operations)==1 and out_operations[0]['span']['file']=='build-output/generated_read.rs' and not out_operations[0].get('source_leaf_observed')
        try:policy_module.manifest([('fixture',a.output/'generated-out-dir-collection-unowned.jsonl')],{'fixture':1})
        except policy_module.PolicyError as error:
            assert 'unowned' in str(error)
            results[-1]['manifest_rejected']=True
            results[-1]['mechanism']='compiler source-leaf ownership rejects the OUT_DIR primary'
        else:raise AssertionError('OUT_DIR read primary must remain unowned in actual manifest')
        env.pop('OUT_DIR')
        broad='pub fn load(){'+mark('BROAD-SINGLE','control::load')+'{let _=std::fs::read("x");}}'
        broad_rows=run('single-read-broad-block',broad,extra_flags=flags)
        assert all(row['broad'] for row in broad_rows if row['kind']=='operation')
        try:policy_module.manifest([('fixture',a.output/'single-read-broad-block.jsonl')],{'fixture':1})
        except policy_module.PolicyError:pass
        else:raise AssertionError('a single-read broad block approval must fail manifest ownership')
        (root/'shared.rs').write_text('pub mod ffi{macro_rules! foreign{()=>{unsafe extern "C"{fn arbitrary_foreign();}}}foreign!();}')
        config['allowed_extern_module']='control::first::ffi'
        run('allowed-module-source-exact','#[path="shared.rs"] pub mod first;')
        run('allowed-module-source-alias','#[path="shared.rs"] pub mod first;#[path="shared.rs"]pub mod second;',reject='N2')
        config['allowed_extern_module']='other::ffi'
        duplicate='pub fn top(){{fn nested(){'+mark('COLLISION-A','control::top::nested')+'let _=std::fs::read("a");}nested();}{fn nested(){'+mark('COLLISION-B','control::top::nested')+'let _=std::fs::read("b");}nested();}}'
        run('distinct-named-owner-collision',duplicate,extra_flags=flags,reject='canonical owner identity collision')
        assert 'canonical owner identity collision' in (a.output/'distinct-named-owner-collision.stderr').read_text()
    (a.output/'summary.json').write_text(json.dumps(results,indent=2)+'\n')
    print(f'{len(results)} compiler-driver regressions passed')

if __name__=='__main__':main()

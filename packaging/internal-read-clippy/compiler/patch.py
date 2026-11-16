#!/usr/bin/env python3
"""Apply narrow hooks to exact pinned Clippy sources; never rewrite rustc."""
from pathlib import Path
import shutil
import sys

HERE=Path(__file__).resolve().parent
root=Path(sys.argv[1])

def change(file,old,new):
    p=root/file
    text=p.read_text()
    if text.count(old)!=1:
        raise SystemExit(f'pin mismatch: {file}: expected one anchor, got {text.count(old)}')
    p.write_text(text.replace(old,new))

shutil.copyfile(HERE/'internal_read.rs',root/'clippy_lints/src/internal_read.rs')
if (HERE/'syntax.rs').exists():
    shutil.copyfile(HERE/'syntax.rs',root/'clippy_lints/src/internal_read_syntax.rs')
    shutil.copyfile(HERE.parent/'syntax/src/lib.rs',root/'clippy_lints/src/internal_read_grammar.rs')
change('clippy_lints/Cargo.toml','[dependencies]\n','[dependencies]\nserde_json = "=1.0.154"\nsha2 = "=0.10.9"\nproc-macro2 = {version="=1.0.106", features=["span-locations"]}\nquote = "=1.0.45"\nsyn = {version="=2.0.117", features=["full", "extra-traits", "visit"]}\n')
change('clippy_lints/src/lib.rs','mod disallowed_methods;','mod disallowed_methods;\npub mod internal_read;\npub mod internal_read_syntax;\npub mod internal_read_grammar;')
change('clippy_config/src/types.rs','    pub fn path(&self) -> &str {\n        &self.path\n    }','    pub fn path(&self) -> &str {\n        &self.path\n    }\n\n    pub fn policy_reason(&self) -> Option<&str> { self.reason.as_deref() }')
change('clippy_lints/src/disallowed_methods.rs','        if let Some(&(path, disallowed_path)) = self.disallowed.get(&id) {','        if let Some(&(path, disallowed_path)) = self.disallowed.get(&id) {\n            crate::internal_read::operation(cx, id, path, disallowed_path.policy_reason(), DISALLOWED_METHODS, expr.hir_id, span);')
change('clippy_lints/src/disallowed_types.rs','fn check_res_emit(&self, cx: &LateContext<\'_>, res: &Res, span: Span)', 'fn check_res_emit(&self, cx: &LateContext<\'_>, res: &Res, span: Span, hir: rustc_hir::HirId)')
change('clippy_lints/src/disallowed_types.rs','        span_lint_and_then(\n            cx,\n            DISALLOWED_TYPES,','        if let Res::Def(_, id) = res { crate::internal_read::operation(cx, *id, path, disallowed_path.policy_reason(), DISALLOWED_TYPES, hir, span); }\n        span_lint_and_then(\n            cx,\n            DISALLOWED_TYPES,')
change('clippy_lints/src/disallowed_types.rs','self.check_res_emit(cx, &res, item.span);','self.check_res_emit(cx, &res, item.span, item.hir_id());')
change('clippy_lints/src/disallowed_types.rs','self.check_res_emit(cx, &cx.qpath_res(path, ty.hir_id), ty.span);','self.check_res_emit(cx, &cx.qpath_res(path, ty.hir_id), ty.span, ty.hir_id);')
change('clippy_lints/src/disallowed_types.rs','self.check_res_emit(cx, &poly.trait_ref.path.res, poly.trait_ref.path.span);','self.check_res_emit(cx, &poly.trait_ref.path.res, poly.trait_ref.path.span, poly.trait_ref.hir_ref_id);')
change('clippy_lints/src/disallowed_macros.rs','    fn check_crate(&mut self, cx: &LateContext<\'_>) {','''    fn check_crate(&mut self, cx: &LateContext<'_>) {
        if crate::internal_read::enabled() {
            // Fully initialize a sentinel; its index bounds all completed local
            // expansion records. Pinned rustc stores these densely without gaps.
            let end=cx.tcx.with_stable_hashing_context(|hcx|rustc_span::hygiene::LocalExpnId::fresh(rustc_span::hygiene::LocalExpnId::ROOT.expn_data(),hcx));
            assert!(end.as_raw().as_u32()>0,"missing completed expansion records");
            let mut matched=0;
            for index in 1..end.as_raw().as_u32() {
                let expn=rustc_span::hygiene::LocalExpnId::from_u32(index).to_expn_id();
                let data=expn.expn_data();
                if let Some(id)=data.macro_def_id
                    && let Some(&(path, disallowed_path))=self.disallowed.get(&id)
                    && self.seen.insert(expn)
                {
                    matched+=1;
                    let call=crate::internal_read::repository_callsite(cx.tcx,expn);
                    let hir=crate::internal_read::invocation_owner(cx.tcx,call);
                    if crate::internal_read::include_exception(cx,id,path,disallowed_path.policy_reason(),call,hir) {continue;}
                    crate::internal_read::operation(cx,id,path,disallowed_path.policy_reason(),DISALLOWED_MACROS,hir,call);
                    span_lint_hir_and_then(cx,DISALLOWED_MACROS,hir,call,format!("use of a disallowed macro `{path}`"),disallowed_path.diag_amendment(call));
                }
            }
            crate::internal_read::expansion_observed(end.as_raw().as_u32()-1,matched);
        }''')
change('src/driver.rs','            clippy_lints::register_lint_passes(lint_store, conf);','            clippy_lints::register_lint_passes(lint_store, conf);\n            if clippy_lints::internal_read::enabled() { clippy_lints::internal_read_syntax::register(sess,lint_store); }')
change('src/driver.rs','impl rustc_driver::Callbacks for ClippyCallbacks {','''impl rustc_driver::Callbacks for ClippyCallbacks {
    fn after_analysis<'tcx>(&mut self,_:&rustc_interface::interface::Compiler,tcx:rustc_middle::ty::TyCtxt<'tcx>)->rustc_driver::Compilation {
        clippy_lints::internal_read::finish(tcx);
        rustc_driver::Compilation::Continue
    }''')
change('src/driver.rs','extern crate rustc_driver;','extern crate rustc_driver;\nextern crate rustc_middle;')
change('src/driver.rs','        let conf_path = clippy_config::lookup_conf_file();','        clippy_lints::internal_read::start();\n        let conf_path = clippy_config::lookup_conf_file();')

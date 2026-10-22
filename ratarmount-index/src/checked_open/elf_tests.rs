//! ELF inspection tests (r11 S6): synthetic images through the portable
//! byte reader, plus the real loader on Linux glibc.

use super::*;

const BIAS: usize = 0x40_0000;
const DYN_OFF: usize = 0;
const SYMTAB_OFF: usize = 0x1000;
const CODE_LEN: usize = 0x100;

const GLOBAL: u8 = STB_GLOBAL;
const WEAK: u8 = STB_WEAK;
const UNIQUE: u8 = STB_GNU_UNIQUE;
const LOCAL: u8 = STB_LOCAL;
const NOTYPE: u8 = 0;
const OBJECT: u8 = 1;
const FUNC: u8 = 2;
const IFUNC: u8 = 10;
const DEFAULT: u8 = 0;
const PROTECTED: u8 = 3;
const HIDDEN: u8 = STV_HIDDEN;
const INTERNAL: u8 = STV_INTERNAL;

#[derive(Clone)]
struct Sym {
    name: Vec<u8>,
    bind: u8,
    kind: u8,
    vis: u8,
    shndx: u16,
    /// Offset into the code area (ordinary definitions), or the raw value.
    value: u64,
}

/// An ordinary defined function at `code` bytes into the code area.
fn func(name: &str, bind: u8, vis: u8, code: u64) -> Sym {
    Sym {
        name: name.as_bytes().to_vec(),
        bind,
        kind: FUNC,
        vis,
        shndx: 1,
        value: code,
    }
}

type DynEdit = fn(&mut Vec<(i64, u64)>);

#[derive(Clone)]
struct Spec {
    syms: Vec<Sym>,
    /// GNU hash `symoffset`: this many symbols (after the null symbol) are
    /// not hashed.
    unhashed: usize,
    gnu: bool,
    sysv: bool,
    /// Write table pointers relocated (glibc's in-place adjustment).
    adjusted: bool,
    /// `DT_INIT` as an offset into the code area.
    init: Option<u64>,
    /// Raw `DT_INIT` value (overrides `init`).
    init_raw: Option<u64>,
    init_array: Option<Vec<u64>>,
    init_arraysz: Option<u64>,
    /// Edit the dynamic entries (before `DT_NULL`).
    edit_dyn: Option<DynEdit>,
    no_null: bool,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            syms: vec![
                func("ordinary_function", GLOBAL, DEFAULT, 0x10),
                func("hidden_init", GLOBAL, HIDDEN, 0x20),
            ],
            unhashed: 0,
            gnu: true,
            sysv: false,
            adjusted: true,
            init: None,
            init_raw: None,
            init_array: Some(vec![0x30]),
            init_arraysz: None,
            edit_dyn: None,
            no_null: false,
        }
    }
}

struct Built {
    bytes: Vec<u8>,
    code_off: usize,
    dyn_len: usize,
    strsz: usize,
    sysv_off: usize,
    gnu_off: usize,
}

impl Built {
    fn code(&self, off: u64) -> usize {
        BIAS + self.code_off + off as usize
    }

    fn image(&self) -> ElfImage<'_> {
        self.image_at(BIAS)
    }

    /// The image loaded at `bias` (an image larger than [`BIAS`] needs a
    /// higher one, or every table pointer is mapped both raw and relocated).
    fn image_at(&self, bias: usize) -> ElfImage<'_> {
        let phdrs = [
            Phdr {
                p_type: PT_LOAD,
                flags: PF_R,
                vaddr: 0,
                memsz: self.code_off as u64,
            },
            Phdr {
                p_type: PT_LOAD,
                flags: PF_R | PF_X,
                vaddr: self.code_off as u64,
                memsz: CODE_LEN as u64,
            },
            Phdr {
                p_type: PT_DYNAMIC,
                flags: PF_R,
                vaddr: DYN_OFF as u64,
                memsz: self.dyn_len as u64,
            },
        ];
        ElfImage::from_phdrs(
            0x1234,
            bias,
            phdrs.len(),
            phdrs.into_iter(),
            Some((bias, &self.bytes)),
        )
        .unwrap()
    }
}

fn put(bytes: &mut Vec<u8>, at: usize, data: &[u8]) {
    if bytes.len() < at + data.len() {
        bytes.resize(at + data.len(), 0);
    }
    bytes[at..at + data.len()].copy_from_slice(data);
}

fn build(spec: &Spec) -> Built {
    let mut bytes = Vec::new();
    // Symbol 0 is the null symbol.
    let n = spec.syms.len() + 1;
    let mut strtab = vec![0u8];
    let code_off;
    #[allow(clippy::needless_late_init)]
    {
        let mut names = Vec::new();
        for s in &spec.syms {
            names.push(strtab.len() as u32);
            strtab.extend_from_slice(&s.name);
            strtab.push(0);
        }
        let symtab_end = SYMTAB_OFF + n * SYM_SIZE;
        let strtab_off = symtab_end;
        let sysv_off = (strtab_off + strtab.len() + 7) & !7;
        // SysV: one bucket, a chain over every symbol (header, bucket, n
        // chain words).
        let gnu_off = (sysv_off + 12 + 4 * n + 7) & !7;
        let symoffset = 1 + spec.unhashed;
        let hashed = n.saturating_sub(symoffset);
        let gnu_len = 16 + 8 + 4 + 4 * hashed;
        let init_off = (gnu_off + gnu_len + 7) & !7;
        let entries = spec.init_array.clone().unwrap_or_default();
        code_off = (init_off + 8 * entries.len().max(1) + 0xfff) & !0xfff;

        put(&mut bytes, SYMTAB_OFF, &[0u8; SYM_SIZE]);
        for (i, s) in spec.syms.iter().enumerate() {
            let mut e = [0u8; SYM_SIZE];
            e[0..4].copy_from_slice(&names[i].to_le_bytes());
            e[4] = (s.bind << 4) | s.kind;
            e[5] = s.vis;
            e[6..8].copy_from_slice(&s.shndx.to_le_bytes());
            let value = if s.shndx == 1 {
                code_off as u64 + s.value
            } else {
                s.value
            };
            e[8..16].copy_from_slice(&value.to_le_bytes());
            put(&mut bytes, SYMTAB_OFF + (i + 1) * SYM_SIZE, &e);
        }
        put(&mut bytes, strtab_off, &strtab);
        // SysV: nbucket = 1, nchain = n; bucket 0 starts at the last symbol
        // and each chain word names the one before it (the hash function
        // does not matter: the inspection checks reachability only).
        put(&mut bytes, sysv_off, &1u32.to_le_bytes());
        put(&mut bytes, sysv_off + 4, &(n as u32).to_le_bytes());
        put(&mut bytes, sysv_off + 8, &((n - 1) as u32).to_le_bytes());
        for i in 0..n {
            let next = i.saturating_sub(1) as u32;
            put(&mut bytes, sysv_off + 12 + 4 * i, &next.to_le_bytes());
        }
        // GNU: one bucket, one bloom word.
        put(&mut bytes, gnu_off, &1u32.to_le_bytes());
        put(&mut bytes, gnu_off + 4, &(symoffset as u32).to_le_bytes());
        put(&mut bytes, gnu_off + 8, &1u32.to_le_bytes());
        let bucket = if hashed > 0 { symoffset as u32 } else { 0 };
        put(&mut bytes, gnu_off + 24, &bucket.to_le_bytes());
        for k in 0..hashed {
            let word: u32 = if k + 1 == hashed { 1 } else { 0 };
            put(&mut bytes, gnu_off + 28 + 4 * k, &word.to_le_bytes());
        }
        for (k, v) in entries.iter().enumerate() {
            let rt = (BIAS + code_off) as u64 + v;
            put(&mut bytes, init_off + 8 * k, &rt.to_le_bytes());
        }
        put(&mut bytes, code_off, &[0xccu8; CODE_LEN]);

        let ptr = |off: usize| {
            if spec.adjusted {
                (BIAS + off) as u64
            } else {
                off as u64
            }
        };
        let mut dynv: Vec<(i64, u64)> = vec![
            (DT_SYMTAB, ptr(SYMTAB_OFF)),
            (DT_STRTAB, ptr(strtab_off)),
            (DT_STRSZ, strtab.len() as u64),
            (DT_SYMENT, SYM_SIZE as u64),
        ];
        if spec.sysv {
            dynv.push((DT_HASH, ptr(sysv_off)));
        }
        if spec.gnu {
            dynv.push((DT_GNU_HASH, ptr(gnu_off)));
        }
        if let Some(raw) = spec.init_raw {
            dynv.push((DT_INIT, raw));
        } else if let Some(off) = spec.init {
            dynv.push((DT_INIT, code_off as u64 + off));
        }
        if spec.init_array.is_some() {
            dynv.push((DT_INIT_ARRAY, init_off as u64));
            dynv.push((
                DT_INIT_ARRAYSZ,
                spec.init_arraysz.unwrap_or(8 * entries.len() as u64),
            ));
        }
        if let Some(edit) = spec.edit_dyn {
            edit(&mut dynv);
        }
        if !spec.no_null {
            dynv.push((DT_NULL, 0));
        }
        assert!(dynv.len() * DYN_SIZE <= SYMTAB_OFF, "dynamic table too big");
        for (k, (tag, val)) in dynv.iter().enumerate() {
            put(&mut bytes, DYN_OFF + k * DYN_SIZE, &tag.to_le_bytes());
            put(&mut bytes, DYN_OFF + k * DYN_SIZE + 8, &val.to_le_bytes());
        }
        let dyn_len = dynv.len() * DYN_SIZE;
        bytes.resize(code_off + CODE_LEN, 0);
        Built {
            bytes,
            code_off,
            dyn_len,
            strsz: strtab.len(),
            sysv_off,
            gnu_off,
        }
    }
}

fn exports(spec: &Spec) -> Result<u32, ExportFailure> {
    let built = build(spec);
    let image = built.image();
    image_exports_no_sqlite(&image)
}

fn with_syms(syms: Vec<Sym>) -> Spec {
    Spec {
        syms,
        ..Spec::default()
    }
}

fn name_of(e: Result<u32, ExportFailure>) -> String {
    match e {
        Err(ExportFailure::Sqlite(n)) => n.to_string(),
        other => panic!("not a SQLite refusal: {other:?}"),
    }
}

/// Regression (r11 S6, Linux P2 full export inspection): the one-name
/// `dlsym("sqlite3_libversion")` probe missed every other SQLite export. Every
/// defined, externally bindable dynamic symbol (global, weak or GNU-unique;
/// default or protected visibility; any type: NOTYPE, OBJECT, FUNC, TLS,
/// IFUNC, absolute) whose name starts with `sqlite3` (any case) refuses;
/// local, hidden, internal and undefined ones do not count.
#[test]
fn regression_elf_export_visibility_and_types() {
    assert_eq!(exports(&Spec::default()), Ok(1));
    let refused = |s: Sym| name_of(exports(&with_syms(vec![func("ok", GLOBAL, 0, 0), s])));
    assert_eq!(
        refused(func("sqlite3_open_v2", GLOBAL, DEFAULT, 0)),
        "sqlite3_open_v2"
    );
    assert_eq!(
        refused(func("sqlite3_vfs_find", WEAK, DEFAULT, 0)),
        "sqlite3_vfs_find"
    );
    assert_eq!(refused(func("sqlite3_x", UNIQUE, DEFAULT, 0)), "sqlite3_x");
    assert_eq!(
        refused(func("sqlite3_y", GLOBAL, PROTECTED, 0)),
        "sqlite3_y"
    );
    assert_eq!(
        refused(func("SQLite3_Mixed", GLOBAL, DEFAULT, 0)),
        "SQLite3_Mixed"
    );
    for kind in [NOTYPE, OBJECT, STT_TLS, IFUNC] {
        let mut s = func("sqlite3_kind", GLOBAL, DEFAULT, 0);
        s.kind = kind;
        assert_eq!(refused(s), "sqlite3_kind", "type {kind}");
    }
    let mut abs = func("sqlite3_abs", GLOBAL, DEFAULT, 0x99);
    abs.shndx = SHN_ABS;
    assert_eq!(refused(abs), "sqlite3_abs");
    let long = format!("sqlite3_{}", "z".repeat(60));
    let n = exports(&with_syms(vec![func(&long, GLOBAL, DEFAULT, 0)]));
    match n {
        Err(ExportFailure::Sqlite(name)) => {
            assert!(name.truncated() && name.as_bytes().len() == 32, "{name}");
            assert!(name.to_string().ends_with("..."));
        }
        other => panic!("{other:?}"),
    }

    // Not exports, or not SQLite names.
    let mut undefined = func("sqlite3_undef", GLOBAL, DEFAULT, 0);
    undefined.shndx = SHN_UNDEF;
    let accepted = vec![
        func("sqlite3_local", LOCAL, DEFAULT, 0),
        func("sqlite3_hidden", GLOBAL, HIDDEN, 0),
        func("sqlite3_internal", WEAK, INTERNAL, 0),
        undefined,
        func("sqlite_no_three", GLOBAL, DEFAULT, 0),
        func("xsqlite3_inner", GLOBAL, DEFAULT, 0),
        func("sqlite", GLOBAL, DEFAULT, 0),
    ];
    assert_eq!(exports(&with_syms(accepted)), Ok(3));

    // An unknown binding might be an export: refuse, never skip.
    assert_eq!(
        exports(&with_syms(vec![func("whatever", 13, DEFAULT, 0)])),
        Err(ExportFailure::Elf(ElfError::Unsupported("symbol binding")))
    );
}

/// Regression (r11 S6): partial or malformed inspection must refuse, never
/// accept: no `DT_NULL`, a wrong or missing `DT_SYMENT`, missing tables, a
/// conflicting duplicate tag (an identical one is fine), names outside or
/// unterminated in the string table, and every work limit.
#[test]
fn regression_elf_dynamic_bounds() {
    let refused = |spec: Spec| exports(&spec).unwrap_err();
    assert_eq!(
        refused(Spec {
            no_null: true,
            ..Spec::default()
        }),
        ExportFailure::Elf(ElfError::Malformed("dynamic section (no DT_NULL)"))
    );
    assert_eq!(
        refused(Spec {
            edit_dyn: Some(|d| d.retain(|e| e.0 != DT_SYMENT)),
            ..Spec::default()
        }),
        ExportFailure::Elf(ElfError::Missing("DT_SYMENT"))
    );
    assert_eq!(
        refused(Spec {
            edit_dyn: Some(|d| d
                .iter_mut()
                .filter(|e| e.0 == DT_SYMENT)
                .for_each(|e| e.1 = 16)),
            ..Spec::default()
        }),
        ExportFailure::Elf(ElfError::Unsupported("DT_SYMENT"))
    );
    for (tag, what) in [
        (DT_SYMTAB, "DT_SYMTAB"),
        (DT_STRTAB, "DT_STRTAB"),
        (DT_STRSZ, "DT_STRSZ"),
    ] {
        let edit: DynEdit = match tag {
            DT_SYMTAB => |d| d.retain(|e| e.0 != DT_SYMTAB),
            DT_STRTAB => |d| d.retain(|e| e.0 != DT_STRTAB),
            _ => |d| d.retain(|e| e.0 != DT_STRSZ),
        };
        let spec = Spec {
            edit_dyn: Some(edit),
            ..Spec::default()
        };
        assert_eq!(refused(spec), ExportFailure::Elf(ElfError::Missing(what)));
    }
    assert_eq!(
        refused(Spec {
            gnu: false,
            sysv: false,
            ..Spec::default()
        }),
        ExportFailure::Elf(ElfError::Missing("DT_HASH or DT_GNU_HASH"))
    );
    // Duplicates: identical is accepted, conflicting refuses.
    assert_eq!(
        exports(&Spec {
            edit_dyn: Some(|d| d.push((DT_SYMENT, SYM_SIZE as u64))),
            ..Spec::default()
        }),
        Ok(1)
    );
    assert_eq!(
        refused(Spec {
            edit_dyn: Some(|d| d.push((DT_STRSZ, 1))),
            ..Spec::default()
        }),
        ExportFailure::Elf(ElfError::Malformed(
            "dynamic section (conflicting duplicate tag)"
        ))
    );
    // A string table running past the image.
    assert_eq!(
        refused(Spec {
            edit_dyn: Some(|d| d
                .iter_mut()
                .filter(|e| e.0 == DT_STRSZ)
                .for_each(|e| e.1 = 1 << 30)),
            ..Spec::default()
        }),
        ExportFailure::Elf(ElfError::Bounds("string table"))
    );

    // A name past the string table, and an unterminated last name.
    let spec = Spec::default();
    let mut built = build(&spec);
    let sym1 = SYMTAB_OFF + SYM_SIZE;
    let strsz = built.strsz as u32;
    built.bytes[sym1..sym1 + 4].copy_from_slice(&strsz.to_le_bytes());
    assert_eq!(
        image_exports_no_sqlite(&built.image()),
        Err(ExportFailure::Elf(ElfError::Bounds("symbol name")))
    );
    let mut built = build(&spec);
    let strtab_off = SYMTAB_OFF + 3 * SYM_SIZE;
    let last = strtab_off + built.strsz - 1;
    assert_eq!(built.bytes[last], 0);
    built.bytes[last] = b'x';
    // The last name belongs to the hidden symbol; make it visible.
    let sym2 = SYMTAB_OFF + 2 * SYM_SIZE;
    built.bytes[sym2 + 5] = DEFAULT;
    assert_eq!(
        image_exports_no_sqlite(&built.image()),
        Err(ExportFailure::Elf(ElfError::Malformed(
            "string table (unterminated name)"
        )))
    );

    // Work limits.
    let phdr = |p_type| Phdr {
        p_type,
        flags: PF_R,
        vaddr: 0,
        memsz: 16,
    };
    let too_many = ElfImage::from_phdrs(
        1,
        BIAS,
        MAX_PHDRS + 1,
        std::iter::repeat_n(phdr(PT_DYNAMIC), MAX_PHDRS + 1),
        None,
    );
    assert_eq!(too_many.err(), Some(ElfError::WorkLimit("program headers")));
    let loads = ElfImage::from_phdrs(
        1,
        BIAS,
        MAX_LOADS + 1,
        std::iter::repeat_n(phdr(PT_LOAD), MAX_LOADS + 1),
        None,
    );
    assert_eq!(loads.err(), Some(ElfError::WorkLimit("load segments")));
    let no_dynamic = ElfImage::from_phdrs(1, BIAS, 1, std::iter::once(phdr(PT_LOAD)), None);
    assert_eq!(no_dynamic.err(), Some(ElfError::Missing("PT_DYNAMIC")));

    // More dynamic entries than the limit (none of them DT_NULL).
    let mut bytes = vec![0u8; (MAX_DYNAMIC + 1) * DYN_SIZE];
    for k in 0..=MAX_DYNAMIC {
        bytes[k * DYN_SIZE..k * DYN_SIZE + 8].copy_from_slice(&0x7000_0000i64.to_le_bytes());
    }
    let len = bytes.len() as u64;
    let image = ElfImage::from_phdrs(
        1,
        BIAS,
        2,
        [
            Phdr {
                p_type: PT_LOAD,
                flags: PF_R,
                vaddr: 0,
                memsz: len,
            },
            Phdr {
                p_type: PT_DYNAMIC,
                flags: PF_R,
                vaddr: 0,
                memsz: len,
            },
        ]
        .into_iter(),
        Some((BIAS, &bytes)),
    )
    .unwrap();
    assert_eq!(
        for_each_export(&image, &mut |_| true),
        Err(ElfError::WorkLimit("dynamic entries"))
    );

    // A SysV symbol count above the limit.
    let mut built = build(&Spec {
        sysv: true,
        gnu: false,
        ..Spec::default()
    });
    let sysv_off = built.sysv_off;
    built.bytes[sysv_off + 4..sysv_off + 8]
        .copy_from_slice(&(MAX_SYMBOLS as u32 + 1).to_le_bytes());
    assert_eq!(
        image_exports_no_sqlite(&built.image()),
        Err(ExportFailure::Elf(ElfError::WorkLimit("symbols")))
    );
    // A symbol table running past the image (its 500 chain words still fit
    // before the code area; the symbols do not).
    assert!(sysv_off + 12 + 4 * 500 <= built.code_off);
    assert!(SYMTAB_OFF + 500 * SYM_SIZE > built.code_off + CODE_LEN);
    built.bytes[sysv_off + 4..sysv_off + 8].copy_from_slice(&500u32.to_le_bytes());
    assert_eq!(
        image_exports_no_sqlite(&built.image()),
        Err(ExportFailure::Elf(ElfError::Bounds("symbol table")))
    );

    // The name-byte budget.
    let built = build(&Spec::default());
    let image = built.image();
    let d = dynamic(&image).unwrap();
    let t = tables(&image, &d).unwrap();
    let mut budget = 3;
    assert_eq!(
        symbol_name(&image, &t, 1, &mut budget).err(),
        Some(ElfError::WorkLimit("name bytes"))
    );
    // Charged per name byte, terminator included (not per 64-byte chunk):
    // "ordinary_function" is 17 bytes plus its NUL.
    let mut budget = 18;
    assert!(symbol_name(&image, &t, 1, &mut budget).is_ok());
    assert_eq!(budget, 0);
    let mut budget = 17;
    assert_eq!(
        symbol_name(&image, &t, 1, &mut budget).err(),
        Some(ElfError::WorkLimit("name bytes"))
    );
    // The budget spans every inspected name of the walk.
    let two = with_syms(vec![
        func("aaaa", GLOBAL, DEFAULT, 0x10),
        func("bbbb", GLOBAL, DEFAULT, 0x20),
    ]);
    let built = build(&two);
    let image = built.image();
    assert_eq!(for_each_export_within(&image, 10, &mut |_| true), Ok(2));
    assert_eq!(
        for_each_export_within(&image, 9, &mut |_| true),
        Err(ElfError::WorkLimit("name bytes"))
    );
}

/// Regression (r11 S6 review N5): the walk's name budget is
/// [`MAX_NAME_BYTES`] across all names. 64 exports of 1 MiB names (plus
/// their terminators) exceed it by 64 bytes; the same walk with 64 more
/// bytes of budget passes.
#[test]
fn regression_elf_name_budget_spans_the_walk() {
    let long = MAX_NAME_BYTES / 64;
    let syms = (0..64u8)
        .map(|i| {
            let mut name = vec![b'n'; long];
            name[0] = b'a' + (i % 26);
            name[1] = b'a' + (i / 26);
            Sym {
                name,
                ..func("x", GLOBAL, DEFAULT, 0x10)
            }
        })
        .collect();
    let built = build(&Spec {
        adjusted: false,
        ..with_syms(syms)
    });
    // Above the image (64 MiB of names) so raw table offsets and relocated
    // pointers never both map; representable on 32-bit targets too.
    let image = built.image_at(1 << 30);
    assert_eq!(
        for_each_export(&image, &mut |_| true),
        Err(ElfError::WorkLimit("name bytes"))
    );
    assert_eq!(
        for_each_export_within(&image, MAX_NAME_BYTES + 64, &mut |_| true),
        Ok(64)
    );
}

/// Regression (r11 S6 review N5): an extended-section-index definition
/// whose address overflows refuses like an ordinary one (it returned
/// `Ok(None)`, the TLS answer).
#[test]
fn regression_elf_xindex_address_overflow_refuses() {
    let export = |shndx, value| Export {
        name: SymbolName::from_prefix(b"x", false),
        sqlite: false,
        kind: FUNC,
        shndx,
        value,
    };
    for shndx in [1, SHN_XINDEX] {
        assert_eq!(
            export(shndx, u64::MAX).address(1),
            Err(ElfError::Bounds("symbol value")),
            "{shndx:#x}"
        );
        assert_eq!(export(shndx, 0x10).address(0x1000), Ok(Some(0x1010)));
    }
}

/// Regression (r11 S6): glibc relocates some dynamic pointers in place and
/// not others. Raw and relocated table pointers are both accepted when only
/// one is mapped; a pointer mapped both ways, or neither, refuses. `DT_INIT`
/// and `DT_INIT_ARRAY` are always load-bias relative.
#[test]
fn regression_elf_dynamic_pointer_classification() {
    for adjusted in [true, false] {
        assert_eq!(
            exports(&Spec {
                adjusted,
                ..Spec::default()
            }),
            Ok(1),
            "adjusted {adjusted}"
        );
    }
    // A table pointer mapped nowhere.
    assert_eq!(
        exports(&Spec {
            edit_dyn: Some(|d| d
                .iter_mut()
                .filter(|e| e.0 == DT_SYMTAB)
                .for_each(|e| e.1 = 0x7fff_0000_0000)),
            ..Spec::default()
        }),
        Err(ExportFailure::Elf(ElfError::Bounds("DT_SYMTAB")))
    );
    // Ambiguous: an image whose bias is smaller than its size maps both the
    // raw and the relocated value.
    let bytes = vec![0u8; 0x3000];
    let image = ElfImage::from_phdrs(
        1,
        0x1000,
        2,
        [
            Phdr {
                p_type: PT_LOAD,
                flags: PF_R,
                vaddr: 0,
                memsz: 0x2000,
            },
            Phdr {
                p_type: PT_DYNAMIC,
                flags: PF_R,
                vaddr: 0,
                memsz: 16,
            },
        ]
        .into_iter(),
        Some((0x1000, &bytes)),
    )
    .unwrap();
    assert_eq!(
        image.table_ptr(0x1100, "DT_SYMTAB"),
        Err(ElfError::AmbiguousPointer("DT_SYMTAB"))
    );
    assert_eq!(image.table_ptr(0x2100, "DT_SYMTAB"), Ok(0x2100));
    assert_eq!(image.table_ptr(0x0100, "DT_SYMTAB"), Ok(0x1100));
    assert_eq!(
        image.table_ptr(u64::MAX, "DT_SYMTAB"),
        Err(ElfError::Bounds("DT_SYMTAB"))
    );
    // Bias zero (a non-PIE executable): raw and relocated agree.
    let zero = ElfImage::from_phdrs(
        1,
        0,
        2,
        [
            Phdr {
                p_type: PT_LOAD,
                flags: PF_R,
                vaddr: 0x1000,
                memsz: 0x1000,
            },
            Phdr {
                p_type: PT_DYNAMIC,
                flags: PF_R,
                vaddr: 0x1000,
                memsz: 16,
            },
        ]
        .into_iter(),
        Some((0x1000, &bytes)),
    )
    .unwrap();
    assert_eq!(zero.table_ptr(0x1100, "DT_SYMTAB"), Ok(0x1100));
    assert_eq!(
        image.runtime_addr(u64::MAX, "DT_INIT"),
        Err(ElfError::Bounds("DT_INIT"))
    );
    // DT_INIT is bias-relative even when its raw value happens to be mapped.
    let built = build(&Spec {
        init_raw: Some((BIAS + 0x10) as u64),
        ..Spec::default()
    });
    assert_eq!(
        initialization(&built.image()),
        Err(InitRefusal::Elf(ElfError::Bounds("DT_INIT")))
    );
}

/// Regression (r11 S6): the GNU hash table is the only symbol-count source
/// on current toolchains (no `DT_HASH`). Symbols below `symoffset` are
/// inspected; empty buckets, SysV-only and matching dual tables are counted;
/// conflicting dual tables, a bucket below `symoffset`, no buckets and a
/// chain without a terminator refuse; the step limit holds.
#[test]
fn regression_elf_gnu_hash_bounds() {
    let syms = vec![
        func("a", GLOBAL, DEFAULT, 0),
        func("b", GLOBAL, DEFAULT, 1),
        func("c", GLOBAL, DEFAULT, 2),
    ];
    for (gnu, sysv) in [(true, false), (false, true), (true, true)] {
        assert_eq!(
            exports(&Spec {
                syms: syms.clone(),
                gnu,
                sysv,
                ..Spec::default()
            }),
            Ok(3),
            "gnu {gnu} sysv {sysv}"
        );
    }
    // A SQLite export below symoffset (not hashed) is still found.
    let mut pre = syms.clone();
    pre.insert(0, func("sqlite3_unhashed", GLOBAL, DEFAULT, 3));
    assert_eq!(
        name_of(exports(&Spec {
            syms: pre.clone(),
            unhashed: 1,
            ..Spec::default()
        })),
        "sqlite3_unhashed"
    );
    // Every symbol unhashed: all buckets empty, count = symoffset.
    assert_eq!(
        name_of(exports(&Spec {
            syms: pre,
            unhashed: 4,
            ..Spec::default()
        })),
        "sqlite3_unhashed"
    );

    let spec = Spec {
        syms: syms.clone(),
        gnu: true,
        sysv: true,
        ..Spec::default()
    };
    // Conflicting dual counts.
    let mut built = build(&spec);
    let sysv_off = built.sysv_off;
    built.bytes[sysv_off + 4..sysv_off + 8].copy_from_slice(&5u32.to_le_bytes());
    assert_eq!(
        image_exports_no_sqlite(&built.image()),
        Err(ExportFailure::Elf(ElfError::Malformed(
            "hash tables (SysV and GNU symbol counts differ)"
        )))
    );

    let gnu_only = Spec {
        syms,
        ..Spec::default()
    };
    // Bucket below symoffset.
    let mut built = build(&gnu_only);
    let g = built.gnu_off;
    built.bytes[g + 4..g + 8].copy_from_slice(&2u32.to_le_bytes());
    built.bytes[g + 24..g + 28].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        image_exports_no_sqlite(&built.image()),
        Err(ExportFailure::Elf(ElfError::Malformed(
            "GNU hash (bucket below symoffset)"
        )))
    );
    // No buckets.
    let mut built = build(&gnu_only);
    built.bytes[g..g + 4].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(
        image_exports_no_sqlite(&built.image()),
        Err(ExportFailure::Elf(ElfError::Malformed(
            "GNU hash (no buckets)"
        )))
    );
    // A chain with no terminator runs off the readable image.
    let mut built = build(&gnu_only);
    let chain_end = g + 28 + 4 * 3;
    built.bytes[chain_end - 4..chain_end].copy_from_slice(&0u32.to_le_bytes());
    for b in &mut built.bytes[chain_end..built.code_off] {
        *b = 0;
    }
    assert!(matches!(
        image_exports_no_sqlite(&built.image()),
        Err(ExportFailure::Elf(ElfError::Bounds(_)))
    ));
    // The step limit: more (empty) buckets than steps.
    let nbuckets = MAX_HASH_STEPS + 1;
    let mut bytes = vec![0u8; 16 + 8 + 4 * nbuckets];
    bytes[0..4].copy_from_slice(&(nbuckets as u32).to_le_bytes());
    bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
    let len = bytes.len() as u64;
    let image = ElfImage::from_phdrs(
        1,
        BIAS,
        2,
        [
            Phdr {
                p_type: PT_LOAD,
                flags: PF_R,
                vaddr: 0,
                memsz: len,
            },
            Phdr {
                p_type: PT_DYNAMIC,
                flags: PF_R,
                vaddr: 0,
                memsz: 0,
            },
        ]
        .into_iter(),
        Some((BIAS, &bytes)),
    )
    .unwrap();
    assert_eq!(
        gnu_symbol_count(&image, BIAS),
        Err(ElfError::WorkLimit("hash-table steps"))
    );
}

/// Regression (r11 S6 skeptic #1): the SysV `DT_HASH` count was `nchain`,
/// read without checking the buckets or chains. glibc's SysV lookup never
/// reads `nchain` (it follows `bucket[h % nbucket]` and `chain[i]` to a
/// zero), so shrinking `nchain` from 4 to 1 hid a `sqlite3*` export the
/// loader still binds, and the inspection accepted (`Ok(0)`). Now every
/// chain is walked: an index at or past `nchain`, no buckets, a cycle, and
/// bucket or chain arrays outside readable memory refuse; a broken SysV
/// table refuses even when a valid GNU table is present.
#[test]
fn regression_elf_sysv_hash_chains_bound_nchain() {
    let sysv = Spec {
        syms: vec![
            func("a", GLOBAL, DEFAULT, 0),
            func("b", GLOBAL, DEFAULT, 1),
            func("sqlite3_hidden_by_nchain", GLOBAL, DEFAULT, 2),
        ],
        gnu: false,
        sysv: true,
        ..Spec::default()
    };
    // The well-formed table: every symbol reachable, the export found.
    assert_eq!(name_of(exports(&sysv)), "sqlite3_hidden_by_nchain");
    let edit = |f: &dyn Fn(&mut Built)| {
        let mut built = build(&sysv);
        f(&mut built);
        image_exports_no_sqlite(&built.image())
    };
    let word = |b: &mut Built, k: usize, v: u32| {
        let at = b.sysv_off + 4 * k;
        b.bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
    };
    let malformed = |what| Err(ExportFailure::Elf(ElfError::Malformed(what)));
    // The skeptic's repro: nchain 4 -> 1 (was Ok(0)).
    assert_eq!(
        edit(&|b| word(b, 1, 1)),
        malformed("SysV hash (index past nchain)")
    );
    // nchain 4 -> 3: the export (index 3) is the bucket head.
    assert_eq!(
        edit(&|b| word(b, 1, 3)),
        malformed("SysV hash (index past nchain)")
    );
    // A chain word past nchain (chain[2] is word 3 + 2).
    assert_eq!(
        edit(&|b| word(b, 5, 9)),
        malformed("SysV hash (index past nchain)")
    );
    // A cycle: chain[1] -> 3 -> 2 -> 1 -> 3 ...
    assert_eq!(
        edit(&|b| word(b, 4, 3)),
        malformed("SysV hash (chain cycle)")
    );
    // A self-loop at the bucket head.
    assert_eq!(
        edit(&|b| word(b, 6, 3)),
        malformed("SysV hash (chain cycle)")
    );
    // No buckets.
    assert_eq!(
        edit(&|b| word(b, 0, 0)),
        malformed("SysV hash (no buckets)")
    );
    // A bucket array past the readable image.
    assert_eq!(
        edit(&|b| word(b, 0, 0x0100_0000)),
        Err(ExportFailure::Elf(ElfError::Bounds("DT_HASH")))
    );
    // A chain array past the readable image (nchain within the symbol
    // limit, larger than the image).
    assert_eq!(
        edit(&|b| word(b, 1, 0x0004_0000)),
        Err(ExportFailure::Elf(ElfError::Bounds("DT_HASH")))
    );
    // nchain above the symbol limit.
    assert_eq!(
        edit(&|b| word(b, 1, (MAX_SYMBOLS + 1) as u32)),
        Err(ExportFailure::Elf(ElfError::WorkLimit("symbols")))
    );
    // Both tables: a broken SysV table refuses although the GNU table (the
    // one glibc uses) is valid and the counts would agree.
    let both = Spec {
        gnu: true,
        ..sysv.clone()
    };
    let mut built = build(&both);
    word(&mut built, 5, 9);
    assert_eq!(
        image_exports_no_sqlite(&built.image()),
        malformed("SysV hash (index past nchain)")
    );
    assert_eq!(name_of(exports(&both)), "sqlite3_hidden_by_nchain");
}

/// Regression (r11 S6, F3 option (b), issue #192): the original F3 required
/// `DT_INIT` to equal a `dlsym`-visible `_init`, which glibc's CRT hides, so
/// it refused every ordinary DSO. Now: the constructor must be init-array
/// entry zero, and `DT_INIT` must not be the address of any inspected
/// exported definition (aliases, weak, protected, absolute, an IFUNC's
/// resolver address); a hidden definition there passes (an assumption); TLS
/// values are offsets and never compared; a present zero `DT_INIT` is not
/// absent; a missing, empty or misaligned init array refuses.
#[test]
fn regression_loader_dt_init_export_comparison() {
    let ctor = |b: &Built| b.code(0x30);
    let check = |spec: Spec| {
        let built = build(&spec);
        check_initialization(&built.image(), ctor(&built))
    };
    // No DT_INIT, constructor first.
    let built = build(&Spec::default());
    assert_eq!(
        check_initialization(&built.image(), ctor(&built)),
        Ok(Initialization {
            dt_init: None,
            first_init_array: built.code(0x30),
        })
    );
    // Hidden initializer at DT_INIT: accepted (the CRT `_init` case).
    let built = build(&Spec {
        init: Some(0x20),
        ..Spec::default()
    });
    assert_eq!(
        check_initialization(&built.image(), ctor(&built)).map(|i| i.dt_init),
        Ok(Some(built.code(0x20)))
    );
    // Exported definitions at DT_INIT: refused, whatever the name.
    let exported = |s: Sym| {
        let mut syms = Spec::default().syms;
        syms.push(s);
        check(Spec {
            syms,
            init: Some(0x40),
            ..Spec::default()
        })
    };
    let at = |name: &str| {
        Err(InitRefusal::ExportedDtInit(SymbolName::from_prefix(
            name.as_bytes(),
            false,
        )))
    };
    assert_eq!(
        exported(func("my_init", GLOBAL, DEFAULT, 0x40)),
        at("my_init")
    );
    assert_eq!(
        exported(func("weak_alias", WEAK, DEFAULT, 0x40)),
        at("weak_alias")
    );
    assert_eq!(exported(func("prot", GLOBAL, PROTECTED, 0x40)), at("prot"));
    let mut ifunc = func("resolver", GLOBAL, DEFAULT, 0x40);
    ifunc.kind = IFUNC;
    assert_eq!(exported(ifunc), at("resolver"));
    // An absolute definition whose value is DT_INIT's runtime address.
    let built = build(&Spec {
        init: Some(0x40),
        ..Spec::default()
    });
    let mut abs = func("abs_init", GLOBAL, DEFAULT, built.code(0x40) as u64);
    abs.shndx = SHN_ABS;
    assert_eq!(exported(abs), at("abs_init"));
    // Hidden or local at that address, a TLS offset equal to it, or an
    // export elsewhere: accepted.
    assert!(exported(func("hidden_custom", GLOBAL, HIDDEN, 0x40)).is_ok());
    assert!(exported(func("local_custom", LOCAL, DEFAULT, 0x40)).is_ok());
    let mut tls = func("tls_var", GLOBAL, DEFAULT, 0);
    tls.kind = STT_TLS;
    tls.shndx = 2;
    tls.value = (built.code(0x40) - BIAS) as u64;
    assert!(exported(tls).is_ok());
    assert!(exported(func("elsewhere", GLOBAL, DEFAULT, 0x41)).is_ok());
    // A reserved section index other than SHN_ABS cannot be compared.
    let mut common = func("common", GLOBAL, DEFAULT, 0x40);
    common.shndx = 0xfff2;
    assert_eq!(
        exported(common),
        Err(InitRefusal::Elf(ElfError::Unsupported(
            "reserved section index"
        )))
    );

    // A present zero DT_INIT (the image start: not executable here) and a
    // DT_INIT outside every executable segment refuse.
    for raw in [0u64, 0x1010] {
        assert_eq!(
            check(Spec {
                init_raw: Some(raw),
                ..Spec::default()
            }),
            Err(InitRefusal::Elf(ElfError::Bounds("DT_INIT"))),
            "raw {raw:#x}"
        );
    }

    // Init array rows.
    assert_eq!(
        check(Spec {
            init_array: None,
            ..Spec::default()
        }),
        Err(InitRefusal::InitArray("no DT_INIT_ARRAY"))
    );
    assert_eq!(
        check(Spec {
            init_arraysz: Some(0),
            ..Spec::default()
        }),
        Err(InitRefusal::InitArray("empty init array"))
    );
    assert_eq!(
        check(Spec {
            init_arraysz: Some(12),
            ..Spec::default()
        }),
        Err(InitRefusal::InitArray(
            "init array size is not a multiple of the pointer size"
        ))
    );
    assert_eq!(
        check(Spec {
            init_arraysz: Some(1 << 40),
            ..Spec::default()
        }),
        Err(InitRefusal::Elf(ElfError::Bounds("init array")))
    );
    assert_eq!(
        check(Spec {
            edit_dyn: Some(|d| d.retain(|e| e.0 != DT_INIT_ARRAYSZ)),
            ..Spec::default()
        }),
        Err(InitRefusal::InitArray(
            "DT_INIT_ARRAY without DT_INIT_ARRAYSZ"
        ))
    );
    // Another entry first.
    assert_eq!(
        check(Spec {
            init_array: Some(vec![0x50, 0x30]),
            ..Spec::default()
        }),
        Err(InitRefusal::InitArray(
            "the constructor is not the first init-array entry"
        ))
    );
    // The constructor last of several is still refused.
    let built = build(&Spec {
        init_array: Some(vec![0x50, 0x60, 0x30]),
        ..Spec::default()
    });
    assert_eq!(
        initialization(&built.image()).map(|i| i.first_init_array),
        Ok(built.code(0x50))
    );
}

/// Real loader, Linux glibc: libc's dynamic symbols as the walk reads them
/// agree with `dlsym` (no IFUNC is resolved: names with an IFUNC definition
/// are skipped), libc exports no `sqlite3*` name, and its initialization
/// facts read back. Regression (r11 S6): the GNU-hash walk is the path real
/// images take; synthetic bytes alone could agree with a wrong parser.
#[cfg(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little",
    target_os = "linux",
    target_env = "gnu"
))]
#[test]
fn regression_elf_exports_walk_matches_dlsym() {
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::CString;

    if cfg!(target_feature = "crt-static") {
        eprintln!("skip: libc is linked statically into this executable");
        return;
    }
    let anchor = libc::qsort as *const () as usize;
    let image = image_containing(anchor).expect("libc image");
    let mut by_name: BTreeMap<Vec<u8>, BTreeSet<usize>> = BTreeMap::new();
    let mut ifunc: BTreeSet<Vec<u8>> = BTreeSet::new();
    let visited = for_each_export(&image, &mut |e| {
        let name = e.name.as_bytes().to_vec();
        if e.name.truncated() {
            return true;
        }
        if e.kind == IFUNC {
            ifunc.insert(name);
        } else if let Ok(Some(a)) = e.address(image.bias) {
            if e.kind == FUNC || e.kind == OBJECT {
                by_name.entry(name).or_default().insert(a);
            }
        }
        true
    })
    .unwrap();
    assert!(visited > 500, "libc exports {visited} symbols?");
    assert_eq!(image_exports_no_sqlite(&image), Ok(visited));
    // SAFETY: `info` is plain data; the handle is of an already loaded image.
    let handle = unsafe {
        let mut info: libc::Dl_info = std::mem::zeroed();
        assert_ne!(libc::dladdr(anchor as *const libc::c_void, &mut info), 0);
        libc::dlopen(info.dli_fname, libc::RTLD_LAZY | libc::RTLD_NOLOAD)
    };
    assert!(!handle.is_null());
    let mut checked = 0;
    for (name, addrs) in &by_name {
        if ifunc.contains(name) {
            continue;
        }
        let c = CString::new(name.clone()).unwrap();
        let found = unsafe { libc::dlsym(handle, c.as_ptr()) } as usize;
        if found == 0 {
            // Only non-default (compat) versions: an unversioned lookup
            // skips them.
            continue;
        }
        if !image.contains(found, 1, 0) {
            // `dlsym` on libc's handle also searches its dependencies (ld.so
            // on older glibc); a definition found there is not libc's.
            continue;
        }
        assert!(
            addrs.contains(&found),
            "{}: dlsym {found:#x}, walk {addrs:x?}",
            String::from_utf8_lossy(name)
        );
        checked += 1;
    }
    assert!(by_name.contains_key(&b"qsort"[..]));
    assert!(checked > 500, "{checked}");
    unsafe { libc::dlclose(handle) };
    // libc has an init array on toolchains configured with
    // `--enable-initfini-array` (every current one); without one there is
    // nothing for option (b) to compare. Its DT_INIT (absent on current
    // glibc) is either no export, or option (b) names the export at that
    // address.
    let init = match initialization(&image) {
        Ok(init) => init,
        Err(InitRefusal::InitArray("no DT_INIT_ARRAY")) => {
            eprintln!("skip: this libc has no DT_INIT_ARRAY (option (b) rows not run)");
            return;
        }
        Err(other) => panic!("libc initialization facts: {other:?}"),
    };
    match check_initialization(&image, init.first_init_array) {
        Ok(_) => {}
        Err(InitRefusal::ExportedDtInit(name)) => {
            assert!(init.dt_init.is_some());
            eprintln!("note: libc's DT_INIT is the export {name}");
        }
        Err(other) => panic!("libc option (b): {other:?}"),
    }
}

/// Real shared objects compiled at test time (`CC`, split on whitespace,
/// else `cc`; `skip:` without a C compiler), loaded through the real loader.
#[cfg(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little",
    target_os = "linux",
    target_env = "gnu"
))]
mod real_dso {
    use std::ffi::CString;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::super::super::host::{host_object, same_private_image, HostFailure, Lookup};
    use super::super::super::install::{
        export_check, proof_decision, InstallState, InstallStatus, InstallWhy, Witness,
    };
    use super::*;

    /// Drives the private initializer's cell with the proof's own decision
    /// over the real loader lookup and the real export check of `anchor`'s
    /// image, and asserts that it refuses with `refusal` before any
    /// installation, leaving the cell non-terminal (a later passing proof
    /// still installs once).
    ///
    /// Where the tested seam ends: `private_proof` itself is a one-line
    /// delegate (`proof_decision(&anchors, module, &host_object,
    /// export_check)`) whose anchors are this test executable's constructor
    /// and linked SQLite, which refuse `MainExecutable` before the export
    /// check runs. Everything from `proof_decision` down (image check,
    /// `export_check`, `elf::image_containing`, the export walk,
    /// `export_refusal`) and the cell (`InstallState::private`) is driven
    /// here on a real loaded image; only that delegate's argument list is
    /// not driven negatively.
    fn assert_refused_before_install(anchor: usize, refusal: HostFailure) {
        const WITNESS: Witness = Witness {
            why: InstallWhy::PrivateInstance,
            threads_at_install: Some(2),
            exports_checked: Some(1),
        };
        let state = InstallState::new();
        let calls = std::cell::Cell::new(0u32);
        let got = state.private(
            || proof_decision(&[("module", anchor)], anchor, &host_object, export_check),
            |_| {
                calls.set(calls.get() + 1);
                Ok(WITNESS)
            },
        );
        assert_eq!(got, Err(InstallStatus::NotPrivate(refusal)));
        assert_eq!(calls.get(), 0, "refused before any installation");
        assert_eq!(state.status(), Err(InstallStatus::NotRun), "not terminal");
        assert_eq!(state.observation(), None, "no constructor observation");
        // Non-terminal: a later passing proof still installs, once.
        let got = state.private(
            || Ok(()),
            |()| {
                calls.set(calls.get() + 1);
                Ok(WITNESS)
            },
        );
        assert_eq!(got, Ok(WITNESS));
        assert_eq!(calls.get(), 1);
    }

    /// A statically linked test executable would load these objects against
    /// a second (shared) libc; their threads and initializers would run
    /// there. Skip, like `regression_elf_exports_walk_matches_dlsym`.
    fn static_executable() -> bool {
        if cfg!(target_feature = "crt-static") {
            eprintln!("skip: libc is linked statically into this executable");
            return true;
        }
        false
    }

    /// Compile `source` into `dir/lib{name}.so` with extra link `args`.
    /// `None` when there is no C compiler.
    fn shared_object(dir: &Path, name: &str, source: &str, args: &[&str]) -> Option<PathBuf> {
        let cc_line = std::env::var("CC").unwrap_or_default();
        let mut words = cc_line.split_whitespace();
        let cc = words.next().unwrap_or("cc").to_owned();
        let c = dir.join(format!("{name}.c"));
        let so = dir.join(format!("lib{name}.so"));
        std::fs::write(&c, source).unwrap();
        let built = Command::new(&cc)
            .args(words)
            .args(["-shared", "-fPIC", "-O1", "-pthread", "-o"])
            .arg(&so)
            .arg(&c)
            .args(args)
            .status();
        // Only a missing compiler skips. A compiler that runs and fails
        // (missing pthread headers, an odd `CC`) panics: a silent skip there
        // would hide the rows on a host that claims to have a compiler.
        match built {
            Ok(status) if status.success() => Some(so),
            Ok(status) => panic!("{name}.c did not compile with {cc:?}: {status}"),
            Err(e) => {
                eprintln!("skip: no C compiler ({cc:?}: {e})");
                None
            }
        }
    }

    struct Loaded(*mut libc::c_void);

    impl Loaded {
        fn open(path: &Path) -> Self {
            let c = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: loading a fixture compiled by this test; its
            // initializers are the code under test and are harmless.
            let handle = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            assert!(!handle.is_null(), "dlopen {path:?}: {:?}", unsafe {
                std::ffi::CStr::from_ptr(libc::dlerror())
            });
            Self(handle)
        }

        fn sym(&self, name: &std::ffi::CStr) -> usize {
            let p = unsafe { libc::dlsym(self.0, name.as_ptr()) } as usize;
            assert_ne!(p, 0, "missing {name:?}");
            p
        }
    }

    impl Drop for Loaded {
        fn drop(&mut self) {
            unsafe { libc::dlclose(self.0) };
        }
    }

    const TARGET: &str = r#"
static int ctor_ran;
/* Priority 101: sorted before the CRT's unprioritized entries, so this is
   init-array entry zero (what F3 checks). */
__attribute__((constructor(101))) void pub_target_constructor(void) { ctor_ran = 1; }
/* A harmless exported entry point: 1 before the constructor ran, 2 after. */
int pub_target_ping(void) { return ctor_ran ? 2 : 1; }
"#;

    const DEPENDENCY: &str = r#"
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
/* The target's exported entry point; bound when this dependency is
   relocated, before any initializer of the target's load runs. */
extern int pub_target_ping(void);
static int (*_Atomic slot)(void);
static atomic_int done;
static int seen = -1;
static void *run(void *arg) {
    int (*f)(void);
    (void)arg;
    while (!(f = atomic_load(&slot))) sched_yield();
    seen = f();
    atomic_store(&done, 1);
    return 0;
}
__attribute__((constructor)) static void pubdep_init(void) {
    pthread_t worker;
    /* The worker exists first; then the entry point is published to it. */
    if (pthread_create(&worker, 0, run, 0) != 0) return;
    atomic_store(&slot, &pub_target_ping);
    while (!atomic_load(&done)) sched_yield();
    pthread_join(worker, 0);
}
int pubdep_seen(void) { return seen; }
void *pubdep_published(void) { return (void *)atomic_load(&slot); }
"#;

    /// Regression (r11 S6, issue #192, the publication counterexample): a
    /// dependency B of a target image A obtains A's exported entry point
    /// and hands it to a worker thread that calls it, all inside B's
    /// initializer, before A's constructor runs. A exports no `sqlite3*`
    /// name, its constructor is init-array entry zero, and its `DT_INIT` is
    /// no export: image ownership (F1), the full export walk (F2) and option
    /// (b) (F3) all accept A. The checks do not see the publication; that
    /// exclusivity stays the documented caller contract of
    /// `install_private_instance`, not a property any of them proves. The
    /// published capability is harmless (no SQLite is involved).
    #[test]
    fn regression_dependency_publication_is_not_proved() {
        if static_executable() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let Some(_dep) = shared_object(dir, "pubdep", DEPENDENCY, &[]) else {
            return;
        };
        let rpath = format!("-Wl,-rpath,{}", dir.display());
        let link = format!("-L{}", dir.display());
        let Some(target) = shared_object(
            dir,
            "pubtarget",
            TARGET,
            &[&link, &rpath, "-Wl,--no-as-needed", "-lpubdep"],
        ) else {
            return;
        };
        let lib = Loaded::open(&target);
        let ctor = lib.sym(c"pub_target_constructor");
        let ping = lib.sym(c"pub_target_ping");
        let seen = lib.sym(c"pubdep_seen");
        let published = lib.sym(c"pubdep_published");
        // SAFETY: the fixture's functions, with these C signatures.
        let (seen, published, ping_fn) = unsafe {
            let seen: extern "C" fn() -> i32 = std::mem::transmute(seen);
            let published: extern "C" fn() -> usize = std::mem::transmute(published);
            let ping_fn: extern "C" fn() -> i32 = std::mem::transmute(ping);
            (seen(), published(), ping_fn)
        };

        // The publication happened: B's worker called A's entry point before
        // A's constructor ran.
        assert_eq!(seen, 1, "the worker did not call A before its constructor");
        assert_eq!(published, ping, "the published pointer is A's export");
        assert_eq!(ping_fn(), 2, "A's constructor ran afterwards");

        // A's own observations accept it.
        let image = same_private_image(&host_object, &[("constructor", ctor), ("module", ping)])
            .expect("F1: one non-main image");
        assert_eq!(host_object(published), Lookup::Found(image));
        let elf = image_containing(ctor).unwrap();
        assert_eq!(elf.id, image.id);
        let exports = image_exports_no_sqlite(&elf).expect("F2: no sqlite3* export");
        assert!(exports >= 2, "{exports}");
        let init = check_initialization(&elf, ctor).expect("F3 (b): entry zero, DT_INIT no export");
        assert_eq!(init.first_init_array, ctor);
    }

    /// Regression (r11 S6, F3 option (b) on real images): an exported custom
    /// initializer (`-Wl,-init=` an exported function) refuses as
    /// `ExportedDtInit`; a hidden one passes (an assumption, not an
    /// observation); a protected `sqlite3*` export that is not
    /// `sqlite3_libversion` refuses the full export walk.
    #[test]
    fn regression_dso_initializer_and_export_rows() {
        if static_executable() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let source = r#"
static int ran;
__attribute__((constructor(101))) void rows_constructor(void) { ran |= 1; }
void rows_custom_init(void) { ran |= 2; }
__attribute__((visibility("hidden"))) void rows_hidden_init(void) { ran |= 4; }
int rows_ran(void) { return ran; }
"#;
        let Some(exported) =
            shared_object(dir, "rowsexported", source, &["-Wl,-init=rows_custom_init"])
        else {
            return;
        };
        let lib = Loaded::open(&exported);
        let ran: extern "C" fn() -> i32 = unsafe { std::mem::transmute(lib.sym(c"rows_ran")) };
        assert_eq!(ran(), 3, "the custom initializer and the constructor ran");
        let ctor = lib.sym(c"rows_constructor");
        let elf = image_containing(ctor).unwrap();
        let init = initialization(&elf).unwrap();
        assert_eq!(init.dt_init, Some(lib.sym(c"rows_custom_init")));
        assert_eq!(
            check_initialization(&elf, ctor),
            Err(InitRefusal::ExportedDtInit(SymbolName::from_prefix(
                b"rows_custom_init",
                false
            )))
        );
        drop(lib);

        let Some(hidden) =
            shared_object(dir, "rowshidden", source, &["-Wl,-init=rows_hidden_init"])
        else {
            return;
        };
        let lib = Loaded::open(&hidden);
        let ran: extern "C" fn() -> i32 = unsafe { std::mem::transmute(lib.sym(c"rows_ran")) };
        assert_eq!(ran(), 5, "the hidden initializer and the constructor ran");
        let ctor = lib.sym(c"rows_constructor");
        let elf = image_containing(ctor).unwrap();
        let init = check_initialization(&elf, ctor).expect("hidden DT_INIT is assumed");
        assert!(init.dt_init.is_some());
        // The private proof's export check accepts it and reports the count.
        let image = same_private_image(&host_object, &[("module", ctor)]).unwrap();
        let walked = image_exports_no_sqlite(&elf).unwrap();
        assert_eq!(export_check(ctor, image), Ok(Some(walked)));
        drop(lib);

        let sqlite = r#"
__attribute__((visibility("protected"))) int sqlite3_fake_open(void) { return 0; }
int rows_other(void) { return 1; }
"#;
        let Some(sq) = shared_object(dir, "rowssqlite", sqlite, &[]) else {
            return;
        };
        let lib = Loaded::open(&sq);
        let elf = image_containing(lib.sym(c"rows_other")).unwrap();
        assert_eq!(
            image_exports_no_sqlite(&elf),
            Err(ExportFailure::Sqlite(SymbolName::from_prefix(
                b"sqlite3_fake_open",
                false
            )))
        );
        // The one-name probe this walk replaced did not see it.
        assert!(unsafe { libc::dlsym(lib.0, c"sqlite3_libversion".as_ptr()) }.is_null());
        // Regression (r11 S6 review N2): the private proof's export check
        // turns the walk's finding into its refusal (not dropped by an
        // `.ok()` or a mapping), and refuses an image that is not the one
        // the proof named.
        let anchor = lib.sym(c"rows_other");
        let image = same_private_image(&host_object, &[("module", anchor)]).unwrap();
        assert_eq!(
            export_check(anchor, image),
            Err(HostFailure::SqliteExportedNamed(SymbolName::from_prefix(
                b"sqlite3_fake_open",
                false
            )))
        );
        // Regression (r11 S6 fix skeptic #1): the proof's decision, with the
        // real loader lookup and the real export check, refuses this image
        // (its anchor passes the image check). Only `private_proof`'s
        // one-line delegate to `proof_decision` is not driven negatively:
        // the test executable's own proof refuses `MainExecutable` first.
        assert_eq!(
            proof_decision(&[("module", anchor)], anchor, &host_object, export_check),
            Err(HostFailure::SqliteExportedNamed(SymbolName::from_prefix(
                b"sqlite3_fake_open",
                false
            )))
        );
        // Through the private initializer's cell: refused before any
        // installation, the state unchanged and non-terminal.
        assert_refused_before_install(
            anchor,
            HostFailure::SqliteExportedNamed(SymbolName::from_prefix(b"sqlite3_fake_open", false)),
        );
        let libc_image =
            same_private_image(&host_object, &[("libc", libc::qsort as *const () as usize)])
                .unwrap();
        assert_eq!(
            export_check(anchor, libc_image),
            Err(HostFailure::ImageMismatch {
                what: "export inspection"
            })
        );
    }

    /// Regression (r11 S6 skeptic #1, on the real loader): a SysV-only
    /// image (`-Wl,--hash-style=sysv`) whose `DT_HASH` `nchain` is patched
    /// from its real value to 1. glibc ignores `nchain`, so `dlsym` still
    /// binds `sqlite3_fake_open` in the patched copy; the inspection
    /// accepted it (`Ok(0)`) and now refuses as malformed. The unpatched
    /// image refuses as a SQLite export.
    #[test]
    fn regression_dso_sysv_hash_nchain() {
        if static_executable() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let source = r#"
int sqlite3_fake_open(void) { return 7; }
int sysv_other(void) { return 1; }
"#;
        let Some(so) = shared_object(dir, "sysvhash", source, &["-Wl,--hash-style=sysv"]) else {
            return;
        };
        let lib = Loaded::open(&so);
        let elf = image_containing(lib.sym(c"sysv_other")).unwrap();
        let d = dynamic(&elf).unwrap();
        assert!(d.gnu_hash.is_none(), "--hash-style=sysv wrote DT_GNU_HASH");
        let h = elf.table_ptr(d.hash.expect("DT_HASH"), "DT_HASH").unwrap();
        let nchain = elf.u32_at(h + 4, "DT_HASH").unwrap();
        assert!(nchain > 2, "{nchain}");
        assert_eq!(
            image_exports_no_sqlite(&elf),
            Err(ExportFailure::Sqlite(SymbolName::from_prefix(
                b"sqlite3_fake_open",
                false
            )))
        );
        // The hash table's file offset: the first load segment maps the file
        // from offset 0 at the load bias (checked against the loaded bytes).
        let off = h - elf.bias;
        drop(lib);
        let mut bytes = std::fs::read(&so).unwrap();
        assert_eq!(
            u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap()),
            nchain,
            "DT_HASH is not at its virtual address in the file"
        );
        bytes[off + 4..off + 8].copy_from_slice(&1u32.to_le_bytes());
        let patched = dir.join("libsysvpatched.so");
        std::fs::write(&patched, &bytes).unwrap();
        let lib = Loaded::open(&patched);
        let fake: extern "C" fn() -> i32 =
            unsafe { std::mem::transmute(lib.sym(c"sqlite3_fake_open")) };
        assert_eq!(fake(), 7, "glibc binds the export past nchain");
        let elf = image_containing(lib.sym(c"sysv_other")).unwrap();
        assert_eq!(
            image_exports_no_sqlite(&elf),
            Err(ExportFailure::Elf(ElfError::Malformed(
                "SysV hash (index past nchain)"
            )))
        );
        // Regression (r11 S6 fix skeptic g4 #1): an image whose export
        // inspection cannot complete refuses through the proof's own
        // decision with the real loader lookup and the real export check
        // (`ExportInspection`, not an accepted partial walk), before any
        // installation, leaving the cell non-terminal.
        let anchor = lib.sym(c"sysv_other");
        let refusal =
            HostFailure::ExportInspection(ElfError::Malformed("SysV hash (index past nchain)"));
        let image = same_private_image(&host_object, &[("module", anchor)]).unwrap();
        assert_eq!(export_check(anchor, image), Err(refusal));
        assert_eq!(
            proof_decision(&[("module", anchor)], anchor, &host_object, export_check),
            Err(refusal)
        );
        assert_refused_before_install(anchor, refusal);
    }
}

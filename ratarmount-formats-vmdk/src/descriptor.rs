//! Text descriptor parse (`# Disk DescriptorFile` / `createType=` / extent lines).

use std::collections::BTreeMap;

use crate::{Result, VmdkError};

/// Hosted/ESXi createTypes that are not v1 KDMV sparse.
pub(crate) const ESXI_CREATE_TYPES: &[&str] = &[
    "vmfs",
    "vmfssparse",
    "vmfsthin",
    "sesparse",
    "vsansparse",
    "vmfsraw",
    "vmfsrdm",
    "vmfseagerzeroedthick",
    "vmfspreallocated",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentKind {
    Sparse,
    Flat,
    Zero,
    /// ESXi VMFS preallocated (treated like FLAT when a host file exists).
    Vmfs,
    /// ESXi grain (COWD / VMFSSPARSE / SESparse) — v1 residual.
    EsxiSparse,
    Other,
}

impl ExtentKind {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "SPARSE" => Self::Sparse,
            "FLAT" => Self::Flat,
            "ZERO" => Self::Zero,
            "VMFS" | "VMFSRAW" => Self::Vmfs,
            "VMFSSPARSE" | "SESPARSE" | "VMFSRDM" => Self::EsxiSparse,
            _ => Self::Other,
        }
    }

    pub fn is_esxi_grain(self) -> bool {
        matches!(self, Self::EsxiSparse)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorExtent {
    pub access: String,
    pub sectors: u64,
    pub kind: ExtentKind,
    pub filename: Option<String>,
    /// FLAT/VMFS byte offset into the extent file (sectors in the descriptor).
    pub offset_sectors: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmdkDescriptor {
    pub version: u32,
    pub cid: String,
    pub parent_cid: String,
    pub create_type: String,
    pub parent_file_name_hint: Option<String>,
    pub extents: Vec<DescriptorExtent>,
    pub ddb: BTreeMap<String, String>,
}

impl VmdkDescriptor {
    pub fn parent_cid_is_none(&self) -> bool {
        let p = self.parent_cid.trim();
        p.is_empty()
            || p.eq_ignore_ascii_case("ffffffff")
            || p.eq_ignore_ascii_case("0xffffffff")
            || p == "0"
    }

    pub fn is_stream_optimized(&self) -> bool {
        self.create_type.eq_ignore_ascii_case("streamOptimized")
    }

    pub fn is_esxi_create_type(&self) -> bool {
        let t = self.create_type.to_ascii_lowercase();
        ESXI_CREATE_TYPES.iter().any(|k| t == *k)
    }
}

/// Parse a VMware disk descriptor (embedded in a KDMV file or a sidecar `.vmdk`).
pub fn parse_vmdk_descriptor(text: &str) -> Result<VmdkDescriptor> {
    let mut version = 1u32;
    let mut cid = String::new();
    let mut parent_cid = String::from("ffffffff");
    let mut create_type = String::new();
    let mut parent_file_name_hint = None;
    let mut extents = Vec::new();
    let mut ddb = BTreeMap::new();

    for raw in text.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(ext) = parse_extent_line(line)? {
            extents.push(ext);
            continue;
        }
        let Some((key, value)) = split_kv(line) else {
            continue;
        };
        let key_l = key.to_ascii_lowercase();
        match key_l.as_str() {
            "version" => {
                version = value
                    .parse::<u32>()
                    .map_err(|_| VmdkError::Msg(format!("invalid descriptor version {value:?}")))?;
            }
            "cid" => cid = value.to_ascii_lowercase(),
            "parentcid" => parent_cid = value.to_ascii_lowercase(),
            "createtype" => create_type = value.to_string(),
            "parentfilenamehint" => parent_file_name_hint = Some(value.to_string()),
            k if k.starts_with("ddb.") => {
                ddb.insert(key.to_string(), value.to_string());
            }
            _ => {}
        }
    }

    if extents.is_empty() {
        return Err(VmdkError::Msg(
            "VMDK descriptor has no extent lines (RW/RDONLY …)".into(),
        ));
    }
    Ok(VmdkDescriptor {
        version,
        cid,
        parent_cid,
        create_type,
        parent_file_name_hint,
        extents,
        ddb,
    })
}

/// First 4 KiB look like a hosted descriptor, not a binary extent.
pub fn looks_like_descriptor_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes[0] == 0 {
        return false;
    }
    // Reject KDMV / COWD / other binary magics before UTF-8 guess.
    if bytes.len() >= 4 && (bytes.starts_with(b"KDMV") || bytes.starts_with(b"COWD")) {
        return false;
    }
    let n = bytes
        .iter()
        .take(64)
        .filter(|b| b.is_ascii_graphic() || matches!(**b, b'\n' | b'\r' | b'\t' | b' '))
        .count();
    if n < 16 {
        return false;
    }
    let text = String::from_utf8_lossy(bytes);
    if text.contains("# Disk DescriptorFile") {
        return true;
    }
    let has_create = text
        .lines()
        .any(|l| l.trim().to_ascii_lowercase().starts_with("createtype="));
    let has_extent = text
        .lines()
        .any(|l| parse_extent_line(l.trim()).ok().flatten().is_some());
    has_create && has_extent
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

fn split_kv(line: &str) -> Option<(&str, &str)> {
    let eq = line.find('=')?;
    let key = line[..eq].trim();
    if key.is_empty() {
        return None;
    }
    let mut val = line[eq + 1..].trim();
    if val.len() >= 2 && val.starts_with('"') && val.ends_with('"') {
        val = &val[1..val.len() - 1];
    }
    Some((key, val))
}

fn parse_extent_line(line: &str) -> Result<Option<DescriptorExtent>> {
    let tokens = tokenize_ws_quoted(line);
    if tokens.len() < 3 {
        return Ok(None);
    }
    let access = tokens[0].to_ascii_uppercase();
    if access != "RW" && access != "RDONLY" && access != "NOACCESS" {
        return Ok(None);
    }
    let sectors = tokens[1]
        .parse::<u64>()
        .map_err(|_| VmdkError::Msg(format!("invalid VMDK extent size {:?}", tokens[1])))?;
    let kind = ExtentKind::parse(&tokens[2]);
    let filename = tokens.get(3).cloned().filter(|s| !s.is_empty());
    let offset_sectors = match tokens.get(4) {
        Some(s) => s
            .parse::<u64>()
            .map_err(|_| VmdkError::Msg(format!("invalid VMDK extent offset {s:?}")))?,
        None => 0,
    };
    Ok(Some(DescriptorExtent {
        access,
        sectors,
        kind,
        filename,
        offset_sectors,
    }))
}

fn tokenize_ws_quoted(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    for c in line.chars() {
        match c {
            '"' => in_quote = !in_quote,
            c if c.is_whitespace() && !in_quote => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType="monolithicSparse"

# Extent description
RW 2097152 SPARSE "disk.vmdk"

# The Disk Data Base
#DDB
ddb.virtualHWVersion = "4"
ddb.geometry.cylinders = "16383"
ddb.geometry.heads = "16"
ddb.geometry.sectors = "63"
ddb.adapterType = "ide"
"#;

    #[test]
    fn parse_descriptor_monolithic_sparse() {
        let d = parse_vmdk_descriptor(SAMPLE).expect("parse");
        assert_eq!(d.version, 1);
        assert_eq!(d.cid, "fffffffe");
        assert!(d.parent_cid_is_none());
        assert_eq!(d.create_type, "monolithicSparse");
        assert_eq!(d.extents.len(), 1);
        assert_eq!(d.extents[0].access, "RW");
        assert_eq!(d.extents[0].sectors, 2_097_152);
        assert_eq!(d.extents[0].kind, ExtentKind::Sparse);
        assert_eq!(d.extents[0].filename.as_deref(), Some("disk.vmdk"));
        assert_eq!(
            d.ddb.get("ddb.adapterType").map(String::as_str),
            Some("ide")
        );
    }

    #[test]
    fn parse_descriptor_split_sparse_and_zero() {
        let text = r#"
version=1
CID=abcdefff
parentCID=ffffffff
createType="twoGbMaxExtentSparse"
RW 4192256 SPARSE "test-s001.vmdk"
RW 4192256 SPARSE "test-s002.vmdk"
RW 1024 ZERO
RW 2101248 FLAT "disk-flat.vmdk" 8
"#;
        let d = parse_vmdk_descriptor(text).unwrap();
        assert_eq!(d.create_type, "twoGbMaxExtentSparse");
        assert_eq!(d.extents.len(), 4);
        assert_eq!(d.extents[2].kind, ExtentKind::Zero);
        assert!(d.extents[2].filename.is_none());
        assert_eq!(d.extents[3].kind, ExtentKind::Flat);
        assert_eq!(d.extents[3].offset_sectors, 8);
        assert_eq!(d.extents[3].filename.as_deref(), Some("disk-flat.vmdk"));
    }

    #[test]
    fn parse_descriptor_quoted_filename_with_spaces() {
        let text = r#"
createType="monolithicSparse"
RW 2048 SPARSE "my disk.vmdk"
"#;
        let d = parse_vmdk_descriptor(text).unwrap();
        assert_eq!(d.extents[0].filename.as_deref(), Some("my disk.vmdk"));
    }

    #[test]
    fn parse_descriptor_vmfssparse_is_esxi() {
        let text = r#"
createType="vmfsSparse"
RW 1048576 VMFSSPARSE "delta.vmdk"
"#;
        let d = parse_vmdk_descriptor(text).unwrap();
        assert!(d.is_esxi_create_type());
        assert!(d.extents[0].kind.is_esxi_grain());
    }

    #[test]
    fn parse_descriptor_stream_optimized() {
        let d =
            parse_vmdk_descriptor("createType=\"streamOptimized\"\nRW 1024 SPARSE \"x.vmdk\"\n")
                .unwrap();
        assert!(d.is_stream_optimized());
        assert!(!d.is_esxi_create_type());
    }

    #[test]
    fn parse_descriptor_parent_cid_is_delta() {
        let d = parse_vmdk_descriptor(
            "createType=\"monolithicSparse\"\nparentCID=12345678\nRW 8 SPARSE \"a.vmdk\"\n",
        )
        .unwrap();
        assert!(!d.parent_cid_is_none());
    }

    #[test]
    fn parse_descriptor_rejects_empty_extents() {
        let err = parse_vmdk_descriptor("createType=\"monolithicSparse\"\n").unwrap_err();
        assert!(err.to_string().contains("no extent"), "unexpected: {err}");
    }

    #[test]
    fn looks_like_descriptor_text_sample() {
        assert!(looks_like_descriptor_text(SAMPLE.as_bytes()));
        assert!(!looks_like_descriptor_text(b"KDMV...."));
        assert!(!looks_like_descriptor_text(b"\0\0\0\0"));
        assert!(!looks_like_descriptor_text(b"not a disk"));
    }
}

use std::collections::BTreeSet;
use std::io::{Read, Seek};

use serde_json::{json, Map, Value};

use crate::{checked_add, elements, invalid, Parsed, Result, Tensor, MAX_HEADER_SIZE};

/// Arrays above this length retain their type, length and first 16 values.
pub const ARRAY_SUMMARY_THRESHOLD: u64 = 1024;
const ARRAY_PREVIEW: u64 = 16;
const MAX_ARRAY_DEPTH: usize = 16;

struct Header<'a, R> {
    reader: &'a mut R,
    position: u64,
    limit: u64,
}

impl<R: Read> Header<'_, R> {
    fn bytes<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.reserve(N as u64)?;
        let mut bytes = [0; N];
        self.reader.read_exact(&mut bytes)?;
        Ok(bytes)
    }
    fn reserve(&mut self, length: u64) -> Result<()> {
        self.position = checked_add(self.position, length)?;
        if self.position > self.limit {
            return Err(invalid(
                "truncated or oversized GGUF header (limit 100 MiB)",
            ));
        }
        Ok(())
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.bytes()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.bytes()?))
    }
    fn string(&mut self) -> Result<String> {
        let n = self.u64()?;
        self.reserve(n)?;
        let mut bytes = vec![0; n as usize];
        self.reader.read_exact(&mut bytes)?;
        String::from_utf8(bytes).map_err(|_| invalid("GGUF string is not UTF-8"))
    }
    fn value(&mut self, ty: u32, depth: usize, keep: bool) -> Result<Value> {
        if depth > MAX_ARRAY_DEPTH {
            return Err(invalid("GGUF array nesting too deep"));
        }
        let value = match ty {
            0 => json!(self.bytes::<1>()?[0]),
            1 => json!(self.bytes::<1>()?[0] as i8),
            2 => json!(u16::from_le_bytes(self.bytes()?)),
            3 => json!(i16::from_le_bytes(self.bytes()?)),
            4 => json!(self.u32()?),
            5 => json!(i32::from_le_bytes(self.bytes()?)),
            6 => float_json(f32::from_le_bytes(self.bytes()?) as f64),
            7 => match self.bytes::<1>()?[0] {
                0 => json!(false),
                1 => json!(true),
                _ => return Err(invalid("invalid GGUF boolean")),
            },
            8 => json!(self.string()?),
            9 => {
                let element_type = self.u32()?;
                if element_type > 12 {
                    return Err(invalid("unknown GGUF array value type"));
                }
                let length = self.u64()?;
                // Every encoded value consumes at least one byte, even nested arrays.
                if length > self.limit - self.position {
                    return Err(invalid("GGUF array length exceeds header budget"));
                }
                let summarized = length > ARRAY_SUMMARY_THRESHOLD;
                let mut values = Vec::new();
                for i in 0..length {
                    let retain = keep && (!summarized || i < ARRAY_PREVIEW);
                    let v = self.value(element_type, depth + 1, retain)?;
                    if retain {
                        values.push(v);
                    }
                }
                if summarized {
                    json!({"__summary__":true,"element_type":element_type,"length":length,"preview":values})
                } else {
                    Value::Array(values)
                }
            }
            10 => json!(self.u64()?),
            11 => json!(i64::from_le_bytes(self.bytes()?)),
            12 => float_json(f64::from_le_bytes(self.bytes()?)),
            _ => return Err(invalid(format!("unknown GGUF metadata value type {ty}"))),
        };
        Ok(if keep { value } else { Value::Null })
    }
}

fn float_json(value: f64) -> Value {
    if value.is_nan() {
        json!("NaN")
    } else if value == f64::INFINITY {
        json!("Infinity")
    } else if value == f64::NEG_INFINITY {
        json!("-Infinity")
    } else {
        json!(value)
    }
}

struct Info {
    name: String,
    dims: Vec<u64>,
    ty: u32,
    offset: u64,
}

pub(crate) fn parse<R: Read + Seek>(reader: &mut R, size: u64) -> Result<Parsed> {
    let mut h = Header {
        reader,
        position: 0,
        limit: size.min(MAX_HEADER_SIZE),
    };
    let magic = h.bytes::<4>()?;
    if &magic == b"FUGG" {
        return Err(invalid("big-endian GGUF is not supported"));
    }
    if &magic != b"GGUF" {
        return Err(invalid("invalid GGUF magic"));
    }
    let version = h.u32()?;
    if matches!(version, 0x02000000 | 0x03000000) {
        return Err(invalid("big-endian GGUF is not supported"));
    }
    if !matches!(version, 2 | 3) {
        return Err(invalid(format!("unsupported GGUF version {version}")));
    }
    let tensor_count = h.u64()?;
    let kv_count = h.u64()?;
    if tensor_count > h.limit / 32 || kv_count > h.limit / 13 {
        return Err(invalid("GGUF counts exceed header budget"));
    }
    let mut metadata = Map::new();
    for _ in 0..kv_count {
        let key = h.string()?;
        let ty = h.u32()?;
        if key == "general.alignment" && ty != 4 {
            return Err(invalid("GGUF general.alignment must be UINT32"));
        }
        let value = h.value(ty, 0, true)?;
        if metadata.insert(key, value).is_some() {
            return Err(invalid("duplicate GGUF metadata key"));
        }
    }
    let alignment = match metadata.get("general.alignment") {
        None => 32,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| invalid("invalid GGUF alignment"))?,
    };
    if !alignment.is_power_of_two() || alignment > MAX_HEADER_SIZE {
        return Err(invalid("GGUF alignment must be a bounded power of two"));
    }
    let mut infos = Vec::new();
    let mut names = BTreeSet::new();
    for _ in 0..tensor_count {
        let name = h.string()?;
        if !names.insert(name.clone()) {
            return Err(invalid("duplicate GGUF tensor name"));
        }
        let n = h.u32()?;
        if !(1..=4).contains(&n) {
            return Err(invalid("GGUF n_dims must be between 1 and 4"));
        }
        let dims = (0..n).map(|_| h.u64()).collect::<Result<Vec<_>>>()?;
        if dims.contains(&0) {
            return Err(invalid("GGUF tensor dimension must be positive"));
        }
        elements(&dims)?;
        let ty = h.u32()?;
        let offset = h.u64()?;
        if offset % alignment != 0 {
            return Err(invalid("GGUF tensor offset violates alignment"));
        }
        infos.push(Info {
            name,
            dims,
            ty,
            offset,
        });
    }
    let data_start = checked_add(h.position, alignment - 1)? & !(alignment - 1);
    if data_start > size {
        return Err(invalid("truncated GGUF data section"));
    }
    let data_len = size - data_start;
    let offsets: BTreeSet<_> = infos.iter().map(|i| i.offset).collect();
    let mut tensors = Vec::new();
    for info in infos {
        if info.offset > data_len {
            return Err(invalid("GGUF tensor offset out of range"));
        }
        let layout = ggml_layout(info.ty);
        let len = if let Some((_, block, bytes)) = layout {
            if info.dims[0] % block != 0 {
                return Err(invalid(
                    "GGUF first dimension is not a whole quantization block",
                ));
            }
            (elements(&info.dims)? / block)
                .checked_mul(bytes)
                .ok_or_else(|| invalid("GGUF tensor byte size overflow"))?
        } else {
            let next = offsets
                .range((
                    std::ops::Bound::Excluded(info.offset),
                    std::ops::Bound::Unbounded,
                ))
                .next()
                .copied()
                .unwrap_or(data_len);
            if next > data_len {
                return Err(invalid("GGUF tensor offset out of range"));
            }
            next - info.offset
        };
        if checked_add(info.offset, len)? > data_len {
            return Err(invalid(format!("truncated GGUF tensor {:?}", info.name)));
        }
        let absolute = checked_add(data_start, info.offset)?;
        tensors.push(Tensor { name:info.name,offset:absolute,size:len,
            sidecar:json!({"format":"gguf","version":version,"ggml_type":info.ty,
                "ggml_type_name":layout.map(|l| l.0).unwrap_or("UNKNOWN"),"dims":info.dims,
                "byte_length":len,"data_offset":info.offset,"absolute_file_offset":absolute,
                "data_section_start":data_start,"alignment":alignment,
                "size_source":if layout.is_some() {"ggml_block_layout"} else {"next_offset_or_data_end"}}) });
    }
    Ok(Parsed {
        tensors,
        metadata: Value::Object(metadata),
        raw_header: None,
    })
}

// GGML enum IDs and on-disk block layouts from ggml.h / ggml-common.h.
// Removed enum values remain unknown; infer their range rather than mislabeling.
pub(crate) fn ggml_layout(ty: u32) -> Option<(&'static str, u64, u64)> {
    Some(match ty {
        0 => ("F32", 1, 4),
        1 => ("F16", 1, 2),
        2 => ("Q4_0", 32, 18),
        3 => ("Q4_1", 32, 20),
        6 => ("Q5_0", 32, 22),
        7 => ("Q5_1", 32, 24),
        8 => ("Q8_0", 32, 34),
        9 => ("Q8_1", 32, 36),
        10 => ("Q2_K", 256, 84),
        11 => ("Q3_K", 256, 110),
        12 => ("Q4_K", 256, 144),
        13 => ("Q5_K", 256, 176),
        14 => ("Q6_K", 256, 210),
        15 => ("Q8_K", 256, 292),
        16 => ("IQ2_XXS", 256, 66),
        17 => ("IQ2_XS", 256, 74),
        18 => ("IQ3_XXS", 256, 98),
        19 => ("IQ1_S", 256, 50),
        20 => ("IQ4_NL", 32, 18),
        21 => ("IQ3_S", 256, 110),
        22 => ("IQ2_S", 256, 82),
        23 => ("IQ4_XS", 256, 136),
        24 => ("I8", 1, 1),
        25 => ("I16", 1, 2),
        26 => ("I32", 1, 4),
        27 => ("I64", 1, 8),
        28 => ("F64", 1, 8),
        29 => ("IQ1_M", 256, 56),
        30 => ("BF16", 1, 2),
        34 => ("TQ1_0", 256, 54),
        35 => ("TQ2_0", 256, 66),
        39 => ("MXFP4", 32, 17),
        40 => ("NVFP4", 64, 36),
        41 => ("Q1_0", 128, 18),
        42 => ("Q2_0", 64, 18),
        _ => return None,
    })
}

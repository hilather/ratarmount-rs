use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::json;

use crate::{checked_add, elements, invalid, Parsed, Result, Tensor, MAX_HEADER_SIZE};

#[derive(Deserialize)]
struct Descriptor {
    dtype: String,
    shape: Vec<u64>,
    data_offsets: [u64; 2],
}

struct Header {
    metadata: BTreeMap<String, String>,
    tensors: BTreeMap<String, Descriptor>,
}

impl<'de> Deserialize<'de> for Header {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct HeaderVisitor;
        impl<'de> Visitor<'de> for HeaderVisitor {
            type Value = Header;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a safetensors header object")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Header, A::Error> {
                let mut metadata = None;
                let mut tensors = BTreeMap::new();
                while let Some(name) = map.next_key::<String>()? {
                    if name == "__metadata__" {
                        if metadata.is_some() {
                            return Err(serde::de::Error::custom("duplicate metadata key"));
                        }
                        metadata = Some(map.next_value()?);
                    } else {
                        let descriptor = map.next_value()?;
                        if tensors.insert(name, descriptor).is_some() {
                            return Err(serde::de::Error::custom("duplicate tensor name"));
                        }
                    }
                }
                Ok(Header {
                    metadata: metadata.unwrap_or_default(),
                    tensors,
                })
            }
        }
        deserializer.deserialize_map(HeaderVisitor)
    }
}

pub(crate) fn parse<R: Read + Seek>(reader: &mut R, size: u64) -> Result<Parsed> {
    reader.seek(SeekFrom::Start(0))?;
    let mut length = [0; 8];
    reader.read_exact(&mut length)?;
    let length = u64::from_le_bytes(length);
    if length > MAX_HEADER_SIZE {
        return Err(invalid("safetensors header too large (limit 100 MiB)"));
    }
    let start = checked_add(8, length)?;
    if start > size {
        return Err(invalid("truncated safetensors header"));
    }
    let mut bytes = vec![0; length as usize];
    reader.read_exact(&mut bytes)?;
    if bytes.first() != Some(&b'{') {
        return Err(invalid("safetensors header must start with '{'"));
    }
    let header: Header = serde_json::from_slice(&bytes)?;
    let metadata = json!(header.metadata);
    let mut tensors = Vec::new();
    for (name, info) in header.tensors {
        let Descriptor {
            dtype,
            shape,
            data_offsets: [begin, end],
        } = info;
        if begin > end || end > size - start {
            return Err(invalid(format!("tensor {name:?} offsets out of range")));
        }
        let len = end - begin;
        let bits = dtype_bits(&dtype);
        if let Some(bits) = bits {
            let expected = elements(&shape)?
                .checked_mul(bits)
                .ok_or_else(|| invalid("tensor byte size overflow"))?;
            if expected % 8 != 0 || expected / 8 != len {
                return Err(invalid(format!(
                    "tensor {name:?} shape/dtype size mismatch"
                )));
            }
        }
        let offset = checked_add(start, begin)?;
        tensors.push(Tensor {
            name: name.clone(), offset, size:len,
            sidecar:json!({"format":"safetensors", "dtype":dtype,"shape":shape,"data_offsets":[begin,end],
                "byte_length":len,"absolute_file_offset":offset,"size_check": if bits.is_some() {"validated"} else {"skipped_unknown_dtype"}}),
        });
    }
    Ok(Parsed {
        tensors,
        metadata,
        raw_header: Some((8, length)),
    })
}

// Upstream safetensors Dtype::bitsize, including packed sub-byte formats.
pub(crate) fn dtype_bits(dtype: &str) -> Option<u64> {
    Some(match dtype {
        "F4" => 4,
        "F6_E2M3" | "F6_E3M2" => 6,
        "BOOL" | "U8" | "I8" | "F8_E4M3" | "F8_E5M2" | "F8_E8M0" | "F8_E4M3FNUZ"
        | "F8_E5M2FNUZ" => 8,
        "F16" | "BF16" | "I16" | "U16" => 16,
        "F32" | "I32" | "U32" => 32,
        "F64" | "I64" | "U64" | "C64" => 64,
        _ => return None,
    })
}

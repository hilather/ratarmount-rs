//! Apple Data Compression (UDIF chunk type `0x80000004`).
//!
//! Matches dmg2img / libdmg-hfsplus: bit7 = literal, bit6 = 3-byte backref,
//! else 2-byte backref. Offsets are `distance - 1` from the output cursor.

use crate::{DmgError, Result};

const ADC_PLAIN: u8 = 0x80;
const ADC_3BYTE: u8 = 0x40;

/// Decompress one ADC run into `output`. Returns bytes written.
pub fn adc_decompress(input: &[u8], output: &mut [u8]) -> Result<usize> {
    let mut ip = 0usize;
    let mut op = 0usize;
    while ip < input.len() {
        if op >= output.len() {
            break;
        }
        let ctl = input[ip];
        if ctl & ADC_PLAIN != 0 {
            let len = (ctl & 0x7f) as usize + 1;
            ip += 1;
            let src_end = ip
                .checked_add(len)
                .ok_or_else(|| DmgError::Msg("ADC literal overflow".into()))?;
            if src_end > input.len() {
                return Err(DmgError::Msg("ADC literal truncated".into()));
            }
            if op + len > output.len() {
                return Err(DmgError::Msg("ADC literal exceeds output".into()));
            }
            output[op..op + len].copy_from_slice(&input[ip..src_end]);
            ip = src_end;
            op += len;
        } else if ctl & ADC_3BYTE != 0 {
            let len = (ctl & 0x3f) as usize + 4;
            if ip + 3 > input.len() {
                return Err(DmgError::Msg("ADC 3-byte command truncated".into()));
            }
            let offset = ((input[ip + 1] as usize) << 8) + input[ip + 2] as usize;
            ip += 3;
            copy_backref(output, &mut op, offset, len)?;
        } else {
            let len = ((ctl & 0x3f) >> 2) as usize + 3;
            if ip + 2 > input.len() {
                return Err(DmgError::Msg("ADC 2-byte command truncated".into()));
            }
            let offset = (((ctl & 0x03) as usize) << 8) + input[ip + 1] as usize;
            ip += 2;
            copy_backref(output, &mut op, offset, len)?;
        }
    }
    Ok(op)
}

fn copy_backref(output: &mut [u8], op: &mut usize, offset: usize, len: usize) -> Result<()> {
    if *op == 0 {
        return Err(DmgError::Msg("ADC backref before any output".into()));
    }
    let src = op
        .checked_sub(offset + 1)
        .ok_or_else(|| DmgError::Msg("ADC backref before start".into()))?;
    if *op + len > output.len() {
        return Err(DmgError::Msg("ADC backref exceeds output".into()));
    }
    // Byte-wise so offset 0 (repeat previous byte) overlaps correctly.
    for i in 0..len {
        output[*op + i] = output[src + i];
    }
    *op += len;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adc_plain_literals() {
        // 0x80 = one literal byte.
        let mut out = [0u8; 4];
        let n = adc_decompress(&[0x80, b'A', 0x80, b'B'], &mut out).unwrap();
        assert_eq!(&out[..n], b"AB");
    }

    #[test]
    fn adc_2byte_repeat_previous() {
        // Literal 'A', then 2-byte backref length 3 offset 0 → "AAAA".
        let mut out = [0u8; 8];
        let n = adc_decompress(&[0x80, b'A', 0x00, 0x00], &mut out).unwrap();
        assert_eq!(&out[..n], b"AAAA");
    }

    #[test]
    fn adc_3byte_backref() {
        let mut out = [0u8; 16];
        // Literal "Hi", then 3-byte copy of 4 bytes from offset 1 (the 'H'… wait)
        // After "Hi", offset 1 copies from op-2 = 'H': would be H repeating?
        // Copy from op-offset-1. offset=1 → src = op-2 = start of "Hi".
        // len = (0x40 & 0x3f) + 4 = 4 → "HiHi" total "Hi"+"HiHi"? len 4 from "Hi" overlapping:
        // src=0, op=2, len=4: out[2]=out[0]='H', [3]=out[1]='i', [4]=out[2]='H', [5]=out[3]='i'
        // → "HiHiHi"
        let n = adc_decompress(&[0x81, b'H', b'i', 0x40, 0x00, 0x01], &mut out).unwrap();
        assert_eq!(&out[..n], b"HiHiHi");
    }
}

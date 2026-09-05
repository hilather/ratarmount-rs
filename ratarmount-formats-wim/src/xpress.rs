//! XPRESS Huffman (MS-XCA LZ77+Huffman) as used by compressed WIM resources.
//!
//! Bitstream is 16-bit little-endian coding units, bits consumed high-to-low
//! (same as wimlib). Length-extra bytes are interleaved in the raw byte stream.

use crate::{Result, WimError};

const NUM_SYMBOLS: usize = 512;
const NUM_CHARS: usize = 256;
const MAX_CODEWORD_LEN: usize = 15;
const MIN_MATCH_LEN: u32 = 3;
const TABLE_BITS: usize = 15;

/// Decompress one XPRESS Huffman chunk into exactly `uncompressed_size` bytes.
pub fn decompress(compressed: &[u8], uncompressed_size: usize) -> Result<Vec<u8>> {
    if uncompressed_size == 0 {
        return Ok(Vec::new());
    }
    if compressed.len() < NUM_SYMBOLS / 2 {
        return Err(WimError::Msg(
            "XPRESS chunk missing Huffman length table".into(),
        ));
    }
    let mut lens = [0u8; NUM_SYMBOLS];
    for i in 0..NUM_SYMBOLS / 2 {
        lens[2 * i] = compressed[i] & 0x0f;
        lens[2 * i + 1] = compressed[i] >> 4;
        if lens[2 * i] as usize > MAX_CODEWORD_LEN || lens[2 * i + 1] as usize > MAX_CODEWORD_LEN {
            return Err(WimError::Msg("XPRESS codeword length > 15".into()));
        }
    }
    let table = build_decode_table(&lens)?;
    let mut br = BitReader::new(&compressed[NUM_SYMBOLS / 2..]);
    let mut out = Vec::with_capacity(uncompressed_size);
    while out.len() < uncompressed_size {
        let sym = br.read_symbol(&table)?;
        if (sym as usize) < NUM_CHARS {
            out.push(sym as u8);
            continue;
        }
        let length_nibble = u32::from(sym & 0xf);
        let log2_offset = (sym >> 4) & 0xf;
        let extra = br.pop_bits(u32::from(log2_offset))?;
        let offset = (1u32 << log2_offset) | extra;
        let mut length = length_nibble;
        if length == 0xf {
            length += u32::from(br.read_byte());
            if length == 0xf + 0xff {
                length = u32::from(br.read_u16());
            }
        }
        length += MIN_MATCH_LEN;
        let start = out.len();
        if offset == 0 || offset as usize > start {
            return Err(WimError::Msg("XPRESS match offset out of range".into()));
        }
        match start.checked_add(length as usize) {
            Some(end) if end <= uncompressed_size => {}
            _ => return Err(WimError::Msg("XPRESS match overruns output".into())),
        }
        let src = start - offset as usize;
        for i in 0..length as usize {
            let b = out[src + i];
            out.push(b);
        }
    }
    Ok(out)
}

/// Huffman-encode `data` with a flat 9-bit alphabet (test / fixture helper).
///
/// Greedy LZ77: match length 3..=17 (no extra length bytes) so the bitstream
/// stays in the 16-bit coding units without interleaved raw bytes.
#[cfg(test)]
pub fn compress(data: &[u8]) -> Vec<u8> {
    let mut lens_bytes = vec![0u8; NUM_SYMBOLS / 2];
    lens_bytes.fill(0x99); // both nibbles = 9
    let mut out = lens_bytes;
    let mut bitbuf: u32 = 0;
    let mut nbits: u32 = 0;
    let mut i = 0usize;
    while i < data.len() {
        let (sym, consumed, extra_bits, extra_n) = match_or_literal(data, i);
        emit_bits(&mut bitbuf, &mut nbits, &mut out, u32::from(sym), 9);
        if extra_n > 0 {
            emit_bits(&mut bitbuf, &mut nbits, &mut out, extra_bits, extra_n);
        }
        i += consumed;
    }
    if nbits > 0 {
        let word = (bitbuf >> 16) as u16;
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}

#[cfg(test)]
fn match_or_literal(data: &[u8], i: usize) -> (u16, usize, u32, u32) {
    if i == 0 || data.len() - i < 3 {
        return (u16::from(data[i]), 1, 0, 0);
    }
    // Match length 3..=17 so the length nibble stays < 0xF (no extra bytes).
    let max_len = (data.len() - i).min(17);
    let window = i.min(65535);
    let mut best_len = 0usize;
    let mut best_off = 0usize;
    for off in 1..=window {
        let mut len = 0usize;
        while len < max_len && data[i + len] == data[i + len - off] {
            len += 1;
        }
        if len >= 3 && len > best_len {
            best_len = len;
            best_off = off;
            if best_len == max_len {
                break;
            }
        }
        if off == 1 && len >= 3 {
            break;
        }
    }
    if best_len < 3 {
        return (u16::from(data[i]), 1, 0, 0);
    }
    let log2 = 31 - (best_off as u32).leading_zeros();
    // offset = (1 << log2) | extra, extra has `log2` bits.
    let extra = (best_off as u32) ^ (1u32 << log2);
    let nibble = (best_len as u32 - MIN_MATCH_LEN) as u16;
    let sym = 256 + ((log2 as u16) << 4) + nibble;
    (sym, best_len, extra, log2)
}

#[cfg(test)]
fn emit_bits(bitbuf: &mut u32, nbits: &mut u32, out: &mut Vec<u8>, bits: u32, n: u32) {
    if n == 0 {
        return;
    }
    let mask = if n == 32 { u32::MAX } else { (1u32 << n) - 1 };
    *bitbuf |= (bits & mask) << (32 - *nbits - n);
    *nbits += n;
    while *nbits >= 16 {
        let word = (*bitbuf >> 16) as u16;
        out.extend_from_slice(&word.to_le_bytes());
        *bitbuf <<= 16;
        *nbits -= 16;
    }
}

fn build_decode_table(lens: &[u8; NUM_SYMBOLS]) -> Result<Vec<u16>> {
    let mut bl_count = [0u32; MAX_CODEWORD_LEN + 1];
    for &l in lens {
        if l as usize > MAX_CODEWORD_LEN {
            return Err(WimError::Msg("XPRESS invalid code length".into()));
        }
        if l > 0 {
            bl_count[l as usize] += 1;
        }
    }
    let mut next_code = [0u16; MAX_CODEWORD_LEN + 1];
    let mut code = 0u16;
    bl_count[0] = 0;
    for bits in 1..=MAX_CODEWORD_LEN {
        code = code.wrapping_add(bl_count[bits - 1] as u16).wrapping_shl(1);
        next_code[bits] = code;
    }
    let table_size = 1 << TABLE_BITS;
    let mut table = vec![0xffffu16; table_size];
    for (sym, &len) in lens.iter().enumerate() {
        if len == 0 {
            continue;
        }
        let len = len as usize;
        let c = next_code[len];
        next_code[len] = next_code[len].wrapping_add(1);
        let shift = TABLE_BITS - len;
        let base = (c as usize) << shift;
        let fill = 1 << shift;
        let entry = ((sym as u16) << 4) | (len as u16);
        for i in 0..fill {
            let idx = base + i;
            if idx >= table_size {
                return Err(WimError::Msg("XPRESS Huffman code out of range".into()));
            }
            table[idx] = entry;
        }
    }
    Ok(table)
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bitbuf: u32,
    bitsleft: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            bitbuf: 0,
            bitsleft: 0,
        }
    }

    fn ensure_bits(&mut self, n: u32) {
        while self.bitsleft < n {
            let w = if self.pos + 1 < self.data.len() {
                u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]) as u32
            } else if self.pos < self.data.len() {
                self.data[self.pos] as u32
            } else {
                0
            };
            self.pos = self.pos.saturating_add(2);
            self.bitbuf |= w << (16 - self.bitsleft);
            self.bitsleft += 16;
        }
    }

    fn peek_bits(&self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        self.bitbuf >> (32 - n)
    }

    fn remove_bits(&mut self, n: u32) {
        self.bitbuf <<= n;
        self.bitsleft = self.bitsleft.saturating_sub(n);
    }

    fn pop_bits(&mut self, n: u32) -> Result<u32> {
        if n > 16 {
            return Err(WimError::Msg("XPRESS extra bits overflow".into()));
        }
        if n == 0 {
            return Ok(0);
        }
        self.ensure_bits(n);
        let v = self.peek_bits(n);
        self.remove_bits(n);
        Ok(v)
    }

    fn read_symbol(&mut self, table: &[u16]) -> Result<u16> {
        self.ensure_bits(MAX_CODEWORD_LEN as u32);
        let idx = self.peek_bits(TABLE_BITS as u32) as usize;
        let entry = table.get(idx).copied().unwrap_or(0xffff);
        if entry == 0xffff {
            return Err(WimError::Msg("XPRESS invalid Huffman symbol".into()));
        }
        let sym = entry >> 4;
        let len = u32::from(entry & 0xf);
        if len == 0 {
            return Err(WimError::Msg("XPRESS empty Huffman code".into()));
        }
        self.remove_bits(len);
        Ok(sym)
    }

    fn read_byte(&mut self) -> u8 {
        if self.pos >= self.data.len() {
            return 0;
        }
        let b = self.data[self.pos];
        self.pos += 1;
        b
    }

    fn read_u16(&mut self) -> u16 {
        let lo = self.read_byte();
        let hi = self.read_byte();
        u16::from_le_bytes([lo, hi])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xpress_literals_round_trip() {
        let src = b"hello xpress wim codec";
        let c = compress(src);
        let d = decompress(&c, src.len()).expect("decompress");
        assert_eq!(d, src);
    }

    #[test]
    fn xpress_repeat_match_round_trip() {
        let src = vec![b'A'; 2000];
        let c = compress(&src);
        assert!(
            c.len() < src.len(),
            "repeat should shrink (got {} vs {})",
            c.len(),
            src.len()
        );
        let d = decompress(&c, src.len()).expect("decompress");
        assert_eq!(d, src);
    }

    #[test]
    fn xpress_mixed_round_trip() {
        let mut src = b"abc".to_vec();
        src.extend(vec![b'x'; 40]);
        src.extend_from_slice(b"tail");
        let c = compress(&src);
        let d = decompress(&c, src.len()).expect("decompress");
        assert_eq!(d, src);
    }
}

//! restic AES-256-CTR + Poly1305-AES (see restic `internal/crypto`).

use aes::cipher::{BlockEncrypt, KeyIvInit, StreamCipher};
use aes::{Aes128, Aes256};
use cipher::generic_array::GenericArray;
use poly1305::universal_hash::KeyInit;
use poly1305::Poly1305;
use scrypt::Params as ScryptParams;
use sha2::{Digest, Sha256};

use crate::{ResticError, Result};

pub const IV_SIZE: usize = 16;
pub const MAC_SIZE: usize = 16;
pub const EXTENSION: usize = IV_SIZE + MAC_SIZE;
/// restic scrypt output: 32-byte AES-256 key + 32-byte Poly1305-AES key.
pub const KDF_OUT: usize = 64;

/// Poly1305-AES r mask (Bernstein). Applied once to the MAC `r` half.
const POLY1305_R_MASK: [u8; 16] = [
    0xff, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f,
];

/// Master encryption + MAC keys (never logged).
#[derive(Clone)]
pub struct MasterKey {
    encrypt: [u8; 32],
    mac_k: [u8; 16],
    mac_r: [u8; 16],
}

impl MasterKey {
    pub fn from_kdf_bytes(bytes: &[u8; KDF_OUT]) -> Self {
        let mut encrypt = [0u8; 32];
        let mut mac_k = [0u8; 16];
        let mut mac_r = [0u8; 16];
        encrypt.copy_from_slice(&bytes[..32]);
        mac_k.copy_from_slice(&bytes[32..48]);
        mac_r.copy_from_slice(&bytes[48..64]);
        mask_r(&mut mac_r);
        Self {
            encrypt,
            mac_k,
            mac_r,
        }
    }

    pub fn from_json_parts(encrypt: &[u8], k: &[u8], r: &[u8]) -> Result<Self> {
        if encrypt.len() != 32 || k.len() != 16 || r.len() != 16 {
            return Err(ResticError::Msg("invalid master key length".into()));
        }
        let mut out = Self {
            encrypt: [0u8; 32],
            mac_k: [0u8; 16],
            mac_r: [0u8; 16],
        };
        out.encrypt.copy_from_slice(encrypt);
        out.mac_k.copy_from_slice(k);
        out.mac_r.copy_from_slice(r);
        mask_r(&mut out.mac_r);
        if out.encrypt.iter().all(|&b| b == 0) || (out.mac_k.iter().all(|&b| b == 0)) {
            return Err(ResticError::Msg("invalid master key".into()));
        }
        Ok(out)
    }
}

fn mask_r(r: &mut [u8; 16]) {
    for (b, m) in r.iter_mut().zip(POLY1305_R_MASK.iter()) {
        *b &= *m;
    }
}

/// Derive 64 key bytes with restic's scrypt parameters (`N`, `r`, `p`, `salt`).
///
/// Caps `N`/`r`/`p` so a crafted key file cannot force unbounded RAM.
pub fn scrypt_derive(
    password: &[u8],
    salt: &[u8],
    n: u32,
    r: u32,
    p: u32,
) -> Result<[u8; KDF_OUT]> {
    if n < 2 || !n.is_power_of_two() {
        return Err(ResticError::Msg("invalid scrypt N".into()));
    }
    let log_n = n.trailing_zeros();
    // N≤2^18, r≤32, p≤16 → ≤128·N·r ≈ 1 GiB worst case; typical restic is 32 MiB.
    if log_n > 18 || r == 0 || r > 32 || p == 0 || p > 16 {
        return Err(ResticError::Msg("scrypt parameters rejected".into()));
    }
    let params = ScryptParams::new(log_n as u8, r, p)
        .map_err(|_| ResticError::Msg("invalid scrypt parameters".into()))?;
    let mut out = [0u8; KDF_OUT];
    scrypt::scrypt(password, salt, &params, &mut out)
        .map_err(|_| ResticError::Msg("scrypt failed".into()))?;
    Ok(out)
}

fn poly1305_prepare_key(nonce: &[u8], key: &MasterKey) -> poly1305::Key {
    let mut k = [0u8; 32];
    k[..16].copy_from_slice(&key.mac_r);
    let cipher = Aes128::new(GenericArray::from_slice(&key.mac_k));
    let mut block = GenericArray::clone_from_slice(nonce);
    cipher.encrypt_block(&mut block);
    k[16..].copy_from_slice(&block);
    poly1305::Key::from(k)
}

/// Decrypt `IV || ciphertext || MAC`. MAC is over ciphertext with nonce=IV.
pub fn decrypt(key: &MasterKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < EXTENSION {
        return Err(ResticError::Msg("ciphertext too short".into()));
    }
    let iv = &ciphertext[..IV_SIZE];
    let mac = &ciphertext[ciphertext.len() - MAC_SIZE..];
    let ct = &ciphertext[IV_SIZE..ciphertext.len() - MAC_SIZE];

    let poly_key = poly1305_prepare_key(iv, key);
    let tag = Poly1305::new(&poly_key).compute_unpadded(ct);
    if tag.as_slice() != mac {
        return Err(ResticError::Msg(
            "wrong password or ciphertext verification failed".into(),
        ));
    }

    let mut plain = ct.to_vec();
    type Aes256Ctr = ctr::Ctr128BE<Aes256>;
    let mut stream = Aes256Ctr::new(
        GenericArray::from_slice(&key.encrypt),
        GenericArray::from_slice(iv),
    );
    stream.apply_keystream(&mut plain);
    Ok(plain)
}

/// Encrypt to `IV || ciphertext || MAC`. `iv` must be 16 unique bytes.
pub fn encrypt(key: &MasterKey, plaintext: &[u8], iv: &[u8; IV_SIZE]) -> Vec<u8> {
    let mut out = Vec::with_capacity(plaintext.len() + EXTENSION);
    out.extend_from_slice(iv);
    out.extend_from_slice(plaintext);
    type Aes256Ctr = ctr::Ctr128BE<Aes256>;
    let mut stream = Aes256Ctr::new(
        GenericArray::from_slice(&key.encrypt),
        GenericArray::from_slice(iv),
    );
    stream.apply_keystream(&mut out[IV_SIZE..]);
    let poly_key = poly1305_prepare_key(iv, key);
    let tag = Poly1305::new(&poly_key).compute_unpadded(&out[IV_SIZE..]);
    out.extend_from_slice(tag.as_slice());
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

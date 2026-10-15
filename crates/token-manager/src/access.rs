//! OATH password / access code derivation, validation, and local key cache.
//!
//! YKOATH protects credentials with an optional password. The host derives a 16-byte
//! key from the user's password and the token's salt using PBKDF2-HMAC-SHA1 (1,000 iterations).
//! The token challenges the host during SELECT; the host validates itself by answering
//! `VALIDATE` (INS 0x07) with `HMAC-SHA1(key, challenge)`.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// Pure-Rust SHA-1 implementation (RFC 3174).
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0 = 0x67452301u32;
    let mut h1 = 0xEFCDAB89u32;
    let mut h2 = 0x98BADCFEu32;
    let mut h3 = 0x10325476u32;
    let mut h4 = 0xC3D2E1F0u32;

    let ml = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&ml.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, part) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([part[0], part[1], part[2], part[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

/// Computes HMAC-SHA1 (RFC 2104).
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let hashed = sha1(key);
        k[..20].copy_from_slice(&hashed);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut o_key_pad = [0u8; 64];
    let mut i_key_pad = [0u8; 64];
    for i in 0..64 {
        o_key_pad[i] = k[i] ^ 0x5C;
        i_key_pad[i] = k[i] ^ 0x36;
    }

    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend_from_slice(&i_key_pad);
    inner.extend_from_slice(data);
    let inner_hash = sha1(&inner);

    let mut outer = Vec::with_capacity(64 + 20);
    outer.extend_from_slice(&o_key_pad);
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}

/// Derives a 16-byte key using PBKDF2-HMAC-SHA1 (1000 iterations).
pub fn derive_access_key(password: &str, salt: &[u8]) -> [u8; 16] {
    let mut key = [0u8; 16];
    let pwd_bytes = password.as_bytes();

    // Block 1 (i = 1)
    let mut u_data = Vec::with_capacity(salt.len() + 4);
    u_data.extend_from_slice(salt);
    u_data.extend_from_slice(&1u32.to_be_bytes());

    let mut u = hmac_sha1(pwd_bytes, &u_data);
    let mut f = u;

    for _ in 1..1000 {
        u = hmac_sha1(pwd_bytes, &u);
        for j in 0..20 {
            f[j] ^= u[j];
        }
    }

    key.copy_from_slice(&f[..16]);
    key
}

/// Local configuration path for remembered OATH access keys.
pub fn oath_keys_store_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .map(|p| p.join("cryptick").join("oath_keys.json"))
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|p| p.join(".config").join("cryptick").join("oath_keys.json"))
    }
}

/// Loads remembered access keys from disk: `{ device_id_hex: key_hex }`.
pub fn load_remembered_keys() -> HashMap<String, String> {
    if let Some(path) = oath_keys_store_path() {
        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(map) = serde_json::from_str::<HashMap<String, String>>(&content) {
                return map;
            }
        }
    }
    HashMap::new()
}

/// Saves remembered access keys to disk.
pub fn save_remembered_keys(keys: &HashMap<String, String>) -> Result<(), String> {
    let path = oath_keys_store_path().ok_or_else(|| "Could not determine config path".to_string())?;
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(keys).map_err(|e| e.to_string())?;
    fs::write(&path, json).map_err(|e| format!("Failed to save remembered keys: {e}"))?;
    Ok(())
}

/// Remembers an access key for a given token salt / ID.
pub fn remember_key(device_id: &[u8], key: &[u8; 16]) -> Result<(), String> {
    let mut keys = load_remembered_keys();
    let id_hex = hex_string(device_id);
    let key_hex = hex_string(key);
    keys.insert(id_hex, key_hex);
    save_remembered_keys(&keys)
}

/// Retrieves a remembered access key for a given token salt / ID.
pub fn get_remembered_key(device_id: &[u8]) -> Option<[u8; 16]> {
    let keys = load_remembered_keys();
    let id_hex = hex_string(device_id);
    let key_hex = keys.get(&id_hex)?;
    let bytes = crate::apdu::parse_hex(key_hex).ok()?;
    if bytes.len() == 16 {
        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes);
        Some(out)
    } else {
        None
    }
}

/// Forgets a remembered access key for a given token salt / ID.
pub fn forget_key(device_id: &[u8]) -> Result<bool, String> {
    let mut keys = load_remembered_keys();
    let id_hex = hex_string(device_id);
    let existed = keys.remove(&id_hex).is_some();
    if existed {
        save_remembered_keys(&keys)?;
    }
    Ok(existed)
}

/// Forgets all remembered access keys.
pub fn forget_all_keys() -> Result<usize, String> {
    let keys = load_remembered_keys();
    let count = keys.len();
    if let Some(path) = oath_keys_store_path() {
        let _ = fs::remove_file(path);
    }
    Ok(count)
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

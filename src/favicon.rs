//! Favicon hash computation — Shodan-compatible MurmurHash3 x86/32.
//!
//! Shodan indexes the hash of `base64(favicon_bytes)` using MurmurHash3.
//! Use the emitted hash to pivot on Shodan: `http.favicon.hash:{value}`.
//!
//! Reference: <https://github.com/pielco11/fav-up>

use base64::{engine::general_purpose::STANDARD, Engine};
use stealthreq::http as reqwest;

/// Download the favicon from `base_url/favicon.ico` and return its Shodan hash.
///
/// Returns `None` on any error (missing favicon, connection failure, etc.).
#[cfg(feature = "fetch")]
pub async fn fetch_hash(client: &reqwest::Client, base_url: &str) -> Option<i32> {
    let favicon_url = format!("{}/favicon.ico", base_url.trim_end_matches('/'));
    let resp = client.get(&favicon_url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let bytes = resp.bytes().await.ok()?;
    if bytes.is_empty() {
        return None;
    }
    Some(shodan_favicon_hash(&bytes))
}

/// Compute Shodan's favicon hash.
///
/// 1. Base64-encode the raw bytes with line breaks every 76 characters.
/// 2. MurmurHash3 x86/32 on the resulting base64 string (as bytes), seed = 0.
pub fn shodan_favicon_hash(data: &[u8]) -> i32 {
    murmurhash3_x86_32(shodan_base64_with_newlines(data).as_bytes(), 0) as i32
}

fn shodan_base64_with_newlines(data: &[u8]) -> String {
    let b64 = STANDARD.encode(data);
    if b64.is_empty() {
        return "\n".to_string();
    }

    let mut formatted = String::with_capacity(b64.len() + (b64.len() / 76) + 1);
    for chunk in b64.as_bytes().chunks(76) {
        // Base64 output is ASCII by construction.
        formatted.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        formatted.push('\n');
    }
    formatted
}

/// MurmurHash3 x86/32 — minimal faithful implementation, seed configurable.
fn murmurhash3_x86_32(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;

    let len = data.len();
    let nblocks = len / 4;
    let mut h1 = seed;

    for i in 0..nblocks {
        let mut k1 = u32::from_le_bytes([
            data[i * 4],
            data[i * 4 + 1],
            data[i * 4 + 2],
            data[i * 4 + 3],
        ]);
        k1 = k1.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h1 ^= k1;
        h1 = h1.rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64);
    }

    let tail = &data[nblocks * 4..];
    let mut k1: u32 = 0;
    if tail.len() >= 3 {
        k1 ^= (tail[2] as u32) << 16;
    }
    if tail.len() >= 2 {
        k1 ^= (tail[1] as u32) << 8;
    }
    if !tail.is_empty() {
        k1 ^= tail[0] as u32;
        k1 = k1.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h1 ^= k1;
    }

    h1 ^= len as u32;
    h1 = fmix32(h1);
    h1
}

/// MurmurHash3 finalisation mix.
fn fmix32(mut h: u32) -> u32 {
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn murmurhash_known_value() {
        assert_eq!(murmurhash3_x86_32(b"", 0), 0);
        assert_eq!(murmurhash3_x86_32(b"hello", 0), 613_153_351);
    }

    #[test]
    fn shodan_base64_always_has_trailing_newline() {
        assert_eq!(shodan_base64_with_newlines(b""), "\n");
        assert_eq!(shodan_base64_with_newlines(b"hello"), "aGVsbG8=\n");
        assert!(shodan_base64_with_newlines(&[b'a'; 80]).ends_with('\n'));
    }
}

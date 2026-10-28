//! PEM: base64 armour around DER.

use crate::Error;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}

pub fn base64_decode(text: &str) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut padding = 0usize;
    for c in text.bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'=' {
            padding += 1;
            continue;
        }
        if padding > 0 {
            return Err(Error::Der("данные после '=' в base64"));
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(Error::Der("недопустимый символ в base64")),
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if padding > 2 {
        return Err(Error::Der("слишком много '=' в base64"));
    }
    Ok(out)
}

/// All blocks with the given label (`CERTIFICATE`, ...), in order.
pub fn decode_all(text: &str, label: &str) -> Result<Vec<Vec<u8>>, Error> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&begin) {
        let after = &rest[start + begin.len()..];
        let stop = after.find(&end).ok_or(Error::Der("PEM-блок без END"))?;
        out.push(base64_decode(&after[..stop])?);
        rest = &after[stop + end.len()..];
    }
    Ok(out)
}

pub fn encode(der: &[u8], label: &str) -> String {
    let body = base64_encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Accepts PEM (first CERTIFICATE block) or raw DER.
pub fn certificate_der(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        if text.contains("-----BEGIN CERTIFICATE-----") {
            return decode_all(text, "CERTIFICATE")?
                .into_iter()
                .next()
                .ok_or(Error::Der("пустой PEM"));
        }
    }
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for len in 0..20 {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let enc = base64_encode(&data);
            assert_eq!(base64_decode(&enc).unwrap(), data, "len {len}");
        }
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(base64_encode(b"Ma"), "TWE=");
        assert_eq!(base64_decode("TW\r\nE=").unwrap(), b"Ma");
    }

    #[test]
    fn pem_blocks() {
        let one = encode(&[1, 2, 3], "CERTIFICATE");
        let two = encode(&[4, 5], "CERTIFICATE");
        let blocks = decode_all(&format!("junk\n{one}middle\r\n{two}"), "CERTIFICATE").unwrap();
        assert_eq!(blocks, vec![vec![1, 2, 3], vec![4, 5]]);
    }
}

//! Minimal DER writer and reader: exactly what X.509 needs, nothing more.

use crate::Error;

pub mod tag {
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OID: u8 = 0x06;
    pub const UTF8_STRING: u8 = 0x0c;
    pub const PRINTABLE_STRING: u8 = 0x13;
    pub const T61_STRING: u8 = 0x14;
    pub const IA5_STRING: u8 = 0x16;
    pub const UTC_TIME: u8 = 0x17;
    pub const GENERALIZED_TIME: u8 = 0x18;
    pub const BMP_STRING: u8 = 0x1e;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;
}

// ---------------------------------------------------------------- writer

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = (len as u64).to_be_bytes();
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
    out.extend_from_slice(content);
    out
}

pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(tag::SEQUENCE, &parts.concat())
}

pub fn set(parts: &[&[u8]]) -> Vec<u8> {
    tlv(tag::SET, &parts.concat())
}

/// Non-negative INTEGER from big-endian magnitude bytes.
pub fn integer(magnitude: &[u8]) -> Vec<u8> {
    let first = magnitude.iter().position(|&b| b != 0);
    let mut content = match first {
        Some(i) => magnitude[i..].to_vec(),
        None => vec![0],
    };
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    tlv(tag::INTEGER, &content)
}

pub fn integer_u64(v: u64) -> Vec<u8> {
    integer(&v.to_be_bytes())
}

pub fn oid(arcs: &[u64]) -> Vec<u8> {
    assert!(arcs.len() >= 2, "OID needs at least two arcs");
    let mut content = Vec::new();
    push_base128(&mut content, arcs[0] * 40 + arcs[1]);
    for &arc in &arcs[2..] {
        push_base128(&mut content, arc);
    }
    tlv(tag::OID, &content)
}

fn push_base128(out: &mut Vec<u8>, mut v: u64) {
    let mut tmp = [0u8; 10];
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            break;
        }
    }
    let last = tmp.len() - 1;
    for (j, b) in tmp.iter().enumerate().skip(i) {
        out.push(if j == last { *b } else { b | 0x80 });
    }
}

pub fn boolean(v: bool) -> Vec<u8> {
    tlv(tag::BOOLEAN, &[if v { 0xff } else { 0x00 }])
}

pub fn octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(tag::OCTET_STRING, bytes)
}

/// BIT STRING with zero unused bits.
pub fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(bytes.len() + 1);
    content.push(0);
    content.extend_from_slice(bytes);
    tlv(tag::BIT_STRING, &content)
}

pub fn utf8_string(s: &str) -> Vec<u8> {
    tlv(tag::UTF8_STRING, s.as_bytes())
}

/// `[n]` constructed context tag (EXPLICIT wrappers, IMPLICIT SEQUENCEs).
pub fn context_constructed(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, content)
}

/// `[n]` primitive context tag (IMPLICIT primitive values).
pub fn context_primitive(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0x80 | n, content)
}

// ---------------------------------------------------------------- reader

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    /// The whole element: tag, length and content.
    pub raw: &'a [u8],
}

/// Reads one element and returns it with the remaining input.
pub fn read(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), Error> {
    if input.len() < 2 {
        return Err(Error::Der("неожиданный конец данных"));
    }
    let tag = input[0];
    if tag & 0x1f == 0x1f {
        return Err(Error::Der("многобайтовые теги не поддерживаются"));
    }
    let first = input[1];
    let (len, header) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 {
            return Err(Error::Der("неопределённая длина запрещена в DER"));
        }
        if n > 4 || input.len() < 2 + n {
            return Err(Error::Der("слишком длинное поле длины"));
        }
        let mut len = 0usize;
        for &b in &input[2..2 + n] {
            len = (len << 8) | b as usize;
        }
        (len, 2 + n)
    };
    let end = header
        .checked_add(len)
        .filter(|&end| end <= input.len())
        .ok_or(Error::Der("длина выходит за пределы данных"))?;
    Ok((
        Tlv {
            tag,
            content: &input[header..end],
            raw: &input[..end],
        },
        &input[end..],
    ))
}

/// Reads one element that must carry `expected` tag.
pub fn expect(input: &[u8], expected: u8) -> Result<(Tlv<'_>, &[u8]), Error> {
    let (t, rest) = read(input)?;
    if t.tag != expected {
        return Err(Error::Der("неожиданный тег"));
    }
    Ok((t, rest))
}

/// Splits a constructed element's content into its children.
pub fn children(mut content: &[u8]) -> Result<Vec<Tlv<'_>>, Error> {
    let mut out = Vec::new();
    while !content.is_empty() {
        let (t, rest) = read(content)?;
        out.push(t);
        content = rest;
    }
    Ok(out)
}

pub fn decode_oid(content: &[u8]) -> Result<Vec<u64>, Error> {
    if content.is_empty() {
        return Err(Error::Der("пустой OID"));
    }
    let mut arcs = Vec::new();
    let mut v: u64 = 0;
    for (i, &b) in content.iter().enumerate() {
        if v > (u64::MAX >> 7) {
            return Err(Error::Der("слишком большой компонент OID"));
        }
        v = (v << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            if arcs.is_empty() {
                let (a0, a1) = if v < 40 {
                    (0, v)
                } else if v < 80 {
                    (1, v - 40)
                } else {
                    (2, v - 80)
                };
                arcs.push(a0);
                arcs.push(a1);
            } else {
                arcs.push(v);
            }
            v = 0;
        } else if i == content.len() - 1 {
            return Err(Error::Der("оборванный OID"));
        }
    }
    Ok(arcs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_roundtrip() {
        let arcs = [1u64, 2, 840, 113549, 1, 1, 11];
        let enc = oid(&arcs);
        assert_eq!(enc, [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]);
        let (t, rest) = read(&enc).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decode_oid(t.content).unwrap(), arcs);
    }

    #[test]
    fn long_length() {
        let content = vec![7u8; 300];
        let enc = tlv(0x04, &content);
        assert_eq!(&enc[..4], &[0x04, 0x82, 0x01, 0x2c]);
        let (t, _) = read(&enc).unwrap();
        assert_eq!(t.content.len(), 300);
    }

    #[test]
    fn integers() {
        assert_eq!(integer(&[0x00, 0x00, 0x01]), [0x02, 0x01, 0x01]);
        assert_eq!(integer(&[0x80]), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(integer(&[0, 0]), [0x02, 0x01, 0x00]);
        assert_eq!(integer_u64(2), [0x02, 0x01, 0x02]);
    }

    #[test]
    fn rejects_truncated() {
        assert!(read(&[0x30, 0x05, 0x01]).is_err());
        assert!(read(&[0x30, 0x80]).is_err());
    }
}

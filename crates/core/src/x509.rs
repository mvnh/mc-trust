//! Just enough X.509 parsing for mc-trust: names, keys, validity and the
//! three extensions we read (SKI, basicConstraints presence, nameConstraints).

use crate::der::{self, tag, Tlv};
use crate::{hash, Error};

pub mod oids {
    pub const CN: &[u64] = &[2, 5, 4, 3];
    pub const ORGANIZATION: &[u64] = &[2, 5, 4, 10];
    pub const SUBJECT_KEY_ID: &[u64] = &[2, 5, 29, 14];
    pub const KEY_USAGE: &[u64] = &[2, 5, 29, 15];
    pub const SUBJECT_ALT_NAME: &[u64] = &[2, 5, 29, 17];
    pub const BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];
    pub const NAME_CONSTRAINTS: &[u64] = &[2, 5, 29, 30];
    pub const AUTHORITY_KEY_ID: &[u64] = &[2, 5, 29, 35];
    pub const RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
    pub const SHA256_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 11];
    pub const SHA384_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 12];
    pub const SHA512_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 13];
    pub const EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
    pub const PRIME256V1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
    pub const SECP384R1: &[u64] = &[1, 3, 132, 0, 34];
    pub const ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
    pub const ECDSA_WITH_SHA384: &[u64] = &[1, 2, 840, 10045, 4, 3, 3];
}

#[derive(Debug, Clone)]
pub struct Extension {
    pub oid: Vec<u64>,
    pub critical: bool,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Cert {
    pub der: Vec<u8>,
    pub tbs_raw: Vec<u8>,
    pub signature_alg: Vec<u64>,
    pub signature: Vec<u8>,
    pub issuer_raw: Vec<u8>,
    pub subject_raw: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
    /// Whole SubjectPublicKeyInfo element.
    pub spki_raw: Vec<u8>,
    pub spki_alg: Vec<u64>,
    /// Algorithm parameter OID (the curve for EC keys), if any.
    pub spki_param: Option<Vec<u64>>,
    /// Contents of the subjectPublicKey BIT STRING (RSAPublicKey or EC point).
    pub spki_key: Vec<u8>,
    pub extensions: Vec<Extension>,
}

fn bit_string_bytes(t: &Tlv<'_>) -> Result<Vec<u8>, Error> {
    if t.tag != tag::BIT_STRING || t.content.is_empty() || t.content[0] != 0 {
        return Err(Error::Der("ожидалась BIT STRING без неиспользуемых бит"));
    }
    Ok(t.content[1..].to_vec())
}

fn algorithm(t: &Tlv<'_>) -> Result<(Vec<u64>, Option<Vec<u64>>), Error> {
    if t.tag != tag::SEQUENCE {
        return Err(Error::Der("ожидался AlgorithmIdentifier"));
    }
    let kids = der::children(t.content)?;
    let first = kids.first().ok_or(Error::Der("пустой AlgorithmIdentifier"))?;
    if first.tag != tag::OID {
        return Err(Error::Der("ожидался OID алгоритма"));
    }
    let param = match kids.get(1) {
        Some(p) if p.tag == tag::OID => Some(der::decode_oid(p.content)?),
        _ => None,
    };
    Ok((der::decode_oid(first.content)?, param))
}

impl Cert {
    pub fn from_der(input: &[u8]) -> Result<Cert, Error> {
        let (cert, rest) = der::expect(input, tag::SEQUENCE)?;
        if !rest.is_empty() {
            return Err(Error::Der("лишние данные после сертификата"));
        }
        let top = der::children(cert.content)?;
        if top.len() != 3 {
            return Err(Error::Der("Certificate должен содержать 3 поля"));
        }
        let (tbs, sig_alg, sig) = (top[0], top[1], top[2]);
        if tbs.tag != tag::SEQUENCE {
            return Err(Error::Der("ожидался TBSCertificate"));
        }
        let (signature_alg, _) = algorithm(&sig_alg)?;
        let signature = bit_string_bytes(&sig)?;

        let fields = der::children(tbs.content)?;
        let mut i = 0;
        if fields.first().map(|f| f.tag) == Some(0xa0) {
            i += 1; // explicit version
        }
        let get = |idx: usize| fields.get(idx).copied().ok_or(Error::Der("TBSCertificate слишком короткий"));
        let _serial = get(i)?;
        let tbs_sig = get(i + 1)?;
        if algorithm(&tbs_sig)?.0 != signature_alg {
            return Err(Error::Der("алгоритмы подписи внутри и снаружи TBSCertificate различаются"));
        }
        let issuer = get(i + 2)?;
        let validity = get(i + 3)?;
        let subject = get(i + 4)?;
        let spki = get(i + 5)?;
        if issuer.tag != tag::SEQUENCE || subject.tag != tag::SEQUENCE || validity.tag != tag::SEQUENCE {
            return Err(Error::Der("некорректные имя или срок действия"));
        }

        let times = der::children(validity.content)?;
        if times.len() != 2 {
            return Err(Error::Der("Validity должна содержать 2 даты"));
        }
        let not_before = crate::time::decode(times[0].tag, times[0].content)?;
        let not_after = crate::time::decode(times[1].tag, times[1].content)?;

        if spki.tag != tag::SEQUENCE {
            return Err(Error::Der("ожидался SubjectPublicKeyInfo"));
        }
        let spki_parts = der::children(spki.content)?;
        if spki_parts.len() != 2 {
            return Err(Error::Der("SubjectPublicKeyInfo должен содержать 2 поля"));
        }
        let (spki_alg, spki_param) = algorithm(&spki_parts[0])?;
        let spki_key = bit_string_bytes(&spki_parts[1])?;

        let mut extensions = Vec::new();
        for f in &fields[i + 6..] {
            if f.tag != 0xa3 {
                continue; // issuerUniqueID / subjectUniqueID
            }
            let (list, _) = der::expect(f.content, tag::SEQUENCE)?;
            for ext in der::children(list.content)? {
                let parts = der::children(ext.content)?;
                let (oid, critical, value) = match parts.as_slice() {
                    [o, v] => (o, false, v),
                    [o, c, v] if c.tag == tag::BOOLEAN => (o, c.content == [0xff], v),
                    _ => return Err(Error::Der("некорректное расширение")),
                };
                if oid.tag != tag::OID || value.tag != tag::OCTET_STRING {
                    return Err(Error::Der("некорректное расширение"));
                }
                extensions.push(Extension {
                    oid: der::decode_oid(oid.content)?,
                    critical,
                    value: value.content.to_vec(),
                });
            }
        }

        Ok(Cert {
            der: input.to_vec(),
            tbs_raw: tbs.raw.to_vec(),
            signature_alg,
            signature,
            issuer_raw: issuer.raw.to_vec(),
            subject_raw: subject.raw.to_vec(),
            not_before,
            not_after,
            spki_raw: spki.raw.to_vec(),
            spki_alg,
            spki_param,
            spki_key,
            extensions,
        })
    }

    pub fn extension(&self, oid: &[u64]) -> Option<&Extension> {
        self.extensions.iter().find(|e| e.oid == oid)
    }

    pub fn is_self_issued(&self) -> bool {
        self.subject_raw == self.issuer_raw
    }

    pub fn subject_cn(&self) -> Option<String> {
        name_attr(&self.subject_raw, oids::CN)
    }

    pub fn issuer_cn(&self) -> Option<String> {
        name_attr(&self.issuer_raw, oids::CN)
    }

    pub fn subject_key_id(&self) -> Option<Vec<u8>> {
        let ext = self.extension(oids::SUBJECT_KEY_ID)?;
        let (t, _) = der::expect(&ext.value, tag::OCTET_STRING).ok()?;
        Some(t.content.to_vec())
    }

    pub fn is_ca(&self) -> bool {
        self.extension(oids::BASIC_CONSTRAINTS)
            .and_then(|e| der::expect(&e.value, tag::SEQUENCE).ok())
            .and_then(|(seq, _)| der::children(seq.content).ok())
            .map(|kids| kids.first().map(|k| k.tag == tag::BOOLEAN && k.content == [0xff]).unwrap_or(false))
            .unwrap_or(false)
    }

    /// Permitted dNSName subtrees, or `None` if the certificate has no
    /// nameConstraints extension at all.
    pub fn permitted_dns(&self) -> Result<Option<Vec<String>>, Error> {
        let Some(ext) = self.extension(oids::NAME_CONSTRAINTS) else {
            return Ok(None);
        };
        let (nc, _) = der::expect(&ext.value, tag::SEQUENCE)?;
        let mut out = Vec::new();
        for part in der::children(nc.content)? {
            if part.tag != 0xa0 {
                continue; // excludedSubtrees
            }
            for subtree in der::children(part.content)? {
                let (base, _) = der::read(subtree.content)?;
                if base.tag == 0x82 {
                    out.push(String::from_utf8_lossy(base.content).into_owned());
                }
            }
        }
        Ok(Some(out))
    }

    /// Whether nameConstraints excludes every IPv4 and IPv6 address
    /// (`0.0.0.0/0` and `::/0`).
    pub fn excludes_all_ips(&self) -> Result<bool, Error> {
        let Some(ext) = self.extension(oids::NAME_CONSTRAINTS) else {
            return Ok(false);
        };
        let (nc, _) = der::expect(&ext.value, tag::SEQUENCE)?;
        let (mut v4, mut v6) = (false, false);
        for part in der::children(nc.content)? {
            if part.tag != 0xa1 {
                continue; // permittedSubtrees
            }
            for subtree in der::children(part.content)? {
                let (base, _) = der::read(subtree.content)?;
                if base.tag == 0x87 && base.content.iter().all(|&b| b == 0) {
                    match base.content.len() {
                        8 => v4 = true,
                        32 => v6 = true,
                        _ => {}
                    }
                }
            }
        }
        Ok(v4 && v6)
    }

    /// dNSName entries of subjectAltName; empty if the extension is absent.
    pub fn san_dns(&self) -> Result<Vec<String>, Error> {
        let Some(ext) = self.extension(oids::SUBJECT_ALT_NAME) else {
            return Ok(Vec::new());
        };
        let (names, _) = der::expect(&ext.value, tag::SEQUENCE)?;
        Ok(der::children(names.content)?
            .into_iter()
            .filter(|n| n.tag == 0x82)
            .map(|n| String::from_utf8_lossy(n.content).into_owned())
            .collect())
    }

    pub fn sha1(&self) -> [u8; 20] {
        hash::sha1(&self.der)
    }

    pub fn sha256(&self) -> [u8; 32] {
        hash::sha256(&self.der)
    }

    pub fn spki_sha256(&self) -> [u8; 32] {
        hash::sha256(&self.spki_raw)
    }

    /// Verifies this certificate's signature with `issuer`'s public key.
    pub fn verify_signed_by(&self, issuer: &Cert) -> Result<(), Error> {
        crate::crypto::verify(
            &issuer.spki_alg,
            issuer.spki_param.as_deref(),
            &issuer.spki_key,
            &self.signature_alg,
            &self.tbs_raw,
            &self.signature,
        )
    }
}

/// First value of the given attribute in a DER Name.
pub fn name_attr(name_raw: &[u8], wanted: &[u64]) -> Option<String> {
    let (name, _) = der::expect(name_raw, tag::SEQUENCE).ok()?;
    for rdn in der::children(name.content).ok()? {
        for atv in der::children(rdn.content).ok()? {
            let parts = der::children(atv.content).ok()?;
            let (oid, value) = (parts.first()?, parts.get(1)?);
            if der::decode_oid(oid.content).ok()?.as_slice() != wanted {
                continue;
            }
            return match value.tag {
                tag::UTF8_STRING | tag::PRINTABLE_STRING | tag::IA5_STRING => {
                    String::from_utf8(value.content.to_vec()).ok()
                }
                tag::T61_STRING => Some(value.content.iter().map(|&b| b as char).collect()),
                tag::BMP_STRING => {
                    let units: Vec<u16> = value
                        .content
                        .chunks_exact(2)
                        .map(|c| u16::from_be_bytes([c[0], c[1]]))
                        .collect();
                    String::from_utf16(&units).ok()
                }
                _ => None,
            };
        }
    }
    None
}

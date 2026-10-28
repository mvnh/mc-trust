//! A grant: our CA plus the constrained copy of the Mintsifry root.

use std::sync::OnceLock;

use crate::der::{self, context_constructed, context_primitive, octet_string, oid, seq, set, tlv};
use crate::root::{MintsifryRoot, EMBEDDED_ROOT_PEM};
use crate::x509::{oids, Cert};
use crate::{crypto, hash, pem, time, Error};

/// CN of every CA mc-trust creates: `mc-trust grant <id>`.
pub const GRANT_CN_PREFIX: &str = "mc-trust grant";

#[derive(Debug, Clone)]
pub struct Grant {
    /// Random hex id, also the tail of the CA's CN.
    pub id: String,
    /// Our CA (self-signed, ECDSA P-256). Install as trusted for TLS only.
    pub ca_der: Vec<u8>,
    /// Constrained copy of the Mintsifry root. Install as an intermediate.
    pub copy_der: Vec<u8>,
    pub domains: Vec<String>,
    pub not_after: i64,
}

impl Grant {
    pub fn ca_pem(&self) -> String {
        pem::encode(&self.ca_der, "CERTIFICATE")
    }

    pub fn copy_pem(&self) -> String {
        pem::encode(&self.copy_der, "CERTIFICATE")
    }
}

fn extension(id: &[u64], critical: bool, value: &[u8]) -> Vec<u8> {
    if critical {
        seq(&[&oid(id), &der::boolean(true), &octet_string(value)])
    } else {
        seq(&[&oid(id), &octet_string(value)])
    }
}

fn name_constraints(domains: &[String]) -> Vec<u8> {
    let subtrees: Vec<Vec<u8>> = domains
        .iter()
        .map(|d| seq(&[&context_primitive(2, d.as_bytes())]))
        .collect();
    let refs: Vec<&[u8]> = subtrees.iter().map(|v| v.as_slice()).collect();
    // RFC 5280 constrains each name type separately, so a certificate whose only
    // name is an IP address would pass a dNSName-only constraint. Address plus
    // mask, all zeros: every IPv4 and every IPv6 address.
    let any_ipv4 = seq(&[&context_primitive(7, &[0u8; 8])]);
    let any_ipv6 = seq(&[&context_primitive(7, &[0u8; 32])]);
    // NameConstraints ::= SEQUENCE { permittedSubtrees [0], excludedSubtrees [1] }
    seq(&[
        &context_constructed(0, &refs.concat()),
        &context_constructed(1, &[any_ipv4, any_ipv6].concat()),
    ])
}

fn ca_basic_constraints() -> Vec<u8> {
    seq(&[&der::boolean(true)])
}

fn ca_key_usage() -> Vec<u8> {
    // keyCertSign (bit 5) | cRLSign (bit 6); one unused trailing bit.
    tlv(der::tag::BIT_STRING, &[0x01, 0x06])
}

fn serial() -> Result<Vec<u8>, Error> {
    let mut s = crypto::random_bytes(16)?;
    s[0] = (s[0] & 0x7f) | 0x40; // positive, fixed length
    Ok(s)
}

fn certificate(tbs: &[u8], signer: &crypto::Signer) -> Result<Vec<u8>, Error> {
    let alg = seq(&[&oid(oids::ECDSA_WITH_SHA256)]);
    let signature = signer.sign_sha256(tbs)?;
    Ok(seq(&[tbs, &alg, &der::bit_string(&signature)]))
}

/// Builds a grant for `domains` (already normalized). `now` is a Unix time.
///
/// The CA key is generated here and dropped before returning: nothing can be
/// signed with it afterwards, by anyone.
pub fn build_grant(root: &MintsifryRoot, domains: &[String], now: i64) -> Result<Grant, Error> {
    if domains.is_empty() {
        return Err(Error::Domain("список доменов пуст".into()));
    }
    let not_after = root.not_after();
    if not_after <= now {
        return Err(Error::Cert("срок действия корня Минцифры истёк".into()));
    }
    let not_before = now - 86_400; // tolerate a day of clock skew
    let id = hash::hex(&crypto::random_bytes(6)?);

    let signer = crypto::Signer::generate()?;
    let point = signer.public_point();
    let ca_spki = seq(&[
        &seq(&[&oid(oids::EC_PUBLIC_KEY), &oid(oids::PRIME256V1)]),
        &der::bit_string(&point),
    ]);
    let ca_ski = hash::sha1(&point).to_vec();
    let ca_name = seq(&[&set(&[&seq(&[
        &oid(oids::CN),
        &der::utf8_string(&format!("{GRANT_CN_PREFIX} {id}")),
    ])])]);

    let version = context_constructed(0, &der::integer_u64(2));
    let tbs_alg = seq(&[&oid(oids::ECDSA_WITH_SHA256)]);
    let validity = seq(&[&time::encode(not_before), &time::encode(not_after)]);
    let nc = extension(oids::NAME_CONSTRAINTS, true, &name_constraints(domains));
    let bc = extension(oids::BASIC_CONSTRAINTS, true, &ca_basic_constraints());
    let ku = extension(oids::KEY_USAGE, true, &ca_key_usage());

    // Our CA: self-signed, constrained like the copy (defence in depth).
    let ca_exts = seq(&[
        &bc,
        &ku,
        &extension(oids::SUBJECT_KEY_ID, false, &octet_string(&ca_ski)),
        &nc,
    ]);
    let ca_tbs = seq(&[
        &version,
        &der::integer(&serial()?),
        &tbs_alg,
        &ca_name,
        &validity,
        &ca_name,
        &ca_spki,
        &context_constructed(3, &ca_exts),
    ]);
    let ca_der = certificate(&ca_tbs, &signer)?;

    // The copy: the root's own subject and key, byte for byte, issued by our CA.
    let mut copy_exts: Vec<Vec<u8>> = vec![bc.clone(), ku.clone()];
    if let Some(ski) = root.subject_key_id() {
        copy_exts.push(extension(oids::SUBJECT_KEY_ID, false, &octet_string(&ski)));
    }
    copy_exts.push(extension(
        oids::AUTHORITY_KEY_ID,
        false,
        &seq(&[&context_primitive(0, &ca_ski)]),
    ));
    copy_exts.push(nc);
    let copy_ext_refs: Vec<&[u8]> = copy_exts.iter().map(|v| v.as_slice()).collect();
    let copy_tbs = seq(&[
        &version,
        &der::integer(&serial()?),
        &tbs_alg,
        &ca_name,
        &validity,
        root.subject_raw(),
        root.spki_raw(),
        &context_constructed(3, &seq(&copy_ext_refs)),
    ]);
    let copy_der = certificate(&copy_tbs, &signer)?;

    // Self-check: never hand out something we did not mean to build.
    let ca = Cert::from_der(&ca_der)?;
    let copy = Cert::from_der(&copy_der)?;
    if copy.subject_raw != root.subject_raw() || copy.spki_raw != root.spki_raw() {
        return Err(Error::Cert("копия не совпадает с корнем по имени или ключу".into()));
    }
    if copy.issuer_raw != ca.subject_raw {
        return Err(Error::Cert("издатель копии не совпадает с CA".into()));
    }
    ca.verify_signed_by(&ca)?;
    copy.verify_signed_by(&ca)?;
    for cert in [&ca, &copy] {
        if cert.permitted_dns()?.as_deref() != Some(domains) {
            return Err(Error::Cert("ограничение имён записано неверно".into()));
        }
        if !cert.excludes_all_ips()? {
            return Err(Error::Cert("запрет IP-адресов записан неверно".into()));
        }
    }

    Ok(Grant {
        id,
        ca_der,
        copy_der,
        domains: domains.to_vec(),
        not_after,
    })
}

/// What a certificate found in a trust store is, from mc-trust's point of view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// The unconstrained Mintsifry root (any key under that exact name).
    OriginalRoot,
    /// A CA created by mc-trust.
    GrantCa { id: String },
    /// A constrained copy created by mc-trust.
    GrantCopy { id: String },
    /// A CA issued by the Mintsifry root (`Russian Trusted Sub CA` and the
    /// like). Harmless as a plain intermediate, but if someone marked it as
    /// trusted it becomes an unconstrained anchor, so mc-trust removes it:
    /// servers send it in their chains anyway.
    MintsifrySub,
    Other,
}

fn mc_subject() -> &'static [u8] {
    static SUBJECT: OnceLock<Vec<u8>> = OnceLock::new();
    SUBJECT.get_or_init(|| {
        let der = pem::certificate_der(EMBEDDED_ROOT_PEM.as_bytes()).expect("embedded root is PEM");
        Cert::from_der(&der).expect("embedded root parses").subject_raw
    })
}

fn grant_id(cn: Option<String>) -> Option<String> {
    cn?.strip_prefix(GRANT_CN_PREFIX)
        .map(|rest| rest.trim().to_string())
        .filter(|id| !id.is_empty())
}

pub fn classify(cert: &Cert) -> Kind {
    if cert.is_self_issued() {
        if cert.subject_raw == mc_subject() {
            return Kind::OriginalRoot;
        }
        if let Some(id) = grant_id(cert.subject_cn()) {
            return Kind::GrantCa { id };
        }
    } else if cert.subject_raw == mc_subject() {
        if let Some(id) = grant_id(cert.issuer_cn()) {
            return Kind::GrantCopy { id };
        }
    } else if cert.issuer_raw == mc_subject() && cert.is_ca() {
        return Kind::MintsifrySub;
    }
    Kind::Other
}

/// Problems visible in an installed grant's certificates alone. Whether the
/// system really trusts the CA is not visible here; `mc-trust check` covers that.
pub fn audit(root: &MintsifryRoot, ca: &Cert, copy: &Cert) -> Vec<String> {
    let mut problems = Vec::new();
    if copy.spki_raw != root.spki_raw() {
        problems.push("ключ копии не совпадает с корнем Минцифры".to_string());
    }
    if copy.verify_signed_by(ca).is_err() {
        problems.push("копия подписана не этим CA".to_string());
    }
    for (what, cert) in [("CA", ca), ("копия корня", copy)] {
        if !matches!(cert.permitted_dns(), Ok(Some(d)) if !d.is_empty()) {
            problems.push(format!("{what}: нет ограничения имён"));
        } else if !cert.excludes_all_ips().unwrap_or(false) {
            problems.push(format!("{what}: IP-адреса не ограничены, переустановите: mc-trust install"));
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_ZONES;

    fn zones() -> Vec<String> {
        DEFAULT_ZONES.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn embedded_root_is_pinned() {
        let root = MintsifryRoot::embedded().unwrap();
        assert!(root.is_pinned());
        assert_eq!(
            hash::hex(&root.subject_key_id().unwrap()),
            "e1d181e5ce5a5f04aad2e9b69d66b1c5faac2c87"
        );
        assert_eq!(time::format_human(root.not_after()), "2032-02-27 21:04:15 UTC");
        assert_eq!(classify(root.cert()), Kind::OriginalRoot);
    }

    #[test]
    fn grant_shape() {
        let root = MintsifryRoot::embedded().unwrap();
        let g = build_grant(&root, &zones(), time::now_unix().unwrap()).unwrap();
        let ca = Cert::from_der(&g.ca_der).unwrap();
        let copy = Cert::from_der(&g.copy_der).unwrap();
        assert_eq!(classify(&ca), Kind::GrantCa { id: g.id.clone() });
        assert_eq!(classify(&copy), Kind::GrantCopy { id: g.id.clone() });
        assert_eq!(copy.subject_key_id(), root.subject_key_id());
        assert_eq!(copy.not_after, root.not_after());
        assert!(ca.is_ca() && copy.is_ca());
        let nc = copy.extension(oids::NAME_CONSTRAINTS).unwrap();
        assert!(nc.critical);
        assert_eq!(copy.permitted_dns().unwrap().unwrap(), zones());
        assert!(ca.excludes_all_ips().unwrap() && copy.excludes_all_ips().unwrap());
    }

    #[test]
    fn classifies_real_sub_ca() {
        let pem_text = include_str!("../tests/data/russian_trusted_sub_ca.pem");
        let der = pem::certificate_der(pem_text.as_bytes()).unwrap();
        assert_eq!(classify(&Cert::from_der(&der).unwrap()), Kind::MintsifrySub);
    }

    #[test]
    fn rejects_empty_domains() {
        let root = MintsifryRoot::embedded().unwrap();
        assert!(build_grant(&root, &[], time::now_unix().unwrap()).is_err());
    }

    #[test]
    fn audit_accepts_a_fresh_grant_and_flags_a_mixup() {
        let root = MintsifryRoot::embedded().unwrap();
        let now = time::now_unix().unwrap();
        let a = build_grant(&root, &zones(), now).unwrap();
        let b = build_grant(&root, &zones(), now).unwrap();
        let ca_a = Cert::from_der(&a.ca_der).unwrap();
        let copy_a = Cert::from_der(&a.copy_der).unwrap();
        let copy_b = Cert::from_der(&b.copy_der).unwrap();
        assert!(audit(&root, &ca_a, &copy_a).is_empty());
        // The copy of another grant was signed by another CA.
        assert_eq!(audit(&root, &ca_a, &copy_b).len(), 1);
    }
}

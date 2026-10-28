//! The Mintsifry root: embedded, pinned, validated.

use crate::x509::Cert;
use crate::{hash, pem, Error};

/// Russian Trusted Root CA (RSA 4096), valid 2022-03-01 .. 2032-02-27.
/// Source: <https://gu-st.ru/content/lending/russian_trusted_root_ca_pem.crt>.
pub const EMBEDDED_ROOT_PEM: &str = include_str!("../assets/russian_trusted_root_ca.pem");

/// SHA-256 of the root's SubjectPublicKeyInfo.
pub const PINNED_SPKI_SHA256: &str = "02b8220c070728db771d9ac59e54521c4eddad21a783bb26cfdf19c1db0fae37";

pub const ROOT_URL: &str = "https://gu-st.ru/content/lending/russian_trusted_root_ca_pem.crt";

pub const MC_ROOT_CN: &str = "Russian Trusted Root CA";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinPolicy {
    /// The key must match [`PINNED_SPKI_SHA256`].
    Require,
    /// Any self-signed certificate named "Russian Trusted Root CA" is accepted.
    /// A root with another key: a rotated root, or a test root.
    AllowUnpinned,
}

#[derive(Debug, Clone)]
pub struct MintsifryRoot {
    cert: Cert,
}

impl MintsifryRoot {
    /// The root compiled into the binary. Always pinned.
    pub fn embedded() -> Result<Self, Error> {
        Self::from_bytes(EMBEDDED_ROOT_PEM.as_bytes(), PinPolicy::Require)
    }

    /// PEM or DER.
    pub fn from_bytes(bytes: &[u8], pin: PinPolicy) -> Result<Self, Error> {
        let der = pem::certificate_der(bytes)?;
        let cert = Cert::from_der(&der)?;
        if cert.subject_cn().as_deref() != Some(MC_ROOT_CN) {
            return Err(Error::NotMintsifry(format!(
                "CN = {:?}",
                cert.subject_cn().unwrap_or_default()
            )));
        }
        if !cert.is_self_issued() {
            return Err(Error::NotMintsifry("сертификат не самоподписан".into()));
        }
        if !cert.is_ca() {
            return Err(Error::NotMintsifry("нет basicConstraints CA:true".into()));
        }
        let got = hash::hex(&cert.spki_sha256());
        if pin == PinPolicy::Require && got != PINNED_SPKI_SHA256 {
            return Err(Error::PinMismatch { got });
        }
        cert.verify_signed_by(&cert)
            .map_err(|_| Error::NotMintsifry("самоподпись не сходится".into()))?;
        Ok(Self { cert })
    }

    pub fn cert(&self) -> &Cert {
        &self.cert
    }

    pub fn subject_raw(&self) -> &[u8] {
        &self.cert.subject_raw
    }

    pub fn spki_raw(&self) -> &[u8] {
        &self.cert.spki_raw
    }

    pub fn subject_key_id(&self) -> Option<Vec<u8>> {
        self.cert.subject_key_id()
    }

    pub fn not_after(&self) -> i64 {
        self.cert.not_after
    }

    pub fn spki_sha256_hex(&self) -> String {
        hash::hex(&self.cert.spki_sha256())
    }

    pub fn is_pinned(&self) -> bool {
        self.spki_sha256_hex() == PINNED_SPKI_SHA256
    }

    /// Whether `cert` claims this root as issuer and the signature checks out.
    /// `Some(false)` means the name matches but the signature does not: either
    /// a forgery or a root that differs from the pinned one.
    pub fn signed(&self, cert: &Cert) -> Option<bool> {
        if cert.issuer_raw != self.cert.subject_raw || cert.is_self_issued() {
            return None;
        }
        Some(cert.verify_signed_by(&self.cert).is_ok())
    }
}

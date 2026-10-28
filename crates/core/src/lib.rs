//! Core of mc-trust: everything about certificates, nothing about OS trust stores.
//!
//! The crate builds a *grant*: a fresh self-signed CA plus a copy of the
//! Mintsifry root (same subject, same public key) signed by that CA, both
//! carrying an X.509 `nameConstraints` extension with the allowed domains.
//! The CA private key exists only inside [`grant::build_grant`] and is dropped
//! before the function returns.

pub mod crypto;
pub mod der;
pub mod domains;
pub mod error;
pub mod grant;
pub mod hash;
pub mod pem;
pub mod root;
pub mod time;
pub mod x509;

pub use domains::{dns_name_matches, host_allowed, is_tld, normalize_domain, DEFAULT_ZONES};
pub use error::Error;
pub use grant::{audit, build_grant, classify, Grant, Kind, GRANT_CN_PREFIX};
pub use root::{MintsifryRoot, PinPolicy, MC_ROOT_CN, PINNED_SPKI_SHA256, ROOT_URL};
pub use x509::Cert;

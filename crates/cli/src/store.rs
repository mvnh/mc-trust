//! What the commands need from an operating system's trust store.

use std::path::PathBuf;

use mc_trust_core::{Cert, Grant, Kind};

use crate::macos::Location;
use crate::util::Res;

/// Where a certificate was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Place {
    /// A macOS keychain.
    Keychain(Location),
    /// A file in the directory the distribution reads anchors from; `certs` is
    /// how many certificates the file holds.
    File { path: PathBuf, certs: usize },
    /// A system bundle that no file of ours explains.
    Bundle(PathBuf),
}

impl Place {
    pub fn label(&self) -> String {
        match self {
            Place::Keychain(loc) => format!("связка {}", loc.label()),
            Place::File { path, .. } => format!("файл {}", path.display()),
            Place::Bundle(path) => format!("хранилище {}", path.display()),
        }
    }
}

pub struct Found {
    pub location: Place,
    pub cert: Cert,
    pub kind: Kind,
}

pub trait TrustStore {
    /// Where grants go, as in «добавить его в …».
    fn target(&self) -> &'static str;
    /// Who decides trust in `check`.
    fn verifier(&self) -> &'static str;
    /// Mintsifry certificates and mc-trust's own.
    fn scan(&self) -> Res<Vec<Found>>;
    /// Fails before anything changes if `found` could not be removed later.
    fn removable(&self, _found: &Found) -> Res<()> {
        Ok(())
    }
    fn install_grant(&self, grant: &Grant) -> Res<()>;
    fn remove(&self, found: &Found) -> Res<()>;
    /// Asks the system verifier whether it accepts `chain` (leaf first) for `host`.
    fn verify(&self, host: &str, chain: &[Vec<u8>]) -> Res<bool>;
}

pub fn detect() -> Res<Box<dyn TrustStore>> {
    if cfg!(target_os = "macos") {
        Ok(Box::new(crate::macos::Keychains::detect()?))
    } else if cfg!(target_os = "linux") {
        Ok(Box::new(crate::linux::LinuxStore::detect()?))
    } else {
        Err("mc-trust работает на macOS и Linux".into())
    }
}

//! Linux backend: the system CA store, driven through the distribution's own tools.
//!
//! Debian, Ubuntu, Alpine and openSUSE take anchors from a directory and rebuild the
//! bundle with `update-ca-certificates`; Fedora, RHEL and Arch use `update-ca-trust`.
//!
//! The store has no place for an untrusted intermediate, so the copy of the root lies
//! next to our CA as an ordinary anchor. OpenSSL still applies the name constraints to
//! it (`tests/constraints.rs`); a client that ignores constraints on trusted
//! certificates would see an unconstrained Mintsifry root.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use mc_trust_core::{classify, pem, Cert, Grant, Kind};

use crate::store::{Found, Place, TrustStore};
use crate::util::{path_str, run_interactive, run_quiet, Res, TempDir};

// Absolute paths, so PATH cannot decide what runs with root rights.
const SUDO: &[&str] = &["/usr/bin/sudo"];
const OPENSSL: &str = "/usr/bin/openssl";
const ID: &[&str] = &["/usr/bin/id", "/bin/id"];
const INSTALL: &[&str] = &["/usr/bin/install", "/bin/install"];
const RM: &[&str] = &["/usr/bin/rm", "/bin/rm"];

const UPDATE_CA_CERTIFICATES: &[&str] = &[
    "/usr/sbin/update-ca-certificates",
    "/usr/bin/update-ca-certificates",
    "/sbin/update-ca-certificates",
];
const UPDATE_CA_TRUST: &[&str] = &["/usr/bin/update-ca-trust", "/usr/sbin/update-ca-trust"];

const ANCHORS_CA_CERTIFICATES: &[&str] = &["/usr/local/share/ca-certificates", "/etc/pki/trust/anchors"];
const ANCHORS_CA_TRUST: &[&str] = &["/etc/pki/ca-trust/source/anchors", "/etc/ca-certificates/trust-source/anchors"];

/// The bundles the distributions build from their anchors.
const BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/tls/cacert.pem",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Updater {
    /// Debian family, Alpine, openSUSE.
    CaCertificates,
    /// Fedora, RHEL, Arch.
    CaTrust,
}

pub struct LinuxStore {
    anchors: PathBuf,
    bundles: Vec<PathBuf>,
    updater: Updater,
    update_cmd: PathBuf,
    root: bool,
}

fn first_existing(candidates: &[&str]) -> Option<PathBuf> {
    candidates.iter().map(PathBuf::from).find(|p| p.is_file())
}

fn tool(candidates: &[&str], name: &str) -> Res<PathBuf> {
    Ok(first_existing(candidates).ok_or_else(|| format!("не найден {name}"))?)
}

fn is_root() -> bool {
    first_existing(ID)
        .and_then(|id| Command::new(id).arg("-u").stdin(Stdio::null()).output().ok())
        .is_some_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "0")
}

fn is_ip(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

impl LinuxStore {
    pub fn detect() -> Res<LinuxStore> {
        let (updater, update_cmd, dirs) = if let Some(cmd) = first_existing(UPDATE_CA_CERTIFICATES) {
            (Updater::CaCertificates, cmd, ANCHORS_CA_CERTIFICATES)
        } else if let Some(cmd) = first_existing(UPDATE_CA_TRUST) {
            (Updater::CaTrust, cmd, ANCHORS_CA_TRUST)
        } else {
            return Err("не найден update-ca-certificates или update-ca-trust: установите пакет ca-certificates".into());
        };
        let anchors = dirs
            .iter()
            .map(PathBuf::from)
            .find(|d| d.is_dir())
            .unwrap_or_else(|| PathBuf::from(dirs[0]));
        let bundles = BUNDLES.iter().map(PathBuf::from).filter(|p| p.is_file()).collect();
        Ok(LinuxStore { anchors, bundles, updater, update_cmd, root: is_root() })
    }

    /// Runs `program args` with root rights: directly for root, through sudo otherwise.
    /// `quiet` captures the output and shows it only if the command fails.
    fn as_root(&self, program: &Path, args: &[&str], quiet: bool) -> Res<()> {
        let program = path_str(program)?;
        let sudo;
        let (cmd, argv): (&str, Vec<&str>) = if self.root {
            (program, args.to_vec())
        } else {
            sudo = tool(SUDO, "sudo").map_err(|_| "нужны права root: запустите mc-trust от root или установите sudo")?;
            let mut full = vec![program];
            full.extend_from_slice(args);
            (path_str(&sudo)?, full)
        };
        if quiet {
            run_quiet(cmd, &argv).map(|_| ())
        } else {
            run_interactive(cmd, &argv)
        }
    }

    /// Rebuilds the bundle. `fresh` also drops entries whose file is gone.
    fn update(&self, fresh: bool) -> Res<()> {
        let args: &[&str] = match (self.updater, fresh) {
            (Updater::CaCertificates, true) => &["--fresh"],
            _ => &[],
        };
        self.as_root(&self.update_cmd, args, true)
            .map_err(|e| format!("не удалось обновить хранилище сертификатов: {e}"))?;
        Ok(())
    }

    /// Takes back what a failed install put in place.
    fn rollback(&self, files: &[PathBuf]) {
        if let Ok(rm) = tool(RM, "rm") {
            let mut args = vec!["-f"];
            args.extend(files.iter().filter_map(|p| p.to_str()));
            let _ = self.as_root(&rm, &args, true);
        }
        let _ = self.update(true);
    }
}

/// Mintsifry and mc-trust certificates in the anchor directory, then those in the
/// bundles that no anchor file explains.
fn scan_paths(anchors: &Path, bundles: &[PathBuf]) -> Res<Vec<Found>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    match fs::read_dir(anchors) {
        Ok(entries) => {
            let mut files: Vec<PathBuf> = entries.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect();
            files.sort();
            for path in files {
                let Ok(text) = fs::read_to_string(&path) else { continue }; // not PEM text
                let ders = pem::decode_all(&text, "CERTIFICATE").unwrap_or_default();
                let certs = ders.len();
                for der in ders {
                    let Ok(cert) = Cert::from_der(&der) else { continue };
                    let kind = classify(&cert);
                    if kind != Kind::Other && seen.insert(cert.sha1()) {
                        out.push(Found { location: Place::File { path: path.clone(), certs }, cert, kind });
                    }
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", anchors.display()).into()),
    }
    for bundle in bundles {
        let text = fs::read_to_string(bundle).map_err(|e| format!("{}: {e}", bundle.display()))?;
        for der in pem::decode_all(&text, "CERTIFICATE")? {
            let Ok(cert) = Cert::from_der(&der) else { continue };
            let kind = classify(&cert);
            if kind != Kind::Other && seen.insert(cert.sha1()) {
                out.push(Found { location: Place::Bundle(bundle.clone()), cert, kind });
            }
        }
    }
    Ok(out)
}

impl TrustStore for LinuxStore {
    fn target(&self) -> &'static str {
        "системное хранилище"
    }

    fn verifier(&self) -> &'static str {
        "OpenSSL"
    }

    fn scan(&self) -> Res<Vec<Found>> {
        scan_paths(&self.anchors, &self.bundles)
    }

    fn removable(&self, found: &Found) -> Res<()> {
        match &found.location {
            Place::File { certs: 1, .. } => Ok(()),
            Place::File { path, .. } => Err(format!(
                "{} содержит несколько сертификатов: уберите сертификат Минцифры из файла вручную и повторите",
                path.display()
            )
            .into()),
            Place::Bundle(path) => Err(format!(
                "сертификат лежит в {} и пришёл не из {}: mc-trust не знает, откуда его убрать, \
                 удалите его вручную и обновите хранилище",
                path.display(),
                self.anchors.display()
            )
            .into()),
            Place::Keychain(_) => Err("сертификат лежит не в системном хранилище Linux".into()),
        }
    }

    /// Both certificates go into the anchor directory; the CA is constrained like the copy.
    fn install_grant(&self, grant: &Grant) -> Res<()> {
        let dir = TempDir::new()?;
        let install = tool(INSTALL, "install")?;
        let certs = [
            (format!("mc-trust-grant-{}-ca.crt", grant.id), grant.ca_pem()),
            (format!("mc-trust-grant-{}-copy.crt", grant.id), grant.copy_pem()),
        ];
        if !self.root {
            println!("Для записи в {} нужны права администратора (sudo).", self.anchors.display());
        }
        self.as_root(&install, &["-d", "-m", "0755", path_str(&self.anchors)?], false)?;
        let mut placed: Vec<PathBuf> = Vec::new();
        for (name, text) in &certs {
            let src = dir.write(name, text.as_bytes())?;
            let dst = self.anchors.join(name);
            if let Err(e) = self.as_root(&install, &["-m", "0644", &src, path_str(&dst)?], true) {
                self.rollback(&placed);
                return Err(format!("не удалось записать {}: {e}", dst.display()).into());
            }
            placed.push(dst);
        }
        if let Err(e) = self.update(false) {
            self.rollback(&placed);
            return Err(e);
        }
        Ok(())
    }

    fn remove(&self, found: &Found) -> Res<()> {
        self.removable(found)?;
        let Place::File { path, .. } = &found.location else {
            return Err("сертификат лежит не в файле".into());
        };
        let rm = tool(RM, "rm")?;
        self.as_root(&rm, &["-f", path_str(path)?], true)?;
        self.update(true)
    }

    /// OpenSSL decides, against the system store.
    fn verify(&self, host: &str, chain: &[Vec<u8>]) -> Res<bool> {
        let Some((leaf_der, rest)) = chain.split_first() else {
            return Err("пустая цепочка сертификатов".into());
        };
        let dir = TempDir::new()?;
        let leaf = dir.write("leaf.pem", pem::encode(leaf_der, "CERTIFICATE").as_bytes())?;
        let mut args: Vec<String> = vec!["verify".into(), "-purpose".into(), "sslserver".into()];
        if !rest.is_empty() {
            let pems: String = rest.iter().map(|d| pem::encode(d, "CERTIFICATE")).collect();
            args.push("-untrusted".into());
            args.push(dir.write("untrusted.pem", pems.as_bytes())?);
        }
        args.push(if is_ip(host) { "-verify_ip" } else { "-verify_hostname" }.into());
        args.push(host.into());
        args.push(leaf);
        let out = Command::new(OPENSSL)
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("не удалось запустить openssl: {e}"))?;
        Ok(out.status.success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_trust_core::root::EMBEDDED_ROOT_PEM;
    use mc_trust_core::{build_grant, time, MintsifryRoot};

    /// A directory holding: the Mintsifry root alone, a grant's CA alone, the same
    /// grant's copy together with an unrelated certificate, and a non-certificate file.
    fn fixture() -> (TempDir, PathBuf, Grant) {
        let dir = TempDir::new().unwrap();
        let grant = build_grant(
            &MintsifryRoot::embedded().unwrap(),
            &[".ru".to_string()],
            time::now_unix().unwrap(),
        )
        .unwrap();
        let sub = include_str!("../../core/tests/data/russian_trusted_sub_ca.pem");
        let any = dir.write("a-root.crt", EMBEDDED_ROOT_PEM.as_bytes()).unwrap();
        dir.write("b-ca.crt", grant.ca_pem().as_bytes()).unwrap();
        dir.write("c-copy-and-sub.crt", format!("{}{}", grant.copy_pem(), sub).as_bytes()).unwrap();
        dir.write("d-notes.txt", b"not a certificate").unwrap();
        let anchors = Path::new(&any).parent().unwrap().to_path_buf();
        (dir, anchors, grant)
    }

    #[test]
    fn scan_finds_our_certificates_and_counts_what_a_file_holds() {
        let (_dir, anchors, grant) = fixture();
        let found = scan_paths(&anchors, &[]).unwrap();
        let kinds: Vec<&Kind> = found.iter().map(|f| &f.kind).collect();
        assert_eq!(found.len(), 4, "{kinds:?}");
        assert_eq!(found[0].kind, Kind::OriginalRoot);
        assert_eq!(found[1].kind, Kind::GrantCa { id: grant.id.clone() });
        assert_eq!(found[2].kind, Kind::GrantCopy { id: grant.id.clone() });
        assert_eq!(found[3].kind, Kind::MintsifrySub);
        assert!(matches!(found[0].location, Place::File { certs: 1, .. }));
        assert!(matches!(found[2].location, Place::File { certs: 2, .. }));
    }

    #[test]
    fn bundle_only_shows_what_no_anchor_file_explains() {
        let (_dir, anchors, grant) = fixture();
        // The bundle lives elsewhere; it repeats the CA and the root, which the anchor files explain.
        let other = TempDir::new().unwrap();
        let bundle = other
            .write("bundle.pem", format!("{}{}", grant.ca_pem(), EMBEDDED_ROOT_PEM).as_bytes())
            .unwrap();
        let no_anchors = Path::new(&bundle).parent().unwrap().join("none");
        // With no anchor files the bundle explains itself.
        let found = scan_paths(&no_anchors, &[PathBuf::from(&bundle)]).unwrap();
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|f| matches!(f.location, Place::Bundle(_))));
        // With the fixture's anchors, nothing in the bundle is new.
        let found = scan_paths(&anchors, &[PathBuf::from(&bundle)]).unwrap();
        assert_eq!(found.len(), 4);
        assert!(found.iter().all(|f| matches!(f.location, Place::File { .. })));
    }

    #[test]
    fn only_single_certificate_files_can_be_removed() {
        let (_dir, anchors, _grant) = fixture();
        let store = LinuxStore {
            anchors: anchors.clone(),
            bundles: Vec::new(),
            updater: Updater::CaCertificates,
            update_cmd: PathBuf::from("/nonexistent"),
            root: false,
        };
        let found = scan_paths(&anchors, &[]).unwrap();
        assert!(store.removable(&found[0]).is_ok());
        assert!(store.removable(&found[2]).is_err());
        let in_bundle = Found {
            location: Place::Bundle(PathBuf::from("/etc/ssl/certs/ca-certificates.crt")),
            cert: Cert::from_der(&found[0].cert.der).unwrap(),
            kind: Kind::OriginalRoot,
        };
        assert!(store.removable(&in_bundle).is_err());
    }

    #[test]
    fn ip_hosts() {
        assert!(is_ip("8.8.8.8"));
        assert!(!is_ip("sberbank.ru"));
        assert!(!is_ip("1.2.3"));
        assert!(!is_ip("999.1.1.1"));
    }
}

//! macOS backend: the login and System keychains, driven through `security`.

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use mc_trust_core::{classify, pem, Cert, Grant, Kind, GRANT_CN_PREFIX};

use crate::store::{Found, Place, TrustStore};
use crate::util::{path_str, run_interactive, run_quiet, sha1_upper, Res, TempDir};

// Absolute paths: the tool changes the trust store and calls sudo, so PATH must not decide what runs.
const SECURITY: &str = "/usr/bin/security";
const SUDO: &str = "/usr/bin/sudo";
/// `security` exit code for errSecItemNotFound.
const NOT_FOUND: i32 = 44;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Location {
    Login,
    System,
}

impl Location {
    pub fn label(self) -> &'static str {
        match self {
            Location::Login => "login",
            Location::System => "System",
        }
    }
}

pub struct Keychains {
    login: PathBuf,
    system: PathBuf,
}

impl Keychains {
    pub fn detect() -> Res<Keychains> {
        let home = std::env::var_os("HOME").ok_or("не задана переменная HOME")?;
        let login = PathBuf::from(home).join("Library/Keychains/login.keychain-db");
        if !login.exists() {
            return Err(format!("не найдена связка ключей login: {}", login.display()).into());
        }
        Ok(Keychains {
            login,
            system: PathBuf::from("/Library/Keychains/System.keychain"),
        })
    }

    fn path(&self, loc: Location) -> Res<&str> {
        path_str(match loc {
            Location::Login => &self.login,
            Location::System => &self.system,
        })
    }
}

impl TrustStore for Keychains {
    fn target(&self) -> &'static str {
        "связку login"
    }

    fn verifier(&self) -> &'static str {
        "macOS"
    }

    /// Mintsifry certificates and mc-trust's own, in both keychains.
    fn scan(&self) -> Res<Vec<Found>> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for loc in [Location::Login, Location::System] {
            let keychain = self.path(loc)?;
            for query in ["Russian Trusted", GRANT_CN_PREFIX] {
                let output = Command::new(SECURITY)
                    .args(["find-certificate", "-a", "-c", query, "-p", keychain])
                    .stdin(Stdio::null())
                    .output()
                    .map_err(|e| format!("не удалось запустить security: {e}"))?;
                // No match is exit 0 with empty output (older macOS: 44). Any other failure
                // must not pass for an empty keychain, or install would leave the old root in place.
                if !matches!(output.status.code(), Some(0) | Some(NOT_FOUND)) {
                    return Err(format!(
                        "security find-certificate (связка {}): {}",
                        loc.label(),
                        String::from_utf8_lossy(&output.stderr).trim()
                    )
                    .into());
                }
                for der in pem::decode_all(&String::from_utf8_lossy(&output.stdout), "CERTIFICATE")? {
                    let Ok(cert) = Cert::from_der(&der) else { continue };
                    let kind = classify(&cert);
                    if kind == Kind::Other {
                        continue;
                    }
                    if seen.insert((loc, cert.sha1())) {
                        out.push(Found { location: Place::Keychain(loc), cert, kind });
                    }
                }
            }
        }
        Ok(out)
    }

    /// Our CA goes in as trusted for SSL only; the copy goes in untrusted.
    fn install_grant(&self, grant: &Grant) -> Res<()> {
        let login = self.path(Location::Login)?;
        let dir = TempDir::new()?;
        let ca = dir.write("mc-trust-ca.der", &grant.ca_der)?;
        let copy = dir.write("mc-trust-copy.der", &grant.copy_der)?;
        println!("macOS попросит пароль, чтобы доверять CA mc-trust (только для SSL)…");
        run_interactive(
            SECURITY,
            &["add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-k", login, &ca],
        )
        .map_err(|e| format!("не удалось добавить CA mc-trust: {e}"))?;
        if let Err(e) = run_quiet(SECURITY, &["add-certificates", "-k", login, &copy]) {
            let _ = run_quiet(
                SECURITY,
                &["delete-certificate", "-t", "-Z", &sha1_upper(&grant.ca_der), login],
            );
            return Err(format!("не удалось добавить копию корня, CA откатан: {e}").into());
        }
        Ok(())
    }

    fn remove(&self, found: &Found) -> Res<()> {
        let Place::Keychain(loc) = found.location else {
            return Err("сертификат лежит не в связке ключей".into());
        };
        let keychain = self.path(loc)?;
        let sha = sha1_upper(&found.cert.der);
        match loc {
            Location::Login => {
                run_quiet(SECURITY, &["delete-certificate", "-t", "-Z", &sha, keychain])?;
            }
            Location::System => {
                let dir = TempDir::new()?;
                let file = dir.write("cert.der", &found.cert.der)?;
                println!("Удаление из связки System требует прав администратора (sudo).");
                // Admin-domain trust settings, if any; absence is not an error.
                let _ = run_interactive(SUDO, &[SECURITY, "remove-trusted-cert", "-d", &file]);
                run_interactive(SUDO, &[SECURITY, "delete-certificate", "-Z", &sha, keychain]).map_err(|e| {
                    format!(
                        "{e}. Если сертификат установлен профилем конфигурации, удалите профиль: \
                         Системные настройки → Основные → Управление устройствами"
                    )
                })?;
            }
        }
        Ok(())
    }

    fn verify(&self, host: &str, chain: &[Vec<u8>]) -> Res<bool> {
        let dir = TempDir::new()?;
        let mut args: Vec<String> = vec!["verify-cert".into()];
        for (i, der) in chain.iter().enumerate() {
            args.push("-c".into());
            args.push(dir.write(&format!("c{i}.der"), der)?);
        }
        args.extend(["-p", "ssl", "-s", host].map(String::from));
        let out = Command::new(SECURITY).args(&args).stdin(Stdio::null()).output()?;
        Ok(out.status.success())
    }
}

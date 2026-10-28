//! Fetches the certificate chain a server presents, without trusting it.
//!
//! The handshake is delegated to the system `openssl s_client` (LibreSSL on
//! macOS). Nothing here decides trust: the chain goes to the OS verifier.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::util::Res;

const TIMEOUT: Duration = Duration::from_secs(20);
/// Absolute path, so PATH cannot swap in another openssl.
const OPENSSL: &str = "/usr/bin/openssl";
/// `s_client` prints this line right after the certificates and then waits for the
/// server to close the connection, which some servers take their time over.
const CHAIN_DONE: &[u8] = b"SSL handshake has read";

/// `https://host:port/path` | `host:port` | `host` -> (host, port)
pub fn parse_target(input: &str) -> Res<(String, u16)> {
    let s = input.trim();
    let s = s.strip_prefix("https://").unwrap_or(s);
    let s = s.split(['/', '?', '#']).next().unwrap_or(s);
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h, p.parse::<u16>().map_err(|_| format!("некорректный порт в «{input}»"))?),
        _ => (s, 443),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.') {
        return Err(format!("некорректный хост «{input}»").into());
    }
    Ok((host, port))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

pub fn fetch_chain(host: &str, port: u16) -> Res<Vec<Vec<u8>>> {
    let mut child = Command::new(OPENSSL)
        .args(["s_client", "-connect", &format!("{host}:{port}"), "-servername", host, "-showcerts"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("не удалось запустить openssl: {e}"))?;
    let mut stdout = child.stdout.take().ok_or("нет stdout у openssl")?;
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });

    let started = Instant::now();
    let mut output = Vec::new();
    while started.elapsed() < TIMEOUT && !contains(&output, CHAIN_DONE) {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(chunk) => output.extend(chunk),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();

    // Newer OpenSSL prints the leaf a second time under "Server certificate".
    let mut chain: Vec<Vec<u8>> = Vec::new();
    for der in mc_trust_core::pem::decode_all(&String::from_utf8_lossy(&output), "CERTIFICATE")? {
        if !chain.contains(&der) {
            chain.push(der);
        }
    }
    if chain.is_empty() {
        return Err(if started.elapsed() >= TIMEOUT {
            format!("{host}: нет ответа за {} с", TIMEOUT.as_secs())
        } else {
            format!("{host}: не удалось получить цепочку сертификатов")
        }
        .into());
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        assert_eq!(parse_target("https://Online.Sberbank.ru/path?x").unwrap(), ("online.sberbank.ru".into(), 443));
        assert_eq!(parse_target("example.com:8443").unwrap(), ("example.com".into(), 8443));
        assert!(parse_target("bad host").is_err());
    }

    #[test]
    fn finds_the_end_of_the_chain() {
        assert!(contains(b"---\nSSL handshake has read 3100 bytes\n", CHAIN_DONE));
        assert!(!contains(b"---\nCertificate chain\n", CHAIN_DONE));
        assert!(!contains(b"", CHAIN_DONE));
    }
}

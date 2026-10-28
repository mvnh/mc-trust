//! End-to-end: does a grant actually constrain the chain?
//!
//! Uses the `openssl` binary as an independent verifier. Skipped when
//! `openssl` is not on PATH.

use std::path::{Path, PathBuf};
use std::process::Command;

use mc_trust_core::{build_grant, normalize_domain, time, MintsifryRoot, PinPolicy};

fn have_openssl() -> bool {
    Command::new("openssl").arg("version").output().map(|o| o.status.success()).unwrap_or(false)
}

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Dir {
        let d = std::env::temp_dir().join(format!("mc-trust-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Dir(d)
    }
    fn p(&self, f: &str) -> String {
        self.0.join(f).to_str().unwrap().to_string()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) {
    let out = Command::new("openssl").args(args).output().unwrap();
    assert!(out.status.success(), "openssl {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

fn verify(ca: &str, untrusted: &str, leaf: &str) -> (bool, String) {
    let out = Command::new("openssl")
        .args(["verify", "-CAfile", ca, "-untrusted", untrusted, leaf])
        .output()
        .unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

fn write_grant(d: &Dir, root: &MintsifryRoot, domains: &[&str]) {
    let domains: Vec<String> = domains.iter().map(|s| normalize_domain(s).unwrap()).collect();
    let g = build_grant(root, &domains, time::now_unix().unwrap()).unwrap();
    std::fs::write(d.p("ca.pem"), g.ca_pem()).unwrap();
    std::fs::write(d.p("copy.pem"), g.copy_pem()).unwrap();
}

const SUBJ: &str = "/C=RU/O=The Ministry of Digital Development and Communications/CN=Russian Trusted Root CA";

/// A throwaway Mintsifry look-alike: root -> sub -> leaves.
fn fake_chain(d: &Dir, leaves: &[&str]) {
    std::fs::write(
        d.p("ca.cnf"),
        "[ca]\nbasicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n",
    )
    .unwrap();
    run(&[
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "365", "-subj", SUBJ,
        "-keyout", &d.p("root.key"), "-out", &d.p("root.pem"),
        "-addext", "basicConstraints=critical,CA:true", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    ]);
    run(&["req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=Fake Sub CA", "-keyout", &d.p("sub.key"), "-out", &d.p("sub.csr")]);
    run(&[
        "x509", "-req", "-in", &d.p("sub.csr"), "-CA", &d.p("root.pem"), "-CAkey", &d.p("root.key"),
        "-set_serial", "2", "-days", "300", "-extfile", &d.p("ca.cnf"), "-extensions", "ca", "-out", &d.p("sub.pem"),
    ]);
    for (i, host) in leaves.iter().enumerate() {
        std::fs::write(d.p("leaf.cnf"), format!("[l]\nsubjectAltName=DNS:{host}\nextendedKeyUsage=serverAuth\n")).unwrap();
        let key = d.p(&format!("{host}.key"));
        let csr = d.p(&format!("{host}.csr"));
        run(&["req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", &format!("/CN={host}"), "-keyout", &key, "-out", &csr]);
        run(&[
            "x509", "-req", "-in", &csr, "-CA", &d.p("sub.pem"), "-CAkey", &d.p("sub.key"),
            "-set_serial", &(10 + i).to_string(), "-days", "200", "-extfile", &d.p("leaf.cnf"), "-extensions", "l",
            "-out", &d.p(&format!("{host}.pem")),
        ]);
    }
}

fn concat(d: &Dir, out: &str, files: &[&str]) {
    let mut s = String::new();
    for f in files {
        s.push_str(&std::fs::read_to_string(d.p(f)).unwrap());
    }
    std::fs::write(d.p(out), s).unwrap();
}

#[test]
fn grant_limits_fake_mintsifry_chain() {
    if !have_openssl() {
        eprintln!("skipped: no openssl");
        return;
    }
    let d = Dir::new("fake");
    fake_chain(&d, &["online.bank.ru", "google.com", "bank.com"]);
    let root = MintsifryRoot::from_bytes(&std::fs::read(d.p("root.pem")).unwrap(), PinPolicy::AllowUnpinned).unwrap();
    assert!(!root.is_pinned());

    // Sanity: with the original root trusted, every leaf passes.
    concat(&d, "plain.pem", &["sub.pem"]);
    for host in ["online.bank.ru", "google.com", "bank.com"] {
        assert!(verify(&d.p("root.pem"), &d.p("plain.pem"), &d.p(&format!("{host}.pem"))).0, "{host} with original root");
    }

    // With the grant instead of the root: only allowed names pass.
    write_grant(&d, &root, &[".ru", "bank.com"]);
    concat(&d, "inter.pem", &["copy.pem", "sub.pem"]);
    let (ok, text) = verify(&d.p("ca.pem"), &d.p("inter.pem"), &d.p("online.bank.ru.pem"));
    assert!(ok, "online.bank.ru must pass: {text}");
    let (ok, text) = verify(&d.p("ca.pem"), &d.p("inter.pem"), &d.p("bank.com.pem"));
    assert!(ok, "bank.com exception must pass: {text}");
    let (ok, text) = verify(&d.p("ca.pem"), &d.p("inter.pem"), &d.p("google.com.pem"));
    assert!(!ok, "google.com must be rejected");
    assert!(text.contains("subtree"), "rejected for the wrong reason: {text}");
}

/// `ip.pem`: signed by the fake sub CA, its only name is an IP address. A dNSName-only
/// constraint would let it through.
fn ip_leaf(d: &Dir) {
    std::fs::write(d.p("ip.cnf"), "[l]\nsubjectAltName=IP:8.8.8.8\nextendedKeyUsage=serverAuth\n").unwrap();
    run(&["req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=ip", "-keyout", &d.p("ip.key"), "-out", &d.p("ip.csr")]);
    run(&[
        "x509", "-req", "-in", &d.p("ip.csr"), "-CA", &d.p("sub.pem"), "-CAkey", &d.p("sub.key"),
        "-set_serial", "50", "-days", "100", "-extfile", &d.p("ip.cnf"), "-extensions", "l", "-out", &d.p("ip.pem"),
    ]);
}

/// Linux has no store for untrusted intermediates: our CA and the copy of the root both
/// sit in the trust store as anchors, and the server sends only the leaf and its sub CA.
#[test]
fn grant_works_when_ca_and_copy_share_the_trust_store() {
    if !have_openssl() {
        eprintln!("skipped: no openssl");
        return;
    }
    let d = Dir::new("shared");
    fake_chain(&d, &["online.bank.ru", "google.com"]);
    ip_leaf(&d);
    let root = MintsifryRoot::from_bytes(&std::fs::read(d.p("root.pem")).unwrap(), PinPolicy::AllowUnpinned).unwrap();
    write_grant(&d, &root, &[".ru"]);
    concat(&d, "store.pem", &["ca.pem", "copy.pem"]);

    let (ok, text) = verify(&d.p("store.pem"), &d.p("sub.pem"), &d.p("online.bank.ru.pem"));
    assert!(ok, "online.bank.ru must pass: {text}");
    for leaf in ["google.com.pem", "ip.pem"] {
        let (ok, text) = verify(&d.p("store.pem"), &d.p("sub.pem"), &d.p(leaf));
        assert!(!ok, "{leaf} must be rejected");
        assert!(text.contains("subtree"), "{leaf} rejected for the wrong reason: {text}");
    }
}

#[test]
fn grant_rejects_a_leaf_with_only_an_ip_address() {
    if !have_openssl() {
        eprintln!("skipped: no openssl");
        return;
    }
    let d = Dir::new("ip");
    fake_chain(&d, &["online.bank.ru"]);
    let root = MintsifryRoot::from_bytes(&std::fs::read(d.p("root.pem")).unwrap(), PinPolicy::AllowUnpinned).unwrap();

    ip_leaf(&d);

    write_grant(&d, &root, &[".ru"]);
    concat(&d, "inter.pem", &["copy.pem", "sub.pem"]);
    let (ok, text) = verify(&d.p("ca.pem"), &d.p("inter.pem"), &d.p("ip.pem"));
    assert!(!ok, "a leaf with only an IP address must be rejected: {text}");
    assert!(text.contains("subtree"), "rejected for the wrong reason: {text}");
    let (ok, text) = verify(&d.p("ca.pem"), &d.p("inter.pem"), &d.p("online.bank.ru.pem"));
    assert!(ok, "online.bank.ru must still pass: {text}");
}

#[test]
fn real_sub_ca_chains_through_copy() {
    if !have_openssl() {
        eprintln!("skipped: no openssl");
        return;
    }
    let d = Dir::new("real");
    let root = MintsifryRoot::embedded().unwrap();
    write_grant(&d, &root, &[".ru", ".su", ".xn--p1ai"]);
    let sub = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/russian_trusted_sub_ca.pem");
    let (ok, text) = verify(&d.p("ca.pem"), &d.p("copy.pem"), sub.to_str().unwrap());
    assert!(ok, "real Russian Trusted Sub CA must chain to our CA via the copy: {text}");

    // And the Sub CA is signed by the pinned key according to our own code too.
    let sub_der = mc_trust_core::pem::certificate_der(&std::fs::read(&sub).unwrap()).unwrap();
    let sub_cert = mc_trust_core::Cert::from_der(&sub_der).unwrap();
    assert_eq!(root.signed(&sub_cert), Some(true));
}

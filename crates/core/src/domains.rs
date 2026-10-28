//! Domain names as they go into nameConstraints.

use crate::Error;

/// `.ru`, `.su`, `.рф` (punycode). A leading dot means "any subdomain".
pub const DEFAULT_ZONES: &[&str] = &[".ru", ".su", ".xn--p1ai"];

/// Lower-cases, trims and validates a domain or zone.
///
/// `example.com` permits the domain and all its subdomains (RFC 5280);
/// `.example.com` permits subdomains only. Wildcards, IP addresses and
/// non-ASCII names are rejected (pass `.рф` as `.xn--p1ai`).
pub fn normalize_domain(input: &str) -> Result<String, Error> {
    let s = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() {
        return Err(Error::Domain("пустой домен".into()));
    }
    if !s.is_ascii() {
        return Err(Error::Domain(format!(
            "«{input}»: нужен punycode (например, .рф → .xn--p1ai)"
        )));
    }
    let (dot, body) = match s.strip_prefix('.') {
        Some(b) => (true, b),
        None => (false, s.as_str()),
    };
    if body.is_empty() || body.len() > 253 {
        return Err(Error::Domain(format!("«{input}»: некорректная длина")));
    }
    let labels: Vec<&str> = body.split('.').collect();
    for label in &labels {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !ok {
            return Err(Error::Domain(format!("«{input}»: недопустимая метка «{label}»")));
        }
    }
    if labels.iter().all(|l| l.bytes().all(|b| b.is_ascii_digit())) {
        return Err(Error::Domain(format!("«{input}»: IP-адреса не поддерживаются")));
    }
    Ok(if dot { format!(".{body}") } else { body.to_string() })
}

/// Whether `host` falls under at least one permitted subtree.
pub fn host_allowed(host: &str, permitted: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    permitted.iter().any(|c| {
        if c.starts_with('.') {
            host.ends_with(c.as_str())
        } else {
            host == *c || host.ends_with(&format!(".{c}"))
        }
    })
}

/// Whether `host` matches a certificate name, which may start with a `*.` label.
pub fn dns_name_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(rest) => host.split_once('.').is_some_and(|(label, tail)| !label.is_empty() && tail == rest),
        None => pattern == host,
    }
}

/// A single-label zone such as `com`: trusting it covers a whole top-level domain.
pub fn is_tld(zone: &str) -> bool {
    !zone.trim_start_matches('.').contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_names() {
        assert!(dns_name_matches("online.sberbank.ru", "Online.Sberbank.ru."));
        assert!(dns_name_matches("*.sberbank.ru", "online.sberbank.ru"));
        assert!(!dns_name_matches("*.sberbank.ru", "sberbank.ru"));
        assert!(!dns_name_matches("*.sberbank.ru", "a.b.sberbank.ru"));
        assert!(!dns_name_matches("sberbank.com", "online.sberbank.com"));
    }

    #[test]
    fn top_level_zones() {
        assert!(is_tld("com") && is_tld(".ru") && is_tld("xn--p1ai"));
        assert!(!is_tld("sberbank.com") && !is_tld(".example.com"));
    }

    #[test]
    fn normalizes() {
        assert_eq!(normalize_domain(" Sberbank.COM. ").unwrap(), "sberbank.com");
        assert_eq!(normalize_domain(".RU").unwrap(), ".ru");
        assert!(normalize_domain("*.ru").is_err());
        assert!(normalize_domain(".рф").is_err());
        assert!(normalize_domain("10.0.0.1").is_err());
        assert!(normalize_domain("-bad.ru").is_err());
        assert!(normalize_domain(".").is_err());
    }

    #[test]
    fn matching() {
        let p: Vec<String> = [".ru", "sberbank.com"].iter().map(|s| s.to_string()).collect();
        assert!(host_allowed("online.sberbank.ru", &p));
        assert!(host_allowed("sberbank.com", &p));
        assert!(host_allowed("www.sberbank.com", &p));
        assert!(!host_allowed("notsberbank.com", &p));
        assert!(!host_allowed("google.com", &p));
        assert!(!host_allowed("ru", &p));
    }
}

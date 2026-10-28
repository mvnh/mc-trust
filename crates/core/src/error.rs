use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Malformed DER.
    Der(&'static str),
    /// Structurally valid DER that is not the certificate we expected.
    Cert(String),
    /// The root's public key does not match the pinned fingerprint.
    PinMismatch { got: String },
    /// The certificate is not a Mintsifry root.
    NotMintsifry(String),
    /// A domain the user passed cannot be used in nameConstraints.
    Domain(String),
    /// Key generation, signing or verification failed.
    Crypto(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Der(what) => write!(f, "некорректный DER: {what}"),
            Error::Cert(msg) => write!(f, "сертификат: {msg}"),
            Error::PinMismatch { got } => write!(
                f,
                "ключ корня не совпадает с зашитым отпечатком (получен SPKI SHA-256 {got})"
            ),
            Error::NotMintsifry(msg) => write!(f, "это не корень Минцифры: {msg}"),
            Error::Domain(msg) => write!(f, "домен: {msg}"),
            Error::Crypto(msg) => write!(f, "криптография: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

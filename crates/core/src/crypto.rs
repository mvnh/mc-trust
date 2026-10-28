//! The only place that touches private keys.

use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, EcdsaKeyPair, KeyPair, UnparsedPublicKey};

use crate::x509::oids;
use crate::Error;

/// A fresh ECDSA P-256 key that signs with SHA-256 and returns DER signatures.
/// It lives as long as the value and is never written out.
pub struct Signer {
    key: EcdsaKeyPair,
    rng: SystemRandom,
}

impl Signer {
    pub fn generate() -> Result<Self, Error> {
        let rng = SystemRandom::new();
        let alg = &signature::ECDSA_P256_SHA256_ASN1_SIGNING;
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng)
            .map_err(|_| Error::Crypto("не удалось сгенерировать ключ".into()))?;
        let key = EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng)
            .map_err(|_| Error::Crypto("не удалось загрузить ключ".into()))?;
        // `pkcs8` is dropped here; the key now lives only inside `key`.
        Ok(Self { key, rng })
    }

    /// Uncompressed EC point (65 bytes, starting with 0x04).
    pub fn public_point(&self) -> Vec<u8> {
        self.key.public_key().as_ref().to_vec()
    }

    /// ASN.1 DER `ECDSA-Sig-Value` over SHA-256(`msg`).
    pub fn sign_sha256(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        self.key
            .sign(&self.rng, msg)
            .map(|s| s.as_ref().to_vec())
            .map_err(|_| Error::Crypto("не удалось подписать".into()))
    }
}

pub fn random_bytes(n: usize) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; n];
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| Error::Crypto("нет источника случайных чисел".into()))?;
    Ok(buf)
}

/// Verifies `sig` over `tbs` with the given subject public key.
pub fn verify(
    key_alg: &[u64],
    key_param: Option<&[u64]>,
    key: &[u8],
    sig_alg: &[u64],
    tbs: &[u8],
    sig: &[u8],
) -> Result<(), Error> {
    let alg: &'static dyn signature::VerificationAlgorithm = match (key_alg, key_param, sig_alg) {
        (k, _, s) if k == oids::RSA_ENCRYPTION && s == oids::SHA256_WITH_RSA => &signature::RSA_PKCS1_2048_8192_SHA256,
        (k, _, s) if k == oids::RSA_ENCRYPTION && s == oids::SHA384_WITH_RSA => &signature::RSA_PKCS1_2048_8192_SHA384,
        (k, _, s) if k == oids::RSA_ENCRYPTION && s == oids::SHA512_WITH_RSA => &signature::RSA_PKCS1_2048_8192_SHA512,
        (k, Some(c), s) if k == oids::EC_PUBLIC_KEY && c == oids::PRIME256V1 && s == oids::ECDSA_WITH_SHA256 => {
            &signature::ECDSA_P256_SHA256_ASN1
        }
        (k, Some(c), s) if k == oids::EC_PUBLIC_KEY && c == oids::SECP384R1 && s == oids::ECDSA_WITH_SHA384 => {
            &signature::ECDSA_P384_SHA384_ASN1
        }
        _ => return Err(Error::Crypto("неподдерживаемый алгоритм подписи".into())),
    };
    UnparsedPublicKey::new(alg, key)
        .verify(tbs, sig)
        .map_err(|_| Error::Crypto("подпись не сходится".into()))
}

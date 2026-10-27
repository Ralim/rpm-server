//! OpenPGP signing of packages (RPM header signatures) and of `repomd.xml`
//! (detached ASCII-armored signature).

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use pgp::composed::{
    ArmorOptions, Deserializable, DetachedSignature, EncryptionCaps, KeyType,
    SecretKeyParamsBuilder, SignedSecretKey, SignedSecretSubKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::types::{KeyDetails, Password, SigningKey};
use rpm::signature::pgp::Signer;
use rpm::{Package, PackageMetadata};

/// A loaded secret key, usable for both package and repository signatures.
pub struct RepoSigner {
    key: SignedSecretKey,
    passphrase: Option<String>,
    rpm_signer: Signer,
    public_key: String,
    sign_packages: bool,
}

impl std::fmt::Debug for RepoSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepoSigner")
            .field("fingerprint", &self.fingerprint())
            .field("sign_packages", &self.sign_packages)
            .finish_non_exhaustive()
    }
}

impl RepoSigner {
    /// Loads an ASCII-armored OpenPGP secret key.
    ///
    /// A test signature is made immediately so a wrong or missing passphrase
    /// fails at startup rather than on the first scan.
    pub fn from_armored(
        asc: &str,
        passphrase: Option<String>,
        sign_packages: bool,
    ) -> Result<Self> {
        let (key, _headers) =
            SignedSecretKey::from_string(asc).context("parsing armored secret key")?;
        key.verify_bindings()
            .context("verifying secret key bindings")?;
        let public_key = key
            .to_public_key()
            .to_armored_string(ArmorOptions::default())
            .context("exporting public key")?;

        let mut rpm_signer =
            Signer::from_asc_bytes(asc.as_bytes()).context("loading key for package signing")?;
        if let Some(p) = &passphrase {
            rpm_signer = rpm_signer.with_key_passphrase(p.as_str());
        }

        let signer = Self {
            key,
            passphrase,
            rpm_signer,
            public_key,
            sign_packages,
        };
        signer
            .sign_detached(b"rpm-server key self-test")
            .context("test signature failed (wrong passphrase?)")?;
        Ok(signer)
    }

    /// Armored public key, served as `/RPM-GPG-KEY`.
    pub fn public_key_armored(&self) -> &str {
        &self.public_key
    }

    /// Whether packages are re-signed (otherwise only `repomd.xml` is signed).
    pub fn signs_packages(&self) -> bool {
        self.sign_packages
    }

    pub fn fingerprint(&self) -> String {
        hex::encode_upper(self.key.fingerprint().as_bytes())
    }

    /// The key the rpm `Signer` also uses: the first signing-capable subkey,
    /// or `None` for the primary key.
    fn signing_subkey(&self) -> Option<&SignedSecretSubKey> {
        self.key
            .secret_subkeys
            .iter()
            .find(|sk| sk.signatures.iter().any(|sig| sig.key_flags().sign()))
    }

    fn signing_key_created_at(&self) -> u32 {
        match self.signing_subkey() {
            Some(sk) => sk.key.created_at().as_secs(),
            None => self.key.primary_key.created_at().as_secs(),
        }
    }

    /// Creates an ASCII-armored detached signature over `data`.
    pub fn sign_detached(&self, data: &[u8]) -> Result<String> {
        fn sign(
            key: &impl SigningKey,
            password: &Password,
            data: &[u8],
        ) -> pgp::errors::Result<DetachedSignature> {
            DetachedSignature::sign_binary_data(
                rand::thread_rng(),
                key,
                password,
                HashAlgorithm::Sha256,
                data,
            )
        }
        let password = self
            .passphrase
            .as_deref()
            .map(Password::from)
            .unwrap_or_else(Password::empty);
        let sig = match self.signing_subkey() {
            Some(sk) => sign(&sk.key, &password, data),
            None => sign(&self.key.primary_key, &password, data),
        }
        .context("creating detached signature")?;
        Ok(sig.to_armored_string(ArmorOptions::default())?)
    }

    /// Replaces all signatures in `metadata` with one from this key.
    ///
    /// Only the lead and headers are touched: the RPM header signature covers
    /// the main header alone, so the payload can be copied verbatim from the
    /// original file after the returned metadata is written.
    pub fn resign_metadata(&self, metadata: PackageMetadata) -> Result<PackageMetadata> {
        let mut pkg = Package {
            metadata,
            payload: Vec::new(),
        };
        pkg.clear_signatures()?;
        // rpm-sequoia rejects signatures that predate the signing key.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX))
            .unwrap_or(0);
        let ts = now.max(self.signing_key_created_at());
        pkg.sign_with_timestamp(&self.rpm_signer, ts)?;
        Ok(pkg.metadata)
    }
}

/// Generates a new Ed25519 signing key and returns it ASCII-armored.
///
/// Ed25519 is accepted by rpm >= 4.16 (EL9, AL2023, current Fedora). Use an
/// RSA key from `gpg` if EL7/AL2 clients must verify signatures.
pub fn generate_secret_key(user_id: &str, passphrase: Option<&str>) -> Result<String> {
    let mut params = SecretKeyParamsBuilder::default();
    params
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .can_encrypt(EncryptionCaps::None)
        .primary_user_id(user_id.into())
        .passphrase(passphrase.map(str::to_owned));
    let key = params
        .build()
        .context("building key parameters")?
        .generate(rand::thread_rng())
        .context("generating key")?;
    Ok(key.to_armored_string(ArmorOptions::default())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;
    use pgp::composed::SignedPublicKey;
    use rpm::signature::pgp::Verifier;
    use std::io::Cursor;

    fn verify_detached(public: &str, sig: &str, data: &[u8]) -> bool {
        let (public, _) = SignedPublicKey::from_string(public).unwrap();
        let (sig, _) = DetachedSignature::from_string(sig).unwrap();
        sig.verify(&public, data).is_ok()
            || public
                .public_subkeys
                .iter()
                .any(|sub| sig.verify(sub, data).is_ok())
    }

    #[test]
    fn detached_signature_verifies() {
        let signer = testutil::signer();
        let sig = signer.sign_detached(b"hello").unwrap();
        assert!(sig.starts_with("-----BEGIN PGP SIGNATURE-----"));
        assert!(verify_detached(signer.public_key_armored(), &sig, b"hello"));
        assert!(!verify_detached(
            signer.public_key_armored(),
            &sig,
            b"tampered"
        ));
    }

    #[test]
    fn passphrase_protected_key() {
        let asc = generate_secret_key("Test <t@example.com>", Some("hunter2")).unwrap();
        assert!(RepoSigner::from_armored(&asc, Some("wrong".into()), true).is_err());
        assert!(RepoSigner::from_armored(&asc, None, true).is_err());
        let signer = RepoSigner::from_armored(&asc, Some("hunter2".into()), true).unwrap();
        signer.sign_detached(b"x").unwrap();
    }

    #[test]
    fn resigned_package_verifies() {
        let signer = testutil::signer();
        let original = testutil::build_rpm("demo", "1.0", &[]);
        let offsets_before = PackageMetadata::parse(&mut Cursor::new(&original))
            .unwrap()
            .get_package_segment_offsets();

        let metadata = PackageMetadata::parse(&mut Cursor::new(&original)).unwrap();
        let metadata = signer.resign_metadata(metadata).unwrap();
        let mut signed = Vec::new();
        metadata.write(&mut signed).unwrap();
        signed.extend_from_slice(&original[offsets_before.payload as usize..]);

        let pkg = Package::parse(&mut Cursor::new(&signed)).unwrap();
        pkg.verify_signature(
            Verifier::from_asc_bytes(signer.public_key_armored().as_bytes()).unwrap(),
        )
        .unwrap();
        pkg.verify_digests().unwrap();
        assert_eq!(pkg.metadata.get_name().unwrap(), "demo");
    }
}

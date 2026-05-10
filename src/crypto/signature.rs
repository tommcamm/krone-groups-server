use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use subtle::ConstantTimeEq;

/// Server-side signing key, kept behind an Arc-friendly wrapper.
#[derive(Clone)]
pub struct ServerSigner {
    inner: std::sync::Arc<SigningKey>,
}

impl ServerSigner {
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.inner.verifying_key().to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.inner.sign(msg).to_bytes()
    }
}

/// Load the server keypair from `data_dir/server-key` if present. Otherwise derive one from
/// `KRONE_SERVER_SEED` (32-byte hex) or generate a fresh random seed, persist, and return it.
pub fn load_or_generate_keypair(data_dir: &Path, seed_hex: Option<&str>) -> Result<ServerSigner> {
    let key_path = data_dir.join("server-key");

    // Prefer on-disk key when it exists — it is the server identity.
    if key_path.exists() {
        if seed_hex.is_some() {
            tracing::warn!(
                key_path = %key_path.display(),
                "KRONE_SERVER_SEED is set but a persisted server-key already exists — \
                 the on-disk key wins. Delete the key file (and lose user TOFU pinning) \
                 if you actually want to rotate to the env-supplied seed."
            );
        }
        let mut seed = [0u8; 32];
        let raw = std::fs::read(&key_path)
            .with_context(|| format!("read server key at {}", key_path.display()))?;
        if raw.len() != 32 {
            return Err(anyhow!(
                "server key file {} has {} bytes, expected 32",
                key_path.display(),
                raw.len()
            ));
        }
        seed.copy_from_slice(&raw);
        return Ok(ServerSigner {
            inner: std::sync::Arc::new(SigningKey::from_bytes(&seed)),
        });
    }

    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("create data dir {}", data_dir.display()))?;

    let seed = match seed_hex {
        Some(hex_str) => {
            let v = hex::decode(hex_str).context("decode KRONE_SERVER_SEED hex")?;
            if v.len() != 32 {
                return Err(anyhow!(
                    "KRONE_SERVER_SEED must decode to 32 bytes, got {}",
                    v.len()
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v);
            arr
        }
        None => {
            let mut arr = [0u8; 32];
            getrandom::getrandom(&mut arr).map_err(|e| anyhow!("getrandom server seed: {e}"))?;
            arr
        }
    };

    atomic_write(&key_path, &seed)
        .with_context(|| format!("persist server key at {}", key_path.display()))?;
    restrict_permissions(&key_path)
        .with_context(|| format!("restrict server key permissions at {}", key_path.display()))?;

    Ok(ServerSigner {
        inner: std::sync::Arc::new(SigningKey::from_bytes(&seed)),
    })
}

fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    match write_private_file(&tmp, bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(&tmp)?;
            write_private_file(&tmp, bytes)?;
        }
        Err(e) => return Err(e),
    }

    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Verify an Ed25519 signature. Returns `Ok(())` on success, `Err` otherwise.
pub fn verify_ed25519(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    let pk = VerifyingKey::from_bytes(public_key).context("invalid Ed25519 pubkey")?;
    let sig = Signature::from_bytes(signature);
    pk.verify(message, &sig)
        .map_err(|e| anyhow!("bad signature: {e}"))
}

/// Constant-time byte equality (export for callers who don't want to depend on `subtle`).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

// Unused helper for type-level tidiness.
#[allow(dead_code)]
pub fn _path_owned(p: &Path) -> PathBuf {
    p.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[cfg(unix)]
    #[test]
    fn generated_server_key_is_private_on_disk() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let _signer = load_or_generate_keypair(tmp.path(), Some(TEST_SEED_HEX)).expect("keypair");

        let mode = std::fs::metadata(tmp.path().join("server-key"))
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

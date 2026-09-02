//! Portable, encrypted trust-vault recovery.

use std::{fs, io::Write as _, path::PathBuf};

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Subcommand;
use cyrene::{OsKeyStore, RecoveryBundle, RecoverySecret, TrustStore, WrappingKey};

use crate::{VaultArgs, open_vault, persist_wrapping_key, read_wrapping_key};

#[derive(Subcommand)]
pub(crate) enum RecoveryCommand {
    /// Export an authenticated, encrypted snapshot of identity and trust.
    Export {
        #[command(flatten)]
        vault: VaultArgs,
        /// New recovery artifact path; existing files are never replaced.
        #[arg(long)]
        output: PathBuf,
    },
    /// Restore a snapshot into a new vault and re-wrap it for this host.
    Restore {
        #[command(flatten)]
        vault: VaultArgs,
        /// Recovery artifact created by `cyrene recovery export`.
        bundle: PathBuf,
        /// URL-safe recovery secret printed during export.
        #[arg(long)]
        secret: String,
    },
}

pub(crate) fn recovery(command: RecoveryCommand) -> Result<()> {
    match command {
        RecoveryCommand::Export { vault, output } => export(&vault, &output),
        RecoveryCommand::Restore {
            vault,
            bundle,
            secret,
        } => restore(&vault, &bundle, &secret),
    }
}

fn export(arguments: &VaultArgs, output: &PathBuf) -> Result<()> {
    let store = open_vault(arguments)?;
    let secret = RecoverySecret::generate()?;
    let artifact = store.export_recovery(&secret)?;
    write_new(output, &artifact.to_bytes())?;
    println!("Recovery bundle written to {}.", output.display());
    println!(
        "Recovery secret: {}",
        URL_SAFE_NO_PAD.encode(secret.secret_bytes())
    );
    println!("Keep the bundle and secret separately. Either one alone is useless.");
    Ok(())
}

fn restore(arguments: &VaultArgs, bundle_path: &PathBuf, encoded_secret: &str) -> Result<()> {
    let bytes = fs::read(bundle_path)
        .with_context(|| format!("could not read {}", bundle_path.display()))?;
    let bundle = RecoveryBundle::from_bytes(&bytes)?;
    let secret = decode_secret(encoded_secret)?;
    bundle.verify(&secret)?;
    let wrapping_key = host_key(arguments)?;
    TrustStore::restore_recovery(&arguments.vault, &bundle, &secret, &wrapping_key)?;
    println!("Trust vault restored to {}.", arguments.vault.display());
    println!(
        "This restores the original device identity. If another copy may exist, remove that device from your user and shared spaces."
    );
    Ok(())
}

fn host_key(arguments: &VaultArgs) -> Result<WrappingKey> {
    if let Some(path) = &arguments.key_file {
        if path.exists() {
            return Ok(WrappingKey::from_bytes(read_wrapping_key(path)?));
        }
        let key = WrappingKey::generate()?;
        persist_wrapping_key(path, key.secret_bytes())?;
        return Ok(key);
    }

    let key_store = OsKeyStore::open(&arguments.keyring_id)?;
    match key_store.load() {
        Ok(key) => Ok(key),
        Err(cyrene::TrustError::MissingWrappingKey(_)) => {
            let key = WrappingKey::generate()?;
            key_store.store_new(&key)?;
            Ok(key)
        }
        Err(error) => Err(error.into()),
    }
}

fn decode_secret(encoded: &str) -> Result<RecoverySecret> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("recovery secret is not valid URL-safe base64")?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow!(
            "recovery secret must decode to 32 bytes, got {}",
            bytes.len()
        )
    })?;
    Ok(RecoverySecret::from_bytes(bytes))
}

fn write_new(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("could not create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_secret_encoding_is_exact_and_url_safe() {
        let secret = RecoverySecret::from_bytes([0xff; 32]);
        let encoded = URL_SAFE_NO_PAD.encode(secret.secret_bytes());
        assert_eq!(decode_secret(&encoded).unwrap().secret_bytes(), &[0xff; 32]);
        assert!(decode_secret("not a secret").is_err());
        assert!(decode_secret(&URL_SAFE_NO_PAD.encode([1; 31])).is_err());
    }
}

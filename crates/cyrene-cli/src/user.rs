use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Subcommand;
use cyrene::{DevicePublicKey, UserEvent, UserIdentity};
use serde::{Deserialize, Serialize};

use crate::{VaultArgs, open_vault, require_device};

const BUNDLE_VERSION: u8 = 1;
const BUNDLE_LIMIT: usize = 256 * 1024;

#[derive(Subcommand)]
pub(crate) enum UserCommand {
    /// Create a user identity rooted in this device.
    Init {
        #[command(flatten)]
        vault: VaultArgs,
    },
    /// Inspect the current verified linked-device membership.
    Status {
        #[command(flatten)]
        vault: VaultArgs,
        /// Emit stable machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Link a device public key and print the updated public identity bundle.
    Add {
        #[command(flatten)]
        vault: VaultArgs,
        /// Full 64-character Ed25519 public key from `cyrene device status --json`.
        device: String,
    },
    /// Remove a device and print the updated public identity bundle.
    Remove {
        #[command(flatten)]
        vault: VaultArgs,
        /// Full 64-character Ed25519 public key to remove going forward.
        device: String,
    },
    /// Verify and atomically import a public linked-user history bundle.
    Import {
        #[command(flatten)]
        vault: VaultArgs,
        /// URL-safe public bundle printed by `user add`, `remove`, or `export`.
        bundle: String,
    },
    /// Print the complete signed public identity bundle.
    Export {
        #[command(flatten)]
        vault: VaultArgs,
    },
}

#[derive(Deserialize, Serialize)]
struct UserBundle {
    version: u8,
    events: Vec<UserEvent>,
}

pub(crate) fn user(command: UserCommand) -> Result<()> {
    match command {
        UserCommand::Init { vault } => initialize(&vault),
        UserCommand::Status { vault, json } => status(&vault, json),
        UserCommand::Add { vault, device } => update(&vault, &device, false),
        UserCommand::Remove { vault, device } => update(&vault, &device, true),
        UserCommand::Import { vault, bundle } => import(&vault, &bundle),
        UserCommand::Export { vault } => export(&vault),
    }
}

fn initialize(arguments: &VaultArgs) -> Result<()> {
    let mut vault = open_vault(arguments)?;
    let identity = vault.initialize_user_identity()?;
    println!(
        "User identity ready.\n  user     {}\n  epoch    {}\n  devices  {}",
        identity.id(),
        identity.epoch(),
        identity.devices().count()
    );
    Ok(())
}

fn status(arguments: &VaultArgs, json: bool) -> Result<()> {
    let vault = open_vault(arguments)?;
    let identity = require_user(&vault)?;
    let devices = identity
        .devices()
        .map(|device| hex(&device.to_bytes()))
        .collect::<Vec<_>>();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "user": hex(identity.id().as_bytes()),
                "epoch": identity.epoch(),
                "devices": devices,
            }))?
        );
    } else {
        println!(
            "Cyrene user\n  id       {}\n  epoch    {}\n  devices  {}",
            identity.id(),
            identity.epoch(),
            devices.len()
        );
        for device in devices {
            println!("    {device}");
        }
    }
    Ok(())
}

fn update(arguments: &VaultArgs, encoded_device: &str, remove: bool) -> Result<()> {
    let mut vault = open_vault(arguments)?;
    let local = require_device(&vault)?;
    let identity = require_user(&vault)?;
    let device = parse_public_key(encoded_device)?;
    let event = if remove {
        identity.remove_device(&local.identity, device)?
    } else {
        identity.link_device(&local.identity, device)?
    };
    let updated = vault.apply_user_event(&event)?;
    println!(
        "User membership updated.\n  user     {}\n  epoch    {}\n  devices  {}\n\n{}",
        updated.id(),
        updated.epoch(),
        updated.devices().count(),
        encode_bundle(&updated)?,
    );
    Ok(())
}

fn import(arguments: &VaultArgs, encoded: &str) -> Result<()> {
    let bundle = decode_bundle(encoded)?;
    if bundle.version != BUNDLE_VERSION {
        bail!("unsupported user identity bundle version");
    }
    let identity = UserIdentity::from_events(bundle.events)?;
    let mut vault = open_vault(arguments)?;
    let imported = vault.import_user_identity(&identity)?;
    println!(
        "User identity imported.\n  user     {}\n  epoch    {}\n  devices  {}",
        imported.id(),
        imported.epoch(),
        imported.devices().count()
    );
    Ok(())
}

fn export(arguments: &VaultArgs) -> Result<()> {
    let vault = open_vault(arguments)?;
    println!("{}", encode_bundle(&require_user(&vault)?)?);
    Ok(())
}

fn require_user(vault: &cyrene::TrustStore) -> Result<UserIdentity> {
    vault.user_identity()?.ok_or_else(|| {
        anyhow!("the vault has no user identity; run `cyrene user init` or `user import`")
    })
}

fn encode_bundle(identity: &UserIdentity) -> Result<String> {
    let bytes = serde_json::to_vec(&UserBundle {
        version: BUNDLE_VERSION,
        events: identity.events().to_vec(),
    })?;
    if bytes.len() > BUNDLE_LIMIT {
        bail!("user identity history exceeds the bundle size limit");
    }
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_bundle(encoded: &str) -> Result<UserBundle> {
    if encoded.len() > BUNDLE_LIMIT * 2 {
        bail!("user identity bundle exceeds its size limit");
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("user identity bundle is not valid URL-safe base64")?;
    if bytes.len() > BUNDLE_LIMIT {
        bail!("user identity bundle exceeds its size limit");
    }
    serde_json::from_slice(&bytes).context("user identity bundle is malformed")
}

pub(crate) fn parse_public_key(encoded: &str) -> Result<DevicePublicKey> {
    if encoded.len() != 64 {
        bail!("device public key must contain exactly 64 hexadecimal characters");
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).context("device public key is not UTF-8")?;
        bytes[index] = u8::from_str_radix(pair, 16)
            .with_context(|| format!("invalid hexadecimal byte at position {}", index * 2))?;
    }
    DevicePublicKey::from_bytes(bytes).context("device public key is not a valid Ed25519 point")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to a string cannot fail");
            output
        },
    )
}

#[cfg(test)]
mod tests {
    use cyrene::DeviceIdentity;

    use super::*;

    #[test]
    fn public_bundle_round_trips_through_verification() {
        let device = DeviceIdentity::from_secret_bytes(&[110; 32]);
        let identity = UserIdentity::create(&device).unwrap();
        let decoded = decode_bundle(&encode_bundle(&identity).unwrap()).unwrap();
        assert_eq!(UserIdentity::from_events(decoded.events).unwrap(), identity);
    }

    #[test]
    fn public_key_parser_is_exact_and_validating() {
        let device = DeviceIdentity::from_secret_bytes(&[111; 32]);
        let encoded = hex(&device.public_key().to_bytes());
        assert_eq!(parse_public_key(&encoded).unwrap(), device.public_key());
        assert!(parse_public_key("00").is_err());
        assert!(parse_public_key(&"zz".repeat(32)).is_err());
    }
}

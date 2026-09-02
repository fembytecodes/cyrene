use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Subcommand, ValueEnum};
use cyrene::{
    App, Capability, CertificatePin, DevicePublicKey, InvitationSecret, PeerRecord, Permission,
    RelayClient, ShareInvitation, SpaceAccess, SpaceAuthority, TrustStore,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use crate::{VaultArgs, open_vault, require_device, unix_time};

const SHARE_VERSION: u8 = 1;
const SHARE_FRAME_LIMIT: usize = 64 * 1024;
const TOKEN_LIMIT: usize = 128 * 1024;
const TOKEN_DOMAIN: &[u8] = b"cyrene/share-token/1";
const CLAIM_DOMAIN: &[u8] = b"cyrene/share-claim/1";

#[derive(Subcommand)]
pub(crate) enum SpaceCommand {
    /// Establish this device as the initial owner of an application space.
    Init {
        #[command(flatten)]
        vault: VaultArgs,
        /// Application database whose space should become shareable.
        database: PathBuf,
    },
    /// Inspect current authority, epoch, and forward membership.
    Status {
        #[command(flatten)]
        vault: VaultArgs,
        /// Application database whose authority should be inspected.
        database: PathBuf,
        /// Emit stable machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Rotate the content key and revoke selected member devices going forward.
    Rotate {
        #[command(flatten)]
        vault: VaultArgs,
        /// Application database whose authority should advance.
        database: PathBuf,
        /// Full public key of a member to omit from the new epoch.
        #[arg(long = "remove")]
        removed: Vec<String>,
    },
    /// Publish the latest retained-member epoch transition to a relay.
    PublishEpoch {
        #[command(flatten)]
        vault: VaultArgs,
        /// Application database whose latest transition should be published.
        database: PathBuf,
        /// Cyrene relay address.
        #[arg(long)]
        relay: SocketAddr,
        /// Days the transition should remain available.
        #[arg(long, default_value_t = 7)]
        retention_days: u64,
    },
}

#[derive(Subcommand)]
pub(crate) enum InviteCommand {
    /// Create one secret invitation and wait for its recipient.
    Listen {
        #[command(flatten)]
        vault: VaultArgs,
        /// Existing application database to share.
        database: PathBuf,
        /// Authority granted to the recipient.
        #[arg(long, value_enum, default_value_t = PermissionArg::ReadWrite)]
        permission: PermissionArg,
        /// TCP address for the one-shot invitation listener.
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: SocketAddr,
        /// Invitation lifetime in seconds.
        #[arg(long, default_value_t = 600)]
        ttl: u64,
    },
    /// Accept a secret invitation into a new local application replica.
    Join {
        #[command(flatten)]
        vault: VaultArgs,
        /// Database path for the accepted space's local replica.
        database: PathBuf,
        /// Secret token printed by `cyrene invite listen`.
        token: String,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum PermissionArg {
    ReadOnly,
    ReadWrite,
}

impl From<PermissionArg> for Permission {
    fn from(value: PermissionArg) -> Self {
        match value {
            PermissionArg::ReadOnly => Self::ReadOnly,
            PermissionArg::ReadWrite => Self::ReadWrite,
        }
    }
}

#[derive(Deserialize, Serialize)]
struct ShareToken {
    version: u8,
    address: SocketAddr,
    invitation: ShareInvitation,
    secret: [u8; 32],
    owner_certificate: Vec<u8>,
    transport_signature: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct ShareClaim {
    version: u8,
    invitation_id: [u8; 16],
    public_key: DevicePublicKey,
    certificate_der: Vec<u8>,
    secret_proof: [u8; 32],
    signature: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct ShareGrant {
    version: u8,
    capability: Capability,
}

pub(crate) async fn space(command: SpaceCommand) -> Result<()> {
    match command {
        SpaceCommand::Init { vault, database } => initialize_space(&vault, &database).await,
        SpaceCommand::Status {
            vault,
            database,
            json,
        } => space_status(&vault, &database, json).await,
        SpaceCommand::Rotate {
            vault,
            database,
            removed,
        } => rotate_space(&vault, &database, &removed).await,
        SpaceCommand::PublishEpoch {
            vault,
            database,
            relay,
            retention_days,
        } => publish_epoch(&vault, &database, relay, retention_days).await,
    }
}

async fn publish_epoch(
    arguments: &VaultArgs,
    database: &PathBuf,
    relay: SocketAddr,
    retention_days: u64,
) -> Result<()> {
    if retention_days == 0 || retention_days > 30 {
        bail!("epoch-update retention must be between 1 and 30 days");
    }
    let app = App::open(database)
        .await
        .with_context(|| format!("could not open {}", database.display()))?;
    let vault = open_vault(arguments)?;
    let client = RelayClient::new(relay, Duration::from_secs(30));
    let retention = Duration::from_secs(retention_days * 24 * 60 * 60);
    let receipt = app
        .relay_publish_epoch_updates(&client, &vault, retention)
        .await?;
    println!(
        "Epoch transition published.\n  members  {}\n  stored   {}\n  relay    {}",
        receipt.offered, receipt.stored, relay
    );
    Ok(())
}

async fn rotate_space(arguments: &VaultArgs, database: &PathBuf, removed: &[String]) -> Result<()> {
    let app = App::open(database)
        .await
        .with_context(|| format!("could not open {}", database.display()))?;
    let mut vault = open_vault(arguments)?;
    let revoked = removed
        .iter()
        .map(|encoded| crate::user::parse_public_key(encoded))
        .collect::<Result<Vec<_>>>()?;
    let current = vault.space_members(app.space_id())?;
    for device in &revoked {
        if !current
            .iter()
            .any(|capability| capability.subject() == *device)
        {
            bail!(
                "device {} is not a current member of this space",
                device.id()
            );
        }
    }
    let credentials = vault.rotate_owned_space(app.space_id(), &revoked, unix_time()?)?;
    println!(
        "Space rotated.\n  space    {}\n  epoch    {}\n  revoked  {}\n  retained {}\n\nRetained members receive the key over direct shared sync. For relay-only members, run `cyrene space publish-epoch`.",
        app.space_id(),
        credentials.authority().epoch,
        revoked.len(),
        current.len().saturating_sub(revoked.len()),
    );
    Ok(())
}

pub(crate) async fn invite(command: InviteCommand) -> Result<()> {
    match command {
        InviteCommand::Listen {
            vault,
            database,
            permission,
            bind,
            ttl,
        } => invite_listen(&vault, &database, permission.into(), bind, ttl).await,
        InviteCommand::Join {
            vault,
            database,
            token,
        } => invite_join(&vault, &database, &token).await,
    }
}

async fn initialize_space(arguments: &VaultArgs, database: &PathBuf) -> Result<()> {
    let app = App::open(database)
        .await
        .with_context(|| format!("could not open {}", database.display()))?;
    let mut vault = open_vault(arguments)?;
    let credentials = vault.initialize_owned_space(app.space_id(), unix_time()?)?;
    println!(
        "Space ready to share.\n  space  {}\n  owner  {}\n  epoch  {}",
        app.space_id(),
        credentials.capability().subject().id(),
        credentials.authority().epoch,
    );
    Ok(())
}

async fn space_status(arguments: &VaultArgs, database: &PathBuf, json: bool) -> Result<()> {
    let app = App::open(database)
        .await
        .with_context(|| format!("could not open {}", database.display()))?;
    let vault = open_vault(arguments)?;
    let credentials = vault
        .space_credentials(app.space_id())?
        .ok_or_else(|| anyhow!("space authority is not initialized; run `cyrene space init`"))?;
    let members = vault.space_members(app.space_id())?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "space": app.space_id().to_string(),
                "epoch": credentials.authority().epoch,
                "issuer": hex(credentials.authority().issuer.to_bytes()),
                "local_permission": format!("{:?}", credentials.capability().permission()),
                "members": members.iter().map(|capability| serde_json::json!({
                    "device": hex(capability.subject().to_bytes()),
                    "permission": format!("{:?}", capability.permission()),
                })).collect::<Vec<_>>(),
            }))?
        );
    } else {
        println!(
            "Cyrene space\n  id       {}\n  epoch    {}\n  role     {:?}\n  members  {}",
            app.space_id(),
            credentials.authority().epoch,
            credentials.capability().permission(),
            members.len(),
        );
    }
    Ok(())
}

async fn invite_listen(
    arguments: &VaultArgs,
    database: &PathBuf,
    permission: Permission,
    bind: SocketAddr,
    ttl: u64,
) -> Result<()> {
    if ttl == 0 || ttl > 86_400 {
        bail!("invitation lifetime must be between 1 second and 24 hours");
    }
    if !database.exists() {
        bail!("{} does not exist", database.display());
    }
    let app = App::open(database).await?;
    let mut vault = open_vault(arguments)?;
    let device = require_device(&vault)?;
    let credentials = vault
        .space_credentials(app.space_id())?
        .ok_or_else(|| anyhow!("space authority is not initialized; run `cyrene space init`"))?;
    if credentials.authority().issuer != device.identity.public_key() {
        bail!("only this space's issuing device can create invitations");
    }
    let listener = TcpListener::bind(bind).await?;
    let address = listener.local_addr()?;
    let now = unix_time()?;
    let expires_at = now
        .checked_add(ttl)
        .ok_or_else(|| anyhow!("invitation expiry overflow"))?;
    let (invitation, secret) = ShareInvitation::issue(
        &device.identity,
        app.space_id(),
        credentials.authority().epoch,
        credentials.key(),
        permission,
        now,
        expires_at,
    )?;
    vault.record_share_invitation(&invitation)?;
    let transcript = token_transcript(address, &invitation, device.certificate.certificate_der());
    let token = ShareToken {
        version: SHARE_VERSION,
        address,
        invitation: invitation.clone(),
        secret: *secret.secret_bytes(),
        owner_certificate: device.certificate.certificate_der().to_vec(),
        transport_signature: device.identity.sign(TOKEN_DOMAIN, &transcript).to_vec(),
    };
    let encoded = encode_token(&token)?;
    println!(
        "Invitation ready ({permission:?}, {ttl}s).\n\n  {encoded}\n\nOn the other device:\n  cyrene invite join --vault … <database> <token>\n\nTreat this token like a password until it is accepted."
    );
    accept_claims(
        &listener,
        &mut vault,
        &device,
        &invitation,
        &secret,
        expires_at,
    )
    .await
}

async fn accept_claims(
    listener: &TcpListener,
    vault: &mut TrustStore,
    device: &cyrene::DeviceMaterial,
    invitation: &ShareInvitation,
    secret: &InvitationSecret,
    expires_at: u64,
) -> Result<()> {
    loop {
        let now = unix_time()?;
        let remaining = expires_at.saturating_sub(now);
        if remaining == 0 {
            bail!("invitation expired before it was accepted");
        }
        let accepted = timeout(Duration::from_secs(remaining), listener.accept())
            .await
            .map_err(|_| anyhow!("invitation expired before it was accepted"))??;
        let (mut stream, remote) = accepted;
        let claim = match timeout(
            Duration::from_secs(remaining),
            read_frame::<ShareClaim>(&mut stream),
        )
        .await
        {
            Ok(Ok(claim)) => claim,
            Err(_) => {
                eprintln!("Rejected stalled claim from {remote}");
                continue;
            }
            Ok(Err(error)) => {
                eprintln!("Rejected malformed claim from {remote}: {error}");
                continue;
            }
        };
        let peer = match validate_claim(&claim, invitation, secret, unix_time()?) {
            Ok(peer) => peer,
            Err(error) => {
                eprintln!("Rejected invitation claim from {remote}: {error}");
                continue;
            }
        };
        let capability = vault.redeem_share_invitation_with_peer(
            invitation,
            &device.identity,
            &peer,
            unix_time()?,
        )?;
        if write_frame(
            &mut stream,
            &ShareGrant {
                version: SHARE_VERSION,
                capability,
            },
        )
        .await
        .is_ok()
        {
            println!(
                "Shared space {} with device {} as {:?}.",
                invitation.space(),
                peer.public_key.id(),
                invitation.permission()
            );
            return Ok(());
        }
    }
}

async fn invite_join(arguments: &VaultArgs, database: &PathBuf, encoded: &str) -> Result<()> {
    let token = decode_token(encoded)?;
    validate_token(&token)?;
    let mut vault = open_vault(arguments)?;
    let device = require_device(&vault)?;
    let now = unix_time()?;
    let authority = SpaceAuthority {
        space: token.invitation.space(),
        issuer: token.invitation.issuer(),
        epoch: token.invitation.epoch(),
    };
    let secret = InvitationSecret::from_bytes(token.secret);
    let key = token.invitation.open(authority, &secret, now)?;
    if vault.space_access(token.invitation.space())?.is_some() {
        bail!("this device has already accepted authority for the invited space");
    }
    App::open_space(database, token.invitation.space())
        .await
        .with_context(|| format!("could not prepare replica in {}", database.display()))?;
    let base = claim_base(
        token.invitation.id(),
        device.identity.public_key(),
        device.certificate.certificate_der(),
    );
    let proof = *blake3::keyed_hash(secret.secret_bytes(), &base).as_bytes();
    let mut signed = base;
    signed.extend_from_slice(&proof);
    let claim = ShareClaim {
        version: SHARE_VERSION,
        invitation_id: token.invitation.id(),
        public_key: device.identity.public_key(),
        certificate_der: device.certificate.certificate_der().to_vec(),
        secret_proof: proof,
        signature: device.identity.sign(CLAIM_DOMAIN, &signed).to_vec(),
    };
    let remaining = token.invitation.expires_at().saturating_sub(unix_time()?);
    if remaining == 0 {
        bail!("invitation has expired");
    }
    let mut stream = timeout(
        Duration::from_secs(remaining),
        TcpStream::connect(token.address),
    )
    .await
    .map_err(|_| anyhow!("timed out connecting to invitation listener"))?
    .with_context(|| format!("could not connect to {}", token.address))?;
    write_frame(&mut stream, &claim).await?;
    let grant: ShareGrant = timeout(Duration::from_secs(remaining), read_frame(&mut stream))
        .await
        .map_err(|_| anyhow!("timed out waiting for the invitation grant"))??;
    if grant.version != SHARE_VERSION
        || grant.capability.permission() != token.invitation.permission()
    {
        bail!("inviter returned an incompatible grant");
    }
    grant.capability.authorize(
        authority,
        device.identity.public_key(),
        cyrene::AuthorizedOperation::Read,
        unix_time()?,
    )?;
    let peer = PeerRecord {
        public_key: token.invitation.issuer(),
        certificate_der: token.owner_certificate,
        paired_at: unix_time()?,
    };
    vault.accept_shared_space(
        &peer,
        &SpaceAccess {
            authority,
            capability: grant.capability,
        },
        &key,
        unix_time()?,
    )?;
    println!(
        "Accepted space {} as {:?}. Local replica: {}",
        token.invitation.space(),
        token.invitation.permission(),
        database.display()
    );
    Ok(())
}

fn validate_token(token: &ShareToken) -> Result<()> {
    if token.version != SHARE_VERSION {
        bail!("unsupported invitation token version");
    }
    let transcript = token_transcript(token.address, &token.invitation, &token.owner_certificate);
    if !token
        .invitation
        .issuer()
        .verify(TOKEN_DOMAIN, &transcript, &token.transport_signature)
    {
        bail!("invitation transport binding is invalid");
    }
    Ok(())
}

fn validate_claim(
    claim: &ShareClaim,
    invitation: &ShareInvitation,
    secret: &InvitationSecret,
    now: u64,
) -> Result<PeerRecord> {
    if claim.version != SHARE_VERSION || claim.invitation_id != invitation.id() {
        bail!("claim targets another invitation");
    }
    let base = claim_base(
        claim.invitation_id,
        claim.public_key,
        &claim.certificate_der,
    );
    let expected = blake3::keyed_hash(secret.secret_bytes(), &base);
    if expected.as_bytes() != &claim.secret_proof {
        bail!("claim does not prove possession of the invitation secret");
    }
    let mut signed = base;
    signed.extend_from_slice(&claim.secret_proof);
    if !claim
        .public_key
        .verify(CLAIM_DOMAIN, &signed, &claim.signature)
    {
        bail!("claim does not prove the recipient device identity");
    }
    Ok(PeerRecord {
        public_key: claim.public_key,
        certificate_der: claim.certificate_der.clone(),
        paired_at: now,
    })
}

fn token_transcript(
    address: SocketAddr,
    invitation: &ShareInvitation,
    certificate_der: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    push(&mut bytes, &[SHARE_VERSION]);
    push(&mut bytes, address.to_string().as_bytes());
    push(&mut bytes, &invitation.id());
    push(
        &mut bytes,
        CertificatePin::from_certificate_der(certificate_der).as_bytes(),
    );
    bytes
}

fn claim_base(id: [u8; 16], public_key: DevicePublicKey, certificate_der: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    push(&mut bytes, &id);
    push(&mut bytes, &public_key.to_bytes());
    push(
        &mut bytes,
        CertificatePin::from_certificate_der(certificate_der).as_bytes(),
    );
    bytes
}

fn push(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn encode_token(token: &ShareToken) -> Result<String> {
    let encoded = serde_json::to_vec(token)?;
    if encoded.len() > TOKEN_LIMIT {
        bail!("invitation token exceeds its hard size limit");
    }
    Ok(URL_SAFE_NO_PAD.encode(encoded))
}

fn decode_token(encoded: &str) -> Result<ShareToken> {
    if encoded.len() > TOKEN_LIMIT * 2 {
        bail!("invitation token exceeds its hard size limit");
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("invitation token is not valid URL-safe base64")?;
    if decoded.len() > TOKEN_LIMIT {
        bail!("invitation token exceeds its hard size limit");
    }
    serde_json::from_slice(&decoded).context("invitation token is malformed")
}

async fn write_frame<T: Serialize>(stream: &mut TcpStream, message: &T) -> Result<()> {
    let encoded = serde_json::to_vec(message)?;
    if encoded.len() > SHARE_FRAME_LIMIT {
        bail!("sharing message exceeds its hard size limit");
    }
    stream.write_u32(u32::try_from(encoded.len())?).await?;
    stream.write_all(&encoded).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_frame<T: DeserializeOwned>(stream: &mut TcpStream) -> Result<T> {
    let length = usize::try_from(stream.read_u32().await?)?;
    if length > SHARE_FRAME_LIMIT {
        bail!("sharing message exceeds its hard size limit");
    }
    let mut encoded = vec![0; length];
    stream.read_exact(&mut encoded).await?;
    serde_json::from_slice(&encoded).context("sharing message is malformed")
}

fn hex(bytes: [u8; 32]) -> String {
    use std::fmt::Write as _;

    bytes
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to a string cannot fail");
            output
        })
}

#[cfg(test)]
mod tests {
    use cyrene::{DeviceIdentity, QuicCertificate, SpaceId, SpaceKey};

    use super::*;

    #[test]
    fn token_round_trip_preserves_secret_and_transport_binding() {
        let owner = DeviceIdentity::from_secret_bytes(&[90; 32]);
        let certificate = QuicCertificate::generate().unwrap();
        let (invitation, secret) = ShareInvitation::issue(
            &owner,
            SpaceId::from_u128(91),
            1,
            &SpaceKey::from_bytes([92; 32]),
            Permission::ReadOnly,
            100,
            200,
        )
        .unwrap();
        let address = "127.0.0.1:4040".parse().unwrap();
        let transcript = token_transcript(address, &invitation, certificate.certificate_der());
        let token = ShareToken {
            version: SHARE_VERSION,
            address,
            invitation,
            secret: *secret.secret_bytes(),
            owner_certificate: certificate.certificate_der().to_vec(),
            transport_signature: owner.sign(TOKEN_DOMAIN, &transcript).to_vec(),
        };
        let decoded = decode_token(&encode_token(&token).unwrap()).unwrap();
        validate_token(&decoded).unwrap();
        assert_eq!(decoded.secret, token.secret);
    }

    #[test]
    fn claim_requires_both_bearer_secret_and_device_signature() {
        let recipient = DeviceIdentity::from_secret_bytes(&[93; 32]);
        let certificate = QuicCertificate::generate().unwrap();
        let owner = DeviceIdentity::from_secret_bytes(&[94; 32]);
        let (invitation, secret) = ShareInvitation::issue(
            &owner,
            SpaceId::from_u128(95),
            1,
            &SpaceKey::from_bytes([96; 32]),
            Permission::ReadWrite,
            100,
            200,
        )
        .unwrap();
        let base = claim_base(
            invitation.id(),
            recipient.public_key(),
            certificate.certificate_der(),
        );
        let proof = *blake3::keyed_hash(secret.secret_bytes(), &base).as_bytes();
        let mut signed = base;
        signed.extend_from_slice(&proof);
        let claim = ShareClaim {
            version: SHARE_VERSION,
            invitation_id: invitation.id(),
            public_key: recipient.public_key(),
            certificate_der: certificate.certificate_der().to_vec(),
            secret_proof: proof,
            signature: recipient.sign(CLAIM_DOMAIN, &signed).to_vec(),
        };
        validate_claim(&claim, &invitation, &secret, 150).unwrap();
        assert!(
            validate_claim(
                &claim,
                &invitation,
                &InvitationSecret::from_bytes([1; 32]),
                150
            )
            .is_err()
        );
    }
}

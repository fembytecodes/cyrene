//! Mutually authenticated, certificate-pinned QUIC transport.
//!
//! TLS protects each connection and the client pins the exact certificate
//! learned through pairing. A second, application-level handshake proves both
//! endpoints possess their advertised Cyrene device keys and binds that proof
//! to the TLS certificate, fresh nonces, and protocol version.

#![forbid(unsafe_code)]

mod discovery;
mod relay;

use std::{fmt, net::SocketAddr, sync::Arc};

use cyrene_identity::{DeviceId, DeviceIdentity, DevicePublicKey};
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

pub use discovery::{DiscoveredPeer, DiscoveryAdvertiser, DiscoveryBrowser};
pub use relay::{
    MAX_RELAY_BATCH, MAX_RELAY_BATCH_BYTES, MAX_RELAY_CLOCK_SKEW, MAX_RELAY_ENVELOPE_BYTES,
    MAX_RELAY_RETENTION, RelayClient, RelayDelivery, RelayEnvelope, RelayMailbox, RelayOperation,
    RelayProtocolError, RelayRejection, RelayRequest, RelayResponse,
};

const SERVER_NAME: &str = "cyrene.local";
const AUTH_DOMAIN: &[u8] = b"cyrene/quic/device-auth/1";
const AUTH_MESSAGE_LIMIT: usize = 8 * 1024;

/// An authenticated transport failure.
#[derive(Debug, Error)]
pub enum NetError {
    /// Socket or endpoint creation failed.
    #[error("could not create the QUIC endpoint: {0}")]
    Endpoint(#[from] std::io::Error),
    /// Certificate generation or configuration failed.
    #[error("could not configure the QUIC certificate: {0}")]
    Certificate(String),
    /// The remote address or client configuration was rejected.
    #[error("could not begin the QUIC connection: {0}")]
    Connect(#[from] quinn::ConnectError),
    /// The QUIC connection closed before authentication completed.
    #[error("the QUIC connection failed: {0}")]
    Connection(#[from] quinn::ConnectionError),
    /// Writing a stream failed.
    #[error("could not write a QUIC stream: {0}")]
    Write(#[from] quinn::WriteError),
    /// A peer closed a stream before it was finished.
    #[error("the peer closed a QUIC stream before it was finished")]
    ClosedStream(#[from] quinn::ClosedStream),
    /// A message exceeded its declared bound or the stream failed.
    #[error("could not read a bounded QUIC message: {0}")]
    Read(String),
    /// A wire message was malformed.
    #[error("the peer sent an invalid authentication message")]
    InvalidMessage,
    /// The remote endpoint did not prove the expected device identity.
    #[error("the peer could not authenticate as the paired device")]
    Authentication,
    /// Secure operating-system randomness was unavailable.
    #[error("secure random generation failed")]
    Randomness,
    /// Local service discovery failed.
    #[error("local peer discovery failed: {0}")]
    Discovery(String),
}

/// The exact hash of a peer's TLS certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CertificatePin([u8; 32]);

impl CertificatePin {
    /// Restores an exact pin from its hash bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derives an exact pin from a DER-encoded certificate.
    pub fn from_certificate_der(certificate_der: &[u8]) -> Self {
        Self(*blake3::hash(certificate_der).as_bytes())
    }

    /// Returns the pin bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for CertificatePin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..8] {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A self-signed QUIC certificate and its private key.
///
/// Generate this once per device and store its encoded values beside the
/// protected device identity. Replacing it invalidates existing peer pins.
pub struct QuicCertificate {
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
}

impl QuicCertificate {
    /// Generates a fresh self-signed certificate for Cyrene's fixed TLS name.
    ///
    /// # Errors
    ///
    /// Returns an error if certificate generation fails.
    pub fn generate() -> Result<Self, NetError> {
        let generated = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()])
            .map_err(|error| NetError::Certificate(error.to_string()))?;
        Ok(Self {
            certificate_der: generated.cert.der().to_vec(),
            private_key_der: generated.signing_key.serialize_der(),
        })
    }

    /// Restores a certificate from DER-encoded certificate and PKCS#8 key.
    pub fn from_der(certificate_der: Vec<u8>, private_key_der: Vec<u8>) -> Self {
        Self {
            certificate_der,
            private_key_der,
        }
    }

    /// Returns the certificate's exact cryptographic pin.
    pub fn pin(&self) -> CertificatePin {
        CertificatePin::from_certificate_der(&self.certificate_der)
    }

    /// Returns the public certificate shared with paired peers.
    pub fn public_certificate(&self) -> PeerCertificate {
        PeerCertificate::from_der(self.certificate_der.clone())
    }

    /// Returns the public DER certificate encoding.
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    /// Returns the secret PKCS#8 key encoding for protected persistence.
    pub fn private_key_der(&self) -> &[u8] {
        &self.private_key_der
    }

    fn server_config(&self) -> Result<ServerConfig, NetError> {
        ServerConfig::with_single_cert(
            vec![CertificateDer::from(self.certificate_der.clone())],
            PrivatePkcs8KeyDer::from(self.private_key_der.clone()).into(),
        )
        .map_err(|error| NetError::Certificate(error.to_string()))
    }
}

/// A peer's public, exactly pinned TLS certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerCertificate {
    certificate_der: Vec<u8>,
}

impl PeerCertificate {
    /// Creates a pin from the DER bytes authenticated during pairing.
    pub fn from_der(certificate_der: Vec<u8>) -> Self {
        Self { certificate_der }
    }

    /// Returns the exact cryptographic certificate pin.
    pub fn pin(&self) -> CertificatePin {
        CertificatePin::from_certificate_der(&self.certificate_der)
    }

    /// Returns the DER certificate encoding.
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    fn client_config(&self) -> Result<ClientConfig, NetError> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(self.certificate_der.clone()))
            .map_err(|error| NetError::Certificate(error.to_string()))?;
        ClientConfig::with_root_certificates(Arc::new(roots))
            .map_err(|error| NetError::Certificate(error.to_string()))
    }
}

impl fmt::Debug for QuicCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuicCertificate")
            .field("pin", &self.pin())
            .finish_non_exhaustive()
    }
}

/// A listening QUIC endpoint.
pub struct Listener {
    endpoint: Endpoint,
    certificate_pin: CertificatePin,
}

impl Listener {
    /// Binds a server endpoint to `address`.
    ///
    /// # Errors
    ///
    /// Returns an error if TLS configuration or socket binding fails.
    pub fn bind(address: SocketAddr, certificate: &QuicCertificate) -> Result<Self, NetError> {
        let endpoint = Endpoint::server(certificate.server_config()?, address)?;
        Ok(Self {
            endpoint,
            certificate_pin: certificate.pin(),
        })
    }

    /// Returns the actual bound address, including an OS-selected port.
    ///
    /// # Errors
    ///
    /// Returns an error if the local socket address is unavailable.
    pub fn local_addr(&self) -> Result<SocketAddr, NetError> {
        Ok(self.endpoint.local_addr()?)
    }

    /// Advertises this listener on local links for an already paired device.
    ///
    /// The returned handle keeps the advertisement alive. Discovery metadata
    /// is untrusted and never replaces device authentication or certificate
    /// pinning during [`connect`].
    ///
    /// # Errors
    ///
    /// Returns an error if the listener address is unavailable or mDNS cannot
    /// register the service.
    pub fn advertise(&self, device: DeviceId) -> Result<DiscoveryAdvertiser, NetError> {
        DiscoveryAdvertiser::start(device, self.certificate_pin, self.local_addr()?.port())
    }

    /// Accepts one connection and authenticates the expected paired peer.
    ///
    /// # Errors
    ///
    /// Returns an error if the endpoint closes, QUIC fails, the message is
    /// malformed, or the peer cannot prove possession of `expected_peer`.
    pub async fn accept(
        &self,
        identity: &DeviceIdentity,
        expected_peer: DevicePublicKey,
    ) -> Result<AuthenticatedConnection, NetError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| NetError::Read("the listener closed".into()))?;
        let connection = incoming.await?;
        authenticate_server(connection, identity, expected_peer, self.certificate_pin).await
    }
}

/// Connects to a certificate-pinned server and mutually authenticates devices.
///
/// # Errors
///
/// Returns an error if endpoint creation, certificate verification, QUIC, or
/// device authentication fails.
pub async fn connect(
    bind_address: SocketAddr,
    server_address: SocketAddr,
    server_certificate: &PeerCertificate,
    identity: &DeviceIdentity,
    expected_peer: DevicePublicKey,
) -> Result<AuthenticatedConnection, NetError> {
    let mut endpoint = Endpoint::client(bind_address)?;
    endpoint.set_default_client_config(server_certificate.client_config()?);
    let connection = endpoint.connect(server_address, SERVER_NAME)?.await?;
    let authenticated = authenticate_client(
        connection,
        identity,
        expected_peer,
        server_certificate.pin(),
    )
    .await?;
    // A Connection retains the endpoint internally for its lifetime.
    Ok(authenticated)
}

/// A QUIC connection authenticated as a specific paired device.
pub struct AuthenticatedConnection {
    connection: Connection,
    peer: DevicePublicKey,
}

impl AuthenticatedConnection {
    /// Returns the authenticated peer identity.
    pub const fn peer(&self) -> DevicePublicKey {
        self.peer
    }

    /// Sends a bounded serialized message on a fresh stream.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails, `message` exceeds `limit`, or
    /// the QUIC stream fails.
    pub async fn send<T: Serialize>(&self, message: &T, limit: usize) -> Result<(), NetError> {
        let encoded = serde_json::to_vec(message).map_err(|_| NetError::InvalidMessage)?;
        if encoded.len() > limit {
            return Err(NetError::InvalidMessage);
        }
        let mut stream = self.connection.open_uni().await?;
        stream.write_all(&encoded).await?;
        stream.finish()?;
        stream
            .stopped()
            .await
            .map_err(|error| NetError::Read(error.to_string()))?;
        Ok(())
    }

    /// Receives and decodes a message from a fresh stream with a hard bound.
    ///
    /// # Errors
    ///
    /// Returns an error if the stream fails, exceeds `limit`, or contains an
    /// invalid message.
    pub async fn receive<T: DeserializeOwned>(&self, limit: usize) -> Result<T, NetError> {
        let stream = self.connection.accept_uni().await?;
        read_message(stream, limit).await
    }

    /// Returns the peer's current socket address.
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }
}

#[derive(Serialize, Deserialize)]
struct ClientHello {
    version: u8,
    public_key: DevicePublicKey,
    nonce: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct ServerHello {
    public_key: DevicePublicKey,
    nonce: [u8; 32],
    signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct ClientProof {
    signature: Vec<u8>,
}

async fn authenticate_client(
    connection: Connection,
    identity: &DeviceIdentity,
    expected_peer: DevicePublicKey,
    certificate_pin: CertificatePin,
) -> Result<AuthenticatedConnection, NetError> {
    let client_nonce = random_nonce()?;
    let hello = ClientHello {
        version: 1,
        public_key: identity.public_key(),
        nonce: client_nonce,
    };
    let (mut send, recv) = connection.open_bi().await?;
    write_message(&mut send, &hello, AUTH_MESSAGE_LIMIT).await?;
    send.finish()?;
    let server: ServerHello = read_message(recv, AUTH_MESSAGE_LIMIT).await?;
    if server.public_key != expected_peer {
        return Err(NetError::Authentication);
    }
    let transcript = auth_transcript(&hello, &server, certificate_pin);
    if !server
        .public_key
        .verify(AUTH_DOMAIN, &transcript, &server.signature)
    {
        return Err(NetError::Authentication);
    }
    let proof = ClientProof {
        signature: identity.sign(AUTH_DOMAIN, &transcript).to_vec(),
    };
    let mut stream = connection.open_uni().await?;
    write_message(&mut stream, &proof, AUTH_MESSAGE_LIMIT).await?;
    stream.finish()?;
    stream
        .stopped()
        .await
        .map_err(|error| NetError::Read(error.to_string()))?;
    Ok(AuthenticatedConnection {
        connection,
        peer: expected_peer,
    })
}

async fn authenticate_server(
    connection: Connection,
    identity: &DeviceIdentity,
    expected_peer: DevicePublicKey,
    certificate_pin: CertificatePin,
) -> Result<AuthenticatedConnection, NetError> {
    let (mut send, recv) = connection.accept_bi().await?;
    let hello: ClientHello = read_message(recv, AUTH_MESSAGE_LIMIT).await?;
    if hello.version != 1 || hello.public_key != expected_peer {
        return Err(NetError::Authentication);
    }
    let mut server = ServerHello {
        public_key: identity.public_key(),
        nonce: random_nonce()?,
        signature: Vec::new(),
    };
    let transcript = auth_transcript(&hello, &server, certificate_pin);
    server.signature = identity.sign(AUTH_DOMAIN, &transcript).to_vec();
    write_message(&mut send, &server, AUTH_MESSAGE_LIMIT).await?;
    send.finish()?;
    let proof_stream = connection.accept_uni().await?;
    let proof: ClientProof = read_message(proof_stream, AUTH_MESSAGE_LIMIT).await?;
    if !hello
        .public_key
        .verify(AUTH_DOMAIN, &transcript, &proof.signature)
    {
        return Err(NetError::Authentication);
    }
    Ok(AuthenticatedConnection {
        connection,
        peer: expected_peer,
    })
}

fn auth_transcript(
    client: &ClientHello,
    server: &ServerHello,
    certificate_pin: CertificatePin,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(161);
    push(&mut bytes, AUTH_DOMAIN);
    push(&mut bytes, &[client.version]);
    push(&mut bytes, &client.public_key.to_bytes());
    push(&mut bytes, &client.nonce);
    push(&mut bytes, &server.public_key.to_bytes());
    push(&mut bytes, &server.nonce);
    push(&mut bytes, certificate_pin.as_bytes());
    bytes
}

fn push(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn random_nonce() -> Result<[u8; 32], NetError> {
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| NetError::Randomness)?;
    Ok(nonce)
}

async fn write_message<T: Serialize>(
    stream: &mut SendStream,
    message: &T,
    limit: usize,
) -> Result<(), NetError> {
    let encoded = serde_json::to_vec(message).map_err(|_| NetError::InvalidMessage)?;
    if encoded.len() > limit {
        return Err(NetError::InvalidMessage);
    }
    stream.write_all(&encoded).await?;
    Ok(())
}

async fn read_message<T: DeserializeOwned>(
    mut stream: RecvStream,
    limit: usize,
) -> Result<T, NetError> {
    let encoded = stream
        .read_to_end(limit)
        .await
        .map_err(|error| NetError::Read(error.to_string()))?;
    serde_json::from_slice(&encoded).map_err(|_| NetError::InvalidMessage)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn identity(byte: u8) -> DeviceIdentity {
        DeviceIdentity::from_secret_bytes(&[byte; 32])
    }

    #[tokio::test]
    async fn pinned_mutually_authenticated_peers_exchange_messages() {
        let alice = identity(1);
        let bob = identity(2);
        let certificate = QuicCertificate::generate().unwrap();
        let peer_certificate = certificate.public_certificate();
        let listener = Listener::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &certificate,
        )
        .unwrap();
        let address = listener.local_addr().unwrap();

        let server = async {
            let connection = listener.accept(&alice, bob.public_key()).await.unwrap();
            let value: String = connection.receive(128).await.unwrap();
            assert_eq!(value, "hello from bob");
            connection.send(&"hello from alice", 128).await.unwrap();
            connection.peer()
        };
        let client = async {
            let connection = connect(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                address,
                &peer_certificate,
                &bob,
                alice.public_key(),
            )
            .await
            .unwrap();
            connection.send(&"hello from bob", 128).await.unwrap();
            let value: String = connection.receive(128).await.unwrap();
            assert_eq!(value, "hello from alice");
            connection.peer()
        };

        let (server_peer, client_peer) = tokio::join!(server, client);
        assert_eq!(server_peer, bob.public_key());
        assert_eq!(client_peer, alice.public_key());
    }

    #[tokio::test]
    async fn a_different_pinned_certificate_cannot_connect() {
        let alice = identity(1);
        let bob = identity(2);
        let certificate = QuicCertificate::generate().unwrap();
        let wrong_certificate = QuicCertificate::generate().unwrap();
        let wrong_peer_certificate = wrong_certificate.public_certificate();
        let listener = Listener::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &certificate,
        )
        .unwrap();
        let address = listener.local_addr().unwrap();

        let server = listener.accept(&alice, bob.public_key());
        let client = connect(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            address,
            &wrong_peer_certificate,
            &bob,
            alice.public_key(),
        );
        let (server_result, client_result) = tokio::join!(server, client);
        assert!(server_result.is_err());
        assert!(client_result.is_err());
    }

    #[tokio::test]
    async fn an_unpaired_device_key_is_rejected() {
        let alice = identity(1);
        let bob = identity(2);
        let mallory = identity(3);
        let certificate = QuicCertificate::generate().unwrap();
        let peer_certificate = certificate.public_certificate();
        let listener = Listener::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &certificate,
        )
        .unwrap();
        let address = listener.local_addr().unwrap();

        let server = listener.accept(&alice, bob.public_key());
        let client = connect(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            address,
            &peer_certificate,
            &mallory,
            alice.public_key(),
        );
        let (server_result, client_result) = tokio::join!(server, client);
        assert!(server_result.is_err());
        assert!(client_result.is_err());
    }
}

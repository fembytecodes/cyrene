use std::{net::SocketAddr, time::Duration};

use cyrene_identity::{DeviceId, DevicePublicKey};
use mdns_sd::{Receiver, ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::{CertificatePin, NetError};

const SERVICE_TYPE: &str = "_cyrene._udp.local.";
const PROTOCOL_VERSION: &str = "1";

/// One untrusted LAN advertisement resolved through mDNS.
///
/// Discovery says only where a device claims to be. Call [`Self::matches`] with
/// an already paired identity and certificate pin before connecting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredPeer {
    /// Claimed device identity.
    pub device_id: DeviceId,
    /// Claimed QUIC certificate pin.
    pub certificate_pin: CertificatePin,
    /// Resolved socket addresses for the QUIC endpoint.
    pub addresses: Vec<SocketAddr>,
}

impl DiscoveredPeer {
    /// Returns whether this advertisement exactly matches durable paired trust.
    pub fn matches(&self, public_key: DevicePublicKey, certificate_pin: CertificatePin) -> bool {
        self.device_id == public_key.id() && self.certificate_pin == certificate_pin
    }
}

/// A live mDNS advertisement for one authenticated QUIC listener.
pub struct DiscoveryAdvertiser {
    daemon: ServiceDaemon,
    fullname: String,
}

impl DiscoveryAdvertiser {
    /// Advertises a device ID, certificate pin, and QUIC port on local links.
    ///
    /// Discovery does not grant trust. The advertised identity and pin must
    /// already match a peer's durable pairing record before use.
    ///
    /// # Errors
    ///
    /// Returns an error if the mDNS daemon, service description, or
    /// registration cannot be created.
    pub fn start(
        device: DeviceId,
        certificate_pin: CertificatePin,
        port: u16,
    ) -> Result<Self, NetError> {
        if port == 0 {
            return Err(NetError::Discovery(
                "cannot advertise an unbound port".into(),
            ));
        }
        let daemon = ServiceDaemon::new().map_err(discovery_error)?;
        let device_hex = encode_hex(device.as_bytes());
        let pin_hex = encode_hex(certificate_pin.as_bytes());
        let instance = &device_hex[..16];
        let hostname = format!("{instance}.local.");
        let properties = [
            ("v", PROTOCOL_VERSION),
            ("device", device_hex.as_str()),
            ("pin", pin_hex.as_str()),
        ];
        let service =
            ServiceInfo::new(SERVICE_TYPE, instance, &hostname, "", port, &properties[..])
                .map_err(discovery_error)?
                .enable_addr_auto();
        let fullname = service.get_fullname().to_owned();
        daemon.register(service).map_err(discovery_error)?;
        Ok(Self { daemon, fullname })
    }
}

impl Drop for DiscoveryAdvertiser {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

/// A live mDNS browser for nearby Cyrene endpoints.
pub struct DiscoveryBrowser {
    daemon: ServiceDaemon,
    receiver: Receiver<ServiceEvent>,
}

impl DiscoveryBrowser {
    /// Starts browsing for Cyrene QUIC services on local links.
    ///
    /// # Errors
    ///
    /// Returns an error if the mDNS daemon cannot start browsing.
    pub fn start() -> Result<Self, NetError> {
        let daemon = ServiceDaemon::new().map_err(discovery_error)?;
        let receiver = daemon.browse(SERVICE_TYPE).map_err(discovery_error)?;
        Ok(Self { daemon, receiver })
    }

    /// Waits for the next well-formed resolved advertisement.
    ///
    /// Malformed and version-incompatible advertisements are ignored. `None`
    /// means no compatible endpoint resolved before `wait` elapsed.
    ///
    /// # Errors
    ///
    /// Returns an error if the discovery channel closes unexpectedly.
    pub async fn next(&self, wait: Duration) -> Result<Option<DiscoveredPeer>, NetError> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let event = match tokio::time::timeout(remaining, self.receiver.recv_async()).await {
                Ok(Ok(event)) => event,
                Ok(Err(error)) => return Err(NetError::Discovery(error.to_string())),
                Err(_) => return Ok(None),
            };
            if let ServiceEvent::ServiceResolved(service) = event
                && let Some(peer) = decode_service(&service)
            {
                return Ok(Some(peer));
            }
        }
    }
}

impl Drop for DiscoveryBrowser {
    fn drop(&mut self) {
        let _ = self.daemon.stop_browse(SERVICE_TYPE);
        let _ = self.daemon.shutdown();
    }
}

fn decode_service(service: &mdns_sd::ResolvedService) -> Option<DiscoveredPeer> {
    if service.get_property_val_str("v")? != PROTOCOL_VERSION {
        return None;
    }
    let device_id = DeviceId::from_bytes(decode_hex(service.get_property_val_str("device")?)?);
    let certificate_pin =
        CertificatePin::from_bytes(decode_hex(service.get_property_val_str("pin")?)?);
    let mut addresses = service
        .get_addresses()
        .iter()
        .map(|address| SocketAddr::new(address.to_ip_addr(), service.get_port()))
        .collect::<Vec<_>>();
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() {
        return None;
    }
    Some(DiscoveredPeer {
        device_id,
        certificate_pin,
        addresses,
    })
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

fn decode_hex<const N: usize>(encoded: &str) -> Option<[u8; N]> {
    if encoded.len() != N * 2 || !encoded.is_ascii() {
        return None;
    }
    let mut decoded = [0; N];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(decoded)
}

fn discovery_error(error: impl std::fmt::Display) -> NetError {
    NetError::Discovery(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_metadata_round_trips_without_truncating_identity() {
        let bytes = [0xabu8; 32];
        assert_eq!(decode_hex::<32>(&encode_hex(&bytes)), Some(bytes));
        assert_eq!(decode_hex::<32>("ab"), None);
        assert_eq!(decode_hex::<32>(&"zz".repeat(32)), None);
    }

    #[test]
    fn an_advertisement_matches_only_both_paired_values() {
        let identity = cyrene_identity::DeviceIdentity::from_secret_bytes(&[7; 32]);
        let pin = CertificatePin::from_bytes([8; 32]);
        let advertisement = DiscoveredPeer {
            device_id: identity.id(),
            certificate_pin: pin,
            addresses: vec!["127.0.0.1:1234".parse().unwrap()],
        };
        assert!(advertisement.matches(identity.public_key(), pin));
        assert!(!advertisement.matches(
            cyrene_identity::DeviceIdentity::from_secret_bytes(&[9; 32]).public_key(),
            pin
        ));
        assert!(
            !advertisement.matches(identity.public_key(), CertificatePin::from_bytes([10; 32]))
        );
    }

    #[tokio::test]
    async fn a_zero_wait_is_a_non_blocking_discovery_poll() {
        let browser = DiscoveryBrowser::start().unwrap();
        assert_eq!(browser.next(Duration::ZERO).await.unwrap(), None);
    }

    #[test]
    fn an_unbound_port_is_never_advertised() {
        let error = DiscoveryAdvertiser::start(
            DeviceId::from_bytes([1; 32]),
            CertificatePin::from_bytes([2; 32]),
            0,
        );
        assert!(matches!(error, Err(NetError::Discovery(_))));
    }
}

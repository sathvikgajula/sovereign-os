//! PQ-QUIC configuration with X25519MLKEM768 hybrid key exchange.
//!
//! Forces the TLS 1.3 handshake to use only the post-quantum hybrid group.
//! Uses self-signed certificates — authentication is handled at the DID layer,
//! not via the TLS certificate chain.

use anyhow::{anyhow, Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use std::sync::Arc;
use tracing::info;

/// The immutable ML-DSA-65 root public key for the Sovereign OS V1.0 Sanctuary.
pub const ROOT_TRUST_ANCHOR: &[u8] = &[
    178, 244, 98, 145, 56, 125, 72, 132, 40, 178, 150, 184, 193, 223, 45, 227, 49, 11, 253, 218, 211,
    209, 84, 131, 121, 9, 31, 105, 84, 107, 160, 112, 44, 57, 102, 198, 55, 234, 200, 213, 56, 203,
    111, 123, 68, 190, 135, 147, 1, 11, 80, 70, 29, 63, 95, 129, 166, 105, 74, 58, 204, 87, 154, 48,
    26, 222, 148, 175, 75, 15, 47, 5, 100, 239, 17, 123, 131, 188, 56, 147, 111, 148, 205, 210, 54,
    41, 173, 17, 28, 182, 168, 100, 216, 162, 236, 176, 20, 38, 111, 84, 139, 190, 27, 200, 95, 234,
    218, 78, 153, 118, 134, 72, 207, 30, 64, 131, 71, 106, 0, 121, 69, 97, 30, 13, 10, 178, 240, 243,
    51, 173, 173, 66, 57, 233, 76, 116, 177, 236, 3, 137, 98, 185, 206, 56, 255, 115, 24, 95, 219,
    139, 193, 165, 69, 180, 106, 56, 224, 169, 145, 173, 115, 62, 48, 238, 52, 66, 16, 40, 151, 56,
    127, 214, 108, 0, 165, 95, 230, 190, 176, 167, 79, 194, 111, 8, 109, 177, 133, 142, 31, 178,
    211, 153, 175, 165, 234, 37, 202, 75, 81, 193, 22, 26, 218, 92, 81, 62, 240, 211, 183, 215, 51,
    168, 59, 126, 164, 13, 30, 139, 45, 191, 119, 69, 66, 0, 40, 28, 46, 239, 31, 31, 159, 149, 138,
    164, 16, 217, 199, 178, 62, 210, 222, 138, 112, 149, 223, 130, 226, 31, 159, 91, 196, 183, 161,
    43, 53, 104, 238, 10, 120, 36, 9, 122, 198, 205, 210, 11, 36, 213, 154, 197, 16, 90, 105, 83,
    191, 69, 31, 110, 58, 42, 94, 84, 187, 253, 86, 196, 172, 65, 67, 75, 3, 69, 26, 7, 33, 246,
    111, 244, 239, 138, 182, 188, 49, 232, 45, 225, 44, 239, 230, 148, 137, 39, 197, 193, 58, 128,
    100, 108, 104, 111, 1, 104, 100, 51, 68, 15, 165, 102, 105, 199, 60, 197, 88, 207, 237, 26, 127,
    244, 149, 226, 154, 203, 185, 250, 102, 243, 214, 123, 151, 34, 177, 139, 134, 86, 137, 162, 36,
    228, 199, 24, 61, 109, 44, 85, 72, 27, 66, 52, 157, 200, 24, 141, 221, 51, 179, 45, 98, 242,
    130, 59, 116, 44, 183, 142, 226, 63, 182, 207, 219, 73, 196, 172, 137, 233, 30, 178, 116, 183,
    84, 156, 3, 174, 65, 58, 168, 104, 65, 142, 97, 158, 98, 51, 116, 125, 171, 230, 108, 79, 217,
    117, 161, 101, 247, 87, 81, 151, 47, 231, 213, 218, 244, 254, 151, 133, 104, 57, 46, 87, 12,
    233, 172, 86, 142, 70, 147, 3, 111, 141, 131, 43, 101, 21, 104, 58, 19, 38, 214, 64, 169, 66,
    155, 205, 86, 220, 77, 211, 19, 156, 92, 255, 214, 79, 22, 164, 134, 190, 32, 220, 86, 127, 249,
    238, 204, 144, 75, 222, 244, 112, 3, 237, 180, 132, 78, 77, 70, 200, 44, 95, 159, 246, 209, 162,
    61, 227, 187, 18, 104, 224, 99, 50, 246, 161, 252, 74, 1, 176, 209, 219, 247, 234, 140, 27, 209,
    222, 143, 88, 223, 162, 90, 177, 94, 114, 245, 52, 174, 48, 0, 209, 187, 136, 157, 117, 101,
    218, 162, 197, 65, 229, 99, 156, 199, 186, 83, 134, 168, 159, 250, 45, 243, 189, 138, 73, 35,
    53, 137, 36, 22, 234, 34, 66, 3, 115, 214, 135, 150, 62, 223, 111, 128, 8, 6, 199, 41, 40, 140,
    15, 155, 98, 120, 55, 14, 106, 207, 174, 199, 138, 212, 47, 240, 103, 198, 249, 244, 223, 247,
    19, 229, 68, 23, 231, 109, 145, 17, 27, 2, 69, 253, 136, 142, 179, 186, 142, 32, 192, 68, 55,
    34, 175, 44, 24, 64, 74, 79, 4, 114, 161, 213, 41, 43, 152, 211, 204, 90, 141, 128, 222, 189,
    13, 83, 97, 64, 152, 240, 102, 102, 201, 166, 66, 31, 94, 255, 100, 16, 240, 227, 240, 86, 254,
    235, 20, 25, 46, 58, 83, 162, 24, 33, 122, 191, 45, 150, 220, 2, 52, 247, 243, 45, 133, 17, 132,
    87, 58, 94, 209, 20, 79, 42, 24, 79, 205, 185, 211, 194, 102, 115, 42, 48, 206, 139, 168, 212,
    228, 84, 107, 108, 176, 82, 50, 193, 15, 114, 228, 124, 187, 58, 43, 61, 46, 100, 121, 222, 48,
    205, 141, 148, 49, 27, 26, 12, 36, 182, 219, 180, 13, 237, 93, 161, 24, 193, 41, 199, 82, 123,
    18, 89, 218, 107, 101, 219, 204, 125, 164, 123, 17, 204, 165, 58, 119, 60, 17, 106, 30, 103, 78,
    152, 42, 211, 123, 202, 254, 232, 145, 253, 158, 230, 70, 172, 58, 12, 209, 116, 58, 170, 209,
    32, 188, 84, 145, 137, 229, 97, 154, 1, 207, 26, 20, 86, 135, 204, 23, 174, 146, 61, 24, 21, 9,
    215, 207, 23, 173, 69, 219, 120, 195, 98, 122, 19, 86, 29, 231, 93, 177, 26, 216, 101, 148, 140,
    37, 199, 150, 206, 111, 72, 31, 191, 195, 227, 198, 46, 35, 69, 150, 122, 3, 50, 194, 128, 90,
    106, 229, 184, 127, 52, 251, 165, 225, 149, 212, 160, 84, 176, 39, 88, 6, 151, 49, 132, 170,
    132, 24, 231, 136, 51, 166, 209, 145, 193, 121, 189, 232, 165, 99, 229, 186, 66, 144, 241, 83,
    175, 145, 199, 78, 119, 171, 84, 131, 244, 228, 139, 253, 193, 178, 145, 104, 107, 29, 216, 77,
    95, 248, 111, 75, 118, 156, 76, 121, 142, 37, 19, 124, 177, 79, 13, 215, 112, 119, 157, 181,
    230, 215, 157, 147, 118, 86, 132, 126, 21, 196, 211, 167, 162, 181, 45, 104, 157, 104, 118, 115,
    56, 225, 25, 30, 53, 109, 106, 216, 63, 101, 61, 117, 51, 36, 78, 175, 249, 92, 255, 55, 1, 245,
    49, 235, 245, 135, 197, 17, 196, 0, 107, 132, 254, 226, 224, 15, 24, 224, 241, 155, 94, 183,
    255, 114, 219, 181, 160, 137, 27, 32, 137, 208, 216, 24, 186, 15, 162, 43, 187, 50, 185, 214,
    189, 235, 211, 31, 203, 3, 147, 243, 29, 174, 211, 95, 220, 243, 181, 112, 163, 86, 144, 134,
    238, 193, 254, 189, 82, 0, 150, 243, 91, 56, 45, 222, 255, 204, 17, 74, 250, 138, 99, 83, 99,
    67, 50, 92, 163, 201, 79, 168, 173, 195, 136, 201, 249, 216, 188, 132, 23, 121, 44, 110, 182,
    239, 21, 232, 192, 82, 175, 148, 138, 223, 252, 39, 1, 242, 172, 45, 2, 99, 115, 1, 168, 75, 49,
    249, 162, 221, 75, 53, 81, 206, 152, 176, 206, 69, 110, 136, 100, 37, 20, 114, 44, 40, 6, 123,
    249, 70, 47, 231, 44, 163, 55, 158, 40, 184, 156, 12, 74, 142, 108, 6, 237, 177, 163, 152, 43,
    240, 188, 170, 204, 198, 132, 77, 219, 91, 235, 95, 113, 34, 6, 114, 49, 105, 107, 194, 110, 64,
    188, 122, 201, 36, 232, 97, 82, 247, 185, 158, 50, 238, 35, 181, 12, 58, 95, 149, 60, 73, 243,
    130, 80, 75, 90, 103, 150, 4, 139, 199, 177, 94, 221, 138, 138, 193, 226, 137, 187, 202, 184,
    77, 70, 246, 53, 159, 24, 58, 205, 244, 150, 206, 209, 23, 153, 139, 20, 68, 181, 207, 220, 4,
    203, 126, 246, 90, 136, 214, 60, 176, 122, 200, 157, 190, 214, 253, 204, 156, 217, 138, 190, 34,
    10, 210, 186, 105, 218, 229, 52, 26, 227, 153, 246, 184, 210, 232, 136, 74, 141, 182, 126, 72,
    126, 179, 69, 228, 21, 241, 89, 236, 150, 60, 248, 107, 174, 90, 45, 230, 203, 226, 197, 101,
    24, 9, 188, 76, 16, 141, 48, 185, 113, 119, 196, 103, 37, 125, 246, 146, 145, 62, 186, 120, 184,
    39, 190, 150, 172, 127, 114, 49, 212, 111, 253, 78, 115, 112, 97, 66, 252, 37, 133, 5, 195, 249,
    47, 206, 158, 219, 251, 22, 199, 60, 192, 99, 251, 10, 15, 167, 249, 8, 104, 239, 15, 203, 196,
    99, 115, 228, 205, 153, 192, 218, 84, 73, 46, 10, 142, 119, 234, 155, 104, 39, 14, 52, 65, 27,
    96, 203, 74, 167, 229, 13, 195, 224, 249, 62, 196, 187, 1, 189, 217, 194, 217, 234, 211, 68,
    122, 141, 147, 59, 55, 153, 190, 0, 56, 230, 131, 167, 122, 49, 35, 215, 191, 36, 44, 246, 19,
    28, 110, 232, 209, 88, 193, 220, 166, 176, 223, 209, 16, 207, 206, 79, 106, 54, 208, 75, 166,
    120, 206, 34, 220, 139, 190, 76, 48, 85, 54, 146, 75, 111, 225, 119, 155, 250, 137, 51, 28, 85,
    69, 173, 89, 219, 55, 245, 244, 30, 186, 152, 199, 13, 118, 87, 161, 66, 203, 247, 25, 104, 98,
    33, 209, 13, 93, 237, 155, 165, 13, 10, 72, 155, 151, 199, 150, 185, 19, 188, 5, 134, 54, 135,
    92, 252, 174, 147, 185, 11, 138, 192, 82, 178, 45, 28, 89, 231, 132, 169, 145, 23, 26, 78, 154,
    120, 134, 174, 25, 48, 140, 180, 30, 123, 88, 215, 136, 134, 169, 230, 82, 166, 198, 81, 129,
    176, 121, 86, 27, 84, 150, 8, 226, 96, 89, 149, 224, 239, 100, 237, 87, 76, 154, 132, 119, 196,
    10, 229, 229, 0, 212, 163, 173, 249, 141, 97, 109, 9, 177, 165, 50, 97, 38, 21, 103, 251, 33,
    250, 60, 17, 180, 10, 135, 29, 175, 166, 195, 179, 78, 11, 118, 157, 145, 14, 200, 129, 59, 112,
    85, 19, 209, 204, 22, 140, 241, 212, 121, 198, 252, 25, 48, 179, 182, 83, 16, 181, 189, 114,
    186, 133, 254, 143, 193, 130, 27, 245, 174, 160, 223, 148, 116, 143, 25, 138, 17, 41, 109, 164,
    100, 197, 72, 200, 239, 140, 174, 34, 150, 155, 125, 13, 180, 239, 14, 165, 25, 106, 73, 175,
    115, 59, 179, 235, 223, 81, 199, 48, 202, 140, 15, 226, 76, 195, 127, 242, 165, 29, 207, 23, 27,
    219, 83, 187, 112, 253, 164, 83, 234, 210, 250, 126, 179, 220, 93, 53, 46, 219, 32, 180, 216,
    36, 43, 40, 71, 6, 22, 213, 226, 10, 53, 231, 66, 190, 215, 251, 130, 253, 148, 121, 183, 86,
    76, 244, 90, 204, 92, 52, 166, 224, 68, 244, 80, 39, 129, 80, 20, 202, 107, 217, 241, 127, 108,
    40, 191, 254, 18, 163, 205, 226, 128, 112, 167, 99, 244, 169, 224, 91, 197, 132, 246, 162, 240,
    6, 85, 148, 11, 178, 138, 150, 194, 54, 206, 15, 122, 166, 223, 186, 41, 194, 10, 94, 93, 138,
    41, 42, 162, 198, 104, 236, 157, 193, 195, 167, 125, 29, 74, 175, 255, 0, 167, 28, 56, 10, 80,
    130, 187, 234, 196, 130, 181, 107, 246, 63, 39, 234, 172, 180, 4, 175, 123, 162, 88, 134, 197,
    46, 81, 103, 116, 139, 1, 2, 4, 225, 165, 194, 15, 206, 201, 154, 214, 62, 83, 137, 128, 156,
    107, 119, 9, 48, 80, 157, 146, 112, 237, 232, 66, 101, 129, 89, 189, 53, 208, 9, 41, 247, 12,
    217, 150, 121, 53, 95, 192, 223, 167, 18, 63, 39, 35, 244, 233, 126, 46, 248, 74, 28, 84, 246,
    204, 80, 117, 224, 144, 188, 182, 192, 107, 202, 223, 155, 92, 17, 64, 154, 23, 204, 52, 140,
    73, 81, 47, 54, 191, 89, 178, 188, 117, 203, 202, 98, 112, 238, 16, 18, 94, 121, 0, 67, 74, 116,
    42, 52, 225, 162, 249, 184, 68, 210, 119, 199, 241, 143, 239, 205, 198, 74, 229, 202, 107, 29,
    75, 83,
];

/// Post-quantum QUIC configuration bundle.
///
/// Both client and server configs enforce X25519MLKEM768 as the sole
/// key exchange group and use MTU 1200 for safe PQ handshake traversal.
pub struct PqQuicConfig {
    pub client_config: quinn::ClientConfig,
    pub server_config: quinn::ServerConfig,
    pub cert_der: CertificateDer<'static>,
    pub bootstrap_mode: bool,
}

impl PqQuicConfig {
    /// Initialize the PQ-QUIC configuration.
    ///
    /// # Arguments
    /// * `bootstrap` - If true, enables "Ghost Mode" where identity proofs are omitted.
    pub fn new(bootstrap: bool) -> Result<Self> {
        // ── Step 1: Build a custom crypto provider with PQ-only KX ──────
        let mut provider = aws_lc_rs::default_provider();

        // Force ONLY the hybrid PQ group — no classical fallback
        provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];

        let provider = Arc::new(provider);

        // Install as process-wide default (idempotent — ignores if already set)
        let _ = rustls::crypto::CryptoProvider::install_default((*provider).clone());

        if bootstrap {
            info!("[TRANSPORT] Initializing Bootstrap Mode (Ghost Keys active)");
        }

        // ── Step 2: Generate ephemeral self-signed certificate ──────────
        // This acts as our "Ghost Key" for the bootstrap handshake.
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["ghost-node.local".into()])
                .map_err(|e| anyhow!("Ghost certificate generation failed: {e}"))?;

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der =
            PrivatePkcs8KeyDer::from(key_pair.serialize_der());

        // ── Step 3: Build TLS server config ─────────────────────────────
        let server_crypto = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .context("Failed to set protocol versions")?
            .with_no_client_auth() // Mandatory for Ghost Mode
            .with_single_cert(vec![cert_der.clone()], key_der.into())
            .context("Failed to build server TLS config")?;

        // ── Step 4: Build TLS client config (skip cert verification) ────
        let client_crypto = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .context("Failed to set protocol versions")?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification(provider.clone())))
            .with_no_client_auth();

        // ── Step 5: Build QUIC configs with MTU constraints ─────────────
        let mut transport = quinn::TransportConfig::default();
        transport.initial_mtu(1200);
        transport.min_mtu(1200);

        let mut mtu_discovery = quinn::MtuDiscoveryConfig::default();
        mtu_discovery.upper_bound(1452);
        transport.mtu_discovery_config(Some(mtu_discovery));

        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30))
                .map_err(|e| anyhow!("Invalid idle timeout: {e}"))?,
        ));

        let transport = Arc::new(transport);

        let quic_client =
            QuicClientConfig::try_from(client_crypto).context("QuicClientConfig creation failed")?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client));
        client_config.transport_config(transport.clone());

        let quic_server =
            QuicServerConfig::try_from(server_crypto).context("QuicServerConfig creation failed")?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
        server_config.transport_config(transport);

        if bootstrap {
            info!("[TRANSPORT] Bootstrap QUIC established via Ghost Key.");
        }

        Ok(Self {
            client_config,
            server_config,
            cert_der,
            bootstrap_mode: bootstrap,
        })
    }
}

// ── Skip TLS certificate verification (auth at DID layer) ──────────────────

/// A dangerous certificate verifier that accepts all server certificates.
///
/// # Safety
///
/// This is intentional for P2P connections where there is no CA infrastructure.
/// Authentication is performed at the application layer via ML-DSA-65 DID
/// identity verification after the encrypted tunnel is established.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // DID-layer authentication will verify the peer's identity
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pq_quic_config_creation() {
        let config = PqQuicConfig::new();
        assert!(config.is_ok(), "PqQuicConfig should initialize successfully");
    }
}

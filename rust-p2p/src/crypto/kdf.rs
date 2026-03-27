use hkdf::Hkdf;
use sha2::Sha256;
use super::AesKeyBytes;

const HKDF_SALT: &[u8] = b"p2pfileshare-v1-salt";
const HKDF_INFO: &[u8] = b"p2pfileshare-v1-session-keys";

/// Derives two AES-256 keys (initiator-to-responder and responder-to-initiator)
/// from the X25519 shared secret.
pub fn derive_session_keys(shared_secret: &[u8; 32]) -> (AesKeyBytes, AesKeyBytes) {
    // Instantiate HKDF with SHA-256 and the salt
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret);
    
    let mut output = [0u8; 64];
    // Expand using the spec's exact info string
    hkdf.expand(HKDF_INFO, &mut output)
        .expect("HKDF expansion should not fail for 64 bytes");

    let mut initiator_key = [0u8; 32];
    let mut responder_key = [0u8; 32];
    
    // Split the 64 bytes into two 32-byte keys
    initiator_key.copy_from_slice(&output[0..32]);
    responder_key.copy_from_slice(&output[32..64]);

    (initiator_key, responder_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_derivation_determinism() {
        let shared_secret = [0x42; 32];
        let (tx1, rx1) = derive_session_keys(&shared_secret);
        let (tx2, rx2) = derive_session_keys(&shared_secret);

        assert_eq!(tx1, tx2, "HKDF should be deterministic");
        assert_eq!(rx1, rx2, "HKDF should be deterministic");
        assert_ne!(tx1, rx1, "TX and RX keys must be distinct");
    }

    #[test]
    fn test_hkdf_different_secrets() {
        let (tx1, _) = derive_session_keys(&[0x01; 32]);
        let (tx2, _) = derive_session_keys(&[0x02; 32]);
        assert_ne!(tx1, tx2, "Different secrets must yield different keys");
    }
}
use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use rand_core::OsRng;
use super::{Ed25519PublicKeyBytes, X25519PublicKeyBytes};

/// Generates a long-term Ed25519 identity keypair.
/// We return the SigningKey (private) and the raw 32-byte public key.
pub fn generate_identity_keypair() -> (SigningKey, Ed25519PublicKeyBytes) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let public_key: VerifyingKey = signing_key.verifying_key();
    
    (signing_key, public_key.to_bytes())
}

/// Generates a short-lived X25519 ephemeral keypair for a single session.
pub fn generate_ephemeral_keypair() -> (EphemeralSecret, X25519PublicKeyBytes) {
    let mut csprng = OsRng;
    let secret = EphemeralSecret::random_from_rng(&mut csprng);
    let public = X25519PublicKey::from(&secret);
    
    (secret, public.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_key_generation() {
        let (secret, pub_bytes) = generate_identity_keypair();
        assert_eq!(pub_bytes.len(), 32, "Ed25519 public key must be 32 bytes");
        // Ensure the derived public key matches the bytes
        assert_eq!(secret.verifying_key().to_bytes(), pub_bytes);
    }

    #[test]
    fn test_ephemeral_key_generation() {
        let (_secret, pub_bytes) = generate_ephemeral_keypair();
        assert_eq!(pub_bytes.len(), 32, "X25519 public key must be 32 bytes");
    }
}
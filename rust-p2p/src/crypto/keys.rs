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
        let (secret, pub_key) = generate_identity_keypair();
        assert_eq!(pub_key.len(), 32);
        
        // Ensure the key can actually sign and verify
        use ed25519_dalek::{Signer, Verifier};
        let message = b"test message";
        let signature = secret.sign(message);
        let verifier = ed25519_dalek::VerifyingKey::from_bytes(&pub_key).unwrap();
        assert!(verifier.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_ephemeral_key_generation_and_dh() {
        let (alice_sec, alice_pub) = generate_ephemeral_keypair();
        let (bob_sec, bob_pub) = generate_ephemeral_keypair();

        // Alice computes shared secret using Bob's public key
        let alice_shared = alice_sec.diffie_hellman(&x25519_dalek::PublicKey::from(bob_pub));
        
        // Bob computes shared secret using Alice's public key
        let bob_shared = bob_sec.diffie_hellman(&x25519_dalek::PublicKey::from(alice_pub));

        // They must match perfectly
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }
}
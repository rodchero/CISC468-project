use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};
use rand::rngs::OsRng;

use crate::crypto::types::*;

pub struct EphemeralKeypair {
    pub secret: EphemeralSecret,
    pub public: PublicKey,
}

impl EphemeralKeypair {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = XPublicKey::from(&secret).to_bytes();

        Self { secret, public }
    }

    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> SharedSecret {
        let peer = XPublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&peer);
        shared.to_bytes()
    }
}


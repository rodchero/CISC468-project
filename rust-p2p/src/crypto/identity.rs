use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature as DalekSig};
use rand::{RngCore, rngs::OsRng};

use crate::crypto::types::*;

pub struct IdentityKeypair {
    pub private: SigningKey,
    pub public: VerifyingKey,
}

impl IdentityKeypair {
    pub fn generate() -> Self {
        let mut rng_bytes = [0u8; 32];
        OsRng::fill_bytes(&mut OsRng, &mut rng_bytes);
        let private = SigningKey::from_bytes(&rng_bytes);
        let public = private.verifying_key();

        Self { private, public }
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        let sig: DalekSig = self.private.sign(msg);
        sig.to_bytes()
    }

    pub fn public_bytes(&self) -> PublicKey {
        self.public.to_bytes()
    }
}

pub fn verify(public: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    let pk = VerifyingKey::from_bytes(public).unwrap();
    let sig = DalekSig::from_bytes(sig);

    pk.verify(msg, &sig).is_ok()
}

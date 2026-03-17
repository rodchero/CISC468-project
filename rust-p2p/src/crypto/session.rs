use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::types::*;

const SALT: &[u8] = b"p2pfileshare-v1-salt";
const INFO: &[u8] = b"p2pfileshare-v1-session-keys";

pub struct SessionKeys {
    pub initiator_to_responder: AesKey,
    pub responder_to_initiator: AesKey,
}

pub fn derive_session_keys(shared: &SharedSecret) -> SessionKeys {
    let hk = Hkdf::<Sha256>::new(Some(SALT), shared);

    let mut okm = [0u8; 64];
    hk.expand(INFO, &mut okm).unwrap();

    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];

    k1.copy_from_slice(&okm[..32]);
    k2.copy_from_slice(&okm[32..]);

    SessionKeys {
        initiator_to_responder: k1,
        responder_to_initiator: k2,
    }
}
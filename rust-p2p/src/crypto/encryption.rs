use aes_gcm::{Aes256Gcm, KeyInit, Nonce as AesNonce};
use aes_gcm::aead::{Aead, Payload};

use crate::crypto::types::*;

pub fn encrypt(
    key: &AesKey,
    nonce: &Nonce,
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    cipher.encrypt(AesNonce::from_slice(nonce), plaintext).unwrap()
}

pub fn decrypt(
    key: &AesKey,
    nonce: &Nonce,
    ciphertext: &[u8],
) -> Result<Vec<u8>, ()> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();

    cipher
        .decrypt(AesNonce::from_slice(nonce), ciphertext)
        .map_err(|_| ())
}

pub fn nonce_from_counter(counter: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}


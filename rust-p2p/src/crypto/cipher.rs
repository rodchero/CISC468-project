use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use super::AesKeyBytes;
use crate::error::P2pError; 

fn build_nonce(counter: u64) -> [u8; 12] {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&counter.to_be_bytes());
    nonce_bytes
}

pub fn encrypt_message(key: &AesKeyBytes, counter: u64, plaintext: &[u8]) -> Result<Vec<u8>, P2pError> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce_bytes = build_nonce(counter);
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher.encrypt(nonce, plaintext)
        // Map the library's generic error into our specific spec-defined error!
        .map_err(|_| P2pError::DecryptionFailed) 
}

pub fn decrypt_message(key: &AesKeyBytes, counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>, P2pError> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce_bytes = build_nonce(counter);
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher.decrypt(nonce, ciphertext)
        // If decryption fails (wrong key, bad tag, wrong counter), 
        // we throw the exact error the spec demands.
        .map_err(|_| P2pError::DecryptionFailed)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption_cycle() {
        let key = [1u8; 32];
        let counter = 1;
        let plaintext = b"Hello, Python peer!";

        // Encrypt
        let ciphertext = encrypt_message(&key, counter, plaintext).unwrap();
        assert_ne!(plaintext.as_slice(), ciphertext.as_slice());

        // Decrypt
        let decrypted = decrypt_message(&key, counter, &ciphertext).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_decryption_fails_with_wrong_counter() {
        let key = [1u8; 32];
        let plaintext = b"Secret data";
        
        let ciphertext = encrypt_message(&key, 5, plaintext).unwrap();
        
        // Attempt to decrypt with counter 6
        let result = decrypt_message(&key, 6, &ciphertext);
        assert!(result.is_err(), "Decryption should fail with incorrect nonce/counter");
    }
}
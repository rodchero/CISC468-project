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
        let key = [0xAA; 32];
        let plaintext = b"Top secret file chunk";
        let counter = 5;

        let ciphertext = encrypt_message(&key, counter, plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);

        let decrypted = decrypt_message(&key, counter, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decryption_fails_with_wrong_counter_or_key() {
        let key = [0xAA; 32];
        let wrong_key = [0xBB; 32];
        let plaintext = b"Data";
        
        let ciphertext = encrypt_message(&key, 1, plaintext).unwrap();

        // Wrong counter should fail (Nonce mismatch)
        assert!(decrypt_message(&key, 2, &ciphertext).is_err());
        
        // Wrong key should fail
        assert!(decrypt_message(&wrong_key, 1, &ciphertext).is_err());
    }
}
pub mod file_sys;
pub mod local_db;

use argon2::{Argon2, Params};
use aes_gcm::{
    aead::{Aead, KeyInit, AeadCore},
    Aes256Gcm, Nonce,
};
use rand_core::OsRng;

use crate::crypto::AesKeyBytes;
use crate::error::P2pError;

/// Derives a 32-byte local master encryption key from a user password and a random 16-byte salt.
/// Conforms to Spec Requirement 8: Argon2id (memory: 64 MB, iterations: 3, parallelism: 1).
pub fn derive_local_master_key(password: &str, salt: &[u8]) -> Result<AesKeyBytes, P2pError> {
    // 65536 KB = 64 MB 
    let params = Params::new(65536, 3, 1, Some(32)).map_err(|e| {
        P2pError::IoError(format!("Invalid Argon2 parameters: {}", e))
    })?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );

    let mut master_key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut master_key).map_err(|e| {
        P2pError::IoError(format!("Failed to derive master key: {}", e))
    })?;

    Ok(master_key)
}

/// Encrypts local data (like private keys or shared files) using the master key.
/// Prepends a fresh random 12-byte nonce to the resulting ciphertext.
pub fn encrypt_local_data(master_key: &AesKeyBytes, plaintext: &[u8]) -> Result<Vec<u8>, P2pError> {
    let cipher = Aes256Gcm::new(master_key.into());
    
    // Generate a secure random 12-byte nonce 
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt the data
    let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|_| {
        P2pError::DecryptionFailed // Reusing standard error for crypto failure
    })?;

    // Combine nonce + ciphertext so we can decrypt it later
    let mut stored_data = Vec::with_capacity(12 + ciphertext.len());
    stored_data.extend_from_slice(nonce.as_slice());
    stored_data.extend_from_slice(&ciphertext);

    Ok(stored_data)
}

/// Decrypts local data by extracting the 12-byte nonce from the front of the data.
pub fn decrypt_local_data(master_key: &AesKeyBytes, stored_data: &[u8]) -> Result<Vec<u8>, P2pError> {
    if stored_data.len() < 12 {
        return Err(P2pError::InvalidMessage); // Data is too short to even contain a nonce
    }

    // Split the data back into the nonce and the actual ciphertext
    let (nonce_bytes, ciphertext) = stored_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new(master_key.into());

    cipher.decrypt(nonce, ciphertext).map_err(|_| P2pError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id_derivation() {
        let password = "super_secret_password";
        let salt = b"random_16_byte_salt_"; // Must be exactly 16 bytes 

        let key1 = derive_local_master_key(password, salt).expect("Derivation should succeed");
        let key2 = derive_local_master_key(password, salt).expect("Derivation should succeed");

        // Same password and salt should yield the exact same 32-byte key [cite: 332]
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_local_encryption_decryption_cycle() {
        // Use a dummy master key for the test
        let master_key = [7u8; 32];
        let secret_file_data = b"This is a highly confidential shared file.";

        // Encrypt it
        let encrypted_data = encrypt_local_data(&master_key, secret_file_data).unwrap();
        
        // Ensure it's longer than the plaintext (12 bytes nonce + 16 bytes auth tag = 28 bytes overhead)
        assert_eq!(encrypted_data.len(), secret_file_data.len() + 28);

        // Decrypt it
        let decrypted_data = decrypt_local_data(&master_key, &encrypted_data).unwrap();
        
        assert_eq!(decrypted_data, secret_file_data);
    }

    #[test]
    fn test_local_decryption_fails_with_wrong_key() {
        let master_key = [7u8; 32];
        let wrong_key = [8u8; 32];
        let secret_file_data = b"Target data";

        let encrypted_data = encrypt_local_data(&master_key, secret_file_data).unwrap();
        
        // Attempting to decrypt with the wrong key should throw a DecryptionFailed error
        let result = decrypt_local_data(&wrong_key, &encrypted_data);
        assert!(matches!(result, Err(P2pError::DecryptionFailed)));
    }
}
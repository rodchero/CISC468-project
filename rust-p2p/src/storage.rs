use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use argon2::{Argon2, Params};
use aes_gcm::{
    aead::{Aead, KeyInit, rand_core::OsRng, AeadCore},
    Aes256Gcm, Nonce,
};
use rand_core::RngCore;

use crate::crypto::AesKeyBytes;
use crate::error::P2pError;

/// Central vault for managing encrypted local files.
pub struct SecureStorage {
    base_dir: PathBuf,
    master_key: AesKeyBytes,
}

impl SecureStorage {
    /// Initializes the secure storage manager.
    /// It derives the master key and ensures the base directory exists.
    pub fn new<P: AsRef<Path>>(
        storage_dir: P,
        password: &str,
        salt: &[u8],
    ) -> Result<Self, P2pError> {
        let base_dir = storage_dir.as_ref().to_path_buf();
        
        // Ensure the directory exists on disk
        if !base_dir.exists() {
            fs::create_dir_all(&base_dir).map_err(|e| {
                P2pError::IoError(format!("Failed to create storage directory: {}", e))
            })?;
        }

        let master_key = derive_local_master_key(password, salt)?;

        Ok(Self {
            base_dir,
            master_key,
        })
    }

    /// Helper to securely generate a random 16-byte salt for new users.
    /// This should be saved to disk in plaintext so it can be re-used on login.
    pub fn generate_salt() -> [u8; 16] {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        salt
    }

    /// Encrypts plaintext bytes and writes them to a file inside the storage directory.
    pub fn write_file(&self, filename: &str, plaintext: &[u8]) -> Result<(), P2pError> {
        let file_path = self.base_dir.join(filename);
        let encrypted_data = encrypt_local_data(&self.master_key, plaintext)?;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path)
            .map_err(|e| P2pError::IoError(format!("Failed to open file for writing: {}", e)))?;

        file.write_all(&encrypted_data)
            .map_err(|e| P2pError::IoError(format!("Failed to write encrypted data: {}", e)))?;

        Ok(())
    }

    /// Reads an encrypted file from disk and decrypts it back to plaintext.
    pub fn read_file(&self, filename: &str) -> Result<Vec<u8>, P2pError> {
        let file_path = self.base_dir.join(filename);

        if !file_path.exists() {
            return Err(P2pError::FileNotFound);
        }

        let mut file = File::open(&file_path)
            .map_err(|e| P2pError::IoError(format!("Failed to open file for reading: {}", e)))?;

        let mut encrypted_data = Vec::new();
        file.read_to_end(&mut encrypted_data)
            .map_err(|e| P2pError::IoError(format!("Failed to read file data: {}", e)))?;

        decrypt_local_data(&self.master_key, &encrypted_data)
    }

    /// Deletes a file from the secure storage directory.
    pub fn delete_file(&self, filename: &str) -> Result<(), P2pError> {
        let file_path = self.base_dir.join(filename);
        if file_path.exists() {
            fs::remove_file(&file_path)
                .map_err(|e| P2pError::IoError(format!("Failed to delete file: {}", e)))?;
        }
        Ok(())
    }
}

/// Derives a 32-byte local master encryption key using Argon2id.
pub fn derive_local_master_key(password: &str, salt: &[u8]) -> Result<AesKeyBytes, P2pError> {
    // Spec Requirement: 64 MB (65536 KB), 3 iterations, parallelism 1
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

/// Encrypts data with a fresh random 12-byte nonce prepended to the ciphertext.
fn encrypt_local_data(master_key: &AesKeyBytes, plaintext: &[u8]) -> Result<Vec<u8>, P2pError> {
    let cipher = Aes256Gcm::new(master_key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|_| {
        P2pError::DecryptionFailed
    })?;

    let mut stored_data = Vec::with_capacity(12 + ciphertext.len());
    stored_data.extend_from_slice(nonce.as_slice());
    stored_data.extend_from_slice(&ciphertext);

    Ok(stored_data)
}

/// Extracts the 12-byte nonce and decrypts the remaining ciphertext.
fn decrypt_local_data(master_key: &AesKeyBytes, stored_data: &[u8]) -> Result<Vec<u8>, P2pError> {
    if stored_data.len() < 12 {
        return Err(P2pError::InvalidMessage); 
    }

    let (nonce_bytes, ciphertext) = stored_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(master_key.into());

    cipher.decrypt(nonce, ciphertext).map_err(|_| P2pError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir; 

    #[test]
    fn test_secure_storage_read_write_cycle() {
        // Create a temporary directory that will automatically be deleted after the test
        let dir = tempdir().unwrap();
        let password = "test_password";
        let salt = SecureStorage::generate_salt();

        // Initialize the storage vault
        let storage = SecureStorage::new(dir.path(), password, &salt).unwrap();

        let filename = "trusted_contacts.db";
        let secret_data = b"Alice: KeyA, Bob: KeyB";

        // Write the encrypted file
        storage.write_file(filename, secret_data).expect("Should write successfully");

        // Read it back
        let retrieved_data = storage.read_file(filename).expect("Should read successfully");
        
        assert_eq!(retrieved_data, secret_data);

        // Verify the file actually exists on disk
        let file_path = dir.path().join(filename);
        assert!(file_path.exists());

        // Attempting to read it as plaintext directly from disk should fail to match
        let raw_disk_bytes = fs::read(&file_path).unwrap();
        assert_ne!(raw_disk_bytes, secret_data);
    }
}
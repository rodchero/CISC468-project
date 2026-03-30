use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use crate::storage::SecureStorage;
use crate::error::P2pError;

const TRUST_DB_FILE: &str = "trusted_peers.json";

/// The structure that actually gets serialized to JSON and encrypted.
#[derive(Serialize, Deserialize, Default)]
pub struct TrustDatabase {
    // Maps a peer's network identifier (e.g., IP address) to their 32-byte public key
    pub known_peers: HashMap<String, Vec<u8>>,
}

/// Manages the TOFU logic and synchronizes with SecureStorage.
pub struct TrustStore<'a> {
    storage: &'a SecureStorage,
    db: TrustDatabase,
}

impl<'a> TrustStore<'a> {
    /// Loads the existing trust database from the encrypted vault, or creates a fresh one.
    pub fn new(storage: &'a SecureStorage) -> Result<Self, P2pError> {
        let db = match storage.read_file(TRUST_DB_FILE) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => TrustDatabase::default(), // Vault doesn't have the file yet
        };
        Ok(Self { storage, db })
    }

    /// Encrypts and writes the current state of the database to disk.
    fn save(&self) -> Result<(), P2pError> {
        let bytes = serde_json::to_vec(&self.db).map_err(|_| P2pError::InvalidMessage)?;
        self.storage.write_file(TRUST_DB_FILE, &bytes)
    }

    /// TOFU Logic: Verifies a key against the database, or trusts it if it's the first time.
    pub fn verify_or_trust_peer(&mut self, identifier: &str, peer_pub_key: &[u8; 32]) -> Result<(), P2pError> {
        match self.db.known_peers.get(identifier) {
            Some(known_key) => {
                if known_key == peer_pub_key {
                    println!("<< Peer '{}' verified successfully against local database.", identifier);
                    Ok(())
                } else {
                    println!("<< SECURITY ALERT: Key mismatch for peer '{}'!", identifier);
                    println!("<< This could be a Man-in-the-Middle attack or the peer rotated their keys.");
                    Err(P2pError::UntrustedKey)
                }
            }
            None => {
                println!("<< TOFU: First time connecting to '{}'. Saving public key to trust store...", identifier);
                self.db.known_peers.insert(identifier.to_string(), peer_pub_key.to_vec());
                self.save()?;
                Ok(())
            }
        }
    }

    /// Safely updates a peer's public key after a verified key rotation.
    pub fn update_peer_key(&mut self, identifier: &str, new_pub_key: &[u8; 32]) -> Result<(), P2pError> {
        self.db.known_peers.insert(identifier.to_string(), new_pub_key.to_vec());
        self.save()
    }

    /// Look up a public key by checking if its SHA-256 hash matches the fingerprint,
    /// or if the key itself perfectly matches the fingerprint.
    pub fn get_pubkey_by_fingerprint(&self, fingerprint: &[u8]) -> Option<Vec<u8>> {
        for key in self.db.known_peers.values() {
            let mut hasher = Sha256::new();
            hasher.update(key);
            let key_fp = hasher.finalize().to_vec();
            
            // Support both hashed fingerprints and raw pubkey fingerprints
            if key_fp == fingerprint || key == fingerprint { 
                return Some(key.clone());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::storage::SecureStorage;

    #[test]
    fn test_tofu_logic() {
        let dir = tempdir().unwrap();
        let salt = SecureStorage::generate_salt();
        let storage = SecureStorage::new(dir.path(), "pass", &salt).unwrap();
        let mut trust_store = TrustStore::new(&storage).unwrap();

        let ip = "192.168.1.5";
        let key1 = [0xAA; 32];
        let key2 = [0xBB; 32];

        // 1. First connection should succeed and save key1
        assert!(trust_store.verify_or_trust_peer(ip, &key1).is_ok());

        // 2. Second connection with SAME key should succeed
        assert!(trust_store.verify_or_trust_peer(ip, &key1).is_ok());

        // 3. Connection with CHANGED key should throw a security error
        assert!(trust_store.verify_or_trust_peer(ip, &key2).is_err());

        // 4. Manual key update should allow the new key
        trust_store.update_peer_key(ip, &key2).unwrap();
        assert!(trust_store.verify_or_trust_peer(ip, &key2).is_ok());
    }
}
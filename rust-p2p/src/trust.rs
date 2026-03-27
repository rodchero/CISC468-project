use std::collections::HashMap;
use serde::{Serialize, Deserialize};

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
                    println!("[+] TOFU: Peer '{}' verified successfully against local database.", identifier);
                    Ok(())
                } else {
                    println!("[-] SECURITY ALERT: Key mismatch for peer '{}'!", identifier);
                    println!("[-] This could be a Man-in-the-Middle attack or the peer rotated their keys.");
                    Err(P2pError::UntrustedKey)
                }
            }
            None => {
                println!("[*] TOFU: First time connecting to '{}'. Saving public key to trust store...", identifier);
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
}
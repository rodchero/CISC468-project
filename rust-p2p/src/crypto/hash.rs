use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::{self, Read};
use crate::crypto::Sha256HashBytes;

/// Hashes the raw bytes of a file on disk using SHA-256.
/// Requirement 10.1: SHA-256 hash of raw file bytes.
pub fn hash_file(file_path: &std::path::Path) -> io::Result<Sha256HashBytes> {
    let mut file = File::open(file_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192]; // Read in 8KB chunks for memory efficiency

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Ok(hash)
}

/// Computes the File ID exactly as mandated by the spec:
/// SHA-256 (filename || file_hash || file_size)
/// Requirement 10.2: File ID rule.
pub fn compute_file_id(filename: &str, file_hash: &Sha256HashBytes, file_size: u64) -> Sha256HashBytes {
    let mut hasher = Sha256::new();
    
    // 1. filename as UTF-8 bytes
    hasher.update(filename.as_bytes());
    // 2. file_hash as raw 32-byte digest
    hasher.update(file_hash);
    // 3. file_size as 8-byte big-endian unsigned integer
    hasher.update(&file_size.to_be_bytes());

    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_id_computation() {
        let filename = "test.txt";
        let hash = [1u8; 32];
        let size: u64 = 1024;
        
        let file_id = compute_file_id(filename, &hash, size);
        assert_eq!(file_id.len(), 32);
    }
}
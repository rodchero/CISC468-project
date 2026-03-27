use ed25519_dalek::{Signer, Verifier, Signature, SigningKey, VerifyingKey};
use crate::error::P2pError;
use crate::protocol::messages::{FileMetadata, KeyRotationNotice};

/// Helper function to build the exact canonical bytes for FileMetadata signing.
/// Matches Python format: owner_fingerprint || file_id || filename_utf8 || file_size_BE || file_hash || timestamp_BE
fn build_canonical_metadata_bytes(metadata: &FileMetadata) -> Vec<u8> {
    let mut buf = Vec::new();
    
    // 1. owner_fingerprint (raw bytes)
    buf.extend_from_slice(&metadata.owner_fingerprint);
    // 2. file_id (raw bytes)
    buf.extend_from_slice(&metadata.file_id);
    // 3. filename (UTF-8 bytes)
    buf.extend_from_slice(metadata.filename.as_bytes());
    // 4. file_size (8-byte big-endian)
    buf.extend_from_slice(&metadata.file_size.to_be_bytes());
    // 5. file_hash (raw bytes)
    buf.extend_from_slice(&metadata.file_hash);
    // 6. timestamp (8-byte big-endian)
    buf.extend_from_slice(&metadata.timestamp.to_be_bytes());
    
    buf
}

/// Helper function to build the exact canonical bytes for KeyRotationNotice signing.
/// Matches Python format: old_pubkey(32) || new_pubkey(32) || timestamp(8-byte BE)
fn build_canonical_key_rotation_bytes(notice: &KeyRotationNotice) -> Vec<u8> {
    // 32 bytes + 32 bytes + 8 bytes = 72 bytes total
    let mut buf = Vec::with_capacity(72); 
    
    // 1. old_pubkey (raw 32 bytes)
    buf.extend_from_slice(&notice.old_public_key);
    // 2. new_pubkey (raw 32 bytes)
    buf.extend_from_slice(&notice.new_public_key);
    // 3. timestamp (8-byte big-endian)
    buf.extend_from_slice(&notice.timestamp.to_be_bytes());
    
    buf
}

/// Signs the file metadata with the owner's identity key using canonical bytes.
pub fn sign_metadata(key: &SigningKey, metadata: &mut FileMetadata) -> Result<(), P2pError> {
    let canonical_bytes = build_canonical_metadata_bytes(metadata);
    
    let signature = key.sign(&canonical_bytes);
    metadata.owner_signature = signature.to_bytes().to_vec();
    
    Ok(())
}

/// Verifies that the metadata signature is authentic using the canonical bytes.
pub fn verify_metadata(metadata: &FileMetadata, owner_pub_key_bytes: &[u8; 32]) -> Result<(), P2pError> {
    let canonical_bytes = build_canonical_metadata_bytes(metadata);

    let sig = Signature::from_slice(&metadata.owner_signature)
        .map_err(|_| P2pError::InvalidFileSignature)?;
        
    let verifier = VerifyingKey::from_bytes(owner_pub_key_bytes)
        .map_err(|_| P2pError::UntrustedKey)?;

    verifier.verify(&canonical_bytes, &sig).map_err(|_| P2pError::InvalidFileSignature)
}

/// Verifies a Key Rotation Notice using canonical bytes to match the Python client.
pub fn verify_key_rotation(notice: &KeyRotationNotice) -> Result<(), P2pError> {
    // 1. Build the canonical bytes agreed upon with the Python client
    let canonical_bytes = build_canonical_key_rotation_bytes(notice);

    // 2. Extract the public keys
    let old_pub_key: [u8; 32] = notice.old_public_key.clone().try_into()
        .map_err(|_| P2pError::InvalidMessage)?;
    let new_pub_key: [u8; 32] = notice.new_public_key.clone().try_into()
        .map_err(|_| P2pError::InvalidMessage)?;

    // 3. Create verifiers
    let old_verifier = VerifyingKey::from_bytes(&old_pub_key)
        .map_err(|_| P2pError::KeyRotationInvalid)?;
    let new_verifier = VerifyingKey::from_bytes(&new_pub_key)
        .map_err(|_| P2pError::KeyRotationInvalid)?;

    // 4. Extract signatures
    let old_sig = Signature::from_slice(&notice.old_signature)
        .map_err(|_| P2pError::KeyRotationInvalid)?;
    let new_sig = Signature::from_slice(&notice.new_signature)
        .map_err(|_| P2pError::KeyRotationInvalid)?;

    // 5. Verify BOTH signatures against the canonical bytes
    old_verifier.verify(&canonical_bytes, &old_sig).map_err(|_| P2pError::KeyRotationInvalid)?;
    new_verifier.verify(&canonical_bytes, &new_sig).map_err(|_| P2pError::KeyRotationInvalid)?;

    Ok(())
}

/// (Optional) Generates a Key Rotation Notice and signs it with both the old and new keys.
pub fn sign_key_rotation(
    old_key: &SigningKey, 
    new_key: &SigningKey, 
    timestamp: u64
) -> Result<KeyRotationNotice, P2pError> {
    let mut notice = KeyRotationNotice {
        old_public_key: old_key.verifying_key().to_bytes().to_vec(),
        new_public_key: new_key.verifying_key().to_bytes().to_vec(),
        timestamp,
        old_signature: vec![],
        new_signature: vec![],
    };

    let canonical_bytes = build_canonical_key_rotation_bytes(&notice);

    notice.old_signature = old_key.sign(&canonical_bytes).to_bytes().to_vec();
    notice.new_signature = new_key.sign(&canonical_bytes).to_bytes().to_vec();

    Ok(notice)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::generate_identity_keypair;
    use rand_core::OsRng;

    #[test]
    fn test_metadata_signing_and_verification() {
        let (secret, pub_key) = generate_identity_keypair();
        
        let mut metadata = FileMetadata {
            owner_fingerprint: pub_key.to_vec(),
            file_id: vec![1, 2, 3],
            filename: "doc.txt".to_string(),
            file_size: 1024,
            file_hash: vec![0xAA; 32],
            timestamp: 100000,
            owner_signature: vec![],
        };

        sign_metadata(&secret, &mut metadata).unwrap();
        assert!(!metadata.owner_signature.is_empty());

        // Should verify successfully
        assert!(verify_metadata(&metadata, &pub_key).is_ok());

        // Tampering with the filename should break the signature
        metadata.filename = "malicious.txt".to_string();
        assert!(verify_metadata(&metadata, &pub_key).is_err());
    }

    #[test]
    fn test_key_rotation_verification() {
        let old_key = SigningKey::generate(&mut OsRng);
        let new_key = SigningKey::generate(&mut OsRng);
        
        let notice = sign_key_rotation(&old_key, &new_key, 123456).unwrap();
        assert!(verify_key_rotation(&notice).is_ok());
    }
}
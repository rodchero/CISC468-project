use ed25519_dalek::{Signer, Verifier, Signature, SigningKey, VerifyingKey};
use prost::Message;
use crate::error::P2pError;
use crate::protocol::messages::{FileMetadata, KeyRotationNotice};

/// Signs the file metadata with the owner's identity key.
/// Requirement 10.3: The owner signs the canonical metadata bytes with Ed25519.
pub fn sign_metadata(key: &SigningKey, metadata: &mut FileMetadata) -> Result<(), P2pError> {
    // 1. Clear any existing signature so we sign the raw data
    metadata.owner_signature.clear();
    
    // 2. Serialize to bytes
    let mut buf = Vec::new();
    metadata.encode(&mut buf).map_err(|_| P2pError::InvalidMessage)?;
    
    // 3. Sign the bytes and attach
    let signature = key.sign(&buf);
    metadata.owner_signature = signature.to_bytes().to_vec();
    
    Ok(())
}

/// Verifies that the metadata signature is authentic and hasn't been tampered with.
/// Requirement 10.4: Verify the owner's signature on the metadata.
pub fn verify_metadata(metadata: &FileMetadata, owner_pub_key_bytes: &[u8; 32]) -> Result<(), P2pError> {
    // 1. We must verify against a copy that has the signature field cleared
    let mut meta_copy = metadata.clone();
    let provided_signature = meta_copy.owner_signature.clone();
    meta_copy.owner_signature.clear();

    let mut buf = Vec::new();
    meta_copy.encode(&mut buf).map_err(|_| P2pError::InvalidMessage)?;

    // 2. Load the signature and the public key
    let sig = Signature::from_slice(&provided_signature).map_err(|_| P2pError::InvalidFileSignature)?;
    let verifier = VerifyingKey::from_bytes(owner_pub_key_bytes).map_err(|_| P2pError::UntrustedKey)?;

    // 3. Verify
    verifier.verify(&buf, &sig).map_err(|_| P2pError::InvalidFileSignature)
}

/// Verifies a Key Rotation Notice. 
/// Requirement 11.2: It must be validly signed by BOTH the old key and the new key.
pub fn verify_key_rotation(notice: &KeyRotationNotice) -> Result<(), P2pError> {
    // 1. Create a copy of the notice with both signatures cleared to get the canonical bytes
    let mut notice_copy = notice.clone();
    let old_sig_bytes = notice_copy.old_signature.clone();
    let new_sig_bytes = notice_copy.new_signature.clone();
    notice_copy.old_signature.clear();
    notice_copy.new_signature.clear();

    let mut buf = Vec::new();
    notice_copy.encode(&mut buf).map_err(|_| P2pError::InvalidMessage)?;

    // 2. Load the keys
    let old_pub_key: [u8; 32] = notice.old_public_key.clone().try_into().map_err(|_| P2pError::InvalidMessage)?;
    let new_pub_key: [u8; 32] = notice.new_public_key.clone().try_into().map_err(|_| P2pError::InvalidMessage)?;

    let old_verifier = VerifyingKey::from_bytes(&old_pub_key).map_err(|_| P2pError::KeyRotationInvalid)?;
    let new_verifier = VerifyingKey::from_bytes(&new_pub_key).map_err(|_| P2pError::KeyRotationInvalid)?;

    let old_sig = Signature::from_slice(&old_sig_bytes).map_err(|_| P2pError::KeyRotationInvalid)?;
    let new_sig = Signature::from_slice(&new_sig_bytes).map_err(|_| P2pError::KeyRotationInvalid)?;

    // 3. Verify BOTH signatures against the canonical bytes
    old_verifier.verify(&buf, &old_sig).map_err(|_| P2pError::KeyRotationInvalid)?;
    new_verifier.verify(&buf, &new_sig).map_err(|_| P2pError::KeyRotationInvalid)?;

    Ok(())
}
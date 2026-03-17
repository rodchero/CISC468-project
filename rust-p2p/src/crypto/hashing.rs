use sha2::{Sha256, Digest};
use crate::crypto::types::*;

pub fn sha256(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
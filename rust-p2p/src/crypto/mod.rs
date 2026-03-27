pub mod cipher;
pub mod hash;
pub mod kdf;
pub mod keys;

// Defining type aliases here makes our function signatures much cleaner
pub type Ed25519PublicKeyBytes = [u8; 32];
pub type X25519PublicKeyBytes = [u8; 32];
pub type AesKeyBytes = [u8; 32];
pub type Sha256HashBytes = [u8; 32];
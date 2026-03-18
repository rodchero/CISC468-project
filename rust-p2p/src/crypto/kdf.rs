use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{SaltString};
use rand::rngs::OsRng;

use crate::crypto::types::*;

pub fn derive_key(password: &str) -> (AesKey, String) {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    let hash = argon2.hash_password(password.as_bytes(), &salt).unwrap();

    let mut key = [0u8; 32];
    key.copy_from_slice(&hash.hash.unwrap().as_bytes()[..32]);

    (key, salt.to_string())
}
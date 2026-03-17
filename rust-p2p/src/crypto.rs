pub mod encryption;
pub mod hashing;
pub mod identity;
pub mod kdf;
pub mod key_exchange;
pub mod session;
pub mod types;



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify() {
        let kp = IdentityKeypair::generate();
        let msg = b"hello";

        let sig = kp.sign(msg);
        assert!(verify(&kp.public_bytes(), msg, &sig));
    }

    #[test]
    fn shared_secret_matches() {
        let a = EphemeralKeypair::generate();
        let b = EphemeralKeypair::generate();

        let s1 = a.diffie_hellman(&b.public);
        let s2 = b.diffie_hellman(&a.public);

        assert_eq!(s1, s2);
    }

    #[test]
    fn hkdf_deterministic() {
        let shared = [1u8; 32];

        let k1 = derive_session_keys(&shared);
        let k2 = derive_session_keys(&shared);

        assert_eq!(k1.initiator_to_responder, k2.initiator_to_responder);
    }

    #[test]
    fn encrypt_decrypt() {
        let key = [0u8; 32];
        let nonce = nonce_from_counter(1);

        let msg = b"secret";
        let ct = encrypt(&key, &nonce, msg);
        let pt = decrypt(&key, &nonce, &ct).unwrap();

        assert_eq!(msg, pt.as_slice());
    }

    #[test]
    fn hash_consistency() {
        let h1 = sha256(b"abc");
        let h2 = sha256(b"abc");

        assert_eq!(h1, h2);
    }
}

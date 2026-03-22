use std::io::{Read, Write};
use prost::Message;
use sha2::{Sha256, Digest};
use ed25519_dalek::{Signer, Verifier, Signature};
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::error::P2pError;
use crate::crypto::keys::generate_ephemeral_keypair;
use crate::crypto::kdf::derive_session_keys;
use crate::crypto::{AesKeyBytes, Ed25519PublicKeyBytes};
use crate::network::tcp::{frame_message, read_framed_message};

// Import our generated protobuf structs
use crate::protocol::messages::{
    p2p_message, AuthSignature, Hello, P2pMessage
};

const PROTOCOL_VERSION: u32 = 1;

/// Helper to build and hash the exact transcript bytes required by the spec.
/// **INTEROP NOTE:** You must confirm with Youssef (Python dev) how he encodes 
/// the protocol_version. Here we use 4-byte big-endian to match Protobuf's uint32.
fn compute_transcript_hash(
    initiator_id: &[u8; 32],
    initiator_eph: &[u8; 32],
    responder_id: &[u8; 32],
    responder_eph: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    
    // 1. Protocol version
    hasher.update(&PROTOCOL_VERSION.to_be_bytes());
    // 2. Initiator identity pub
    hasher.update(initiator_id);
    // 3. Initiator ephemeral pub
    hasher.update(initiator_eph);
    // 4. Responder identity pub
    hasher.update(responder_id);
    // 5. Responder ephemeral pub
    hasher.update(responder_eph);
    
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Helper to send a protobuf message over a stream
fn send_msg<S: Write>(stream: &mut S, payload: p2p_message::Payload) -> Result<(), P2pError> {
    let msg = P2pMessage { payload: Some(payload) };
    let mut buf = Vec::new();
    msg.encode(&mut buf).map_err(|_| P2pError::InvalidMessage)?;
    
    let framed = frame_message(&buf);
    stream.write_all(&framed).map_err(|e| P2pError::IoError(e.to_string()))?;
    stream.flush().map_err(|e| P2pError::IoError(e.to_string()))?;
    Ok(())
}

/// Runs the handshake as the Initiator (the peer making the connection).
/// Returns: (Tx Session Key, Rx Session Key, Peer's Identity Key)
pub fn run_initiator<S: Read + Write>(
    stream: &mut S,
    my_id_key: &ed25519_dalek::SigningKey,
    my_display_name: &str,
) -> Result<(AesKeyBytes, AesKeyBytes, Ed25519PublicKeyBytes), P2pError> {
    let my_id_pub = my_id_key.verifying_key().to_bytes();
    let (my_eph_sec, my_eph_pub) = generate_ephemeral_keypair();

    // STEP 3: Send Hello
    send_msg(stream, p2p_message::Payload::Hello(Hello {
        protocol_version: PROTOCOL_VERSION,
        identity_public_key: my_id_pub.to_vec(),
        ephemeral_public_key: my_eph_pub.to_vec(),
        display_name: my_display_name.to_string(),
    }))?;

    // STEP 3: Receive Hello
    let resp_bytes = read_framed_message(stream)?;
    let resp_msg = P2pMessage::decode(&resp_bytes[..]).map_err(|_| P2pError::InvalidMessage)?;
    let peer_hello = match resp_msg.payload {
        Some(p2p_message::Payload::Hello(h)) => h,
        _ => return Err(P2pError::HandshakeFailed),
    };

    // Extract peer keys safely
    let peer_id_pub: [u8; 32] = peer_hello.identity_public_key.try_into().map_err(|_| P2pError::InvalidMessage)?;
    let peer_eph_pub_bytes: [u8; 32] = peer_hello.ephemeral_public_key.try_into().map_err(|_| P2pError::InvalidMessage)?;
    
    // STEP 4: Compute Shared Secret
    let peer_eph_pub = X25519PublicKey::from(peer_eph_pub_bytes);
    let shared_secret = my_eph_sec.diffie_hellman(&peer_eph_pub);

    // STEP 5 & 6: Build Transcript and Hash
    let transcript_hash = compute_transcript_hash(&my_id_pub, &my_eph_pub, &peer_id_pub, &peer_eph_pub_bytes);

    // STEP 7: Sign transcript hash
    let my_signature = my_id_key.sign(&transcript_hash);

    // STEP 8: Send AuthSignature
    send_msg(stream, p2p_message::Payload::AuthSignature(AuthSignature {
        signature: my_signature.to_bytes().to_vec(),
    }))?;

    // STEP 8: Receive peer's AuthSignature
    let auth_bytes = read_framed_message(stream)?;
    let auth_msg = P2pMessage::decode(&auth_bytes[..]).map_err(|_| P2pError::InvalidMessage)?;
    let peer_auth = match auth_msg.payload {
        Some(p2p_message::Payload::AuthSignature(a)) => a,
        _ => return Err(P2pError::HandshakeFailed),
    };

    // STEP 8: Verify Signature
    let peer_sig = Signature::from_slice(&peer_auth.signature).map_err(|_| P2pError::AuthFailed)?;
    let peer_verifier = ed25519_dalek::VerifyingKey::from_bytes(&peer_id_pub).map_err(|_| P2pError::AuthFailed)?;
    peer_verifier.verify(&transcript_hash, &peer_sig).map_err(|_| P2pError::AuthFailed)?;

    // STEP 10: Derive Session Keys
    let (initiator_tx, responder_tx) = derive_session_keys(shared_secret.as_bytes());

    // As initiator, our transmit key is initiator_tx, and receive key is responder_tx
    Ok((initiator_tx, responder_tx, peer_id_pub))
}

/// Runs the handshake as the Responder (the peer who received the connection).
pub fn run_responder<S: Read + Write>(
    stream: &mut S,
    my_id_key: &ed25519_dalek::SigningKey,
    my_display_name: &str,
) -> Result<(AesKeyBytes, AesKeyBytes, Ed25519PublicKeyBytes), P2pError> {
    let my_id_pub = my_id_key.verifying_key().to_bytes();
    let (my_eph_sec, my_eph_pub) = generate_ephemeral_keypair();

    // STEP 3: Receive Hello
    let req_bytes = read_framed_message(stream)?;
    let req_msg = P2pMessage::decode(&req_bytes[..]).map_err(|_| P2pError::InvalidMessage)?;
    let peer_hello = match req_msg.payload {
        Some(p2p_message::Payload::Hello(h)) => h,
        _ => return Err(P2pError::HandshakeFailed),
    };

    let peer_id_pub: [u8; 32] = peer_hello.identity_public_key.try_into().map_err(|_| P2pError::InvalidMessage)?;
    let peer_eph_pub_bytes: [u8; 32] = peer_hello.ephemeral_public_key.try_into().map_err(|_| P2pError::InvalidMessage)?;

    // STEP 3: Send Hello
    send_msg(stream, p2p_message::Payload::Hello(Hello {
        protocol_version: PROTOCOL_VERSION,
        identity_public_key: my_id_pub.to_vec(),
        ephemeral_public_key: my_eph_pub.to_vec(),
        display_name: my_display_name.to_string(),
    }))?;

    // STEP 4: Compute Shared Secret
    let peer_eph_pub = X25519PublicKey::from(peer_eph_pub_bytes);
    let shared_secret = my_eph_sec.diffie_hellman(&peer_eph_pub);

    // STEP 5 & 6: Build Transcript and Hash
    // NOTE: Initiator is always the peer here, we are the responder
    let transcript_hash = compute_transcript_hash(&peer_id_pub, &peer_eph_pub_bytes, &my_id_pub, &my_eph_pub);

    // STEP 8: Receive peer's AuthSignature FIRST
    let auth_bytes = read_framed_message(stream)?;
    let auth_msg = P2pMessage::decode(&auth_bytes[..]).map_err(|_| P2pError::InvalidMessage)?;
    let peer_auth = match auth_msg.payload {
        Some(p2p_message::Payload::AuthSignature(a)) => a,
        _ => return Err(P2pError::HandshakeFailed),
    };

    // STEP 8: Verify Signature
    let peer_sig = Signature::from_slice(&peer_auth.signature).map_err(|_| P2pError::AuthFailed)?;
    let peer_verifier = ed25519_dalek::VerifyingKey::from_bytes(&peer_id_pub).map_err(|_| P2pError::AuthFailed)?;
    peer_verifier.verify(&transcript_hash, &peer_sig).map_err(|_| P2pError::AuthFailed)?;

    // STEP 7 & 8: Sign and Send our AuthSignature
    let my_signature = my_id_key.sign(&transcript_hash);
    send_msg(stream, p2p_message::Payload::AuthSignature(AuthSignature {
        signature: my_signature.to_bytes().to_vec(),
    }))?;

    // STEP 10: Derive Session Keys
    let (initiator_tx, responder_tx) = derive_session_keys(shared_secret.as_bytes());

    // As responder, our transmit key is responder_tx, and receive key is initiator_tx
    Ok((responder_tx, initiator_tx, peer_id_pub))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn test_full_handshake_flow() {
        // 1. Setup simulated keys
        let mut rng1 = rand_core::OsRng;
        let init_key = ed25519_dalek::SigningKey::generate(&mut rng1);
        
        let mut rng2 = rand_core::OsRng;
        let resp_key = ed25519_dalek::SigningKey::generate(&mut rng2);

        // 2. Setup a local TCP connection
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // 3. Run Responder in a background thread
        let resp_key_clone = resp_key.clone();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            run_responder(&mut stream, &resp_key_clone, "Responder").unwrap()
        });

        // 4. Run Initiator in main thread
        let mut init_stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let init_result = run_initiator(&mut init_stream, &init_key, "Initiator").unwrap();

        let resp_result = handle.join().unwrap();

        // 5. Verify the derived keys match perfectly!
        let (init_tx, init_rx, init_peer_pub) = init_result;
        let (resp_tx, resp_rx, resp_peer_pub) = resp_result;

        // Initiator's Tx should be Responder's Rx
        assert_eq!(init_tx, resp_rx);
        // Initiator's Rx should be Responder's Tx
        assert_eq!(init_rx, resp_tx);
        
        // They should have correctly identified each other
        assert_eq!(init_peer_pub, resp_key.verifying_key().to_bytes());
        assert_eq!(resp_peer_pub, init_key.verifying_key().to_bytes());
    }
}
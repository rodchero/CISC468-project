use std::io::{Read, Write};
use prost::Message;

use crate::crypto::AesKeyBytes;
use crate::crypto::cipher::{encrypt_message, decrypt_message};
use crate::error::P2pError;
use crate::network::tcp::{frame_message, read_framed_message};
use crate::protocol::messages::{p2p_message, EncryptedMessage, P2pMessage};

/// Manages an active, encrypted P2P session after a successful handshake.
pub struct SecureSession<S> {
    stream: S,
    tx_key: AesKeyBytes,
    rx_key: AesKeyBytes,
    tx_counter: u64,
    expected_rx_counter: u64,
}

impl<S: Read + Write> SecureSession<S> {
    /// Creates a new secure session wrapping the network stream and the derived session keys.
    pub fn new(stream: S, tx_key: AesKeyBytes, rx_key: AesKeyBytes) -> Self {
        Self {
            stream,
            tx_key,
            rx_key,
            tx_counter: 0,         // Counters always start at 0
            expected_rx_counter: 0,
        }
    }

    /// Encrypts a payload, wraps it in an EncryptedMessage, and sends it over the stream.
    /// `msg_type` is a string identifier (e.g., "FileListRequest") so the receiver knows how to decode the plaintext.
    pub fn send_encrypted(&mut self, msg_type: &str, plaintext_payload: &[u8]) -> Result<(), P2pError> {
        // 1. Encrypt the raw protobuf bytes using our transmit key and current counter
        let ciphertext = encrypt_message(&self.tx_key, self.tx_counter, plaintext_payload)?;
        
        // 2. Build the 12-byte nonce explicitly for the protobuf message as requested by the spec
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&self.tx_counter.to_be_bytes());

        // 3. Construct the EncryptedMessage wrapper
        let enc_msg = EncryptedMessage {
            message_type: msg_type.to_string(),
            counter: self.tx_counter,
            nonce: nonce.to_vec(),
            ciphertext,
        };

        // 4. Wrap it in the master P2PMessage oneof
        let wrapper = P2pMessage {
            payload: Some(p2p_message::Payload::EncryptedMessage(enc_msg))
        };

        // 5. Serialize and frame it
        let mut buf = Vec::new();
        wrapper.encode(&mut buf).map_err(|_| P2pError::InvalidMessage)?;
        let framed = frame_message(&buf);

        // 6. Send over the network
        self.stream.write_all(&framed).map_err(|e| P2pError::IoError(e.to_string()))?;
        self.stream.flush().map_err(|e| P2pError::IoError(e.to_string()))?;

        // 7. Increment the counter to prevent nonce reuse!
        self.tx_counter += 1;

        Ok(())
    }

    /// Waits for an EncryptedMessage, verifies the counter, and decrypts the payload.
    /// Returns the message type string and the raw decrypted bytes.
    pub fn receive_encrypted(&mut self) -> Result<(String, Vec<u8>), P2pError> {
        // 1. Read the next framed message from the network
        let framed_bytes = read_framed_message(&mut self.stream)?;
        let wrapper = P2pMessage::decode(&framed_bytes[..]).map_err(|_| P2pError::InvalidMessage)?;

        // 2. Ensure it is actually an EncryptedMessage
        let enc_msg = match wrapper.payload {
            Some(p2p_message::Payload::EncryptedMessage(e)) => e,
            _ => return Err(P2pError::InvalidMessage), 
        };

        // 3. REPLAY PROTECTION: Reject duplicate or older counters
        if enc_msg.counter < self.expected_rx_counter {
            return Err(P2pError::DecryptionFailed); 
        }

        // 4. Decrypt using the receive key and the peer's counter
        let plaintext = decrypt_message(&self.rx_key, enc_msg.counter, &enc_msg.ciphertext)?;

        // 5. Update our expected counter to whatever they sent + 1.
        // (If they skipped a message, we accept the jump, but they can never go backward).
        self.expected_rx_counter = enc_msg.counter + 1;

        Ok((enc_msg.message_type, plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_secure_session_encryption_and_replay_protection() {
        let tx_key = [1u8; 32];
        let rx_key = [2u8; 32];
        let mut network_buffer = Cursor::new(Vec::new());

        let mut alice = SecureSession::new(&mut network_buffer, tx_key, rx_key);
        alice.send_encrypted("TestMsg", b"Data1").unwrap();
        alice.send_encrypted("TestMsg", b"Data2").unwrap();

        network_buffer.set_position(0);
        let mut bob = SecureSession::new(&mut network_buffer, rx_key, tx_key);
        
        let (_, msg1) = bob.receive_encrypted().unwrap();
        assert_eq!(msg1, b"Data1");
        assert_eq!(bob.expected_rx_counter, 1);

        let (_, msg2) = bob.receive_encrypted().unwrap();
        assert_eq!(msg2, b"Data2");
        assert_eq!(bob.expected_rx_counter, 2);
    }
}
use std::io::{Read};
use crate::error::P2pError;

/// Prepends a 4-byte unsigned big-endian length prefix to a payload.
/// This matches the exact framing format required by the interoperability spec.
pub fn frame_message(payload: &[u8]) -> Vec<u8> {
    // 1. Get the length as a 32-bit unsigned integer
    let len = payload.len() as u32;
    
    // 2. Convert to exactly 4 big-endian bytes
    let len_bytes = len.to_be_bytes();
    
    // 3. Create a buffer with enough capacity to hold both length and payload
    let mut framed = Vec::with_capacity(4 + payload.len());
    
    // 4. Append the length prefix, then the actual protobuf payload
    framed.extend_from_slice(&len_bytes);
    framed.extend_from_slice(payload);
    
    framed
}

/// Reads a fully framed message from any stream (TCP or in-memory buffer).
/// It first reads exactly 4 bytes to determine the length, then reads the payload.
pub fn read_framed_message<R: Read>(stream: &mut R) -> Result<Vec<u8>, P2pError> {
    // 1. Read the 4-byte length prefix
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| {
        P2pError::IoError(format!("Failed to read message length: {}", e))
    })?;

    // 2. Decode the big-endian bytes into a u32, then cast to usize for memory allocation
    let msg_len = u32::from_be_bytes(len_buf) as usize;

    // Prevent massive allocations if a malicious peer sends a huge length
    if msg_len > 100_000_000 { // 100 MB arbitrary safety limit
        return Err(P2pError::InvalidMessage);
    }

    // 3. Create a buffer of the exact size needed, filled with zeroes
    let mut payload_buf = vec![0u8; msg_len];

    // 4. Read exactly `msg_len` bytes from the network into our buffer
    stream.read_exact(&mut payload_buf).map_err(|e| {
        P2pError::IoError(format!("Failed to read message payload: {}", e))
    })?;

    Ok(payload_buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_frame_and_read_message() {
        let payload = b"Hello P2P Network";
        let framed = frame_message(payload);
        
        // 4 bytes length + payload
        assert_eq!(framed.len(), 4 + payload.len());
        
        // Ensure length prefix is correct (Big Endian)
        let expected_len = payload.len() as u32;
        assert_eq!(&framed[0..4], &expected_len.to_be_bytes());

        // Test reading it back
        let mut cursor = Cursor::new(framed);
        let read_back = read_framed_message(&mut cursor).unwrap();
        assert_eq!(read_back, payload);
    }

    #[test]
    fn test_read_framed_message_incomplete() {
        let mut cursor = Cursor::new(vec![0, 0, 0, 10, 1, 2, 3]); // Length 10, but only 3 bytes provided
        assert!(read_framed_message(&mut cursor).is_err());
    }
}
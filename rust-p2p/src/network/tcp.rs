use std::io::{Read, Write};
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

// --- Unit Tests ---
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_frame_message_adds_correct_length_prefix() {
        let payload = b"hello world"; // 11 bytes long
        let framed = frame_message(payload);

        // Total length should be 4 (prefix) + 11 (payload) = 15
        assert_eq!(framed.len(), 15);

        // The first 4 bytes should represent the number 11 in big-endian
        assert_eq!(&framed[0..4], &11u32.to_be_bytes());
        
        // The rest should be the payload
        assert_eq!(&framed[4..], payload);
    }

    #[test]
    fn test_read_framed_message_success() {
        // Create a fake network stream in memory using Cursor
        let original_payload = b"test payload";
        let framed_data = frame_message(original_payload);
        
        // Cursor implements the `Read` trait, so our function treats it like a TCP stream!
        let mut mock_stream = Cursor::new(framed_data);

        let result = read_framed_message(&mut mock_stream).expect("Reading should succeed");
        
        assert_eq!(result, original_payload);
    }

    #[test]
    fn test_read_framed_message_incomplete_payload() {
        let payload = b"12345";
        let mut framed_data = frame_message(payload);
        
        // Corrupt the data by dropping the last byte simulating a broken network connection
        framed_data.pop(); 

        let mut mock_stream = Cursor::new(framed_data);
        let result = read_framed_message(&mut mock_stream);
        
        // It should throw an IO error because it expected 5 bytes but only found 4
        assert!(matches!(result, Err(P2pError::IoError(_))));
    }
}
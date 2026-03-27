// src/protocol/messages.rs

// This macro finds the generated file `p2pfileshare.rs` in the build output directory
// and virtually pastes its contents right here.
include!(concat!(env!("OUT_DIR"), "/p2pfileshare.rs"));


#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn test_hello_serialization() {
        // 1. Create a Rust struct from the generated code
        let hello = Hello {
            protocol_version: 1,
            identity_public_key: vec![1, 2, 3, 4], // Fake key
            ephemeral_public_key: vec![5, 6, 7, 8], // Fake key
            display_name: "RustNode".to_string(),
        };

        // 2. Serialize it to bytes (what you'll send over TCP)
        let mut buf = Vec::new();
        hello.encode(&mut buf).unwrap();
        assert!(!buf.is_empty(), "Serialization should produce bytes");

        // 3. Deserialize it back to a Rust struct
        let decoded_hello = Hello::decode(buf.as_slice()).unwrap();
        assert_eq!(decoded_hello.display_name, "RustNode");
        assert_eq!(decoded_hello.protocol_version, 1);
    }
}
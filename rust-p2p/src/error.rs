use std::fmt;

/// Represents all possible errors defined by the P2P Interoperability Specification.
#[derive(Debug, PartialEq)]
pub enum P2pError {
    UnsupportedProtocolVersion,
    InvalidMessage,
    HandshakeFailed,
    AuthFailed,
    UnknownPeer,
    UntrustedKey,
    KeyChanged,
    ConsentDenied,
    FileNotFound,
    FileHashMismatch,
    InvalidFileSignature,
    DecryptionFailed,
    TransferInterrupted,
    KeyRotationInvalid,
    
    // It's helpful to have a generic wrapper for lower-level library errors 
    // (like network timeouts or IO errors) that aren't strictly protocol errors.
    IoError(String),
}

impl fmt::Display for P2pError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            P2pError::UnsupportedProtocolVersion => write!(f, "UNSUPPORTED_PROTOCOL_VERSION: The peer uses an incompatible protocol version."),
            P2pError::InvalidMessage => write!(f, "INVALID_MESSAGE: Received a malformed or unexpected message."),
            P2pError::HandshakeFailed => write!(f, "HANDSHAKE_FAILED: Could not establish a secure connection."),
            P2pError::AuthFailed => write!(f, "AUTH_FAILED: Peer authentication signature was invalid."),
            P2pError::UnknownPeer => write!(f, "UNKNOWN_PEER: Attempted to interact with an unrecognized peer."),
            P2pError::UntrustedKey => write!(f, "UNTRUSTED_KEY: The peer's identity key has not been trusted."),
            P2pError::KeyChanged => write!(f, "KEY_CHANGED: The peer's identity key has changed. Re-verification required."),
            P2pError::ConsentDenied => write!(f, "CONSENT_DENIED: The peer denied the file transfer request."),
            P2pError::FileNotFound => write!(f, "FILE_NOT_FOUND: The requested file does not exist on the peer."),
            P2pError::FileHashMismatch => write!(f, "FILE_HASH_MISMATCH: The received file's hash does not match the metadata."),
            P2pError::InvalidFileSignature => write!(f, "INVALID_FILE_SIGNATURE: The file's metadata signature is invalid."),
            P2pError::DecryptionFailed => write!(f, "DECRYPTION_FAILED: Failed to decrypt the incoming message."),
            P2pError::TransferInterrupted => write!(f, "TRANSFER_INTERRUPTED: The file transfer was disconnected unexpectedly."),
            P2pError::KeyRotationInvalid => write!(f, "KEY_ROTATION_INVALID: The key migration notice is invalid or improperly signed."),
            P2pError::IoError(msg) => write!(f, "IO_ERROR: {}", msg),
        }
    }
}

// This allows our custom enum to be treated as a standard Rust Error
impl std::error::Error for P2pError {}
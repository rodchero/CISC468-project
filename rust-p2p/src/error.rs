use std::fmt;

#[derive(Debug)]
pub enum AppError {
    // Spec-defined errors
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

    // Internal errors
    IoError(std::io::Error),
    ConfigError(String),
    CryptoError(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::UnsupportedProtocolVersion => write!(f, "Unsupported protocol version"),
            AppError::InvalidMessage => write!(f, "Invalid message"),
            AppError::HandshakeFailed => write!(f, "Handshake failed"),
            AppError::AuthFailed => write!(f, "Authentication failed"),
            AppError::UnknownPeer => write!(f, "Unknown peer"),
            AppError::UntrustedKey => write!(f, "Untrusted key"),
            AppError::KeyChanged => write!(f, "Peer key changed"),
            AppError::ConsentDenied => write!(f, "Consent denied"),
            AppError::FileNotFound => write!(f, "File not found"),
            AppError::FileHashMismatch => write!(f, "File hash mismatch"),
            AppError::InvalidFileSignature => write!(f, "Invalid file signature"),
            AppError::DecryptionFailed => write!(f, "Decryption failed"),
            AppError::TransferInterrupted => write!(f, "Transfer interrupted"),
            AppError::KeyRotationInvalid => write!(f, "Invalid key rotation"),

            AppError::IoError(e) => write!(f, "IO error: {}", e),
            AppError::ConfigError(msg) => write!(f, "Config error: {}", msg),
            AppError::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::IoError(e)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn display_error() {
        let e = AppError::FileNotFound;
        assert_eq!(format!("{}", e), "File not found");
    }
}

use std::io::{Read, Write};
use prost::Message;

use crate::error::P2pError;
use crate::protocol::session::SecureSession;
use crate::protocol::messages::{
    ErrorMessage, FileListRequest, FileListResponse, FileRequest, FileResponse,
};

/// Represents the high-level application state.
/// Later, this will hold references to your storage module and UI callbacks.
pub struct P2pApp {
    pub display_name: String,
    // future: storage: StorageManager,
    // future: ui_callback: Sender<UiEvent>,
}

impl P2pApp {
    pub fn new(display_name: &str) -> Self {
        Self {
            display_name: display_name.to_string(),
        }
    }

    /// The main event loop for a connected, secured peer.
    /// This function blocks and continuously reads messages until the connection drops.
    pub fn run_peer_session<S: Read + Write>(&self, mut session: SecureSession<S>) -> Result<(), P2pError> {
        loop {
            // 1. Wait for the next encrypted message
            let (msg_type, payload) = match session.receive_encrypted() {
                Ok(msg) => msg,
                Err(e) => {
                    println!("Session error or disconnected: {}", e);
                    return Err(e);
                }
            };

            // 2. Route the message based on its type string
            match msg_type.as_str() {
                "FileListRequest" => self.handle_file_list_request(&mut session, &payload)?,
                "FileRequest" => self.handle_file_request(&mut session, &payload)?,
                // Add other message handlers here (FileSendOffer, KeyRotationNotice, etc.)
                _ => {
                    println!("Received unknown or unhandled message type: {}", msg_type);
                    self.send_error(&mut session, "INVALID_MESSAGE", "Unknown message type")?;
                }
            }
        }
    }

    /// Handles an incoming request for our file list. 
    /// Requirement 9.1: No consent required.
    fn handle_file_list_request<S: Read + Write>(
        &self, 
        session: &mut SecureSession<S>, 
        _payload: &[u8]
    ) -> Result<(), P2pError> {
        println!("Peer requested file list. Sending automatically...");
        
        // In the future, this will ask the `storage` module for the real list of files.
        // For now, return an empty list.
        let response = FileListResponse {
            files: vec![], // Empty for now
        };

        let mut buf = Vec::new();
        response.encode(&mut buf).unwrap();
        
        session.send_encrypted("FileListResponse", &buf)
    }

    /// Handles an incoming request to download a file from us.
    /// Consent REQUIRED
    fn handle_file_request<S: Read + Write>(
        &self, 
        session: &mut SecureSession<S>, 
        payload: &[u8]
    ) -> Result<(), P2pError> {
        let req = FileRequest::decode(payload).map_err(|_| P2pError::InvalidMessage)?;
        println!("Peer requested file ID: {:x?}", req.file_id);

        // TODO: Hook this up to your actual UI/CLI to ask the user!
        // For now, deny by default
        let user_consents = false; 

        if user_consents {
            // Send FileResponse(approved=true), then start sending FileChunks...
            let response = FileResponse {
                approved: true,
                error_code: String::new(),
            };
            let mut buf = Vec::new();
            response.encode(&mut buf).unwrap();
            session.send_encrypted("FileResponse", &buf)?;
            
            // TODO: stream_file_chunks(session, req.file_id)
            Ok(())
        } else {
            // Requirement 9.2: If consent is denied, return correct error message.
            println!("Consent denied by user. Notifying peer.");
            let response = FileResponse {
                approved: false,
                error_code: "CONSENT_DENIED".to_string(), // Matches spec error code
            };
            let mut buf = Vec::new();
            response.encode(&mut buf).unwrap();
            session.send_encrypted("FileResponse", &buf)
        }
    }

    /// Helper to send standard error messages back to the peer.
    fn send_error<S: Read + Write>(
        &self, 
        session: &mut SecureSession<S>, 
        code: &str, 
        desc: &str
    ) -> Result<(), P2pError> {
        let err_msg = ErrorMessage {
            error_code: code.to_string(),
            description: desc.to_string(),
        };
        let mut buf = Vec::new();
        err_msg.encode(&mut buf).unwrap();
        session.send_encrypted("ErrorMessage", &buf)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use crate::crypto::AesKeyBytes;
    use crate::protocol::messages::FileListRequest;

    #[test]
    fn test_app_handles_file_list_request() {
        let tx_key = [1u8; 32];
        let rx_key = [2u8; 32];
        
        // Setup a simulated network buffer
        let mut network_buffer = Cursor::new(Vec::new());

        // 1. Simulate the remote peer sending a FileListRequest
        let mut remote_peer = SecureSession::new(&mut network_buffer, tx_key, rx_key);
        let req = FileListRequest {};
        let mut req_buf = Vec::new();
        req.encode(&mut req_buf).unwrap();
        remote_peer.send_encrypted("FileListRequest", &req_buf).unwrap();

        // Rewind buffer so our app can read it
        network_buffer.set_position(0);
        
        // Record the size of the buffer before the app responds
        let buffer_size_before = network_buffer.get_ref().len();

        // 2. Run the App logic to process the request
        let app = P2pApp::new("TestApp");
        let mut local_session = SecureSession::new(&mut network_buffer, rx_key, tx_key);
        
        let (msg_type, payload) = local_session.receive_encrypted().unwrap();
        assert_eq!(msg_type, "FileListRequest");
        
        // The app should handle it without error
        let result = app.handle_file_list_request(&mut local_session, &payload);
        assert!(result.is_ok());

        // explicitly destroy the session to release the mutable borrow on network_buffer!
        drop(local_session);

        // 3. Verify the app sent a FileListResponse back!
        // Can now safely look at network_buffer directly.
        let final_buffer_size = network_buffer.get_ref().len();
        assert!(final_buffer_size > buffer_size_before, "App should have written an encrypted response to the buffer");
    }
}
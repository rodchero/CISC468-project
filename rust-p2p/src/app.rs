use std::io::{Read, Write};
use prost::Message;

use crate::error::P2pError;
use crate::protocol::session::SecureSession;
use crate::protocol::messages::{
    p2p_message, ErrorMessage, FileListRequest, FileListResponse, 
    FileRequest, FileResponse, FileChunk, FileTransferComplete, FileMetadata
};
use crate::protocol::verification::verify_metadata;
use crate::crypto::hash::{hash_file, compute_file_id};
use crate::storage::SecureStorage;

const CHUNK_SIZE: usize = 1024 * 64; // 64 KB per chunk

/// The high-level application state, holding references to our display name and local storage.
pub struct P2pApp<'a> {
    pub display_name: String,
    pub storage: &'a SecureStorage,
}

impl<'a> P2pApp<'a> {
    pub fn new(display_name: &str, storage: &'a SecureStorage) -> Self {
        Self {
            display_name: display_name.to_string(),
            storage,
        }
    }

    /// The main event loop for a connected, secured peer.
    pub fn run_peer_session<S: Read + Write>(&self, mut session: SecureSession<S>) -> Result<(), P2pError> {
        loop {
            let (msg_type, payload) = match session.receive_encrypted() {
                Ok(msg) => msg,
                Err(e) => {
                    println!("Session ended or network error: {}", e);
                    return Err(e);
                }
            };

            match msg_type.as_str() {
                "FileListRequest" => self.handle_file_list_request(&mut session, &payload)?,
                "FileRequest" => self.handle_file_request(&mut session, &payload)?,
                "FileSendOffer" => println!("Received file offer. (UI hook needed)"),
                "KeyRotationNotice" => println!("Received key rotation. (DB update needed)"),
                _ => {
                    println!("Unhandled message type: {}", msg_type);
                    self.send_error(&mut session, "INVALID_MESSAGE", "Unknown message type")?;
                }
            }
        }
    }

    /// Handles an incoming request for our file list. 
    /// Requirement 9.1: No consent required[cite: 254].
    fn handle_file_list_request<S: Read + Write>(
        &self, 
        session: &mut SecureSession<S>, 
        _payload: &[u8]
    ) -> Result<(), P2pError> {
        println!("[*] Peer requested file list. Generating response...");
        
        // In a complete app, you would read a local SQLite DB or JSON file 
        // storing your signed metadata records here. For the skeleton, we send an empty list.
        let response = FileListResponse {
            files: vec![], 
        };

        let mut buf = Vec::new();
        response.encode(&mut buf).unwrap();
        session.send_encrypted("FileListResponse", &buf)
    }

    /// Handles an incoming request to download a file from us.
    /// Requirement 9.2: Consent REQUIRED[cite: 256].
    fn handle_file_request<S: Read + Write>(
        &self, 
        session: &mut SecureSession<S>, 
        payload: &[u8]
    ) -> Result<(), P2pError> {
        let req = FileRequest::decode(payload).map_err(|_| P2pError::InvalidMessage)?;
        println!("[?] Peer requested file ID: {:x?}", &req.file_id[0..8]);

        // Simulating user consent. In reality, you'd trigger a UI prompt here.
        let user_consents = true; 

        if !user_consents {
            println!("[-] Consent denied by user. Notifying peer.");
            let response = FileResponse {
                approved: false,
                error_code: "CONSENT_DENIED".to_string(), // Spec mandated error [cite: 311]
            };
            let mut buf = Vec::new();
            response.encode(&mut buf).unwrap();
            return session.send_encrypted("FileResponse", &buf);
        }

        // 1. Consent granted. Send the approval message.
        println!("[+] Consent granted. Starting file transfer...");
        let response = FileResponse {
            approved: true,
            error_code: String::new(),
        };
        let mut buf = Vec::new();
        response.encode(&mut buf).unwrap();
        session.send_encrypted("FileResponse", &buf)?;

        // 2. We use a placeholder filename here. You would normally look up the filename 
        // in your local database using the requested `req.file_id`.
        let local_filename = "shared_document.txt"; 

        // 3. Stream the file in chunks from SecureStorage over the network
        match self.storage.read_file(local_filename) {
            Ok(file_bytes) => {
                let total_chunks = (file_bytes.len() as f64 / CHUNK_SIZE as f64).ceil() as u32;
                
                for (index, chunk) in file_bytes.chunks(CHUNK_SIZE).enumerate() {
                    let file_chunk = FileChunk {
                        file_id: req.file_id.clone(),
                        chunk_index: index as u32,
                        data: chunk.to_vec(),
                    };
                    
                    let mut chunk_buf = Vec::new();
                    file_chunk.encode(&mut chunk_buf).unwrap();
                    session.send_encrypted("FileChunk", &chunk_buf)?;
                }

                // 4. Send Transfer Complete
                let complete_msg = FileTransferComplete {
                    file_id: req.file_id.clone(),
                    total_chunks,
                };
                let mut comp_buf = Vec::new();
                complete_msg.encode(&mut comp_buf).unwrap();
                session.send_encrypted("FileTransferComplete", &comp_buf)?;
                
                println!("[+] File transfer complete!");
            }
            Err(e) => {
                println!("[-] Failed to read requested file from storage: {}", e);
                self.send_error(session, "FILE_NOT_FOUND", "The requested file is unavailable.")?;
            }
        }
        
        Ok(())
    }

    /// Helper to verify a third-party file before saving it.
    pub fn verify_and_accept_file(
        &self,
        metadata: &FileMetadata,
        received_bytes: &[u8]
    ) -> Result<(), P2pError> {
        use sha2::{Sha256, Digest};
        
        // 1. Verify Owner Signature
        let owner_pub: [u8; 32] = metadata.owner_fingerprint.clone().try_into().map_err(|_| P2pError::InvalidMessage)?;
        verify_metadata(metadata, &owner_pub)?;

        // 2. Verify File Hash
        let mut hasher = Sha256::new();
        hasher.update(received_bytes);
        let computed_hash = hasher.finalize();
        
        if computed_hash.as_slice() != metadata.file_hash {
            return Err(P2pError::FileHashMismatch); 
        }

        println!("[+] Third-party file verification passed. Saving to local storage...");
        self.storage.write_file(&metadata.filename, received_bytes)?;

        Ok(())
    }

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
    use tempfile::tempdir;
    use crate::crypto::AesKeyBytes;
    use crate::crypto::keys::generate_identity_keypair;
    use crate::protocol::verification::sign_metadata;

    /// A helper function to quickly spin up an isolated test environment:
    /// Returns a temporary directory (which deletes itself when out of scope),
    /// an initialized SecureStorage vault, and dummy AES keys for the network stream.
    fn setup_test_env() -> (tempfile::TempDir, SecureStorage, AesKeyBytes, AesKeyBytes) {
        let dir = tempdir().unwrap();
        let salt = SecureStorage::generate_salt();
        let storage = SecureStorage::new(dir.path(), "test_password", &salt).unwrap();
        
        let tx_key = [1u8; 32];
        let rx_key = [2u8; 32];
        
        (dir, storage, tx_key, rx_key)
    }

    #[test]
    fn test_app_handles_file_list_request() {
        let (_dir, storage, tx_key, rx_key) = setup_test_env();
        let app = P2pApp::new("TestApp", &storage);

        let mut network_buffer = Cursor::new(Vec::new());
        let mut remote_peer = SecureSession::new(&mut network_buffer, tx_key, rx_key);
        
        // 1. Remote peer asks for the file list
        let req = FileListRequest {};
        let mut req_buf = Vec::new();
        req.encode(&mut req_buf).unwrap();
        remote_peer.send_encrypted("FileListRequest", &req_buf).unwrap();

        // Rewind the buffer
        network_buffer.set_position(0);
        let buffer_size_before = network_buffer.get_ref().len();

        let mut local_session = SecureSession::new(&mut network_buffer, rx_key, tx_key);
        let (_msg_type, payload) = local_session.receive_encrypted().unwrap();
        
        // 2. The app handles it
        app.handle_file_list_request(&mut local_session, &payload).unwrap();

        // 3. Drop session to appease the borrow checker, then check the buffer
        drop(local_session);
        assert!(network_buffer.get_ref().len() > buffer_size_before, "App should have written a response");
    }

    #[test]
    fn test_verify_and_accept_third_party_file() {
        let (_dir, storage, _, _) = setup_test_env();
        let app = P2pApp::new("TestApp", &storage);

        // 1. Generate a dummy identity for the file owner
        let (owner_secret, owner_pub) = generate_identity_keypair();
        let file_data = b"Some important shared data from Peer A";
        
        // 2. Hash the file data exactly as Peer A would
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(file_data);
        let file_hash = hasher.finalize().to_vec();

        // 3. Construct the metadata
        let mut metadata = FileMetadata {
            owner_fingerprint: owner_pub.to_vec(),
            file_id: vec![1, 2, 3], 
            filename: "received_file.txt".to_string(),
            file_size: file_data.len() as u64,
            file_hash,
            timestamp: 1678886400,
            owner_signature: vec![], // Empty until signed
        };

        // 4. Peer A signs the metadata
        sign_metadata(&owner_secret, &mut metadata).unwrap();

        // 5. Our app receives the file and metadata from Peer C. Verify it!
        let result = app.verify_and_accept_file(&metadata, file_data);
        assert!(result.is_ok(), "Verification should pass for valid signature and hash");

        // 6. Ensure the app actually encrypted and saved it to our local vault
        let read_back = storage.read_file("received_file.txt").unwrap();
        assert_eq!(read_back, file_data, "The file in storage should match the received bytes");
    }

    #[test]
    fn test_handle_file_request_with_chunking() {
        let (_dir, storage, tx_key, rx_key) = setup_test_env();
        
        // 1. Inject a fake file into our local secure storage vault
        // We make it ~100 KB so it exceeds the 64 KB CHUNK_SIZE, forcing the app to split it.
        let filename = "shared_document.txt";
        let file_data = vec![42u8; 100_000]; 
        storage.write_file(filename, &file_data).unwrap();

        let app = P2pApp::new("TestApp", &storage);

        let mut network_buffer = Cursor::new(Vec::new());
        let mut remote_peer = SecureSession::new(&mut network_buffer, tx_key, rx_key);
        
        // 2. Remote peer requests the file
        let req = FileRequest {
            file_id: vec![0xAA, 0xBB], 
        };
        let mut req_buf = Vec::new();
        req.encode(&mut req_buf).unwrap();
        remote_peer.send_encrypted("FileRequest", &req_buf).unwrap();

        network_buffer.set_position(0);
        let mut local_session = SecureSession::new(&mut network_buffer, rx_key, tx_key);
        let (_msg_type, payload) = local_session.receive_encrypted().unwrap();
        
        // 3. The app handles the request!
        app.handle_file_request(&mut local_session, &payload).unwrap();

        // At this point, local_session should have written:
        // - FileResponse (Approved)
        // - FileChunk (Index 0)
        // - FileChunk (Index 1)
        // - FileTransferComplete
        
        drop(local_session);
        
        // 4. Assert the buffer grew significantly, proving the chunking loop ran and sent the data
        let final_size = network_buffer.get_ref().len();
        assert!(final_size > file_data.len(), "Network buffer should contain the file chunks and protobuf overhead");
    }
}
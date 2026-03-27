use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use prost::Message;

use crate::error::P2pError;
use crate::protocol::session::SecureSession;
use crate::protocol::messages::{
    p2p_message, ErrorMessage, FileListRequest, FileListResponse, 
    FileRequest, FileResponse, FileChunk, FileTransferComplete, FileMetadata,
    FileSendOffer, KeyRotationNotice
};
use crate::protocol::verification::{verify_metadata, verify_key_rotation};
use crate::storage::SecureStorage;
use crate::trust::TrustStore;

const CHUNK_SIZE: usize = 1024 * 64; // 64 KB per chunk

/// Shared state between the main CLI thread and the background connection threads.
#[derive(Default)]
pub struct NodeState {
    // Maps a short hex ID to a Yes (true), No (false), or Pending (None) decision
    pub pending_consents: HashMap<String, Option<bool>>,
    // Maps a 32-byte File ID to a local filename on disk
    pub file_registry: HashMap<Vec<u8>, String>,
    // Maps a 32-byte File ID to its metadata so we can share it
    pub metadata_cache: HashMap<Vec<u8>, FileMetadata>,
}

/// Defines an action a session should take immediately upon connecting
pub enum SessionAction {
    None,
    RequestFileList,
    RequestFile(Vec<u8>),
    OfferFile(FileMetadata),
}

pub struct P2pApp<'a> {
    pub display_name: String,
    pub storage: &'a SecureStorage,
    pub state: Arc<Mutex<NodeState>>,
    pub trust_store: Arc<Mutex<TrustStore<'a>>>,
}

impl<'a> P2pApp<'a> {
    pub fn new(
        display_name: &str, 
        storage: &'a SecureStorage, 
        state: Arc<Mutex<NodeState>>,
        trust_store: Arc<Mutex<TrustStore<'a>>>
    ) -> Self {
        Self {
            display_name: display_name.to_string(),
            storage,
            state,
            trust_store,
        }
    }

    /// The main event loop for a connected, secured peer.
    pub fn run_peer_session<S: Read + Write>(
        &self, 
        mut session: SecureSession<S>, 
        peer_ip: &str,
        initial_action: SessionAction
    ) -> Result<(), P2pError> {
        
        // Execute any immediate commands triggered by the CLI
        match initial_action {
            SessionAction::RequestFileList => {
                let req = FileListRequest {};
                let mut buf = Vec::new();
                req.encode(&mut buf).unwrap();
                session.send_encrypted("FileListRequest", &buf)?;
                println!("[*] Sent FileListRequest to {}", peer_ip);
            }
            SessionAction::RequestFile(file_id) => {
                let req = FileRequest { file_id: file_id.clone() };
                let mut buf = Vec::new();
                req.encode(&mut buf).unwrap();
                session.send_encrypted("FileRequest", &buf)?;
                println!("[*] Sent FileRequest to {}", peer_ip);
            }
            SessionAction::OfferFile(metadata) => {
                let offer = FileSendOffer { metadata: Some(metadata) };
                let mut buf = Vec::new();
                offer.encode(&mut buf).unwrap();
                session.send_encrypted("FileSendOffer", &buf)?;
                println!("[*] Sent FileSendOffer to {}", peer_ip);
            }
            SessionAction::None => {}
        }

        // Enter the continuous listening loop
        loop {
            let (msg_type, payload) = match session.receive_encrypted() {
                Ok(msg) => msg,
                Err(e) => {
                    println!("\n[-] Session with {} ended: {}", peer_ip, e);
                    return Err(e);
                }
            };

            match msg_type.as_str() {
                "FileListRequest" => self.handle_file_list_request(&mut session, peer_ip)?,
                "FileListResponse" => self.handle_file_list_response(&payload)?,
                "FileRequest" => self.handle_file_request(&mut session, peer_ip, &payload)?,
                "FileSendOffer" => self.handle_file_send_offer(&mut session, peer_ip, &payload)?,
                "KeyRotationNotice" => self.handle_key_rotation_notice(peer_ip, &payload)?,
                "FileResponse" => println!("\n[+] Received FileResponse. Transfer status updated."),
                "FileChunk" => println!("\n[*] Receiving file chunk..."), // Stubbed for brevity
                "FileTransferComplete" => println!("\n[+] File transfer complete!"),
                _ => {
                    println!("\n[-] Unhandled message type: {}", msg_type);
                    self.send_error(&mut session, "INVALID_MESSAGE", "Unknown message type")?;
                }
            }
        }
    }

    /// REAL FILE LIST: Returns actual files registered in the NodeState
    fn handle_file_list_request<S: Read + Write>(&self, session: &mut SecureSession<S>, peer_ip: &str) -> Result<(), P2pError> {
        println!("\n[*] Peer {} requested file list.", peer_ip);
        
        let state = self.state.lock().unwrap();
        let files: Vec<FileMetadata> = state.metadata_cache.values().cloned().collect();

        let response = FileListResponse { files };
        let mut buf = Vec::new();
        response.encode(&mut buf).unwrap();
        session.send_encrypted("FileListResponse", &buf)
    }

    fn handle_file_list_response(&self, payload: &[u8]) -> Result<(), P2pError> {
        let resp = FileListResponse::decode(payload).map_err(|_| P2pError::InvalidMessage)?;
        println!("\n--- Remote File List ---");
        if resp.files.is_empty() {
            println!("(No files available)");
        }
        for file in resp.files {
            let id_hex = hex::encode(&file.file_id[..4]); // Show first 8 chars
            println!(" ID: {} | Name: {} | Size: {} bytes", id_hex, file.filename, file.file_size);
        }
        println!("------------------------");
        Ok(())
    }

    /// REAL LOOKUP & CONSENT PROMPT: Looks up the file and waits for CLI approval
    fn handle_file_request<S: Read + Write>(&self, session: &mut SecureSession<S>, peer_ip: &str, payload: &[u8]) -> Result<(), P2pError> {
        let req = FileRequest::decode(payload).map_err(|_| P2pError::InvalidMessage)?;
        
        let local_filename = {
            let state = self.state.lock().unwrap();
            match state.file_registry.get(&req.file_id) {
                Some(name) => name.clone(),
                None => {
                    println!("\n[-] Peer {} requested unknown file.", peer_ip);
                    return self.send_error(session, "FILE_NOT_FOUND", "File not available");
                }
            }
        };

        let id_hex = hex::encode(&req.file_id[..4]);
        println!("\n[!] Peer {} wants to download '{}'.", peer_ip, local_filename);
        println!("[!] Type '/approve {}' or '/deny {}' to respond.", id_hex, id_hex);

        // Wait for user consent
        let approved = self.wait_for_consent(&id_hex);

        if !approved {
            println!("\n[-] Consent denied. Notifying peer.");
            let response = FileResponse { approved: false, error_code: "CONSENT_DENIED".to_string() };
            let mut buf = Vec::new();
            response.encode(&mut buf).unwrap();
            return session.send_encrypted("FileResponse", &buf);
        }

        println!("\n[+] Consent granted. Starting transfer of '{}'...", local_filename);
        let response = FileResponse { approved: true, error_code: String::new() };
        let mut buf = Vec::new();
        response.encode(&mut buf).unwrap();
        session.send_encrypted("FileResponse", &buf)?;

        // Stream chunks from secure storage
        match self.storage.read_file(&local_filename) {
            Ok(file_bytes) => {
                let total_chunks = (file_bytes.len() as f64 / CHUNK_SIZE as f64).ceil() as u32;
                for (index, chunk) in file_bytes.chunks(CHUNK_SIZE).enumerate() {
                    let file_chunk = FileChunk { file_id: req.file_id.clone(), chunk_index: index as u32, data: chunk.to_vec() };
                    let mut chunk_buf = Vec::new();
                    file_chunk.encode(&mut chunk_buf).unwrap();
                    session.send_encrypted("FileChunk", &chunk_buf)?;
                }

                let complete_msg = FileTransferComplete { file_id: req.file_id.clone(), total_chunks };
                let mut comp_buf = Vec::new();
                complete_msg.encode(&mut comp_buf).unwrap();
                session.send_encrypted("FileTransferComplete", &comp_buf)?;
                println!("[+] File transfer complete!");
            }
            Err(e) => {
                println!("[-] Failed to read file from storage: {}", e);
            }
        }
        Ok(())
    }

    /// UNSOLICITED OFFER CONSENT PROMPT
    fn handle_file_send_offer<S: Read + Write>(&self, session: &mut SecureSession<S>, peer_ip: &str, payload: &[u8]) -> Result<(), P2pError> {
        let offer = FileSendOffer::decode(payload).map_err(|_| P2pError::InvalidMessage)?;
        let metadata = offer.metadata.ok_or(P2pError::InvalidMessage)?;

        let id_hex = hex::encode(&metadata.file_id[..4]);
        println!("\n[!] Peer {} is offering to send you '{}' ({} bytes).", peer_ip, metadata.filename, metadata.file_size);
        println!("[!] Type '/approve {}' or '/deny {}' to accept.", id_hex, id_hex);

        let approved = self.wait_for_consent(&id_hex);

        if approved {
            println!("\n[+] Offer accepted. Requesting file...");
            let req = FileRequest { file_id: metadata.file_id.clone() };
            let mut buf = Vec::new();
            req.encode(&mut buf).unwrap();
            session.send_encrypted("FileRequest", &buf)?;
        } else {
            println!("\n[-] Offer denied.");
        }
        Ok(())
    }

    /// KEY ROTATION HANDLER: Verifies and permanently updates the trust database
    fn handle_key_rotation_notice(&self, peer_ip: &str, payload: &[u8]) -> Result<(), P2pError> {
        let notice = KeyRotationNotice::decode(payload).map_err(|_| P2pError::InvalidMessage)?;
        
        println!("\n[!] SECURITY: Received Key Rotation Notice from {}", peer_ip);
        
        // 1. Verify both the old and new signatures!
        if let Err(e) = verify_key_rotation(&notice) {
            println!("[-] Key Rotation verification FAILED! {}", e);
            return Err(e);
        }

        // 2. Safely update the TrustStore
        let mut ts = self.trust_store.lock().unwrap();
        let new_key: [u8; 32] = notice.new_public_key.clone().try_into().unwrap();
        
        // Directly update the public map and force a save to disk
        let _ = ts.update_peer_key(peer_ip, &new_key);
        
        println!("[+] Key Rotation successful. Trust Database updated for {}", peer_ip);
        Ok(())
    }

    /// Helper to block the active thread until the main CLI thread records a decision
    fn wait_for_consent(&self, id_hex: &str) -> bool {
        {
            let mut state = self.state.lock().unwrap();
            state.pending_consents.insert(id_hex.to_string(), None);
        }

        // Poll for 60 seconds
        for _ in 0..120 {
            std::thread::sleep(Duration::from_millis(500));
            let mut state = self.state.lock().unwrap();
            // Extract the boolean, dropping the reference to the map itself
            let decision = state.pending_consents.get(id_hex).copied().flatten();
            
            if let Some(d) = decision {
                state.pending_consents.remove(id_hex); // Safe to mutate now!
                return d;
            }
        }

        // Timeout
        println!("\n[-] Consent request for {} timed out.", id_hex);
        let mut state = self.state.lock().unwrap();
        state.pending_consents.remove(id_hex);
        false
    }

    fn send_error<S: Read + Write>(&self, session: &mut SecureSession<S>, code: &str, desc: &str) -> Result<(), P2pError> {
        let err_msg = ErrorMessage { error_code: code.to_string(), description: desc.to_string() };
        let mut buf = Vec::new();
        err_msg.encode(&mut buf).unwrap();
        session.send_encrypted("ErrorMessage", &buf)
    }
}


pub mod app;
pub mod crypto;
pub mod error;
pub mod network;
pub mod protocol;
pub mod storage;
pub mod trust;

use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use crate::error::P2pError;
use crate::storage::SecureStorage;
use crate::app::{P2pApp, NodeState, SessionAction};
use crate::network::discovery::Discovery;
use crate::trust::TrustStore;
use crate::protocol::messages::FileMetadata;

fn main() -> Result<(), P2pError> {
    println!("==========================================");
    println!(" CISC 468 P2P Secure File Sharing Client  ");
    println!("==========================================");

    let display_name = "RustNode_Roman2";
    let storage_dir = "./roman_p2p_vault";
    let salt = b"cisc468_static_salt_1234"; 
    let port = 9468; 

    // 1. Vault & Identity Setup
    let password = rpassword::prompt_password("[?] Enter your secure vault password: ")
        .expect("Failed to read password from terminal");
        
    let storage = SecureStorage::new(storage_dir, &password, salt)?;
    let identity_filename = "ed25519_identity.key";
    
    // Construct the actual OS path to check if the file exists
    let identity_filepath = format!("{}/{}", storage_dir, identity_filename);
    let is_new_vault = !std::path::Path::new(&identity_filepath).exists();

    let my_id_secret = if is_new_vault {
        println!("[*] No identity key found. Generating a fresh Ed25519 keypair...");
        let mut csprng = OsRng;
        let new_key = SigningKey::generate(&mut csprng);
        storage.write_file(identity_filename, &new_key.to_bytes())?;
        new_key
    } else {
        // The file exists on disk. If read_file fails now, it is a wrong password.
        match storage.read_file(identity_filename) {
            Ok(key_bytes) => {
                println!("[+] Vault unlocked successfully. Loaded existing identity.");
                let secret_bytes: [u8; 32] = key_bytes.try_into().expect("Invalid key length");
                SigningKey::from_bytes(&secret_bytes)
            }
            Err(_) => {
                println!("\n[!!!] FATAL SECURITY ERROR [!!!]");
                println!("Failed to decrypt the identity key. You entered an incorrect password.");
                println!("Shutting down to prevent data corruption.");
                std::process::exit(1);
            }
        }
    };

    // 2. Trust Store & Application State Setup
    let trust_store = Arc::new(Mutex::new(TrustStore::new(&storage)?));
    let node_state = Arc::new(Mutex::new(NodeState::default()));
    
    // --- DEMO SETUP: Inject a dummy file into our local state so we have something to share ---
    let dummy_id = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let dummy_metadata = FileMetadata {
        owner_fingerprint: my_id_secret.verifying_key().to_bytes().to_vec(),
        file_id: dummy_id.clone(),
        filename: "test_image.png".to_string(),
        file_size: 1048576,
        file_hash: vec![0xAA; 32],
        timestamp: 1678886400,
        owner_signature: vec![], // In reality, you'd sign this here
    };
    {
        let mut state = node_state.lock().unwrap();
        state.file_registry.insert(dummy_id.clone(), "test_image.png".to_string());
        state.metadata_cache.insert(dummy_id, dummy_metadata);
        
        // Write the actual bytes to disk so the SecureStorage can stream it if requested
        let _ = storage.write_file("test_image.png", &[0x00; 1024]);
    }
    // -----------------------------------------------------------------------------------------

    let p2p_app = P2pApp::new(display_name, &storage, Arc::clone(&node_state), Arc::clone(&trust_store));

    // 3. Discovery Setup
    println!("[*] Initializing mDNS discovery...");
    let discovery = Discovery::new()?;
    discovery.start_advertising(display_name, port)?;
    let _browser = discovery.start_browsing()?;
    println!("[+] Node is fully initialized and online!\n");

    // 4. Multithreaded CLI Environment
    let app_ref = &p2p_app;
    let secret_ref = &my_id_secret;
    let ts_listener = Arc::clone(&trust_store);

    thread::scope(|s| {
        // BACKGROUND THREAD: The Listener
        s.spawn(move || {
            let listener = TcpListener::bind(("0.0.0.0", port)).expect("Failed to bind TCP port");
            for stream in listener.incoming() {
                if let Ok(mut tcp_stream) = stream {
                    let peer_addr = tcp_stream.peer_addr().unwrap();
                    let peer_ip = peer_addr.ip().to_string();

                    // Clone the Arc AGAIN for this specific incoming connection thread
                    let ts_conn = Arc::clone(&ts_listener);
                    
                    s.spawn(move || {
                        match protocol::handshake::run_responder(&mut tcp_stream, secret_ref, display_name) {
                            Ok((tx_key, rx_key, peer_pub)) => {
                                // TOFU Verification
                                {
                                    let mut ts = ts_conn.lock().unwrap();
                                    if let Err(e) = ts.verify_or_trust_peer(&peer_ip, &peer_pub) {
                                        println!("\n[-] Connection rejected by Trust Store: {}", e);
                                        return; 
                                    }
                                }
                                let session = protocol::session::SecureSession::new(tcp_stream, tx_key, rx_key);
                                let _ = app_ref.run_peer_session(session, &peer_ip, SessionAction::None);
                            }
                            Err(_) => {}
                        }
                    });
                }
            }
        });

        thread::sleep(std::time::Duration::from_millis(50));
        let stdin = io::stdin();
        let mut buffer = String::new();

        // MAIN THREAD: Interactive CLI
        loop {
            print!("p2p-node> ");
            io::stdout().flush().unwrap();
            buffer.clear();
            if stdin.read_line(&mut buffer).unwrap() == 0 { break; }

            let input = buffer.trim();
            if input.is_empty() { continue; }

            let mut args = input.split_whitespace();
            let command = args.next().unwrap();

            match command {
                "/help" => {
                    println!("--- Available Commands ---");
                    println!(" /list <ip>             : Request a peer's file list");
                    println!(" /request <ip> <hex_id> : Request a file from a peer");
                    println!(" /approve <hex_id>      : Approve a pending file request or offer");
                    println!(" /deny <hex_id>         : Deny a pending file request or offer");
                    println!(" /local_files           : Show the files currently in your vault");
                    println!(" /quit                  : Shut down the node");
                }
                "/quit" | "/q" => std::process::exit(0),
                "/local_files" => {
                    let state = node_state.lock().unwrap();
                    println!("--- Local File Registry ---");
                    for (id, filename) in &state.file_registry {
                        println!(" ID: {} | File: {}", hex::encode(&id[..4]), filename);
                    }
                }
                "/approve" | "/deny" => {
                    if let Some(id) = args.next() {
                        let mut state = node_state.lock().unwrap();
                        if state.pending_consents.contains_key(id) {
                            let decision = command == "/approve";
                            state.pending_consents.insert(id.to_string(), Some(decision));
                            println!("[+] Marked request {} as {}", id, if decision { "APPROVED" } else { "DENIED" });
                        } else {
                            println!("[-] No pending request found with ID {}", id);
                        }
                    } else {
                        println!("Usage: {} <hex_id>", command);
                    }
                }
                "/list" => {
                    if let Some(ip) = args.next() {
                        let target = format!("{}:{}", ip, port);
                        let peer_ip = ip.to_string();

                        // Clone the Arc for the outgoing list request thread
                        let ts_cmd = Arc::clone(&trust_store);
                        
                        s.spawn(move || {
                            if let Ok(mut tcp_stream) = TcpStream::connect(&target) {
                                if let Ok((tx_key, rx_key, peer_pub)) = protocol::handshake::run_initiator(&mut tcp_stream, secret_ref, display_name) {
                                    {
                                        let mut ts = ts_cmd.lock().unwrap();
                                        if ts.verify_or_trust_peer(&peer_ip, &peer_pub).is_err() { return; }
                                    }
                                    let session = protocol::session::SecureSession::new(tcp_stream, tx_key, rx_key);
                                    let _ = app_ref.run_peer_session(session, &peer_ip, SessionAction::RequestFileList);
                                }
                            }
                        });
                    } else { println!("Usage: /list <ip_address>"); }
                }
                "/request" => {
                    if let (Some(ip), Some(hex_id)) = (args.next(), args.next()) {
                        if let Ok(file_id) = hex::decode(hex_id) {
                            // Pad to 32 bytes just in case they typed the short ID
                            let mut full_id = vec![0u8; 32];
                            let copy_len = std::cmp::min(file_id.len(), 32);
                            full_id[..copy_len].copy_from_slice(&file_id[..copy_len]);

                            let target = format!("{}:{}", ip, port);
                            let peer_ip = ip.to_string();

                            // Clone the Arc for the outgoing file request thread
                            let ts_cmd = Arc::clone(&trust_store);
                            
                            s.spawn(move || {
                                if let Ok(mut tcp_stream) = TcpStream::connect(&target) {
                                    if let Ok((tx_key, rx_key, peer_pub)) = protocol::handshake::run_initiator(&mut tcp_stream, secret_ref, display_name) {
                                        {
                                            let mut ts = ts_cmd.lock().unwrap();
                                            if ts.verify_or_trust_peer(&peer_ip, &peer_pub).is_err() { return; }
                                        }
                                        let session = protocol::session::SecureSession::new(tcp_stream, tx_key, rx_key);
                                        let _ = app_ref.run_peer_session(session, &peer_ip, SessionAction::RequestFile(full_id));
                                    }
                                }
                            });
                        } else { println!("[-] Invalid hex ID"); }
                    } else { println!("Usage: /request <ip_address> <hex_id>"); }
                }
                _ => println!("Unknown command. Type /help."),
            }
        }
    });

    Ok(())
}
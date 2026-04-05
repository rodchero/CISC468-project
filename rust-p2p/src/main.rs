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
use std::time::SystemTime;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use sha2::{Sha256, Digest};

use crate::protocol::verification::sign_metadata;
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

    let display_name = "Bob";
    let storage_dir = "./roman_p2p_vault";
    let salt = b"cisc468_static_salt_1234"; 
    let port = 9468; 

    // 1. Vault & Identity Setup
    let password = rpassword::prompt_password("<< Enter your secure vault password: ")
        .expect("Failed to read password from terminal");
        
    let storage = SecureStorage::new(storage_dir, &password, salt)?;
    let identity_filename = "ed25519_identity.key";
    
    // Construct the actual OS path to check if the file exists
    let identity_filepath = format!("{}/{}", storage_dir, identity_filename);
    let is_new_vault = !std::path::Path::new(&identity_filepath).exists();

    let my_id_secret_base = if is_new_vault {
        println!("<< No identity key found. Generating a fresh Ed25519 keypair...");
        let mut csprng = OsRng;
        let new_key = SigningKey::generate(&mut csprng);
        storage.write_file(identity_filename, &new_key.to_bytes())?;
        new_key
    } else {
        // The file exists on disk. If read_file fails now, it is a wrong password.
        match storage.read_file(identity_filename) {
            Ok(key_bytes) => {
                println!("<< Local storage decrypted. Loaded existing identity.");
                let secret_bytes: [u8; 32] = key_bytes.try_into().expect("Invalid key length");
                SigningKey::from_bytes(&secret_bytes)
            }
            Err(_) => {
                println!("\n<< FATAL SECURITY ERROR");
                println!("Failed to decrypt the identity key. You entered an incorrect password.");
                println!("Shutting down to prevent data corruption.");
                std::process::exit(1);
            }
        }
    };

    // Wrap the secret in an Arc<Mutex> so it can be mutated during a key rotation
    let my_id_secret = Arc::new(Mutex::new(my_id_secret_base));

    // 2. Trust Store & Application State Setup
    let trust_store = Arc::new(Mutex::new(TrustStore::new(&storage)?));
    let node_state = Arc::new(Mutex::new(NodeState::default()));
    
    // Load third-party cache on startup
    if let Ok(tp_meta) = storage.read_third_party_metadata() {
        println!("<< Loaded {} third-party files from secure storage.", tp_meta.len());
        let mut state = node_state.lock().unwrap();
        for (id, meta) in tp_meta {
            state.file_registry.insert(id.clone(), meta.filename.clone());
            state.third_party_metadata.insert(id, meta);
        }
    }

    // --- DEMO SETUP: Inject a dummy file into our local state so we have something to share ---
    let test_file_bytes = vec![0x00; 1024]; // 1KB of zeros
    let file_hash = Sha256::digest(&test_file_bytes).to_vec();
    let filename = "test_image.png".to_string();
    let file_size = test_file_bytes.len() as u64;

    let owner_fp = {
        let secret = my_id_secret.lock().unwrap();
        Sha256::digest(secret.verifying_key().as_bytes()).to_vec()
    };

    // file_id = SHA-256(filename | file_hash | file_size_BE)
    let file_id = {
        let mut hasher = Sha256::new();
        hasher.update(filename.as_bytes());
        hasher.update(&file_hash);
        hasher.update(&file_size.to_be_bytes());
        hasher.finalize().to_vec()
    };

    let mut dummy_metadata = FileMetadata {
        owner_fingerprint: owner_fp,
        file_id: file_id.clone(),
        filename: filename.clone(),
        file_size,
        file_hash,
        timestamp: 1678886400,
        owner_signature: vec![],
    };

    // Actually sign the canonical bytes!
    {
        let secret = my_id_secret.lock().unwrap();
        sign_metadata(&*secret, &mut dummy_metadata).unwrap();
    }

    {
        let mut state = node_state.lock().unwrap();
        state.file_registry.insert(file_id.clone(), filename.clone());
        state.metadata_cache.insert(file_id.clone(), dummy_metadata);
        
        // Write the actual bytes to disk so the SecureStorage can stream it if requested
        let _ = storage.write_file(&filename, &test_file_bytes);
    }
    // -----------------------------------------------------------------------------------------

    let p2p_app = P2pApp::new(display_name, &storage, Arc::clone(&node_state), Arc::clone(&trust_store));

    // 3. Discovery Setup
    println!("<< Initializing mDNS discovery...");
    let discovery = Discovery::new()?;
    discovery.start_advertising(display_name, port)?;
    
    let browser = discovery.start_browsing()?;
    let my_name = display_name.to_string();

    // Spawn a dedicated background thread to listen for peer announcements
    thread::spawn(move || {
        while let Ok(event) = browser.recv() {
            match event {
                // PHASE 1: A peer broadcasted their presence
                mdns_sd::ServiceEvent::ServiceFound(_service_type, fullname) => {
                    if !fullname.contains(&my_name) {
                        println!("\n<< mDNS: Heard broadcast from '{}'. Automatically resolving...", fullname);
                        print!("p2p-node> ");
                        let _ = io::stdout().flush();
                    }
                }
                // PHASE 2: The daemon successfully fetched the IP address in the background
                mdns_sd::ServiceEvent::ServiceResolved(info) => {
                    if !info.get_fullname().contains(&my_name) {
                        let ips: Vec<String> = info.get_addresses().iter().map(|ip| ip.to_string()).collect();
                        
                        if ips.is_empty() {
                            println!("\n<< mDNS ERROR: Resolved '{}' but couldn't extract an IP address!", info.get_fullname());
                        } else {
                            println!("\n\n<< 📡 mDNS DISCOVERY: Found Peer!");
                            
                            // Check TXT records for friendly display name (Python interop)
                            let mut disp_name = info.get_fullname().to_string();
                            if let Some(prop) = info.get_property("display_name") {
                                disp_name = prop.val_str().to_string(); 
                            }
                            
                            println!("    -> Name: {}", disp_name);
                            println!("    -> IP Addresses: {:?}", ips);
                            println!("    -> Try: /list {}", ips[0]);
                        }
                        print!("p2p-node> ");
                        let _ = io::stdout().flush();
                    }
                }
                _ => {} 
            }
        }
    });

    println!("<< Node is fully initialized and online!\n");

    // 4. Multithreaded CLI Environment
    let app_ref = &p2p_app;
    let ts_listener = Arc::clone(&trust_store);

    thread::scope(|s| {
        // BACKGROUND THREAD: The Listener
        let listener_secret_ref = Arc::clone(&my_id_secret);
        s.spawn(move || {
            let listener = TcpListener::bind(("0.0.0.0", port)).expect("Failed to bind TCP port");
            for stream in listener.incoming() {
                if let Ok(mut tcp_stream) = stream {
                    let peer_addr = tcp_stream.peer_addr().unwrap();
                    let peer_ip = peer_addr.ip().to_string();

                    let ts_conn = Arc::clone(&ts_listener);
                    let secret_clone = Arc::clone(&listener_secret_ref);
                    
                    s.spawn(move || {
                        let secret = secret_clone.lock().unwrap().clone();
                        match protocol::handshake::run_responder(&mut tcp_stream, &secret, display_name) {
                            Ok((tx_key, rx_key, peer_pub)) => {
                                // TOFU Verification
                                {
                                    let mut ts = ts_conn.lock().unwrap();
                                    if let Err(e) = ts.verify_or_trust_peer(&peer_ip, &peer_pub) {
                                        println!("\n<< Connection rejected by Trust Store: {}", e);
                                        return; 
                                    }
                                }
                                let session = protocol::session::SecureSession::new(tcp_stream, tx_key, rx_key);
                                let _ = app_ref.run_peer_session(session, &peer_ip, &peer_pub, SessionAction::None);
                            }
                            Err(e) => {
                                println!("<< Inbound handshake failed from {}: {:?}", peer_addr, e);
                            }
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
                    println!(" /list <ip>                  : Request a peer's file list");
                    println!(" /request <ip> <hex_id>      : Request a file from a peer");
                    println!(" /send <ip> <hex_id>         : Send (offer) a local file to a peer");
                    println!(" /add <filepath>             : Add a local file to the secure vault");
                    println!(" /remove <hex_id>            : Delete a file from the secure vault");
                    println!(" /export <hex_id> <filepath> : Decrypt and save a file to disk");
                    println!(" /view <hex_id>              : Print the contents of a text file");
                    println!(" /approve <hex_id>           : Approve a pending file request or offer");
                    println!(" /deny <hex_id>              : Deny a pending file request or offer");
                    println!(" /local_files                : Show the files currently in your vault");
                    println!(" /rotate                     : Rotate your identity key and notify peers");
                    println!(" /quit                       : Shut down the node");
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
                            println!("<< Marked request {} as {}", id, if decision { "APPROVED" } else { "DENIED" });
                        } else {
                            println!("<< No pending request found with ID {}", id);
                        }
                    } else {
                        println!("Usage: {} <hex_id>", command);
                    }
                }
                "/add" => {
                    if let Some(filepath) = args.next() {
                        let path = std::path::Path::new(filepath);
                        match std::fs::read(path) {
                            Ok(bytes) => {
                                let filename = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
                                let file_size = bytes.len() as u64;
                                let file_hash = Sha256::digest(&bytes).to_vec();
                                
                                let owner_fp = {
                                    let secret = my_id_secret.lock().unwrap();
                                    Sha256::digest(secret.verifying_key().as_bytes()).to_vec()
                                };
                                
                                let mut hasher = Sha256::new();
                                hasher.update(filename.as_bytes());
                                hasher.update(&file_hash);
                                hasher.update(&file_size.to_be_bytes());
                                let file_id = hasher.finalize().to_vec();

                                let timestamp = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

                                let mut metadata = FileMetadata {
                                    owner_fingerprint: owner_fp,
                                    file_id: file_id.clone(),
                                    filename: filename.clone(),
                                    file_size,
                                    file_hash,
                                    timestamp,
                                    owner_signature: vec![],
                                };

                                // Sign the metadata
                                {
                                    let secret = my_id_secret.lock().unwrap();
                                    if let Err(e) = sign_metadata(&*secret, &mut metadata) {
                                        println!("<< Failed to sign metadata: {}", e);
                                        continue;
                                    }
                                }

                                // Write to secure storage
                                if let Err(e) = app_ref.storage.write_file(&filename, &bytes) {
                                    println!("<< Failed to write to secure vault: {}", e);
                                    continue;
                                }
                                
                                let mut state = node_state.lock().unwrap();
                                state.file_registry.insert(file_id.clone(), filename.clone());
                                state.metadata_cache.insert(file_id.clone(), metadata);
                                
                                println!("<< Success! Added '{}' to secure vault (ID: {}).", filename, hex::encode(&file_id[..4]));
                            }
                            Err(e) => println!("<< Failed to read local file '{}': {}", filepath, e),
                        }
                    } else {
                        println!("Usage: /add <filepath>");
                    }
                }
                "/remove" => {
                    if let Some(hex_id) = args.next() {
                        let mut state = node_state.lock().unwrap();
                        let target = state.file_registry.keys().find(|id| {
                            let prefix_len = std::cmp::min(4, id.len());
                            hex::encode(&id[..prefix_len]) == hex_id
                        }).cloned();

                        if let Some(full_id) = target {
                            if let Some(filename) = state.file_registry.remove(&full_id) {
                                state.metadata_cache.remove(&full_id);
                                state.third_party_metadata.remove(&full_id);
                                // Delete from disk vault
                                let _ = app_ref.storage.delete_file(&filename);
                                println!("<< Removed '{}' (ID: {}) from secure vault.", filename, hex_id);
                            }
                        } else {
                            println!("<< Unknown file ID '{}'", hex_id);
                        }
                    } else {
                        println!("Usage: /remove <hex_id>");
                    }
                }
                "/export" => {
                    if let (Some(hex_id), Some(dest_path)) = (args.next(), args.next()) {
                        let target_filename = {
                            let state = node_state.lock().unwrap();
                            state.file_registry.iter().find(|(id, _)| {
                                let prefix_len = std::cmp::min(4, id.len());
                                hex::encode(&id[..prefix_len]) == hex_id
                            }).map(|(_, name)| name.clone())
                        };

                        if let Some(filename) = target_filename {
                            match app_ref.storage.read_file(&filename) {
                                Ok(bytes) => {
                                    match std::fs::write(dest_path, &bytes) {
                                        Ok(_) => println!("<< Success! File exported decrypted to '{}'.", dest_path),
                                        Err(e) => println!("<< Failed to write exported file: {}", e),
                                    }
                                }
                                Err(e) => println!("<< Failed to read from secure vault: {}", e),
                            }
                        } else {
                            println!("<< Unknown file ID '{}'", hex_id);
                        }
                    } else {
                        println!("Usage: /export <hex_id> <destination_filepath>");
                    }
                }
                "/view" => {
                    if let Some(hex_id) = args.next() {
                        let target_filename = {
                            let state = node_state.lock().unwrap();
                            state.file_registry.iter().find(|(id, _)| {
                                let prefix_len = std::cmp::min(4, id.len());
                                hex::encode(&id[..prefix_len]) == hex_id
                            }).map(|(_, name)| name.clone())
                        };

                        if let Some(filename) = target_filename {
                            match app_ref.storage.read_file(&filename) {
                                Ok(bytes) => {
                                    let content = String::from_utf8_lossy(&bytes);
                                    println!("\n--- Contents of '{}' ---", filename);
                                    for (i, line) in content.lines().take(100).enumerate() {
                                        println!("{:3} | {}", i + 1, line);
                                    }
                                    if content.lines().count() > 100 {
                                        println!("... (truncated after 100 lines) ...");
                                    }
                                    println!("--------------------------\n");
                                }
                                Err(e) => println!("<< Failed to read from secure vault: {}", e),
                            }
                        } else {
                            println!("<< Unknown file ID '{}'", hex_id);
                        }
                    } else {
                        println!("Usage: /view <hex_id>");
                    }
                }
                "/list" => {
                    if let Some(ip) = args.next() {
                        let target = format!("{}:{}", ip, port);
                        let peer_ip = ip.to_string();

                        let ts_cmd = Arc::clone(&trust_store);
                        let secret_clone = Arc::clone(&my_id_secret);
                        
                        s.spawn(move || {
                            match TcpStream::connect(&target) {
                                Ok(mut tcp_stream) => {
                                    let secret = secret_clone.lock().unwrap().clone();
                                    if let Ok((tx_key, rx_key, peer_pub)) = protocol::handshake::run_initiator(&mut tcp_stream, &secret, display_name) {
                                        {
                                            let mut ts = ts_cmd.lock().unwrap();
                                            if ts.verify_or_trust_peer(&peer_ip, &peer_pub).is_err() { return; }
                                        }
                                        let session = protocol::session::SecureSession::new(tcp_stream, tx_key, rx_key);
                                        let _ = app_ref.run_peer_session(session, &peer_ip, &peer_pub, SessionAction::RequestFileList);
                                    } else {
                                        println!("<< Handshake failed with {}. Is the peer online and running the same protocol version?", target);
                                    }
                                }    
                                Err(e) => {
                                    println!("<< Failed to connect to {}, {}", target, e);
                                }
                            }
                        });
                    } else { println!("Usage: /list <ip_address>"); }
                }
                "/request" => {
                    if let (Some(ip), Some(hex_id)) = (args.next(), args.next()) {
                        let full_id = {
                            let state = node_state.lock().unwrap();
                            state.metadata_cache.keys().find(|id| {
                                let prefix_len = std::cmp::min(4, id.len());
                                hex::encode(&id[..prefix_len]) == hex_id
                            }).cloned()
                        };

                        if let Some(full_id) = full_id {
                            let target = format!("{}:{}", ip, port);
                            let peer_ip = ip.to_string();

                            let ts_cmd = Arc::clone(&trust_store);
                            let secret_clone = Arc::clone(&my_id_secret);
                            
                            s.spawn(move || {
                                if let Ok(mut tcp_stream) = TcpStream::connect(&target) {
                                    let secret = secret_clone.lock().unwrap().clone();
                                    if let Ok((tx_key, rx_key, peer_pub)) = protocol::handshake::run_initiator(&mut tcp_stream, &secret, display_name) {
                                        {
                                            let mut ts = ts_cmd.lock().unwrap();
                                            if ts.verify_or_trust_peer(&peer_ip, &peer_pub).is_err() { return; }
                                        }
                                        let session = protocol::session::SecureSession::new(tcp_stream, tx_key, rx_key);
                                        let _ = app_ref.run_peer_session(session, &peer_ip, &peer_pub, SessionAction::RequestFile(full_id));
                                    } else { println!("<< Handshake err") }
                                } else { println!("<< TCP connection err") }
                            });
                        } else {
                            println!("<< Unknown short ID '{}'. Did you run '/list {}' first to cache the file?", hex_id, ip);
                        }
                    } else { println!("Usage: /request <ip_address> <hex_id>"); }
                }
                "/send" => {
                    if let (Some(ip), Some(hex_id)) = (args.next(), args.next()) {
                        let target_metadata = {
                            let state = node_state.lock().unwrap();
                            state.metadata_cache.iter().find(|(id, _)| {
                                let prefix_len = std::cmp::min(4, id.len());
                                hex::encode(&id[..prefix_len]) == hex_id
                            }).map(|(_, meta)| meta.clone())
                        };

                        if let Some(metadata) = target_metadata {
                            let target = format!("{}:{}", ip, port);
                            let peer_ip = ip.to_string();
                            let ts_cmd = Arc::clone(&trust_store);
                            let secret_clone = Arc::clone(&my_id_secret);

                            s.spawn(move || {
                                match TcpStream::connect(&target) {
                                    Ok(mut tcp_stream) => {
                                        let secret = secret_clone.lock().unwrap().clone();
                                        if let Ok((tx_key, rx_key, peer_pub)) = protocol::handshake::run_initiator(&mut tcp_stream, &secret, display_name) {
                                            {
                                                let mut ts = ts_cmd.lock().unwrap();
                                                if ts.verify_or_trust_peer(&peer_ip, &peer_pub).is_err() { return; }
                                            }
                                            let session = protocol::session::SecureSession::new(tcp_stream, tx_key, rx_key);
                                            let _ = app_ref.run_peer_session(session, &peer_ip, &peer_pub, SessionAction::OfferFile(metadata));
                                        } else {
                                            println!("<< Handshake failed with {}", target);
                                        }
                                    }
                                    Err(e) => println!("<< Failed to connect to {}, {}", target, e),
                                }
                            });
                        } else {
                            println!("<< Unknown file ID '{}'. Did you check '/local_files'?", hex_id);
                        }
                    } else { println!("Usage: /send <ip_address> <hex_id>"); }
                }
                "/rotate" => {
                    println!("<< Initiating key rotation...");
                    let mut csprng = rand_core::OsRng;
                    let new_key = ed25519_dalek::SigningKey::generate(&mut csprng);
                    let timestamp = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

                    // 1. Generate the signed notice using the OLD key
                    let old_key = my_id_secret.lock().unwrap().clone();
                    let notice = match crate::protocol::verification::sign_key_rotation(&old_key, &new_key, timestamp) {
                        Ok(n) => n,
                        Err(e) => {
                            println!("<< Failed to sign rotation notice: {}", e);
                            continue;
                        }
                    };

                    // 2. Retrieve all known contacts to notify them
                    let known_ips: Vec<String> = {
                        let ts = trust_store.lock().unwrap();
                        ts.get_known_peer_ips()
                    };

                    // 3. Broadcast the notice to all peers using the OLD key to pass the handshake
                    for ip in known_ips {
                        let target = format!("{}:{}", ip, port);
                        let peer_ip = ip.clone();
                        let notice_clone = notice.clone();
                        let old_key_clone = old_key.clone();
                        let display_name_clone = display_name.to_string();
                        let ts_cmd = Arc::clone(&trust_store);

                        s.spawn(move || {
                            if let Ok(mut tcp_stream) = TcpStream::connect(&target) {
                                if let Ok((tx_key, rx_key, peer_pub)) = protocol::handshake::run_initiator(&mut tcp_stream, &old_key_clone, &display_name_clone) {
                                    {
                                        let mut ts = ts_cmd.lock().unwrap();
                                        if ts.verify_or_trust_peer(&peer_ip, &peer_pub).is_err() { return; }
                                    }
                                    let session = protocol::session::SecureSession::new(tcp_stream, tx_key, rx_key);
                                    let _ = app_ref.run_peer_session(session, &peer_ip, &peer_pub, SessionAction::SendRotationNotice(notice_clone));
                                }
                            } else {
                                println!("<< Peer {} is offline. Next time you connect, their TOFU may reject you.", peer_ip);
                            }
                        });
                    }

                    // 4. Save the new key to disk and update local memory for all FUTURE connections
                    if let Err(e) = app_ref.storage.write_file("ed25519_identity.key", &new_key.to_bytes()) {
                        println!("<< FATAL: Failed to save new key to vault: {}", e);
                    } else {
                        *my_id_secret.lock().unwrap() = new_key;
                        println!("<< Local identity key rotated and saved successfully.");
                    }
                }
                _ => println!("Unknown command. Type /help."),
            }
        }
    });

    Ok(())
}
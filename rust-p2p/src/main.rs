// module tree
pub mod app;
pub mod crypto;
pub mod error;
pub mod network;
pub mod protocol;
pub mod storage;

// external crates
use std::net::TcpListener;
use std::path::Path;

use ed25519_dalek::{SigningKey, SecretKey};
use rand_core::OsRng;

// internal modules
use crate::error::P2pError;
use crate::storage::SecureStorage;
use crate::app::P2pApp;
use crate::network::discovery::Discovery;

fn main() -> Result<(), P2pError> {
    println!("==========================================");
    println!(" CISC 468 P2P Secure File Sharing Client  ");
    println!("==========================================");

    // ---------------------------------------------------------
    // PHASE 1: Local Storage & Vault Initialization
    // ---------------------------------------------------------
    
    // In a final production app, you'd securely prompt the user for this password via CLI/UI.
    let display_name = "RustNode_Roman";
    let password = "super_secret_user_password";
    let storage_dir = "./roman_p2p_vault";
    
    // We use a static salt for simplicity in this implementation, 
    // but in a real scenario, you'd generate this once and store it alongside the vault.
    let salt = b"cisc468_static_salt_1234"; 

    println!("[*] Unlocking local storage vault...");
    let storage = SecureStorage::new(storage_dir, password, salt)?;

    // ---------------------------------------------------------
    // PHASE 2: Cryptographic Identity (Persistent)
    // ---------------------------------------------------------
    
    let identity_filename = "ed25519_identity.key";
    let my_id_secret = match storage.read_file(identity_filename) {
        Ok(key_bytes) => {
            println!("[+] Loaded existing encrypted identity key from storage.");
            let secret_bytes: [u8; 32] = key_bytes.try_into().expect("Key should be 32 bytes");
            SigningKey::from_bytes(&secret_bytes)
        }
        Err(_) => {
            println!("[*] No identity key found. Generating a fresh Ed25519 keypair...");
            let mut csprng = OsRng;
            let new_key = SigningKey::generate(&mut csprng);
            
            // Save it securely to our encrypted vault
            storage.write_file(identity_filename, &new_key.to_bytes())?;
            println!("[+] New identity key securely saved to vault.");
            new_key
        }
    };

    // ---------------------------------------------------------
    // PHASE 3: Application State & mDNS Discovery
    // ---------------------------------------------------------
    
    let p2p_app = P2pApp::new(display_name, &storage);
    let port = 9468; 

    println!("[*] Initializing mDNS discovery...");
    let discovery = Discovery::new()?;
    
    // Broadcast our presence to the local network so the Python client can find us
    discovery.start_advertising(display_name, port)?;
    
    // Start browsing for Python peers in the background
    let _browser = discovery.start_browsing()?;

    // ---------------------------------------------------------
    // PHASE 4: TCP Listener & Connection Handling
    // ---------------------------------------------------------
    
    let listener = TcpListener::bind(("0.0.0.0", port)).map_err(|e| {
        P2pError::IoError(format!("Failed to bind TCP listener on port {}: {}", port, e))
    })?;

    println!("\n[+] Node is online! Listening on TCP port {}...", port);
    println!("[+] Waiting for Youssef's Python peer to connect...\n");

    // This loop blocks and waits for incoming TCP connections
    for stream in listener.incoming() {
        match stream {
            Ok(mut tcp_stream) => {
                let peer_addr = tcp_stream.peer_addr().unwrap();
                println!("------------------------------------------");
                println!(" Incoming connection from: {}", peer_addr);
                
                println!(" [*] Running secure handshake as Responder...");
                
                // Pass the stream, our secret key, and display name into the handshake state machine
                match protocol::handshake::run_responder(&mut tcp_stream, &my_id_secret, display_name) {
                    Ok((tx_key, rx_key, peer_id_pub)) => {
                        println!(" [+] Handshake successful! Mutual authentication complete.");
                        println!(" [+] Peer Identity Fingerprint: {:x?}", &peer_id_pub[0..8]); 
                        
                        let secure_session = protocol::session::SecureSession::new(tcp_stream, tx_key, rx_key);
                        
                        println!(" [*] Handing encrypted channel to Application Router...");
                        
                        // Blocks and handles all protobuf messages until the peer disconnects
                        if let Err(e) = p2p_app.run_peer_session(secure_session) {
                            println!(" [-] Session ended: {}", e);
                        }
                    }
                    Err(e) => {
                        println!(" [-] Handshake failed: {}", e);
                    }
                }
                println!("------------------------------------------");
                println!("[+] Waiting for next connection...\n");
            }
            Err(e) => {
                println!(" [-] Network error accepting connection: {}", e);
            }
        }
    }

    Ok(())
}
// Declare the top-level modules.
mod error;
mod app;
mod crypto;
mod network;
mod protocol;
mod storage;

use std::net::TcpListener;
use crate::error::P2pError;

fn main() -> Result<(), P2pError> {
    println!("==========================================");
    println!(" CISC 468 P2P Secure File Sharing Client  ");
    println!("==========================================");

    // ---------------------------------------------------------
    // PHASE 1: Local Storage & Cryptographic Identity Setup
    // ---------------------------------------------------------
    
    // In a real app, you would prompt the user for this in the terminal.
    let display_name = "RustPeer_Alpha";
    let password = "super_secret_user_password";
    
    // A hardcoded salt for the skeleton. In reality, generate this once and save it to disk!
    let salt = b"cisc468_static_salt_1234"; 
    
    println!("[*] Deriving local master key via Argon2id...");
    let _master_key = storage::derive_local_master_key(password, salt)?;

    println!("[*] Generating Ed25519 Identity Keypair...");
    // For the skeleton we generate a fresh key every time. 
    // Later, you will load the saved key encrypted by _master_key.
    let (my_id_secret, _my_id_pub) = crypto::keys::generate_identity_keypair();

    // ---------------------------------------------------------
    // PHASE 2: Application State & Discovery
    // ---------------------------------------------------------
    
    let p2p_app = app::P2pApp::new(display_name);
    let port = 9468; // Default TCP port from the spec

    println!("[*] Initializing mDNS discovery...");
    let discovery = network::discovery::Discovery::new()?;
    
    // Broadcast our presence to the local network [cite: 502]
    discovery.start_advertising(display_name, port)?;
    
    // Optional: Start browsing for Python peers in the background
    let _browser = discovery.start_browsing()?;

    // ---------------------------------------------------------
    // PHASE 3: TCP Listener & Connection Handling
    // ---------------------------------------------------------
    
    // Bind to 0.0.0.0 to listen on all available network interfaces
    let listener = TcpListener::bind(("0.0.0.0", port)).map_err(|e| {
        P2pError::IoError(format!("Failed to bind TCP listener on port {}: {}", port, e))
    })?;

    println!("\n[+] Listening for incoming P2P connections on TCP port {}...", port);
    println!("[+] Waiting for Python peer to connect...\n");

    // This loop blocks and waits for an incoming TCP connection
    for stream in listener.incoming() {
        match stream {
            Ok(mut tcp_stream) => {
                let peer_addr = tcp_stream.peer_addr().unwrap();
                println!("------------------------------------------");
                println!(" Incoming connection from: {}", peer_addr);
                
                // ---------------------------------------------------------
                // PHASE 4: The Handshake
                // ---------------------------------------------------------
                println!(" [*] Running secure handshake as Responder...");
                
                match protocol::handshake::run_responder(&mut tcp_stream, &my_id_secret, display_name) {
                    Ok((tx_key, rx_key, peer_id_pub)) => {
                        println!(" [+] Handshake successful!");
                        println!(" [+] Peer Identity: {:x?}", &peer_id_pub[0..8]); // Print first 8 bytes of fingerprint
                        
                        // ---------------------------------------------------------
                        // PHASE 5: Secure Session & App Logic
                        // ---------------------------------------------------------
                        let secure_session = protocol::session::SecureSession::new(tcp_stream, tx_key, rx_key);
                        
                        println!(" [*] Handing connection to Application Router...");
                        
                        // This will block and handle messages until the peer disconnects
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
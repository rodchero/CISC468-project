pub mod app;
pub mod crypto;
pub mod error;
pub mod network;
pub mod protocol;
pub mod storage;

use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use crate::error::P2pError;
use crate::storage::SecureStorage;
use crate::app::P2pApp;
use crate::network::discovery::Discovery;

fn main() -> Result<(), P2pError> {
    println!("==========================================");
    println!(" CISC 468 P2P Secure File Sharing Client  ");
    println!("==========================================");

    // ---------------------------------------------------------
    // PHASE 1: Initialization
    // ---------------------------------------------------------
    let display_name = "RustNode_Roman";
    let password = "super_secret_user_password";
    let storage_dir = "./roman_p2p_vault";
    let salt = b"cisc468_static_salt_1234"; 

    println!("[*] Unlocking local storage ...");
    let storage = SecureStorage::new(storage_dir, password, salt)?;

    let identity_filename = "ed25519_identity.key";
    let my_id_secret = match storage.read_file(identity_filename) {
        Ok(key_bytes) => {
            println!("[+] Loaded existing encrypted identity key.");
            let secret_bytes: [u8; 32] = key_bytes.try_into().unwrap();
            SigningKey::from_bytes(&secret_bytes)
        }
        Err(_) => {
            println!("[*] Generating fresh Ed25519 keypair...");
            let mut csprng = OsRng;
            let new_key = SigningKey::generate(&mut csprng);
            storage.write_file(identity_filename, &new_key.to_bytes())?;
            new_key
        }
    };

    let p2p_app = P2pApp::new(display_name, &storage);
    let port = 9468; 

    println!("[*] Initializing mDNS discovery...");
    let discovery = Discovery::new()?;
    discovery.start_advertising(display_name, port)?;
    let _browser = discovery.start_browsing()?;

    println!("[+] Node is fully initialized and online!\n");

    // ---------------------------------------------------------
    // PHASE 2: Multithreaded CLI Environment
    // ---------------------------------------------------------
    
    // Create explicit shared references. Since these are just references (&), 
    // they are `Copy`, meaning they can be safely duplicated into many threads!
    let app_ref = &p2p_app;
    let secret_ref = &my_id_secret;

    // Create a thread scope so we can safely share these references across threads
    thread::scope(|s| {

        // BACKGROUND THREAD: The Listener (Responder)
        s.spawn(move || {
            let listener = TcpListener::bind(("0.0.0.0", port)).expect("Failed to bind TCP port");
            
            for stream in listener.incoming() {
                if let Ok(mut tcp_stream) = stream {
                    let peer_addr = tcp_stream.peer_addr().unwrap();
                    println!("\n[+] Incoming connection from: {}", peer_addr);
                    print!("p2p-node> "); // Re-print the prompt to keep UI clean
                    io::stdout().flush().unwrap();
                    
                    // Spawn a NEW thread for every individual connection
                    s.spawn(move || {
                        // Use our copied references here!
                        match protocol::handshake::run_responder(&mut tcp_stream, secret_ref, display_name) {
                            Ok((tx_key, rx_key, _peer_pub)) => {
                                let session = protocol::session::SecureSession::new(tcp_stream, tx_key, rx_key);
                                if let Err(e) = app_ref.run_peer_session(session) {
                                    println!("\n[-] Session with {} ended: {}", peer_addr, e);
                                    print!("p2p-node> ");
                                    io::stdout().flush().unwrap();
                                }
                            }
                            Err(e) => println!("\n[-] Handshake failed: {}", e),
                        }
                    });
                }
            }
        });

        // MAIN THREAD: The Interactive CLI
        // Give the background thread a tiny moment to bind the port before showing prompt
        thread::sleep(std::time::Duration::from_millis(50));
        
        let stdin = io::stdin();
        let mut buffer = String::new();

        loop {
            print!("p2p-node> ");
            io::stdout().flush().unwrap();
            buffer.clear();

            if stdin.read_line(&mut buffer).unwrap() == 0 {
                break; // EOF (Ctrl+D) pressed
            }

            let input = buffer.trim();
            if input.is_empty() { continue; }

            let mut args = input.split_whitespace();
            let command = args.next().unwrap();

            match command {
                "/help" => {
                    println!("--- Available Commands ---");
                    println!(" /connect <ip>    : Initiate a connection to a peer");
                    println!(" /quit            : Shut down the node");
                }
                "/quit" | "/q" => {
                    println!("Shutting down P2P node...");
                    std::process::exit(0);
                }
                "/connect" => {
                    if let Some(ip) = args.next() {
                        let target = format!("{}:{}", ip, port);
                        println!("[*] Attempting to connect to {}...", target);
                        
                        // Spawn a thread for the outgoing connection (Initiator)
                        s.spawn(move || {
                            match TcpStream::connect(&target) {
                                Ok(mut tcp_stream) => {
                                    println!("\n[+] TCP connection established. Running handshake...");
                                    // Use our copied references here too!
                                    match protocol::handshake::run_initiator(&mut tcp_stream, secret_ref, display_name) {
                                        Ok((tx_key, rx_key, _peer_pub)) => {
                                            println!("\n[+] Secure connection established with {}!", target);
                                            let session = protocol::session::SecureSession::new(tcp_stream, tx_key, rx_key);
                                            if let Err(e) = app_ref.run_peer_session(session) {
                                                println!("\n[-] Session ended: {}", e);
                                            }
                                        }
                                        Err(e) => println!("\n[-] Handshake failed: {}", e),
                                    }
                                }
                                Err(e) => println!("\n[-] Failed to connect to {}: {}", target, e),
                            }
                            print!("p2p-node> ");
                            io::stdout().flush().unwrap();
                        });
                    } else {
                        println!("Usage: /connect <ip_address>");
                    }
                }
                _ => {
                    println!("Unknown command: '{}'. Type /help for options.", command);
                }
            }
        }
    }); // End of thread::scope

    Ok(())
}
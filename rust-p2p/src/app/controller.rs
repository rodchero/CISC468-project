use crate::app::config::AppConfig;
use crate::app::state::AppState;
use crate::error::AppError;

pub fn run(config: AppConfig) -> Result<(), AppError> {
    println!("Starting P2P client...");
    println!("Config: {:?}", config);

    let mut state = AppState::new();

    // Phase 1: startup
    initialize(&config)?;

    // Phase 2: event loop (stub for now)
    event_loop(&mut state)?;

    Ok(())
}

fn initialize(config: &AppConfig) -> Result<(), AppError> {
    println!("Initializing services on port {}", config.port);

    // later:
    // - start mDNS
    // - start TCP listener
    // - load keys

    Ok(())
}

fn event_loop(state: &mut AppState) -> Result<(), AppError> {
    println!("Entering event loop...");

    // stub: simulate one event
    simulate_peer_discovery(state);

    Ok(())
}

// temporary function to simulate peer discovery, delete later
fn simulate_peer_discovery(state: &mut AppState) {
    println!("Discovered peer!");

    state.add_peer(crate::app::state::PeerInfo {
        id: "peer1".into(),
        address: "192.168.1.5:9468".into(),
        trusted: false,
    });
}
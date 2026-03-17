pub mod config;
pub mod controller;
pub mod state;


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_peer() {
        let mut state = state::AppState::new();

        state.add_peer(state::PeerInfo {
            id: "peer1".into(),
            address: "127.0.0.1".into(),
            trusted: false,
        });

        assert!(state.peers.contains_key("peer1"));
    }

    #[test]
    fn run_does_not_crash() {
        let config = config::AppConfig::default();
        let result = controller::run(config);

        assert!(result.is_ok());
    }
}
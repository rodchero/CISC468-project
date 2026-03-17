use std::collections::HashMap;

#[derive(Debug)]
pub struct AppState {
    pub peers: HashMap<String, PeerInfo>,
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub id: String,
    pub address: String,
    pub trusted: bool,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    pub fn add_peer(&mut self, peer: PeerInfo) {
        self.peers.insert(peer.id.clone(), peer);
    }
}
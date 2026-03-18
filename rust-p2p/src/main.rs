mod app;
mod cli;
mod crypto;
mod error;
mod file;
mod handshake;
mod net;
mod peer;
mod protocol;
mod storage;
mod tests;

use app::config::AppConfig;

fn main() {
    let config = AppConfig::default();

    if let Err(e) = app::controller::run(config) {
        eprintln!("Error: {}", e);
    }
}

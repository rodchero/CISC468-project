#[derive(Debug, Clone)]
pub struct AppConfig {
    pub port: u16,
    pub data_dir: String,
    pub display_name: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            port: 9468,
            data_dir: "./data".into(),
            display_name: "rust-peer".into(),
        }
    }
}
mod app;
mod error;

use app::config::AppConfig;

fn main() {
    let config = AppConfig::default();

    if let Err(e) = app::controller::run(config) {
        eprintln!("Error: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_main() {
        // Test main function
        todo!();
    }
}

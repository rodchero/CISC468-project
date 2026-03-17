fn main() {
    let config = cli::parse_args();
    app::controller::run(config).unwrap();
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

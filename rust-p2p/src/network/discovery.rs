use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo, Receiver};
use std::collections::HashMap; 
use crate::error::P2pError;

pub const SERVICE_TYPE: &str = "_p2pfileshare._tcp.local.";

pub struct Discovery {
    daemon: ServiceDaemon,
}

impl Discovery {
    pub fn new() -> Result<Self, P2pError> {
        let daemon = ServiceDaemon::new().map_err(|e| {
            P2pError::IoError(format!("Failed to start mDNS daemon: {}", e))
        })?;
        
        Ok(Self { daemon })
    }

    pub fn start_advertising(&self, instance_name: &str, port: u16) -> Result<(), P2pError> {
        // The crate expects a simple string slice for the IP
        let my_ip = "0.0.0.0"; 
        let host_name = format!("{}.local.", instance_name);

        // The crate expects an Option<HashMap<String, String>> for properties
        let mut props = HashMap::new();
        props.insert("app".to_string(), "cisc468-p2p".to_string());
        let properties = Some(props);

        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            instance_name,
            &host_name,
            my_ip,
            port,
            properties,
        );

        self.daemon.register(service_info).map_err(|e| {
            P2pError::IoError(format!("Failed to register mDNS service: {}", e))
        })?;

        println!("Advertising mDNS service: {} on port {}", instance_name, port);
        Ok(())
    }

    pub fn start_browsing(&self) -> Result<Receiver<ServiceEvent>, P2pError> {
        let receiver = self.daemon.browse(SERVICE_TYPE).map_err(|e| {
            P2pError::IoError(format!("Failed to browse mDNS: {}", e))
        })?;

        println!("Browsing for peers on {}...", SERVICE_TYPE);
        Ok(receiver)
    }

    pub fn stop_advertising(&self, instance_name: &str) -> Result<(), P2pError> {
        let full_name = format!("{}.{}", instance_name, SERVICE_TYPE);
        self.daemon.unregister(&full_name).map_err(|e| {
            P2pError::IoError(format!("Failed to stop mDNS advertising: {}", e))
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_mdns_advertise_and_discover() {
        let discovery = Discovery::new().expect("Failed to create discovery daemon");
        let test_peer_name = "TestRustPeer";
        let test_port = 9468;

        let receiver = discovery.start_browsing().expect("Failed to start browsing");
        discovery.start_advertising(test_peer_name, test_port).expect("Failed to advertise");

        let mut found_ourselves = false;
        let timeout = Duration::from_secs(2);
        let start_time = std::time::Instant::now();

        while start_time.elapsed() < timeout {
            if let Ok(event) = receiver.recv_timeout(Duration::from_millis(100)) {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        if info.get_fullname().contains(test_peer_name) {
                            assert_eq!(info.get_port(), test_port);
                            found_ourselves = true;
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }

        assert!(found_ourselves, "Should have discovered our own advertised mDNS service");
        discovery.stop_advertising(test_peer_name).expect("Failed to stop advertising");
    }
}
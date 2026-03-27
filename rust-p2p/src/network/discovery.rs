use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::time::Duration;
use crate::error::P2pError;

pub struct Discovery {
    daemon: ServiceDaemon,
}

impl Discovery {
    pub fn new() -> Result<Self, P2pError> {
        let daemon = ServiceDaemon::new().map_err(|e| P2pError::NetworkError(e.to_string()))?;
        
        // IMPORTANT FIX FOR 0.18+: 
        // Explicitly enable multicast loopback so the daemon can discover its own services.
        // Without this, local unit tests will timeout and fail!
        let _ = daemon.set_multicast_loop_v4(true);
        let _ = daemon.set_multicast_loop_v6(true);

        Ok(Self { daemon })
    }

    pub fn start_advertising(&self, instance_name: &str, port: u16) -> Result<(), P2pError> {
        let service_type = "_p2pfileshare._tcp.local.";
        // mdns-sd 0.18 strictly requires hostnames to end with .local.
        let host_name = format!("{}.local.", instance_name); 
        let properties = [("version", "1.0")];
        
        // Use `()` instead of `""` to represent "No IP" in 0.18's AsIpAddrs trait
        let service_info = ServiceInfo::new(
            service_type,
            instance_name,
            &host_name,
            (), 
            port,
            &properties[..],
        ).unwrap().enable_addr_auto();
        
        self.daemon.register(service_info).map_err(|e| P2pError::NetworkError(e.to_string()))?;
        
        println!("Advertising mDNS service: {} on port {}", instance_name, port);
        Ok(())
    }

    pub fn start_browsing(&self) -> Result<mdns_sd::Receiver<ServiceEvent>, P2pError> {
        let service_type = "_p2pfileshare._tcp.local.";
        println!("Browsing for peers on {}...", service_type);
        self.daemon.browse(service_type).map_err(|e| P2pError::NetworkError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mdns_advertise_and_discover() {
        let discovery = Discovery::new().expect("Failed to create Discovery instance");
        let receiver = discovery.start_browsing().expect("Failed to start browsing");

        let instance_name = "TestRustPeer";
        discovery.start_advertising(instance_name, 9468).expect("Failed to advertise");

        let timeout = Duration::from_secs(5);
        let start = std::time::Instant::now();
        let mut found = false;

        while start.elapsed() < timeout {
            // Check for messages every 100ms
            if let Ok(event) = receiver.recv_timeout(Duration::from_millis(100)) {
                use mdns_sd::ServiceEvent;
                // In 0.18, ServiceResolved yields a `ResolvedService` struct
                if let ServiceEvent::ServiceResolved(info) = event {
                    if info.get_fullname().contains(instance_name) {
                        found = true;
                        break;
                    }
                }
            }
        }

        assert!(
            found,
            "Failed to discover our own advertised mDNS service. Ensure loopback is enabled."
        );
    }
}
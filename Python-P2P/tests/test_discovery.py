import asyncio
import socket
import pytest
from zeroconf import Zeroconf, ServiceBrowser, ServiceInfo
from src.discovery import PeerDiscovery, SERVICE_TYPE


# mDNS tests can be flaky depending on OS, firewall, and network config.
# The sleeps below give zeroconf time to discover services on the local network.


@pytest.mark.asyncio
async def test_discover_peer():
    """Register a service with PeerDiscovery, use a second zeroconf to check it shows up."""
    disc = PeerDiscovery()
    await disc.start("test-peer", port=19468)

    # Give it a moment to register
    await asyncio.sleep(1)

    # Second zeroconf instance to verify the service is visible
    zc2 = Zeroconf()
    found = []

    def handler(zeroconf, service_type, name, state_change):
        info = zeroconf.get_service_info(service_type, name)
        if info:
            found.append(info)

    browser = ServiceBrowser(zc2, SERVICE_TYPE, handlers=[handler])
    await asyncio.sleep(2)

    await disc.stop()
    zc2.close()

    # Check that at least one service was found with our port
    matching = [f for f in found if f.port == 19468]
    assert len(matching) >= 1
    props = matching[0].properties
    assert props[b"display_name"] == b"test-peer"


@pytest.mark.asyncio
async def test_stop_no_crash():
    """start() then stop() should not raise."""
    disc = PeerDiscovery()
    await disc.start("cleanup-test", port=19469)
    await asyncio.sleep(0.5)
    await disc.stop()  # should not crash


@pytest.mark.asyncio
async def test_stop_without_start():
    """stop() without start() should not crash either."""
    disc = PeerDiscovery()
    await disc.stop()

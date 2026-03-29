import asyncio
import socket
from zeroconf import ServiceInfo, ServiceStateChange
from zeroconf.asyncio import AsyncZeroconf, AsyncServiceBrowser, AsyncServiceInfo

SERVICE_TYPE = "_p2pfileshare._tcp.local."
DEFAULT_PORT = 9468


class PeerDiscovery:
    def __init__(self):
        self.peers = {}  # service_name -> {name, ip, port}
        self.async_zc = None
        self.browser = None
        self.service_info = None
        self._our_name = None

    async def start(self, display_name, port=DEFAULT_PORT):
        self.async_zc = AsyncZeroconf()
        self._our_name = f"{display_name}.{SERVICE_TYPE}"

        # Register our service
        local_ip = self._get_local_ip()
        self.service_info = ServiceInfo(
            SERVICE_TYPE,
            self._our_name,
            addresses=[socket.inet_aton(local_ip)],
            port=port,
            properties={"display_name": display_name},
        )
        await self.async_zc.async_register_service(self.service_info)

        # Browse for other peers
        self.browser = AsyncServiceBrowser(
            self.async_zc.zeroconf, SERVICE_TYPE, handlers=[self._on_change]
        )

    def _on_change(self, zeroconf, service_type, name, state_change):
        if name == self._our_name:
            return

        if state_change == ServiceStateChange.Added:
            # Schedule async lookup — can't call sync get_service_info from event loop
            asyncio.ensure_future(self._async_add_peer(zeroconf, service_type, name))

        elif state_change == ServiceStateChange.Removed:
            self.peers.pop(name, None)

    async def _async_add_peer(self, zeroconf, service_type, name):
        info = AsyncServiceInfo(service_type, name)
        await info.async_request(zeroconf, 3000)
        if info and info.addresses:
            ip = socket.inet_ntoa(info.addresses[0])
            display = info.properties.get(b"display_name", b"unknown").decode()
            self.peers[name] = {"name": display, "ip": ip, "port": info.port}

    def get_peers(self):
        return list(self.peers.values())

    async def stop(self):
        if self.service_info and self.async_zc:
            await self.async_zc.async_unregister_service(self.service_info)
        if self.async_zc:
            await self.async_zc.async_close()

    def _get_local_ip(self):
        # Quick trick to get the local IP without hardcoding
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"
        finally:
            s.close()

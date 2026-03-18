class Session:
    def __init__(self, send_key, recv_key, peer_identity_pubkey, peer_display_name, is_initiator):
        self.send_key = send_key
        self.recv_key = recv_key
        self.peer_identity_pubkey = peer_identity_pubkey
        self.peer_display_name = peer_display_name
        self.is_initiator = is_initiator

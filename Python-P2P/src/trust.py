import asyncio
from src.crypto_utils import fingerprint


class TrustStore:
    def __init__(self):
        self.contacts = {}  # fingerprint_str -> {pubkey, display_name, trusted}

    def _fp(self, pubkey_bytes):
        return fingerprint(pubkey_bytes)

    def is_known(self, pubkey_bytes) -> bool:
        return self._fp(pubkey_bytes) in self.contacts

    def is_trusted(self, pubkey_bytes) -> bool:
        entry = self.contacts.get(self._fp(pubkey_bytes))
        return entry is not None and entry["trusted"]

    def add_contact(self, pubkey_bytes, display_name, trusted=False):
        fp = self._fp(pubkey_bytes)
        self.contacts[fp] = {
            "pubkey": pubkey_bytes.hex(),
            "display_name": display_name,
            "trusted": trusted,
        }

    def mark_trusted(self, pubkey_bytes):
        fp = self._fp(pubkey_bytes)
        if fp in self.contacts:
            self.contacts[fp]["trusted"] = True

    def replace_key(self, old_pubkey_bytes, new_pubkey_bytes):
        """Replace a contact's key after key rotation. Marks as untrusted."""
        old_fp = self._fp(old_pubkey_bytes)
        entry = self.contacts.pop(old_fp, None)
        if entry is None:
            return
        new_fp = self._fp(new_pubkey_bytes)
        entry["pubkey"] = new_pubkey_bytes.hex()
        entry["trusted"] = False
        self.contacts[new_fp] = entry

    def check_key_changed(self, display_name, pubkey_bytes) -> bool:
        fp = self._fp(pubkey_bytes)
        for stored_fp, entry in self.contacts.items():
            if entry["display_name"] == display_name and stored_fp != fp:
                return True
        return False

    def lookup_by_owner_fingerprint(self, owner_fp_bytes):
        """Look up a contact's public key by raw SHA-256 fingerprint bytes."""
        fp_str = ':'.join(f'{b:02x}' for b in owner_fp_bytes)
        entry = self.contacts.get(fp_str)
        if entry:
            return bytes.fromhex(entry["pubkey"])
        return None

    def to_dict(self) -> dict:
        return {"contacts": self.contacts}

    @classmethod
    def from_dict(cls, data) -> "TrustStore":
        store = cls()
        store.contacts = data.get("contacts", {})
        return store


async def prompt_trust(peer_pubkey_bytes, peer_display_name) -> bool:
    fp = fingerprint(peer_pubkey_bytes)
    print(f"\nNew peer: {peer_display_name}")
    print(f"Fingerprint: {fp}")
    # TODO: use asyncio-friendly input in the real app
    response = input("Trust this contact? [y/n]: ").strip().lower()
    return response == "y"

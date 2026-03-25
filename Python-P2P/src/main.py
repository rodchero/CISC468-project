import asyncio
import os
from src.storage import SecureStorage
from src.crypto_utils import (
    generate_identity_keypair, get_public_key_bytes,
    private_key_to_seed, seed_to_private_key, fingerprint,
)
from src.trust import TrustStore
from src.file_manager import FileManager
from src.discovery import PeerDiscovery
from src.transport import ConnectionManager
from src.protocol import (
    request_file_list, request_file, send_file,
    offer_file, send_key_rotation,
)
from src.key_rotation import create_rotation_notice

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORAGE_DIR = os.path.join(BASE_DIR, ".p2p_storage")
SHARED_DIR = os.path.join(BASE_DIR, "shared_files")


async def main():
    print("=== P2P Secure File Sharing ===\n")

    display_name = input("Enter display name: ").strip()
    password = input("Enter password: ").strip()

    # Init storage
    storage = SecureStorage(STORAGE_DIR)
    storage.setup(password)

    # Load or generate identity key
    seed = storage.load_identity_key()
    if seed is None:
        print("Generating new identity keypair...")
        priv, pub = generate_identity_keypair()
        seed = private_key_to_seed(priv)
        storage.save_identity_key(seed)
    else:
        priv = seed_to_private_key(seed)
        pub = priv.public_key()

    pub_bytes = get_public_key_bytes(pub)
    print(f"Your fingerprint: {fingerprint(pub_bytes)}")

    # Load or create trust store
    trust_store = storage.load_trust_store()
    if trust_store is None:
        trust_store = TrustStore()

    # Set up shared files directory
    os.makedirs(SHARED_DIR, exist_ok=True)
    file_mgr = FileManager(SHARED_DIR, priv, pub)
    file_mgr.scan_files()
    print(f"Sharing {len(file_mgr.get_file_list())} files from {SHARED_DIR}")

    # Start mDNS discovery
    discovery = PeerDiscovery()
    discovery.start(display_name)
    print("mDNS discovery started.")

    # Start TCP server
    conn_mgr = ConnectionManager(priv, pub, display_name, trust_store, file_mgr)
    await conn_mgr.start_server()

    # Track current connection for menu commands
    current_peer = None
    current_reader = None
    current_writer = None
    current_session = None

    try:
        while True:
            print("\n--- Menu ---")
            print("1. List discovered peers")
            print("2. Connect to a peer")
            print("3. Request file list")
            print("4. Request a file")
            print("5. Send a file to peer")
            print("6. Rotate identity key")
            print("7. View trusted contacts")
            print("8. Rescan shared files")
            print("9. Exit")

            # TODO: make this non-blocking so we can handle incoming connections
            choice = input("\n> ").strip()

            if choice == "1":
                peers = discovery.get_peers()
                if not peers:
                    print("No peers found.")
                else:
                    for i, p in enumerate(peers):
                        print(f"  {i+1}. {p['name']} ({p['ip']}:{p['port']})")

            elif choice == "2":
                peers = discovery.get_peers()
                if not peers:
                    ip = input("No mDNS peers. Enter IP manually: ").strip()
                    port = int(input("Port [9468]: ").strip() or "9468")
                else:
                    for i, p in enumerate(peers):
                        print(f"  {i+1}. {p['name']} ({p['ip']}:{p['port']})")
                    idx = int(input("Select peer: ").strip()) - 1
                    ip = peers[idx]["ip"]
                    port = peers[idx]["port"]

                session = await conn_mgr.connect_to_peer(ip, port)
                if session:
                    current_session = session
                    current_peer = session.peer_display_name
                    # Get the reader/writer from active sessions
                    entry = conn_mgr.active_sessions.get(current_peer)
                    if entry:
                        current_session, current_reader, current_writer = entry

            elif choice == "3":
                if not current_session:
                    print("Not connected to any peer.")
                    continue
                files = await request_file_list(current_session, current_reader, current_writer)
                if not files:
                    print("Peer has no files.")
                else:
                    for i, f in enumerate(files):
                        print(f"  {i+1}. {f.filename} ({f.file_size} bytes)")

            elif choice == "4":
                if not current_session:
                    print("Not connected to any peer.")
                    continue
                # Get file list first
                files = await request_file_list(current_session, current_reader, current_writer)
                if not files:
                    print("Peer has no files.")
                    continue
                for i, f in enumerate(files):
                    print(f"  {i+1}. {f.filename} ({f.file_size} bytes)")
                idx = int(input("Select file: ").strip()) - 1
                meta = files[idx]

                approved = await request_file(current_session, current_reader, current_writer, meta.file_id)
                if approved:
                    from src.protocol import receive_file
                    filepath = await receive_file(
                        current_session, current_reader, meta, SHARED_DIR,
                        current_session.peer_identity_pubkey
                    )
                    print(f"File saved: {filepath}")

            elif choice == "5":
                if not current_session:
                    print("Not connected to any peer.")
                    continue
                file_mgr.scan_files()
                our_files = file_mgr.get_file_list()
                if not our_files:
                    print("No files to send.")
                    continue
                for i, f in enumerate(our_files):
                    print(f"  {i+1}. {f.filename} ({f.file_size} bytes)")
                idx = int(input("Select file: ").strip()) - 1
                meta = our_files[idx]

                accepted = await offer_file(current_session, current_reader, current_writer, meta)
                if accepted:
                    await send_file(current_session, current_writer, file_mgr, meta.file_id)
                    print("File sent.")

            elif choice == "6":
                new_priv, new_pub = generate_identity_keypair()
                notice = create_rotation_notice(priv, pub, new_priv, new_pub)

                # Notify all connected peers
                for name, (sess, _, wrt) in conn_mgr.active_sessions.items():
                    await send_key_rotation(sess, wrt, notice)
                    print(f"Notified {name} of key rotation.")

                # Update local state
                priv, pub = new_priv, new_pub
                pub_bytes = get_public_key_bytes(pub)
                seed = private_key_to_seed(priv)
                storage.save_identity_key(seed)
                file_mgr.identity_priv = priv
                file_mgr.identity_pub = pub
                file_mgr.identity_pub_bytes = pub_bytes
                conn_mgr.identity_priv = priv
                conn_mgr.identity_pub = pub
                print(f"New fingerprint: {fingerprint(pub_bytes)}")

            elif choice == "7":
                if not trust_store.contacts:
                    print("No trusted contacts.")
                else:
                    for fp, entry in trust_store.contacts.items():
                        status = "trusted" if entry["trusted"] else "untrusted"
                        print(f"  {entry['display_name']}: {status}")

            elif choice == "8":
                file_mgr.scan_files()
                print(f"Found {len(file_mgr.get_file_list())} files.")

            elif choice == "9":
                break

            else:
                print("Invalid option.")

    finally:
        print("\nShutting down...")
        storage.save_trust_store(trust_store)
        discovery.stop()
        conn_mgr.stop()
        print("Goodbye.")


if __name__ == "__main__":
    asyncio.run(main())

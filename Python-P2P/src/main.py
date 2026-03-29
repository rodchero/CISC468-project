import asyncio
import os
import threading
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
    offer_file, send_key_rotation, receive_file, resolve_owner_pubkey,
)
from src.key_rotation import create_rotation_notice

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


async def main():
    print("=== P2P Secure File Sharing ===\n")

    # Setup prompts (before server starts, regular input is fine)
    display_name = input("Enter display name: ").strip()
    password = input("Enter password: ").strip()
    port = int(input("Port [9468]: ").strip() or "9468")

    # Each instance gets its own storage and shared directory
    STORAGE_DIR = os.path.join(BASE_DIR, f".p2p_storage_{port}")
    SHARED_DIR = os.path.join(BASE_DIR, f"shared_files_{port}")

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

    # Load cached third-party metadata before scanning
    cache = storage.load_metadata_cache()
    if cache:
        file_mgr.import_third_party(cache)

    file_mgr.scan_files()
    print(f"Sharing {len(file_mgr.get_file_list())} files from {SHARED_DIR}")

    # Start mDNS discovery
    discovery = PeerDiscovery()
    await discovery.start(display_name, port)
    print("mDNS discovery started.")

    # Start TCP server
    conn_mgr = ConnectionManager(priv, pub, display_name, trust_store, file_mgr)
    await conn_mgr.start_server(port)

    # Background stdin reader — single thread reads all input
    input_queue = asyncio.Queue()
    loop = asyncio.get_event_loop()

    def _stdin_reader():
        while True:
            try:
                line = input()
                loop.call_soon_threadsafe(input_queue.put_nowait, line)
            except EOFError:
                break

    threading.Thread(target=_stdin_reader, daemon=True).start()

    async def get_input(prompt=""):
        """Print prompt and wait for next line from stdin."""
        if prompt:
            print(prompt, end="", flush=True)
        return await input_queue.get()

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
            print("\n> ", end="", flush=True)

            # Race: wait for user input OR a consent request from a peer
            input_task = asyncio.create_task(input_queue.get())
            consent_task = asyncio.create_task(conn_mgr.pending_consents.get())

            done, pending = await asyncio.wait(
                {input_task, consent_task},
                return_when=asyncio.FIRST_COMPLETED,
            )

            for t in pending:
                t.cancel()

            # If a consent request arrived, handle it immediately
            if consent_task in done:
                req = consent_task.result()
                # If user also typed something, put it back for next loop
                if input_task in done:
                    input_queue.put_nowait(input_task.result())
                answer = await get_input(f"\n{req['prompt']}")
                req["future"].set_result(answer.strip().lower() == "y")
                continue

            choice = input_task.result().strip()

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
                    ip = (await get_input("No mDNS peers. Enter IP manually: ")).strip()
                    port = int((await get_input("Port [9468]: ")).strip() or "9468")
                else:
                    for i, p in enumerate(peers):
                        print(f"  {i+1}. {p['name']} ({p['ip']}:{p['port']})")
                    idx = int((await get_input("Select peer: ")).strip()) - 1
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
                idx = int((await get_input("Select file: ")).strip()) - 1
                meta = files[idx]

                approved = await request_file(current_session, current_reader, current_writer, meta.file_id)
                if approved:
                    owner_key = resolve_owner_pubkey(
                        meta, current_session.peer_identity_pubkey, trust_store
                    )
                    if owner_key is None:
                        owner_key = current_session.peer_identity_pubkey
                    filepath = await receive_file(
                        current_session, current_reader, meta, SHARED_DIR, owner_key
                    )
                    file_mgr.store_third_party_metadata(meta)
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
                idx = int((await get_input("Select file: ")).strip()) - 1
                meta = our_files[idx]

                accepted = await offer_file(current_session, current_reader, current_writer, meta)
                if accepted:
                    await send_file(current_session, current_writer, file_mgr, meta.file_id)
                    print("File sent.")

            elif choice == "6":
                new_priv, new_pub = generate_identity_keypair()
                notice = create_rotation_notice(priv, pub, new_priv, new_pub)

                # Notify all connected peers
                for name, (sess, _, wrt) in list(conn_mgr.active_sessions.items()):
                    try:
                        await send_key_rotation(sess, wrt, notice)
                        print(f"Notified {name} of key rotation.")
                    except (ConnectionError, OSError):
                        print(f"Could not notify {name} (disconnected).")

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
        storage.save_metadata_cache(file_mgr.export_third_party())
        await discovery.stop()
        conn_mgr.stop()
        print("Goodbye.")


if __name__ == "__main__":
    asyncio.run(main())

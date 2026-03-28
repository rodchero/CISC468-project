import os
import asyncio
import pytest
from src.crypto_utils import generate_identity_keypair, get_public_key_bytes
from src.handshake import perform_handshake_initiator, perform_handshake_responder
from src.file_manager import FileManager
from src.trust import TrustStore
from src.key_rotation import create_rotation_notice
from src.crypto_utils import sha256
from src.file_manager import verify_file_metadata
from src.protocol import (
    request_file_list, handle_file_list_request,
    request_file, send_file, receive_file,
    offer_file, resolve_owner_pubkey,
    send_app_message, recv_app_message,
    handle_key_rotation,
    FILE_LIST_REQUEST, FILE_RESPONSE, FILE_SEND_RESPONSE,
)
from src.generated.p2pfileshare_pb2 import FileResponse, FileSendResponse
from src.errors import (
    P2PError, KEY_ROTATION_INVALID, FILE_HASH_MISMATCH, INVALID_FILE_SIGNATURE,
)


async def _connect_peers():
    """Full handshake over loopback TCP. Returns (alice, bob, server, keep_alive)."""
    priv_a, pub_a = generate_identity_keypair()
    priv_b, pub_b = generate_identity_keypair()

    bob_ready = asyncio.Event()
    keep_alive = asyncio.Future()
    bob = {}

    async def bob_handler(reader, writer):
        session = await perform_handshake_responder(reader, writer, priv_b, pub_b, "bob")
        bob["session"] = session
        bob["reader"] = reader
        bob["writer"] = writer
        bob_ready.set()
        try:
            await keep_alive
        except (asyncio.CancelledError, Exception):
            pass
        writer.close()

    srv = await asyncio.start_server(bob_handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    reader_a, writer_a = await asyncio.open_connection("127.0.0.1", port)
    session_a = await perform_handshake_initiator(reader_a, writer_a, priv_a, pub_a, "alice")
    await bob_ready.wait()

    alice = {
        "session": session_a, "reader": reader_a, "writer": writer_a,
        "priv": priv_a, "pub": pub_a, "pub_bytes": get_public_key_bytes(pub_a),
    }
    bob_state = {
        "session": bob["session"], "reader": bob["reader"], "writer": bob["writer"],
        "priv": priv_b, "pub": pub_b, "pub_bytes": get_public_key_bytes(pub_b),
    }
    return alice, bob_state, srv, keep_alive


async def _close(alice, srv, keep_alive):
    if not keep_alive.done():
        keep_alive.set_result(None)
    try:
        alice["writer"].close()
    except Exception:
        pass
    await asyncio.sleep(0.05)
    srv.close()


# ---- Authentication ----

@pytest.mark.asyncio
async def test_handshake_keys_cross_match():
    alice, bob, srv, keep_alive = await _connect_peers()

    assert alice["session"].send_key == bob["session"].recv_key
    assert alice["session"].recv_key == bob["session"].send_key
    assert alice["session"].peer_display_name == "bob"
    assert bob["session"].peer_display_name == "alice"
    assert alice["session"].peer_identity_pubkey == bob["pub_bytes"]
    assert bob["session"].peer_identity_pubkey == alice["pub_bytes"]

    await _close(alice, srv, keep_alive)


@pytest.mark.asyncio
async def test_encrypted_message_roundtrip():
    alice, bob, srv, keep_alive = await _connect_peers()

    from src.generated.p2pfileshare_pb2 import FileListRequest
    req = FileListRequest()
    await send_app_message(alice["session"], alice["writer"], FILE_LIST_REQUEST, req)

    msg_type, _ = await recv_app_message(bob["session"], bob["reader"])
    assert msg_type == FILE_LIST_REQUEST

    await _close(alice, srv, keep_alive)


# ---- File list ----

@pytest.mark.asyncio
async def test_file_list_exchange(tmp_path):
    alice, bob, srv, keep_alive = await _connect_peers()

    bob_dir = str(tmp_path / "bob_files")
    os.makedirs(bob_dir)
    with open(os.path.join(bob_dir, "readme.txt"), "wb") as f:
        f.write(b"hello from bob")

    fm_bob = FileManager(bob_dir, bob["priv"], bob["pub"])
    fm_bob.scan_files()

    async def bob_responds():
        msg_type, _ = await recv_app_message(bob["session"], bob["reader"])
        await handle_file_list_request(
            bob["session"], bob["reader"], bob["writer"], fm_bob.get_file_list()
        )

    task = asyncio.create_task(bob_responds())
    files = await request_file_list(alice["session"], alice["reader"], alice["writer"])
    await task

    assert len(files) == 1
    assert files[0].filename == "readme.txt"

    await _close(alice, srv, keep_alive)


# ---- File transfer ----

@pytest.mark.asyncio
async def test_file_transfer_consent_granted(tmp_path):
    alice, bob, srv, keep_alive = await _connect_peers()

    bob_dir = str(tmp_path / "bob_files")
    alice_dir = str(tmp_path / "alice_dl")
    os.makedirs(bob_dir)
    os.makedirs(alice_dir)

    content = b"secret document"
    with open(os.path.join(bob_dir, "secret.txt"), "wb") as f:
        f.write(content)

    fm_bob = FileManager(bob_dir, bob["priv"], bob["pub"])
    fm_bob.scan_files()
    meta = fm_bob.get_file_list()[0]
    file_id = meta.file_id

    async def bob_side():
        msg_type, req = await recv_app_message(bob["session"], bob["reader"])
        resp = FileResponse()
        resp.approved = True
        await send_app_message(bob["session"], bob["writer"], FILE_RESPONSE, resp)
        await send_file(bob["session"], bob["writer"], fm_bob, file_id)

    task = asyncio.create_task(bob_side())
    approved = await request_file(alice["session"], alice["reader"], alice["writer"], file_id)
    assert approved
    filepath = await receive_file(
        alice["session"], alice["reader"], meta, alice_dir, bob["pub_bytes"]
    )
    await task

    with open(filepath, "rb") as f:
        assert f.read() == content

    await _close(alice, srv, keep_alive)


@pytest.mark.asyncio
async def test_file_transfer_consent_denied(tmp_path):
    alice, bob, srv, keep_alive = await _connect_peers()

    bob_dir = str(tmp_path / "bob_files")
    os.makedirs(bob_dir)
    with open(os.path.join(bob_dir, "private.txt"), "wb") as f:
        f.write(b"nope")

    fm_bob = FileManager(bob_dir, bob["priv"], bob["pub"])
    fm_bob.scan_files()
    file_id = fm_bob.get_file_list()[0].file_id

    async def bob_side():
        msg_type, _ = await recv_app_message(bob["session"], bob["reader"])
        resp = FileResponse()
        resp.approved = False
        resp.error_code = "CONSENT_DENIED"
        await send_app_message(bob["session"], bob["writer"], FILE_RESPONSE, resp)

    task = asyncio.create_task(bob_side())
    approved = await request_file(alice["session"], alice["reader"], alice["writer"], file_id)
    await task

    assert approved is False

    await _close(alice, srv, keep_alive)


# ---- File send offer ----

@pytest.mark.asyncio
async def test_file_send_offer_accepted(tmp_path):
    alice, bob, srv, keep_alive = await _connect_peers()

    alice_dir = str(tmp_path / "alice_files")
    bob_dir = str(tmp_path / "bob_dl")
    os.makedirs(alice_dir)
    os.makedirs(bob_dir)

    content = b"sharing is caring"
    with open(os.path.join(alice_dir, "shared.txt"), "wb") as f:
        f.write(content)

    fm_alice = FileManager(alice_dir, alice["priv"], alice["pub"])
    fm_alice.scan_files()
    meta = fm_alice.get_file_list()[0]

    async def bob_side():
        msg_type, offer = await recv_app_message(bob["session"], bob["reader"])
        resp = FileSendResponse()
        resp.accepted = True
        await send_app_message(bob["session"], bob["writer"], FILE_SEND_RESPONSE, resp)
        filepath = await receive_file(
            bob["session"], bob["reader"], offer.metadata, bob_dir, alice["pub_bytes"]
        )
        return filepath

    task = asyncio.create_task(bob_side())
    accepted = await offer_file(alice["session"], alice["reader"], alice["writer"], meta)
    assert accepted
    await send_file(alice["session"], alice["writer"], fm_alice, meta.file_id)
    filepath = await task

    with open(filepath, "rb") as f:
        assert f.read() == content

    await _close(alice, srv, keep_alive)


@pytest.mark.asyncio
async def test_file_send_offer_rejected(tmp_path):
    alice, bob, srv, keep_alive = await _connect_peers()

    alice_dir = str(tmp_path / "alice_files")
    os.makedirs(alice_dir)
    with open(os.path.join(alice_dir, "unwanted.txt"), "wb") as f:
        f.write(b"nah")

    fm_alice = FileManager(alice_dir, alice["priv"], alice["pub"])
    fm_alice.scan_files()
    meta = fm_alice.get_file_list()[0]

    async def bob_side():
        msg_type, _ = await recv_app_message(bob["session"], bob["reader"])
        resp = FileSendResponse()
        resp.accepted = False
        await send_app_message(bob["session"], bob["writer"], FILE_SEND_RESPONSE, resp)

    task = asyncio.create_task(bob_side())
    accepted = await offer_file(alice["session"], alice["reader"], alice["writer"], meta)
    await task

    assert accepted is False

    await _close(alice, srv, keep_alive)


# ---- Integrity ----

@pytest.mark.asyncio
async def test_integrity_hash_mismatch(tmp_path):
    alice, bob, srv, keep_alive = await _connect_peers()

    bob_dir = str(tmp_path / "bob_files")
    alice_dir = str(tmp_path / "alice_dl")
    os.makedirs(bob_dir)
    os.makedirs(alice_dir)

    filepath = os.path.join(bob_dir, "data.bin")
    with open(filepath, "wb") as f:
        f.write(b"original content")

    fm_bob = FileManager(bob_dir, bob["priv"], bob["pub"])
    fm_bob.scan_files()
    meta = fm_bob.get_file_list()[0]
    file_id = meta.file_id

    # Tamper with file on disk after metadata was signed
    with open(filepath, "wb") as f:
        f.write(b"tampered_content")

    async def bob_sends():
        await send_file(bob["session"], bob["writer"], fm_bob, file_id)

    task = asyncio.create_task(bob_sends())

    with pytest.raises(P2PError) as exc_info:
        await receive_file(
            alice["session"], alice["reader"], meta, alice_dir, bob["pub_bytes"]
        )
    await task

    assert exc_info.value.error_code == FILE_HASH_MISMATCH
    assert not os.path.exists(os.path.join(alice_dir, "data.bin"))

    await _close(alice, srv, keep_alive)


@pytest.mark.asyncio
async def test_integrity_bogus_signature(tmp_path):
    alice, bob, srv, keep_alive = await _connect_peers()

    bob_dir = str(tmp_path / "bob_files")
    alice_dir = str(tmp_path / "alice_dl")
    os.makedirs(bob_dir)
    os.makedirs(alice_dir)

    with open(os.path.join(bob_dir, "signed.bin"), "wb") as f:
        f.write(b"signed content")

    fm_bob = FileManager(bob_dir, bob["priv"], bob["pub"])
    fm_bob.scan_files()
    meta = fm_bob.get_file_list()[0]
    file_id = meta.file_id

    # Tamper with the signature
    meta.owner_signature = b'\x00' * 64

    async def bob_sends():
        await send_file(bob["session"], bob["writer"], fm_bob, file_id)

    task = asyncio.create_task(bob_sends())

    with pytest.raises(P2PError) as exc_info:
        await receive_file(
            alice["session"], alice["reader"], meta, alice_dir, bob["pub_bytes"]
        )
    await task

    assert exc_info.value.error_code == INVALID_FILE_SIGNATURE
    assert not os.path.exists(os.path.join(alice_dir, "signed.bin"))

    await _close(alice, srv, keep_alive)


# ---- Key rotation ----

@pytest.mark.asyncio
async def test_key_rotation_valid():
    old_priv, old_pub = generate_identity_keypair()
    new_priv, new_pub = generate_identity_keypair()
    old_bytes = get_public_key_bytes(old_pub)
    new_bytes = get_public_key_bytes(new_pub)

    store = TrustStore()
    store.add_contact(old_bytes, "alice", trusted=True)

    notice = create_rotation_notice(old_priv, old_pub, new_priv, new_pub)
    await handle_key_rotation(None, store, notice)

    assert not store.is_known(old_bytes)
    assert store.is_known(new_bytes)
    assert not store.is_trusted(new_bytes)


@pytest.mark.asyncio
async def test_key_rotation_bad_signature():
    old_priv, old_pub = generate_identity_keypair()
    new_priv, new_pub = generate_identity_keypair()
    old_bytes = get_public_key_bytes(old_pub)

    store = TrustStore()
    store.add_contact(old_bytes, "alice", trusted=True)

    notice = create_rotation_notice(old_priv, old_pub, new_priv, new_pub)
    notice.old_signature = b'\x00' * 64

    with pytest.raises(P2PError) as exc_info:
        await handle_key_rotation(None, store, notice)
    assert exc_info.value.error_code == KEY_ROTATION_INVALID


# ---- Third-party file verification ----

@pytest.mark.asyncio
async def test_third_party_file_transfer(tmp_path):
    """Alice creates a file. Bob downloads it. Charlie downloads from Bob
    and verifies using Alice's original signature."""
    alice, bob, srv, keep_alive = await _connect_peers()

    alice_dir = str(tmp_path / "alice_files")
    bob_dir = str(tmp_path / "bob_dl")
    os.makedirs(alice_dir)
    os.makedirs(bob_dir)

    content = b"alice original content"
    with open(os.path.join(alice_dir, "paper.txt"), "wb") as f:
        f.write(content)

    fm_alice = FileManager(alice_dir, alice["priv"], alice["pub"])
    fm_alice.scan_files()
    meta = fm_alice.get_file_list()[0]
    file_id = meta.file_id

    # Bob downloads from Alice
    async def alice_sends():
        msg_type, _ = await recv_app_message(alice["session"], alice["reader"])
        resp = FileResponse()
        resp.approved = True
        await send_app_message(alice["session"], alice["writer"], FILE_RESPONSE, resp)
        await send_file(alice["session"], alice["writer"], fm_alice, file_id)

    task = asyncio.create_task(alice_sends())
    approved = await request_file(bob["session"], bob["reader"], bob["writer"], file_id)
    assert approved
    filepath = await receive_file(
        bob["session"], bob["reader"], meta, bob_dir, alice["pub_bytes"]
    )
    await task

    # Bob stores the third-party metadata (preserves Alice's signature)
    fm_bob = FileManager(bob_dir, bob["priv"], bob["pub"])
    fm_bob.store_third_party_metadata(meta)
    fm_bob.scan_files()

    # Verify Bob's file list includes alice's file with alice's signature
    bob_files = fm_bob.get_file_list()
    found = [f for f in bob_files if f.filename == "paper.txt"]
    assert len(found) == 1
    assert found[0].owner_signature == meta.owner_signature
    assert verify_file_metadata(found[0], alice["pub_bytes"])

    # Now simulate Charlie verifying: resolve_owner_pubkey should find alice's key
    trust = TrustStore()
    trust.add_contact(alice["pub_bytes"], "alice", trusted=True)
    trust.add_contact(bob["pub_bytes"], "bob", trusted=True)

    owner_key = resolve_owner_pubkey(found[0], bob["pub_bytes"], trust)
    assert owner_key == alice["pub_bytes"]
    assert verify_file_metadata(found[0], owner_key)

    await _close(alice, srv, keep_alive)

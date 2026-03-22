import os
import asyncio
import tempfile
from unittest.mock import patch
import pytest
from src.session import Session
from src.protocol import (
    request_file_list, handle_file_list_request,
    request_file, handle_file_request,
    send_file, receive_file,
    offer_file, handle_file_offer,
    send_app_message, recv_app_message, FILE_LIST_REQUEST,
)
from src.generated.p2pfileshare_pb2 import FileMetadata
from src.file_manager import FileManager
from src.crypto_utils import generate_identity_keypair, get_public_key_bytes
from src.errors import P2PError, FILE_HASH_MISMATCH


def _make_session_pair():
    key_a = os.urandom(32)
    key_b = os.urandom(32)
    initiator = Session(key_a, key_b, b'\x00' * 32, "bob", True)
    responder = Session(key_b, key_a, b'\x00' * 32, "alice", False)
    return initiator, responder


def _make_test_metadata():
    meta = FileMetadata()
    meta.owner_fingerprint = b'\xaa' * 32
    meta.file_id = b'\xbb' * 32
    meta.filename = "notes.txt"
    meta.file_size = 1234
    meta.file_hash = b'\xcc' * 32
    meta.timestamp = 1700000000
    meta.owner_signature = b'\xdd' * 64
    return meta


@pytest.mark.asyncio
async def test_file_list_roundtrip():
    client_sess, server_sess = _make_session_pair()
    result = {}

    test_meta = _make_test_metadata()

    async def server_handler(reader, writer):
        # Receive the file list request
        msg_type, _ = await recv_app_message(server_sess, reader)
        assert msg_type == FILE_LIST_REQUEST

        # Send back a file list with one file
        await handle_file_list_request(server_sess, reader, writer, [test_meta])
        writer.close()

    srv = await asyncio.start_server(server_handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    files = await request_file_list(client_sess, reader, writer)
    writer.close()

    await asyncio.sleep(0.1)
    srv.close()

    assert len(files) == 1
    f = files[0]
    assert f.filename == "notes.txt"
    assert f.file_size == 1234
    assert f.file_hash == b'\xcc' * 32
    assert f.file_id == b'\xbb' * 32


@pytest.mark.asyncio
async def test_empty_file_list():
    client_sess, server_sess = _make_session_pair()

    async def server_handler(reader, writer):
        await recv_app_message(server_sess, reader)
        await handle_file_list_request(server_sess, reader, writer, [])
        writer.close()

    srv = await asyncio.start_server(server_handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    files = await request_file_list(client_sess, reader, writer)
    writer.close()

    await asyncio.sleep(0.1)
    srv.close()

    assert len(files) == 0


def _make_file_manager_with_file():
    """Create a FileManager with one test file, return (fm, file_id, tmpdir)."""
    priv, pub = generate_identity_keypair()
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "secret.txt")
    with open(path, "wb") as f:
        f.write(b"secret data")
    fm = FileManager(tmpdir, priv, pub)
    fm.scan_files()
    file_id = fm.get_file_list()[0].file_id
    return fm, file_id, tmpdir


@pytest.mark.asyncio
async def test_file_request_approved():
    client_sess, server_sess = _make_session_pair()
    fm, file_id, _ = _make_file_manager_with_file()

    async def server_handler(reader, writer):
        with patch("builtins.input", return_value="y"):
            await handle_file_request(server_sess, reader, writer, fm)
        writer.close()

    srv = await asyncio.start_server(server_handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    result = await request_file(client_sess, reader, writer, file_id)
    writer.close()

    await asyncio.sleep(0.1)
    srv.close()

    assert result is True


@pytest.mark.asyncio
async def test_file_request_denied():
    client_sess, server_sess = _make_session_pair()
    fm, file_id, _ = _make_file_manager_with_file()

    async def server_handler(reader, writer):
        with patch("builtins.input", return_value="n"):
            await handle_file_request(server_sess, reader, writer, fm)
        writer.close()

    srv = await asyncio.start_server(server_handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    result = await request_file(client_sess, reader, writer, file_id)
    writer.close()

    await asyncio.sleep(0.1)
    srv.close()

    assert result is False


@pytest.mark.asyncio
async def test_file_request_not_found():
    client_sess, server_sess = _make_session_pair()
    fm, _, _ = _make_file_manager_with_file()
    fake_id = b'\xff' * 32  # doesn't exist

    async def server_handler(reader, writer):
        await handle_file_request(server_sess, reader, writer, fm)
        writer.close()

    srv = await asyncio.start_server(server_handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    result = await request_file(client_sess, reader, writer, fake_id)
    writer.close()

    await asyncio.sleep(0.1)
    srv.close()

    assert result is False


# --- Day 15: chunked file transfer ---

def _make_file_manager_with_content(content: bytes):
    """Create a FileManager with a single file containing given bytes."""
    priv, pub = generate_identity_keypair()
    pub_bytes = get_public_key_bytes(pub)
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "testfile.bin")
    with open(path, "wb") as f:
        f.write(content)
    fm = FileManager(tmpdir, priv, pub)
    fm.scan_files()
    meta = fm.get_file_list()[0]
    return fm, meta, pub_bytes, tmpdir


@pytest.mark.asyncio
async def test_transfer_small_file():
    content = b"small file content here"
    fm, meta, pub_bytes, _ = _make_file_manager_with_content(content)
    client_sess, server_sess = _make_session_pair()
    output_dir = tempfile.mkdtemp()

    async def server_handler(reader, writer):
        await send_file(server_sess, writer, fm, meta.file_id)
        writer.close()

    srv = await asyncio.start_server(server_handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    outpath = await receive_file(client_sess, reader, meta, output_dir, pub_bytes)
    writer.close()

    await asyncio.sleep(0.1)
    srv.close()

    with open(outpath, "rb") as f:
        assert f.read() == content


@pytest.mark.asyncio
async def test_transfer_multi_chunk():
    # ~200KB so it splits into a few 64KB chunks
    content = os.urandom(200_000)
    fm, meta, pub_bytes, _ = _make_file_manager_with_content(content)
    client_sess, server_sess = _make_session_pair()
    output_dir = tempfile.mkdtemp()

    async def server_handler(reader, writer):
        await send_file(server_sess, writer, fm, meta.file_id)
        writer.close()

    srv = await asyncio.start_server(server_handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    outpath = await receive_file(client_sess, reader, meta, output_dir, pub_bytes)
    writer.close()

    await asyncio.sleep(0.1)
    srv.close()

    with open(outpath, "rb") as f:
        assert f.read() == content


@pytest.mark.asyncio
async def test_transfer_hash_mismatch():
    content = b"original content"
    fm, meta, pub_bytes, _ = _make_file_manager_with_content(content)
    client_sess, server_sess = _make_session_pair()
    output_dir = tempfile.mkdtemp()

    # Tamper with the expected hash so verification fails
    meta.file_hash = b'\x00' * 32

    async def server_handler(reader, writer):
        await send_file(server_sess, writer, fm, meta.file_id)
        writer.close()

    srv = await asyncio.start_server(server_handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    with pytest.raises(P2PError) as exc_info:
        await receive_file(client_sess, reader, meta, output_dir, pub_bytes)
    writer.close()

    await asyncio.sleep(0.1)
    srv.close()

    # File should have been deleted
    assert not os.path.exists(os.path.join(output_dir, "testfile.bin"))


# --- Day 16: file send offer ---

@pytest.mark.asyncio
async def test_offer_accepted():
    content = b"offered file data"
    fm, meta, pub_bytes, _ = _make_file_manager_with_content(content)
    sender_sess, receiver_sess = _make_session_pair()
    output_dir = tempfile.mkdtemp()

    async def receiver_handler(reader, writer):
        with patch("builtins.input", return_value="y"):
            await handle_file_offer(receiver_sess, reader, writer, output_dir, pub_bytes)
        writer.close()

    srv = await asyncio.start_server(receiver_handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    accepted = await offer_file(sender_sess, reader, writer, meta)
    assert accepted

    # Now send the file since it was accepted
    await send_file(sender_sess, writer, fm, meta.file_id)
    writer.close()

    await asyncio.sleep(0.1)
    srv.close()

    outpath = os.path.join(output_dir, meta.filename)
    assert os.path.exists(outpath)
    with open(outpath, "rb") as f:
        assert f.read() == content


@pytest.mark.asyncio
async def test_offer_rejected():
    content = b"unwanted file"
    fm, meta, pub_bytes, _ = _make_file_manager_with_content(content)
    sender_sess, receiver_sess = _make_session_pair()
    output_dir = tempfile.mkdtemp()

    async def receiver_handler(reader, writer):
        with patch("builtins.input", return_value="n"):
            result = await handle_file_offer(receiver_sess, reader, writer, output_dir, pub_bytes)
        assert result is None
        writer.close()

    srv = await asyncio.start_server(receiver_handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    accepted = await offer_file(sender_sess, reader, writer, meta)
    writer.close()

    await asyncio.sleep(0.1)
    srv.close()

    assert accepted is False
    # No file should have been written
    assert not os.path.exists(os.path.join(output_dir, meta.filename))

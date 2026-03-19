import os
import asyncio
import pytest
from src.session import Session
from src.protocol import (
    request_file_list, handle_file_list_request,
    send_app_message, recv_app_message, FILE_LIST_REQUEST,
)
from src.generated.p2pfileshare_pb2 import FileMetadata


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

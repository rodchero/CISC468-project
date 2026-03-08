import asyncio
import pytest
from src.framing import send_message, recv_message
from src.generated.p2pfileshare_pb2 import P2PMessage, Hello, AuthSignature


@pytest.mark.asyncio
async def test_send_recv_hello():
    """Send a Hello in a P2PMessage, receive it, check fields match."""
    server_ready = asyncio.Event()
    result = {}

    async def server(reader, writer):
        msg = await recv_message(reader)
        result["msg"] = msg
        writer.close()

    srv = await asyncio.start_server(server, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    msg = P2PMessage()
    msg.hello.protocol_version = 1
    msg.hello.identity_public_key = b'\xaa' * 32
    msg.hello.ephemeral_public_key = b'\xbb' * 32
    msg.hello.display_name = "alice"

    await send_message(writer, msg)
    writer.close()

    # Give server a moment to process
    await asyncio.sleep(0.1)
    srv.close()

    got = result["msg"]
    assert got.WhichOneof("payload") == "hello"
    assert got.hello.protocol_version == 1
    assert got.hello.identity_public_key == b'\xaa' * 32
    assert got.hello.ephemeral_public_key == b'\xbb' * 32
    assert got.hello.display_name == "alice"


@pytest.mark.asyncio
async def test_multiple_messages():
    """Send two messages back to back, make sure framing keeps them separate."""
    results = []

    async def server(reader, writer):
        msg1 = await recv_message(reader)
        msg2 = await recv_message(reader)
        results.append(msg1)
        results.append(msg2)
        writer.close()

    srv = await asyncio.start_server(server, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    # First message: Hello
    msg1 = P2PMessage()
    msg1.hello.protocol_version = 1
    msg1.hello.display_name = "bob"
    await send_message(writer, msg1)

    # Second message: AuthSignature
    msg2 = P2PMessage()
    msg2.auth_signature.signature = b'\xcc' * 64
    await send_message(writer, msg2)

    writer.close()
    await asyncio.sleep(0.1)
    srv.close()

    assert len(results) == 2
    assert results[0].WhichOneof("payload") == "hello"
    assert results[0].hello.display_name == "bob"
    assert results[1].WhichOneof("payload") == "auth_signature"
    assert results[1].auth_signature.signature == b'\xcc' * 64


@pytest.mark.asyncio
async def test_connection_closed():
    """If connection drops mid-read, we should get an error."""
    srv = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    await asyncio.sleep(0.1)

    with pytest.raises(asyncio.IncompleteReadError):
        await recv_message(reader)

    writer.close()
    srv.close()

import struct
import asyncio
from src.generated.p2pfileshare_pb2 import P2PMessage

MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MB


async def send_message(writer: asyncio.StreamWriter, message: P2PMessage):
    data = message.SerializeToString()
    length = len(data)
    writer.write(struct.pack('>I', length) + data)
    await writer.drain()


async def recv_message(reader: asyncio.StreamReader) -> P2PMessage:
    # Read 4-byte length prefix
    header = await reader.readexactly(4)
    length = struct.unpack('>I', header)[0]

    if length == 0 or length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Invalid message length: {length}")

    data = await reader.readexactly(length)
    msg = P2PMessage()
    msg.ParseFromString(data)
    return msg

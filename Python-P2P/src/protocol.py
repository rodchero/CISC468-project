import asyncio
from src.generated.p2pfileshare_pb2 import (
    FileListRequest, FileListResponse, FileRequest, FileResponse,
    FileChunk, FileTransferComplete, FileSendOffer, FileSendResponse,
    KeyRotationNotice, ErrorMessage,
)
import os
from src.framing import send_message
from src.file_manager import verify_file_integrity, verify_file_metadata
from src.errors import (
    P2PError, FILE_HASH_MISMATCH, INVALID_FILE_SIGNATURE,
    KEY_ROTATION_INVALID, INVALID_MESSAGE, TRANSFER_INTERRUPTED,
)
from src.crypto_utils import sha256
from src.key_rotation import verify_rotation_notice

# Message type strings — must match between Python and Rust
FILE_LIST_REQUEST = "FileListRequest"
FILE_LIST_RESPONSE = "FileListResponse"
FILE_REQUEST = "FileRequest"
FILE_RESPONSE = "FileResponse"
FILE_CHUNK = "FileChunk"
FILE_TRANSFER_COMPLETE = "FileTransferComplete"
FILE_SEND_OFFER = "FileSendOffer"
FILE_SEND_RESPONSE = "FileSendResponse"
KEY_ROTATION_NOTICE = "KeyRotationNotice"
ERROR_MESSAGE = "ErrorMessage"

# Map message type strings to protobuf classes for parsing
MSG_TYPE_MAP = {
    FILE_LIST_REQUEST: FileListRequest,
    FILE_LIST_RESPONSE: FileListResponse,
    FILE_REQUEST: FileRequest,
    FILE_RESPONSE: FileResponse,
    FILE_CHUNK: FileChunk,
    FILE_TRANSFER_COMPLETE: FileTransferComplete,
    FILE_SEND_OFFER: FileSendOffer,
    FILE_SEND_RESPONSE: FileSendResponse,
    KEY_ROTATION_NOTICE: KeyRotationNotice,
    ERROR_MESSAGE: ErrorMessage,
}


def resolve_owner_pubkey(metadata, sender_pubkey_bytes, trust_store):
    """Figure out which key to verify a file with. If the sender isn't the
    owner (third-party file), look up the original owner in the trust store."""
    sender_fp = sha256(sender_pubkey_bytes)
    if metadata.owner_fingerprint == sender_fp:
        return sender_pubkey_bytes
    return trust_store.lookup_by_owner_fingerprint(metadata.owner_fingerprint)


async def send_app_message(session, writer, msg_type, inner_msg):
    plaintext = inner_msg.SerializeToString()
    msg = session.encrypt(msg_type, plaintext)
    await send_message(writer, msg)


async def recv_app_message(session, reader):
    msg_type, plaintext = await session.recv_encrypted(reader)

    proto_class = MSG_TYPE_MAP.get(msg_type)
    if proto_class is None:
        raise P2PError(INVALID_MESSAGE, f"Unknown message type: {msg_type}")

    parsed = proto_class()
    parsed.ParseFromString(plaintext)
    return msg_type, parsed


async def request_file_list(session, reader, writer):
    req = FileListRequest()
    await send_app_message(session, writer, FILE_LIST_REQUEST, req)

    msg_type, resp = await recv_app_message(session, reader)
    return list(resp.files)


async def handle_file_list_request(session, reader, writer, file_list):
    resp = FileListResponse()
    for f in file_list:
        resp.files.append(f)
    await send_app_message(session, writer, FILE_LIST_RESPONSE, resp)


async def request_file(session, reader, writer, file_id) -> bool:
    req = FileRequest()
    req.file_id = file_id
    await send_app_message(session, writer, FILE_REQUEST, req)

    msg_type, resp = await recv_app_message(session, reader)
    if resp.approved:
        return True
    print(f"File request denied: {resp.error_code}")
    return False


async def handle_file_request(session, reader, writer, file_manager):
    msg_type, req = await recv_app_message(session, reader)
    file_id = req.file_id
    filepath = file_manager.get_file_path(file_id)

    resp = FileResponse()

    if filepath is None:
        resp.approved = False
        resp.error_code = "FILE_NOT_FOUND"
        await send_app_message(session, writer, FILE_RESPONSE, resp)
        return

    # Look up filename for the prompt
    _, meta = file_manager.files[file_id]
    answer = input(f"Peer wants to download '{meta.filename}'. Allow? [y/n]: ").strip().lower()

    if answer == "y":
        resp.approved = True
    else:
        resp.approved = False
        resp.error_code = "CONSENT_DENIED"

    await send_app_message(session, writer, FILE_RESPONSE, resp)


async def send_file(session, writer, file_manager, file_id, chunk_size=65536):
    filepath = file_manager.get_file_path(file_id)
    # Decrypt file from secure storage before sending
    file_bytes = file_manager._read_file(filepath)
    chunk_index = 0

    for i in range(0, len(file_bytes), chunk_size):
        chunk = FileChunk()
        chunk.file_id = file_id
        chunk.chunk_index = chunk_index
        chunk.data = file_bytes[i:i + chunk_size]
        await send_app_message(session, writer, FILE_CHUNK, chunk)
        chunk_index += 1

    complete = FileTransferComplete()
    complete.file_id = file_id
    complete.total_chunks = chunk_index
    await send_app_message(session, writer, FILE_TRANSFER_COMPLETE, complete)


async def receive_file(session, reader, expected_metadata, output_dir, owner_pubkey_bytes, file_manager=None) -> str:
    chunks = {}

    try:
        while True:
            msg_type, msg = await recv_app_message(session, reader)
            if msg_type == FILE_CHUNK:
                chunks[msg.chunk_index] = msg.data
            elif msg_type == FILE_TRANSFER_COMPLETE:
                break
    except (asyncio.IncompleteReadError, ConnectionError) as e:
        raise P2PError(TRANSFER_INTERRUPTED, f"Connection lost during transfer: {e}")

    # Reassemble in order
    file_bytes = b""
    for i in range(len(chunks)):
        file_bytes += chunks[i]

    # Verify signature against plaintext before writing
    if not verify_file_metadata(expected_metadata, owner_pubkey_bytes):
        raise P2PError(INVALID_FILE_SIGNATURE, "File metadata signature invalid")

    # Verify hash against plaintext
    if sha256(file_bytes) != expected_metadata.file_hash:
        raise P2PError(FILE_HASH_MISMATCH, "File hash does not match metadata")

    # Write encrypted to disk
    filepath = os.path.join(output_dir, expected_metadata.filename)
    if file_manager:
        file_manager._write_file(filepath, file_bytes)
    else:
        with open(filepath, "wb") as f:
            f.write(file_bytes)

    return filepath


async def offer_file(session, reader, writer, metadata) -> bool:
    offer = FileSendOffer()
    offer.metadata.CopyFrom(metadata)
    await send_app_message(session, writer, FILE_SEND_OFFER, offer)

    msg_type, resp = await recv_app_message(session, reader)

    if msg_type == FILE_SEND_RESPONSE:
        # Python-to-Python: peer sends FileSendResponse
        if resp.accepted:
            return True
        print("Peer declined the file.")
        return False
    elif msg_type == FILE_REQUEST:
        # Rust interop: peer sends FileRequest (means accepted)
        file_resp = FileResponse()
        file_resp.approved = True
        await send_app_message(session, writer, FILE_RESPONSE, file_resp)
        return True
    else:
        print(f"Unexpected response to file offer: {msg_type}")
        return False


async def handle_file_offer(session, reader, writer, output_dir, owner_pubkey_bytes):
    msg_type, offer = await recv_app_message(session, reader)
    meta = offer.metadata

    answer = input(
        f"Peer wants to send you '{meta.filename}' ({meta.file_size} bytes). Accept? [y/n]: "
    ).strip().lower()

    resp = FileSendResponse()
    if answer == "y":
        resp.accepted = True
        await send_app_message(session, writer, FILE_SEND_RESPONSE, resp)
        return await receive_file(session, reader, meta, output_dir, owner_pubkey_bytes)
    else:
        resp.accepted = False
        await send_app_message(session, writer, FILE_SEND_RESPONSE, resp)
        return None


async def send_key_rotation(session, writer, notice):
    await send_app_message(session, writer, KEY_ROTATION_NOTICE, notice)


async def handle_key_rotation(session, trust_store, notice):
    fp = trust_store._fp(notice.old_public_key)
    if fp not in trust_store.contacts:
        # Peer not in trust store yet — add them so rotation can proceed
        name = session.peer_display_name if session else "unknown"
        trust_store.add_contact(notice.old_public_key, name)

    if not verify_rotation_notice(notice, notice.old_public_key):
        raise P2PError(KEY_ROTATION_INVALID, "Key rotation verification failed")

    trust_store.replace_key(notice.old_public_key, notice.new_public_key)
    print("Contact rotated their key. Re-verification required.")

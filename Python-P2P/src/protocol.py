from src.generated.p2pfileshare_pb2 import (
    FileListRequest, FileListResponse, FileRequest, FileResponse,
    FileChunk, FileTransferComplete, FileSendOffer, FileSendResponse,
    KeyRotationNotice, ErrorMessage,
)
import os
from src.framing import send_message
from src.file_manager import verify_file_integrity, verify_file_metadata
from src.errors import P2PError, FILE_HASH_MISMATCH, INVALID_FILE_SIGNATURE, KEY_ROTATION_INVALID
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


async def send_app_message(session, writer, msg_type, inner_msg):
    plaintext = inner_msg.SerializeToString()
    msg = session.encrypt(msg_type, plaintext)
    await send_message(writer, msg)


async def recv_app_message(session, reader):
    msg_type, plaintext = await session.recv_encrypted(reader)

    proto_class = MSG_TYPE_MAP.get(msg_type)
    if proto_class is None:
        raise ValueError(f"Unknown message type: {msg_type}")

    parsed = proto_class()
    parsed.ParseFromString(plaintext)
    return msg_type, parsed


async def request_file_list(session, reader, writer):
    req = FileListRequest()
    await send_app_message(session, writer, FILE_LIST_REQUEST, req)

    msg_type, resp = await recv_app_message(session, reader)
    # TODO: handle unexpected message type
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
    # TODO: make this non-blocking
    answer = input(f"Peer wants to download '{meta.filename}'. Allow? [y/n]: ").strip().lower()

    if answer == "y":
        resp.approved = True
    else:
        resp.approved = False
        resp.error_code = "CONSENT_DENIED"

    await send_app_message(session, writer, FILE_RESPONSE, resp)


async def send_file(session, writer, file_manager, file_id, chunk_size=65536):
    filepath = file_manager.get_file_path(file_id)
    chunk_index = 0

    with open(filepath, "rb") as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            chunk = FileChunk()
            chunk.file_id = file_id
            chunk.chunk_index = chunk_index
            chunk.data = data
            await send_app_message(session, writer, FILE_CHUNK, chunk)
            chunk_index += 1

    complete = FileTransferComplete()
    complete.file_id = file_id
    complete.total_chunks = chunk_index
    await send_app_message(session, writer, FILE_TRANSFER_COMPLETE, complete)


async def receive_file(session, reader, expected_metadata, output_dir, owner_pubkey_bytes) -> str:
    chunks = {}

    # TODO: handle missing chunks or out-of-order total_chunks
    while True:
        msg_type, msg = await recv_app_message(session, reader)
        if msg_type == FILE_CHUNK:
            chunks[msg.chunk_index] = msg.data
        elif msg_type == FILE_TRANSFER_COMPLETE:
            break

    # Reassemble in order
    file_bytes = b""
    for i in range(len(chunks)):
        file_bytes += chunks[i]

    filepath = os.path.join(output_dir, expected_metadata.filename)
    with open(filepath, "wb") as f:
        f.write(file_bytes)

    # Verify signature first, then integrity
    if not verify_file_metadata(expected_metadata, owner_pubkey_bytes):
        os.remove(filepath)
        raise P2PError(INVALID_FILE_SIGNATURE, "File metadata signature invalid")

    if not verify_file_integrity(filepath, expected_metadata):
        os.remove(filepath)
        raise P2PError(FILE_HASH_MISMATCH, "File hash does not match metadata")

    return filepath


async def offer_file(session, reader, writer, metadata) -> bool:
    offer = FileSendOffer()
    offer.metadata.CopyFrom(metadata)
    await send_app_message(session, writer, FILE_SEND_OFFER, offer)

    msg_type, resp = await recv_app_message(session, reader)
    if resp.accepted:
        return True
    print("Peer declined the file.")
    return False


async def handle_file_offer(session, reader, writer, output_dir, owner_pubkey_bytes):
    msg_type, offer = await recv_app_message(session, reader)
    meta = offer.metadata

    # TODO: make this non-blocking
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
    # Look up the stored old key to verify against
    stored_old = bytes.fromhex(
        trust_store.contacts[trust_store._fp(notice.old_public_key)]["pubkey"]
    )

    if not verify_rotation_notice(notice, stored_old):
        raise P2PError(KEY_ROTATION_INVALID, "Key rotation verification failed")

    trust_store.replace_key(notice.old_public_key, notice.new_public_key)
    print("Contact rotated their key. Re-verification required.")

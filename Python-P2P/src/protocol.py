from src.generated.p2pfileshare_pb2 import (
    FileListRequest, FileListResponse, FileRequest, FileResponse,
    FileChunk, FileTransferComplete, FileSendOffer, FileSendResponse,
    KeyRotationNotice, ErrorMessage,
)
from src.framing import send_message

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

import asyncio
from src.handshake import perform_handshake_initiator, perform_handshake_responder
from src.protocol import (
    recv_app_message, handle_file_list_request, handle_file_request,
    handle_file_offer, handle_key_rotation, send_file, send_app_message,
    FILE_LIST_REQUEST, FILE_REQUEST, FILE_SEND_OFFER,
    KEY_ROTATION_NOTICE, ERROR_MESSAGE,
)
from src.errors import P2PError


class ConnectionManager:
    def __init__(self, identity_priv, identity_pub, display_name, trust_store, file_manager):
        self.identity_priv = identity_priv
        self.identity_pub = identity_pub
        self.display_name = display_name
        self.trust_store = trust_store
        self.file_manager = file_manager
        self.active_sessions = {}  # peer_display_name -> (session, reader, writer)
        self.pending_consents = asyncio.Queue()
        self.server = None

    async def start_server(self, port=9468):
        self.server = await asyncio.start_server(
            self._handle_connection, "0.0.0.0", port
        )
        print(f"Listening on port {port}")

    async def _handle_connection(self, reader, writer):
        addr = writer.get_extra_info("peername")
        print(f"Incoming connection from {addr}")
        try:
            session = await perform_handshake_responder(
                reader, writer, self.identity_priv, self.identity_pub, self.display_name
            )
            print(f"Handshake complete with {session.peer_display_name}")
            self.active_sessions[session.peer_display_name] = (session, reader, writer)
            await self._message_loop(session, reader, writer)
        except P2PError as e:
            print(f"Handshake failed: {e}")
        except ConnectionError:
            print(f"Peer disconnected during handshake.")
        except Exception as e:
            print(f"Connection error: {e}")
        finally:
            writer.close()

    async def connect_to_peer(self, ip, port):
        reader, writer = await asyncio.open_connection(ip, port)
        try:
            session = await perform_handshake_initiator(
                reader, writer, self.identity_priv, self.identity_pub, self.display_name
            )
            print(f"Connected to {session.peer_display_name}")
            self.active_sessions[session.peer_display_name] = (session, reader, writer)
            return session
        except P2PError as e:
            print(f"Handshake failed: {e}")
            writer.close()
            return None

    async def _message_loop(self, session, reader, writer):
        try:
            while True:
                msg_type, plaintext = await session.recv_encrypted(reader)

                if msg_type == FILE_LIST_REQUEST:
                    file_list = self.file_manager.get_file_list()
                    await handle_file_list_request(session, reader, writer, file_list)

                elif msg_type == FILE_REQUEST:
                    from src.generated.p2pfileshare_pb2 import FileRequest, FileResponse
                    req = FileRequest()
                    req.ParseFromString(plaintext)
                    file_id = req.file_id
                    filepath = self.file_manager.get_file_path(file_id)

                    resp = FileResponse()
                    if filepath is None:
                        resp.approved = False
                        resp.error_code = "FILE_NOT_FOUND"
                        from src.protocol import send_app_message, FILE_RESPONSE
                        await send_app_message(session, writer, FILE_RESPONSE, resp)
                    else:
                        _, meta = self.file_manager.files[file_id]
                        # Queue consent request — menu loop will prompt the user
                        future = asyncio.get_event_loop().create_future()
                        await self.pending_consents.put({
                            "prompt": f"Peer wants to download '{meta.filename}'. Allow? [y/n]: ",
                            "future": future,
                        })
                        print(f"\n[!] Incoming file request for '{meta.filename}' — answer at next menu prompt")
                        approved = await future
                        if approved:
                            resp.approved = True
                            from src.protocol import send_app_message, FILE_RESPONSE
                            await send_app_message(session, writer, FILE_RESPONSE, resp)
                            await send_file(session, writer, self.file_manager, file_id)
                        else:
                            resp.approved = False
                            resp.error_code = "CONSENT_DENIED"
                            from src.protocol import send_app_message, FILE_RESPONSE
                            await send_app_message(session, writer, FILE_RESPONSE, resp)

                elif msg_type == FILE_SEND_OFFER:
                    from src.generated.p2pfileshare_pb2 import FileSendOffer
                    offer = FileSendOffer()
                    offer.ParseFromString(plaintext)
                    meta = offer.metadata
                    # Queue consent request — menu loop will prompt the user
                    future = asyncio.get_event_loop().create_future()
                    await self.pending_consents.put({
                        "prompt": f"Peer wants to send you '{meta.filename}' ({meta.file_size} bytes). Accept? [y/n]: ",
                        "future": future,
                    })
                    print(f"\n[!] Incoming file offer '{meta.filename}' — answer at next menu prompt")
                    accepted = await future
                    from src.protocol import send_app_message, FILE_SEND_RESPONSE, receive_file, resolve_owner_pubkey
                    from src.generated.p2pfileshare_pb2 import FileSendResponse
                    resp = FileSendResponse()
                    if accepted:
                        resp.accepted = True
                        await send_app_message(session, writer, FILE_SEND_RESPONSE, resp)
                        output_dir = self.file_manager.shared_dir
                        owner_key = resolve_owner_pubkey(meta, session.peer_identity_pubkey, self.trust_store)
                        if owner_key is None:
                            owner_key = session.peer_identity_pubkey
                        await receive_file(session, reader, meta, output_dir, owner_key)
                        self.file_manager.store_third_party_metadata(meta)
                        print(f"Received file: {meta.filename}")
                    else:
                        resp.accepted = False
                        await send_app_message(session, writer, FILE_SEND_RESPONSE, resp)

                elif msg_type == KEY_ROTATION_NOTICE:
                    from src.generated.p2pfileshare_pb2 import KeyRotationNotice
                    notice = KeyRotationNotice()
                    notice.ParseFromString(plaintext)
                    await handle_key_rotation(session, self.trust_store, notice)

                elif msg_type == ERROR_MESSAGE:
                    from src.generated.p2pfileshare_pb2 import ErrorMessage
                    err = ErrorMessage()
                    err.ParseFromString(plaintext)
                    print(f"Peer error: {err.error_code} - {err.description}")

                else:
                    print(f"Unknown message type: {msg_type}")

        except asyncio.IncompleteReadError:
            print(f"Peer {session.peer_display_name} disconnected.")
        except P2PError as e:
            print(f"Protocol error: {e}")
            try:
                from src.generated.p2pfileshare_pb2 import ErrorMessage as ErrMsg
                err = ErrMsg()
                err.error_code = e.error_code
                err.description = e.description
                await send_app_message(session, writer, ERROR_MESSAGE, err)
            except Exception:
                pass  # connection might already be dead
        except ConnectionError:
            print(f"Peer {session.peer_display_name} disconnected.")
        except Exception as e:
            print(f"Connection error: {e}")
        finally:
            self.active_sessions.pop(session.peer_display_name, None)

    def stop(self):
        if self.server:
            self.server.close()

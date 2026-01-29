import asyncio
import base64
import json
import logging
from contextlib import suppress

import websockets

from .authenticate import Authenticate
from .receive import ReceiveData
from .entries import Entry, Entries
from .establish_connection import EstablishConnection
from .type_int import TypeInt
from .message import MessageReceived, MessageSend, MC_AUTO

logger = logging.getLogger(__name__)


class QueuedMessage:
    """Wrapper for a message to be sent along with its optional ACK callback."""

    def __init__(self, message: MessageSend, async_ack_callback=None):
        self.message = message
        self.async_ack_callback = async_ack_callback


KEEPALIVE_INTERVAL = 270.0
MINIMUM_MC = 20000  # minimum message count number
MAXIMUM_MC = 32000  # maximum message count number
HEADERS = {}


class Connection:
    def __init__(
        self,
        *,
        strict_mode: bool = False,
        message_log_filename: str | None = None,
        dump_entities: bool = False,
        traverse_screens_on_init: bool = False,
    ) -> None:
        self.ws = None
        self.strict = strict_mode
        self.message_log_filename = message_log_filename
        self.dump_entities = dump_entities
        self.traverse_screens_on_init = traverse_screens_on_init
        self.device_id = None
        self.device_version = None
        self.connection_id = None
        self.device_signature = None
        self.token = None
        self.device_home_id = None
        self.device_home_name = None
        self.sc_id = None
        self.async_notify_update_callbacks = []
        self.event_initial_setup_complete = asyncio.Event()
        self.event_initial_traverse_screens_complete = asyncio.Event()
        self.entries = Entries(self)
        self.data = ReceiveData(self)
        self.establish_connection_obj = EstablishConnection(self)
        self.authentication_obj = Authenticate(self)
        self.message_queue = asyncio.Queue()
        self.message_counter = MINIMUM_MC
        self.cipher = None
        self.pending_ack_callbacks = {}  # ref -> callback mapping

        # Create TraverseScreens object if screen traversal is enabled
        self.traverse_screens_obj = None
        if self.traverse_screens_on_init:
            from .traverse_screens import TraverseScreens

            self.traverse_screens_obj = TraverseScreens(self)
            # we need to add it here, before connection is being initialized
            # as it has to intercept messages that send over the initial screens
            self.add_async_notify_update_callback(
                self.traverse_screens_obj.entry_update_callback
            )

    def _log_raw_message(self, direction: str, payload: str) -> None:
        """Append raw message text to the log file, if configured."""
        if not self.message_log_filename:
            return
        try:
            # Parse JSON and pretty-print it
            try:
                parsed = json.loads(payload)
                pretty_payload = json.dumps(parsed, indent=2)
            except (json.JSONDecodeError, ValueError):
                # If not valid JSON, use as-is
                pretty_payload = payload

            with open(self.message_log_filename, "a", encoding="utf-8") as f:
                f.write(f"{direction}\n{pretty_payload}\n\n")
        except Exception:  # pragma: no cover - logging should not break flow
            logger.warning("Failed to write raw message log", exc_info=True)

    def add_async_notify_update_callback(self, callback) -> None:
        if callback not in self.async_notify_update_callbacks:
            self.async_notify_update_callbacks.append(callback)

    def remove_async_notify_update_callback(self, callback) -> None:
        if callback in self.async_notify_update_callbacks:
            self.async_notify_update_callbacks.remove(callback)

    async def async_notify_update(self, key: tuple, entry: Entry, new: bool) -> None:
        for callback in self.async_notify_update_callbacks:
            await callback(key, entry, new)

    async def initial_connection_setup_complete(self) -> None:
        """Called when initial connection setup is complete (after SET_ALERTS)."""
        if not self.event_initial_setup_complete.is_set():
            self.event_initial_setup_complete.set()
            # If traverse_screens is enabled, start traversal in background
            # Note: traverse_screens will wait for event_initial_setup_complete before proceeding anyway
            if self.traverse_screens_obj:

                async def run_traverse():
                    try:
                        await self.traverse_screens_obj.traverse_screens()
                    except Exception as e:
                        logger.error(
                            "Error during traverse_screens: %s", e, exc_info=True
                        )
                    finally:
                        self.remove_async_notify_update_callback(
                            self.traverse_screens_obj.entry_update_callback
                        )
                        self.event_initial_traverse_screens_complete.set()

                asyncio.create_task(run_traverse())

    async def enqueue_authentication_flow(
        self,
        username,
        password,
        auto_start_session=True,
        async_auth_result_callback=None,
    ):
        return await self.authentication_obj.enqueue_authentication_flow(
            username,
            password,
            auto_start_session,
            async_auth_result_callback,
        )

    async def receive_raw_message(self):
        buffer = b""
        while b"\x04" not in buffer:
            try:
                chunk = await self.ws.recv()  # type: ignore
            except (
                websockets.exceptions.ConnectionClosed,
                websockets.exceptions.ConnectionClosedOK,
            ) as e:
                logger.warning("Connection closed during recv: %s", e)
                raise

            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8")
            if not chunk:
                raise ConnectionError("Connection closed before message complete")
            buffer += chunk

        if buffer.endswith(b"\x04"):
            msg_bytes = buffer[:-1]
        else:
            raise Exception(
                "Protocol error: message does not end with terminator", buffer
            )
        return msg_bytes

    async def receive_message(self):
        msg_encoded = await self.receive_raw_message()

        encrypted_data = base64.b64decode(msg_encoded)

        if self.cipher is None:
            raise RuntimeError("Cipher not initialized; secure connection missing")

        decryptor = self.cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
        decrypted_msg = decrypted_padded.rstrip(b"\x00").decode("utf-8")

        self._log_raw_message("recv", decrypted_msg)

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Received decrypted JSON: {decrypted_msg}")
        data = json.loads(decrypted_msg)

        if self.strict:
            allowed_keys = {"type_int", "mc", "payload", "ref"}
            extra_keys = set(data.keys()) - allowed_keys
            if extra_keys:
                logger.error(
                    "Strict mode: unexpected fields %s in message: %s", extra_keys, data
                )
                raise ValueError(f"Message contains unexpected fields: {extra_keys}")

        return MessageReceived(
            type_int=data.get("type_int"),
            mc=data.get("mc"),
            payload=data.get("payload"),
            ref=data.get("ref"),
        )

    async def messages_process(self):
        last_keepalive = asyncio.get_event_loop().time()
        socket_task: asyncio.Task | None = None
        queue_task: asyncio.Task | None = None

        try:
            while True:
                current_time = asyncio.get_event_loop().time()
                if current_time - last_keepalive >= KEEPALIVE_INTERVAL:
                    await self.send_keepalive()
                    last_keepalive = current_time

                time_until_keepalive = KEEPALIVE_INTERVAL - (
                    current_time - last_keepalive
                )
                timeout = max(0.1, time_until_keepalive)

                socket_task = asyncio.create_task(self.receive_message())
                queue_task = asyncio.create_task(self.message_queue.get())

                done, pending = await asyncio.wait(
                    [socket_task, queue_task],
                    timeout=timeout,
                    return_when=asyncio.FIRST_COMPLETED,
                )

                for task in pending:
                    task.cancel()
                    with suppress(asyncio.CancelledError):
                        await task

                queued_msg = None
                msg = None
                exception_to_raise = None

                for task in done:
                    try:
                        if task == queue_task:
                            queued_msg = task.result()
                        elif task == socket_task:
                            msg = task.result()
                    except asyncio.TimeoutError:
                        pass
                    except (
                        websockets.exceptions.ConnectionClosed,
                        websockets.exceptions.ConnectionClosedOK,
                    ) as e:
                        logger.warning("Connection closed detected in messages_process")
                        exception_to_raise = e
                    except Exception as e:  # pragma: no cover - defensive catch
                        logger.warning("Error receiving message: %s", e, exc_info=True)
                        exception_to_raise = e

                if exception_to_raise:
                    raise exception_to_raise

                if queued_msg is not None:
                    # Extract MessageSend and register callback if present
                    msg_to_send = queued_msg.message
                    # Auto-fill MC_AUTO with actual message counter
                    if msg_to_send.mc == MC_AUTO:
                        msg_to_send.mc = self.new_message_reference()
                    if queued_msg.async_ack_callback and msg_to_send.mc:
                        self.pending_ack_callbacks[msg_to_send.mc] = (
                            queued_msg.async_ack_callback
                        )
                    await self.send_message(msg_to_send)

                if msg is not None:
                    await self.async_dispatch_message(msg)

        except Exception:
            for task in (socket_task, queue_task):
                if task and not task.done():
                    task.cancel()
                    with suppress(asyncio.CancelledError):
                        await task
            raise

    async def send_ack_message(self, message_received):
        await self.send_message(
            MessageSend(
                type_int=TypeInt.ACK,
                ref=message_received.mc,
            )
        )
        logger.debug(f"Sent ACK for mc: {message_received.mc}")

    async def async_dispatch_message(self, msg: MessageReceived) -> None:
        if msg.type_int == TypeInt.ACK:
            await self.recv_ACK(msg)
        elif msg.type_int == TypeInt.NACK:
            await self.recv_NACK(msg)
        elif msg.type_int == TypeInt.HEARTBEAT:
            # Heartbeat messages are no-op, device is just keeping connection alive
            logger.debug("Received HEARTBEAT")
        elif msg.type_int == TypeInt.WAIT4ACK:
            # Device sends WAIT4ACK if it cannot answer the request within 3 seconds
            logger.debug(
                "Received WAIT4ACK, device is processing the request for more than 3 seconds"
            )
        elif msg.type_int == TypeInt.SET_HOME_DATA:
            await self.data.recv_SET_HOME_DATA(msg)
        elif msg.type_int == TypeInt.APP_INFO:
            await self.data.recv_APP_INFO(msg)
        elif msg.type_int == TypeInt.AUTH_LOGIN_DENIED:
            await self.authentication_obj.recv_AUTH_LOGIN_DENIED(msg)
        elif msg.type_int == TypeInt.AUTH_LOGIN_SUCCESS:
            await self.authentication_obj.recv_AUTH_LOGIN_SUCCESS(msg)
        elif msg.type_int == TypeInt.AUTH_APPLY_TOKEN_RESPONSE:
            await self.authentication_obj.recv_AUTH_APPLY_TOKEN_RESPONSE(msg)
        elif msg.type_int == TypeInt.ADD_SCREEN:
            await self.data.recv_ADD_SCREEN(msg)
        elif msg.type_int == TypeInt.ADD_DBENTRIES:
            await self.data.recv_ADD_DBENTRIES(msg)
        elif msg.type_int == TypeInt.ADD_ITEMS:
            await self.data.recv_ADD_ITEMS(msg)
        elif msg.type_int == TypeInt.SET_ALERTS:
            await self.data.recv_SET_ALERTS(msg)
            # there is no formal "initialization complete" message, but when alerts come, everything else seem to be already setup
            await self.initial_connection_setup_complete()
        elif msg.type_int == TypeInt.UPDATE_ITEMS:
            await self.data.recv_UPDATE_ITEMS(msg)
        else:
            logger.warning(f"Unhandled message: {msg}")

    async def recv_ACK(self, msg: MessageReceived) -> None:
        ref = msg.ref

        # Call callback if registered
        callback = self.pending_ack_callbacks.pop(ref, None)
        if callback is not None:
            await callback(True)

    async def recv_NACK(self, msg: MessageReceived) -> None:
        ref = msg.ref
        logger.info("Received NACK for ref: %s", ref)

        # Call callback if registered
        callback = self.pending_ack_callbacks.pop(ref, None)
        if callback is not None:
            await callback(False)

    async def send_message(self, msg: MessageSend) -> None:
        # Auto-fill MC_AUTO with actual message counter
        if msg.mc == MC_AUTO:
            msg.mc = self.new_message_reference()
        
        data = {
            "type_int": msg.type_int,
        }
        if msg.mc:
            data["mc"] = msg.mc
        if msg.payload:
            data["payload"] = msg.payload
        if msg.ref:
            data["ref"] = msg.ref

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Sending JSON: {data}")

        json_text = json.dumps(data)
        self._log_raw_message("send", json_text)

        msg_bytes = json_text.encode("utf-8")
        await self.encrypt_and_send_raw_message(msg_bytes)

    def new_message_reference(self) -> int:
        self.message_counter += 1
        if self.message_counter >= MAXIMUM_MC:
            self.message_counter = MINIMUM_MC
        return self.message_counter

    async def send_keepalive(self):
        msg = MessageSend(
            type_int=TypeInt.ACTION_SELECTED,
            payload={"ScreenID": 100},
            mc=self.new_message_reference(),
        )
        await self.send_message(msg)
        logger.debug("Sent ACTION_SELECTED with ScreenID=100")

    async def enqueue_message(self, msg: MessageSend, async_ack_callback=None) -> None:
        queued = QueuedMessage(msg, async_ack_callback)
        await self.message_queue.put(queued)

    async def enqueue_message_get_ack(self, msg: MessageSend) -> bool:
        """Enqueue a message and wait for ACK/NACK. Returns True for ACK, False for NACK."""
        ack_event = asyncio.Event()
        ack_result = False

        async def ack_callback(is_ack: bool):
            nonlocal ack_result
            ack_result = is_ack
            ack_event.set()

        queued = QueuedMessage(msg, ack_callback)
        await self.message_queue.put(queued)

        await ack_event.wait()
        return ack_result

    async def encrypt_and_send_raw_message(self, msg_bytes):
        pad_len = 16 - (len(msg_bytes) % 16)
        if pad_len < 16:
            msg_bytes += b"\x00" * pad_len

        if self.cipher is None:
            raise RuntimeError("Cipher not initialized; secure connection missing")

        encryptor = self.cipher.encryptor()
        encrypted_data = encryptor.update(msg_bytes) + encryptor.finalize()

        await self.ws.send(base64.b64encode(encrypted_data) + b"\x04")

    async def establish_secure_connection(self):
        return await self.establish_connection_obj.establish_secure_connection()

    async def async_websocket_connect(self, ws_url, proxy_url=None):
        ws_connect_kwargs = {
            "proxy": True,
        }

        if proxy_url:
            logger.info("Using proxy: %s", proxy_url)
            ws_connect_kwargs["proxy"] = proxy_url

        self.ws = await websockets.connect(ws_url, **ws_connect_kwargs)

        logger.info("Connected to WS server")

    async def async_close(self):
        if self.ws is not None:
            with suppress(Exception):
                await self.ws.close()
            self.ws = None

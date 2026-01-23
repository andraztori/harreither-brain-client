import asyncio
import base64
import json
import logging
from contextlib import suppress

import websockets
from cryptography.hazmat.primitives.asymmetric import rsa

from .authenticate import Authenticate
from .data import Data
from .establish_connection import EstablishConnection
from .type_int import TypeInt
from .message import MessageReceived, MessageSend

logger = logging.getLogger(__name__)

KEEPALIVE_INTERVAL = 270.0
MINIMUM_MC = 20000  # minimum message count number
MAXIMUM_MC = 32000  # maximum message count number
HEADERS = {}

class Connection:
    def __init__(self, *, strict_mode: bool = False) -> None:
        self.ws = None
        self.strict = strict_mode
        self.device_id = None
        self.device_version = None
        self.connection_id = None
        self.public_key: rsa.RSAPublicKey | None = None
        self.session_key = None
        self.session_iv = None
        self.device_signature = None
        self.token = None
        self.device_home_id = None
        self.device_home_name = None
        self.sc_id = None
        self.async_notify_update_callback = None
        self.event_initial_setup_complete = asyncio.Event()
        self.data = Data(self)
        self.establish_connection_obj = EstablishConnection(self)
        self.authentication_obj = Authenticate(self)
        self.message_queue = asyncio.Queue()
        self.message_counter = MINIMUM_MC
        self.cipher = None

    def set_async_notify_update_callback(self, callback) -> None:
        self.async_notify_update_callback = callback

    async def async_notify_update(self, key, value_dict, new):
        if self.async_notify_update_callback is not None:
            await self.async_notify_update_callback(key, value_dict, new)

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
                chunk = await self.ws.recv()
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

                time_until_keepalive = KEEPALIVE_INTERVAL - (current_time - last_keepalive)
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
                    await self.send_message(queued_msg)

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
        if msg.type_int == TypeInt.SET_HOME_DATA:
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
            if not self.event_initial_setup_complete.is_set():
                self.event_initial_setup_complete.set()
        elif msg.type_int == TypeInt.UPDATE_ITEMS:
            await self.data.recv_UPDATE_ITEMS(msg)
        else:
            logger.warning(f"Unhandled message: {msg}")

    async def recv_ACK(self, msg: MessageReceived) -> None:
        ref = msg.ref
        logger.debug("Received ACK for ref: %s", ref)

    async def send_message(self, msg: MessageSend) -> None:
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

        msg_bytes = json.dumps(data).encode("utf-8")
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

    async def enqueue_message(self, msg: MessageSend) -> None:
        await self.message_queue.put(msg)

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

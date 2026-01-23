import logging
import hashlib
import secrets
import string
from typing import Awaitable, Callable

from .type_int import TypeInt
from .message import MessageSend

logger = logging.getLogger(__name__)


def generate_key(length: int = 12) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def hash_device(device_id: str, password: str, salt: str | None = None) -> dict:
    inner = hashlib.sha256((device_id + password).encode("utf-8")).hexdigest()

    if not isinstance(salt, str) or len(salt) == 0:
        salt = generate_key(12)

    final_hash = hashlib.sha256((salt + inner).encode("utf-8")).hexdigest()

    return {
        "salt": salt,
        "hash": final_hash,
    }


class Authenticate:
    def __init__(self, connection) -> None:
        self.connection = connection
        self.auto_start_session = True
        self.async_auth_result_callback: Callable[[bool], Awaitable[None]] | None = None

    def create_auth_msg(self, username: str, password: str) -> MessageSend:
        auth_data = hash_device(self.connection.device_id, password)
        return MessageSend(
            type_int=TypeInt.AUTH_LOGIN,
            mc=1,
            payload={
                "username": username,
                "password": auth_data["hash"],
                "salt": auth_data["salt"],
            },
        )

    async def enqueue_authentication_flow(
        self,
        username: str,
        password: str,
        auto_start_session: bool = True,
        async_auth_result_callback: Callable[[bool], Awaitable[None]] | None = None,
    ):
        self.auto_start_session = auto_start_session
        self.async_auth_result_callback = async_auth_result_callback
        auth_msg = self.create_auth_msg(username, password)
        await self.connection.enqueue_message(auth_msg)
        logger.debug("Queued AUTH_LOGIN [30]")

    async def execute_authentication_now(self, username: str, password: str) -> bool:
        auth_msg = self.create_auth_msg(username, password)
        await self.connection.send_message(auth_msg)
        logger.debug("Sent AUTH_LOGIN [30] immediately")

        response = await self.connection.receive_message()

        if response.type_int == TypeInt.AUTH_LOGIN_SUCCESS:
            payload = response.payload
            self.connection.token = payload.get("token")
            logger.debug("Authentication successful! Token received.")
            return True
        if response.type_int == TypeInt.AUTH_LOGIN_DENIED:
            logger.debug("Authentication denied - wrong username or password.")
            return False
        raise ValueError(
            f"Unexpected message type during authentication: {response.type_int}"
        )

    async def _async_auth_result_callback(self, success: bool):
        if self.async_auth_result_callback is None:
            return
        try:
            await self.async_auth_result_callback(success)
        except Exception:
            logger.exception("async_auth_result_callback failed")

    async def recv_AUTH_LOGIN_SUCCESS(self, message):
        payload = message.payload
        self.connection.token = payload.get("token")

        logger.debug("Login success! Token received.")

        await self._async_auth_result_callback(True)

        if self.auto_start_session:
            await self.enqueue_AUTH_APPLY_TOKEN()

    async def recv_AUTH_LOGIN_DENIED(self, message):
        logger.error("Login denied by the server (device) - wrong username or password.")
        await self._async_auth_result_callback(False)

    async def enqueue_AUTH_APPLY_TOKEN(self):
        await self.connection.enqueue_message(
            MessageSend(
                type_int=TypeInt.AUTH_APPLY_TOKEN,
                mc=-1,
                payload={"token": self.connection.token},
            )
        )
        logger.debug("Queued AUTH_APPLY_TOKEN [33]")

    async def recv_AUTH_APPLY_TOKEN_RESPONSE(self, message):
        payload = message.payload
        valid = payload.get("valid")
        remaining = payload.get("remaining")

        logger.debug(f"Auth Result: valid={valid}, remaining={remaining}")

        if not valid:
            logger.warning("Applying the token failed!")

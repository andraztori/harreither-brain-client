import base64
import json
import logging
from secrets import token_bytes

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .type_int import TypeInt

logger = logging.getLogger(__name__)


class EstablishConnection:  # noqa: D101
    def __init__(self, connection) -> None:
        self.connection = connection
        self.public_key: rsa.RSAPublicKey | None = None
        self.session_key: bytes | None = None
        self.session_iv: bytes | None = None

    async def recv_unencrypted(self, label):
        msg_bytes = await self.connection.receive_raw_message()
        return json.loads(msg_bytes.decode("utf-8"))

    async def send_json_message(self, type_int, payload=None, mc=-1):
        data = {
            "type_int": type_int,
            "mc": mc,
        }
        if payload:
            data["payload"] = payload

        await self.connection.ws.send(json.dumps(data) + "\x04")
        logger.debug(f"Sent type_int: {type_int} ({TypeInt.get_name(type_int)})")

    async def establish_secure_connection(self):
        first = await self.recv_unencrypted("FIRST")

        if first.get("type_int") != TypeInt.CONNECTION_START:
            raise ValueError(
                f"Expected CONNECTION_START ({TypeInt.CONNECTION_START.value}), got {first.get('type_int')}"
            )

        payload = first.get("payload", {})
        self.connection.device_id = payload.get("device_id")
        self.connection.device_version = payload.get("device_version")
        self.connection.connection_id = payload.get("connection_id")

        logger.info(
            f"Connected [10]. ID: {self.connection.connection_id}, Device: {self.connection.device_id}, Version: {self.connection.device_version}"
        )

        await self.send_json_message(
            type_int=TypeInt.CONNECTION_CONFIRM,
            payload={
                "client_type": "nextgen-app",
                "client_id": "abaf877411be6b59",
                "client_version": "1.2.2",
                "connection_id": self.connection.connection_id,
            },
        )

        resp_11 = await self.recv_unencrypted("RESP 11")
        resp_11_type = resp_11.get("type_int")

        if resp_11_type == TypeInt.CONNECTION_DECLINED:
            reason = resp_11.get("payload", {}).get("reason") or "unknown reason"
            raise ConnectionError(f"Connection declined by device: {reason}")

        if resp_11_type != TypeInt.CONNECTION_ESTABLISHED:
            raise ValueError(
                f"Expected CONNECTION_ESTABLISHED ({TypeInt.CONNECTION_ESTABLISHED.value}), got {resp_11_type}"
            )

        logger.info(f"Connection established [12]: {resp_11}")

        await self.send_json_message(type_int=TypeInt.SC_INIT)

        resp_14 = await self.recv_unencrypted("RESP 14")

        if resp_14.get("type_int") != TypeInt.SC_PUBKEY:
            raise ValueError(
                f"Expected SC_PUBKEY ({TypeInt.SC_PUBKEY.value}), got {resp_14.get('type_int')}"
            )

        payload = resp_14.get("payload", {})

        public_key = payload.get("public_key")
        device_signature = payload.get("device_signature")

        if not public_key or not device_signature:
            raise ValueError("Missing public_key or device_signature in payload")

        logger.debug(f"Public key [15]: {public_key}")
        logger.debug(f"Device signature [15]: {device_signature}")

        # in theory we would now check the device signature, but why...

        self.public_key = serialization.load_pem_public_key(
            public_key.encode("utf-8"), backend=default_backend()
        )

        self.connection.device_signature = device_signature

        self.session_key = token_bytes(32)
        self.session_iv = token_bytes(16)

        logger.debug(f"Generated Session Key: {self.session_key.hex()}")
        logger.debug(f"Generated Session IV: {self.session_iv.hex()}")

        # Only the cipher is needed by the connection for subsequent encrypted traffic
        self.connection.cipher = Cipher(
            algorithms.AES(self.session_key),
            modes.CBC(self.session_iv),
            backend=default_backend(),
        )
        secret_payload = (
            f"{self.session_key.hex()}:::{self.session_iv.hex()}"
        )

        encrypted_secret = self.public_key.encrypt(
            secret_payload.encode("utf-8"), padding.PKCS1v15()
        )

        secret = base64.b64encode(encrypted_secret).decode("utf-8")
        await self.send_json_message(
            type_int=TypeInt.SC_SECRET,
            payload={"secret": secret},
        )
        msg_bytes_17 = await self.connection.receive_raw_message()
        resp_17_raw = base64.b64decode(msg_bytes_17)
        decryptor = self.connection.cipher.decryptor()
        decrypted_17_padded = decryptor.update(resp_17_raw) + decryptor.finalize()
        decrypted_17_bytes = decrypted_17_padded.rstrip(b"\x00")

        try:
            resp_17 = json.loads(decrypted_17_bytes.decode("utf-8"))
        except json.JSONDecodeError:
            raise ValueError(
                f"Failed to decode SC_ESTABLISHED message as JSON: {decrypted_17_bytes}"
            )

        if resp_17.get("type_int") != TypeInt.SC_ESTABLISHED:
            raise ValueError(
                f"Expected SC_ESTABLISHED ({TypeInt.SC_ESTABLISHED.value}), got {resp_17.get('type_int')}"
            )

        payload = resp_17.get("payload", {})
        self.connection.sc_id = payload.get("sc_id")

        logger.info(f"Secure Connection established. SC_ID: {self.connection.sc_id}")

import asyncio
import base64
import json
import unittest
from unittest.mock import patch

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from harreither_brain_client.establish_connection import EstablishConnection
from harreither_brain_client.type_int import TypeInt


class FakeWebSocket:
    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, data: str) -> None:
        self.sent.append(data)


class FakeConnection:
    def __init__(self, recv_bytes: list[bytes]) -> None:
        self.ws = FakeWebSocket()
        self._recv_iter = iter(recv_bytes)
        self.device_id = None
        self.device_version = None
        self.connection_id = None
        self.public_key = None
        self.device_signature = None
        self.session_key = None
        self.session_iv = None
        self.cipher = None
        self.sc_id = None

    async def receive_raw_message(self) -> bytes:
        try:
            return next(self._recv_iter)
        except StopIteration:
            raise AssertionError("No more fake messages queued")


class EstablishConnectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_establish_secure_connection_happy_path(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_pem = (
            private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )

        session_key = b"K" * 32
        session_iv = b"I" * 16

        sc_established_payload = json.dumps(
            {"type_int": TypeInt.SC_ESTABLISHED, "payload": {"sc_id": "secure-1"}}
        ).encode("utf-8")
        pad_len = (16 - (len(sc_established_payload) % 16)) % 16
        padded = sc_established_payload + b"\x00" * pad_len
        encryptor = Cipher(
            algorithms.AES(session_key),
            modes.CBC(session_iv),
            backend=default_backend(),
        ).encryptor()
        resp17_ciphertext = encryptor.update(padded) + encryptor.finalize()
        resp17_base64 = base64.b64encode(resp17_ciphertext)

        first = json.dumps(
            {
                "type_int": TypeInt.CONNECTION_START,
                "payload": {
                    "device_id": "dev-1",
                    "device_version": "1.0",
                    "connection_id": "conn-1",
                },
            }
        ).encode("utf-8")
        resp_11 = json.dumps({"type_int": TypeInt.CONNECTION_ESTABLISHED}).encode(
            "utf-8"
        )
        resp_14 = json.dumps(
            {
                "type_int": TypeInt.SC_PUBKEY,
                "payload": {"public_key": public_pem, "device_signature": "sig"},
            }
        ).encode("utf-8")

        fake_conn = FakeConnection([first, resp_11, resp_14, resp17_base64])
        handler = EstablishConnection(fake_conn)

        with patch(
            "harreither_brain_client.establish_connection.token_bytes",
            side_effect=[session_key, session_iv],
        ):
            await handler.establish_secure_connection()

        self.assertEqual(fake_conn.device_id, "dev-1")
        self.assertEqual(fake_conn.device_version, "1.0")
        self.assertEqual(fake_conn.connection_id, "conn-1")

        secret_msg = json.loads(fake_conn.ws.sent[2][:-1])
        encrypted_secret_b64 = secret_msg["payload"]["secret"]
        decrypted_secret = private_key.decrypt(
            base64.b64decode(encrypted_secret_b64), padding.PKCS1v15()
        ).decode("utf-8")
        self.assertEqual(decrypted_secret, f"{session_key.hex()}:::{session_iv.hex()}")

        self.assertIsNotNone(fake_conn.cipher)
        self.assertEqual(fake_conn.session_key, session_key)
        self.assertEqual(fake_conn.session_iv, session_iv)
        self.assertEqual(fake_conn.sc_id, "secure-1")

        sent_msgs = [json.loads(msg[:-1]) for msg in fake_conn.ws.sent]
        self.assertEqual(sent_msgs[0]["type_int"], TypeInt.CONNECTION_CONFIRM)
        self.assertEqual(sent_msgs[1]["type_int"], TypeInt.SC_INIT)
        self.assertEqual(sent_msgs[2]["type_int"], TypeInt.SC_SECRET)

    async def test_establish_secure_connection_declined_raises(self):
        first = json.dumps({"type_int": TypeInt.CONNECTION_START, "payload": {}}).encode(
            "utf-8"
        )
        declined = json.dumps(
            {"type_int": TypeInt.CONNECTION_DECLINED, "payload": {"reason": "nope"}}
        ).encode("utf-8")
        fake_conn = FakeConnection([first, declined])
        handler = EstablishConnection(fake_conn)

        with self.assertRaises(ConnectionError):
            await handler.establish_secure_connection()

        sent_msgs = [json.loads(msg[:-1]) for msg in fake_conn.ws.sent]
        self.assertEqual(len(sent_msgs), 1)
        self.assertEqual(sent_msgs[0]["type_int"], TypeInt.CONNECTION_CONFIRM)

    async def test_establish_secure_connection_wrong_first_message(self):
        first = json.dumps({"type_int": TypeInt.HEARTBEAT}).encode("utf-8")
        fake_conn = FakeConnection([first])
        handler = EstablishConnection(fake_conn)

        with self.assertRaises(ValueError):
            await handler.establish_secure_connection()

        self.assertEqual(fake_conn.ws.sent, [])

    async def test_establish_secure_connection_missing_pubkey(self):
        first = json.dumps({"type_int": TypeInt.CONNECTION_START, "payload": {}}).encode(
            "utf-8"
        )
        resp_11 = json.dumps({"type_int": TypeInt.CONNECTION_ESTABLISHED}).encode(
            "utf-8"
        )
        resp_14 = json.dumps(
            {
                "type_int": TypeInt.SC_PUBKEY,
                "payload": {"public_key": None, "device_signature": None},
            }
        ).encode("utf-8")
        fake_conn = FakeConnection([first, resp_11, resp_14])
        handler = EstablishConnection(fake_conn)

        with self.assertRaises(ValueError):
            await handler.establish_secure_connection()

        sent_msgs = [json.loads(msg[:-1]) for msg in fake_conn.ws.sent]
        self.assertEqual(len(sent_msgs), 2)
        self.assertEqual(sent_msgs[0]["type_int"], TypeInt.CONNECTION_CONFIRM)
        self.assertEqual(sent_msgs[1]["type_int"], TypeInt.SC_INIT)


if __name__ == "__main__":
    unittest.main()

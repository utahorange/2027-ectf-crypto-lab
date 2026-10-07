import json

from enum import Enum

class CommandType(Enum):
    UPDATE = 1
    BOOT_APP = 2
    TAKEOFF = 3

def encode_message(message: dict) -> bytes:
    return json.dumps(message, separators=(",", ":")).encode()

def decode_message(data: bytes) -> dict:
    return json.loads(data.decode())

def load_public_key():
    from cryptography.hazmat.primitives import serialization
    with open("../../keys/ground_public.pem", "rb") as f:
        return serialization.load_pem_public_key(
            f.read()
        )
 
def load_private_key():
    from cryptography.hazmat.primitives import serialization
    with open("../../keys/ground_private.pem", "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
        )
 